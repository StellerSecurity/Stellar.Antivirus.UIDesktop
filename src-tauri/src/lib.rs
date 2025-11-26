use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tauri_plugin_autostart::MacosLauncher;
use rusqlite::{Connection, params};
use sha2::{Sha256, Digest};
use hex;

// ---- Global state ----

static REALTIME_ENABLED: AtomicBool = AtomicBool::new(true);

// ---- Payloads to frontend ----

#[derive(Serialize, Clone)]
struct ScanProgressPayload {
    file: String,
    current: usize,
    total: usize,
}

#[derive(Serialize, Clone)]
struct ScanFinishedPayload {
    threats: Vec<(String, String)>, // (threat_name, file_path)
}

#[derive(Serialize, Clone)]
struct RealtimeFilePayload {
    file: String,
    event: String,
}

#[derive(Deserialize)]
struct RestoreItem {
    file_name: String,
    original_path: String,
}

// ---- Threat DB JSON structs (fra Azure) ----

#[derive(Deserialize)]
struct ThreatDbFile {
    schema_version: u32,
    db_version: u32,
    updated_at: String,
    threats: Vec<ThreatJsonEntry>,
    // rules ignorerer vi lige nu
}

#[derive(Deserialize)]
struct ThreatJsonEntry {
    id: String,
    sha256: String,
    name: String,
    family: String,
    category: String,
    severity: String,
    platforms: Vec<String>,
    tags: Option<Vec<String>>,
    notes: Option<String>,
    first_seen: Option<String>,
    last_updated: Option<String>,
    source: Option<String>,
}

// ---- Lokale DB structs ----

#[derive(Clone)]
struct ThreatSignature {
    id: i64,
    sha256: String,
    name: String,
    family: String,
    severity: String,
    platforms: String,
}

// ---- Helper paths ----

fn quarantine_root() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir.join("StellarAntivirus").join("Quarantine")
}

fn db_path() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir
        .join("StellarAntivirus")
        .join("stellar_av.db")
}

// ---- DB init ----

fn init_db() -> Result<(), String> {
    let db_file = db_path();

    if let Some(parent) = db_file.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create db dir: {e}"))?;
    }

    let conn = Connection::open(&db_file)
        .map_err(|e| format!("Failed to open DB: {e}"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS threat_signatures (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256        TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            family        TEXT NOT NULL,
            severity      TEXT NOT NULL,
            platforms     TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS detections (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path     TEXT NOT NULL,
            sha256        TEXT NOT NULL,
            threat_id     INTEGER,
            detected_at   TEXT NOT NULL DEFAULT (datetime('now')),
            source        TEXT NOT NULL,
            action        TEXT NOT NULL,
            FOREIGN KEY(threat_id) REFERENCES threat_signatures(id)
        );
        "#,
    ).map_err(|e| format!("Failed to create tables: {e}"))?;

    Ok(())
}

// ---- Hash & lookup helpers ----

fn sha256_of_file(path: &std::path::Path) -> Option<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let hash = hasher.finalize();
    Some(hex::encode(hash))
}

fn lookup_threat_by_hash(hash: &str) -> Option<ThreatSignature> {
    let conn = Connection::open(db_path()).ok()?;

    let mut stmt = conn.prepare(
        "SELECT id, sha256, name, family, severity, platforms
         FROM threat_signatures
         WHERE sha256 = ?1",
    ).ok()?;

    let sig = stmt
        .query_row(params![hash], |row| {
            Ok(ThreatSignature {
                id: row.get(0)?,
                sha256: row.get(1)?,
                name: row.get(2)?,
                family: row.get(3)?,
                severity: row.get(4)?,
                platforms: row.get(5)?,
            })
        })
        .ok()?; // Result<T, E> -> Option<T>

    Some(sig)
}

fn insert_detection(
    file_path: &str,
    sha256: &str,
    threat: Option<&ThreatSignature>,
    source: &str,
    action: &str,
) {
    if let Ok(conn) = Connection::open(db_path()) {
        let threat_id = threat.map(|t| t.id);
        let _ = conn.execute(
            "INSERT INTO detections (file_path, sha256, threat_id, source, action)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![file_path, sha256, threat_id, source, action],
        );
    }
}

// ---- Commands ----

#[tauri::command]
async fn fake_full_scan(app: AppHandle) -> Result<(), String> {
    let mut files_to_scan: Vec<PathBuf> = Vec::new();
    let mut scan_paths: Vec<PathBuf> = Vec::new();

    if let Some(downloads) = dirs::download_dir() {
        scan_paths.push(downloads);
    }
    if let Some(documents) = dirs::document_dir() {
        scan_paths.push(documents);
    }
    if let Some(desktop) = dirs::desktop_dir() {
        scan_paths.push(desktop);
    }

    for path in scan_paths {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten().take(300) {
                files_to_scan.push(entry.path());
            }
        }
    }

    let total = files_to_scan.len();
    let mut threats: Vec<(String, String)> = Vec::new();

    for (i, file) in files_to_scan.iter().enumerate() {
        let file_str = file.to_string_lossy().to_string();

        let _ = app.emit(
            "scan_progress",
            ScanProgressPayload {
                file: file_str.clone(),
                current: i + 1,
                total,
            },
        );

        if let Some(hash) = sha256_of_file(file) {
            let hash_lower = hash.to_lowercase();
            if let Some(sig) = lookup_threat_by_hash(&hash_lower) {
                threats.push((sig.name.clone(), file_str.clone()));
                insert_detection(&file_str, &hash_lower, Some(&sig), "full_scan", "none");
            }
        }

        thread::sleep(Duration::from_millis(10));
    }

    let _ = app.emit("scan_finished", ScanFinishedPayload { threats });

    Ok(())
}

#[tauri::command]
fn set_realtime_enabled(enabled: bool) {
    REALTIME_ENABLED.store(enabled, Ordering::SeqCst);
    println!("Realtime protection set to: {enabled}");
}

#[tauri::command]
fn quarantine_files(paths: Vec<String>) -> Result<(), String> {
    let quarantine_root = quarantine_root();

    fs::create_dir_all(&quarantine_root).map_err(|e| {
        format!("Failed to create quarantine directory: {e}")
    })?;

    for original in paths {
        let src = PathBuf::from(&original);

        if !src.exists() {
            eprintln!("File does not exist, skipping: {original}");
            continue;
        }

        let file_name = src
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("unknown"));

        let dest = quarantine_root.join(file_name);

        if dest.exists() {
            if let Err(e) = fs::remove_file(&dest) {
                eprintln!("failed to remove existing quarantine file {:?}: {e}", dest);
            }
        }

        let rename_result = fs::rename(&src, &dest);
        if let Err(e) = rename_result {
            eprintln!("rename failed ({src:?} -> {dest:?}): {e}, trying copy+delete");
            if let Err(e2) = fs::copy(&src, &dest).and_then(|_| fs::remove_file(&src)) {
                eprintln!("copy+delete also failed for {src:?}: {e2}");
                return Err(format!("Failed to quarantine file {original}: {e2}"));
            }
        }
    }

    Ok(())
}

#[tauri::command]
fn restore_from_quarantine(items: Vec<RestoreItem>) -> Result<(), String> {
    let quarantine_root = quarantine_root();

    for item in items {
        let src = quarantine_root.join(&item.file_name);
        if !src.exists() {
            eprintln!("quarantine file does not exist for restore: {:?}", src);
            continue;
        }

        let dest = PathBuf::from(&item.original_path);

        if let Some(parent) = dest.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("failed to create dest parent dir {:?}: {e}", parent);
            }
        }

        if dest.exists() {
            let backup = dest.with_extension("stellar_backup");
            if let Err(e) = fs::rename(&dest, &backup) {
                eprintln!(
                    "failed to backup existing file before restore ({dest:?} -> {backup:?}): {e}"
                );
            }
        }

        let rename_result = fs::rename(&src, &dest);
        if let Err(e) = rename_result {
            eprintln!("restore rename failed ({src:?} -> {dest:?}): {e}, trying copy+delete");
            if let Err(e2) = fs::copy(&src, &dest).and_then(|_| fs::remove_file(&src)) {
                eprintln!("restore copy+delete also failed for {src:?}: {e2}");
                return Err(format!(
                    "Failed to restore file {} to {}: {e2}",
                    item.file_name, item.original_path
                ));
            }
        }
    }

    Ok(())
}

#[tauri::command]
fn delete_quarantine_files(file_names: Vec<String>) -> Result<(), String> {
    let quarantine_root = quarantine_root();

    for name in file_names {
        let path = quarantine_root.join(&name);
        if !path.exists() {
            eprintln!("quarantine file does not exist for delete: {:?}", path);
            continue;
        }

        if let Err(e) = fs::remove_file(&path) {
            eprintln!("failed to delete quarantine file {:?}: {e}", path);
            return Err(format!("Failed to delete quarantine file {}: {e}", name));
        }
    }

    Ok(())
}

#[tauri::command]
fn update_threat_db(threats_json: String) -> Result<(), String> {
    let db_file: ThreatDbFile = serde_json::from_str(&threats_json)
        .map_err(|e| format!("Failed to parse threat DB JSON: {e}"))?;

    let mut conn = Connection::open(db_path())
        .map_err(|e| format!("Failed to open DB: {e}"))?;

    let tx = conn
        .transaction()
        .map_err(|e| format!("Failed to start transaction: {e}"))?;

    for t in db_file.threats {
        let platforms_joined = t.platforms.join(",");

        tx.execute(
            r#"
            INSERT INTO threat_signatures (sha256, name, family, severity, platforms)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(sha256) DO UPDATE SET
                name = excluded.name,
                family = excluded.family,
                severity = excluded.severity,
                platforms = excluded.platforms
            "#,
            params![
                t.sha256.to_lowercase(),
                t.name,
                t.family,
                t.severity,
                platforms_joined,
            ],
        )
        .map_err(|e| format!("Failed to upsert threat signature: {e}"))?;
    }

    tx.commit()
        .map_err(|e| format!("Failed to commit threat DB update: {e}"))?;

    println!("Threat DB updated from server. db_version = {}", db_file.db_version);

    Ok(())
}

// ---- Realtime watcher ----

fn start_realtime_watcher(app_handle: AppHandle) {
    thread::spawn(move || {
        let mut watch_paths: Vec<PathBuf> = Vec::new();

        if let Some(downloads) = dirs::download_dir() {
            watch_paths.push(downloads);
        }
        if let Some(documents) = dirs::document_dir() {
            watch_paths.push(documents);
        }
        if let Some(desktop) = dirs::desktop_dir() {
            watch_paths.push(desktop);
        }

        let (tx, rx) = mpsc::channel::<Event>();

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        let _ = tx.send(event);
                    }
                    Err(e) => eprintln!("watch error: {e}"),
                }
            })
            .expect("failed to create file watcher");

        for path in &watch_paths {
            if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                eprintln!("failed to watch {:?}: {e}", path);
            }
        }

        println!("Realtime watcher started on {:?}", watch_paths);

        for event in rx {
            if !REALTIME_ENABLED.load(Ordering::SeqCst) {
                continue;
            }

            if event.paths.is_empty() {
                continue;
            }

            let path = &event.paths[0];
            let file = path.to_string_lossy().to_string();
            let kind_str = match &event.kind {
                EventKind::Create(_) => "create",
                EventKind::Modify(_) => "modify",
                EventKind::Remove(_) => "remove",
                EventKind::Any => "any",
                _ => "other",
            }
            .to_string();

            // 1) Emit normal realtime log til UI
            if let Err(e) = app_handle.emit(
                "realtime_file_event",
                RealtimeFilePayload {
                    file: file.clone(),
                    event: kind_str.clone(),
                },
            ) {
                eprintln!("failed to emit realtime_file_event: {e}");
            }

            // 2) Kun ved create/modify: hash + threat lookup
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                if let Some(hash) = sha256_of_file(path) {
                    let hash_lower = hash.to_lowercase();
                    if let Some(sig) = lookup_threat_by_hash(&hash_lower) {
                        // gem detection i DB som realtime
                        insert_detection(&file, &hash_lower, Some(&sig), "realtime", "none");

                        // emit særskilt event så UI kan reagere (toast/modal/log)
                        let _ = app_handle.emit(
                            "realtime_threat_detected",
                            ScanFinishedPayload {
                                threats: vec![(sig.name.clone(), file.clone())],
                            },
                        );
                    }
                }
            }
        }
    });
}


// ---- App entry ----

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .invoke_handler(tauri::generate_handler![
            fake_full_scan,
            set_realtime_enabled,
            quarantine_files,
            restore_from_quarantine,
            delete_quarantine_files,
            update_threat_db,
        ])
        .setup(|app| {
            if let Err(e) = init_db() {
                eprintln!("Failed to init DB: {e}");
            }

            let handle = app.handle().clone();
            start_realtime_watcher(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
