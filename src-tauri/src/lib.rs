use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_notification::NotificationExt;
use walkdir::WalkDir;

// ---- Global state ----

static REALTIME_ENABLED: AtomicBool = AtomicBool::new(true);

// ---- API config ----

const API_BASE_URL: &str = "https://stellarantivirusthreatapiprod.azurewebsites.net";
const API_HASH_CHECK_PATH: &str = "/api/av/v1/hash/check";

// ---- HTTP hardening ----
// If the API stalls, we must not hang forever.
const HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;
const HTTP_TOTAL_TIMEOUT_SECS: u64 = 45;
const HTTP_RETRIES: usize = 1;

// ---- Scan tuning ----
const QUICK_MAX_FILE_BYTES: u64 = 25 * 1024 * 1024; // 25 MB
const FULL_MAX_FILE_BYTES: u64 = 200 * 1024 * 1024; // 200 MB (still keeps you sane)

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
    #[serde(rename = "fileName", alias = "file_name")]
    file_name: String,
    #[serde(rename = "originalPath", alias = "original_path")]
    original_path: String,
}

// ---- API structs ----

#[derive(Serialize)]
struct ThreatApiClient {
    product: String,
    platform: String,
    version: String,
    threat_db_version: Option<u32>,
}

#[derive(Serialize, Clone)]
struct ThreatApiFile {
    sha256: String,
    size: Option<u64>,
    extension: Option<String>,
}

#[derive(Serialize)]
struct ThreatApiRequest {
    client: ThreatApiClient,
    files: Vec<ThreatApiFile>,
}

#[derive(Deserialize, Clone)]
struct ThreatApiSignature {
    id: String,
    name: String,
    family: String,
    category: String,
    severity: String,
}

#[derive(Deserialize, Clone)]
struct ThreatApiResult {
    sha256: String,
    verdict: String, // e.g. "clean", "malware", "pup", ...
    signature: Option<ThreatApiSignature>,
    recommended_action: Option<String>,
}

#[derive(Deserialize)]
struct ThreatApiResponse {
    schema_version: u32,
    db_version: u32,
    results: Vec<ThreatApiResult>,
}

// ---- Helper paths ----

fn quarantine_root() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir.join("StellarAntivirus").join("Quarantine")
}

// Simple test-file rule (filename)
fn is_test_filename(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        let lower = name.to_lowercase();
        return lower == "stellar-test.bin" || lower == "stellar_test.bin";
    }
    false
}

// ---- Hash helper ----

fn sha256_of_file(path: &Path) -> Option<String> {
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

    Some(hex::encode(hasher.finalize()))
}

// ---- HTTP / API helpers ----

fn build_http_client() -> Result<Client, String> {
    Client::builder()
        .connect_timeout(Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(HTTP_TOTAL_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

fn build_client_payload() -> ThreatApiClient {
    ThreatApiClient {
        product: "Stellar Antivirus Desktop".to_string(),
        platform: std::env::consts::OS.to_string(),
        version: "1.0.0".to_string(),
        threat_db_version: None,
    }
}

fn call_threat_api_batch(files: Vec<ThreatApiFile>) -> Result<Vec<ThreatApiResult>, String> {
    if files.is_empty() {
        return Ok(vec![]);
    }

    let url = format!("{}{}", API_BASE_URL, API_HASH_CHECK_PATH);
    let client = build_http_client()?;

    let mut all_results: Vec<ThreatApiResult> = Vec::new();
    const CHUNK_SIZE: usize = 1000;

    for chunk in files.chunks(CHUNK_SIZE) {
        let req = ThreatApiRequest {
            client: build_client_payload(),
            files: chunk.to_vec(),
        };

        let mut last_err: Option<String> = None;

        for attempt in 0..=HTTP_RETRIES {
            let resp = client.post(&url).json(&req).send();

            match resp {
                Ok(r) => {
                    if !r.status().is_success() {
                        let msg = format!("API returned HTTP {}", r.status());
                        last_err = Some(msg.clone());

                        // Retry on transient server errors.
                        if attempt < HTTP_RETRIES && r.status().is_server_error() {
                            thread::sleep(Duration::from_millis(400));
                            continue;
                        }
                        return Err(msg);
                    }

                    let parsed: ThreatApiResponse = r
                        .json()
                        .map_err(|e| format!("Failed to parse API JSON: {e}"))?;

                    all_results.extend(parsed.results);
                    last_err = None;
                    break;
                }
                Err(e) => {
                    let msg = format!("API request error: {e}");
                    last_err = Some(msg.clone());

                    // Retry once on network/timeouts.
                    if attempt < HTTP_RETRIES {
                        thread::sleep(Duration::from_millis(400));
                        continue;
                    }
                }
            }
        }

        if let Some(e) = last_err {
            return Err(e);
        }
    }

    Ok(all_results)
}

fn call_threat_api_single(hash: &str) -> Result<Option<ThreatApiResult>, String> {
    let file = ThreatApiFile {
        sha256: hash.to_string(),
        size: None,
        extension: None,
    };

    let results = call_threat_api_batch(vec![file])?;
    Ok(results.into_iter().next())
}

// ---- Shared scan routine ----

fn run_hash_lookup_scan(
    app: AppHandle,
    paths_to_scan: Vec<PathBuf>,
    notification_label: &str,
) -> Result<(), String> {
    let total = paths_to_scan.len();
    if total == 0 {
        let _ = app.emit("scan_finished", ScanFinishedPayload { threats: vec![] });
        return Ok(());
    }

    // Hash files + emit progress
    let mut index_to_path: Vec<(usize, PathBuf, String)> = Vec::with_capacity(total);

    for (i, path) in paths_to_scan.iter().enumerate() {
        let file_str = path.to_string_lossy().to_string();

        let _ = app.emit(
            "scan_progress",
            ScanProgressPayload {
                file: file_str.clone(),
                current: i + 1,
                total,
            },
        );

        if let Some(hash) = sha256_of_file(path) {
            index_to_path.push((i, path.clone(), hash));
        }

        // Let UI breathe on fast disks
        if i % 100 == 0 {
            thread::sleep(Duration::from_millis(5));
        }
    }

    // Build API payload
    let mut files_for_api: Vec<ThreatApiFile> = Vec::new();
    for (_idx, path, hash) in &index_to_path {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_lowercase());
        let size = fs::metadata(path).ok().map(|m| m.len());

        files_for_api.push(ThreatApiFile {
            sha256: hash.clone(),
            size,
            extension: ext,
        });
    }

    // Call API (chunked + timeout + retry)
    let api_results = match call_threat_api_batch(files_for_api) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{notification_label} API error: {e}");

            // Never leave the UI stuck in scanning state.
            let _ = app.emit("scan_finished", ScanFinishedPayload { threats: vec![] });

            let _ = app
                .notification()
                .builder()
                .title("Stellar Antivirus")
                .body(format!("{notification_label} failed – could not verify results."))
                .show();

            return Err(e);
        }
    };

    // Map sha256 -> file path
    use std::collections::HashMap;
    let mut hash_to_path: HashMap<String, String> = HashMap::new();
    for (_idx, path, hash) in &index_to_path {
        hash_to_path.insert(hash.to_lowercase(), path.to_string_lossy().to_string());
    }

    // Build threats list
    let mut threats_vec: Vec<(String, String)> = Vec::new();

    for r in api_results {
        let verdict = r.verdict.to_lowercase();
        if verdict == "clean" || verdict == "unknown" {
            continue;
        }

        if let Some(path_str) = hash_to_path.get(&r.sha256.to_lowercase()) {
            let name = r
                .signature
                .as_ref()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "Unknown threat".to_string());

            threats_vec.push((name, path_str.clone()));
        }
    }

    // Emit finished event
    let _ = app.emit(
        "scan_finished",
        ScanFinishedPayload {
            threats: threats_vec.clone(),
        },
    );

    // System notification
    if !threats_vec.is_empty() {
        let _ = app
            .notification()
            .builder()
            .title("Stellar Antivirus")
            .body(format!(
                "{notification_label} completed – {} threat(s) found.",
                threats_vec.len()
            ))
            .show();
    } else {
        let _ = app
            .notification()
            .builder()
            .title("Stellar Antivirus")
            .body(format!("{notification_label} completed – no threats found."))
            .show();
    }

    Ok(())
}

fn collect_paths(
    max_depth: usize,
    max_files: usize,
    include_documents: bool,
    include_desktop: bool,
    max_file_bytes: Option<u64>,
) -> Vec<PathBuf> {
    let mut paths_to_scan: Vec<PathBuf> = Vec::new();

    let mut push_if_ok = |p: PathBuf| {
        if let Some(limit) = max_file_bytes {
            match fs::metadata(&p) {
                Ok(m) => {
                    if m.len() > limit {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        paths_to_scan.push(p);
    };

    if let Some(downloads) = dirs::download_dir() {
        for entry in WalkDir::new(downloads)
            .max_depth(max_depth)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_file() {
                push_if_ok(entry.into_path());
            }
        }
    }

    if include_documents {
        if let Some(documents) = dirs::document_dir() {
            for entry in WalkDir::new(documents)
                .max_depth(max_depth)
                .into_iter()
                .flatten()
            {
                if entry.file_type().is_file() {
                    push_if_ok(entry.into_path());
                }
            }
        }
    }

    if include_desktop {
        if let Some(desktop) = dirs::desktop_dir() {
            for entry in WalkDir::new(desktop)
                .max_depth(max_depth)
                .into_iter()
                .flatten()
            {
                if entry.file_type().is_file() {
                    push_if_ok(entry.into_path());
                }
            }
        }
    }

    paths_to_scan.truncate(max_files);
    paths_to_scan
}

// ---- Commands ----

#[tauri::command]
async fn fake_full_scan(app: AppHandle) -> Result<(), String> {
    const MAX_DEPTH: usize = 3;
    const MAX_FILES: usize = 500;

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let paths_to_scan = collect_paths(MAX_DEPTH, MAX_FILES, true, true, Some(FULL_MAX_FILE_BYTES));
        run_hash_lookup_scan(app2, paths_to_scan, "Full scan")
    })
    .await
    .map_err(|e| format!("Full scan task failed: {e}"))?
}

#[tauri::command]
async fn quick_scan(app: AppHandle) -> Result<(), String> {
    const MAX_DEPTH: usize = 2;
    const MAX_FILES: usize = 150;

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        // Quick scan: smaller scope + skip large files
        let paths_to_scan = collect_paths(MAX_DEPTH, MAX_FILES, false, true, Some(QUICK_MAX_FILE_BYTES));
        run_hash_lookup_scan(app2, paths_to_scan, "Quick scan")
    })
    .await
    .map_err(|e| format!("Quick scan task failed: {e}"))?
}

#[tauri::command]
fn set_realtime_enabled(enabled: bool) {
    REALTIME_ENABLED.store(enabled, Ordering::SeqCst);
    println!("Realtime protection set to: {enabled}");
}

fn validate_quarantine_name(name: &str) -> Result<(), String> {
    use std::path::{Component, Path};

    let p = Path::new(name);
    let mut comps = p.components();

    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err("Invalid quarantine file name".to_string()),
    }
}

#[tauri::command]
async fn quarantine_files(paths: Vec<String>) -> Result<(), String> {
    let qdir = quarantine_root();

    fs::create_dir_all(&qdir)
        .map_err(|e| format!("Failed to create quarantine directory: {e}"))?;

    for original in paths {
        let src = PathBuf::from(&original);

        if !src.exists() {
            eprintln!("File does not exist, skipping: {original}");
            continue;
        }

        let fname = src
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("unknown"));
        let dest = qdir.join(fname);

        if dest.exists() {
            let _ = fs::remove_file(&dest);
        }

        if let Err(e) = fs::rename(&src, &dest) {
            eprintln!("rename failed: {e}, trying copy+delete");
            fs::copy(&src, &dest)
                .and_then(|_| fs::remove_file(&src))
                .map_err(|e2| format!("Failed to quarantine file {original}: {e2}"))?;
        }

        println!("Quarantined file: {src:?} -> {dest:?}");
    }

    Ok(())
}

#[tauri::command]
async fn restore_from_quarantine(items: Vec<RestoreItem>) -> Result<(), String> {
    let quarantine_root = quarantine_root();

    for item in items {
        validate_quarantine_name(&item.file_name)?;

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
        } else {
            println!("Restored file: {src:?} -> {dest:?}");
        }
    }

    Ok(())
}

#[tauri::command]
#[allow(non_snake_case)]
async fn delete_quarantine_files(fileNames: Vec<String>) -> Result<(), String> {
    let quarantine_root = quarantine_root();

    for name in fileNames {
        validate_quarantine_name(&name)?;

        let path = quarantine_root.join(&name);
        if !path.exists() {
            eprintln!("quarantine file does not exist for delete: {:?}", path);
            continue;
        }

        if let Err(e) = fs::remove_file(&path) {
            eprintln!("failed to delete quarantine file {:?}: {e}", path);
            return Err(format!("Failed to delete quarantine file {}: {e}", name));
        } else {
            println!("Deleted quarantine file: {:?}", path);
        }
    }

    Ok(())
}

#[tauri::command]
async fn delete_files(paths: Vec<String>) -> Result<(), String> {
    let qdir = quarantine_root();

    for original in paths {
        let fname = Path::new(&original).file_name().unwrap().to_os_string();
        let qpath = qdir.join(fname);

        if qpath.exists() {
            println!("Deleting quarantine file: {:?}", qpath);
            fs::remove_file(&qpath).map_err(|e| format!("Failed to delete file: {e}"))?;
        }
    }

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

        let quarantine_dir = quarantine_root();

        use std::collections::HashMap;
        use std::time::{Duration as StdDuration, Instant};

        let mut recent_hits: HashMap<String, Instant> = HashMap::new();
        let suppress_window = StdDuration::from_secs(2);

        let (tx, rx) = mpsc::channel::<Event>();

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    let _ = tx.send(event);
                }
                Err(e) => eprintln!("watch error: {e}"),
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

            let path = match event.paths.last() {
                Some(p) => p,
                None => continue,
            };

            // Ignore quarantine folder activity (prevents "remove threat" causing re-detect)
            if path.starts_with(&quarantine_dir) {
                continue;
            }

            let file = path.to_string_lossy().to_string();

            let kind_str = match &event.kind {
                EventKind::Create(_) => "create",
                EventKind::Modify(_) => "modify",
                EventKind::Remove(_) => "remove",
                EventKind::Any => "any",
                _ => "other",
            }
            .to_string();

            let _ = app_handle.emit(
                "realtime_file_event",
                RealtimeFilePayload {
                    file: file.clone(),
                    event: kind_str.clone(),
                },
            );

            let relevant =
                matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any);

            if !relevant {
                continue;
            }

            thread::sleep(Duration::from_millis(20));

            let now = Instant::now();
            if let Some(last) = recent_hits.get(&file) {
                if now.duration_since(*last) < suppress_window {
                    continue;
                }
            }
            recent_hits.insert(file.clone(), now);

            if recent_hits.len() > 256 {
                let cutoff = Instant::now() - suppress_window;
                recent_hits.retain(|_, t| *t >= cutoff);
            }

            let mut detected_name: Option<String> = None;

            if is_test_filename(path) {
                detected_name = Some("Stellar.Test.FileNameRule".to_string());
            } else if let Some(hash) = sha256_of_file(path) {
                let hash_lower = hash.to_lowercase();

                match call_threat_api_single(&hash_lower) {
                    Ok(Some(result)) => {
                        let verdict = result.verdict.to_lowercase();
                        if verdict != "clean" && verdict != "unknown" {
                            let name = result
                                .signature
                                .as_ref()
                                .map(|s| s.name.clone())
                                .unwrap_or_else(|| "Unknown threat".to_string());

                            detected_name = Some(name);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[Realtime] API error for {}: {e}", file);
                    }
                }
            }

            if let Some(name) = detected_name {
                let _ = app_handle.emit(
                    "realtime_threat_detected",
                    ScanFinishedPayload {
                        threats: vec![(name.clone(), file.clone())],
                    },
                );

                let _ = app_handle
                    .notification()
                    .builder()
                    .title("Stellar Antivirus")
                    .body(format!("Real-time protection blocked: {}", file))
                    .show();
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
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            fake_full_scan,
            quick_scan,
            set_realtime_enabled,
            quarantine_files,
            restore_from_quarantine,
            delete_quarantine_files,
            delete_files,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            start_realtime_watcher(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
