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
use serde::{de::Deserializer, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_notification::NotificationExt;
use walkdir::WalkDir;
use tauri::Manager;
use tauri::menu::MenuBuilder;
use tauri::tray::TrayIconBuilder;

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
const FULL_MAX_FILE_BYTES: u64 = 200 * 1024 * 1024; // 200 MB

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

// Robust deserializer: accept string/number/bool/null into Option<String>
fn de_opt_string_any<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(deserializer)?;
    Ok(match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    })
}

#[derive(Deserialize, Clone)]
struct ThreatApiSignature {
    // Laravel might send numeric IDs. DB might be null. Humans are creative.
    #[serde(default, deserialize_with = "de_opt_string_any")]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Deserialize, Clone)]
struct ThreatApiResult {
    sha256: String,
    verdict: String, // e.g. "clean", "malware", "pua", "unknown"
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
        .user_agent("StellarAntivirus/1.0.0")
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

    println!("[HTTP] POST {} ({} files total)", url, files.len());

    for (chunk_idx, chunk) in files.chunks(CHUNK_SIZE).enumerate() {
        let req = ThreatApiRequest {
            client: build_client_payload(),
            files: chunk.to_vec(),
        };

        let mut last_err: Option<String> = None;

        for attempt in 0..=HTTP_RETRIES {
            println!(
                "[HTTP] chunk {}/{} attempt {}/{} ({} items)",
                chunk_idx + 1,
                (files.len() + CHUNK_SIZE - 1) / CHUNK_SIZE,
                attempt + 1,
                HTTP_RETRIES + 1,
                chunk.len()
            );

            let t0 = std::time::Instant::now();

            let resp = client
                .post(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&req)
                .send();

            match resp {
                Ok(r) => {
                    let status = r.status();
                    let elapsed = t0.elapsed();

                    println!(
                        "[HTTP] status={} in {:?} (chunk {})",
                        status,
                        elapsed,
                        chunk_idx + 1
                    );

                    if !status.is_success() {
                        // Try to read body to help debugging even when status != 2xx
                        let body = r.text().unwrap_or_else(|_| "<failed to read body>".to_string());
                        let msg = format!("API returned HTTP {} body_snippet={}", status, body);
                        last_err = Some(msg.clone());

                        // Retry on transient server errors.
                        if attempt < HTTP_RETRIES && status.is_server_error() {
                            thread::sleep(Duration::from_millis(400));
                            continue;
                        }
                        return Err(msg);
                    }

                    // Read bytes and parse manually so we can log snippet on parse error.
                    let headers = r.headers().clone();
                    let body_bytes = r
                        .bytes()
                        .map_err(|e| format!("Failed to read API response body: {e}"))?;

                    let ct = headers
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<missing>");

                    println!(
                        "[HTTP] response content-type={} bytes={}",
                        ct,
                        body_bytes.len()
                    );

                    let parsed: ThreatApiResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
                        let snippet_len = body_bytes.len().min(800);
                        let snippet = String::from_utf8_lossy(&body_bytes[..snippet_len]);
                        format!(
                            "Failed to parse API JSON: {e} | content-type={} | body_snippet={}",
                            ct, snippet
                        )
                    })?;

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

    println!(
        "[SCAN] {} starting. paths_to_scan={}",
        notification_label, total
    );

    // Hash files + emit progress
    let t0 = std::time::Instant::now();
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

    let hashing_elapsed = t0.elapsed();
    println!(
        "[SCAN] {} hashing done in {:?}. hashed_ok={}/{}",
        notification_label,
        hashing_elapsed,
        index_to_path.len(),
        total
    );

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
            eprintln!("[SCAN] {} API error: {}", notification_label, e);

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
                .and_then(|s| s.name.clone())
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
) -> (Vec<PathBuf>, usize) {
    fn push_if_ok(
        paths: &mut Vec<PathBuf>,
        skipped_too_big: &mut usize,
        max_file_bytes: Option<u64>,
        p: PathBuf,
    ) {
        if let Some(limit) = max_file_bytes {
            match fs::metadata(&p) {
                Ok(m) => {
                    if m.len() > limit {
                        *skipped_too_big += 1;
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        paths.push(p);
    }

    let mut paths_to_scan: Vec<PathBuf> = Vec::new();
    let mut skipped_too_big: usize = 0;

    if let Some(downloads) = dirs::download_dir() {
        for entry in WalkDir::new(downloads)
            .max_depth(max_depth)
            .into_iter()
            .flatten()
        {
            if paths_to_scan.len() >= max_files {
                break;
            }
            if entry.file_type().is_file() {
                push_if_ok(
                    &mut paths_to_scan,
                    &mut skipped_too_big,
                    max_file_bytes,
                    entry.into_path(),
                );
            }
        }
    }

    if include_documents && paths_to_scan.len() < max_files {
        if let Some(documents) = dirs::document_dir() {
            for entry in WalkDir::new(documents)
                .max_depth(max_depth)
                .into_iter()
                .flatten()
            {
                if paths_to_scan.len() >= max_files {
                    break;
                }
                if entry.file_type().is_file() {
                    push_if_ok(
                        &mut paths_to_scan,
                        &mut skipped_too_big,
                        max_file_bytes,
                        entry.into_path(),
                    );
                }
            }
        }
    }

    if include_desktop && paths_to_scan.len() < max_files {
        if let Some(desktop) = dirs::desktop_dir() {
            for entry in WalkDir::new(desktop)
                .max_depth(max_depth)
                .into_iter()
                .flatten()
            {
                if paths_to_scan.len() >= max_files {
                    break;
                }
                if entry.file_type().is_file() {
                    push_if_ok(
                        &mut paths_to_scan,
                        &mut skipped_too_big,
                        max_file_bytes,
                        entry.into_path(),
                    );
                }
            }
        }
    }

    paths_to_scan.truncate(max_files);
    (paths_to_scan, skipped_too_big)
}


// ---- Commands ----

#[tauri::command]
async fn fake_full_scan(app: AppHandle) -> Result<(), String> {
    const MAX_DEPTH: usize = 3;
    const MAX_FILES: usize = 500;

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (paths_to_scan, skipped) =
            collect_paths(MAX_DEPTH, MAX_FILES, true, true, Some(FULL_MAX_FILE_BYTES));

        println!(
            "[SCAN] collect_paths depth={} max_files={} include_docs=true include_desktop=true limit_bytes={:?} -> kept={} skipped_too_big={}",
            MAX_DEPTH,
            MAX_FILES,
            Some(FULL_MAX_FILE_BYTES),
            paths_to_scan.len(),
            skipped
        );

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
        let (paths_to_scan, skipped) =
            collect_paths(MAX_DEPTH, MAX_FILES, false, true, Some(QUICK_MAX_FILE_BYTES));

        println!(
            "[SCAN] collect_paths depth={} max_files={} include_docs=false include_desktop=true limit_bytes={:?} -> kept={} skipped_too_big={}",
            MAX_DEPTH,
            MAX_FILES,
            Some(QUICK_MAX_FILE_BYTES),
            paths_to_scan.len(),
            skipped
        );

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

            // Let editors finish writing
            thread::sleep(Duration::from_millis(20));

            // Suppress duplicates for the same file within a short window
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
                                .and_then(|s| s.name.clone())
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
            // Start realtime watcher immediately (so it’s alive after reboot/login)
            let handle = app.handle().clone();
            start_realtime_watcher(handle);

            // Tray menu (Show / Quit)
            let menu = MenuBuilder::new(app)
                .text("show", "Show Stellar Antivirus")
                .separator()
                .text("quit", "Quit")
                .build()
                .map_err(|e| format!("Failed to build tray menu: {e}"))?;

            let mut tray = TrayIconBuilder::with_id("stellar_antivirus_tray")
                .menu(&menu)
                .tooltip("Stellar Antivirus");

            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }

            tray.on_menu_event(|app, event| {
                match event.id().as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                }
            })
            .build(app)
            .map_err(|e| format!("Failed to build tray icon: {e}"))?;

            Ok(())
        })
        // IMPORTANT: don’t let window close kill the process
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
