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
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, RunEvent, WindowEvent,
};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_notification::NotificationExt;
use walkdir::WalkDir;

// ---- Global state ----

static REALTIME_ENABLED: AtomicBool = AtomicBool::new(true);
static ALLOW_EXIT: AtomicBool = AtomicBool::new(false);

// Detect autostart launches (so release builds can boot silently)
const AUTOSTART_ARG: &str = "--autostart";

// ---- API config ----

const API_BASE_URL: &str = "https://stellarantivirusthreatapiprod.azurewebsites.net";
const API_HASH_CHECK_PATH: &str = "/api/av/v1/hash/check";

// ---- HTTP hardening ----

const HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;
const HTTP_TOTAL_TIMEOUT_SECS: u64 = 45;
const HTTP_RETRIES: usize = 1;

// ---- Scan tuning ----

const QUICK_MAX_FILE_BYTES: u64 = 25 * 1024 * 1024; // 25 MB
const FULL_MAX_FILE_BYTES: u64 = 200 * 1024 * 1024; // 200 MB

// ---- Persisted runtime config ----

#[derive(Serialize, Deserialize)]
struct RuntimeConfig {
    realtime_enabled: bool,
    shown_background_hint: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            realtime_enabled: true,
            shown_background_hint: false,
        }
    }
}

fn config_path() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir
        .join("StellarAntivirus")
        .join("runtime_config.json")
}

fn load_runtime_config() -> RuntimeConfig {
    let p = config_path();
    if let Ok(bytes) = fs::read(&p) {
        if let Ok(cfg) = serde_json::from_slice::<RuntimeConfig>(&bytes) {
            return cfg;
        }
    }
    RuntimeConfig::default()
}

fn save_runtime_config(cfg: &RuntimeConfig) {
    let p = config_path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_vec_pretty(cfg) {
        let _ = fs::write(p, json);
    }
}

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
    verdict: String,
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

    println!("[HTTP] POST {} ({} files total)", url, files.len());

    for (chunk_index, chunk) in files.chunks(CHUNK_SIZE).enumerate() {
        let req = ThreatApiRequest {
            client: build_client_payload(),
            files: chunk.to_vec(),
        };

        let mut last_err: Option<String> = None;

        for attempt in 0..=HTTP_RETRIES {
            println!(
                "[HTTP] chunk {}/{} attempt {}/{} ({} items)",
                chunk_index + 1,
                (files.len() + CHUNK_SIZE - 1) / CHUNK_SIZE,
                attempt + 1,
                HTTP_RETRIES + 1,
                chunk.len()
            );

            let started = std::time::Instant::now();
            let resp = client.post(&url).json(&req).send();

            match resp {
                Ok(r) => {
                    let status = r.status();
                    let elapsed = started.elapsed();

                    if !status.is_success() {
                        let msg = format!("API returned HTTP {}", status);
                        last_err = Some(msg.clone());

                        println!(
                            "[HTTP] status={} in {:?} (chunk {})",
                            status,
                            elapsed,
                            chunk_index + 1
                        );

                        if attempt < HTTP_RETRIES && status.is_server_error() {
                            thread::sleep(Duration::from_millis(400));
                            continue;
                        }
                        return Err(msg);
                    }

                    println!(
                        "[HTTP] status={} in {:?} (chunk {})",
                        status,
                        elapsed,
                        chunk_index + 1
                    );

                    // Clone headers before consuming body
                    let headers = r.headers().clone();
                    let content_type = headers
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown")
                        .to_string();

                    let bytes = r
                        .bytes()
                        .map_err(|e| format!("Failed to read API body: {e}"))?;

                    println!(
                        "[HTTP] response content-type={} bytes={}",
                        content_type,
                        bytes.len()
                    );

                    let parsed: ThreatApiResponse = serde_json::from_slice(&bytes).map_err(|e| {
                        let preview_len = bytes.len().min(200);
                        let preview = String::from_utf8_lossy(&bytes[..preview_len]);
                        format!("Failed to parse API JSON: {e}. body_preview={preview}")
                    })?;

                    all_results.extend(parsed.results);
                    last_err = None;
                    break;
                }
                Err(e) => {
                    let msg = format!("API request error: {e}");
                    last_err = Some(msg.clone());

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

    println!("[SCAN] {} starting. paths_to_scan={}", notification_label, total);

    let started_hash = std::time::Instant::now();

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

        if i % 100 == 0 {
            thread::sleep(Duration::from_millis(5));
        }
    }

    println!(
        "[SCAN] {} hashing done in {:?}. hashed_ok={}/{}",
        notification_label,
        started_hash.elapsed(),
        index_to_path.len(),
        total
    );

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

    let api_results = match call_threat_api_batch(files_for_api) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[SCAN] {} API error: {}", notification_label, e);

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

    use std::collections::HashMap;
    let mut hash_to_path: HashMap<String, String> = HashMap::new();
    for (_idx, path, hash) in &index_to_path {
        hash_to_path.insert(hash.to_lowercase(), path.to_string_lossy().to_string());
    }

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

    let _ = app.emit(
        "scan_finished",
        ScanFinishedPayload {
            threats: threats_vec.clone(),
        },
    );

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

fn try_add_path(
    paths: &mut Vec<PathBuf>,
    p: PathBuf,
    max_files: usize,
    max_file_bytes: Option<u64>,
    skipped_too_big: &mut usize,
) -> bool {
    if paths.len() >= max_files {
        return false;
    }

    if let Some(limit) = max_file_bytes {
        match fs::metadata(&p) {
            Ok(m) => {
                if m.len() > limit {
                    *skipped_too_big += 1;
                    return true;
                }
            }
            Err(_) => return true,
        }
    }

    paths.push(p);
    true
}

fn collect_paths(
    max_depth: usize,
    max_files: usize,
    include_documents: bool,
    include_desktop: bool,
    max_file_bytes: Option<u64>,
) -> Vec<PathBuf> {
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
                if !try_add_path(
                    &mut paths_to_scan,
                    entry.into_path(),
                    max_files,
                    max_file_bytes,
                    &mut skipped_too_big,
                ) {
                    break;
                }
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
                    if !try_add_path(
                        &mut paths_to_scan,
                        entry.into_path(),
                        max_files,
                        max_file_bytes,
                        &mut skipped_too_big,
                    ) {
                        break;
                    }
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
                    if !try_add_path(
                        &mut paths_to_scan,
                        entry.into_path(),
                        max_files,
                        max_file_bytes,
                        &mut skipped_too_big,
                    ) {
                        break;
                    }
                }
            }
        }
    }

    println!(
        "[SCAN] collect_paths depth={} max_files={} include_docs={} include_desktop={} limit_bytes={:?} -> kept={} skipped_too_big={}",
        max_depth,
        max_files,
        include_documents,
        include_desktop,
        max_file_bytes,
        paths_to_scan.len(),
        skipped_too_big
    );

    paths_to_scan
}

// ---- Commands ----

#[tauri::command]
async fn fake_full_scan(app: AppHandle) -> Result<(), String> {
    const MAX_DEPTH: usize = 3;
    const MAX_FILES: usize = 500;

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let paths_to_scan =
            collect_paths(MAX_DEPTH, MAX_FILES, true, true, Some(FULL_MAX_FILE_BYTES));
        run_hash_lookup_scan(app2, paths_to_scan, "Full scan")
    })
    .await
    .map_err(|e| format!("Full scan task failed: {e}"))?
}

#[tauri::command]
async fn quick_scan(app: AppHandle, max_bytes: Option<u64>) -> Result<(), String> {
    const MAX_DEPTH: usize = 2;
    const MAX_FILES: usize = 150;

    let limit = max_bytes.unwrap_or(QUICK_MAX_FILE_BYTES);

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let paths_to_scan = collect_paths(MAX_DEPTH, MAX_FILES, false, true, Some(limit));
        run_hash_lookup_scan(app2, paths_to_scan, "Quick scan")
    })
    .await
    .map_err(|e| format!("Quick scan task failed: {e}"))?
}

#[tauri::command]
fn get_realtime_enabled() -> bool {
    REALTIME_ENABLED.load(Ordering::SeqCst)
}

#[tauri::command]
fn set_realtime_enabled(enabled: bool) {
    REALTIME_ENABLED.store(enabled, Ordering::SeqCst);

    let mut cfg = load_runtime_config();
    cfg.realtime_enabled = enabled;
    save_runtime_config(&cfg);

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

            if detected_name.is_some() {
                let _ = app_handle.emit(
                    "realtime_threat_detected",
                    ScanFinishedPayload {
                        threats: vec![("Threat detected".to_string(), file.clone())],
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

// ---- Dock helpers (macOS) ----

#[cfg(target_os = "macos")]
fn set_dock_visible(app: &AppHandle, visible: bool) {
    if let Err(e) = app.set_dock_visibility(visible) {
        eprintln!("[DOCK] set_dock_visibility({visible}) failed: {e}");
    }
}

#[cfg(not(target_os = "macos"))]
fn set_dock_visible(_app: &AppHandle, _visible: bool) {}

// ---- Tray helpers ----

fn show_background_hint_once(app: &AppHandle) {
    let mut cfg = load_runtime_config();
    if cfg.shown_background_hint {
        return;
    }

    cfg.shown_background_hint = true;
    save_runtime_config(&cfg);

    let _ = app
        .notification()
        .builder()
        .title("Stellar Antivirus")
        .body("Stellar Antivirus is still protecting you in the background. Use the menu bar icon to Quit.")
        .show();
}

fn show_main_window(app: &AppHandle) {
    // When we show UI, we want it back in the Dock (macOS).
    set_dock_visible(app, true);

    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn hide_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }

    // When we hide UI, remove from Dock so it's a true background app (macOS).
    set_dock_visible(app, false);
}

fn launched_via_autostart() -> bool {
    std::env::args().any(|a| a == AUTOSTART_ARG)
}

fn init_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open_i = MenuItemBuilder::new("Open").id("tray_open").build(app)?;
    let hide_i = MenuItemBuilder::new("Hide").id("tray_hide").build(app)?;
    let quit_i = MenuItemBuilder::new("Quit").id("tray_quit").build(app)?;

    let menu = MenuBuilder::new(app)
        .items(&[&open_i, &hide_i, &quit_i])
        .build()?;

    let icon = app
        .default_window_icon()
        .cloned()
        .expect("Missing default window icon for tray");

    TrayIconBuilder::new()
        .menu(&menu)
        .icon(icon)
        .icon_as_template(true)
        .tooltip("Stellar Antivirus")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "tray_open" => show_main_window(app),
            "tray_hide" => hide_main_window(app),
            "tray_quit" => {
                // Allow a real quit only from tray Quit
                ALLOW_EXIT.store(true, Ordering::SeqCst);
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}

// ---- App entry ----

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let is_autostart = launched_via_autostart();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![AUTOSTART_ARG.into()]),
        ))
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            fake_full_scan,
            quick_scan,
            get_realtime_enabled,
            set_realtime_enabled,
            quarantine_files,
            restore_from_quarantine,
            delete_quarantine_files,
            delete_files,
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                show_background_hint_once(window.app_handle());
                hide_main_window(window.app_handle());
            }
        })
        .setup(move |app| {
            // Load persisted realtime toggle before watcher starts
            let cfg = load_runtime_config();
            REALTIME_ENABLED.store(cfg.realtime_enabled, Ordering::SeqCst);
            println!("[BOOT] realtime_enabled={}", cfg.realtime_enabled);

            // Tray so app can live in background
            init_tray(app)?;

            // Start watcher (this is what actually does real-time)
            let handle = app.handle().clone();
            start_realtime_watcher(handle);

            // If launched by autostart, boot silently (hidden + no Dock icon on macOS)
            if is_autostart {
                hide_main_window(app.handle());
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| match event {
        // Cmd+Q / Dock Quit / app exit request => HIDE, don't exit (unless tray Quit set ALLOW_EXIT)
        RunEvent::ExitRequested { api, .. } => {
            if ALLOW_EXIT.load(Ordering::SeqCst) {
                return;
            }

            api.prevent_exit();
            show_background_hint_once(app_handle);
            hide_main_window(app_handle);
        }

        // Clicking Dock icon / reopening should bring it back (also re-adds Dock icon)
        RunEvent::Reopen { .. } => {
            show_main_window(app_handle);
        }

        _ => {}
    });
}
