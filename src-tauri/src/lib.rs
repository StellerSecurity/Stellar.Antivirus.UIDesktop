use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, RunEvent, WindowEvent,
};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_notification::NotificationExt;
use walkdir::WalkDir;

// ---- Global state ----

static REALTIME_ENABLED: AtomicBool = AtomicBool::new(true);
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);
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

fn default_realtime_enabled() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
struct RuntimeConfig {
    #[serde(default = "default_realtime_enabled")]
    realtime_enabled: bool,
    #[serde(default)]
    shown_background_hint: bool,
    #[serde(default)]
    shown_background_hint_v2: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            realtime_enabled: true,
            shown_background_hint: false,
            shown_background_hint_v2: false,
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
    stats: Option<ScanStatsPayload>,
    scan_kind: String,
    scan_label: String,
}

#[derive(Serialize, Clone)]
struct ScanStatsPayload {
    files_discovered: usize,
    files_hashed: usize,
    files_skipped: usize,
    threats_found: usize,
    eicar_found: usize,
    duration_ms: u128,
    cancelled: bool,
    cloud_hashes_queued: usize,
    cloud_hashes_checked: usize,
    cloud_hashes_failed: usize,
    cloud_batches_total: usize,
    cloud_batches_succeeded: usize,
    cloud_batches_failed: usize,
    cloud_retry_count: usize,
    file_hash_cache_hits: usize,
    verdict_cache_hits: usize,
    cloud_hashes_skipped_cached: usize,
    completed_with_warnings: bool,
}

#[derive(Serialize, Clone)]
struct RealtimeFilePayload {
    file: String,
    event: String,
}

#[derive(Deserialize)]
struct RestoreItem {
    #[serde(rename = "quarantineId", alias = "quarantine_id")]
    quarantine_id: Option<String>,
    #[serde(rename = "fileName", alias = "file_name")]
    file_name: String,
    #[serde(rename = "originalPath", alias = "original_path")]
    original_path: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct QuarantineManifestEntry {
    id: String,
    original_path: String,
    quarantine_file_name: String,
    display_name: String,
    sha256: Option<String>,
    detection: Option<String>,
    quarantined_at: u64,
}

#[derive(Serialize, Clone)]
struct QuarantineResult {
    quarantine_id: String,
    original_path: String,
    quarantine_file_name: String,
    display_name: String,
    detection: Option<String>,
}

#[derive(Serialize)]
struct DiagnosticsSystemInfo {
    os: String,
    arch: String,
    family: String,
    exe_path: Option<String>,
    data_dir: Option<String>,
    config_path: String,
    quarantine_dir: String,
    quarantine_manifest_path: String,
    quarantine_manifest_entries: usize,
    file_hash_cache_path: String,
    file_hash_cache_entries: usize,
    verdict_cache_path: String,
    verdict_cache_entries: usize,
    realtime_enabled: bool,
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

#[derive(Serialize, Deserialize, Clone)]
struct ThreatApiSignature {
    id: String,
    name: String,
    family: String,
    category: String,
    severity: String,
}

#[derive(Serialize, Deserialize, Clone)]
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

struct ThreatApiBatchReport {
    results: Vec<ThreatApiResult>,
    hashes_queued: usize,
    hashes_checked: usize,
    hashes_failed: usize,
    batches_total: usize,
    batches_succeeded: usize,
    batches_failed: usize,
    retries_used: usize,
}

impl ThreatApiBatchReport {
    fn empty() -> Self {
        Self {
            results: Vec::new(),
            hashes_queued: 0,
            hashes_checked: 0,
            hashes_failed: 0,
            batches_total: 0,
            batches_succeeded: 0,
            batches_failed: 0,
            retries_used: 0,
        }
    }

    fn completed_with_warnings(&self) -> bool {
        self.hashes_failed > 0 || self.batches_failed > 0
    }
}


// ---- Helper paths ----

fn quarantine_root() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir.join("StellarAntivirus").join("Quarantine")
}

fn quarantine_manifest_path() -> PathBuf {
    quarantine_root().join("manifest.json")
}

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn load_quarantine_manifest() -> Vec<QuarantineManifestEntry> {
    let p = quarantine_manifest_path();
    match fs::read(&p) {
        Ok(bytes) => serde_json::from_slice::<Vec<QuarantineManifestEntry>>(&bytes)
            .unwrap_or_else(|e| {
                eprintln!("[Quarantine] failed to parse manifest {:?}: {e}", p);
                Vec::new()
            }),
        Err(_) => Vec::new(),
    }
}

fn save_quarantine_manifest(entries: &[QuarantineManifestEntry]) -> Result<(), String> {
    let p = quarantine_manifest_path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create quarantine manifest directory: {e}"))?;
    }

    let json = serde_json::to_vec_pretty(entries)
        .map_err(|e| format!("Failed to serialize quarantine manifest: {e}"))?;

    fs::write(&p, json).map_err(|e| format!("Failed to write quarantine manifest: {e}"))
}

fn remove_manifest_entry_by_id(id: &str) -> Result<(), String> {
    let mut entries = load_quarantine_manifest();
    let before = entries.len();
    entries.retain(|e| e.id != id);
    if entries.len() != before {
        save_quarantine_manifest(&entries)?;
    }
    Ok(())
}

fn find_manifest_entry_by_id(id: &str) -> Option<QuarantineManifestEntry> {
    load_quarantine_manifest().into_iter().find(|e| e.id == id)
}

fn find_manifest_entry_by_file_name(file_name: &str) -> Option<QuarantineManifestEntry> {
    load_quarantine_manifest()
        .into_iter()
        .find(|e| e.quarantine_file_name == file_name)
}

// ---- Local scan caches ----

const CLEAN_VERDICT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const UNKNOWN_VERDICT_TTL_SECS: u64 = 24 * 60 * 60;
const MALICIOUS_VERDICT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Serialize, Deserialize, Clone)]
struct FileHashCacheEntry {
    size: u64,
    modified_secs: u64,
    sha256: String,
    cached_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct VerdictCacheEntry {
    verdict: String,
    signature: Option<ThreatApiSignature>,
    recommended_action: Option<String>,
    checked_at: u64,
    ttl_seconds: u64,
}

fn cache_root() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir.join("StellarAntivirus").join("Cache")
}

fn file_hash_cache_path() -> PathBuf {
    cache_root().join("file_hash_cache.json")
}

fn verdict_cache_path() -> PathBuf {
    cache_root().join("verdict_cache.json")
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn metadata_modified_secs(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn load_file_hash_cache() -> std::collections::HashMap<String, FileHashCacheEntry> {
    let p = file_hash_cache_path();
    match fs::read(&p) {
        Ok(bytes) => serde_json::from_slice::<std::collections::HashMap<String, FileHashCacheEntry>>(&bytes)
            .unwrap_or_else(|e| {
                eprintln!("[Cache] failed to parse file hash cache {:?}: {e}", p);
                std::collections::HashMap::new()
            }),
        Err(_) => std::collections::HashMap::new(),
    }
}

fn save_file_hash_cache(cache: &std::collections::HashMap<String, FileHashCacheEntry>) {
    let p = file_hash_cache_path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_vec_pretty(cache) {
        let _ = fs::write(p, json);
    }
}

fn load_verdict_cache() -> std::collections::HashMap<String, VerdictCacheEntry> {
    let p = verdict_cache_path();
    match fs::read(&p) {
        Ok(bytes) => serde_json::from_slice::<std::collections::HashMap<String, VerdictCacheEntry>>(&bytes)
            .unwrap_or_else(|e| {
                eprintln!("[Cache] failed to parse verdict cache {:?}: {e}", p);
                std::collections::HashMap::new()
            }),
        Err(_) => std::collections::HashMap::new(),
    }
}

fn save_verdict_cache(cache: &std::collections::HashMap<String, VerdictCacheEntry>) {
    let p = verdict_cache_path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_vec_pretty(cache) {
        let _ = fs::write(p, json);
    }
}

fn verdict_ttl_seconds(verdict: &str) -> u64 {
    match verdict.to_lowercase().as_str() {
        "clean" => CLEAN_VERDICT_TTL_SECS,
        "unknown" => UNKNOWN_VERDICT_TTL_SECS,
        _ => MALICIOUS_VERDICT_TTL_SECS,
    }
}

fn cached_verdict_is_fresh(entry: &VerdictCacheEntry, now: u64) -> bool {
    now.saturating_sub(entry.checked_at) <= entry.ttl_seconds
}

fn cached_verdict_to_result(sha256: &str, entry: &VerdictCacheEntry) -> ThreatApiResult {
    ThreatApiResult {
        sha256: sha256.to_string(),
        verdict: entry.verdict.clone(),
        signature: entry.signature.clone(),
        recommended_action: entry.recommended_action.clone(),
    }
}

fn update_verdict_cache_from_result(
    cache: &mut std::collections::HashMap<String, VerdictCacheEntry>,
    result: &ThreatApiResult,
    now: u64,
) {
    let verdict = result.verdict.to_lowercase();
    cache.insert(
        result.sha256.to_lowercase(),
        VerdictCacheEntry {
            verdict: verdict.clone(),
            signature: result.signature.clone(),
            recommended_action: result.recommended_action.clone(),
            checked_at: now,
            ttl_seconds: verdict_ttl_seconds(&verdict),
        },
    );
}

fn sha256_of_file_with_cache(
    path: &Path,
    cache: &mut std::collections::HashMap<String, FileHashCacheEntry>,
) -> (Option<String>, bool) {
    let Ok(metadata) = fs::metadata(path) else {
        return (None, false);
    };

    if !metadata.is_file() {
        return (None, false);
    }

    let Some(modified_secs) = metadata_modified_secs(&metadata) else {
        return (sha256_of_file(path), false);
    };

    let size = metadata.len();
    let path_key = path.to_string_lossy().to_string();

    if let Some(entry) = cache.get(&path_key) {
        if entry.size == size && entry.modified_secs == modified_secs && !entry.sha256.is_empty() {
            return (Some(entry.sha256.clone()), true);
        }
    }

    let hash = sha256_of_file(path);
    if let Some(h) = &hash {
        cache.insert(
            path_key,
            FileHashCacheEntry {
                size,
                modified_secs,
                sha256: h.clone(),
                cached_at: current_timestamp_secs(),
            },
        );
    }

    (hash, false)
}


fn is_test_filename(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        let lower = name.to_lowercase();
        return lower == "stellar-test.bin" || lower == "stellar_test.bin";
    }
    false
}

fn is_eicar_test_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    // EICAR is a small harmless industry-standard antivirus test file. Keep the
    // read bounded so real-time protection cannot be forced to load large files.
    if !metadata.is_file() || metadata.len() > 4096 {
        return false;
    }

    let Ok(bytes) = fs::read(path) else {
        return false;
    };

    let content = String::from_utf8_lossy(&bytes);
    content.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
}

fn local_test_detection_name(path: &Path) -> Option<String> {
    if is_eicar_test_file(path) {
        return Some("EICAR-Test-File".to_string());
    }

    if is_test_filename(path) {
        return Some("Stellar.Test.FileNameRule".to_string());
    }

    None
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

fn call_threat_api_batches_with_report(files: Vec<ThreatApiFile>) -> ThreatApiBatchReport {
    if files.is_empty() {
        return ThreatApiBatchReport::empty();
    }

    let url = format!("{}{}", API_BASE_URL, API_HASH_CHECK_PATH);
    let client = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[HTTP] failed to build client: {e}");
            return ThreatApiBatchReport {
                hashes_queued: files.len(),
                hashes_failed: files.len(),
                batches_total: 1,
                batches_failed: 1,
                ..ThreatApiBatchReport::empty()
            };
        }
    };

    let mut all_results: Vec<ThreatApiResult> = Vec::new();
    const CHUNK_SIZE: usize = 100;
    const MAX_ATTEMPTS: usize = 3;

    let total_batches = (files.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let mut batches_succeeded = 0usize;
    let mut batches_failed = 0usize;
    let mut hashes_checked = 0usize;
    let mut hashes_failed = 0usize;
    let mut retries_used = 0usize;

    println!(
        "[HTTP] POST {} ({} unique hashes total, {} batches of max {})",
        url,
        files.len(),
        total_batches,
        CHUNK_SIZE
    );

    for (chunk_index, chunk) in files.chunks(CHUNK_SIZE).enumerate() {
        let req = ThreatApiRequest {
            client: build_client_payload(),
            files: chunk.to_vec(),
        };

        let mut chunk_succeeded = false;
        let mut last_err: Option<String> = None;

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                retries_used += 1;
            }

            println!(
                "[HTTP] chunk {}/{} attempt {}/{} ({} hashes)",
                chunk_index + 1,
                total_batches,
                attempt + 1,
                MAX_ATTEMPTS,
                chunk.len()
            );

            let started = std::time::Instant::now();
            let resp = client.post(&url).json(&req).send();

            match resp {
                Ok(r) => {
                    let status = r.status();
                    let elapsed = started.elapsed();

                    println!(
                        "[HTTP] status={} in {:?} (chunk {})",
                        status,
                        elapsed,
                        chunk_index + 1
                    );

                    if !status.is_success() {
                        last_err = Some(format!("API returned HTTP {}", status));

                        if attempt + 1 < MAX_ATTEMPTS {
                            let delay_ms = if attempt == 0 { 500 } else { 1500 };
                            thread::sleep(Duration::from_millis(delay_ms));
                            continue;
                        }

                        break;
                    }

                    let headers = r.headers().clone();
                    let content_type = headers
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown")
                        .to_string();

                    let bytes = match r.bytes() {
                        Ok(b) => b,
                        Err(e) => {
                            last_err = Some(format!("Failed to read API body: {e}"));
                            if attempt + 1 < MAX_ATTEMPTS {
                                thread::sleep(Duration::from_millis(500));
                                continue;
                            }
                            break;
                        }
                    };

                    println!(
                        "[HTTP] response content-type={} bytes={}",
                        content_type,
                        bytes.len()
                    );

                    match serde_json::from_slice::<ThreatApiResponse>(&bytes) {
                        Ok(parsed) => {
                            all_results.extend(parsed.results);
                            hashes_checked += chunk.len();
                            batches_succeeded += 1;
                            chunk_succeeded = true;
                            last_err = None;
                            break;
                        }
                        Err(e) => {
                            let preview_len = bytes.len().min(200);
                            let preview = String::from_utf8_lossy(&bytes[..preview_len]);
                            last_err = Some(format!(
                                "Failed to parse API JSON: {e}. body_preview={preview}"
                            ));

                            if attempt + 1 < MAX_ATTEMPTS {
                                thread::sleep(Duration::from_millis(500));
                                continue;
                            }

                            break;
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(format!("API request error: {e}"));

                    if attempt + 1 < MAX_ATTEMPTS {
                        let delay_ms = if attempt == 0 { 500 } else { 1500 };
                        thread::sleep(Duration::from_millis(delay_ms));
                        continue;
                    }

                    break;
                }
            }
        }

        if !chunk_succeeded {
            batches_failed += 1;
            hashes_failed += chunk.len();

            if let Some(e) = last_err {
                eprintln!(
                    "[HTTP] chunk {}/{} failed after {} attempts: {}",
                    chunk_index + 1,
                    total_batches,
                    MAX_ATTEMPTS,
                    e
                );
            }
        }
    }

    ThreatApiBatchReport {
        results: all_results,
        hashes_queued: files.len(),
        hashes_checked,
        hashes_failed,
        batches_total: total_batches,
        batches_succeeded,
        batches_failed,
        retries_used,
    }
}

fn call_threat_api_batch(files: Vec<ThreatApiFile>) -> Result<Vec<ThreatApiResult>, String> {
    let report = call_threat_api_batches_with_report(files);

    if report.batches_failed > 0 && report.batches_succeeded == 0 {
        return Err(format!(
            "All cloud hash check batches failed ({} hash(es) failed).",
            report.hashes_failed
        ));
    }

    Ok(report.results)
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
    scan_kind: &str,
) -> Result<(), String> {
    let total = paths_to_scan.len();
    let scan_started = std::time::Instant::now();
    let scan_kind_owned = scan_kind.to_string();
    let scan_label_owned = notification_label.to_string();

    let emit_finished = |app: &AppHandle,
                         threats: Vec<(String, String)>,
                         files_hashed: usize,
                         files_skipped: usize,
                         eicar_found: usize,
                         cancelled: bool,
                         api_report: &ThreatApiBatchReport,
                         file_hash_cache_hits: usize,
                         verdict_cache_hits: usize,
                         started: std::time::Instant| {
        let _ = app.emit(
            "scan_finished",
            ScanFinishedPayload {
                stats: Some(ScanStatsPayload {
                    files_discovered: total,
                    files_hashed,
                    files_skipped,
                    threats_found: threats.len(),
                    eicar_found,
                    duration_ms: started.elapsed().as_millis(),
                    cancelled,
                    cloud_hashes_queued: api_report.hashes_queued,
                    cloud_hashes_checked: api_report.hashes_checked,
                    cloud_hashes_failed: api_report.hashes_failed,
                    cloud_batches_total: api_report.batches_total,
                    cloud_batches_succeeded: api_report.batches_succeeded,
                    cloud_batches_failed: api_report.batches_failed,
                    cloud_retry_count: api_report.retries_used,
                    file_hash_cache_hits,
                    verdict_cache_hits,
                    cloud_hashes_skipped_cached: verdict_cache_hits,
                    completed_with_warnings: api_report.completed_with_warnings(),
                }),
                scan_kind: scan_kind_owned.clone(),
                scan_label: scan_label_owned.clone(),
                threats,
            },
        );
    };

    if total == 0 {
        emit_finished(
            &app,
            vec![],
            0,
            0,
            0,
            false,
            &ThreatApiBatchReport::empty(),
            0,
            0,
            scan_started,
        );
        return Ok(());
    }

    println!("[SCAN] {} starting. paths_to_scan={}", notification_label, total);

    let started_hash = std::time::Instant::now();
    let mut file_hash_cache = load_file_hash_cache();
    let mut verdict_cache = load_verdict_cache();
    let mut file_hash_cache_hits: usize = 0;
    let mut verdict_cache_hits: usize = 0;
    let mut index_to_path: Vec<(usize, PathBuf, String)> = Vec::with_capacity(total);
    let mut local_threats: Vec<(String, String)> = Vec::new();
    let mut eicar_found: usize = 0;
    let mut skipped_files: usize = 0;

    for (i, path) in paths_to_scan.iter().enumerate() {
        if SCAN_CANCELLED.load(Ordering::SeqCst) {
            println!("[SCAN] {} cancelled before hashing completed", notification_label);
            let _ = app.emit("scan_cancelled", ());
            save_file_hash_cache(&file_hash_cache);
            emit_finished(
                &app,
                local_threats,
                index_to_path.len(),
                skipped_files,
                eicar_found,
                true,
                &ThreatApiBatchReport::empty(),
                file_hash_cache_hits,
                verdict_cache_hits,
                scan_started,
            );
            return Ok(());
        }

        let file_str = path.to_string_lossy().to_string();

        let _ = app.emit(
            "scan_progress",
            ScanProgressPayload {
                file: file_str.clone(),
                current: i + 1,
                total,
            },
        );

        if let Some(detection) = local_test_detection_name(path) {
            if detection == "EICAR-Test-File" {
                eicar_found += 1;
            }
            local_threats.push((detection, file_str));
            continue;
        }

        let (hash, cache_hit) = sha256_of_file_with_cache(path, &mut file_hash_cache);
        if cache_hit {
            file_hash_cache_hits += 1;
        }

        if let Some(hash) = hash {
            index_to_path.push((i, path.clone(), hash));
        } else {
            skipped_files += 1;
        }

        if i % 100 == 0 {
            thread::sleep(Duration::from_millis(5));
        }
    }

    println!(
        "[SCAN] {} hashing done in {:?}. hashed_ok={}/{} local_threats={} skipped={} hash_cache_hits={}",
        notification_label,
        started_hash.elapsed(),
        index_to_path.len(),
        total,
        local_threats.len(),
        skipped_files,
        file_hash_cache_hits
    );

    save_file_hash_cache(&file_hash_cache);

    use std::collections::HashMap;

    let mut unique_files_for_api: HashMap<String, ThreatApiFile> = HashMap::new();
    let mut hash_to_paths: HashMap<String, Vec<String>> = HashMap::new();

    for (_idx, path, hash) in &index_to_path {
        let hash_lower = hash.to_lowercase();
        hash_to_paths
            .entry(hash_lower.clone())
            .or_default()
            .push(path.to_string_lossy().to_string());

        unique_files_for_api.entry(hash_lower.clone()).or_insert_with(|| {
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_lowercase());
            let size = fs::metadata(path).ok().map(|m| m.len());

            ThreatApiFile {
                sha256: hash_lower,
                size,
                extension: ext,
            }
        });
    }

    let now_secs = current_timestamp_secs();
    let mut cached_api_results: Vec<ThreatApiResult> = Vec::new();
    let mut files_for_api: Vec<ThreatApiFile> = Vec::new();

    for (hash, file) in unique_files_for_api {
        if let Some(entry) = verdict_cache.get(&hash) {
            if cached_verdict_is_fresh(entry, now_secs) {
                verdict_cache_hits += 1;
                cached_api_results.push(cached_verdict_to_result(&hash, entry));
                continue;
            }
        }

        files_for_api.push(file);
    }

    println!(
        "[SCAN] {} verdict_cache_hits={} cloud_hashes_needed={}",
        notification_label,
        verdict_cache_hits,
        files_for_api.len()
    );

    if SCAN_CANCELLED.load(Ordering::SeqCst) {
        println!("[SCAN] {} cancelled before API verification", notification_label);
        let _ = app.emit("scan_cancelled", ());
        emit_finished(
            &app,
            local_threats,
            index_to_path.len(),
            skipped_files,
            eicar_found,
            true,
            &ThreatApiBatchReport::empty(),
            file_hash_cache_hits,
            verdict_cache_hits,
            scan_started,
        );
        return Ok(());
    }

    let api_report = call_threat_api_batches_with_report(files_for_api);
    let mut api_results = cached_api_results;
    api_results.extend(api_report.results.clone());

    let cache_update_time = current_timestamp_secs();
    for result in &api_report.results {
        update_verdict_cache_from_result(&mut verdict_cache, result, cache_update_time);
    }
    save_verdict_cache(&verdict_cache);

    if api_report.completed_with_warnings() {
        eprintln!(
            "[SCAN] {} completed with cloud warnings: {} hash(es) failed across {} failed batch(es)",
            notification_label,
            api_report.hashes_failed,
            api_report.batches_failed
        );
    }

    let mut threats_vec: Vec<(String, String)> = local_threats;

    for r in api_results {
        let verdict = r.verdict.to_lowercase();
        if verdict == "clean" || verdict == "unknown" {
            continue;
        }

        if let Some(paths) = hash_to_paths.get(&r.sha256.to_lowercase()) {
            let name = r
                .signature
                .as_ref()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "Unknown threat".to_string());

            for path_str in paths {
                threats_vec.push((name.clone(), path_str.clone()));
            }
        }
    }

    emit_finished(
        &app,
        threats_vec.clone(),
        index_to_path.len(),
        skipped_files,
        eicar_found,
        false,
        &api_report,
        file_hash_cache_hits,
        verdict_cache_hits,
        scan_started,
    );

    let scan_notification_body = if !threats_vec.is_empty() || api_report.completed_with_warnings() {
        format!("{notification_label} completed. Some items need attention.")
    } else {
        format!("{notification_label} completed. No threats found.")
    };

    let _ = app
        .notification()
        .builder()
        .title("Stellar Antivirus")
        .body(scan_notification_body)
        .show();

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

fn scan_path_component_should_be_skipped(name: &str) -> bool {
    let lower = name.to_lowercase();

    matches!(
        lower.as_str(),
        ".git"
            | ".svn"
            | ".hg"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".next"
            | ".nuxt"
            | ".cache"
            | "cache"
            | "caches"
            | "deriveddata"
            | "trash"
            | ".trash"
            | ".trashes"
            | "__pycache__"
            | ".venv"
            | "venv"
            | "tmp"
            | "temp"
    )
}

fn should_skip_full_scan_entry(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };

    if scan_path_component_should_be_skipped(name) {
        return true;
    }

    let path_text = path.to_string_lossy().to_lowercase();

    let is_browser_cache = path_text.contains("/library/application support/google/chrome/default/cache")
        || path_text.contains("/library/application support/google/chrome/default/code cache")
        || path_text.contains("/library/application support/bravesoftware/brave-browser/default/cache")
        || (path_text.contains("/library/application support/firefox/profiles") && path_text.contains("/cache"));

    let is_apple_music_library = path_text.contains("/music/music/")
        || path_text.contains("/music/itunes/")
        || path_text.contains("/music/media.localized/")
        || path_text.contains("/music/music library.musiclibrary")
        || path_text.contains("/music/itunes library.itl")
        || path_text.contains("/music/itunes media/");

    path_text.contains("/library/caches")
        || path_text.contains("/library/developer")
        || path_text.contains("/library/containers")
        || path_text.contains("/library/group containers")
        || path_text.contains("/library/logs")
        || path_text.contains("/library/safari/favicondatabase")
        || is_browser_cache
        || is_apple_music_library
}


fn try_add_full_scan_path(
    paths: &mut Vec<PathBuf>,
    p: PathBuf,
    max_file_bytes: Option<u64>,
    skipped_too_big: &mut usize,
    skipped_unreadable: &mut usize,
) {
    if let Some(limit) = max_file_bytes {
        match fs::metadata(&p) {
            Ok(m) => {
                if !m.is_file() {
                    return;
                }
                if m.len() > limit {
                    *skipped_too_big += 1;
                    return;
                }
            }
            Err(_) => {
                *skipped_unreadable += 1;
                return;
            }
        }
    }

    paths.push(p);
}

fn collect_full_scan_paths(max_file_bytes: Option<u64>) -> Vec<PathBuf> {
    let mut paths_to_scan: Vec<PathBuf> = Vec::new();
    let mut skipped_too_big: usize = 0;
    let mut skipped_unreadable: usize = 0;
    let mut skipped_dirs: usize = 0;

    let mut roots: Vec<PathBuf> = Vec::new();

    if let Some(home) = dirs::home_dir() {
        roots.push(home);
    } else {
        if let Some(downloads) = dirs::download_dir() {
            roots.push(downloads);
        }
        if let Some(documents) = dirs::document_dir() {
            roots.push(documents);
        }
        if let Some(desktop) = dirs::desktop_dir() {
            roots.push(desktop);
        }
    }

    roots.sort();
    roots.dedup();

    for root in roots {
        if SCAN_CANCELLED.load(Ordering::SeqCst) {
            break;
        }

        if !root.exists() {
            continue;
        }

        for item in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }

                if entry.file_type().is_dir() && should_skip_full_scan_entry(entry.path()) {
                    return false;
                }

                true
            })
        {
            if SCAN_CANCELLED.load(Ordering::SeqCst) {
                break;
            }

            match item {
                Ok(entry) => {
                    if entry.file_type().is_dir() && should_skip_full_scan_entry(entry.path()) {
                        skipped_dirs += 1;
                        continue;
                    }

                    if entry.file_type().is_file() {
                        try_add_full_scan_path(
                            &mut paths_to_scan,
                            entry.into_path(),
                            max_file_bytes,
                            &mut skipped_too_big,
                            &mut skipped_unreadable,
                        );
                    }
                }
                Err(e) => {
                    skipped_unreadable += 1;
                    eprintln!("[SCAN] Full scan skipped unreadable entry: {e}");
                }
            }
        }
    }

    println!(
        "[SCAN] collect_full_scan_paths limit_bytes={:?} -> kept={} skipped_too_big={} skipped_unreadable={} skipped_dirs={}",
        max_file_bytes,
        paths_to_scan.len(),
        skipped_too_big,
        skipped_unreadable,
        skipped_dirs
    );

    paths_to_scan
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


#[derive(serde::Serialize)]
struct FsAccessProbe {
    label: String,
    path: String,
    ok: bool,
    error: Option<String>,
}

fn probe_one(label: &str, p: std::path::PathBuf) -> FsAccessProbe {
    // Try to list directory entries to force a real permission/access check.
    match std::fs::read_dir(&p) {
        Ok(mut it) => {
            // Touch first entry (if any) to trigger real FS access.
            let _ = it.next();
            FsAccessProbe {
                label: label.to_string(),
                path: p.to_string_lossy().to_string(),
                ok: true,
                error: None,
            }
        }
        Err(e) => FsAccessProbe {
            label: label.to_string(),
            path: p.to_string_lossy().to_string(),
            ok: false,
            error: Some(e.to_string()),
        },
    }
}

#[tauri::command]
fn probe_fs_access() -> Vec<FsAccessProbe> {
    let mut out: Vec<FsAccessProbe> = Vec::new();

    if let Some(p) = dirs::download_dir() {
        out.push(probe_one("Downloads", p));
    } else {
        out.push(FsAccessProbe {
            label: "Downloads".to_string(),
            path: "(not found)".to_string(),
            ok: false,
            error: Some("dirs::download_dir() returned None".to_string()),
        });
    }

    if let Some(p) = dirs::document_dir() {
        out.push(probe_one("Documents", p));
    } else {
        out.push(FsAccessProbe {
            label: "Documents".to_string(),
            path: "(not found)".to_string(),
            ok: false,
            error: Some("dirs::document_dir() returned None".to_string()),
        });
    }

    if let Some(p) = dirs::desktop_dir() {
        out.push(probe_one("Desktop", p));
    } else {
        out.push(FsAccessProbe {
            label: "Desktop".to_string(),
            path: "(not found)".to_string(),
            ok: false,
            error: Some("dirs::desktop_dir() returned None".to_string()),
        });
    }

    out
}



#[tauri::command]
fn cancel_scan() {
    SCAN_CANCELLED.store(true, Ordering::SeqCst);
    println!("[SCAN] cancellation requested");
}

#[tauri::command]
async fn fake_full_scan(app: AppHandle) -> Result<(), String> {
    SCAN_CANCELLED.store(false, Ordering::SeqCst);

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let paths_to_scan = collect_full_scan_paths(Some(FULL_MAX_FILE_BYTES));
        run_hash_lookup_scan(app2, paths_to_scan, "Full scan", "full")
    })
    .await
    .map_err(|e| format!("Full scan task failed: {e}"))?
}

#[tauri::command]
async fn quick_scan(app: AppHandle, max_bytes: Option<u64>) -> Result<(), String> {
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
    const MAX_DEPTH: usize = 2;
    const MAX_FILES: usize = 150;

    let limit = max_bytes.unwrap_or(QUICK_MAX_FILE_BYTES);

    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let paths_to_scan = collect_paths(MAX_DEPTH, MAX_FILES, false, true, Some(limit));
        run_hash_lookup_scan(app2, paths_to_scan, "Quick scan", "quick")
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

fn validate_quarantine_id(id: &str) -> Result<(), String> {
    validate_quarantine_name(id)
}

fn quarantine_single_file(original: &str, detection: Option<String>) -> Result<Option<QuarantineResult>, String> {
    let qdir = quarantine_root();
    fs::create_dir_all(&qdir)
        .map_err(|e| format!("Failed to create quarantine directory: {e}"))?;

    let src = PathBuf::from(original);
    if !src.exists() || !src.is_file() {
        eprintln!("File does not exist or is not a file, skipping quarantine: {original}");
        return Ok(None);
    }

    let original_name = src
        .file_name()
        .and_then(|st| st.to_str())
        .unwrap_or("unknown")
        .to_string();

    let hash = sha256_of_file(&src);
    let hash_prefix = hash
        .as_ref()
        .map(|h| h.chars().take(16).collect::<String>())
        .unwrap_or_else(|| current_timestamp_millis().to_string());

    let mut quarantine_id = format!("{}__{}", current_timestamp_millis(), hash_prefix);
    validate_quarantine_id(&quarantine_id)?;

    let mut quarantine_file_name = format!("{}__{}", quarantine_id, original_name);
    validate_quarantine_name(&quarantine_file_name)?;

    let mut dest = qdir.join(&quarantine_file_name);
    if dest.exists() {
        quarantine_id = format!("{}__{}", current_timestamp_millis(), hash_prefix);
        quarantine_file_name = format!("{}__{}", quarantine_id, original_name);
        validate_quarantine_name(&quarantine_file_name)?;
        dest = qdir.join(&quarantine_file_name);
    }

    if dest.exists() {
        return Err(format!("Quarantine destination already exists: {quarantine_file_name}"));
    }

    if let Err(e) = fs::rename(&src, &dest) {
        eprintln!("rename failed: {e}, trying copy+delete");
        fs::copy(&src, &dest)
            .and_then(|_| fs::remove_file(&src))
            .map_err(|e2| format!("Failed to quarantine file {original}: {e2}"))?;
    }

    let entry = QuarantineManifestEntry {
        id: quarantine_id.clone(),
        original_path: original.to_string(),
        quarantine_file_name: quarantine_file_name.clone(),
        display_name: original_name.clone(),
        sha256: hash,
        detection: detection.clone(),
        quarantined_at: current_timestamp_millis(),
    };

    let mut manifest = load_quarantine_manifest();
    manifest.retain(|e| e.id != quarantine_id && e.quarantine_file_name != quarantine_file_name);
    manifest.push(entry);
    save_quarantine_manifest(&manifest)?;

    println!("Quarantined file: {src:?} -> {dest:?}");

    Ok(Some(QuarantineResult {
        quarantine_id,
        original_path: original.to_string(),
        quarantine_file_name,
        display_name: original_name,
        detection,
    }))
}

#[tauri::command]
async fn quarantine_files(paths: Vec<String>) -> Result<Vec<QuarantineResult>, String> {
    let mut results: Vec<QuarantineResult> = Vec::new();

    for original in paths {
        if let Some(result) = quarantine_single_file(&original, None)? {
            results.push(result);
        }
    }

    Ok(results)
}

#[tauri::command]
async fn restore_from_quarantine(items: Vec<RestoreItem>) -> Result<(), String> {
    let qroot = quarantine_root();

    for item in items {
        let manifest_entry = match item.quarantine_id.as_deref() {
            Some(id) if !id.is_empty() => {
                validate_quarantine_id(id)?;
                find_manifest_entry_by_id(id)
            }
            _ => {
                validate_quarantine_name(&item.file_name)?;
                find_manifest_entry_by_file_name(&item.file_name)
            }
        };

        let (entry_id, quarantine_file_name, original_path) = if let Some(entry) = manifest_entry {
            (entry.id, entry.quarantine_file_name, entry.original_path)
        } else {
            validate_quarantine_name(&item.file_name)?;
            (String::new(), item.file_name.clone(), item.original_path.clone())
        };

        validate_quarantine_name(&quarantine_file_name)?;

        let src = qroot.join(&quarantine_file_name);
        if !src.exists() {
            eprintln!("quarantine file does not exist for restore: {:?}", src);
            continue;
        }

        let dest = PathBuf::from(&original_path);

        if let Some(parent) = dest.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("failed to create dest parent dir {:?}: {e}", parent);
            }
        }

        if dest.exists() {
            let backup = dest.with_extension("stellar_backup");
            if let Err(e) = fs::rename(&dest, &backup) {
                eprintln!("failed to backup existing file before restore ({dest:?} -> {backup:?}): {e}");
            }
        }

        let rename_result = fs::rename(&src, &dest);
        if let Err(e) = rename_result {
            eprintln!("restore rename failed ({src:?} -> {dest:?}): {e}, trying copy+delete");
            if let Err(e2) = fs::copy(&src, &dest).and_then(|_| fs::remove_file(&src)) {
                eprintln!("restore copy+delete also failed for {src:?}: {e2}");
                return Err(format!(
                    "Failed to restore file {} to {}: {e2}",
                    quarantine_file_name, original_path
                ));
            }
        } else {
            println!("Restored file: {src:?} -> {dest:?}");
        }

        if !entry_id.is_empty() {
            remove_manifest_entry_by_id(&entry_id)?;
        }
    }

    Ok(())
}

#[tauri::command]
#[allow(non_snake_case)]
async fn delete_quarantine_files(fileNames: Vec<String>) -> Result<(), String> {
    let qroot = quarantine_root();
    let mut manifest = load_quarantine_manifest();
    let mut changed_manifest = false;

    for name in fileNames {
        validate_quarantine_name(&name)?;

        let path = qroot.join(&name);
        if !path.exists() {
            eprintln!("quarantine file does not exist for delete: {:?}", path);
        } else if let Err(e) = fs::remove_file(&path) {
            eprintln!("failed to delete quarantine file {:?}: {e}", path);
            return Err(format!("Failed to delete quarantine file {}: {e}", name));
        } else {
            println!("Deleted quarantine file: {:?}", path);
        }

        let before = manifest.len();
        manifest.retain(|e| e.quarantine_file_name != name);
        changed_manifest = changed_manifest || manifest.len() != before;
    }

    if changed_manifest {
        save_quarantine_manifest(&manifest)?;
    }

    Ok(())
}

#[tauri::command]
async fn delete_quarantine_items(ids: Vec<String>) -> Result<(), String> {
    let qroot = quarantine_root();
    let mut manifest = load_quarantine_manifest();
    let mut changed_manifest = false;

    for id in ids {
        validate_quarantine_id(&id)?;

        if let Some(entry) = manifest.iter().find(|e| e.id == id).cloned() {
            let path = qroot.join(&entry.quarantine_file_name);
            if path.exists() {
                fs::remove_file(&path).map_err(|e| {
                    format!("Failed to delete quarantined file {}: {e}", entry.display_name)
                })?;
            }

            let before = manifest.len();
            manifest.retain(|e| e.id != id);
            changed_manifest = changed_manifest || manifest.len() != before;
        }
    }

    if changed_manifest {
        save_quarantine_manifest(&manifest)?;
    }

    Ok(())
}

#[tauri::command]
async fn delete_files(paths: Vec<String>) -> Result<(), String> {
    let qdir = quarantine_root();

    for original in paths {
        let Some(fname) = Path::new(&original).file_name().map(|f| f.to_os_string()) else {
            continue;
        };
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

            if let Some(name) = local_test_detection_name(path) {
                detected_name = Some(name);
            } else {
                let mut file_hash_cache = load_file_hash_cache();
                let (hash, _cache_hit) = sha256_of_file_with_cache(path, &mut file_hash_cache);
                save_file_hash_cache(&file_hash_cache);

                if let Some(hash) = hash {
                    let hash_lower = hash.to_lowercase();
                    let now_secs = current_timestamp_secs();
                    let mut verdict_cache = load_verdict_cache();

                    let cached_result = verdict_cache
                        .get(&hash_lower)
                        .filter(|entry| cached_verdict_is_fresh(entry, now_secs))
                        .map(|entry| cached_verdict_to_result(&hash_lower, entry));

                    let result = match cached_result {
                        Some(result) => Some(result),
                        None => match call_threat_api_single(&hash_lower) {
                            Ok(Some(result)) => {
                                update_verdict_cache_from_result(
                                    &mut verdict_cache,
                                    &result,
                                    current_timestamp_secs(),
                                );
                                save_verdict_cache(&verdict_cache);
                                Some(result)
                            }
                            Ok(None) => None,
                            Err(e) => {
                                eprintln!("[Realtime] API error for {}: {e}", file);
                                None
                            }
                        },
                    };

                    if let Some(result) = result {
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
                }
            }

            if let Some(threat_name) = detected_name {
                match quarantine_single_file(&file, Some(threat_name.clone())) {
                    Ok(Some(result)) => {
                        let _ = app_handle.emit("realtime_threat_quarantined", result.clone());

                        let _ = app_handle
                            .notification()
                            .builder()
                            .title("Stellar Antivirus")
                            .body(format!("Real-time protection quarantined: {}", file))
                            .show();
                    }
                    Ok(None) => {
                        let _ = app_handle.emit(
                            "realtime_threat_detected",
                            ScanFinishedPayload {
                                threats: vec![(threat_name, file.clone())],
                                stats: None,
                                scan_kind: "realtime_scan".to_string(),
                                scan_label: "Real-time protection".to_string(),
                            },
                        );
                    }
                    Err(e) => {
                        eprintln!("[Realtime] failed to auto-quarantine {}: {e}", file);
                        let _ = app_handle.emit(
                            "realtime_threat_detected",
                            ScanFinishedPayload {
                                threats: vec![(threat_name, file.clone())],
                                stats: None,
                                scan_kind: "realtime_scan".to_string(),
                                scan_label: "Real-time protection".to_string(),
                            },
                        );

                        let _ = app_handle
                            .notification()
                            .builder()
                            .title("Stellar Antivirus")
                            .body(format!("Threat detected but quarantine failed: {}", file))
                            .show();
                    }
                }
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
    if cfg.shown_background_hint_v2 {
        return;
    }

    match app
        .notification()
        .builder()
        .title("Stellar Antivirus")
        .body("Stellar Antivirus is still protecting you in the background. Use the menu bar icon to Quit.")
        .show()
    {
        Ok(_) => {
            cfg.shown_background_hint = true;
            cfg.shown_background_hint_v2 = true;
            save_runtime_config(&cfg);
        }
        Err(e) => {
            eprintln!("[NOTIFICATION] background hint failed: {e}");
        }
    }
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

    let icon = Image::new(include_bytes!("../icons/tray-icon.rgba"), 32, 32);

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


#[tauri::command]
fn reveal_path_in_file_manager(path: String) -> Result<(), String> {
    let target = PathBuf::from(&path);

    if !target.exists() {
        return Err(format!("Path does not exist: {path}"));
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg("-R")
            .arg(&target)
            .status()
            .map_err(|err| format!("Failed to open Finder: {err}"))?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(format!("/select,{}", target.to_string_lossy()))
            .status()
            .map_err(|err| format!("Failed to open Explorer: {err}"))?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let dir = if target.is_dir() {
            target
        } else {
            target
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| "Could not resolve parent directory".to_string())?
        };

        Command::new("xdg-open")
            .arg(&dir)
            .status()
            .map_err(|err| format!("Failed to open file manager: {err}"))?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err("Opening diagnostics is not supported on this platform".to_string())
}

#[tauri::command]
fn get_diagnostics_system_info() -> DiagnosticsSystemInfo {
    DiagnosticsSystemInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        family: std::env::consts::FAMILY.to_string(),
        exe_path: std::env::current_exe().ok().map(|p| p.to_string_lossy().to_string()),
        data_dir: dirs::data_dir().map(|p| p.to_string_lossy().to_string()),
        config_path: config_path().to_string_lossy().to_string(),
        quarantine_dir: quarantine_root().to_string_lossy().to_string(),
        quarantine_manifest_path: quarantine_manifest_path().to_string_lossy().to_string(),
        quarantine_manifest_entries: load_quarantine_manifest().len(),
        file_hash_cache_path: file_hash_cache_path().to_string_lossy().to_string(),
        file_hash_cache_entries: load_file_hash_cache().len(),
        verdict_cache_path: verdict_cache_path().to_string_lossy().to_string(),
        verdict_cache_entries: load_verdict_cache().len(),
        realtime_enabled: REALTIME_ENABLED.load(Ordering::SeqCst),
    }
}

#[tauri::command]
fn export_diagnostics_file(content: String) -> Result<String, String> {
    let export_dir = dirs::download_dir()
        .or_else(dirs::desktop_dir)
        .or_else(dirs::home_dir)
        .ok_or_else(|| "Could not resolve a diagnostics export directory".to_string())?;

    fs::create_dir_all(&export_dir)
        .map_err(|err| format!("Failed to prepare diagnostics directory: {err}"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("Failed to create diagnostics timestamp: {err}"))?
        .as_secs();

    let file_path = export_dir.join(format!(
        "stellar-antivirus-diagnostics-{timestamp}.json"
    ));

    fs::write(&file_path, content)
        .map_err(|err| format!("Failed to write diagnostics file: {err}"))?;

    Ok(file_path.to_string_lossy().to_string())
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
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            fake_full_scan,
            quick_scan,
            cancel_scan,
            get_realtime_enabled,
            set_realtime_enabled,
            quarantine_files,
            restore_from_quarantine,
            delete_quarantine_files,
            delete_quarantine_items,
            delete_files,
            probe_fs_access,
            get_diagnostics_system_info,
            export_diagnostics_file,
            reveal_path_in_file_manager
        ])
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                show_background_hint_once(window.app_handle());
                hide_main_window(window.app_handle());
            }
            WindowEvent::Resized(_) => {
                // Treat minimize like close-to-tray: keep protection running silently.
                if window.is_minimized().unwrap_or(false) {
                    show_background_hint_once(window.app_handle());
                    hide_main_window(window.app_handle());
                }
            }
            _ => {}
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

            // The window is configured as hidden by default.
            // Manual launches open the UI; autostart launches stay in the background.
            if is_autostart {
                hide_main_window(app.handle());
            } else {
                show_main_window(app.handle());
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
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => {
            show_main_window(app_handle);
        }

        _ => {}
    });
}
