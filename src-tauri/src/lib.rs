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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_notification::NotificationExt;
use walkdir::WalkDir;
use reqwest::blocking::Client;

// ---- Global state ----

static REALTIME_ENABLED: AtomicBool = AtomicBool::new(true);

// ---- API config ----

const API_BASE_URL: &str = "https://stellarantivirusthreatapiprod.azurewebsites.net";
const API_HASH_CHECK_PATH: &str = "/api/av/v1/hash/check";

// ---- Payloads til frontend ----

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
    verdict: String, // fx "clean", "malware", "pup", ...
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

// Simpel test-filregel (navn)
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

    let hash = hasher.finalize();
    Some(hex::encode(hash))
}

// ---- API helpers ----

fn build_client_payload() -> ThreatApiClient {
    ThreatApiClient {
        product: "Stellar Antivirus Desktop".to_string(),
        platform: std::env::consts::OS.to_string(),
        version: "1.0.0".to_string(),
        threat_db_version: None,
    }
}

fn call_threat_api_batch(files: Vec<ThreatApiFile>) -> Result<Vec<ThreatApiResult>, String> {
    // If there are no files, there is nothing to look up
    if files.is_empty() {
        return Ok(vec![]);
    }

    // Base URL for the Threat API
    let url = format!("{}{}", API_BASE_URL, API_HASH_CHECK_PATH);

    // Reuse the same HTTP client for all chunks
    let client = Client::new();

    // Collect all results from all chunks here
    let mut all_results: Vec<ThreatApiResult> = Vec::new();

    // How many files to send per API call.
    // 500–1000 is usually a good balance between performance and payload size.
    const CHUNK_SIZE: usize = 1000;

    // Iterate over the files in fixed-size chunks
    for chunk in files.chunks(CHUNK_SIZE) {
        // Build request payload for this chunk
        let req = ThreatApiRequest {
            client: build_client_payload(),
            files: chunk.to_vec(), // now valid because ThreatApiFile: Clone
        };

        // Perform the HTTP request
        let resp = client
            .post(&url)
            .json(&req)
            .send()
            .map_err(|e| format!("API request error: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("API returned HTTP {}", resp.status()));
        }

        // Parse JSON response from this chunk
        let parsed: ThreatApiResponse = resp
            .json()
            .map_err(|e| format!("Failed to parse API JSON: {e}"))?;

        // Append results from this chunk to the global list
        all_results.extend(parsed.results);
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

// ---- Commands ----

/// Full scan – scanner en masse filer og slår dem op mod API
#[tauri::command]
async fn fake_full_scan(app: AppHandle) -> Result<(), String> {
          // 1) Build a list of files to scan (Downloads, Documents, Desktop – limited recursion)
          let mut paths_to_scan: Vec<PathBuf> = Vec::new();

          if let Some(downloads) = dirs::download_dir() {
              for entry in WalkDir::new(downloads)
                  .max_depth(3)
                  .into_iter()
                  .flatten()
              {
                  if entry.file_type().is_file() {
                      paths_to_scan.push(entry.into_path());
                  }
              }
          }

          if let Some(documents) = dirs::document_dir() {
              for entry in WalkDir::new(documents)
                  .max_depth(3)
                  .into_iter()
                  .flatten()
              {
                  if entry.file_type().is_file() {
                      paths_to_scan.push(entry.into_path());
                  }
              }
          }

          if let Some(desktop) = dirs::desktop_dir() {
              for entry in WalkDir::new(desktop)
                  .max_depth(3)
                  .into_iter()
                  .flatten()
              {
                  if entry.file_type().is_file() {
                      paths_to_scan.push(entry.into_path());
                  }
              }
          }

          // Hard test limit: never scan more than 1 file (for debugging)
          const MAX_FILES: usize = 1;
          paths_to_scan.truncate(MAX_FILES);

          let total = paths_to_scan.len();
          if total == 0 {
              // No files to scan → immediately tell UI that scan is finished with no threats
              let _ = app.emit(
                  "scan_finished",
                  ScanFinishedPayload { threats: vec![] },
              );
              return Ok(());
          }

          // 2) Hash all files and emit scan_progress events to the UI
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

              // Small pause so the UI has time to update (especially on very fast scans)
              if i % 100 == 0 {
                  thread::sleep(Duration::from_millis(5));
              }
          }

          // 3) Build batch payload for the Threat API
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

          // 4) Call the Threat API (this is chunked inside call_threat_api_batch)
          let api_results = match call_threat_api_batch(files_for_api) {
              Ok(r) => r,
              Err(e) => {
                  eprintln!("Full scan API error: {e}");
                  // Make sure the UI does not hang if the API fails
                  let _ = app.emit(
                      "scan_finished",
                      ScanFinishedPayload { threats: vec![] },
                  );
                  return Err(e);
              }
          };

          // Map sha256 -> file path for easy lookup when processing API results
          use std::collections::HashMap;

          let mut hash_to_path: HashMap<String, String> = HashMap::new();
          for (_idx, path, hash) in &index_to_path {
              hash_to_path.insert(
                  hash.to_lowercase(),
                  path.to_string_lossy().to_string(),
              );
          }

          // Build the final list of (threat_name, file_path) pairs
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

          // 5) Notify React that the scan is finished + pass the list of threats
          let _ = app.emit(
              "scan_finished",
              ScanFinishedPayload {
                  threats: threats_vec.clone(),
              },
          );

          // 6) Show a system notification when the scan completes
          if !threats_vec.is_empty() {
              let _ = app
                  .notification()
                  .builder()
                  .title("Stellar Antivirus")
                  .body(format!(
                      "Full scan completed – {} threat(s) found.",
                      threats_vec.len()
                  ))
                  .show();
          } else {
              let _ = app
                  .notification()
                  .builder()
                  .title("Stellar Antivirus")
                  .body("Full scan completed – no threats found.")
                  .show();
          }

          Ok(())
      }


#[tauri::command]
fn set_realtime_enabled(enabled: bool) {
    REALTIME_ENABLED.store(enabled, Ordering::SeqCst);
    println!("Realtime protection set to: {enabled}");
}

// Quarantine: flyt filer til karantænemappe
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

        let fname = src.file_name().unwrap_or_else(|| std::ffi::OsStr::new("unknown"));
        let dest = qdir.join(fname);

        if dest.exists() {
            let _ = fs::remove_file(&dest);
        }

        if let Err(e) = fs::rename(&src, &dest) {
            eprintln!("rename failed: {e}, trying copy+delete");
            fs::copy(&src, &dest).and_then(|_| fs::remove_file(&src))
                .map_err(|e2| format!("Failed to quarantine file {original}: {e2}"))?;
        }

        println!("Quarantined file: {src:?} -> {dest:?}");
    }

    Ok(())
}

// Restore fra quarantine tilbage til original path
#[tauri::command]
async fn restore_from_quarantine(items: Vec<RestoreItem>) -> Result<(), String> {
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
        } else {
            println!("Restored file: {src:?} -> {dest:?}");
        }
    }

    Ok(())
}

// Slet filer i quarantine baseret på filnavn (bruges af UI's delete-knap)
#[tauri::command]
async fn delete_quarantine_files(file_names: Vec<String>) -> Result<(), String> {
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
        } else {
            println!("Deleted quarantine file: {:?}", path);
        }
    }

    Ok(())
}

// Ældre helper – sletter baseret på original paths (kan stadig bruges fra UI hvis nødvendigt)
#[tauri::command]
async fn delete_files(paths: Vec<String>) -> Result<(), String> {
    let qdir = quarantine_root();

    for original in paths {
        let fname = Path::new(&original)
            .file_name()
            .unwrap()
            .to_os_string();

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

            let file = path.to_string_lossy().to_string();

            let kind_str = match &event.kind {
                EventKind::Create(_) => "create",
                EventKind::Modify(_) => "modify",
                EventKind::Remove(_) => "remove",
                EventKind::Any => "any",
                _ => "other",
            }
            .to_string();

            // Emit til UI (du logger ikke længere realtime spam i React, men håller event til debugging)
            if let Err(e) = app_handle.emit(
                "realtime_file_event",
                RealtimeFilePayload {
                    file: file.clone(),
                    event: kind_str.clone(),
                },
            ) {
                eprintln!("failed to emit realtime_file_event: {e}");
            }

            // Kun create/modify/any er interessante
            let relevant = matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
            );

            if !relevant {
                continue;
            }

            // Lille pause så editor kan skrive filen færdig
            thread::sleep(Duration::from_millis(20));

            let mut detected_name: Option<String> = None;

            // 1) Testfilregel (filnavn)
            if is_test_filename(path) {
                let test_name = "Stellar.Test.FileNameRule".to_string();
                println!("[Realtime] Test filename rule matched: {}", file);
                detected_name = Some(test_name);
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

                            println!(
                                "[Realtime] API threat detected: {} ({})",
                                name, file
                            );
                            detected_name = Some(name);
                        }
                    }
                    Ok(None) => {
                        // Intet match, alt godt
                    }
                    Err(e) => {
                        eprintln!("[Realtime] API error for {}: {e}", file);
                    }
                }
            }

            // Hvis vi fandt noget → emit event + native notification
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
