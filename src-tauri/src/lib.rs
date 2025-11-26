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

use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

// global flag der styrer om vi emitter realtime events
static REALTIME_ENABLED: AtomicBool = AtomicBool::new(true);

#[derive(Serialize, Clone)]
struct ScanProgressPayload {
    file: String,
    current: usize,
    total: usize,
}

#[derive(Serialize, Clone)]
struct ScanFinishedPayload {
    threats: Vec<(String, String)>,
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

// ---- Helpers ----

fn quarantine_root() -> PathBuf {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    base_dir.join("StellarAntivirus").join("Quarantine")
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

        if let Err(e) = app.emit(
            "scan_progress",
            ScanProgressPayload {
                file: file_str.clone(),
                current: i + 1,
                total,
            },
        ) {
            eprintln!("failed to emit scan_progress: {e}");
        }

        let lower = file_str.to_lowercase();
        if lower.contains("crack") || lower.contains("patch") || lower.ends_with(".exe") {
            let name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            threats.push((name, file_str.clone()));
        }

        thread::sleep(Duration::from_millis(10));
    }

    if let Err(e) = app.emit("scan_finished", ScanFinishedPayload { threats }) {
        eprintln!("failed to emit scan_finished: {e}");
    }

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

        // Hvis der allerede er en fil med samme navn i quarantine, slet den gamle
        if dest.exists() {
            if let Err(e) = fs::remove_file(&dest) {
                eprintln!("failed to remove existing quarantine file {:?}: {e}", dest);
            }
        }

        let rename_result = fs::rename(&src, &dest);
        if let Err(e) = rename_result {
            eprintln!("rename failed ({src:?} -> {dest:?}): {e}, trying copy+delete");
            if let Err(e2) = fs::copy(&src, &dest)
                .and_then(|_| fs::remove_file(&src))
            {
                eprintln!("copy+delete also failed for {src:?}: {e2}");
                return Err(format!(
                    "Failed to quarantine file {original}: {e2}"
                ));
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
            eprintln!(
                "quarantine file does not exist for restore: {:?}",
                src
            );
            continue;
        }

        let dest = PathBuf::from(&item.original_path);

        if let Some(parent) = dest.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("failed to create dest parent dir {:?}: {e}", parent);
            }
        }

        // Hvis der allerede ligger noget på original path, så omdøb det til .stellar_backup
        if dest.exists() {
            let backup = dest
                .with_extension("stellar_backup");
            if let Err(e) = fs::rename(&dest, &backup) {
                eprintln!(
                    "failed to backup existing file before restore ({dest:?} -> {backup:?}): {e}"
                );
            }
        }

        let rename_result = fs::rename(&src, &dest);
        if let Err(e) = rename_result {
            eprintln!("restore rename failed ({src:?} -> {dest:?}): {e}, trying copy+delete");
            if let Err(e2) = fs::copy(&src, &dest)
                .and_then(|_| fs::remove_file(&src))
            {
                eprintln!("restore copy+delete also failed for {src:?}: {e2}");
                return Err(format!(
                    "Failed to restore file {} to {}: {e2}",
                    item.file_name,
                    item.original_path
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

            if let Err(e) = app_handle.emit(
                "realtime_file_event",
                RealtimeFilePayload {
                    file,
                    event: kind_str,
                },
            ) {
                eprintln!("failed to emit realtime_file_event: {e}");
            }
        }
    });
}

// ---- App entry ----

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            fake_full_scan,
            set_realtime_enabled,
            quarantine_files,
            restore_from_quarantine,
            delete_quarantine_files,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            start_realtime_watcher(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
