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

use serde::Serialize;
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

// ---- Realtime watcher (FSEvents via notify) ----

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
            set_realtime_enabled
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            start_realtime_watcher(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
