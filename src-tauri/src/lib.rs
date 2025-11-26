use std::{fs, path::PathBuf, thread, time::Duration};

use serde::Serialize;
use tauri::{AppHandle, Emitter}; // 👈 VIGTIG: Emitter trait

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

        // Emit progress event
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
        if lower.contains("crack")
            || lower.contains("patch")
            || lower.ends_with(".exe")
        {
            let name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            threats.push((name, file_str.clone()));
        }

        thread::sleep(Duration::from_millis(10));
    }

    // Emit finished event
    if let Err(e) = app.emit(
        "scan_finished",
        ScanFinishedPayload { threats },
    ) {
        eprintln!("failed to emit scan_finished: {e}");
    }

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![fake_full_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
