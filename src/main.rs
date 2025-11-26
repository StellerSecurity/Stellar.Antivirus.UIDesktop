#![cfg_attr(
    all(not(debug_assertions), target_os = "macos"),
    windows_subsystem = "macos"
)]

use tauri::{Manager, SystemTray, SystemTrayEvent, SystemTrayMenu};
use std::sync::Mutex;

#[derive(Clone, serde::Serialize)]
enum TrayStatus {
    Protected,
    NotProtected,
    Scanning,
}

struct AppState {
    tray_status: TrayStatus,
}

#[tauri::command]
fn set_tray_status(state: tauri::State<Mutex<AppState>>, status: String, app: tauri::AppHandle) {
    let mut s = state.lock().unwrap();
    s.tray_status = match status.as_str() {
        "protected" => TrayStatus::Protected,
        "scanning" => TrayStatus::Scanning,
        _ => TrayStatus::NotProtected,
    };

    // vælg ikon alt efter status (tre forskellige .png / .icns)
    let icon_name = match s.tray_status {
        TrayStatus::Protected => "tray_protected",
        TrayStatus::Scanning => "tray_scanning",
        TrayStatus::NotProtected => "tray_not_protected",
    };

    let icon = tauri::Icon::Raw(
        include_bytes!("../icons/tray_protected.png").to_vec()
    );
    // du kan bruge match til at include forskellige icons

    app.tray_handle().set_icon(Some(icon)).ok();
}

fn main() {
    let tray = SystemTray::new().with_menu(SystemTrayMenu::new());

    tauri::Builder::default()
        .system_tray(tray)
        .manage(Mutex::new(AppState {
            tray_status: TrayStatus::Protected,
        }))
        .on_system_tray_event(|_app, _event| {
            // evt. åbne hovedvindue ved klik
        })
        .invoke_handler(tauri::generate_handler![set_tray_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
