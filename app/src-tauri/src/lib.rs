pub mod init;
pub mod sealed;
pub mod workspace;

use std::sync::Mutex;

pub struct AppState {
    pub ops_cache: Mutex<sealed::totp::OpsCache>,
    pub app_data_dir: Mutex<Option<std::path::PathBuf>>,
}

#[cfg(not(test))]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            ops_cache: Mutex::new(sealed::totp::OpsCache::new()),
            app_data_dir: Mutex::new(None),
        })
        .setup(|app| {
            use tauri::Manager;
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("app_data_dir must be available");
            std::fs::create_dir_all(&data_dir).expect("create app_data_dir");
            *app.state::<AppState>().app_data_dir.lock().unwrap() = Some(data_dir);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            init::init_keys,
            init::inspect_directory,
            init::read_env_file,
            init::seal_file,
            init::ensure_gitignore,
            init::get_recents,
            init::push_recent,
            init::remove_recent,
            init::clear_recents,
            init::get_settings,
            init::save_settings,
            init::open_sealed_file,
            init::decrypt_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
