use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RecentEntry {
    pub id: String,
    pub absolute_path: String,
    pub mode: String,
    pub last_opened_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecentsFileV1 {
    version: u32,
    entries: Vec<RecentEntry>,
}

pub const RECENTS_MAX: usize = 10;

/// Load recents from `recents.json` at the given path.
/// Returns empty Vec on missing file. Migrates v0 (bare array) to v1.
/// Unknown future versions: return empty Vec (disable gracefully).
pub fn load_recents(recents_path: &Path) -> Vec<RecentEntry> {
    let content = match std::fs::read_to_string(recents_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Try v1 format first
    if let Ok(v1) = serde_json::from_str::<RecentsFileV1>(&content) {
        match v1.version {
            1 => return v1.entries,
            v if v > 1 => {
                // Future version: disable gracefully
                return Vec::new();
            }
            _ => {}
        }
    }

    // Try v0: bare array of strings (paths)
    if let Ok(paths) = serde_json::from_str::<Vec<String>>(&content) {
        // Migrate v0: generate synthetic ids and timestamps
        return paths
            .into_iter()
            .map(|p| RecentEntry {
                id: Uuid::new_v4().to_string(),
                absolute_path: p,
                mode: "basic".to_string(),
                last_opened_at: "1970-01-01T00:00:00.000Z".to_string(),
            })
            .collect();
    }

    // Unrecognized format: disable gracefully
    Vec::new()
}

/// Save recents to `recents.json` atomically (write-tmp → rename).
/// Enforces max 10 entries (oldest evicted = earliest lastOpenedAt).
pub fn save_recents(recents_path: &Path, entries: Vec<RecentEntry>) -> std::io::Result<()> {
    // Evict oldest if over limit (sort by lastOpenedAt descending, keep first 10)
    let mut entries = entries;
    entries.sort_by(|a, b| b.last_opened_at.cmp(&a.last_opened_at));
    entries.truncate(RECENTS_MAX);

    let file = RecentsFileV1 { version: 1, entries };
    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Atomic write: write to tmp then rename
    let tmp_path = recents_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, recents_path)?;
    Ok(())
}

/// Add or update an entry in the recents list (push to front, deduplicate by path).
pub fn push_recent(recents_path: &Path, entry: RecentEntry) -> std::io::Result<()> {
    let mut entries = load_recents(recents_path);
    // Remove existing entry with same path
    entries.retain(|e| e.absolute_path != entry.absolute_path);
    // Add new at beginning
    entries.insert(0, entry);
    save_recents(recents_path, entries)
}

/// Remove a recent entry by id.
pub fn remove_recent(recents_path: &Path, id: &str) -> std::io::Result<()> {
    let mut entries = load_recents(recents_path);
    entries.retain(|e| e.id != id);
    save_recents(recents_path, entries)
}

/// Clear all recents.
pub fn clear_recents(recents_path: &Path) -> std::io::Result<()> {
    save_recents(recents_path, Vec::new())
}

/// App settings persisted to `settings.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    #[serde(default = "default_mode")]
    pub default_mode: String,
    #[serde(default = "default_true")]
    pub auto_append_gitignore: bool,
    #[serde(default = "default_false")]
    pub mask_values: bool,
    #[serde(default = "default_argon2_t")]
    pub argon2_t: u32,
    #[serde(default = "default_argon2_m")]
    pub argon2_m: u32,
    #[serde(default = "default_argon2_p")]
    pub argon2_p: u32,
}

fn default_mode() -> String {
    "basic".to_string()
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_argon2_t() -> u32 {
    3
}
fn default_argon2_m() -> u32 {
    65536
}
fn default_argon2_p() -> u32 {
    4
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            default_mode: default_mode(),
            auto_append_gitignore: default_true(),
            mask_values: default_false(),
            argon2_t: default_argon2_t(),
            argon2_m: default_argon2_m(),
            argon2_p: default_argon2_p(),
        }
    }
}

pub fn load_settings(settings_path: &Path) -> AppSettings {
    let content = match std::fs::read_to_string(settings_path) {
        Ok(c) => c,
        Err(_) => return AppSettings::default(),
    };
    serde_json::from_str(&content).unwrap_or_default()
}

pub fn save_settings(settings_path: &Path, settings: &AppSettings) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tmp_path = settings_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, settings_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn temp_recents_path() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recents.json");
        (dir, path)
    }

    fn make_entry(id: &str, path: &str, ts: &str) -> RecentEntry {
        RecentEntry {
            id: id.to_string(),
            absolute_path: path.to_string(),
            mode: "basic".to_string(),
            last_opened_at: ts.to_string(),
        }
    }

    #[test]
    fn recents_write_read_roundtrip() {
        let (_dir, path) = temp_recents_path();
        let entry = make_entry("abc-123", "/vault/test.env.sealed", "2026-01-01T00:00:00.000Z");
        save_recents(&path, vec![entry.clone()]).unwrap();
        let loaded = load_recents(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], entry);
    }

    #[test]
    fn recents_max_10_eviction() {
        let (_dir, path) = temp_recents_path();
        let mut entries = Vec::new();
        for i in 0..11 {
            // Use timestamps that sort clearly: oldest = "2026-01-01", newest = "2026-01-11"
            let ts = format!("2026-01-{:02}T00:00:00.000Z", i + 1);
            entries.push(make_entry(&format!("id-{}", i), &format!("/vault/{}.sealed", i), &ts));
        }
        save_recents(&path, entries).unwrap();
        let loaded = load_recents(&path);
        assert_eq!(loaded.len(), 10);
        // Oldest (2026-01-01) should be evicted
        assert!(!loaded.iter().any(|e| e.last_opened_at == "2026-01-01T00:00:00.000Z"));
    }

    #[test]
    fn recents_missing_file_returns_empty() {
        let (_dir, path) = temp_recents_path();
        let entries = load_recents(&path);
        assert!(entries.is_empty());
    }

    #[test]
    fn recents_v0_migration() {
        let (_dir, path) = temp_recents_path();
        // Write v0: bare array of strings
        let v0 = r#"["/vault/old.sealed"]"#;
        fs::write(&path, v0).unwrap();
        let entries = load_recents(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].absolute_path, "/vault/old.sealed");
        // id should be a UUID (non-empty)
        assert!(!entries[0].id.is_empty());
    }

    #[test]
    fn recents_unknown_version_returns_empty() {
        let (_dir, path) = temp_recents_path();
        let future_version = r#"{"version":99,"entries":[]}"#;
        fs::write(&path, future_version).unwrap();
        let entries = load_recents(&path);
        assert!(entries.is_empty());
    }

    #[test]
    fn recents_atomic_write_does_not_leave_tmp() {
        let (_dir, path) = temp_recents_path();
        save_recents(&path, vec![]).unwrap();
        let tmp = path.with_extension("json.tmp");
        // tmp file should not exist after successful save
        assert!(!tmp.exists());
    }
}
