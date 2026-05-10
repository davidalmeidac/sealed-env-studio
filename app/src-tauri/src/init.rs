use crate::sealed::{
    crypto,
    errors::SealedError,
    format::{KdfParams, SealedMode},
    SealParams,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ======================================================================
// Request / Response types
// ======================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitKeysRequest {
    pub mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitKeysResponse {
    pub master_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectDirectoryRequest {
    pub folder_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedTemplate {
    pub file_name: String,
    pub absolute_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectDirectoryResponse {
    pub detected_templates: Vec<DetectedTemplate>,
    pub existing_sealed_files: Vec<String>,
    pub has_gitignore: bool,
    pub gitignore_covers_env: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadEnvFileRequest {
    pub absolute_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadEnvFileResponse {
    pub raw_content: String,
    pub detected_format: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealFileRequest {
    pub mode: String,
    pub output_path: String,
    pub raw_dotenv: String,
    pub master_key_hex: String,
    pub signing_key_hex: Option<String>,
    pub totp_secret_hex: Option<String>,
    pub argon2: Option<Argon2Params>,
}

#[derive(Debug, Deserialize)]
pub struct Argon2Params {
    pub t: u32,
    pub m: u32,
    pub p: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealFileResponse {
    pub absolute_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureGitignoreRequest {
    pub folder_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureGitignoreResponse {
    pub modified: bool,
}

// ======================================================================
// Hex validation
// ======================================================================

fn validate_hex(s: &str, expected_bytes: usize) -> Result<Vec<u8>, SealedError> {
    if s.len() != expected_bytes * 2 {
        return Err(SealedError::ValidationError(format!(
            "expected {} hex chars, got {}",
            expected_bytes * 2,
            s.len()
        )));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SealedError::ValidationError(
            "invalid hex characters".to_string(),
        ));
    }
    hex::decode(s).map_err(|e| SealedError::ValidationError(e.to_string()))
}

fn parse_mode(mode_str: &str) -> Result<SealedMode, SealedError> {
    match mode_str {
        "basic" => Ok(SealedMode::Basic),
        "team" => Ok(SealedMode::Team),
        "enterprise" => Ok(SealedMode::Enterprise),
        other => Err(SealedError::ValidationError(format!(
            "unknown mode: {}",
            other
        ))),
    }
}

// ======================================================================
// Tauri command handlers (thin adapters; logic in sealed::* / workspace)
// ======================================================================

/// Generate new cryptographic keys for the given mode.
#[tauri::command]
pub fn init_keys(req: InitKeysRequest) -> Result<InitKeysResponse, SealedError> {
    let mode = parse_mode(&req.mode)?;

    let master_key = crypto::random_bytes(32);
    let master_key_hex = hex::encode(&master_key);

    match mode {
        SealedMode::Basic => Ok(InitKeysResponse {
            master_key_hex,
            signing_key_hex: None,
            totp_secret_hex: None,
        }),
        SealedMode::Team => {
            let signing_key = crypto::random_bytes(32);
            Ok(InitKeysResponse {
                master_key_hex,
                signing_key_hex: Some(hex::encode(&signing_key)),
                totp_secret_hex: None,
            })
        }
        SealedMode::Enterprise => {
            let signing_key = crypto::random_bytes(32);
            let totp_secret = crypto::random_bytes(20);
            Ok(InitKeysResponse {
                master_key_hex,
                signing_key_hex: Some(hex::encode(&signing_key)),
                totp_secret_hex: Some(hex::encode(&totp_secret)),
            })
        }
    }
}

/// Inspect a directory for .env templates and existing .env.sealed siblings.
#[tauri::command]
pub fn inspect_directory(req: InspectDirectoryRequest) -> Result<InspectDirectoryResponse, SealedError> {
    let folder = Path::new(&req.folder_path);

    if !folder.is_dir() {
        return Err(SealedError::ValidationError(format!(
            "not a directory: {}",
            req.folder_path
        )));
    }

    let mut detected_templates: Vec<DetectedTemplate> = Vec::new();
    let mut existing_sealed_files: Vec<String> = Vec::new();
    let mut has_gitignore = false;
    let mut gitignore_covers_env = false;

    let entries = std::fs::read_dir(folder)
        .map_err(|e| SealedError::ValidationError(e.to_string()))?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let abs = entry.path().to_string_lossy().to_string();

        if name_str == ".gitignore" {
            has_gitignore = true;
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                gitignore_covers_env = content
                    .lines()
                    .any(|l| l.trim() == ".env" || l.trim() == "*.env");
            }
        } else if name_str.ends_with(".env.example")
            || name_str.ends_with(".env.template")
            || name_str == ".env"
        {
            detected_templates.push(DetectedTemplate {
                file_name: name_str,
                absolute_path: abs,
            });
        } else if name_str.ends_with(".env.sealed") {
            existing_sealed_files.push(abs);
        }
    }

    Ok(InspectDirectoryResponse {
        detected_templates,
        existing_sealed_files,
        has_gitignore,
        gitignore_covers_env,
    })
}

/// Read a .env file from disk (raw content only; no parsing).
#[tauri::command]
pub fn read_env_file(req: ReadEnvFileRequest) -> Result<ReadEnvFileResponse, SealedError> {
    let content = std::fs::read_to_string(&req.absolute_path)
        .map_err(|e| SealedError::ValidationError(e.to_string()))?;
    Ok(ReadEnvFileResponse {
        raw_content: content,
        detected_format: "dotenv".to_string(),
    })
}

/// Seal a .env file and write it to disk.
#[tauri::command]
pub fn seal_file(req: SealFileRequest) -> Result<SealFileResponse, SealedError> {
    let mode = parse_mode(&req.mode)?;

    // Validate + decode master key (must be 32 bytes = 64 hex chars)
    let master_key = validate_hex(&req.master_key_hex, 32)?;

    let signing_key = req
        .signing_key_hex
        .as_deref()
        .map(|s| validate_hex(s, 32))
        .transpose()?;

    let totp_secret = req
        .totp_secret_hex
        .as_deref()
        .map(|s| validate_hex(s, 20))
        .transpose()?;

    let kdf_params = if let Some(a) = req.argon2 {
        KdfParams::Argon2id {
            t: a.t,
            m: a.m,
            p: a.p,
        }
    } else {
        KdfParams::Argon2id {
            t: crypto::ARGON2_T_DEFAULT,
            m: crypto::ARGON2_M_DEFAULT,
            p: crypto::ARGON2_P_DEFAULT,
        }
    };

    let sealed_content = crate::sealed::seal(SealParams {
        mode,
        plaintext: req.raw_dotenv,
        master_key,
        signing_key,
        totp_secret,
        kdf_params,
    })?;

    let bytes = sealed_content.as_bytes();
    std::fs::write(&req.output_path, bytes)
        .map_err(|e| SealedError::ValidationError(e.to_string()))?;

    Ok(SealFileResponse {
        absolute_path: req.output_path,
        bytes_written: bytes.len(),
    })
}

/// Ensure `.env` is in `.gitignore`. Idempotent.
#[tauri::command]
pub fn ensure_gitignore(req: EnsureGitignoreRequest) -> Result<EnsureGitignoreResponse, SealedError> {
    let folder = Path::new(&req.folder_path);
    let gitignore_path = folder.join(".gitignore");

    let mut content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();

    let already_covered = content
        .lines()
        .any(|l| l.trim() == ".env" || l.trim() == "*.env");

    if already_covered {
        return Ok(EnsureGitignoreResponse { modified: false });
    }

    if !content.ends_with('\n') && !content.is_empty() {
        content.push('\n');
    }
    content.push_str(".env\n");

    std::fs::write(&gitignore_path, &content)
        .map_err(|e| SealedError::ValidationError(e.to_string()))?;

    Ok(EnsureGitignoreResponse { modified: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_keys_basic_returns_only_master() {
        let resp = init_keys(InitKeysRequest { mode: "basic".to_string() }).unwrap();
        assert_eq!(resp.master_key_hex.len(), 64);
        assert!(resp.signing_key_hex.is_none());
        assert!(resp.totp_secret_hex.is_none());
    }

    #[test]
    fn init_keys_team_returns_two_keys() {
        let resp = init_keys(InitKeysRequest { mode: "team".to_string() }).unwrap();
        assert_eq!(resp.master_key_hex.len(), 64);
        assert!(resp.signing_key_hex.is_some());
        assert_eq!(resp.signing_key_hex.unwrap().len(), 64);
        assert!(resp.totp_secret_hex.is_none());
    }

    #[test]
    fn init_keys_enterprise_returns_three_keys() {
        let resp = init_keys(InitKeysRequest { mode: "enterprise".to_string() }).unwrap();
        assert_eq!(resp.master_key_hex.len(), 64);
        assert!(resp.signing_key_hex.is_some());
        assert_eq!(resp.signing_key_hex.unwrap().len(), 64);
        assert!(resp.totp_secret_hex.is_some());
        // 20 bytes = 40 hex chars
        assert_eq!(resp.totp_secret_hex.unwrap().len(), 40);
    }

    #[test]
    fn seal_file_rejects_bad_hex_master_key() {
        let result = seal_file(SealFileRequest {
            mode: "basic".to_string(),
            output_path: "/tmp/test.env.sealed".to_string(),
            raw_dotenv: "KEY=val\n".to_string(),
            master_key_hex: "zzzz".to_string(),
            signing_key_hex: None,
            totp_secret_hex: None,
            argon2: None,
        });
        match result {
            Err(SealedError::ValidationError(_)) => {}
            other => panic!("expected ValidationError, got {:?}", other),
        }
    }

    #[test]
    fn ensure_gitignore_idempotent() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let folder = dir.path().to_str().unwrap().to_string();

        // First call: creates .gitignore
        let resp1 = ensure_gitignore(EnsureGitignoreRequest { folder_path: folder.clone() }).unwrap();
        assert!(resp1.modified);

        // Second call: idempotent
        let resp2 = ensure_gitignore(EnsureGitignoreRequest { folder_path: folder }).unwrap();
        assert!(!resp2.modified);
    }

    #[test]
    fn inspect_directory_returns_templates_and_sealed() {
        use tempfile::TempDir;
        use std::fs;
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=val").unwrap();
        fs::write(dir.path().join("app.env.sealed"), "SEALED-ENV-V1 MODE=basic\n").unwrap();

        let resp = inspect_directory(InspectDirectoryRequest {
            folder_path: dir.path().to_str().unwrap().to_string(),
        })
        .unwrap();

        assert_eq!(resp.detected_templates.len(), 1);
        assert_eq!(resp.detected_templates[0].file_name, ".env.example");
        assert_eq!(resp.existing_sealed_files.len(), 1);
    }
}
