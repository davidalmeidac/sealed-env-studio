//! Credential store — Tier A persistence for vault keys.
//!
//! Stores the (master, signing?, totp?) tuple for a vault in the OS Credential
//! Manager (Windows DPAPI / macOS Keychain / Linux Secret Service via D-Bus),
//! wrapped by a passphrase-derived key (Argon2id → AES-256-GCM).
//!
//! Threat model:
//!  - OS keychain alone defends against filesystem-read malware.
//!  - Passphrase wrap defends against keychain-dump tools (Mimikatz, etc).
//!  - Vault ID in AAD prevents "swap blob between vaults" attacks: the
//!    ciphertext stored for vault A cannot decrypt as creds of vault B even
//!    if both share the same passphrase.
//!
//! Cross-stack: the blob format is intentionally readable by a future Node
//! CLI opt-in integration. See `../sealed-env/COORDINATION.md` §Credential
//! storage policy.

use crate::sealed::crypto;
use crate::sealed::errors::SealedError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Service name used as the keyring namespace.
const KEYRING_SERVICE: &str = "sealed-env-studio";

/// Wire-format magic header for the persisted blob.
const BLOB_MAGIC: &str = "SEALED-CREDS-V1";

/// Argon2id params for passphrase wrap. Lighter than the vault KDF (p=2 vs p=4)
/// because passphrase wrap runs twice per session (save + unlock), vault KDF runs
/// once. m=64MB keeps GPU/ASIC parallel attacks expensive.
const ARGON2_T: u32 = 3;
const ARGON2_M: u32 = 65536;
const ARGON2_P: u32 = 2;

const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;

/// In-memory representation of the unwrapped credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    pub master: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signing: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub totp: Option<String>,
    pub saved_at: String,
}

/// Compute a stable vault ID from the absolute path of the `.env.sealed` file.
/// `sha256(absolute_path_utf8)` → hex string. Stable across sessions, no collisions
/// for distinct paths, no plaintext path stored in the keychain entry name.
pub fn compute_vault_id(absolute_path: &str) -> String {
    let mut h = Sha256::new();
    h.update(absolute_path.as_bytes());
    hex::encode(h.finalize())
}

/// Encrypt the credentials blob with a passphrase-derived key, binding the
/// `vault_id` as AAD so the ciphertext cannot be replayed under a different vault.
pub fn seal_blob(
    vault_id: &str,
    creds: &Credentials,
    passphrase: &str,
) -> Result<String, SealedError> {
    if passphrase.is_empty() {
        return Err(SealedError::ValidationError(
            "passphrase must not be empty".to_string(),
        ));
    }

    let salt = crypto::random_bytes(SALT_BYTES);
    let nonce = crypto::random_bytes(NONCE_BYTES);

    let kdf_params = crate::sealed::format::KdfParams::Argon2id {
        t: ARGON2_T,
        m: ARGON2_M,
        p: ARGON2_P,
    };
    let key = crypto::kdf_derive(passphrase.as_bytes(), &salt, &kdf_params)?;

    let plaintext = serde_json::to_vec(creds)
        .map_err(|e| SealedError::ValidationError(format!("serialize credentials: {}", e)))?;

    let ciphertext = crypto::aes256gcm_encrypt(&key, &nonce, &plaintext, vault_id.as_bytes());

    Ok(format!(
        "{}\nSALT={}\nKDF-PARAMS=t={},m={},p={}\nNONCE={}\nCIPHERTEXT={}",
        BLOB_MAGIC,
        B64.encode(&salt),
        ARGON2_T,
        ARGON2_M,
        ARGON2_P,
        B64.encode(&nonce),
        B64.encode(&ciphertext),
    ))
}

/// Decrypt a blob produced by `seal_blob` under the same vault_id.
/// On any cryptographic failure (bad passphrase, wrong vault_id, tampered
/// ciphertext) returns `DecryptFailed` per oracle-defense convention.
pub fn unseal_blob(
    vault_id: &str,
    blob: &str,
    passphrase: &str,
) -> Result<Credentials, SealedError> {
    let parsed = parse_blob(blob)?;
    let kdf_params = crate::sealed::format::KdfParams::Argon2id {
        t: parsed.argon2_t,
        m: parsed.argon2_m,
        p: parsed.argon2_p,
    };

    let key = crypto::kdf_derive(passphrase.as_bytes(), &parsed.salt, &kdf_params)
        .map_err(|_| SealedError::DecryptFailed)?;

    let plaintext = crypto::aes256gcm_decrypt(
        &key,
        &parsed.nonce,
        &parsed.ciphertext,
        vault_id.as_bytes(),
    )
    .map_err(|_| SealedError::DecryptFailed)?;

    let creds: Credentials = serde_json::from_slice(&plaintext)
        .map_err(|_| SealedError::DecryptFailed)?;

    Ok(creds)
}

struct ParsedBlob {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    argon2_t: u32,
    argon2_m: u32,
    argon2_p: u32,
}

fn parse_blob(blob: &str) -> Result<ParsedBlob, SealedError> {
    let mut lines = blob.lines();
    let magic = lines.next().ok_or(SealedError::FormatInvalid)?;
    if magic != BLOB_MAGIC {
        return Err(SealedError::FormatInvalid);
    }

    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut ciphertext: Option<Vec<u8>> = None;
    let mut kdf_t: Option<u32> = None;
    let mut kdf_m: Option<u32> = None;
    let mut kdf_p: Option<u32> = None;

    for line in lines {
        let (key, value) = line.split_once('=').ok_or(SealedError::FormatInvalid)?;
        match key {
            "SALT" => salt = Some(B64.decode(value).map_err(|_| SealedError::FormatInvalid)?),
            "NONCE" => nonce = Some(B64.decode(value).map_err(|_| SealedError::FormatInvalid)?),
            "CIPHERTEXT" => {
                ciphertext = Some(B64.decode(value).map_err(|_| SealedError::FormatInvalid)?)
            }
            "KDF-PARAMS" => {
                for part in value.split(',') {
                    let (k, v) = part.split_once('=').ok_or(SealedError::FormatInvalid)?;
                    let n: u32 = v.parse().map_err(|_| SealedError::FormatInvalid)?;
                    match k {
                        "t" => kdf_t = Some(n),
                        "m" => kdf_m = Some(n),
                        "p" => kdf_p = Some(n),
                        _ => return Err(SealedError::FormatInvalid),
                    }
                }
            }
            _ => return Err(SealedError::FormatInvalid),
        }
    }

    Ok(ParsedBlob {
        salt: salt.ok_or(SealedError::FormatInvalid)?,
        nonce: nonce.ok_or(SealedError::FormatInvalid)?,
        ciphertext: ciphertext.ok_or(SealedError::FormatInvalid)?,
        argon2_t: kdf_t.ok_or(SealedError::FormatInvalid)?,
        argon2_m: kdf_m.ok_or(SealedError::FormatInvalid)?,
        argon2_p: kdf_p.ok_or(SealedError::FormatInvalid)?,
    })
}

// =====================================================================
// OS keyring wrapper
// =====================================================================
//
// All keyring errors except "no entry" map to `ValidationError(String)` —
// the OS-level keychain is a hard dependency, so failures are operator-visible
// (keychain locked, no D-Bus service, permission denied, etc.) rather than
// oracle-defended.

fn keyring_entry(vault_id: &str) -> Result<keyring::Entry, SealedError> {
    keyring::Entry::new(KEYRING_SERVICE, vault_id)
        .map_err(|e| SealedError::ValidationError(format!("keyring init: {}", e)))
}

pub fn keystore_set(vault_id: &str, blob: &str) -> Result<(), SealedError> {
    let entry = keyring_entry(vault_id)?;
    entry
        .set_password(blob)
        .map_err(|e| SealedError::ValidationError(format!("keyring set: {}", e)))
}

pub fn keystore_get(vault_id: &str) -> Result<Option<String>, SealedError> {
    let entry = keyring_entry(vault_id)?;
    match entry.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(SealedError::ValidationError(format!("keyring get: {}", e))),
    }
}

pub fn keystore_has(vault_id: &str) -> Result<bool, SealedError> {
    Ok(keystore_get(vault_id)?.is_some())
}

pub fn keystore_delete(vault_id: &str) -> Result<(), SealedError> {
    let entry = keyring_entry(vault_id)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SealedError::ValidationError(format!(
            "keyring delete: {}",
            e
        ))),
    }
}

// =====================================================================
// Tauri commands
// =====================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveCredsRequest {
    pub absolute_path: String,
    pub credentials: Credentials,
    pub passphrase: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadCredsRequest {
    pub absolute_path: String,
    pub passphrase: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HasCredsRequest {
    pub absolute_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearCredsRequest {
    pub absolute_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassphraseRequest {
    pub absolute_path: String,
    pub old_passphrase: String,
    pub new_passphrase: String,
}

#[tauri::command]
pub fn save_vault_credentials(req: SaveCredsRequest) -> Result<(), SealedError> {
    let vault_id = compute_vault_id(&req.absolute_path);
    let blob = seal_blob(&vault_id, &req.credentials, &req.passphrase)?;
    keystore_set(&vault_id, &blob)
}

#[tauri::command]
pub fn load_vault_credentials(req: LoadCredsRequest) -> Result<Credentials, SealedError> {
    let vault_id = compute_vault_id(&req.absolute_path);
    let blob = keystore_get(&vault_id)?.ok_or(SealedError::MissingKey)?;
    unseal_blob(&vault_id, &blob, &req.passphrase)
}

#[tauri::command]
pub fn has_vault_credentials(req: HasCredsRequest) -> Result<bool, SealedError> {
    let vault_id = compute_vault_id(&req.absolute_path);
    keystore_has(&vault_id)
}

#[tauri::command]
pub fn clear_vault_credentials(req: ClearCredsRequest) -> Result<(), SealedError> {
    let vault_id = compute_vault_id(&req.absolute_path);
    keystore_delete(&vault_id)
}

#[tauri::command]
pub fn change_passphrase(req: ChangePassphraseRequest) -> Result<(), SealedError> {
    let vault_id = compute_vault_id(&req.absolute_path);
    let blob = keystore_get(&vault_id)?.ok_or(SealedError::MissingKey)?;
    let creds = unseal_blob(&vault_id, &blob, &req.old_passphrase)?;
    let new_blob = seal_blob(&vault_id, &creds, &req.new_passphrase)?;
    keystore_set(&vault_id, &new_blob)
}

// =====================================================================
// Tests (crypto roundtrip only — keystore I/O requires OS interaction)
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn enterprise_creds() -> Credentials {
        Credentials {
            master: "4242424242424242424242424242424242424242424242424242424242424242".to_string(),
            signing: Some(
                "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            ),
            totp: Some("abababababababababababababababababababab".to_string()),
            saved_at: "2026-05-11T00:00:00.000Z".to_string(),
        }
    }

    fn basic_creds() -> Credentials {
        Credentials {
            master: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            signing: None,
            totp: None,
            saved_at: "2026-05-11T00:00:00.000Z".to_string(),
        }
    }

    #[test]
    fn vault_id_is_sha256_of_path() {
        let id = compute_vault_id("/abs/path/.env.sealed");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn vault_id_is_deterministic() {
        let id1 = compute_vault_id("/abs/path/.env.sealed");
        let id2 = compute_vault_id("/abs/path/.env.sealed");
        assert_eq!(id1, id2);
    }

    #[test]
    fn vault_id_differs_per_path() {
        let id1 = compute_vault_id("/abs/path/a/.env.sealed");
        let id2 = compute_vault_id("/abs/path/b/.env.sealed");
        assert_ne!(id1, id2);
    }

    #[test]
    fn seal_unseal_roundtrip_enterprise() {
        let creds = enterprise_creds();
        let vault_id = compute_vault_id("/test/vault.env.sealed");
        let blob = seal_blob(&vault_id, &creds, "correct-horse-battery-staple").unwrap();
        let restored = unseal_blob(&vault_id, &blob, "correct-horse-battery-staple").unwrap();
        assert_eq!(restored, creds);
    }

    #[test]
    fn seal_unseal_roundtrip_basic_master_only() {
        let creds = basic_creds();
        let vault_id = compute_vault_id("/test/basic.env.sealed");
        let blob = seal_blob(&vault_id, &creds, "pw1").unwrap();
        let restored = unseal_blob(&vault_id, &blob, "pw1").unwrap();
        assert_eq!(restored, creds);
        assert_eq!(restored.signing, None);
        assert_eq!(restored.totp, None);
    }

    #[test]
    fn unseal_with_wrong_passphrase_fails() {
        let creds = enterprise_creds();
        let vault_id = compute_vault_id("/test/vault.env.sealed");
        let blob = seal_blob(&vault_id, &creds, "right-pass").unwrap();
        let result = unseal_blob(&vault_id, &blob, "wrong-pass");
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }

    #[test]
    fn unseal_with_wrong_vault_id_fails() {
        // AAD binding: blob for vault A must not decrypt as creds of vault B
        let creds = enterprise_creds();
        let vault_a = compute_vault_id("/test/vault-a.env.sealed");
        let vault_b = compute_vault_id("/test/vault-b.env.sealed");
        let blob = seal_blob(&vault_a, &creds, "same-pass").unwrap();
        let result = unseal_blob(&vault_b, &blob, "same-pass");
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        let creds = enterprise_creds();
        let vault_id = compute_vault_id("/test/vault.env.sealed");
        let mut blob = seal_blob(&vault_id, &creds, "pp").unwrap();
        // Flip one char in the ciphertext line
        let ct_line_pos = blob.find("CIPHERTEXT=").unwrap() + "CIPHERTEXT=".len();
        let b = blob.as_bytes()[ct_line_pos];
        let new_b = if b == b'A' { b'B' } else { b'A' };
        // SAFETY: ASCII-only base64 chars, single byte replacement
        unsafe {
            blob.as_bytes_mut()[ct_line_pos] = new_b;
        }
        let result = unseal_blob(&vault_id, &blob, "pp");
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }

    #[test]
    fn blob_format_starts_with_magic() {
        let creds = basic_creds();
        let vault_id = compute_vault_id("/x");
        let blob = seal_blob(&vault_id, &creds, "p").unwrap();
        assert!(blob.starts_with(BLOB_MAGIC));
    }

    #[test]
    fn blob_has_all_required_fields() {
        let creds = basic_creds();
        let blob = seal_blob(&compute_vault_id("/x"), &creds, "p").unwrap();
        assert!(blob.contains("\nSALT="));
        assert!(blob.contains("\nKDF-PARAMS=t=3,m=65536,p=2"));
        assert!(blob.contains("\nNONCE="));
        assert!(blob.contains("\nCIPHERTEXT="));
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let bad = "NOT-OUR-FORMAT\nSALT=AAAA\n";
        let parsed = parse_blob(bad);
        assert!(parsed.is_err());
    }

    #[test]
    fn parse_rejects_missing_field() {
        let creds = basic_creds();
        let blob = seal_blob(&compute_vault_id("/x"), &creds, "p").unwrap();
        // Remove the CIPHERTEXT line
        let truncated: String = blob
            .lines()
            .filter(|l| !l.starts_with("CIPHERTEXT="))
            .collect::<Vec<_>>()
            .join("\n");
        let result = unseal_blob(&compute_vault_id("/x"), &truncated, "p");
        assert_eq!(result, Err(SealedError::FormatInvalid));
    }

    #[test]
    fn empty_passphrase_rejected_at_seal() {
        let creds = basic_creds();
        let vault_id = compute_vault_id("/x");
        let result = seal_blob(&vault_id, &creds, "");
        match result {
            Err(SealedError::ValidationError(msg)) => assert!(msg.contains("passphrase")),
            other => panic!("expected ValidationError, got {:?}", other),
        }
    }

    #[test]
    fn change_passphrase_roundtrip_in_memory() {
        // Simulates the change_passphrase flow without touching the OS keychain.
        let creds = enterprise_creds();
        let vault_id = compute_vault_id("/test/vault.env.sealed");
        let blob_v1 = seal_blob(&vault_id, &creds, "old-pp").unwrap();

        // Recover with old, re-seal with new
        let recovered = unseal_blob(&vault_id, &blob_v1, "old-pp").unwrap();
        let blob_v2 = seal_blob(&vault_id, &recovered, "new-pp").unwrap();

        // New passphrase opens it, old does not
        assert!(unseal_blob(&vault_id, &blob_v2, "new-pp").is_ok());
        assert_eq!(
            unseal_blob(&vault_id, &blob_v2, "old-pp"),
            Err(SealedError::DecryptFailed)
        );
    }

    #[test]
    fn different_calls_produce_different_blobs() {
        // Salt + nonce are random per seal; same inputs → different blobs
        let creds = enterprise_creds();
        let vault_id = compute_vault_id("/x");
        let b1 = seal_blob(&vault_id, &creds, "p").unwrap();
        let b2 = seal_blob(&vault_id, &creds, "p").unwrap();
        assert_ne!(b1, b2, "salt+nonce randomness must produce different blobs");
    }
}
