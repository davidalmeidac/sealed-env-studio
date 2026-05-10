pub mod errors;
pub mod format;
pub mod crypto;
pub mod totp;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use errors::SealedError;
use format::{KdfKind, KdfParams, SealedFile, SealedMode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Parameters for sealing a new file.
pub struct SealParams {
    pub mode: SealedMode,
    pub plaintext: String,
    pub master_key: Vec<u8>,
    /// Required for team + enterprise
    pub signing_key: Option<Vec<u8>>,
    /// Required for enterprise: raw 20-byte TOTP secret
    pub totp_secret: Option<Vec<u8>>,
    pub kdf_params: KdfParams,
}

/// Keys provided for decryption.
pub struct DecryptKeys {
    pub master_key: Vec<u8>,
    /// Required for team + enterprise
    pub signing_key: Option<Vec<u8>>,
    /// Required for enterprise: the unseal token string
    pub unseal_token: Option<String>,
}

/// Seal plaintext into a SEALED-ENV-V1 file string.
pub fn seal(params: SealParams) -> Result<String, SealedError> {
    use chrono::Utc;

    let salt = crypto::random_bytes(16);
    let nonce = crypto::random_bytes(12);

    // Step 3: derive key
    let seal_params = match &params.kdf_params {
        KdfParams::Argon2id { t, m, p } => KdfParams::Argon2id {
            t: *t,
            m: *m,
            p: *p,
        },
        // seal() always writes argon2id — remap scrypt to argon2id defaults
        KdfParams::Scrypt { .. } => KdfParams::Argon2id {
            t: crypto::ARGON2_T_DEFAULT,
            m: crypto::ARGON2_M_DEFAULT,
            p: crypto::ARGON2_P_DEFAULT,
        },
    };
    let derived_key = crypto::argon2id_derive(&params.master_key, &salt, &seal_params)?;

    // Step 4: enc_key via HKDF
    let enc_key_vec = crypto::hkdf_expand(&derived_key, &salt, b"sealed-env:v1:enc", 32);
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_vec);

    let created = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Build a partial SealedFile to compute AAD
    let epoch_commit_b64: Option<String> = if params.mode == SealedMode::Enterprise {
        let totp_secret = params
            .totp_secret
            .as_deref()
            .ok_or(SealedError::MissingKey)?;
        // enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")
        let mut salt_and_suffix = salt.clone();
        salt_and_suffix.extend_from_slice(b"epoch-v1");
        let enterprise_epoch = crypto::hmac_sha256(totp_secret, &salt_and_suffix);
        // epoch_commit = HMAC-SHA256(derived_key, enterprise_epoch || "epoch-commit-v1")
        let mut epoch_and_suffix = enterprise_epoch.to_vec();
        epoch_and_suffix.extend_from_slice(b"epoch-commit-v1");
        let commit = crypto::hmac_sha256(&derived_key, &epoch_and_suffix);
        Some(B64.encode(commit))
    } else {
        None
    };

    // Build canonical AAD (excludes AAD-DIGEST and HMAC — matches Node buildAad())
    let kdf_str = "argon2id";
    let kdf_params_str = match &seal_params {
        KdfParams::Argon2id { t, m, p } => format!("t={},m={},p={}", t, m, p),
        _ => unreachable!(),
    };
    let salt_b64 = B64.encode(&salt);
    let nonce_b64 = B64.encode(&nonce);
    let magic_line = format!("SEALED-ENV-V1 MODE={}", params.mode.as_str_ref());

    // Build AAD lines (no AAD-DIGEST, no HMAC)
    let mut aad_lines: Vec<String> = Vec::new();
    aad_lines.push(magic_line.clone());
    aad_lines.push(format!("KDF={}", kdf_str));
    aad_lines.push(format!("KDF-PARAMS={}", kdf_params_str));
    aad_lines.push(format!("SALT={}", salt_b64));
    aad_lines.push(format!("NONCE={}", nonce_b64));
    if let Some(ref ec) = epoch_commit_b64 {
        aad_lines.push(format!("EPOCH-COMMIT={}", ec));
    }
    if params.mode == SealedMode::Enterprise {
        aad_lines.push("CHALLENGE-BIND=disabled".to_string());
    }
    aad_lines.push(format!("CREATED={}", created));

    let aad_str = aad_lines.join("\n");
    let aad_bytes = aad_str.as_bytes();

    // aad_digest = SHA256(aad)
    let aad_digest_bytes: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(aad_bytes);
        hasher.finalize().into()
    };
    let aad_digest_b64 = B64.encode(aad_digest_bytes);

    // Encrypt (GCM AAD = aad_bytes — same string, no AAD-DIGEST included)
    let ciphertext_with_tag =
        crypto::aes256gcm_encrypt(&enc_key, &nonce, params.plaintext.as_bytes(), aad_bytes);
    let body_b64 = B64.encode(&ciphertext_with_tag);

    // Compute HMAC if team/enterprise: HMAC(mac_key, aad + ciphertext)
    let hmac_b64: Option<String> = if params.mode == SealedMode::Team || params.mode == SealedMode::Enterprise {
        let signing_key = params.signing_key.as_deref().ok_or(SealedError::MissingKey)?;
        let mac_key_vec = crypto::hkdf_expand(signing_key, &salt, b"sealed-env:v1:mac", 32);
        let hmac_input: Vec<u8> = {
            let mut buf = aad_bytes.to_vec();
            buf.extend_from_slice(&ciphertext_with_tag);
            buf
        };
        let mac = crypto::hmac_sha256(&mac_key_vec, &hmac_input);
        Some(B64.encode(mac))
    } else {
        None
    };

    // Build output lines (serial format)
    let mut out_lines = vec![magic_line];
    out_lines.push(format!("KDF={}", kdf_str));
    out_lines.push(format!("KDF-PARAMS={}", kdf_params_str));
    out_lines.push(format!("SALT={}", salt_b64));
    out_lines.push(format!("NONCE={}", nonce_b64));
    if let Some(ref ec) = epoch_commit_b64 {
        out_lines.push(format!("EPOCH-COMMIT={}", ec));
    }
    if params.mode == SealedMode::Enterprise {
        out_lines.push("CHALLENGE-BIND=disabled".to_string());
    }
    out_lines.push(format!("AAD-DIGEST={}", aad_digest_b64));
    if let Some(ref h) = hmac_b64 {
        out_lines.push(format!("HMAC={}", h));
    }
    out_lines.push(format!("CREATED={}", created));
    out_lines.push(String::new()); // blank separator
    out_lines.push(body_b64);

    Ok(out_lines.join("\n"))
}

/// Helper to access SealedMode as &str.
trait ModeStr {
    fn as_str_ref(&self) -> &str;
}

impl ModeStr for SealedMode {
    fn as_str_ref(&self) -> &str {
        match self {
            SealedMode::Basic => "basic",
            SealedMode::Team => "team",
            SealedMode::Enterprise => "enterprise",
        }
    }
}

/// Collapse errors per oracle defense (SEC-R1).
/// `TokenInvalid` and `MissingKey` are preserved; everything else → `DecryptFailed`.
fn collapse(e: SealedError) -> SealedError {
    e.collapse_to_decrypt_failed()
}

/// Decrypt a SEALED-ENV-V1 file. Returns plaintext.
pub fn decrypt(
    file_content: &str,
    keys: DecryptKeys,
    ops_cache: &mut totp::OpsCache,
) -> Result<String, SealedError> {
    // Step 1: parse
    let file = format::parse(file_content).map_err(collapse)?;

    // Step 2: derive key (dispatch on KDF field)
    let derived_key = crypto::kdf_derive(&keys.master_key, &decode_b64_field(&file.salt)?, &file.kdf_params)
        .map_err(collapse)?;

    // Step 4: HMAC verify for team + enterprise
    if file.mode == SealedMode::Team || file.mode == SealedMode::Enterprise {
        let signing_key = keys.signing_key.as_deref().ok_or(SealedError::MissingKey)?;
        let salt_bytes = decode_b64_field(&file.salt)?;
        let mac_key_vec = crypto::hkdf_expand(signing_key, &salt_bytes, b"sealed-env:v1:mac", 32);

        let ct_bytes = decode_b64_field(&file.body).map_err(collapse)?;

        // Build HMAC input: the "aad" (magic + metadata without HMAC) + ciphertext_with_tag
        let hmac_input = build_hmac_input_for_file(&file, &ct_bytes);
        let stored_hmac = decode_b64_field(file.hmac.as_deref().unwrap_or_default()).map_err(collapse)?;
        crypto::hmac_verify(&mac_key_vec, &hmac_input, &stored_hmac).map_err(collapse)?;
    }

    // Step 5: Enterprise unseal token verification
    if file.mode == SealedMode::Enterprise {
        let token_str = keys
            .unseal_token
            .as_deref()
            .ok_or(SealedError::MissingKey)?;

        // verify_unseal_token returns epoch_bytes if valid
        let epoch_bytes =
            totp::verify_unseal_token(token_str, &derived_key, ops_cache)?;

        // Verify epoch_commit
        let stored_commit = decode_b64_field(
            file.epoch_commit
                .as_deref()
                .ok_or(SealedError::FormatInvalid).map_err(collapse)?,
        ).map_err(collapse)?;

        // epoch_commit = HMAC-SHA256(derived_key, enterprise_epoch || "epoch-commit-v1")
        let mut epoch_and_suffix = epoch_bytes.clone();
        epoch_and_suffix.extend_from_slice(b"epoch-commit-v1");
        let computed_commit = crypto::hmac_sha256(&derived_key, &epoch_and_suffix);

        if computed_commit.ct_eq(&stored_commit).unwrap_u8() != 1 {
            return Err(SealedError::DecryptFailed);
        }
    }

    // Step 6: AAD reconstruction and digest verify
    let salt_bytes = decode_b64_field(&file.salt)?;
    let enc_key_vec = crypto::hkdf_expand(&derived_key, &salt_bytes, b"sealed-env:v1:enc", 32);
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_vec);

    // Rebuild AAD (same as seal: magic + metadata without HMAC)
    let gcm_aad = build_gcm_aad_for_file(&file);
    let gcm_aad_bytes = gcm_aad.as_bytes();

    // Verify AAD-DIGEST
    let stored_digest = decode_b64_field(&file.aad_digest).map_err(collapse)?;
    let aad_for_digest = build_aad_input_for_digest(&file);
    let computed_digest: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(aad_for_digest.as_bytes());
        hasher.finalize().into()
    };
    if computed_digest.ct_eq(&stored_digest).unwrap_u8() != 1 {
        return Err(SealedError::DecryptFailed);
    }

    // Step 8: decrypt
    let nonce_bytes = decode_b64_field(&file.nonce).map_err(collapse)?;
    let ct_bytes = decode_b64_field(&file.body).map_err(collapse)?;

    let plaintext_bytes =
        crypto::aes256gcm_decrypt(&enc_key, &nonce_bytes, &ct_bytes, gcm_aad_bytes)
            .map_err(collapse)?;

    String::from_utf8(plaintext_bytes).map_err(|_| SealedError::DecryptFailed)
}

fn decode_b64_field(s: &str) -> Result<Vec<u8>, SealedError> {
    B64.decode(s).map_err(|_| SealedError::DecryptFailed)
}

/// Build the canonical AAD string (also used as HMAC input base and for AAD-DIGEST):
/// magic_line + "\n" + metadata lines joined by "\n".
/// Excludes: AAD-DIGEST field, HMAC field. Only includes core auth fields.
/// This matches the Node `buildAad()` function exactly.
fn build_aad_for_file(file: &SealedFile) -> String {
    let magic = format!("SEALED-ENV-V1 MODE={}", file.mode.as_str_ref());
    let kdf_str = match &file.kdf {
        KdfKind::Argon2id => "argon2id",
        KdfKind::Scrypt => "scrypt",
    };
    let mut lines: Vec<String> = Vec::new();
    lines.push(magic);
    lines.push(format!("KDF={}", kdf_str));
    lines.push(format!("KDF-PARAMS={}", file.kdf_params.as_str()));
    lines.push(format!("SALT={}", file.salt));
    lines.push(format!("NONCE={}", file.nonce));
    if let Some(ref ec) = file.epoch_commit {
        lines.push(format!("EPOCH-COMMIT={}", ec));
    }
    if let Some(ref cb) = file.challenge_bind {
        lines.push(format!("CHALLENGE-BIND={}", cb));
    }
    // AAD-DIGEST excluded (it's the hash of this string)
    // HMAC excluded
    lines.push(format!("CREATED={}", file.created));
    if let Some(ref r) = file.rotated {
        lines.push(format!("ROTATED={}", r));
    }
    lines.join("\n")
}

// GCM AAD = same as the AAD string used for digest computation
fn build_gcm_aad_for_file(file: &SealedFile) -> String {
    build_aad_for_file(file)
}

// For digest: same AAD string
fn build_aad_input_for_digest(file: &SealedFile) -> String {
    build_aad_for_file(file)
}

/// Build HMAC input: GCM AAD bytes + ciphertext_with_tag bytes.
fn build_hmac_input_for_file(file: &SealedFile, ciphertext_with_tag: &[u8]) -> Vec<u8> {
    let mut buf = build_gcm_aad_for_file(file).into_bytes();
    buf.extend_from_slice(ciphertext_with_tag);
    buf
}

/// Parse a .env dotenv string into key-value pairs.
pub fn parse_dotenv(raw: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        // Skip comments and blanks
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let val = line[eq_pos + 1..].trim().to_string();
            // Strip surrounding quotes
            let val = strip_quotes(&val);
            if !key.is_empty() {
                result.push((key, val));
            }
        }
    }
    result
}

fn strip_quotes(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::format::{KdfParams, SealedMode};

    fn basic_key() -> Vec<u8> {
        hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }

    fn signing_key() -> Vec<u8> {
        hex::decode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap()
    }

    fn argon2_params() -> KdfParams {
        KdfParams::Argon2id {
            t: crypto::ARGON2_T_DEFAULT,
            m: crypto::ARGON2_M_DEFAULT,
            p: crypto::ARGON2_P_DEFAULT,
        }
    }

    // ===================== Cross-stack vectors =====================

    fn node_basic_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=basic\nKDF=scrypt\nKDF-PARAMS=N=32768,r=8,p=1\nSALT=cjEZ9LJdMm7EB+XJmuDIlg==\nNONCE=auNcyoBkKZkm6np7\nAAD-DIGEST=SwCUaIOaLblHUq4AZQZJkJ+uQWNPjGKiNLqPn24x8xo=\nCREATED=2026-05-07T04:26:07.314Z\n\n5INrQBHklbC3giGmO2L4S8SbZB8F5UKd21whO7Jp4uUz+RQxxtzlqtyZIzkqI4CmBvFt1tNTQsX0ce0="
    }

    fn node_team_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=team\nKDF=scrypt\nKDF-PARAMS=N=32768,r=8,p=1\nSALT=huM5+57SPMO2P9jXxjuTAA==\nNONCE=jqSUI2Grdx0MFs8Q\nAAD-DIGEST=tytwlpq9gBl7aCnbE6hMbdF/RsUGuI7IdfEA18x+MqQ=\nHMAC=Iwzo3aQK5yOFE9Kk0NKjZfXuG+/6T4W2YSESHFF9T/s=\nCREATED=2026-05-07T04:26:07.596Z\n\nzR74Rx95lFsY3csJEg4RMifWKIv/c2U5T4qF8CRnx/yPwz4YNUyYAWHTsjuSxl3V+Ei3MZIRdJxMQac="
    }

    fn node_enterprise_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=enterprise\nKDF=scrypt\nKDF-PARAMS=N=32768,r=8,p=1\nSALT=14CTlMMsDqA0aw02u7NBRQ==\nNONCE=ekCHpjTcJfyLLk6R\nEPOCH-COMMIT=UkROU3FZIlmECGLFsbfthlQWhqO2x0JbGjxmNi/2qsQ=\nCHALLENGE-BIND=disabled\nAAD-DIGEST=f7TqR6VnpnZiJSmp2XJ189tMu5/bAzFYOa2oELG3OkU=\nHMAC=yQ9pw2cNDGAcVd/S+Hm558ReHusswsCRx4vhUaKUuqY=\nCREATED=2026-05-07T04:26:01.492Z\n\nRjsD6WlScnm9b4OWmj6Jck0lyTzGFdx/2/IdkpbZr3FMy6PHkfVz/fuaPRniibjmRPylpEpDKsxh1OY="
    }

    fn enterprise_scrypt_n131072_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=basic\nKDF=scrypt\nKDF-PARAMS=N=131072,r=8,p=1\nSALT=ZgePkg02sVW6/nqcXF39EQ==\nNONCE=FxkQJ7fy9gG7A1UT\nAAD-DIGEST=B5OUpbIiU4tz9g7A9sZJhMfVdQhqRl+40ulEmY7i1fI=\nCREATED=2026-05-10T20:20:54.271Z\n\nWBrgeDm8RItoChRC+nT6kEAXiuiiHIkVfIHbmpXrzVxV3WPR3mA+wjeWlkgXarQNOD76ZVHrkK9qwCs="
    }

    // node-basic: basic mode cross-stack vector
    #[test]
    fn cross_stack_basic_decrypt() {
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            node_basic_serialized(),
            DecryptKeys {
                master_key: basic_key(),
                signing_key: None,
                unseal_token: None,
            },
            &mut cache,
        );
        assert!(result.is_ok(), "basic decrypt failed: {:?}", result.err());
        let plaintext = result.unwrap();
        assert_eq!(plaintext, "API_KEY=cross-stack\nDB_URL=postgres://prod\n");
    }

    // node-team: team mode cross-stack vector
    #[test]
    fn cross_stack_team_decrypt() {
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            node_team_serialized(),
            DecryptKeys {
                master_key: basic_key(),
                signing_key: Some(signing_key()),
                unseal_token: None,
            },
            &mut cache,
        );
        assert!(result.is_ok(), "team decrypt failed: {:?}", result.err());
        assert_eq!(result.unwrap(), "API_KEY=cross-stack\nDB_URL=postgres://prod\n");
    }

    // enterprise-scrypt-N131072: basic mode with N=131072
    #[test]
    fn cross_stack_scrypt_n131072_decrypt() {
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            enterprise_scrypt_n131072_serialized(),
            DecryptKeys {
                master_key: basic_key(),
                signing_key: None,
                unseal_token: None,
            },
            &mut cache,
        );
        assert!(result.is_ok(), "scrypt N=131072 decrypt failed: {:?}", result.err());
        assert_eq!(result.unwrap(), "SEC002_TEST=n131072\nDB_HOST=db.example.com\n");
    }

    // node-enterprise: without a valid token we get MissingKey (proves format parses + HMAC verifies)
    #[test]
    fn cross_stack_enterprise_without_token_returns_missing_key() {
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            node_enterprise_serialized(),
            DecryptKeys {
                master_key: basic_key(),
                signing_key: Some(signing_key()),
                unseal_token: None,
            },
            &mut cache,
        );
        // No token → MissingKey (not DecryptFailed — proves HMAC verified first)
        assert_eq!(result, Err(SealedError::MissingKey));
    }

    // ===================== Unit tests =====================

    #[test]
    fn basic_seal_decrypt_roundtrip() {
        let plaintext = "API_KEY=hello\n";
        let master_key = crypto::random_bytes(32);
        let params = SealParams {
            mode: SealedMode::Basic,
            plaintext: plaintext.to_string(),
            master_key: master_key.clone(),
            signing_key: None,
            totp_secret: None,
            kdf_params: argon2_params(),
        };
        let sealed = seal(params).expect("seal");
        let mut cache = totp::OpsCache::new();
        let recovered = decrypt(
            &sealed,
            DecryptKeys {
                master_key,
                signing_key: None,
                unseal_token: None,
            },
            &mut cache,
        )
        .expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn team_hmac_tamper_rejected() {
        let plaintext = "SECRET=value\n";
        let master_key = crypto::random_bytes(32);
        let sign_key = crypto::random_bytes(32);
        let params = SealParams {
            mode: SealedMode::Team,
            plaintext: plaintext.to_string(),
            master_key: master_key.clone(),
            signing_key: Some(sign_key.clone()),
            totp_secret: None,
            kdf_params: argon2_params(),
        };
        let mut sealed = seal(params).expect("seal");
        // Tamper HMAC line
        let hmac_line_pos = sealed.find("HMAC=").unwrap();
        let end = sealed[hmac_line_pos..].find('\n').unwrap() + hmac_line_pos;
        sealed.replace_range(hmac_line_pos..end, "HMAC=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            &sealed,
            DecryptKeys {
                master_key,
                signing_key: Some(sign_key),
                unseal_token: None,
            },
            &mut cache,
        );
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }

    #[test]
    fn enterprise_without_token_returns_missing_key() {
        let plaintext = "API_KEY=x\n";
        let master_key = crypto::random_bytes(32);
        let sign_key = crypto::random_bytes(32);
        let totp_secret = crypto::random_bytes(20);
        let params = SealParams {
            mode: SealedMode::Enterprise,
            plaintext: plaintext.to_string(),
            master_key: master_key.clone(),
            signing_key: Some(sign_key.clone()),
            totp_secret: Some(totp_secret),
            kdf_params: argon2_params(),
        };
        let sealed = seal(params).expect("seal");
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            &sealed,
            DecryptKeys {
                master_key,
                signing_key: Some(sign_key),
                unseal_token: None, // no token!
            },
            &mut cache,
        );
        assert_eq!(result, Err(SealedError::MissingKey));
    }

    #[test]
    fn parse_dotenv_basic() {
        let raw = "API_KEY=hello\nDB_URL=postgres://prod\n";
        let pairs = parse_dotenv(raw);
        assert_eq!(pairs, vec![
            ("API_KEY".to_string(), "hello".to_string()),
            ("DB_URL".to_string(), "postgres://prod".to_string()),
        ]);
    }

    #[test]
    fn parse_dotenv_skips_comments() {
        let raw = "# comment\nKEY=value\n";
        let pairs = parse_dotenv(raw);
        assert_eq!(pairs, vec![("KEY".to_string(), "value".to_string())]);
    }

    #[test]
    fn parse_dotenv_strips_quotes() {
        let raw = "KEY=\"quoted value\"\n";
        let pairs = parse_dotenv(raw);
        assert_eq!(pairs, vec![("KEY".to_string(), "quoted value".to_string())]);
    }

    // SEC-007: the malformed-epoch vector must return TokenInvalid, NOT DecryptFailed
    #[test]
    fn sec007_malformed_epoch_token_returns_token_invalid() {
        let malformed_token = "usl_eyJhbGciOiJIUzI1NiIsInR5cCI6InNlYWxlZC1lbnYtdW5zZWFsL3YxIn0.eyJpc3MiOiJzZWFsZWQtZW52LWNsaSIsImlhdCI6MTc3ODQ0NTUwNCwiZXhwIjoxNzc4NDQ5MTA0LCJlcG9jaCI6Ilx0QnNoUWhwcG1UWmwrNmgrR2lvM3VMK3dITC9YdDl2STZyd0ZhbWJsa1k3QT0iLCJkZXBsb3lfaWQiOm51bGwsIm9wc19pZCI6Imdlbi12ZWN0b3ItZml4ZWQtb3BzLWlkIn0.va4l_4z_JGWsxOsG1gG7C4N5IslhS4qq2qY8HbPkTas";
        let derived_key = hex::decode("3601493fe669cebf7b60ce544266102157f635199a9fc003bb6f136a672856ff").unwrap();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&derived_key);
        let mut cache = totp::OpsCache::new();
        let result = totp::verify_unseal_token(malformed_token, &key_arr, &mut cache);
        // Must be TokenInvalid (not DecryptFailed)
        match result {
            Err(SealedError::TokenInvalid(_)) => {}
            other => panic!("expected TokenInvalid, got {:?}", other),
        }
    }

    // AAD digest mismatch → DecryptFailed
    #[test]
    fn aad_digest_mismatch_returns_decrypt_failed() {
        let plaintext = "KEY=val\n";
        let master_key = crypto::random_bytes(32);
        let params = SealParams {
            mode: SealedMode::Basic,
            plaintext: plaintext.to_string(),
            master_key: master_key.clone(),
            signing_key: None,
            totp_secret: None,
            kdf_params: argon2_params(),
        };
        let mut sealed = seal(params).expect("seal");
        // Tamper AAD-DIGEST
        let pos = sealed.find("AAD-DIGEST=").unwrap();
        let end = sealed[pos..].find('\n').unwrap() + pos;
        sealed.replace_range(pos..end, "AAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let mut cache = totp::OpsCache::new();
        let result = decrypt(
            &sealed,
            DecryptKeys {
                master_key,
                signing_key: None,
                unseal_token: None,
            },
            &mut cache,
        );
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }
}
