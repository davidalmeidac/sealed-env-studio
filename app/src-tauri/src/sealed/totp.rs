use super::crypto::hmac_sha256;
use super::errors::{SealedError, TokenInvalidReason};
use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// In-process ops_id replay cache.
pub struct OpsCache {
    entries: HashMap<String, Instant>,
}

impl OpsCache {
    pub fn new() -> Self {
        OpsCache {
            entries: HashMap::new(),
        }
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, exp| *exp > now);
    }

    fn contains(&mut self, ops_id: &str) -> bool {
        self.evict_expired();
        self.entries.contains_key(ops_id)
    }

    fn insert(&mut self, ops_id: String, exp_duration: Duration) {
        let deadline = Instant::now() + exp_duration;
        self.entries.insert(ops_id, deadline);
    }
}

impl Default for OpsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// SEC-007: validate base64 charset BEFORE any decode attempt.
/// Only standard base64 alphabet is allowed: A-Za-z0-9+/ with up to 2 '=' padding.
pub fn validate_base64_charset(s: &str) -> Result<(), SealedError> {
    // Manual check is more reliable than regex for this pattern:
    let chars_valid = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !chars_valid {
        return Err(SealedError::TokenInvalid(
            TokenInvalidReason::MalformedEpoch,
        ));
    }
    // Padding must only appear at the end (max 2)
    let without_padding = s.trim_end_matches('=');
    let padding_count = s.len() - without_padding.len();
    if padding_count > 2 {
        return Err(SealedError::TokenInvalid(
            TokenInvalidReason::MalformedEpoch,
        ));
    }
    // No '=' allowed in the non-padding part
    if without_padding.contains('=') {
        return Err(SealedError::TokenInvalid(
            TokenInvalidReason::MalformedEpoch,
        ));
    }
    Ok(())
}

/// Inputs for `build_unseal_token`. The `derived_key` is `kdf_derive(master_key, salt, kdf_params)`.
/// `totp_secret` is the raw secret bytes (NOT hex). `salt` is the raw salt bytes from the SEALED-ENV-V1 header (NOT base64).
pub struct BuildTokenInput<'a> {
    pub derived_key: &'a [u8; 32],
    pub totp_secret: &'a [u8],
    pub salt: &'a [u8],
    pub deploy_id: Option<String>,
    /// Capped to 600 seconds (SEC-R6). Floored at 5 seconds so the token isn't already expired by clock skew.
    pub ttl_seconds: u64,
}

/// Mint an unseal token for the enterprise mode unlock flow.
///
/// Wire format mirror of the Node CLI `sealed-env unseal` output.
/// The resulting token can be verified by `verify_unseal_token` (Rust),
/// the Node CLI, or the Java SDK — same format across stacks.
pub fn build_unseal_token(input: BuildTokenInput<'_>) -> Result<String, SealedError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Cap TTL: floor 5s, ceil 600s (SEC-R6 lifetime invariant).
    let ttl = input.ttl_seconds.clamp(5, 600);

    // enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")
    let mut salt_and_suffix = Vec::with_capacity(input.salt.len() + 8);
    salt_and_suffix.extend_from_slice(input.salt);
    salt_and_suffix.extend_from_slice(b"epoch-v1");
    let enterprise_epoch = hmac_sha256(input.totp_secret, &salt_and_suffix);
    let epoch_b64 = B64_STANDARD.encode(enterprise_epoch);

    // Timestamps
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SealedError::ValidationError("system clock before unix epoch".to_string()))?
        .as_secs() as i64;
    let iat = now_unix;
    let exp = iat + ttl as i64;

    // ops_id: UUID v4 (replay protection requires uniqueness per call)
    let ops_id = uuid::Uuid::new_v4().to_string();

    // Header (fixed)
    let header_json = r#"{"alg":"HS256","typ":"sealed-env-unseal/v1"}"#;
    let header_enc = URL_SAFE_NO_PAD.encode(header_json);

    // Payload (issuer = "sealed-env" — the wire format library, not the GUI)
    let payload_json = serde_json::json!({
        "iss": "sealed-env",
        "iat": iat,
        "exp": exp,
        "epoch": epoch_b64,
        "deploy_id": input.deploy_id,
        "ops_id": ops_id,
    })
    .to_string();
    let payload_enc = URL_SAFE_NO_PAD.encode(&payload_json);

    // Signature: HMAC-SHA256(derived_key, header_enc + "." + payload_enc)
    let signing_input = format!("{}.{}", header_enc, payload_enc);
    let sig = hmac_sha256(input.derived_key, signing_input.as_bytes());
    let sig_enc = URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("usl_{}.{}.{}", header_enc, payload_enc, sig_enc))
}

/// Unseal token structure: `usl_<b64url(header)>.<b64url(payload)>.<b64url(sig)>`
#[derive(Debug)]
struct UnsealToken {
    header_part: String,
    payload_part: String,
    sig_bytes: Vec<u8>,
    /// Parsed from the payload but not validated — informational only.
    /// Kept for forensic / debug logging surfaces in future iterations.
    #[allow(dead_code)]
    iss: String,
    iat: i64,
    exp: i64,
    epoch: String,
    ops_id: String,
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, SealedError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| SealedError::TokenInvalid(TokenInvalidReason::BadStructure))
}

fn parse_unseal_token(token: &str) -> Result<UnsealToken, SealedError> {
    // Must start with "usl_"
    let token_body = token
        .strip_prefix("usl_")
        .ok_or(SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?;

    let parts: Vec<&str> = token_body.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::BadStructure));
    }

    let header_part = parts[0].to_string();
    let payload_part = parts[1].to_string();
    let sig_part = parts[2];

    let sig_bytes = decode_base64url(sig_part)?;

    // Decode payload JSON
    let payload_bytes = decode_base64url(&payload_part)?;
    let payload_str = std::str::from_utf8(&payload_bytes)
        .map_err(|_| SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?;
    let payload: serde_json::Value = serde_json::from_str(payload_str)
        .map_err(|_| SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?;

    let iss = payload["iss"]
        .as_str()
        .ok_or(SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?
        .to_string();
    let iat = payload["iat"]
        .as_i64()
        .ok_or(SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?;
    let exp = payload["exp"]
        .as_i64()
        .ok_or(SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?;
    let epoch = payload["epoch"]
        .as_str()
        .ok_or(SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?
        .to_string();
    let ops_id = payload["ops_id"]
        .as_str()
        .ok_or(SealedError::TokenInvalid(TokenInvalidReason::BadStructure))?
        .to_string();

    Ok(UnsealToken {
        header_part,
        payload_part,
        sig_bytes,
        iss,
        iat,
        exp,
        epoch,
        ops_id,
    })
}

/// Verify an unseal token. Returns epoch bytes on success (for epoch-commit verification).
pub fn verify_unseal_token(
    token: &str,
    derived_key: &[u8; 32],
    ops_cache: &mut OpsCache,
) -> Result<Vec<u8>, SealedError> {
    let t = parse_unseal_token(token)?;

    // SEC-007: validate epoch base64 charset BEFORE decode
    validate_base64_charset(&t.epoch)?;

    // Decode epoch bytes
    let epoch_bytes = B64_STANDARD
        .decode(&t.epoch)
        .map_err(|_| SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch))?;

    // SEC-R6: token lifetime must be <= 600 seconds
    let lifetime = t.exp - t.iat;
    if !(0..=600).contains(&lifetime) {
        return Err(SealedError::TokenInvalid(
            TokenInvalidReason::LifetimeTooLong,
        ));
    }

    // Check expiry against current time
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if t.exp <= now_unix {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::Expired));
    }

    // Replay check
    if ops_cache.contains(&t.ops_id) {
        return Err(SealedError::TokenReplay);
    }

    // Verify signature: HMAC-SHA256(derived_key, header_part + "." + payload_part)
    let signing_input = format!("{}.{}", t.header_part, t.payload_part);
    let expected_sig = hmac_sha256(derived_key, signing_input.as_bytes());

    use subtle::ConstantTimeEq;
    if expected_sig.ct_eq(&t.sig_bytes).unwrap_u8() != 1 {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::BadSignature));
    }

    // Register ops_id in cache
    let exp_duration = Duration::from_secs((t.exp - now_unix).max(0) as u64);
    ops_cache.insert(t.ops_id, exp_duration);

    Ok(epoch_bytes)
}

/// Convenience: verify with a test-time unix `now` (for tests that need expired tokens).
/// This is only compiled in test builds.
#[cfg(test)]
pub fn verify_unseal_token_at(
    token: &str,
    derived_key: &[u8; 32],
    ops_cache: &mut OpsCache,
    now_unix: i64,
) -> Result<Vec<u8>, SealedError> {
    let t = parse_unseal_token(token)?;

    // SEC-007
    validate_base64_charset(&t.epoch)?;

    let epoch_bytes = B64_STANDARD
        .decode(&t.epoch)
        .map_err(|_| SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch))?;

    let lifetime = t.exp - t.iat;
    if !(0..=600).contains(&lifetime) {
        return Err(SealedError::TokenInvalid(
            TokenInvalidReason::LifetimeTooLong,
        ));
    }

    if t.exp <= now_unix {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::Expired));
    }

    if ops_cache.contains(&t.ops_id) {
        return Err(SealedError::TokenReplay);
    }

    let signing_input = format!("{}.{}", t.header_part, t.payload_part);
    let expected_sig = hmac_sha256(derived_key, signing_input.as_bytes());

    use subtle::ConstantTimeEq;
    if expected_sig.ct_eq(&t.sig_bytes).unwrap_u8() != 1 {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::BadSignature));
    }

    let exp_duration = Duration::from_secs((t.exp - now_unix).max(0) as u64);
    ops_cache.insert(t.ops_id, exp_duration);

    Ok(epoch_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::crypto::hmac_sha256;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // ─── build_unseal_token tests (TDD-first for Option A) ─────────────

    fn fake_salt() -> Vec<u8> {
        (0..16).map(|i| i as u8 ^ 0x55).collect()
    }

    fn fake_totp_secret() -> Vec<u8> {
        (0..20).map(|i| (i as u8).wrapping_mul(7)).collect()
    }

    #[test]
    fn build_token_has_usl_prefix_and_three_parts() {
        let key = test_key();
        let token = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &fake_totp_secret(),
            salt: &fake_salt(),
            deploy_id: None,
            ttl_seconds: 60,
        })
        .unwrap();
        assert!(token.starts_with("usl_"), "token must start with usl_");
        let body = &token[4..];
        let parts: Vec<&str> = body.split('.').collect();
        assert_eq!(parts.len(), 3, "token must have header.payload.sig");
    }

    #[test]
    fn build_then_verify_roundtrip() {
        let key = test_key();
        let totp = fake_totp_secret();
        let salt = fake_salt();

        let token = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &totp,
            salt: &salt,
            deploy_id: None,
            ttl_seconds: 60,
        })
        .unwrap();

        let mut cache = fresh_cache();
        let epoch_bytes = verify_unseal_token(&token, &key, &mut cache).unwrap();

        // The verified epoch must equal HMAC(totp_secret, salt || "epoch-v1")
        let mut salt_and_suffix = Vec::with_capacity(salt.len() + 8);
        salt_and_suffix.extend_from_slice(&salt);
        salt_and_suffix.extend_from_slice(b"epoch-v1");
        let expected_epoch = hmac_sha256(&totp, &salt_and_suffix);
        assert_eq!(epoch_bytes, expected_epoch.to_vec());
    }

    #[test]
    fn build_uses_unique_ops_id_per_call() {
        let key = test_key();
        let totp = fake_totp_secret();
        let salt = fake_salt();

        let t1 = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &totp,
            salt: &salt,
            deploy_id: None,
            ttl_seconds: 60,
        })
        .unwrap();
        let t2 = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &totp,
            salt: &salt,
            deploy_id: None,
            ttl_seconds: 60,
        })
        .unwrap();

        // Identical inputs MUST produce different tokens (uuid v4 ops_id)
        assert_ne!(
            t1, t2,
            "two builds must produce different tokens (ops_id uniqueness)"
        );
    }

    #[test]
    fn build_ttl_capped_at_600() {
        let key = test_key();
        let token = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &fake_totp_secret(),
            salt: &fake_salt(),
            deploy_id: None,
            ttl_seconds: 999_999,
        })
        .unwrap();
        let parsed = parse_unseal_token(&token).unwrap();
        assert_eq!(parsed.exp - parsed.iat, 600, "TTL must be capped at 600s");
    }

    #[test]
    fn build_ttl_floor_5() {
        let key = test_key();
        let token = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &fake_totp_secret(),
            salt: &fake_salt(),
            deploy_id: None,
            ttl_seconds: 0,
        })
        .unwrap();
        let parsed = parse_unseal_token(&token).unwrap();
        assert_eq!(parsed.exp - parsed.iat, 5, "TTL must have a floor of 5s");
    }

    #[test]
    fn build_with_deploy_id_propagates() {
        let key = test_key();
        let token = build_unseal_token(BuildTokenInput {
            derived_key: &key,
            totp_secret: &fake_totp_secret(),
            salt: &fake_salt(),
            deploy_id: Some("commit-abc123".to_string()),
            ttl_seconds: 60,
        })
        .unwrap();
        // Decode payload and check deploy_id is present
        let body = &token[4..];
        let parts: Vec<&str> = body.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["deploy_id"].as_str(), Some("commit-abc123"));
    }

    // ─── Pre-existing tests below ─────────────────────────────────────

    /// Build a test token with controlled iat/exp/epoch/ops_id.
    fn make_token(
        derived_key: &[u8; 32],
        iat: i64,
        exp: i64,
        epoch_b64: &str,
        ops_id: &str,
    ) -> String {
        use base64::Engine;
        let header = r#"{"alg":"HS256","typ":"sealed-env-unseal/v1"}"#;
        let payload = serde_json::json!({
            "iss": "sealed-env-cli",
            "iat": iat,
            "exp": exp,
            "epoch": epoch_b64,
            "deploy_id": null,
            "ops_id": ops_id,
        })
        .to_string();

        let h_enc = URL_SAFE_NO_PAD.encode(header);
        let p_enc = URL_SAFE_NO_PAD.encode(&payload);
        let signing_input = format!("{}.{}", h_enc, p_enc);
        let sig = hmac_sha256(derived_key, signing_input.as_bytes());
        let sig_enc = URL_SAFE_NO_PAD.encode(sig);

        format!("usl_{}.{}.{}", h_enc, p_enc, sig_enc)
    }

    fn fresh_cache() -> OpsCache {
        OpsCache::new()
    }

    // A valid epoch: 32 zero bytes in standard base64
    fn valid_epoch_b64() -> String {
        B64_STANDARD.encode([0u8; 32])
    }

    // A derived key for tests
    fn test_key() -> [u8; 32] {
        [0xabu8; 32]
    }

    // "now" far enough before exp
    fn base_now() -> i64 {
        1_700_000_000i64
    }

    #[test]
    fn sec007_tab_in_epoch_is_rejected() {
        // The enterprise-token-malformed-epoch vector: epoch contains a tab character
        let malformed = "\tBshQhppmTZl+6h+Gio3uL+wHL/Xt9vI6rwFamblkY7A=";
        let result = validate_base64_charset(malformed);
        assert_eq!(
            result,
            Err(SealedError::TokenInvalid(
                TokenInvalidReason::MalformedEpoch
            ))
        );
    }

    #[test]
    fn sec007_valid_epoch_passes_charset_check() {
        let valid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(validate_base64_charset(valid).is_ok());
    }

    #[test]
    fn sec007_newline_in_epoch_is_rejected() {
        let bad = "AAAA\nAAAA";
        assert!(validate_base64_charset(bad).is_err());
    }

    #[test]
    fn sec007_tilde_in_epoch_is_rejected() {
        let bad = "AAAA~AAAA";
        assert!(validate_base64_charset(bad).is_err());
    }

    #[test]
    fn valid_token_accepted() {
        let key = test_key();
        let now = base_now();
        let epoch = valid_epoch_b64();
        let token = make_token(&key, now, now + 60, &epoch, "ops-id-001");
        let mut cache = fresh_cache();
        let result = verify_unseal_token_at(&token, &key, &mut cache, now);
        assert!(result.is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let key = test_key();
        let iat = base_now();
        let exp = iat + 60;
        let now = exp + 1; // one second past expiry
        let epoch = valid_epoch_b64();
        let token = make_token(&key, iat, exp, &epoch, "ops-id-002");
        let mut cache = fresh_cache();
        let result = verify_unseal_token_at(&token, &key, &mut cache, now);
        assert_eq!(
            result,
            Err(SealedError::TokenInvalid(TokenInvalidReason::Expired))
        );
    }

    #[test]
    fn token_lifetime_over_600s_rejected() {
        let key = test_key();
        let now = base_now();
        let epoch = valid_epoch_b64();
        // lifetime = 601 > 600
        let token = make_token(&key, now, now + 601, &epoch, "ops-id-003");
        let mut cache = fresh_cache();
        let result = verify_unseal_token_at(&token, &key, &mut cache, now);
        assert_eq!(
            result,
            Err(SealedError::TokenInvalid(
                TokenInvalidReason::LifetimeTooLong
            ))
        );
    }

    #[test]
    fn token_replay_rejected() {
        let key = test_key();
        let now = base_now();
        let epoch = valid_epoch_b64();
        let token = make_token(&key, now, now + 60, &epoch, "ops-id-replay");
        let mut cache = fresh_cache();
        // First call: OK
        assert!(verify_unseal_token_at(&token, &key, &mut cache, now).is_ok());
        // Second call with same token: TokenReplay
        let result = verify_unseal_token_at(&token, &key, &mut cache, now);
        assert_eq!(result, Err(SealedError::TokenReplay));
    }

    #[test]
    fn bad_signature_rejected() {
        let key = test_key();
        let now = base_now();
        let epoch = valid_epoch_b64();
        let token = make_token(&key, now, now + 60, &epoch, "ops-id-badsig");
        // Corrupt the signature part
        let parts: Vec<&str> = token[4..].split('.').collect(); // skip "usl_"
        let mut bad_sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        bad_sig[0] ^= 0xff;
        let bad_sig_enc = URL_SAFE_NO_PAD.encode(&bad_sig);
        let bad_token = format!("usl_{}.{}.{}", parts[0], parts[1], bad_sig_enc);
        let mut cache = fresh_cache();
        let result = verify_unseal_token_at(&bad_token, &key, &mut cache, now);
        assert_eq!(
            result,
            Err(SealedError::TokenInvalid(TokenInvalidReason::BadSignature))
        );
    }

    #[test]
    fn sec007_token_with_tab_epoch_returns_token_invalid() {
        // Replicate enterprise-token-malformed-epoch vector test at the token level.
        // We construct a token where the epoch field contains a tab char.
        let key = test_key();
        let now = base_now();
        let epoch_with_tab = "\tBshQhppmTZl+6h+Gio3uL+wHL/Xt9vI6rwFamblkY7A=";
        let token = make_token(&key, now, now + 60, epoch_with_tab, "ops-id-malformed");
        let mut cache = fresh_cache();
        let result = verify_unseal_token_at(&token, &key, &mut cache, now);
        assert_eq!(
            result,
            Err(SealedError::TokenInvalid(
                TokenInvalidReason::MalformedEpoch
            ))
        );
    }
}
