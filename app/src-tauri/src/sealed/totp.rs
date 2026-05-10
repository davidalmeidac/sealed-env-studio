use super::errors::{SealedError, TokenInvalidReason};
use super::crypto::hmac_sha256;
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
    let chars_valid = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
    });
    if !chars_valid {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch));
    }
    // Padding must only appear at the end (max 2)
    let without_padding = s.trim_end_matches('=');
    let padding_count = s.len() - without_padding.len();
    if padding_count > 2 {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch));
    }
    // No '=' allowed in the non-padding part
    if without_padding.contains('=') {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch));
    }
    Ok(())
}

/// Unseal token structure: `usl_<b64url(header)>.<b64url(payload)>.<b64url(sig)>`
#[derive(Debug)]
struct UnsealToken {
    header_part: String,
    payload_part: String,
    sig_bytes: Vec<u8>,
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
    if lifetime > 600 || lifetime < 0 {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::LifetimeTooLong));
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
    if lifetime > 600 || lifetime < 0 {
        return Err(SealedError::TokenInvalid(TokenInvalidReason::LifetimeTooLong));
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
        let sig_enc = URL_SAFE_NO_PAD.encode(&sig);

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
            Err(SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch))
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
            Err(SealedError::TokenInvalid(TokenInvalidReason::LifetimeTooLong))
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
            Err(SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch))
        );
    }
}
