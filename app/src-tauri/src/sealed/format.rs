use super::errors::SealedError;

/// Represents the parsed contents of a SEALED-ENV-V1 file.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedFile {
    pub mode: SealedMode,
    pub kdf: KdfKind,
    pub kdf_params: KdfParams,
    /// Base64-encoded, 16 raw bytes
    pub salt: String,
    /// Base64-encoded, 12 raw bytes
    pub nonce: String,
    /// Enterprise only: base64-encoded, 32 raw bytes
    pub epoch_commit: Option<String>,
    /// Enterprise only: "enabled" | "disabled"
    pub challenge_bind: Option<String>,
    /// Base64-encoded, 32 raw bytes (SHA-256 of AAD)
    pub aad_digest: String,
    /// Team + enterprise: base64-encoded, 32 raw bytes
    pub hmac: Option<String>,
    /// ISO-8601 UTC
    pub created: String,
    /// Optional ISO-8601 UTC
    pub rotated: Option<String>,
    /// The body: base64 of (ciphertext || 16-byte GCM tag)
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedMode {
    Basic,
    Team,
    Enterprise,
}

impl SealedMode {
    fn as_str(&self) -> &'static str {
        match self {
            SealedMode::Basic => "basic",
            SealedMode::Team => "team",
            SealedMode::Enterprise => "enterprise",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfKind {
    Argon2id,
    Scrypt,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KdfParams {
    Argon2id { t: u32, m: u32, p: u32 },
    Scrypt { n: u64, r: u32, p: u32 },
}

impl KdfParams {
    pub fn as_str(&self) -> String {
        match self {
            KdfParams::Argon2id { t, m, p } => format!("t={},m={},p={}", t, m, p),
            KdfParams::Scrypt { n, r, p } => format!("N={},r={},p={}", n, r, p),
        }
    }
}

/// Validate that a base64 string uses only standard alphabet characters (no spaces/newlines/control chars).
fn is_valid_b64(s: &str) -> bool {
    let re = regex::Regex::new(r"^[A-Za-z0-9+/]+=*$").unwrap();
    re.is_match(s)
}

/// Parse a SEALED-ENV-V1 file from its text content.
pub fn parse(input: &str) -> Result<SealedFile, SealedError> {
    let mut lines = input.lines();

    // === Line 1: magic + mode ===
    let magic_line = lines.next().ok_or(SealedError::FormatInvalid)?;
    let mode = parse_magic_line(magic_line)?;

    // === Metadata lines: collect as key=value pairs, stop at blank line ===
    let mut meta_lines: Vec<(String, String)> = Vec::new();
    let mut found_separator = false;

    for line in lines.by_ref() {
        if line.is_empty() {
            found_separator = true;
            break;
        }
        let kv = parse_meta_line(line)?;
        meta_lines.push(kv);
    }

    if !found_separator {
        return Err(SealedError::FormatInvalid);
    }

    // === Body: one line ===
    let body_line = lines.next().ok_or(SealedError::FormatInvalid)?.to_string();
    if body_line.is_empty() {
        return Err(SealedError::FormatInvalid);
    }
    if !is_valid_b64(&body_line) {
        return Err(SealedError::FormatInvalid);
    }

    // === Parse metadata in strict order ===
    parse_metadata(magic_line, mode, meta_lines, body_line)
}

fn parse_magic_line(line: &str) -> Result<SealedMode, SealedError> {
    let prefix = "SEALED-ENV-V1 MODE=";
    if !line.starts_with(prefix) {
        return Err(SealedError::FormatInvalid);
    }
    match &line[prefix.len()..] {
        "basic" => Ok(SealedMode::Basic),
        "team" => Ok(SealedMode::Team),
        "enterprise" => Ok(SealedMode::Enterprise),
        _ => Err(SealedError::FormatInvalid),
    }
}

fn parse_meta_line(line: &str) -> Result<(String, String), SealedError> {
    // Must contain exactly one '=' not at start/end
    let eq_pos = line.find('=').ok_or(SealedError::FormatInvalid)?;
    if eq_pos == 0 {
        return Err(SealedError::FormatInvalid);
    }
    let key = line[..eq_pos].to_string();
    let value = line[eq_pos + 1..].to_string();

    // Key must be uppercase ASCII + hyphens
    if !key.chars().all(|c| c.is_ascii_uppercase() || c == '-') {
        return Err(SealedError::FormatInvalid);
    }
    // Value must not contain '\n' or spaces
    if value.contains('\n') || value.contains(' ') {
        return Err(SealedError::FormatInvalid);
    }

    Ok((key, value))
}

/// The expected key order per SPEC §4.
const FIELD_ORDER: &[&str] = &[
    "KDF",
    "KDF-PARAMS",
    "SALT",
    "NONCE",
    "EPOCH-COMMIT",   // enterprise only
    "CHALLENGE-BIND", // enterprise only
    "AAD-DIGEST",
    "HMAC", // team + enterprise
    "CREATED",
    "ROTATED", // optional
];

fn parse_metadata(
    _magic_line: &str,
    mode: SealedMode,
    meta_lines: Vec<(String, String)>,
    body: String,
) -> Result<SealedFile, SealedError> {
    // Check for duplicate keys
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (k, _) in &meta_lines {
        if !seen_keys.insert(k.clone()) {
            return Err(SealedError::FormatInvalid);
        }
    }

    // Check key order: iterate meta_lines and verify each key appears no earlier
    // than its position in FIELD_ORDER.
    let mut order_cursor = 0usize;
    for (key, _) in &meta_lines {
        let pos = FIELD_ORDER
            .iter()
            .position(|&k| k == key)
            .ok_or(SealedError::FormatInvalid)?;
        if pos < order_cursor {
            return Err(SealedError::FormatInvalid);
        }
        order_cursor = pos;
    }

    // Extract fields
    let get = |k: &str| -> Option<&str> {
        meta_lines
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };

    let kdf_str = get("KDF").ok_or(SealedError::FormatInvalid)?;
    let kdf_params_str = get("KDF-PARAMS").ok_or(SealedError::FormatInvalid)?;
    let salt = get("SALT").ok_or(SealedError::FormatInvalid)?.to_string();
    let nonce = get("NONCE").ok_or(SealedError::FormatInvalid)?.to_string();
    let aad_digest = get("AAD-DIGEST")
        .ok_or(SealedError::FormatInvalid)?
        .to_string();
    let created = get("CREATED")
        .ok_or(SealedError::FormatInvalid)?
        .to_string();
    let rotated = get("ROTATED").map(|s| s.to_string());
    let hmac = get("HMAC").map(|s| s.to_string());
    let epoch_commit = get("EPOCH-COMMIT").map(|s| s.to_string());
    let challenge_bind = get("CHALLENGE-BIND").map(|s| s.to_string());

    // Validate base64 fields
    for (field_name, value) in [
        ("SALT", &salt),
        ("NONCE", &nonce),
        ("AAD-DIGEST", &aad_digest),
    ] {
        if !is_valid_b64(value) {
            let _ = field_name; // suppress unused warning
            return Err(SealedError::FormatInvalid);
        }
    }
    if let Some(ref h) = hmac {
        if !is_valid_b64(h) {
            return Err(SealedError::FormatInvalid);
        }
    }
    if let Some(ref ec) = epoch_commit {
        if !is_valid_b64(ec) {
            return Err(SealedError::FormatInvalid);
        }
    }

    // Mode-specific required fields
    match &mode {
        SealedMode::Enterprise => {
            if epoch_commit.is_none() || challenge_bind.is_none() {
                return Err(SealedError::FormatInvalid);
            }
            if hmac.is_none() {
                return Err(SealedError::FormatInvalid);
            }
        }
        SealedMode::Team => {
            if hmac.is_none() {
                return Err(SealedError::FormatInvalid);
            }
        }
        SealedMode::Basic => {}
    }

    // Parse KDF
    let (kdf, kdf_params) = parse_kdf(kdf_str, kdf_params_str)?;

    Ok(SealedFile {
        mode,
        kdf,
        kdf_params,
        salt,
        nonce,
        epoch_commit,
        challenge_bind,
        aad_digest,
        hmac,
        created,
        rotated,
        body,
    })
}

fn parse_kdf(kdf: &str, params: &str) -> Result<(KdfKind, KdfParams), SealedError> {
    match kdf {
        "argon2id" => {
            // t=<int>,m=<int>,p=<int>
            let parsed = parse_argon2_params(params)?;
            Ok((KdfKind::Argon2id, parsed))
        }
        "scrypt" => {
            // N=<int>,r=<int>,p=<int>
            let parsed = parse_scrypt_params(params)?;
            Ok((KdfKind::Scrypt, parsed))
        }
        _ => Err(SealedError::FormatInvalid),
    }
}

fn parse_argon2_params(s: &str) -> Result<KdfParams, SealedError> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err(SealedError::FormatInvalid);
    }
    let t = parse_int_param(parts[0], "t")?;
    let m = parse_int_param(parts[1], "m")?;
    let p = parse_int_param(parts[2], "p")?;
    Ok(KdfParams::Argon2id { t, m, p })
}

fn parse_scrypt_params(s: &str) -> Result<KdfParams, SealedError> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err(SealedError::FormatInvalid);
    }
    let n = parse_u64_param(parts[0], "N")?;
    let r = parse_int_param(parts[1], "r")?;
    let p = parse_int_param(parts[2], "p")?;
    Ok(KdfParams::Scrypt { n, r, p })
}

fn parse_int_param(s: &str, expected_key: &str) -> Result<u32, SealedError> {
    let eq = s.find('=').ok_or(SealedError::FormatInvalid)?;
    let key = &s[..eq];
    let val = &s[eq + 1..];
    if key != expected_key {
        return Err(SealedError::FormatInvalid);
    }
    val.parse::<u32>().map_err(|_| SealedError::FormatInvalid)
}

fn parse_u64_param(s: &str, expected_key: &str) -> Result<u64, SealedError> {
    let eq = s.find('=').ok_or(SealedError::FormatInvalid)?;
    let key = &s[..eq];
    let val = &s[eq + 1..];
    if key != expected_key {
        return Err(SealedError::FormatInvalid);
    }
    val.parse::<u64>().map_err(|_| SealedError::FormatInvalid)
}

/// Serialize a `SealedFile` back to the canonical text format.
pub fn serialize(file: &SealedFile) -> String {
    let mut lines = Vec::new();

    // Magic line
    lines.push(format!("SEALED-ENV-V1 MODE={}", file.mode.as_str()));

    // Metadata in spec order
    let kdf_str = match &file.kdf {
        KdfKind::Argon2id => "argon2id",
        KdfKind::Scrypt => "scrypt",
    };
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
    lines.push(format!("AAD-DIGEST={}", file.aad_digest));
    if let Some(ref h) = file.hmac {
        lines.push(format!("HMAC={}", h));
    }
    lines.push(format!("CREATED={}", file.created));
    if let Some(ref r) = file.rotated {
        lines.push(format!("ROTATED={}", r));
    }

    // Blank separator + body
    lines.push(String::new());
    lines.push(file.body.clone());

    lines.join("\n")
}

/// Build the AAD bytes: magic_line + "\n" + metadata_canonical_form (metadata lines joined
/// by "\n", NO trailing newline, HMAC line excluded).
pub fn build_aad(file: &SealedFile) -> Vec<u8> {
    let magic = format!("SEALED-ENV-V1 MODE={}", file.mode.as_str());

    let mut meta_parts: Vec<String> = Vec::new();
    let kdf_str = match &file.kdf {
        KdfKind::Argon2id => "argon2id",
        KdfKind::Scrypt => "scrypt",
    };
    meta_parts.push(format!("KDF={}", kdf_str));
    meta_parts.push(format!("KDF-PARAMS={}", file.kdf_params.as_str()));
    meta_parts.push(format!("SALT={}", file.salt));
    meta_parts.push(format!("NONCE={}", file.nonce));
    if let Some(ref ec) = file.epoch_commit {
        meta_parts.push(format!("EPOCH-COMMIT={}", ec));
    }
    if let Some(ref cb) = file.challenge_bind {
        meta_parts.push(format!("CHALLENGE-BIND={}", cb));
    }
    meta_parts.push(format!("AAD-DIGEST={}", file.aad_digest));
    // HMAC is excluded from AAD
    meta_parts.push(format!("CREATED={}", file.created));
    if let Some(ref r) = file.rotated {
        meta_parts.push(format!("ROTATED={}", r));
    }

    let canonical = meta_parts.join("\n");
    format!("{}\n{}", magic, canonical).into_bytes()
}

/// Build the HMAC input: magic_line || metadata_without_HMAC || ciphertext_with_tag
/// (all bytes concatenated directly, with '\n' between metadata lines but
/// the HMAC line itself excluded).
pub fn build_hmac_input(file: &SealedFile, ciphertext_with_tag: &[u8]) -> Vec<u8> {
    let mut buf = build_aad(file);
    buf.extend_from_slice(ciphertext_with_tag);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=basic\nKDF=scrypt\nKDF-PARAMS=N=32768,r=8,p=1\nSALT=cjEZ9LJdMm7EB+XJmuDIlg==\nNONCE=auNcyoBkKZkm6np7\nAAD-DIGEST=SwCUaIOaLblHUq4AZQZJkJ+uQWNPjGKiNLqPn24x8xo=\nCREATED=2026-05-07T04:26:07.314Z\n\n5INrQBHklbC3giGmO2L4S8SbZB8F5UKd21whO7Jp4uUz+RQxxtzlqtyZIzkqI4CmBvFt1tNTQsX0ce0="
    }

    fn team_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=team\nKDF=scrypt\nKDF-PARAMS=N=32768,r=8,p=1\nSALT=huM5+57SPMO2P9jXxjuTAA==\nNONCE=jqSUI2Grdx0MFs8Q\nAAD-DIGEST=tytwlpq9gBl7aCnbE6hMbdF/RsUGuI7IdfEA18x+MqQ=\nHMAC=Iwzo3aQK5yOFE9Kk0NKjZfXuG+/6T4W2YSESHFF9T/s=\nCREATED=2026-05-07T04:26:07.596Z\n\nzR74Rx95lFsY3csJEg4RMifWKIv/c2U5T4qF8CRnx/yPwz4YNUyYAWHTsjuSxl3V+Ei3MZIRdJxMQac="
    }

    fn enterprise_serialized() -> &'static str {
        "SEALED-ENV-V1 MODE=enterprise\nKDF=scrypt\nKDF-PARAMS=N=32768,r=8,p=1\nSALT=14CTlMMsDqA0aw02u7NBRQ==\nNONCE=ekCHpjTcJfyLLk6R\nEPOCH-COMMIT=UkROU3FZIlmECGLFsbfthlQWhqO2x0JbGjxmNi/2qsQ=\nCHALLENGE-BIND=disabled\nAAD-DIGEST=f7TqR6VnpnZiJSmp2XJ189tMu5/bAzFYOa2oELG3OkU=\nHMAC=yQ9pw2cNDGAcVd/S+Hm558ReHusswsCRx4vhUaKUuqY=\nCREATED=2026-05-07T04:26:01.492Z\n\nRjsD6WlScnm9b4OWmj6Jck0lyTzGFdx/2/IdkpbZr3FMy6PHkfVz/fuaPRniibjmRPylpEpDKsxh1OY="
    }

    #[test]
    fn parse_basic_vector() {
        let f = parse(basic_serialized()).expect("parse basic");
        assert_eq!(f.mode, SealedMode::Basic);
        assert_eq!(f.kdf, KdfKind::Scrypt);
        assert_eq!(f.salt, "cjEZ9LJdMm7EB+XJmuDIlg==");
        assert_eq!(f.nonce, "auNcyoBkKZkm6np7");
        assert!(f.hmac.is_none());
        assert_eq!(f.created, "2026-05-07T04:26:07.314Z");
    }

    #[test]
    fn roundtrip_basic_vector() {
        let original = basic_serialized();
        let f = parse(original).expect("parse");
        let out = serialize(&f);
        assert_eq!(out, original);
    }

    #[test]
    fn roundtrip_team_vector() {
        let original = team_serialized();
        let f = parse(original).expect("parse");
        let out = serialize(&f);
        assert_eq!(out, original);
    }

    #[test]
    fn roundtrip_enterprise_vector() {
        let original = enterprise_serialized();
        let f = parse(original).expect("parse");
        let out = serialize(&f);
        assert_eq!(out, original);
    }

    #[test]
    fn reject_unknown_mode() {
        let input = "SEALED-ENV-V1 MODE=supermode\nKDF=argon2id\nKDF-PARAMS=t=3,m=65536,p=4\nSALT=AAAAAAAAAAAAAAAA\nNONCE=AAAAAAAAAAAA\nAAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nCREATED=2026-01-01T00:00:00Z\n\nAAAAA=";
        assert_eq!(parse(input), Err(SealedError::FormatInvalid));
    }

    #[test]
    fn reject_wrong_prefix() {
        let input = "SEALED-ENV-V2 MODE=basic\nKDF=argon2id\nKDF-PARAMS=t=3,m=65536,p=4\nSALT=AAAAAAAAAAAAAAAA\nNONCE=AAAAAAAAAAAA\nAAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nCREATED=2026-01-01T00:00:00Z\n\nAAAAA=";
        assert_eq!(parse(input), Err(SealedError::FormatInvalid));
    }

    #[test]
    fn reject_wrong_field_order_nonce_before_salt() {
        // NONCE before SALT violates spec order
        let input = "SEALED-ENV-V1 MODE=basic\nKDF=argon2id\nKDF-PARAMS=t=3,m=65536,p=4\nNONCE=AAAAAAAAAAAA\nSALT=AAAAAAAAAAAAAAAA\nAAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nCREATED=2026-01-01T00:00:00Z\n\nAAAAA=";
        assert_eq!(parse(input), Err(SealedError::FormatInvalid));
    }

    #[test]
    fn reject_duplicate_keys() {
        let input = "SEALED-ENV-V1 MODE=basic\nKDF=argon2id\nKDF=argon2id\nKDF-PARAMS=t=3,m=65536,p=4\nSALT=AAAAAAAAAAAAAAAA\nNONCE=AAAAAAAAAAAA\nAAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nCREATED=2026-01-01T00:00:00Z\n\nAAAAA=";
        assert_eq!(parse(input), Err(SealedError::FormatInvalid));
    }

    #[test]
    fn reject_value_with_space() {
        let input = "SEALED-ENV-V1 MODE=basic\nKDF=argon2 id\nKDF-PARAMS=t=3,m=65536,p=4\nSALT=AAAAAAAAAAAAAAAA\nNONCE=AAAAAAAAAAAA\nAAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nCREATED=2026-01-01T00:00:00Z\n\nAAAAA=";
        assert_eq!(parse(input), Err(SealedError::FormatInvalid));
    }

    #[test]
    fn parse_scrypt_params() {
        let f = parse(basic_serialized()).expect("parse");
        assert_eq!(
            f.kdf_params,
            KdfParams::Scrypt {
                n: 32768,
                r: 8,
                p: 1
            }
        );
    }

    #[test]
    fn parse_argon2id_params() {
        let input = "SEALED-ENV-V1 MODE=basic\nKDF=argon2id\nKDF-PARAMS=t=3,m=65536,p=4\nSALT=AAAAAAAAAAAAAAAAAAAAAA==\nNONCE=AAAAAAAAAAAAAAAA\nAAD-DIGEST=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nCREATED=2026-01-01T00:00:00Z\n\nAAAAAAAAA=";
        let f = parse(input).expect("parse argon2id");
        assert_eq!(
            f.kdf_params,
            KdfParams::Argon2id {
                t: 3,
                m: 65536,
                p: 4
            }
        );
    }

    #[test]
    fn parse_enterprise_fields() {
        let f = parse(enterprise_serialized()).expect("parse enterprise");
        assert_eq!(f.mode, SealedMode::Enterprise);
        assert!(f.epoch_commit.is_some());
        assert_eq!(f.challenge_bind.as_deref(), Some("disabled"));
        assert!(f.hmac.is_some());
    }
}
