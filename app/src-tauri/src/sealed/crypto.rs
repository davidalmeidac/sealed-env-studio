use super::errors::SealedError;
use super::format::KdfParams;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// Argon2id defaults (SPEC §8)
pub const ARGON2_T_DEFAULT: u32 = 3;
pub const ARGON2_M_DEFAULT: u32 = 65536;
pub const ARGON2_P_DEFAULT: u32 = 4;

// Argon2id floors
pub const ARGON2_T_MIN: u32 = 2;
pub const ARGON2_M_MIN: u32 = 16384;
pub const ARGON2_P_MIN: u32 = 1;

/// Derive a 32-byte key with Argon2id.
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; 32], SealedError> {
    let (t, m, p) = match params {
        KdfParams::Argon2id { t, m, p } => (*t, *m, *p),
        _ => (ARGON2_T_DEFAULT, ARGON2_M_DEFAULT, ARGON2_P_DEFAULT),
    };

    let argon2_params = Params::new(m, t, p, Some(32)).map_err(|_| SealedError::DecryptFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| SealedError::DecryptFailed)?;
    Ok(out)
}

/// Derive a 32-byte key with scrypt.
pub fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; 32], SealedError> {
    let (n, r, p) = match params {
        KdfParams::Scrypt { n, r, p } => (*n, *r, *p),
        _ => return Err(SealedError::DecryptFailed),
    };

    // scrypt::Params expects log2(N)
    let log_n = (n as f64).log2().round() as u8;
    let scrypt_params =
        scrypt::Params::new(log_n, r, p, 32).map_err(|_| SealedError::DecryptFailed)?;

    let mut out = [0u8; 32];
    scrypt::scrypt(password, salt, &scrypt_params, &mut out)
        .map_err(|_| SealedError::DecryptFailed)?;
    Ok(out)
}

/// Dispatch KDF based on params variant.
pub fn kdf_derive(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; 32], SealedError> {
    match params {
        KdfParams::Argon2id { .. } => argon2id_derive(password, salt, params),
        KdfParams::Scrypt { .. } => scrypt_derive(password, salt, params),
    }
}

/// Expand a PRK with HKDF-SHA256.
pub fn hkdf_expand(prk: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), prk);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("HKDF expand length must be valid");
    out
}

/// Encrypt plaintext with AES-256-GCM. Returns ciphertext || 16-byte auth tag.
pub fn aes256gcm_encrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce, payload)
        .expect("AES-GCM encrypt must not fail")
}

/// Decrypt ciphertext (with appended 16-byte auth tag) using AES-256-GCM.
pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SealedError> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| SealedError::DecryptFailed)
}

/// Compute HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length is valid");
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Verify HMAC-SHA256 in constant time.
pub fn hmac_verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), SealedError> {
    let computed = hmac_sha256(key, data);
    if computed.ct_eq(expected).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(SealedError::DecryptFailed)
    }
}

/// Generate `n` cryptographically random bytes using OS CSPRNG.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::format::KdfParams;

    fn argon2id_params() -> KdfParams {
        KdfParams::Argon2id {
            t: ARGON2_T_DEFAULT,
            m: ARGON2_M_DEFAULT,
            p: ARGON2_P_DEFAULT,
        }
    }

    fn scrypt_params(n: u64) -> KdfParams {
        KdfParams::Scrypt { n, r: 8, p: 1 }
    }

    #[test]
    fn argon2id_deterministic() {
        let pw = b"test-password";
        let salt = b"0123456789abcdef"; // 16 bytes
        let params = argon2id_params();
        let k1 = argon2id_derive(pw, salt, &params).unwrap();
        let k2 = argon2id_derive(pw, salt, &params).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn scrypt_deterministic() {
        let pw = b"test-password";
        let salt = b"0123456789abcdef";
        let params = scrypt_params(1024); // small N for test speed
        let k1 = scrypt_derive(pw, salt, &params).unwrap();
        let k2 = scrypt_derive(pw, salt, &params).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_expand_length_correct() {
        let prk = [0u8; 32];
        let salt = b"test-salt";
        let info = b"test-info";
        let out = hkdf_expand(&prk, salt, info, 32);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn hkdf_expand_deterministic() {
        let prk = [1u8; 32];
        let salt = b"salt";
        let info = b"sealed-env:v1:enc";
        let a = hkdf_expand(&prk, salt, info, 32);
        let b = hkdf_expand(&prk, salt, info, 32);
        assert_eq!(a, b);
    }

    #[test]
    fn gcm_tamper_detection() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let aad = b"test-aad";
        let mut ct = aes256gcm_encrypt(&key, &nonce, plaintext, aad);
        ct[0] ^= 0xff; // flip a byte
        let result = aes256gcm_decrypt(&key, &nonce, &ct, aad);
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }

    #[test]
    fn gcm_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"API_KEY=hello\n";
        let aad = b"some-aad";
        let ct = aes256gcm_encrypt(&key, &nonce, plaintext, aad);
        let pt = aes256gcm_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn hmac_verify_correct() {
        let key = b"secret-key";
        let data = b"some data";
        let tag = hmac_sha256(key, data);
        assert!(hmac_verify(key, data, &tag).is_ok());
    }

    #[test]
    fn hmac_verify_mismatch_returns_decrypt_failed() {
        let key = b"secret-key";
        let data = b"some data";
        let mut tag = hmac_sha256(key, data);
        tag[0] ^= 0x01; // corrupt 1 byte
        let result = hmac_verify(key, data, &tag);
        assert_eq!(result, Err(SealedError::DecryptFailed));
    }

    #[test]
    fn random_bytes_correct_length() {
        let b = random_bytes(16);
        assert_eq!(b.len(), 16);
    }

    #[test]
    fn random_bytes_unique() {
        let a = random_bytes(32);
        let b = random_bytes(32);
        // Extremely unlikely to collide
        assert_ne!(a, b);
    }

    #[test]
    fn kdf_dispatch_argon2id() {
        let params = argon2id_params();
        let key = kdf_derive(b"pw", b"0123456789abcdef", &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn kdf_dispatch_scrypt() {
        let params = scrypt_params(1024);
        let key = kdf_derive(b"pw", b"0123456789abcdef", &params).unwrap();
        assert_eq!(key.len(), 32);
    }
}
