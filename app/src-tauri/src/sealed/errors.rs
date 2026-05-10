use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TokenInvalidReason {
    #[error("malformed epoch field")]
    MalformedEpoch,
    #[error("token expired")]
    Expired,
    #[error("token lifetime exceeds maximum")]
    LifetimeTooLong,
    #[error("epoch commitment mismatch")]
    EpochMismatch,
    #[error("invalid token structure")]
    BadStructure,
    #[error("invalid token signature")]
    BadSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SealedError {
    #[error("decrypt failed")]
    DecryptFailed,

    #[error("missing required key")]
    MissingKey,

    #[error("format invalid")]
    FormatInvalid,

    #[error("token invalid: {0}")]
    TokenInvalid(TokenInvalidReason),

    #[error("token replay detected")]
    TokenReplay,

    #[error("validation error: {0}")]
    ValidationError(String),
}

impl SealedError {
    /// Collapse any error to `DecryptFailed` UNLESS it is `TokenInvalid` or `MissingKey`.
    /// This is the oracle-defense collapse used in `sealed::mod` after crypto operations.
    pub fn collapse_to_decrypt_failed(self) -> SealedError {
        match self {
            SealedError::TokenInvalid(_) => self,
            SealedError::MissingKey => self,
            _ => SealedError::DecryptFailed,
        }
    }
}

impl serde::Serialize for SealedError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_failed_variant_exists() {
        let e = SealedError::DecryptFailed;
        assert_eq!(e, SealedError::DecryptFailed);
    }

    #[test]
    fn missing_key_variant_exists() {
        let e = SealedError::MissingKey;
        assert_eq!(e, SealedError::MissingKey);
    }

    #[test]
    fn format_invalid_variant_exists() {
        let e = SealedError::FormatInvalid;
        assert_eq!(e, SealedError::FormatInvalid);
    }

    #[test]
    fn token_invalid_with_reason() {
        let e = SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch);
        match e {
            SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch) => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn token_replay_variant_exists() {
        let e = SealedError::TokenReplay;
        assert_eq!(e, SealedError::TokenReplay);
    }

    #[test]
    fn validation_error_variant_exists() {
        let e = SealedError::ValidationError("bad hex".to_string());
        match e {
            SealedError::ValidationError(msg) => assert_eq!(msg, "bad hex"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn collapse_decrypt_failed_stays() {
        let e = SealedError::DecryptFailed;
        assert_eq!(e.collapse_to_decrypt_failed(), SealedError::DecryptFailed);
    }

    #[test]
    fn collapse_format_invalid_becomes_decrypt_failed() {
        let e = SealedError::FormatInvalid;
        assert_eq!(e.collapse_to_decrypt_failed(), SealedError::DecryptFailed);
    }

    #[test]
    fn collapse_token_invalid_is_preserved() {
        let e = SealedError::TokenInvalid(TokenInvalidReason::MalformedEpoch);
        let collapsed = e.clone().collapse_to_decrypt_failed();
        assert_eq!(collapsed, e);
    }

    #[test]
    fn collapse_missing_key_is_preserved() {
        let e = SealedError::MissingKey;
        assert_eq!(e.collapse_to_decrypt_failed(), SealedError::MissingKey);
    }

    #[test]
    fn collapse_token_replay_becomes_decrypt_failed() {
        let e = SealedError::TokenReplay;
        assert_eq!(e.collapse_to_decrypt_failed(), SealedError::DecryptFailed);
    }

    #[test]
    fn collapse_validation_error_becomes_decrypt_failed() {
        let e = SealedError::ValidationError("x".into());
        assert_eq!(e.collapse_to_decrypt_failed(), SealedError::DecryptFailed);
    }
}
