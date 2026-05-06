use crate::domain::{error::DotLockError, model::DotLockResult};

const CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

pub const MIN_PASSWORD_LEN: usize = 12;

pub fn generate_password(len: usize) -> DotLockResult<String> {
    for _ in 0..16 {
        let mut bytes = vec![0u8; len];
        getrandom::fill(&mut bytes).map_err(|e| DotLockError::Crypto(e.to_string()))?;
        let pwd: String = bytes
            .iter()
            .map(|b| CHARSET[*b as usize % CHARSET.len()] as char)
            .collect();
        if validate_password_strength(&pwd).is_ok() {
            return Ok(pwd);
        }
    }
    Err(DotLockError::Crypto(
        "could not generate a strong password".into(),
    ))
}

pub fn validate_password_strength(pwd: &str) -> DotLockResult<()> {
    let mut missing: Vec<&str> = Vec::new();

    if pwd.chars().count() < MIN_PASSWORD_LEN {
        missing.push("at least 12 characters");
    }
    if !pwd.chars().any(|c| c.is_ascii_lowercase()) {
        missing.push("a lowercase letter");
    }
    if !pwd.chars().any(|c| c.is_ascii_uppercase()) {
        missing.push("an uppercase letter");
    }
    if !pwd.chars().any(|c| c.is_ascii_digit()) {
        missing.push("a digit");
    }
    if !pwd
        .chars()
        .any(|c| c.is_ascii_punctuation() && !c.is_ascii_alphanumeric())
    {
        missing.push("a symbol");
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(DotLockError::WeakPassword {
            missing: missing.join(", "),
        })
    }
}
