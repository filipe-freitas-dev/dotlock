use crate::domain::{error::DotLockError, model::DotLockResult};

const CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

pub const MIN_PASSWORD_LEN: usize = 12;

/// Draws one uniformly distributed charset character from the OS CSPRNG using
/// rejection sampling (L2): bytes in the truncated tail of the 0..=255 range
/// (`256 % CHARSET.len()` values) are discarded and redrawn, so every charset
/// index is exactly equiprobable — a plain `byte % len` would make the first
/// `256 % len` characters ~1.3x more likely.
fn random_charset_char() -> DotLockResult<char> {
    // Largest multiple of CHARSET.len() that fits in a byte; bytes at or
    // above it would wrap unevenly and are rejected.
    let limit = (256 / CHARSET.len()) * CHARSET.len();
    loop {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).map_err(|e| DotLockError::Crypto(e.to_string()))?;
        if (byte[0] as usize) < limit {
            return Ok(CHARSET[byte[0] as usize % CHARSET.len()] as char);
        }
    }
}

pub fn generate_password(len: usize) -> DotLockResult<String> {
    for _ in 0..16 {
        let mut pwd = String::with_capacity(len);
        for _ in 0..len {
            pwd.push(random_charset_char()?);
        }
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

#[cfg(test)]
mod tests {
    use super::{CHARSET, generate_password, validate_password_strength};

    #[test]
    fn generated_password_has_requested_length_and_charset_membership() {
        for len in [12, 24, 32] {
            let pwd = generate_password(len).expect("generate");
            assert_eq!(pwd.chars().count(), len);
            assert!(
                pwd.bytes().all(|b| CHARSET.contains(&b)),
                "password contains a byte outside the charset: {pwd:?}"
            );
            validate_password_strength(&pwd).expect("strength");
        }
    }

    /// Statistical smoke test for the L2 fix: with `byte % 74` the first
    /// `256 % 74 = 34` charset positions were ~33% more likely. Rejection
    /// sampling makes every index equiprobable, so over a large sample the
    /// biased head must not exceed its fair share by a wide margin.
    #[test]
    fn charset_distribution_is_not_modulo_biased() {
        let biased_head = 256 % CHARSET.len(); // 34 for the 74-char set
        let mut head_hits = 0usize;
        let mut total = 0usize;
        for _ in 0..500 {
            let pwd = generate_password(32).expect("generate");
            for b in pwd.bytes() {
                let index = CHARSET.iter().position(|&c| c == b).expect("in charset");
                if index < biased_head {
                    head_hits += 1;
                }
                total += 1;
            }
        }
        let observed = head_hits as f64 / total as f64;
        let fair = biased_head as f64 / CHARSET.len() as f64; // ~0.459
        // With `byte % 74`, each of the 34 head indices maps from 4 byte
        // values (74*3 = 222, remainder 34) while the rest map from 3, so
        // the head's aggregate share is 34*4/256 ~ 0.531 vs the fair 34/74
        // ~ 0.459. Assert we sit clearly on the fair side of the midpoint
        // (~0.495), with slack for sampling noise.
        let biased = (4.0 * biased_head as f64) / 256.0;
        assert!(
            observed < (fair + biased) / 2.0,
            "head frequency {observed:.4} suggests modulo bias (fair={fair:.4}, biased={biased:.4})"
        );
        assert!(
            (observed - fair).abs() < 0.03,
            "head frequency {observed:.4} too far from fair share {fair:.4}"
        );
    }
}
