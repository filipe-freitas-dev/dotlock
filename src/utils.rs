use crate::domain::{error::DotLockError, model::Alg, model::DotLockResult};

pub fn parse_alg(alg: &str) -> DotLockResult<Alg> {
    match alg {
        "xchacha20-poly1305" => Ok(Alg::XChaCha20Poly1305),
        other => Err(DotLockError::UnsupportedAlgorithm {
            alg: other.to_string(),
        }),
    }
}

pub fn normalize_var_name(name: &str) -> DotLockResult<String> {
    let mut chars = name.chars();

    let first = chars.next().ok_or_else(|| DotLockError::InvalidVariableName {
        name: name.to_string(),
    })?;

    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(DotLockError::InvalidVariableName {
            name: name.to_string(),
        });
    }

    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(DotLockError::InvalidVariableName {
            name: name.to_string(),
        });
    }

    Ok(name.to_ascii_uppercase())
}
