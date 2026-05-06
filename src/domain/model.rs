use crate::domain::error::DotLockError;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub type DotLockResult<T> = Result<T, DotLockError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct DataEncrypted<'a> {
    pub alg: &'a str,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Alg {
    #[value(name = "xcha", alias = "chacha20-poly1305")]
    XChaCha20Poly1305,
}
