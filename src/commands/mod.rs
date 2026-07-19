//! Application/use-case layer: one module per top-level `dl` subcommand.
//! `main.rs` only parses the CLI and routes here; these functions orchestrate
//! storage/crypto and print the user-facing output.

pub mod audit;
pub mod cert;
pub mod config;
pub mod context;
pub mod env;
pub mod exec;
pub mod export;
pub mod get;
pub mod git;
pub mod init;
pub mod list;
pub mod lock;
pub mod migrate;
pub mod provider;
pub mod reconcile;
pub mod repair;
pub mod rotate;
pub mod run;
pub mod set;
pub mod share;
pub mod sync;
pub mod unset;
