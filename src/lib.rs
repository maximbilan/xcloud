//! xcloud library exports.
//!
//! This crate now follows a modular architecture with three top-level modules:
//! - `asc`: App Store Connect API client and data access
//! - `cli`: CLI types and command handlers
//! - `util`: shared helpers used by the client and CLI

pub mod asc;
pub mod cli;
pub mod util;

// Re-export commonly used helpers to preserve the existing public API
pub use util::{
    compare_runs_desc, is_branch_git_ref, pretty_run_status, resource_id, resource_name,
};

// Re-export client/config so external code and tests can access them via `xcloud::...`
pub use asc::{AppStoreConnectClient, Config};
