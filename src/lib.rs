//! xcloud library exports.
//! Modular architecture with three modules:
//! - `asc`: App Store Connect API client and data access
//! - `cli`: CLI types and command handlers
//! - `util`: shared helpers used by the client and CLI

pub mod util;
pub mod asc;
pub mod cli;

// Re-export commonly used helpers to preserve the existing public API
pub use util::{
    compare_runs_desc,
    is_branch_git_ref,
    pretty_run_status,
    resource_id,
    resource_name,
};

// Re-export client/config so external code and tests can access them via `xcloud::...`
pub use asc::{AppStoreConnectClient, Config};
