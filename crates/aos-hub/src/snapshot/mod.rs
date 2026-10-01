//! Offline database capture without serving or provider initialization.
//!
//! This module exposes audited Native SQLite/PostgreSQL capture and private archive
//! orchestration. It never initializes a Hub, installs storage authority,
//! imports SQL, executes jobs or authorizes activation.

pub mod capture;
pub mod scratch;
#[cfg(target_os = "linux")]
pub mod inventory;

mod credentials;
#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
pub mod workflow;

pub use credentials::{CaptureCredentials, VerifyCredentials, WrappingFiles};

#[cfg(all(test, target_os = "linux"))]
mod tests;
