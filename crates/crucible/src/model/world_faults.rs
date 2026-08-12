//! Executable World declarations addressed by signal-driven fault bindings.
//!
//! The topology owner validates cross-family references. Network, storage, and
//! node modules own their respective immutable declaration schemas.

use super::*;

mod network;
mod node;
mod storage;
mod topology;

pub use network::*;
pub use node::*;
pub use storage::*;
pub use topology::*;

#[cfg(test)]
#[path = "world_faults_test.rs"]
mod tests;
