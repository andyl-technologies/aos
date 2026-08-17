//! Tests for file-artifact materialization, hydration, and parse-artifact entries.

use super::*;
use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockError, AdvisoryFileLockMode};
use std::io::ErrorKind;
use std::time::{Duration, Instant};

mod file_artifact_hydration;
mod file_artifact_materialization;
mod file_index;
mod parse_artifact_entry_materialization;
mod parse_index;
mod source_index;

fn wait_until_advisory_try_lock_blocks(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match AdvisoryFileLock::try_lock(path, AdvisoryFileLockMode::Exclusive) {
            Ok(lock) => drop(lock),
            Err(AdvisoryFileLockError::Lock { source, .. })
                if source.kind() == ErrorKind::WouldBlock =>
            {
                return;
            }
            Err(error) => panic!("advisory lock probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "worker did not acquire advisory lock before the deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
