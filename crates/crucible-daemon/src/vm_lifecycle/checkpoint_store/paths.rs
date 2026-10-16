//! Durable checkpoint-store path derivation.

use super::*;

/// Returns the scenario-local directory of authenticated closure manifests.
pub(super) fn closure_parent(run_state_root: &Path, scenario: ContentHash) -> PathBuf {
    run_state_root
        .join(scenario.to_hex())
        .join("checkpoint-closures")
}

/// Returns the scenario-local content-addressed object directory.
pub(super) fn object_parent(run_state_root: &Path, scenario: ContentHash) -> PathBuf {
    run_state_root
        .join(scenario.to_hex())
        .join("checkpoint-objects")
}
