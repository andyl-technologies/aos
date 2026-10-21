//! Exercises the canonical settled Source comparison with real Domain fixtures.
//!
//! The live Root owner and its borrowed current floors now belong to Policy.
//! This test-only adapter retains the existing genuine Source append/signature,
//! ACK, compaction and cold-reopen regressions without a reverse crate edge.

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_ledger_replay::source_signer_data::VerifiedSourceTreeGenesisReadbackV1;
use aos_sandbox_ledger_replay::replay::root_genesis_records::SourceHierarchyFloorRecordV1;

fn require_anchored_observation(
    observed: &VerifiedSourceTreeGenesisReadbackV1,
    floor: &SourceHierarchyFloorRecordV1,
) -> Result<(), SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_records::require_anchored_observation_data_v1(
        observed, floor,
    ).map_err(SourceGenesisErrorV1::from)
}

#[cfg(test)]
mod tests;
