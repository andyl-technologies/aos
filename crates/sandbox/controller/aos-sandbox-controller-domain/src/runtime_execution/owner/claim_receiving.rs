//! Prices the real Host claim's semantic replay and optional genesis appends.
//!
//! The four native openings have already been priced against their captured
//! prefixes. Claim additionally owns decoded execution/Agent graphs, reducer
//! history, lifecycle indices and the three possible store initializations.
//! This supplier borrows actual materialized bytes without decoding, allocating,
//! opening files, initializing a store or authenticating any of its contents.

use std::mem::size_of;

use aos_sandbox_guest_protocol::{AgentExecutionOutcomeV1, AgentFeatureV1, AgentFrameV1};
use aos_sandbox_model::model::{
    CapturedStreamV1, EnvironmentEntry, ExecutionEndpointCapabilityV1, ExecutionEnvironmentEntry,
    ExecutionPublicKeyV1, ExecutionResourceRequestV1, ExecutionResourceSublimitV1, ExecutionSpecV1,
    Limit,
};
use aos_sandbox_model::{FeatureRef, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, conservative_btree_node_bytes_v1};

use crate::journal::{Journal, JournalAppendReceivingDemandErrorV1, JournalError};

use super::{DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerV1};

impl DormantRuntimeExecutionOwnerV1 {
    /// Forecasts the complete first claim against these same four held journals.
    ///
    /// The genuine enclosing Host receiver must admit the additional demand
    /// before calling `claim`. Native opening/replay, later launch/effect work,
    /// independent name posts and earlier resident owners remain separate.
    /// Empty stores include their actual existing initialization appends. No
    /// journal mutation, decoding or authority construction occurs here.
    ///
    /// # Errors
    /// Rejects checked representation overflow or an unavailable actual native
    /// append geometry. A later semantic claim retains its own validation errors.
    pub fn initial_claim_receiving_demand_v2(
        &self,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        let mut complete = ResourceVector::ZERO;

        let fixed = size_of::<DormantRuntimeExecutionClaimV1<'_>>()
            .checked_add(size_of::<super::ResolvedOwnerCurrentnessV1>())
            .and_then(|bytes| bytes.checked_add(size_of::<ExecutionSpecV1>()))
            .and_then(|bytes| bytes.checked_add(size_of::<AgentFrameV1>()))
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or_else(overflow)?;
        complete = complete.checked_add(memory(fixed)?)?;

        // Peer decoding has two bounded, eleven-element capability vectors.
        // Include both canonical/raw record copies and constructor overlap.
        let mut peer_bytes = 0usize;
        for (key, value) in self
            .peer_journal
            .records(super::RecordNamespace::HostExecution)
        {
            peer_bytes = peer_bytes
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or_else(overflow)?;
        }
        let capabilities = size_of::<super::BackendCapabilityV1>()
            .checked_mul(22)
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or_else(overflow)?;
        complete = complete.checked_add(memory(
            peer_bytes
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(capabilities))
                .ok_or_else(overflow)?,
        )?)?;

        let execution = super::super::store::claim_replay_geometry_v2(&self.execution_journal)
            .ok_or_else(overflow)?;
        let agent = super::super::agent_store::claim_replay_geometry_v2(&self.agent_journal)
            .ok_or_else(overflow)?;
        complete = complete.checked_add(replay_demand(execution)?)?;
        complete = complete.checked_add(replay_demand(agent)?)?;

        let mut lifecycle_rows = 0usize;
        let mut lifecycle_bytes = 0usize;
        for (key, value) in self
            .lifecycle_journal
            .records(super::RecordNamespace::HostExecution)
        {
            lifecycle_rows = lifecycle_rows.checked_add(1).ok_or_else(overflow)?;
            lifecycle_bytes = lifecycle_bytes
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or_else(overflow)?;
        }
        // Terminal bytes, two sequence sets, sorted decoded terminal history
        // and its predecessor all coexist in open_lifecycle_store.
        let lifecycle_node = conservative_btree_node_bytes_v1::<[u8; 16], Vec<u8>>(1)
            .and_then(|bytes| bytes.checked_add(conservative_btree_node_bytes_v1::<u64, ()>(2)?))
            .and_then(|bytes| {
                bytes.checked_add(size_of::<super::LifecycleTerminalV1>().checked_mul(4)?)
            })
            .ok_or_else(overflow)?;
        complete = complete.checked_add(replay_demand(ReplayGeometry {
            rows: lifecycle_rows,
            encoded: lifecycle_bytes,
            node_bytes: lifecycle_node,
            dynamic: false,
        })?)?;

        // The very same empty-map condition precedes each existing initializer.
        // Forecast exact record keys/values without manufacturing their bytes.
        if empty(&self.execution_journal) {
            complete = complete.checked_add(
                self.execution_journal
                    .append_sequence_receiving_demand_v1([Ok([
                        RecordShape {
                            key_bytes: super::super::store::claim_owner_key_bytes_v2(),
                            value_bytes: Some(32),
                        },
                        RecordShape {
                            key_bytes: super::super::store::claim_authority_key_bytes_v2(),
                            value_bytes: Some(72),
                        },
                    ]
                    .into_iter())])?,
            )?;
        }
        if empty(&self.agent_journal) {
            complete = complete.checked_add(
                self.agent_journal
                    .append_sequence_receiving_demand_v1([Ok([RecordShape {
                        key_bytes: super::super::agent_store::claim_owner_key_bytes_v2(),
                        value_bytes: Some(64),
                    }]
                    .into_iter())])?,
            )?;
        }
        if empty(&self.lifecycle_journal) {
            complete = complete.checked_add(
                self.lifecycle_journal
                    .append_sequence_receiving_demand_v1([Ok([RecordShape {
                        key_bytes: super::LIFECYCLE_HEAD_KEY.len(),
                        value_bytes: Some(super::LIFECYCLE_HEAD_BYTES),
                    }]
                    .into_iter())])?,
            )?;
        }

        Ok(complete)
    }
}

/// Describes reached replay geometry, without interpreting any record as proof.
pub(in crate::runtime_execution) struct ReplayGeometry {
    pub(in crate::runtime_execution) rows: usize,
    pub(in crate::runtime_execution) encoded: usize,
    pub(in crate::runtime_execution) node_bytes: usize,
    pub(in crate::runtime_execution) dynamic: bool,
}

fn empty(journal: &Journal) -> bool {
    journal
        .historical_read_view_v1()
        .materialized_state_v1()
        .is_empty()
}

fn replay_demand(shape: ReplayGeometry) -> Result<ResourceVector, JournalError> {
    // Execution's fourteen primary maps, resource/sequence/commitment indices,
    // ordered/grouped vectors and output/global-capacity validation fit within
    // thirty-two parallel row planes. Agent's replay/reducer uses fewer. These
    // are actual temporary index entries, never a fee on Rust struct fields.
    let mut cells = shape.rows.checked_mul(32).ok_or_else(overflow)?;
    let mut bytes = cells
        .checked_mul(shape.node_bytes)
        .and_then(|bytes| bytes.checked_add(shape.encoded.checked_mul(32)?))
        .ok_or_else(overflow)?;
    if shape.dynamic {
        let cell = collection_cell_width();
        // Distinct successful collection elements consume encoded heads. Two
        // slots cover Vec growth; eight representations cover decode/model,
        // canonical encoding, cloned admission/effect, reducer and comparison.
        let nested_node = conservative_btree_node_bytes_v1::<
            super::ExecutionId,
            aos_sandbox_guest_protocol::AgentExecutionPhaseV1,
        >(1)
        .ok_or_else(overflow)?;
        let element = cell
            .checked_mul(2)
            .and_then(|width| width.checked_add(2))
            .ok_or_else(overflow)?
            .max(nested_node);
        let decoded = shape
            .encoded
            .checked_mul(element)
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or_else(overflow)?;
        // A malformed final collection may reserve before its first element.
        // Core's durable execution decoder caps announced arrays at 65,536;
        // Agent checkpoints cap executions/history at 4,096/1,024, and its
        // frame feature arrays are smaller. Prior decoded rows are above.
        let announced = 65_536usize
            .checked_mul(cell)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(overflow)?;
        bytes = bytes
            .checked_add(decoded)
            .and_then(|bytes| bytes.checked_add(announced))
            .ok_or_else(overflow)?;
        // Reducer/checkpoint execution indices and their comparison planes
        // create real nested entries. Each successful element consumes input;
        // an unfilled announced Vec capacity is memory only, not an entry.
        cells = cells
            .checked_add(shape.encoded.checked_mul(8).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
    }
    Ok(memory(bytes)?.with(
        D::MetadataEntries,
        u64::try_from(cells).map_err(|_| overflow())?,
    ))
}

fn collection_cell_width() -> usize {
    [
        size_of::<String>(),
        size_of::<FeatureRef>(),
        size_of::<Limit>(),
        size_of::<EnvironmentEntry>(),
        size_of::<ExecutionEnvironmentEntry>(),
        size_of::<ExecutionResourceRequestV1>(),
        size_of::<ExecutionResourceSublimitV1>(),
        size_of::<ExecutionPublicKeyV1>(),
        size_of::<ExecutionEndpointCapabilityV1>(),
        size_of::<CapturedStreamV1>(),
        size_of::<AgentExecutionOutcomeV1>(),
        size_of::<AgentFeatureV1>(),
        size_of::<(super::ExecutionId, aos_sandbox_guest_protocol::AgentExecutionPhaseV1)>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
}

fn memory(bytes: usize) -> Result<ResourceVector, JournalError> {
    Ok(ResourceVector::ZERO.with(
        D::MemoryBytes,
        u64::try_from(bytes).map_err(|_| overflow())?,
    ))
}

fn overflow() -> JournalError {
    JournalError::LimitExceeded("Host claim semantic receiving geometry")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn forecast_preserves_native_prefixes_and_covers_all_three_real_initializers() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut owner = DormantRuntimeExecutionOwnerV1::provisioned_protected_at_uid_for_test(
            directory.path(),
            rustix::process::geteuid().as_raw(),
        )
        .unwrap();
        let names = [
            super::super::PEER_JOURNAL_NAME,
            super::super::EXECUTION_JOURNAL_NAME,
            super::super::AGENT_JOURNAL_NAME,
            super::super::LIFECYCLE_JOURNAL_NAME,
        ];
        let lengths = || {
            names.map(|name| {
                std::fs::metadata(directory.path().join(name))
                    .unwrap()
                    .len()
            })
        };
        let before = lengths();

        let demand = owner.initial_claim_receiving_demand_v2().unwrap();

        assert_eq!(lengths(), before);
        assert!(empty(&owner.execution_journal));
        assert!(empty(&owner.agent_journal));
        assert!(empty(&owner.lifecycle_journal));

        drop(owner.claim().unwrap());
        let after = lengths();
        let appended: u64 = after
            .iter()
            .zip(before)
            .map(|(after, before)| after - before)
            .sum();
        assert!(appended > 0);
        assert!(demand.get(D::StorageBytes) >= appended);
        assert_eq!(
            owner
                .execution_journal
                .records(super::super::RecordNamespace::Effect)
                .count(),
            2
        );
        assert_eq!(
            owner
                .agent_journal
                .records(super::super::RecordNamespace::Effect)
                .count(),
            1
        );
        assert_eq!(
            owner
                .lifecycle_journal
                .records(super::super::RecordNamespace::HostExecution)
                .count(),
            1
        );

        drop(owner.claim().unwrap());
        assert_eq!(lengths(), after);
    }

    #[test]
    fn truncated_dynamic_row_still_pays_announced_collection_reservation() {
        let plain = replay_demand(ReplayGeometry {
            rows: 1,
            encoded: 1,
            node_bytes: 1,
            dynamic: false,
        })
        .unwrap();
        let dynamic = replay_demand(ReplayGeometry {
            rows: 1,
            encoded: 1,
            node_bytes: 1,
            dynamic: true,
        })
        .unwrap();
        let announced = (65_536 * collection_cell_width() * 2) as u64;

        assert!(dynamic.get(D::MemoryBytes) >= plain.get(D::MemoryBytes) + announced);
        assert!(dynamic.get(D::MetadataEntries) > plain.get(D::MetadataEntries));
        assert_eq!(dynamic.get(D::OpenFiles), 0);
    }

    #[test]
    fn all_reached_rows_are_charged_and_arithmetic_cannot_wrap() {
        let one = replay_demand(ReplayGeometry {
            rows: 1,
            encoded: 8,
            node_bytes: 16,
            dynamic: false,
        })
        .unwrap();
        let two = replay_demand(ReplayGeometry {
            rows: 2,
            encoded: 16,
            node_bytes: 16,
            dynamic: false,
        })
        .unwrap();

        assert_eq!(two.get(D::MemoryBytes), 2 * one.get(D::MemoryBytes));
        assert_eq!(two.get(D::MetadataEntries), 2 * one.get(D::MetadataEntries));
        assert!(
            replay_demand(ReplayGeometry {
                rows: usize::MAX,
                encoded: 0,
                node_bytes: 1,
                dynamic: false
            })
            .is_err()
        );
    }
}
