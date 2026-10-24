//! Prices the actual owned Host snapshot models before a fresh read admission.
//!
//! The immutable resident tables supply all existing lengths/capacities. The
//! same selected snapshot serializer/writer supplies its real bounded encoding
//! allocation and native destinations. No speculative snapshot is constructed,
//! encoded or admitted while deriving this representation DATA.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
use std::mem::size_of;

fn add(left: usize, right: usize) -> Option<usize> {
    left.checked_add(right)
}

fn fence_dynamic(fence: &DurableFence) -> Option<usize> {
    add(
        fence.authorization.capacity(),
        fence.base_authorization.as_ref().map_or(0, Vec::capacity),
    )
}

#[derive(Clone, Copy)]
enum TransitionPurposeV4 {
    QueryExecution,
    PrepareExecutionArgument,
    CompositeStop,
}

impl HostState {
    /// Bounds the actual resident and proposed models for one QueryExecution admission.
    ///
    /// The caller must debit its genuine same-Launch receiving original before
    /// cloning or serializing HostState. This comparison DATA grants no read,
    /// execution, fresh account or cutoff. `None` reports checked overflow.
    pub(crate) fn execution_query_receiving_demand_v3(&self) -> Option<ResourceVector> {
        self.execution_transition_receiving_demand_v4(TransitionPurposeV4::QueryExecution)
    }

    /// Prices the existing State reservation for a genuine next method58.
    ///
    /// The enclosing consumed control original must admit this before the
    /// same signed reservation clones, seals or writes State. No preparation
    /// blob or effect permission is created by this passive census.
    pub(crate) fn execution_prepare_receiving_demand_v5(&self) -> Option<ResourceVector> {
        self.execution_transition_receiving_demand_v4(TransitionPurposeV4::PrepareExecutionArgument)
    }

    /// Prices the same owned models and the full historical Stop validation.
    ///
    /// The real Stop interval pays this before lineage validation or cloning.
    /// Its existing finite snapshot-write supplier remains separately charged.
    pub(crate) fn composite_stop_receiving_demand_v4(&self) -> Option<ResourceVector> {
        self.execution_transition_receiving_demand_v4(TransitionPurposeV4::CompositeStop)
    }

    /// Prices both existing native readers and the same historical validator.
    ///
    /// The original consumed control pays this before any snapshot allocation
    /// or authentication. Checked overflow supplies no receiving permission.
    pub(crate) fn native_inventory_history_receiving_demand_v6(&self) -> Option<ResourceVector> {
        // Two actual canonical snapshot readers and the same full authenticated
        // history traversal. Pure validation indices consume memory, not names.
        let read = read_capture::HostStateReadAttemptV2::receiving_demand_v2()?;
        let validation = self.stop_validation_receiving_v4()?.0;
        read.checked_add(read)
            .ok()?
            .checked_add(
                ResourceVector::ZERO.with(
                    D::MemoryBytes,
                    u64::try_from(
                        validation.checked_add(historical_namespace::receiving_bytes_v6()?)?,
                    )
                    .ok()?,
                ),
            )
            .ok()
    }

    fn execution_transition_receiving_demand_v4(
        &self,
        purpose: TransitionPurposeV4,
    ) -> Option<ResourceVector> {
        let mut bytes = size_of::<Self>();
        for term in [
            nodes::<[u8; 16], DurableFence>(self.fences.len())?,
            nodes::<[u8; 16], RequestRecord>(self.requests.len())?,
            nodes::<[u8; 16], u64>(self.observation_sequences.len())?,
            nodes::<[u8; 32], DurableScopeReplay>(self.scope_replays.len())?,
            nodes::<[u8; 16], DurableScopeHandle>(self.scope_handles.len())?,
            nodes::<[u8; 16], DurableExistingOutputObservation>(
                self.existing_output_observations.len(),
            )?,
            nodes::<[u8; 16], DurableFuseWorkerLaunchV1>(self.fuse_worker_launches.len())?,
            self.execution_origins
                .capacity()
                .checked_mul(size_of::<execution_origin::DurableExecutionOriginV2>())?,
        ] {
            bytes = add(bytes, term)?;
        }
        for fence in self.fences.values() {
            bytes = add(bytes, fence_dynamic(fence)?)?;
        }
        for request in self.requests.values() {
            bytes = add(bytes, fence_dynamic(&request.fence)?)?;
            bytes = add(bytes, request.execution.receiving_dynamic_bytes_v3()?)?;
            for value in [&request.execution_authentication, &request.effect] {
                bytes = add(bytes, value.capacity())?;
            }
            bytes = add(bytes, request.receipt.as_ref().map_or(0, Vec::capacity))?;
        }
        for replay in self.scope_replays.values() {
            bytes = add(bytes, replay.authentication.capacity())?;
        }
        for handle in self.scope_handles.values() {
            bytes = add(bytes, handle.authentication.capacity())?;
        }
        for output in self.existing_output_observations.values() {
            for value in [&output.request, &output.response, &output.authentication] {
                bytes = add(bytes, value.capacity())?;
            }
        }
        for launch in self.fuse_worker_launches.values() {
            bytes = add(bytes, launch.receiving_dynamic_bytes_v3()?)?;
        }
        for origin in &self.execution_origins {
            bytes = add(bytes, origin.receiving_dynamic_bytes_v3())?;
        }
        // The current native-backed model and both complete proposed/commit
        // model overlaps are separately retained. Vec clones fit the original
        // capacity bound; boxed Guardian models have an explicit body term.
        bytes = bytes.checked_mul(3)?;
        let record = aos_sandbox_broker::MAXIMUM_AUTHENTICATED_RECORD_BYTES_V3;
        // Every sealed record uses a Vec allocation no larger than twice its
        // enforced final width. Query and method58 create no argument-preparation
        // blob or Guardian payload: only one request/fence and its ordinary
        // authentication/effect/receipt records can be added.
        let fence_copies = 2_usize.checked_mul(2)?.checked_mul(3)?;
        let effect_copies = 3_usize;
        let sealing_scratch = 3_usize;
        let record_planes = fence_copies
            .checked_add(effect_copies)?
            .checked_add(sealing_scratch)?;
        let new_backing = record
            .checked_mul(2)?
            .checked_mul(record_planes)?
            .checked_add(MAXIMUM_EXECUTION_AUTHENTICATION_BYTES.checked_mul(3)?)?
            .checked_add(MAXIMUM_RECEIPT_BYTES.checked_mul(3)?)?;
        bytes = add(bytes, new_backing)?;
        bytes = add(bytes, nodes::<[u8; 16], DurableFence>(1)?.checked_mul(3)?)?;
        bytes = add(bytes, nodes::<[u8; 16], RequestRecord>(1)?.checked_mul(3)?)?;
        // Native writes and selected encoder use the SAME actual maximum
        // reserve_exact body/envelope allocations. Their established supplier
        // prices both retained writes, construction overlap and all descriptors.
        let native = match purpose {
            TransitionPurposeV4::QueryExecution | TransitionPurposeV4::PrepareExecutionArgument => {
                write_capture::HostStateWriteAttemptV2::argument_pair_demand_v2()?
            }
            TransitionPurposeV4::CompositeStop => ResourceVector::ZERO,
        };
        let mut entries = self
            .fences
            .len()
            .checked_add(self.requests.len())?
            .checked_add(self.observation_sequences.len())?
            .checked_add(self.scope_replays.len())?
            .checked_add(self.scope_handles.len())?
            .checked_add(self.existing_output_observations.len())?
            .checked_add(self.fuse_worker_launches.len())?
            .checked_add(self.execution_origins.len())?
            .checked_mul(3)?
            .checked_add(6)?;
        if matches!(purpose, TransitionPurposeV4::CompositeStop) {
            bytes = add(bytes, historical_namespace::receiving_bytes_v6()?)?;
            // One fresh child may add its exact canonical signed subject in
            // each current/proposed/commit model. Link metadata is inline in
            // the compiled RequestRecord already counted above.
            bytes = add(bytes, aos_sandbox_protocol::host_stop_cleanup::HOST_STOP_CLEANUP_SUBJECT_BYTES_V1
                .checked_mul(3)?)?;
            // Stop also inserts one observation sequence in each complete
            // proposed/commit model. Its execution variant is inline, so the
            // shared RequestRecord node already carries its whole body.
            bytes = add(bytes, nodes::<[u8; 16], u64>(1)?.checked_mul(3)?)?;
            entries = entries.checked_add(3)?;
            let validation = self.stop_validation_receiving_v4()?;
            bytes = add(bytes, validation.0)?;
            entries = entries.checked_add(validation.1)?;
        }
        native
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                    .with(D::MetadataEntries, u64::try_from(entries).ok()?),
            )
            .ok()
    }

    fn stop_validation_receiving_v4(&self) -> Option<(usize, usize)> {
        // These are actual temporary indices in validate_authenticated:
        // retained incarnation ownership, pending sandboxes, scope-handle
        // incarnations and FUSE workers. They are charged together even though
        // their individual helper calls return sequentially.
        let incarnation_rows = self.fences.len().checked_add(self.requests.len())?;
        let mut bytes = nodes::<[u8; 16], [u8; 16]>(incarnation_rows)?;
        bytes = add(bytes, nodes::<[u8; 16], ()>(self.requests.len())?)?;
        // Scope-handle uniqueness indexes the full sandbox/incarnation pair.
        bytes = add(bytes, nodes::<([u8; 16], [u8; 16]), ()>(self.scope_handles.len())?)?;
        bytes = add(bytes, nodes::<[u8; 16], ()>(self.fuse_worker_launches.len())?)?;
        // Whole-chain authentication retains one child index, one commitment
        // index and one visited set concurrently. Hashing uses the existing
        // streaming serde record encoder and one compiled SHA state.
        bytes = add(bytes, nodes::<[u8; 16], [u8; 16]>(self.requests.len())?)?;
        bytes = add(bytes, nodes::<[u8; 16], [u8; 32]>(self.requests.len())?)?;
        bytes = add(bytes, nodes::<[u8; 16], ()>(self.requests.len())?)?;
        bytes = add(bytes, size_of::<sha2::Sha256>())?;
        bytes = add(bytes, aos_sandbox_protocol::host_stop_cleanup::HOST_STOP_CLEANUP_SUBJECT_BYTES_V1)?;
        let names = self.requests.len().checked_mul(3)?.checked_add(incarnation_rows)?
            .checked_add(self.requests.len())?
            .checked_add(self.scope_handles.len())?
            .checked_add(self.fuse_worker_launches.len())?;

        // The lineage collector stores references, not cloned requests. Vec's
        // growth and its previous allocation coexist; include its minimum
        // allocation for short histories as well as geometric growth.
        let history = self
            .requests
            .len()
            .max(4)
            .checked_mul(4)?
            .checked_mul(size_of::<&RequestRecord>())?;
        bytes = add(bytes, history)?;

        // Full validation can hold an effect plus exact/base fence values.
        // The same canonical Broker codec bounds every owned key/receipt and
        // opened local-record payload. Six complete backing lanes cover the
        // three opened records plus their nested authentication/payload scratch;
        // this is a byte-buffer bound, not a JSON-to-model density estimate.
        let records = aos_sandbox_broker::MAXIMUM_AUTHENTICATED_RECORD_BYTES_V3;
        bytes = add(bytes, records.checked_mul(2)?.checked_mul(6)?)?;
        bytes = add(bytes, size_of::<BrokerEffectIntentV1>())?;
        bytes = add(
            bytes,
            size_of::<BrokerAuthorizationFenceV1>().checked_mul(2)?,
        )?;
        bytes = add(bytes, size_of::<StableAuthorityFields>().checked_mul(2)?)?;

        // Authenticate each historical handoff with the SAME canonical execution
        // serializer. Its largest temporary allocation is sequential, while all
        // owned cloned State/source models above remain charged concurrently.
        let authentication = self.requests.values().try_fold(0_usize, |maximum, request|
            Some(maximum.max(request.execution.authentication_encoding_receiving_bytes_v5()?)))?;
        bytes = add(bytes, authentication)?;

        // FUSE validation separately serializes its retained Binding as JSON.
        // It is a subset of the same bounded snapshot schema; count actual
        // JSON byte planes separately from all owned model layouts above.
        // No FUSE row means this serializer is never entered. Fixed
        // scope/output/origin payloads use the already counted canonical
        // local-record scratch, not the snapshot JSON planes.
        if !self.fuse_worker_launches.is_empty() {
            bytes = add(bytes, MAXIMUM_STATE_BYTES.checked_mul(4)?)?;
        }
        bytes = add(bytes, size_of::<Result<GuardianLineage>>().checked_mul(2)?)?;
        Some((bytes, names))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_snapshot_encoder_and_owned_capacities_stay_within_the_supplier() {
        let mut state = HostState::default();
        let initial = state.execution_query_receiving_demand_v3().unwrap();
        assert!(initial.get(D::MemoryBytes) >= state.encode().unwrap().len() as u64);

        let mut authorization = Vec::with_capacity(8192);
        authorization.extend_from_slice(&[3; 17]);
        let mut base = Vec::with_capacity(4096);
        base.extend_from_slice(&[4; 11]);
        state.fences.insert(
            [1; 16],
            DurableFence {
                witness_request_id: [2; 16],
                sandbox_id: [1; 16],
                incarnation_id: [3; 16],
                assignment_epoch: 1,
                desired_generation: 2,
                assignment_digest: [4; 32],
                authorization,
                base_authorization: Some(base),
            },
        );
        let grown = state.execution_query_receiving_demand_v3().unwrap();
        assert!(grown.get(D::MemoryBytes) >= initial.get(D::MemoryBytes) + 3 * (8192 + 4096));
        assert_eq!(
            grown.get(D::MetadataEntries),
            initial.get(D::MetadataEntries) + 3
        );
        let encoded = state.encode().unwrap();
        assert!(grown.get(D::MemoryBytes) >= encoded.capacity() as u64);
        assert!(grown.get(D::StorageBytes) >= 2 * encoded.len() as u64);
        let clone = state.clone();
        assert_eq!(clone.encode().unwrap(), encoded);
    }

    #[test]
    fn stop_prices_reached_validation_indices_and_has_no_second_write_fd_invoice() {
        let mut state = HostState::default();
        let empty = state.composite_stop_receiving_demand_v4().unwrap();
        assert_eq!(empty.get(D::OpenFiles), 0);

        let mut authorization = Vec::with_capacity(8192);
        authorization.extend_from_slice(&[3; 17]);
        state.fences.insert(
            [1; 16],
            DurableFence {
                witness_request_id: [2; 16],
                sandbox_id: [1; 16],
                incarnation_id: [3; 16],
                assignment_epoch: 1,
                desired_generation: 2,
                assignment_digest: [4; 32],
                authorization,
                base_authorization: None,
            },
        );
        let grown = state.composite_stop_receiving_demand_v4().unwrap();

        assert!(grown.get(D::MemoryBytes) >= empty.get(D::MemoryBytes) + 3 * 8192);
        // Three model entries and one actual validation incarnation index.
        assert_eq!(
            grown.get(D::MetadataEntries),
            empty.get(D::MetadataEntries) + 4
        );
        assert_eq!(grown.get(D::OpenFiles), 0);
    }
}
