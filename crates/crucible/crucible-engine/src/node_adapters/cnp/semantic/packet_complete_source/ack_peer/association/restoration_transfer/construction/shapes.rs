//! Composes the actual Source normalization and keyed-validation call graph.
//!
//! Each serialization row names a complete Value/canonical construction; each
//! decoder row adds the actual DTO root and closed dynamic child geometry.
//! Nested validator calls are added by name below. Their cumulative sum also
//! bounds the overlap of independently retained Source/SDK originals and local
//! expected receipts. No encoded extent is converted into a typed heap factor.

use super::super::super::typed_decoder_backing as typed_backing;
use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::{
    PacketNativeRestoredCommitHold, maximum_complete_restore_held_evidence_bytes,
    maximum_complete_restore_held_evidence_counter_scratch_data,
};

#[derive(Clone, Copy)]
pub(super) struct Shape {
    serialization: usize,
    backing: usize,
}

impl Shape {
    pub(super) fn measure(value: &impl Serialize, maximum: usize) -> Result<Self, RuntimeError> {
        Ok(Self {
            serialization: add(
                &[
                    size_of::<serde_json::Value>(),
                    NodeRuntime::original_runtime_constructor_serialization_storage_data(
                        value, maximum,
                    )?,
                ],
                maximum,
            )?,
            backing: typed_backing::measure(value, maximum)?,
        })
    }

    fn decode<T: ClosedType>(&self, maximum: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                T::inline_bytes(),
                size_of::<Result<T, serde_json::Error>>(),
                size_of::<&serde_json::Value>(),
                self.backing,
            ],
            maximum,
        )
    }
}

pub(super) struct ConstructionShapes {
    pub(super) restoration: Shape,
    pub(super) archive_binding: Shape,
    pub(super) target_binding: Shape,
    pub(super) input_roster: Shape,
    pub(super) prepare: Shape,
    pub(super) commit: Shape,
    pub(super) prepare_baseline: Shape,
    pub(super) commit_baseline: Shape,
    pub(super) prepare_frame: Shape,
    pub(super) commit_frame: Shape,
    pub(super) prepare_identity: Shape,
    pub(super) commit_identity: Shape,
    pub(super) prepare_context: Shape,
    pub(super) commit_context: Shape,
    pub(super) prepare_proof: Shape,
    pub(super) commit_proof: Shape,
    pub(super) prepare_receipt: Shape,
    pub(super) commit_receipt: Shape,
    pub(super) held: Shape,
}

impl ConstructionShapes {
    fn prepare_validate(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[self.restoration.serialization, self.prepare.serialization],
            max,
        )
    }

    fn roster(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_validate(max)?,
                self.input_roster.serialization,
                32,
            ],
            max,
        )
    }

    fn prepare_context_authenticate(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_context.serialization,
                self.prepare_validate(max)?,
                self.prepare.serialization,
                32,
                self.roster(max)?,
            ],
            max,
        )
    }

    fn commit_validate(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[self.prepare_validate(max)?, self.commit.serialization],
            max,
        )
    }

    fn context_bindings(&self, max: usize) -> Result<usize, RuntimeError> {
        // Both json! owners coexist while their canonical outputs are hashed.
        add(
            &[
                self.restoration.serialization,
                self.archive_binding.serialization,
                self.target_binding.serialization,
                self.restoration.serialization,
                size_of::<[u8; 32]>(),
                size_of::<[u8; 32]>(),
                size_of::<[u8; 32]>(),
                size_of::<[u8; 32]>(),
            ],
            max,
        )
    }

    fn commit_context_authenticate(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_context.serialization,
                self.commit_validate(max)?,
                self.context_bindings(max)?,
                self.commit.serialization,
                32,
                self.roster(max)?,
            ],
            max,
        )
    }

    fn create_prepare_proof(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_context.serialization,
                self.prepare_context.serialization,
                self.prepare_proof
                    .decode::<PacketCompleteRestoreTransferProof>(max)?,
                self.prepare_proof.serialization,
            ],
            max,
        )
    }

    fn verify_prepare_proof(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_proof.serialization,
                self.create_prepare_proof(max)?,
            ],
            max,
        )
    }

    fn create_commit_proof(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_context.serialization,
                self.commit_context.serialization,
                self.commit_proof
                    .decode::<PacketCompleteRestoreTransferProof>(max)?,
                self.commit_proof.serialization,
            ],
            max,
        )
    }

    fn verify_commit_proof(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_proof.serialization,
                self.create_commit_proof(max)?,
            ],
            max,
        )
    }

    fn create_prepare_receipt(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_context_authenticate(max)?,
                self.prepare_context.serialization,
                self.prepare_receipt
                    .decode::<PacketCompleteRestorePrepareReceipt>(max)?,
                self.prepare.serialization,
                self.roster(max)?,
                // receipt_input first constructs a Value, then bounded_canonical
                // clones that Value before encoding. mac's initial and replacement
                // banks may overlap; the extra fixed bank is named independently.
                self.prepare_receipt.serialization,
                self.prepare_receipt.serialization,
                32,
                self.prepare_receipt.serialization,
            ],
            max,
        )
    }

    fn verify_prepare_receipt(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_receipt.serialization,
                self.create_prepare_receipt(max)?,
                self.prepare_receipt.serialization,
                self.prepare_receipt.serialization,
            ],
            max,
        )
    }

    fn create_commit_receipt(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_validate(max)?,
                self.commit_context.serialization,
                self.commit.serialization,
                self.roster(max)?,
                self.commit_receipt
                    .decode::<PacketCompleteRestoreCommitReceipt>(max)?,
                self.commit_context.serialization,
                self.commit_receipt.serialization,
                self.commit_receipt.serialization,
                32,
                self.commit_receipt.serialization,
            ],
            max,
        )
    }

    fn verify_commit_receipt(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_receipt.serialization,
                self.create_commit_receipt(max)?,
                self.commit_receipt.serialization,
                self.commit_receipt.serialization,
            ],
            max,
        )
    }

    fn prepare_pair(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_frame.serialization,
                self.prepare
                    .decode::<PacketCompleteRestorePrepareRequest>(max)?,
                self.prepare_context
                    .decode::<PacketCompleteRestorePrepareContext>(max)?,
                self.prepare_proof
                    .decode::<PacketCompleteRestoreTransferProof>(max)?,
                self.prepare_receipt
                    .decode::<PacketCompleteRestorePrepareReceipt>(max)?,
                // The response digest repeats the original request digest; the
                // third call below is the independently retained original itself.
                self.prepare_frame.serialization,
                self.prepare_baseline.decode::<BeginRequest>(max)?,
                self.prepare_frame.serialization,
                self.prepare_baseline.decode::<BeginRequest>(max)?,
                self.verify_prepare_proof(max)?,
                self.verify_prepare_receipt(max)?,
                self.prepare_baseline.decode::<BeginRequest>(max)?,
                self.prepare_baseline
                    .decode::<PrepareRestoreArguments>(max)?,
            ],
            max,
        )
    }

    fn commit_pair(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_frame.serialization,
                self.commit
                    .decode::<PacketCompleteRestoreCommitRequest>(max)?,
                self.commit_context
                    .decode::<PacketCompleteRestoreCommitContext>(max)?,
                self.commit_proof
                    .decode::<PacketCompleteRestoreTransferProof>(max)?,
                self.commit_receipt
                    .decode::<PacketCompleteRestoreCommitReceipt>(max)?,
                self.commit_frame.serialization,
                self.commit_baseline.decode::<BeginRequest>(max)?,
                self.commit_frame.serialization,
                self.commit_baseline.decode::<BeginRequest>(max)?,
                self.prepare.serialization,
                self.commit_context_authenticate(max)?,
                self.verify_commit_proof(max)?,
                self.verify_commit_receipt(max)?,
                self.commit_baseline.decode::<BeginRequest>(max)?,
                self.commit_baseline
                    .decode::<PrepareRestoreArguments>(max)?,
            ],
            max,
        )
    }

    fn sdk_prepare(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.prepare_validate(max)?, // selected prepare constructor
                self.prepare.serialization,  // request extension Value
                self.prepare_baseline
                    .decode::<PrepareRestoreArguments>(max)?,
                self.prepare_baseline.serialization, // baseline object
                self.prepare_frame.decode::<Envelope>(max)?, // assigned owner
                self.prepare_proof.serialization,    // seal validate
                self.prepare_proof.serialization,    // proof extension Value
                self.prepare_frame.serialization,    // connection retained writer
                self.prepare_frame.decode::<Envelope>(max)?, // guard pending clone
                self.prepare_frame.serialization,    // Session envelope_bytes
                self.prepare_identity.serialization, // Session request_hash
                self.prepare_frame.decode::<Envelope>(max)?, // ClientOriginal clone
                self.prepare_frame.serialization,    // publish/restricted correspondence
            ],
            max,
        )
    }

    fn sdk_commit(&self, max: usize) -> Result<usize, RuntimeError> {
        add(
            &[
                self.commit_validate(max)?,       // actual commit constructor
                self.prepare.serialization,       // embedded original correspondence
                self.prepare_frame.serialization, // full prior request digest
                self.prepare_receipt
                    .decode::<PacketCompleteRestorePrepareReceipt>(max)?,
                self.prepare_receipt.serialization, // receipt validate
                self.commit.serialization,          // commit extension Value
                self.commit_baseline
                    .decode::<PrepareRestoreArguments>(max)?,
                self.commit_baseline.serialization,
                self.commit_frame.decode::<Envelope>(max)?,
                self.commit_proof.serialization,
                self.commit_proof.serialization,
                self.commit_frame.serialization,
                self.commit_frame.decode::<Envelope>(max)?,
                self.commit_frame.serialization,
                self.commit_identity.serialization,
                self.commit_frame.decode::<Envelope>(max)?,
                self.commit_frame.serialization,
            ],
            max,
        )
    }

    pub(super) fn requested_bytes(&self, max: usize) -> Result<usize, RuntimeError> {
        // These ten independently retained Values are not borrowed aliases of
        // the SDK originals. Their canonical banks are separately preallocated
        // in OriginalRestoreTransferBanks and counted by the parent row.
        let normalized = add(
            &[
                self.prepare.serialization,
                self.prepare_context.serialization,
                self.prepare_proof.serialization,
                self.prepare_frame.serialization,
                self.prepare_receipt.serialization,
                self.commit.serialization,
                self.commit_context.serialization,
                self.commit_proof.serialization,
                self.commit_frame.serialization,
                self.commit_receipt.serialization,
            ],
            max,
        )?;
        let prepare_construction = add(
            &[
                self.prepare
                    .decode::<PacketCompleteRestorePrepareRequest>(max)?,
                self.prepare_validate(max)?,
                self.prepare_baseline.decode::<BeginRequest>(max)?,
                self.prepare_baseline.serialization,
                self.prepare_baseline
                    .decode::<PrepareRestoreArguments>(max)?,
                self.prepare_frame.decode::<Envelope>(max)?,
                self.prepare_frame.serialization,
                self.prepare_frame.serialization,
                self.prepare_baseline.decode::<BeginRequest>(max)?,
                self.prepare
                    .decode::<PacketCompleteRestorePrepareRequest>(max)?,
                self.prepare_context
                    .decode::<PacketCompleteRestorePrepareContext>(max)?,
                self.roster(max)?,
                self.prepare_context_authenticate(max)?,
                self.create_prepare_proof(max)?,
                self.prepare_frame.serialization,
                self.prepare_frame.decode::<Envelope>(max)?,
                self.prepare_pair(max)?,
            ],
            max,
        )?;
        let commit_construction = add(
            &[
                self.prepare_pair(max)?,
                self.prepare_frame.serialization,
                self.prepare_receipt
                    .decode::<PacketCompleteRestorePrepareReceipt>(max)?,
                self.prepare
                    .decode::<PacketCompleteRestorePrepareRequest>(max)?,
                self.commit
                    .decode::<PacketCompleteRestoreCommitRequest>(max)?,
                self.commit_validate(max)?,
                self.commit_baseline.decode::<BeginRequest>(max)?,
                self.commit_baseline.serialization,
                self.commit_baseline
                    .decode::<PrepareRestoreArguments>(max)?,
                self.commit_frame.decode::<Envelope>(max)?,
                self.commit_frame.serialization,
                self.commit_frame.serialization,
                self.commit_baseline.decode::<BeginRequest>(max)?,
                self.commit
                    .decode::<PacketCompleteRestoreCommitRequest>(max)?,
                self.context_bindings(max)?,
                self.commit_context
                    .decode::<PacketCompleteRestoreCommitContext>(max)?,
                self.roster(max)?,
                self.commit
                    .decode::<PacketCompleteRestoreCommitRequest>(max)?,
                self.commit_context_authenticate(max)?,
                self.create_commit_proof(max)?,
                self.commit_frame.serialization,
                self.commit_frame.decode::<Envelope>(max)?,
                self.commit_pair(max)?,
            ],
            max,
        )?;
        let held_maximum = maximum_complete_restore_held_evidence_bytes()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let held_decode = add(
            &[
                crucible_node_transport::client::original_host_source_json_extent_storage_data(
                    held_maximum,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?,
                self.held.decode::<PacketNativeRestoredCommitHold>(max)?,
                self.held.serialization,
                self.prepare
                    .decode::<PacketCompleteRestorePrepareRequest>(max)?,
                maximum_complete_restore_held_evidence_counter_scratch_data(),
            ],
            max,
        )?;
        // Reauthentication can run after Commit without renewing Query. The
        // full retained graph stays live while a fresh local validation graph
        // is built. Use that actual largest closed path as a separate peak.
        let inspection = add(
            &[self.prepare_pair(max)?, self.commit_pair(max)?, held_decode],
            max,
        )?;
        add(
            &[
                normalized,
                prepare_construction,
                commit_construction,
                inspection,
                self.sdk_prepare(max)?,
                self.sdk_commit(max)?,
            ],
            max,
        )
    }
}

pub(super) fn projection_scratch_data() -> usize {
    size_of::<ConstructionShapes>()
        + size_of::<Result<Shape, RuntimeError>>()
        + size_of::<Restoration<'static>>()
        + size_of::<Prepare<'static>>()
        + size_of::<Commit<'static, 'static>>()
        + size_of::<Baseline<'static>>()
        + size_of::<Baseline<'static>>()
        + size_of::<PrepareContext>()
        + size_of::<CommitContext>()
        + size_of::<Proof>()
        + size_of::<Proof>()
        + size_of::<PrepareReceipt>()
        + size_of::<CommitReceipt<'static>>()
        + size_of::<Held<'static, 'static>>()
        + size_of::<ArchiveBinding<'static, 'static>>()
        + size_of::<TargetBinding<'static, 'static>>()
        + size_of::<Reference<'static>>()
        + size_of::<Allocation>()
        + size_of::<
            AssignedEnvelope<
                'static,
                &'static Baseline<'static>,
                PrepareExtensions<'static, 'static>,
            >,
        >()
        + size_of::<
            AssignedEnvelope<
                'static,
                &'static Baseline<'static>,
                CommitExtensions<'static, 'static, 'static>,
            >,
        >()
        + size_of::<
            AssignedIdentity<
                'static,
                'static,
                &'static Baseline<'static>,
                PrepareExtensions<'static, 'static>,
            >,
        >()
        + size_of::<
            AssignedIdentity<
                'static,
                'static,
                &'static Baseline<'static>,
                CommitExtensions<'static, 'static, 'static>,
            >,
        >()
        + size_of::<PrepareExtensions<'static, 'static>>()
        + size_of::<CommitExtensions<'static, 'static, 'static>>()
        + size_of::<Binding<'static>>()
        + size_of::<
            [std::mem::MaybeUninit<(Vec<u16>, (&'static str, &'static serde_json::Value))>;
                4096 / size_of::<(Vec<u16>, (&'static str, &'static serde_json::Value))>()],
        >()
        + size_of::<
            [(
                Vec<(Vec<u16>, (&'static str, &'static serde_json::Value))>,
                std::collections::BTreeMap<Vec<u16>, (&'static str, &'static serde_json::Value)>,
            ); 128],
        >()
        + size_of::<Option<&'static serde_json::Value>>()
        + size_of::<Result<PacketNativeRestoredCommitHold, serde_json::Error>>()
        + size_of::<Result<ContentRef, serde_json::Error>>()
        + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<&'static PacketNativeRestoredCommitHold>()
        + size_of::<&'static ContentRef>()
        + size_of::<
            Option<&'static crucible_node_transport::client::OriginalCompleteRestoreInputUpload>,
        >()
        + typed_backing::counter_scratch_data()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 8]>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 9]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 10]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 13]>()
        + size_of::<[usize; 15]>()
        + size_of::<[usize; 13]>()
        + size_of::<[usize; 17]>()
        + size_of::<[usize; 10]>()
        + size_of::<[usize; 17]>()
        + size_of::<[usize; 23]>()
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 6]>()
        + size_of::<&'static [usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
}

// Only these concrete roots can use the structural decoder bound above. Every
// field is matched without `..`, so changing a DTO's owning layout requires
// revisiting its projection and this closed roster together.
trait ClosedType {
    fn inline_bytes() -> usize;
}

impl ClosedType for PacketCompleteRestorePrepareRequest {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                restoration: _,
                host_protocol: _,
                native_protocol: _,
                native_control: _,
                native_anchor: _,
                transaction_id: _,
                generation: _,
                allocation: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestoreCommitRequest {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                prepare: _,
                capture_terminal: _,
                prepare_request_id: _,
                prepare_request_sequence: _,
                prepare_request_digest: _,
                prepare_response_sequence: _,
                prepare_response_digest: _,
                transfer_token: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestorePrepareContext {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                algorithm: _,
                source_birth: _,
                kernel_binding: _,
                policy_binding: _,
                host_registration: _,
                native_registration: _,
                hello_request: _,
                hello_response: _,
                assigned_prepare: _,
                prepare_request: _,
                input_roster: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestoreCommitContext {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                algorithm: _,
                restoration: _,
                commit_request: _,
                prepare_request: _,
                prepare_response: _,
                transfer_token: _,
                input_roster: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestoreTransferProof {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                algorithm: _,
                context_digest: _,
                mac: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestorePrepareReceipt {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                algorithm: _,
                prepare_digest: _,
                context_digest: _,
                input_roster: _,
                transfer_token: _,
                generation: _,
                native_sequence: _,
                assigned_response: _,
                mac: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestoreCommitReceipt {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                algorithm: _,
                commit_digest: _,
                context_digest: _,
                installed_mapping: _,
                transfer_token: _,
                native_sequence: _,
                assigned_response: _,
                mac: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketNativeRestoredCommitHold {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                native_pid: _,
                target_world: _,
                target_owner: _,
                target_owner_binding: _,
                target_activation: _,
                target_generation: _,
                captured_owner_state: _,
                captured_control: _,
                captured_journal: _,
                mapping: _,
                restore_commit: _,
                context_digest: _,
                local_cursor: _,
                inventory_hash: _,
                physical_gate_held: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for BeginRequest {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                kind: _,
                binding_hash: _,
                owner_generation: _,
                activation_id: _,
                world_generation: _,
                arguments: _,
                extensions: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PrepareRestoreArguments {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                transaction_id: _,
                capture_manifest: _,
                expected_world_binding_hash: _,
                expected_owner_binding_hash: _,
                destination_owner_ids: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for Envelope {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                protocol: _,
                message: _,
                session_id: _,
                incarnation_id: _,
                node_id: _,
                execution_owner_id: _,
                capture_owner_id: _,
                request_id: _,
                operation_id: _,
                sequence: _,
                method: _,
                body: _,
                extensions: _,
            } = value;
        };
        size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    //! Uses real DTO/serde allocation paths; no Source/member is fabricated.
    // crucible-lint: allow panic-shortcut -- Closed DATA fixture failures stop the control.
    use super::*;

    #[test]
    fn actual_prepare_context_decoder_keeps_estimated_digest_capacity_in_quote() {
        let digest = || Bytes::new(vec![7; 32]);
        let context = PacketCompleteRestorePrepareContext {
            schema: "source-owned.packet-complete-restore-prepare-context/12".into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            source_birth: digest(),
            kernel_binding: digest(),
            policy_binding: digest(),
            host_registration: digest(),
            native_registration: digest(),
            hello_request: digest(),
            hello_response: digest(),
            assigned_prepare: digest(),
            prepare_request: digest(),
            input_roster: digest(),
        };
        let projected = PrepareContext::ceiling();
        let quote = Shape::measure(&projected, 16 * 1024 * 1024).unwrap();

        let value = serde_json::to_value(&context).unwrap();
        let decoded: PacketCompleteRestorePrepareContext =
            Deserialize::deserialize(&value).unwrap();
        decoded.validate_data().unwrap();

        assert_eq!(decoded.source_birth.as_slice().len(), 32);
        assert_eq!(decoded.source_birth.allocation_capacity(), 33);
        let actual = size_of::<PacketCompleteRestorePrepareContext>()
            + decoded.schema.capacity()
            + decoded.algorithm.capacity()
            + [
                &decoded.source_birth,
                &decoded.kernel_binding,
                &decoded.policy_binding,
                &decoded.host_registration,
                &decoded.native_registration,
                &decoded.hello_request,
                &decoded.hello_response,
                &decoded.assigned_prepare,
                &decoded.prepare_request,
                &decoded.input_roster,
            ]
            .iter()
            .map(|one| one.allocation_capacity())
            .sum::<usize>();
        assert!(
            quote
                .decode::<PacketCompleteRestorePrepareContext>(16 * 1024 * 1024)
                .unwrap()
                >= actual
        );

        let encoded = canonical::canonical_json(&value).unwrap();
        let dom =
            crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::
                value_storage_with_error::<RuntimeError>(
                    &value,
                    0,
                    16 * 1024 * 1024
                )
                .unwrap();

        assert!(quote.serialization >= size_of::<serde_json::Value>() + dom + encoded.capacity());
        assert!(Shape::measure(&projected, 1).is_err());
    }

    #[test]
    fn opaque_value_arrays_and_maps_keep_independent_decoder_children() {
        let original = serde_json::json!({
            "nested": [
                {"payload": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                {"payload": "kept independently"}
            ],
            "empty": [],
            "null": null,
        });
        let projected = Shape::measure(&original, 16 * 1024 * 1024).unwrap();
        let decoded: serde_json::Value = Deserialize::deserialize(&original).unwrap();

        assert_eq!(decoded, original);

        let actual =
            crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::
                value_storage_with_error::<RuntimeError>(
                    &decoded,
                    0,
                    16 * 1024 * 1024
                )
                .unwrap();

        assert!(projected.backing >= actual);

        struct NativeByteCodec;

        impl Serialize for NativeByteCodec {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&[7; 32])
            }
        }

        // The closed roster accepts Bytes only through its projected base64
        // string; a newly introduced native byte serializer must be reviewed.
        assert!(typed_backing::measure(&NativeByteCodec, 16 * 1024 * 1024).is_err());
    }
}

impl ClosedType for PacketCompleteRestoreRequest {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                archive_index: _,
                capture_manifest: _,
                owner_state: _,
                journal: _,
                source_runtime: _,
                backend_implementation: _,
                backend_schema: _,
                archived_cut: _,
                archived_ordinal: _,
                target_world: _,
                target_owner: _,
                target_owner_binding: _,
                target_activation: _,
                target_generation: _,
                target_owner_generation: _,
                mapping: _,
                nonce: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestoreContext {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                schema: _,
                algorithm: _,
                source_birth: _,
                kernel_binding: _,
                policy_binding: _,
                host_registration: _,
                native_registration: _,
                hello_request: _,
                hello_response: _,
                assigned_restore: _,
                archive_binding: _,
                target_binding: _,
                mapping_binding: _,
                request_binding: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for PacketCompleteRestoreInputAllocation {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                maximum_known_requested_bytes: _,
                maximum_input_bytes: _,
                maximum_nodes: _,
                maximum_depth: _,
                maximum_owned_backing_bytes: _,
                maximum_tree_entries: _,
                maximum_metadata_rows: _,
                maximum_literal_backing_bytes: _,
                maximum_content_transfers: _,
                maximum_content_objects: _,
                maximum_content_groups: _,
                maximum_content_bytes: _,
                maximum_content_metadata_bytes: _,
                maximum_model_bytes: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for HashRef {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                algorithm: _,
                domain: _,
                digest: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for ContentRef {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                hash: _,
                length: _,
                media_type: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for crucible_node_format::SchemaRef {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                id: _,
                version: _,
                definition: _,
                extensions: _,
            } = value;
        };
        size_of::<Self>()
    }
}

impl ClosedType for crucible_node_format::Position {
    fn inline_bytes() -> usize {
        let _closed_fields: fn(&Self) = |value| {
            let Self {
                time_ps: _,
                microstep: _,
                phase: _,
            } = value;
        };
        size_of::<Self>()
    }
}
