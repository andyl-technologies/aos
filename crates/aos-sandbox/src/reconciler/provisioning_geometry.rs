//! Prices one exact private publication phase before its canonical row growth.
//!
//! The existing encoders supply widths; the same complete decoder recipes
//! supply model bytes. This module borrows immutable inputs and the held C
//! map. It neither constructs records nor grants a commit, scope or effect.

use std::mem::size_of;

use aos_sandbox_core::{DecodeLimits, ResourceDimension as D, ResourceVector};
use aos_sandbox_core::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_journal::geometry::RecordShape;
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{authority_effect_record_bound_v1, effect_decoding_receiving_bytes_v1},
    operation::OPERATION_RECORD_V1_BYTES,
    ownership_gate::ownership_gate_encoded_bytes_v1,
    runtime_authority_history::{self as runtime, runtime_pending_encoded_bytes_v1,
        runtime_binding_encoded_bytes_v1, runtime_head_encoded_bytes_v1},
};
use aos_sandbox_protocol::publication::{self, current_publication_encoded_bytes_v1};

use super::OperationPlan;
use crate::cold_launch_publication::action::PublicationActionPhaseV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::{AuthorityPublicationDraftV1, Journal, JournalError, PreparedAuthorityPublicationV1,
    };

#[derive(Clone, Copy)]
enum PublicationGeometryPurposeV2 {
    CreateStopped,
    StartHost,
}

impl PublicationGeometryPurposeV2 {
    fn companion_count_v2(self) -> usize {
        match self {
            Self::CreateStopped => 3,
            Self::StartHost => 0,
        }
    }
}

impl OperationPlan {
    // The actual immutable contract survives Source-only turns too. This
    // supplier includes its owned typed graphs without forecasting a Core
    // append or charging traffic for a phase which has not been entered.
    pub(crate) fn provisioning_resident_receiving_demand_v1(
        &self,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.publication_resident_receiving_demand_v2(
            draft, prepared, PublicationGeometryPurposeV2::CreateStopped,
        )
    }

    pub(crate) fn start_host_publication_resident_receiving_demand_v2(
        &self,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.publication_resident_receiving_demand_v2(
            draft, prepared, PublicationGeometryPurposeV2::StartHost,
        )
    }

    fn publication_resident_receiving_demand_v2(
        &self,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
        purpose: PublicationGeometryPurposeV2,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::Conflict;
        let gate = self.ownership_gate.as_ref().ok_or_else(invalid)?;
        if self.effects.len() != 1 || self.local_records.len() != purpose.companion_count_v2()
            || self.runtime_authority.is_none() || self.public_operation.is_some()
            || gate.publication_draft() != draft || prepared.manifest() != draft.manifest()
            || prepared.source_draft_digest() != draft.digest()
        {
            return Err(invalid());
        }
        let effect = authority_effect_record_bound_v1(&self.effects[0])
            .map_err(|_| invalid())?;
        let manifest = draft.manifest().canonical_bytes().len();
        let current = current_publication_encoded_bytes_v1(prepared.canonical_bytes().len())
            .ok_or_else(invalid)?;
        let bytes = effect_decoding_receiving_bytes_v1(effect)
            .and_then(|bytes| bytes.checked_add(publication::decoding_receiving_bytes_v1(
                draft.canonical_bytes().len().max(current))?))
            .and_then(|bytes| bytes.checked_add(assignment_bytes(manifest)?.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(2)?))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| invalid())?))
    }

    pub(crate) fn provisioning_phase_increment_receiving_demand_v1(
        &self,
        journal: &Journal,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
        phase: PublicationActionPhaseV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.publication_phase_increment_receiving_demand_v2(
            journal, draft, prepared, phase, PublicationGeometryPurposeV2::CreateStopped,
        )
    }

    pub(crate) fn start_host_publication_phase_receiving_demand_v2(
        &self,
        journal: &Journal,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
        phase: PublicationActionPhaseV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.publication_phase_increment_receiving_demand_v2(
            journal, draft, prepared, phase, PublicationGeometryPurposeV2::StartHost,
        )
    }

    fn publication_phase_increment_receiving_demand_v2(
        &self,
        journal: &Journal,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
        phase: PublicationActionPhaseV1,
        purpose: PublicationGeometryPurposeV2,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::Conflict;
        let gate = self.ownership_gate.as_ref().ok_or_else(invalid)?;
        // Both finite issuers have one real broker effect. Only CreateStopped
        // carries its three reservation companions; Start Host preserves the
        // existing resources and cannot manufacture those creation records.
        if self.effects.len() != 1 || self.local_records.len() != purpose.companion_count_v2()
            || self.runtime_authority.is_none() || self.public_operation.is_some()
            || gate.publication_draft() != draft || prepared.manifest() != draft.manifest()
            || prepared.source_draft_digest() != draft.digest()
        {
            return Err(invalid());
        }
        let effect = authority_effect_record_bound_v1(&self.effects[0])
            .map_err(|_| invalid())?;
        let gate_bytes = ownership_gate_encoded_bytes_v1(gate).map_err(|_| invalid())?;
        let manifest = draft.manifest().canonical_bytes().len();
        let pending = runtime_pending_encoded_bytes_v1(manifest).map_err(|_| invalid())?;
        let binding = runtime_binding_encoded_bytes_v1(manifest).map_err(|_| invalid())?;
        let head = runtime_head_encoded_bytes_v1();
        let publication = prepared.canonical_bytes().len();
        let current = current_publication_encoded_bytes_v1(publication).ok_or_else(invalid)?;
        let shape = |key_bytes, value_bytes| RecordShape { key_bytes, value_bytes: Some(value_bytes) };
        let operation = shape(16, OPERATION_RECORD_V1_BYTES);
        let effect_row = shape(20, effect);

        // Admission emits desired/operation/idempotency/gate/pending, the
        // finite purpose's actual companions, then the sole authority effect.
        let admission = [
            shape(self.desired_key.len(), self.desired_value.len()), operation,
            shape(self.idempotency_key.as_bytes().len(),
                aos_sandbox_protocol::domain_ledger::transaction::idempotency_value_encoded_bytes_v1()), shape(16, gate_bytes),
            shape(runtime::PENDING_KEY_BYTES, pending),
        ];
        // Activation emits two publication rows, binding/head, operation/gate.
        let activation = [
            shape(publication::PREPARED_KEY_PREFIX.len() + 32, publication),
            shape(publication::CURRENT_KEY_PREFIX.len() + 16, current),
            shape(runtime::BINDING_KEY_BYTES, binding),
            shape(runtime::CURRENT_KEY_BYTES, head), operation, shape(16, gate_bytes),
        ];
        // The existing Applying/Absent branch durably refreshes an attempt
        // before dispatch, then writes its real terminal/retry result. These
        // two serial commits are the actual branch ceiling, not a retry cap.
        // Including an operation row in each also covers Planned and terminal.
        let child = [effect_row, operation];
        let (rows, transactions): (&[RecordShape], usize) = match phase {
            PublicationActionPhaseV1::Admission => (&admission, 1),
            PublicationActionPhaseV1::Activation => (&activation, 1),
            PublicationActionPhaseV1::ChildTransition => (&child, 2),
        };
        let companions = match phase {
            PublicationActionPhaseV1::Admission => self.local_records.as_slice(),
            _ => &[],
        };
        if companions.iter().any(|record| record.value().is_none()) {
            return Err(invalid());
        }
        let final_effect = matches!(phase, PublicationActionPhaseV1::Admission)
            .then_some(effect_row);
        // The source recipe already prices two [RecordShape; 17] planes.
        // This fixed backing and the three phase arrays fit that same bound;
        // only the actual selected prefix enters the native width iterator.
        let mut actual_rows = [RecordShape { key_bytes: 0, value_bytes: None }; 17];
        let mut row_count = 0usize;
        for row in rows.iter().copied()
            .chain(companions.iter().map(|record| RecordShape {
                key_bytes: record.key().len(),
                value_bytes: record.value().map(<[u8]>::len),
            }))
            .chain(final_effect)
        {
            *actual_rows.get_mut(row_count).ok_or_else(invalid)? = row;
            row_count = row_count.checked_add(1).ok_or_else(invalid)?;
        }
        let actual_rows = actual_rows.get(..row_count).ok_or_else(invalid)?;
        let native = journal.append_sequence_receiving_demand_v1(
            (0..transactions).map(|_| Ok::<_, JournalError>(actual_rows.iter().copied())),
        ).map_err(|cause| match cause {
            crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) =>
                ResourceReservationErrorV1::Journal(cause),
            crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => cause.into(),
        })?;
        let future_bytes = actual_rows.iter().try_fold(0usize, |bytes, row| {
            bytes.checked_add(row.key_bytes)?.checked_add(row.value_bytes?)
        }).and_then(|bytes| bytes.checked_mul(transactions)).ok_or_else(invalid)?;
        let future_rows = row_count.checked_mul(transactions).ok_or_else(invalid)?;
        let future_semantic = aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
            future_bytes, future_rows,
        ).map_err(|cause| ResourceReservationErrorV1::Journal(cause.into()))?;

        // Full ledger validation can reach any foreign Effect/publication
        // grammar in the actual held map before a later relation refuses.
        // Every current raw extent contributes through its canonical supplier.
        let mut models = crate::cold_launch_publication::completion::
            controller_selector_model_bytes_v1(journal.historical_read_view_v1().materialized_state_v1())
            .ok_or_else(invalid)?;
        // Only this Core phase reaches future rows, their canonical encoder
        // planes and the additional raw child capture before native handback.
        // The immutable contract's resident graphs use the shared recipe below.
        models = models.checked_add(effect)
            .and_then(|bytes| bytes.checked_add(future_bytes.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<[RecordShape; 17]>().checked_mul(2)?))
            .ok_or_else(invalid)?;
        let existing_namespaces = crate::cold_launch_publication::completion::
            controller_selector_namespace_entries_v1(journal.historical_read_view_v1().materialized_state_v1())
            .ok_or_else(invalid)?;
        // Only reached future gate/publication/assignment decoders add their
        // named planes. Immutable resident contract bytes are not reclassified
        // as metadata, and actual native map rows remain in future_semantic.
        let future_namespaces = match phase {
            PublicationActionPhaseV1::Admission => publication::decoding_receiving_namespace_entries_v1(gate_bytes)
                .and_then(|entries| entries.checked_add(publication::assignment_decoding_namespace_entries_v1(pending)?)),
            PublicationActionPhaseV1::Activation => publication::decoding_receiving_namespace_entries_v1(publication)
                .and_then(|entries| entries.checked_add(publication::decoding_receiving_namespace_entries_v1(current)?))
                .and_then(|entries| entries.checked_add(publication::decoding_receiving_namespace_entries_v1(gate_bytes)?))
                .and_then(|entries| entries.checked_add(publication::assignment_decoding_namespace_entries_v1(binding)?)),
            PublicationActionPhaseV1::ChildTransition => Some(0),
        }.ok_or_else(invalid)?;
        let namespaces = existing_namespaces.checked_add(future_namespaces).ok_or_else(invalid)?;
        let models = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(models).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(namespaces).map_err(|_| invalid())?);
        let models = future_semantic.checked_add(models)?;
        match purpose {
            PublicationGeometryPurposeV2::CreateStopped => Ok(native.checked_add(models)?),
            // Host's same native append stage quotes the reached transaction
            // before physical IO. This earlier invoice pays its co-live model
            // growth; operation traffic is accumulated exactly once there.
            PublicationGeometryPurposeV2::StartHost => Ok(models),
        }
    }
}

fn assignment_bytes(encoded: usize) -> Option<usize> {
    let (dynamic, _) = CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
        encoded, DecodeLimits::default(),
    )?;
    dynamic.checked_add(CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()?)
        .and_then(|bytes| bytes.checked_add(encoded.checked_mul(3)?))
}
