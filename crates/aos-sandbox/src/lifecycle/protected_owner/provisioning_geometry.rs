//! Prices the actual closed Create Accepted Source member before model growth.
//!
//! Widths are passive DATA from the existing codec and held Source journal.
//! They issue no Source loan, schema success, mutation or receiving allowance.

use super::*;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::RecordShape;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainSchemaV1, ENVELOPE_FIXED_BYTES, DURABLE_MEMBER_FIXED_BYTES,
    reducer_payload_encoded_bytes_v1,
};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::lifecycle::protected_journal::{LifecycleReplayReceivingV1, LIFECYCLE_PROTECTED_IDENTITY_BYTES};

/// Prices only the real Create intent: one expectation, one unbound anchor.
///
/// The caller independently pays its actual public-input snapshot and Source
/// native/name before/after owners. This helper retains the existing held-native
/// forecast error through its returned rich Result; it performs no append.
pub(crate) fn create_provisioning_admission_receiving_demand_v1(
    source: &Journal,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    create_provisioning_uncommitted_source_receiving_demand_v1(source)
}

// Binding and the two presemantic successors retain the same one expectation,
// one fixed-width step and no semantic payload/attempts. Their existing codecs
// use exactly the same count-derived width, while native/schema payment still
// comes from the actual reached Source prefix on every separate native turn.
pub(crate) fn create_provisioning_uncommitted_source_receiving_demand_v1(
    source: &Journal,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    create_provisioning_source_record_receiving_demand_v1(source, false)
}

pub(crate) fn create_provisioning_committed_source_receiving_demand_v1(
    source: &Journal,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    create_provisioning_source_record_receiving_demand_v1(source, true)
}

pub(crate) fn start_provisioning_admission_receiving_demand_v1(source:&Journal)
    ->Result<ResourceVector,ResourceReservationErrorV1> {
    let body=crate::lifecycle::format::start_accepted_record_encoded_length_v1()
        .map_err(|_|ResourceReservationErrorV1::Conflict)?;
    provisioning_source_record_receiving_demand_v1(source,body,false,0)
}

pub(crate) fn start_provisioning_source_receiving_demand_v2(
    source: &Journal, purpose: crate::controller_resource_reservation::StartSourcePurposeV2,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    use crate::controller_resource_reservation::StartSourcePurposeV2 as Purpose;
    let committed = matches!(purpose, Purpose::SemanticCommit | Purpose::Completing | Purpose::Terminal);
    let body = if committed { crate::lifecycle::format::start_committed_record_encoded_length_v2() }
        else { crate::lifecycle::format::start_accepted_record_encoded_length_v1() }
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    provisioning_source_record_receiving_demand_v1(source, body, committed, 0)
}

pub(crate) fn stop_source_receiving_demand_v4(
    source: &Journal,
    committed: bool,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let body = crate::lifecycle::format::stop_source_record_encoded_length_v4(committed)
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    // Stop uses lifecycle_desired_state_semantic_commit_v1, whose actual
    // shared builder supplies no reservation facts. This is its model count,
    // not a native/financial incremental allowance.
    provisioning_source_record_receiving_demand_v1(source, body, committed, 0)
}

pub(super) fn stop_dispatch_source_receiving_demand_v1(source: &Journal, packet_bytes: usize)
    -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    let operation = crate::lifecycle::format::stop_source_record_encoded_length_v4(true)
        .map_err(|_| invalid())?;
    // The same planner retains two actual auxiliary members. Each invocation
    // prices its real protected envelope, predecessor, replay and native append
    // representations; shared fixed overhead is conservatively counted twice.
    let operation_member = operation.checked_add(4 + 244 + 32).ok_or_else(invalid)?;
    let dispatch_member = packet_bytes.checked_add(172 + 244 + 32).ok_or_else(invalid)?;
    provisioning_source_record_receiving_demand_v1(source, operation_member, true, 0)?
        .checked_add(provisioning_source_record_receiving_demand_v1(source, dispatch_member, true, 0)?)
        .map_err(Into::into)
}

/// Prices the same two-member planner for one fixed independent settlement.
///
/// This is comparison geometry, never an allowance or Source permission. The
/// native loan separately prepays its compiled proof, clocks and all bookends.
pub(crate) fn stop_cleanup_completion_receiving_demand_v1(
    source: &Journal,
    completion: &aos_sandbox_protocol::domain_ledger::stop_completion::LifecycleStopCompletionDataV1,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    let operation = crate::lifecycle::format::stop_source_record_encoded_length_v4(true)
        .map_err(|_| invalid())?;
    // The unchanged Stop uses the same fixed attempt slots even if Residual.
    // Each actual member has its own envelope/reducer/predecessor/plan backing;
    // conservative duplicate replay overhead cannot invent financial credit.
    let operation_member = operation.checked_add(4 + 244 + 32).ok_or_else(invalid)?;
    let completion_member = completion.encoded_length().checked_add(244 + 32)
        .ok_or_else(invalid)?;
    provisioning_source_record_receiving_demand_v1(source, operation_member, true, 0)?
        .checked_add(provisioning_source_record_receiving_demand_v1(source, completion_member, true, 0)?)
        .map_err(Into::into)
}

fn create_provisioning_source_record_receiving_demand_v1(source: &Journal, committed: bool)
    -> Result<ResourceVector, ResourceReservationErrorV1> {
    type Schema = LifecycleProtectedJournalSchemaV1;
    let invalid = || ResourceReservationErrorV1::Conflict;
    let body = if committed {
        crate::lifecycle::format::create_committed_record_encoded_length_v1()
    } else {
        crate::lifecycle::format::create_accepted_record_encoded_length_v1()
    }.map_err(|_| invalid())?;
    provisioning_source_record_receiving_demand_v1(source,body,committed,1)
}

fn provisioning_source_record_receiving_demand_v1(source:&Journal,body:usize,committed:bool,reservations:usize)
    ->Result<ResourceVector,ResourceReservationErrorV1> {
    type Schema=LifecycleProtectedJournalSchemaV1;
    let invalid=||ResourceReservationErrorV1::Conflict;
    let key = LifecycleProtectedJournalKeyV1::encoded_bytes_for_identity_v1(
        LIFECYCLE_PROTECTED_IDENTITY_BYTES,
    ).map_err(|_| invalid())?;
    // Canonical derived_companions emits the body digest and one semantic
    // project/subject digest for this operation family. Dedup can only shrink it.
    let reducer = reducer_payload_encoded_bytes_v1::<Schema>(body, 2).map_err(|_| invalid())?;
    let durable = reducer.checked_add(ENVELOPE_FIXED_BYTES)
        .and_then(|bytes| bytes.checked_add(DURABLE_MEMBER_FIXED_BYTES)).ok_or_else(invalid)?;
    let native = source.append_receiving_demand_v1(std::iter::once(RecordShape {
        key_bytes: key, value_bytes: Some(durable),
    })).map_err(|cause| match cause {
        crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) =>
            ResourceReservationErrorV1::Journal(cause),
        crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => cause.into(),
    })?;
    let reached = LifecycleReplayReceivingV1::from_lifecycle_record_lengths_v1(
        source.all_records().filter_map(|(_, key, value)| key.starts_with(Schema::KEY_PREFIX)
            .then_some((key.len(), value.len())))
            .chain(std::iter::once((key, durable))),
    ).ok_or_else(invalid)?;
    // The canonical planner retains three durable copies, one possible old
    // value, one reducer payload, two keys and one typed identity. Each
    // phase can replace a different canonical Lifecycle key, so this passive
    // maximum covers the actual held namespace roster, including Effect and
    // Operation predecessors. The typed append still selects one exact key.
    let previous = source.all_records().filter(|(_, key, _)|
        key.starts_with(Schema::KEY_PREFIX))
        .map(|(_, _, value)| value.len()).max().unwrap_or(0);
    let payload = aos_sandbox_broker::domain_transaction_custody::members::
        resident_plan_member_payload_bytes_for_lengths_v1(
            reducer, key, LIFECYCLE_PROTECTED_IDENTITY_BYTES, previous,
        ).map_err(|cause| ResourceReservationErrorV1::Journal(cause.into()))?;
    let carriers = std::mem::size_of::<PreparedLifecycleProgressV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            aos_sandbox_broker::domain_transaction_custody::DomainPlannedMembersDataV1<Schema>>()
            .checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<LifecycleOperationAdmissionV1>()
            .checked_mul(2)?)).ok_or_else(invalid)?;
    let semantic = if committed {
        std::mem::size_of::<LifecycleMethodSemanticCommitV1>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::LifecycleCommittedResourceV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::LifecycleAssignmentCommitFactV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::LifecycleReservationCommitFactV1>().checked_mul(2)?.checked_mul(reservations)?))
            .ok_or_else(invalid)?
    } else { 0 };
    let memory = reached.memory_bytes_v1().checked_add(payload)
        .and_then(|bytes| bytes.checked_add(semantic))
        .and_then(|bytes| bytes.checked_add(carriers))
        .and_then(|bytes| bytes.checked_add(LifecycleVerifierRecoveryOriginalV1::carrier_receiving_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(LifecycleCurrentOperationSelectionOriginalV1::carrier_receiving_bytes_v1()?))
        .ok_or_else(invalid)?;
    let models = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::MetadataEntries, u64::try_from(reached.metadata_entries_v1()).map_err(|_| invalid())?);
    Ok(native.checked_add(models)?)
}
