//! Shares the existing generic-append denials for closed native completions.
//!
//! These predicates inspect canonical saved rows and proposed bytes only. They
//! cannot select an exception: the actual Domain or Mount native owner keeps
//! its separate typed loan, financial admission and final-crossing recipe.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_model::RecordNamespace;

mod consumer;
pub use consumer::{consumer_capacity_is_selected_v1, require_no_consumer_resource_transition_v1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use std::collections::BTreeMap;

use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
    LIFECYCLE_PROTECTED_DOMAIN_V1, LIFECYCLE_PROTECTED_KEY_PREFIX_V1,
    LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1, LifecycleAuxiliaryEnvelopeFormatV1,
    borrow_lifecycle_auxiliary_member_data_v1,
};
use aos_sandbox_protocol::domain_ledger::records::borrowed::{
    DurableMemberFrameDataV1, borrow_protected_key_data_v1,
};
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::{
    CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2, ClosedCreateFailurePrepareDataV2,
};
use aos_sandbox_protocol::public_api::projection::{PROJECTION_KEY_PREFIX, PublicProjectionKindV1};

/// Identifies the original Root genesis record keys without admitting them.
#[must_use]
pub fn transaction_touches_root_genesis_v1(transaction: &JournalTransaction) -> bool {
    use crate::replay::root_genesis_records::{
        FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY,
    };
    transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::DesiredState
            && (record.key() == INSTANCE_KEY
                || record.key() == PINS_KEY
                || record.key().starts_with(INTENT_PREFIX)
                || record.key().starts_with(FLOOR_PREFIX))
    })
}

/// Refuses the existing ordinary Source hold and pending settlement boundary.
///
/// # Errors
/// Refuses malformed current rows, an active hold or any proposed hold write.
pub fn require_no_source_policy_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let readback = crate::source_policy_hold::current_state(state)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if readback.delete_pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    #[cfg(target_os = "linux")]
    if readback.q04_pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    if readback.hold.is_some_and(|hold| hold.is_held())
        || readback.v8_pending.is_some()
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::SourceDomainPolicyHold)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Refuses generic Source Q04 pending-marker mutation after canonical lookup.
///
/// # Errors
/// Refuses either current/proposed marker, preserving the old absent fast path.
pub fn require_no_source_q04_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let writes = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::SourceDomainPolicyHold
            && record.key() == crate::source_policy_hold::SOURCE_PENDING_KEY
    });
    let current = state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::SourceDomainPolicyHold
            && key == crate::source_policy_hold::SOURCE_PENDING_KEY
    });
    if !writes && !current {
        return Ok(());
    }
    crate::source_policy_hold::current_state(state).map_err(|_| JournalError::ProtectedBoundary)?;
    Err(JournalError::ProtectedBoundary)
}

/// Refuses the existing generic Cache Q04 pending-marker boundary.
///
/// # Errors
/// Refuses the exact current or proposed pending-marker key.
pub fn require_no_cache_q04_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    use aos_sandbox_protocol::cache_state::hold_state::CACHE_PENDING_KEY;
    if state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::DesiredState && key == CACHE_PENDING_KEY
    }) || transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::DesiredState && record.key() == CACHE_PENDING_KEY
    }) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Refuses the existing generic Root Q04 historical-prefix boundary.
///
/// # Errors
/// Refuses any actual or proposed key with the canonical Root Q04 prefix.
pub fn require_no_root_q04_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if state
        .keys()
        .any(|(_, key)| key.starts_with(b"\0aos-q04-root-"))
        || transaction
            .records()
            .iter()
            .any(|record| record.key().starts_with(b"\0aos-q04-root-"))
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Compares the decoded project-admission rows for the ordinary no-loan branch.
///
/// # Errors
/// Refuses an outstanding reservation or a proposed write to any protected key.
pub fn require_no_project_admission_mutation_v1(
    rows: &aos_sandbox_protocol::domain_ledger::source_project_history::SourceProjectAdmissionHistoryV1,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    use crate::source_project_readback::{
        CANCELLATION_KEY, KEY, RESERVATION_KEY, RETIREMENT_ACK_KEY, SETTLEMENT_KEY,
    };
    if rows.reservation().is_some() && rows.retirement_ack().is_none() {
        return Err(JournalError::ProtectedBoundary);
    }
    if transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::DesiredState
            && (record.key() == KEY
                || record.key() == SETTLEMENT_KEY
                || record.key() == RESERVATION_KEY
                || record.key() == CANCELLATION_KEY
                || record.key() == RETIREMENT_ACK_KEY)
    }) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Refuses generic mutation of the retained Nix native provisioning namespace.
///
/// # Errors
/// Refuses current or proposed native provisioning history without its owner.
pub fn require_no_nix_native_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if state
        .keys()
        .any(|(namespace, _)| *namespace == RecordNamespace::NixOfflineProvisioning)
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::NixOfflineProvisioning)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}
/// Rejects generic mutation with retained Create storage history.
///
/// # Errors
/// Refuses any current or proposed CreateStorageHistory row.
pub fn require_no_create_storage_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if state
        .keys()
        .any(|(namespace, _)| *namespace == RecordNamespace::CreateStorageHistory)
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::CreateStorageHistory)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Rejects generic writes to the closed Root NoApply floor.
///
/// # Errors
/// Refuses a proposed RootExecutionNoApplyFloorV2 row.
pub fn require_no_root_execution_no_apply_floor_mutation_v2(
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::RootExecutionNoApplyFloorV2)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Rejects rewriting an admitted Stop-cleanup Controller operation.
///
/// # Errors
/// Refuses a selected canonical StopCleanup operation or malformed selected bytes.
pub fn require_no_stop_cleanup_controller_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    use aos_sandbox_protocol::domain_ledger::{
        operation::{decode_operation, has_operation_record_version_data_v1},
        public_operation::PublicRecoveryKindV1,
    };
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::Operation {
            continue;
        }
        let Some(old) = state.get(&(record.namespace(), record.key().to_vec())) else {
            continue;
        };
        if has_operation_record_version_data_v1(old)
            && decode_operation(old)
                .map_err(|_| JournalError::ProtectedBoundary)?
                .public_operation()
                .is_some_and(|public| {
                    public.recovery_kind_v1() == PublicRecoveryKindV1::StopCleanup
                })
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

/// Rejects generic writes through a closed NoApply Controller relation.
///
/// # Errors
/// Refuses selected prepared or target rows and malformed canonical records.
pub fn require_no_closed_controller_mutation_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    for record in transaction.records() {
        if record.namespace() == RecordNamespace::Operation {
            if let Some(old) = state.get(&(record.namespace(), record.key().to_vec())) {
                // Mount and Storage share this namespace with their own
                // record formats. Only Controller-versioned rows select this
                // decoder; malformed selected rows still refuse the append.
                if aos_sandbox_protocol::domain_ledger::operation::has_operation_record_version_data_v1(old) {
                    let old = aos_sandbox_protocol::domain_ledger::operation::decode_operation(old)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    if old.public_operation().is_some_and(|public| public.recovery_kind_v1()
                        == aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::ExecutionNoApply) {
                        // Kind3 completion belongs exclusively to its real fresh
                        // Source/C18 native append after completed Root confirmation.
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
            }
        }
        if record.namespace() == RecordNamespace::ControllerCreateFailurePrepare
            && (record
                .value()
                .is_some_and(|bytes| bytes.starts_with(CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2))
                || state
                    .get(&(record.namespace(), record.key().to_vec()))
                    .is_some_and(|bytes| bytes.starts_with(CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2)))
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for ((namespace, key), bytes) in state {
        if *namespace != RecordNamespace::ControllerCreateFailurePrepare
            || !bytes.starts_with(CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2)
        {
            continue;
        }
        let prepared = ClosedCreateFailurePrepareDataV2::decode_canonical(key, bytes)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let operation = prepared.operation.as_bytes();
        let execution = prepared.identity.marker.fields().source.fields().execution;
        for record in transaction.records() {
            let key = record.key();
            let target = match record.namespace() {
                RecordNamespace::Operation => key == operation,
                RecordNamespace::Effect => key.get(..16) == Some(operation.as_slice()),
                RecordNamespace::DesiredState => {
                    key.len() == PROJECTION_KEY_PREFIX.len() + 17
                        && key.starts_with(PROJECTION_KEY_PREFIX)
                        && key[PROJECTION_KEY_PREFIX.len()]
                            == PublicProjectionKindV1::Execution as u8
                        && key[PROJECTION_KEY_PREFIX.len() + 1..] == execution
                }
                _ => false,
            };
            if target {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    Ok(())
}

/// Rejects generic creation, replacement or deletion of Source A8 settlement.
///
/// # Errors
/// Refuses either existing or proposed A8 member and malformed selected framing.
pub fn require_no_generic_settlement_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::DesiredState
            || !record.key().starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1)
        {
            continue;
        }
        let (kind, _) =
            borrow_protected_key_data_v1(record.key(), LIFECYCLE_PROTECTED_KEY_PREFIX_V1)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        if kind != 5 {
            continue;
        }

        // Both sides matter: a normal replacement or deletion must not erase
        // an already settled row or its unchanged A8 Operation companion.
        if let Some(value) = record.value() {
            require_not_settlement_v1(record.key(), value)?;
        }
        if let Some((_, value)) = state.iter().find(|((namespace, key), _)| {
            *namespace == record.namespace() && key.as_slice() == record.key()
        }) {
            require_not_settlement_v1(record.key(), value)?;
        }
    }
    Ok(())
}

fn require_not_settlement_v1(key: &[u8], value: &[u8]) -> Result<(), JournalError> {
    let invalid = || JournalError::ProtectedBoundary;
    // Read each existing member's real native transaction rather than treating
    // this new attempt's ID as the old row's identity. The canonical borrowed
    // owner checks all three nested checksums and the exact key association.
    let member = DurableMemberFrameDataV1::decode(
        value,
        LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
        LIFECYCLE_PROTECTED_DOMAIN_V1,
    )
    .map_err(|_| invalid())?;
    let frame = borrow_lifecycle_auxiliary_member_data_v1(key, value, &member.transaction_id)
        .map_err(|_| invalid())?;
    if frame.format == LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion {
        return Err(invalid());
    }
    Ok(())
}

mod common_boundaries;
pub use common_boundaries::require_common_no_selected_boundaries_v1;
