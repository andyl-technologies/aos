//! Owns the sole zero-effect kind2/3 Recover terminal metadata recipe.
//!
//! The resulting one-row transaction is passive DATA. A genuine fresh cleanup
//! payer must first prove complete NoApply/Root confirmation, then run its real
//! native append/readback/posts and Source disposal. These functions issue no
//! completion, effect authority, historical adoption or financial borrower.

use super::*;
use crate::domain_ledger::public_operation::PublicRecoveryKindV1;

/// Derives the exact admitted Stop or NoApply Recover Operation successor.
///
/// The three other immutable admission rows and the old Create terminal rows
/// remain outside this one-row transaction. The native caller independently
/// verifies their exact protected preimages before and after its append.
///
/// # Errors
/// Refuses a different admission/Operation, an already terminal row, invalid
/// native time, expired current authorization or malformed transaction DATA.
pub fn closed_cleanup_terminal_transaction_data_v2(
    purpose: PublicRecoveryKindV1,
    observation: Data<'_>,
    admitted: OperationRecord,
    actual_final_clock: RawPairedClockSample,
) -> Result<JournalTransaction, MetadataCompleteDataErrorV1> {
    if admitted != cleanup_operation(purpose, observation)?
        || actual_final_clock.host_boot_id() != observation.original.host_boot_id()
        || actual_final_clock.boottime_nanoseconds() < observation.original.boottime_nanoseconds()
        || actual_final_clock.boottime_nanoseconds() >= observation.cutoff
        || actual_final_clock.wall_seconds() >= observation.wall_expiry
    {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    let public = admitted
        .public_operation()
        .ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    let completed = admitted.with_state_and_public_operation(
        OperationState::Succeeded,
        Some(public.advance(OperationState::Succeeded, actual_final_clock.wall_seconds())?),
    );
    let encoded = encode_operation_record(completed);
    require_closed_cleanup_completed_operation_data_v2(purpose, observation, &encoded)?;
    let digest = Sha256::new()
        .chain_update(match purpose {
            PublicRecoveryKindV1::StopCleanup => {
                b"aos.sandbox.stop-cleanup-recover.terminal.v2\0".as_slice()
            }
            PublicRecoveryKindV1::ExecutionNoApply => {
                b"aos.sandbox.execution-no-apply-recover.terminal.v2\0".as_slice()
            }
            _ => return Err(MetadataCompleteDataErrorV1::Mismatch),
        })
        .chain_update(observation.key_v1())
        .chain_update(&encoded)
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::Operation,
            observation.operation.to_vec(),
            encoded,
        )],
    )?)
}

/// Checks the sole finite cleanup terminal transition as comparison DATA.
///
/// # Errors
/// Refuses changed immutable metadata, another kind, a nonterminal state,
/// additional reconciliation transitions or malformed canonical bytes.
pub fn require_closed_cleanup_completed_operation_data_v2(
    purpose: PublicRecoveryKindV1,
    observation: Data<'_>,
    encoded: &[u8],
) -> Result<(), MetadataCompleteDataErrorV1> {
    let actual = decode_operation(encoded)?;
    let admitted = cleanup_operation(purpose, observation)?;
    let wall = actual
        .public_operation()
        .and_then(|public| public.completed_wall_seconds_v1())
        .ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    let public = admitted
        .public_operation()
        .ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    let expected = admitted.with_state_and_public_operation(
        OperationState::Succeeded,
        Some(public.advance(OperationState::Succeeded, wall)?),
    );
    if actual != expected {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    Ok(())
}

fn cleanup_operation(
    purpose: PublicRecoveryKindV1,
    observation: Data<'_>,
) -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    match purpose {
        PublicRecoveryKindV1::StopCleanup => stop_cleanup_operation_v1(observation),
        PublicRecoveryKindV1::ExecutionNoApply => execution_no_apply_operation_v1(observation),
        _ => Err(MetadataCompleteDataErrorV1::Mismatch),
    }
}

/// Derives the explicit terminal supersession of an older Stop-cleanup Recover.
///
/// This passive recipe preserves its immutable admission and does not assert
/// success, absence of physical work, or retirement of its historical finance.
/// Only the current genuine Source22/Root completion writer may commit it,
/// after independently checking the complete old admission and same Stop target.
/// The old authorization's expiry is history; the writer checks its own current
/// authority and clock before appending this terminal fact.
///
/// # Errors
/// Refuses another purpose, changed admitted metadata, an already terminal row
/// or a completion wall sample preceding the older accepted observation.
pub fn stop_cleanup_superseded_operation_data_v1(
    observation: Data<'_>,
    admitted: OperationRecord,
    actual_final_clock: RawPairedClockSample,
) -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    if admitted != stop_cleanup_operation_v1(observation)? {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    superseded_operation(observation, actual_final_clock.wall_seconds())
}

/// Compares the sole canonical kind2 superseded Operation successor.
///
/// The caller separately verifies the other three immutable admission members
/// and genuine completed same-target Stop history. Matching DATA grants neither
/// historical financial completion nor permission to execute another cleanup.
///
/// # Errors
/// Refuses changed immutable metadata, another terminal state, an invalid wall
/// timestamp or a sequence other than the sole Accepted-to-superseded successor.
pub fn require_stop_cleanup_superseded_operation_data_v1(
    observation: Data<'_>,
    encoded: &[u8],
) -> Result<(), MetadataCompleteDataErrorV1> {
    let actual = decode_operation(encoded)?;
    let wall = actual.public_operation()
        .and_then(|public| public.completed_wall_seconds_v1())
        .ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    if actual != superseded_operation(observation, wall)? {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    Ok(())
}

fn superseded_operation(
    observation: Data<'_>,
    wall: i64,
) -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    let admitted = stop_cleanup_operation_v1(observation)?;
    let public = admitted.public_operation().ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    Ok(admitted.with_state_and_public_operation(
        OperationState::PermanentlyBlocked,
        Some(public.advance(OperationState::PermanentlyBlocked, wall)?),
    ))
}
