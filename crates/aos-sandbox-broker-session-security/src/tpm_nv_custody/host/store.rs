//! Typed Host sidecar history joined to genuine original main comparisons.
//!
//! This adapter interprets only validated native DATA from Core's same parser.
//! Its canonical bytes, prepared codec and expected sidecar transactions use
//! the single shared engines. It neither parses native frames, decodes phases,
//! hashes a HEAD, reduces fresh NV nor grants recovery or append authority.
//!
//! ```text
//! checkpoint(C1) -> [intent + exact prepared TX] -> [checkpoint(target), DEL, DEL]
//! ```

use std::mem::size_of;

use aos_sandbox::{
    HeldRuntimeDeploymentPairComparisonV1, JournalLimits, JournalRecord,
    JournalTransaction, RuntimeDeploymentNativeTransactionDataV1,
};

use super::HostOwnedJournalErrorV1;
use crate::tpm_nv_custody::{
    FloorCutV1, HostFloorCheckpointDataV1, HostFloorIntentDataV1,
    INTENT_KEY, TRANSACTION_KEY, host_finalize_transaction, host_initial_transaction,
    host_prepare_transaction, sidecar_sequence_v1,
};

/// Describes only complete original disk associations, not NV recovery rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostDiskAssociationV1 {
    Complete,
    PendingMainOld,
    PendingMainTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredHostFloorV1 {
    pub(super) checkpoint: HostFloorCheckpointDataV1,
    pub(super) prepared: Option<(HostFloorIntentDataV1, JournalTransaction)>,
    pub(super) current: FloorCutV1,
    pub(super) association: HostDiskAssociationV1,
    pub(super) sidecar_sequence: u64,
}

struct RetainedTransitionV1 {
    intent: HostFloorIntentDataV1,
    transaction: JournalTransaction,
    finalized: bool,
}

/// Walks bounded original native DATA and joins every completed main transition.
pub(super) fn compare_original_state(
    pair: &mut HeldRuntimeDeploymentPairComparisonV1<'_, '_, '_, '_>,
    main_limits: JournalLimits,
) -> Result<StoredHostFloorV1, HostOwnedJournalErrorV1> {
    let scope = pair.compared_scope()?;
    let (sequence, head) = pair.compare_historical_prefix(4)?;
    let initial = HostFloorCheckpointDataV1::initial(scope, FloorCutV1::new(sequence, head)?)?;
    let (sequence, head) = pair.compared_current()?;
    let current = FloorCutV1::new(sequence, head)?;
    let (checkpoint, transitions, sidecar_sequence) = {
        let history = pair.sidecar_native_history()?;
        decode_original_history(history, initial, scope, main_limits)?
    };

    let mut prepared = None;
    let mut association = HostDiskAssociationV1::Complete;
    for transition in transitions {
        let predecessor = transition.intent.predecessor().cut();
        let target = transition.intent.target().cut();
        let (sequence, head) = pair.compare_historical_prefix(predecessor.sequence())?;
        if FloorCutV1::new(sequence, head)? != predecessor {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        if transition.finalized || current == target {
            let (before, after) = pair.compare_retained_transition(&transition.transaction)?;
            if FloorCutV1::new(before.0, before.1)? != predecessor
                || FloorCutV1::new(after.0, after.1)? != target
            {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
        }
        if !transition.finalized {
            association = if current == predecessor {
                // The genuine prospective comparison is performed by the
                // whole owner after releasing this transient pair borrow.
                HostDiskAssociationV1::PendingMainOld
            } else if current == target {
                HostDiskAssociationV1::PendingMainTarget
            } else {
                return Err(HostOwnedJournalErrorV1::Changed);
            };
            prepared = Some((transition.intent, transition.transaction));
        }
    }
    if prepared.is_none() && current != checkpoint.cut() {
        return Err(HostOwnedJournalErrorV1::Changed);
    }
    pair.recheck()?;
    Ok(StoredHostFloorV1 {
        checkpoint, prepared, current, association, sidecar_sequence,
    })
}

fn decode_original_history(
    history: &[RuntimeDeploymentNativeTransactionDataV1],
    initial: HostFloorCheckpointDataV1,
    scope: [u8; 32],
    main_limits: JournalLimits,
) -> Result<(HostFloorCheckpointDataV1, Vec<RetainedTransitionV1>, u64), HostOwnedJournalErrorV1> {
    let first = history.first().ok_or(HostOwnedJournalErrorV1::Changed)?;
    if first.begin_sequence() != 1
        || first.commit_sequence() != 3
        || first.next_sequence() != 4
        || first.transaction() != &host_initial_transaction(initial)?
    {
        return Err(HostOwnedJournalErrorV1::Changed);
    }

    let mut checkpoint = initial;
    let mut next_sequence = first.next_sequence();
    let mut transitions: Vec<RetainedTransitionV1> = Vec::new();
    let mut pending = false;
    let mut retained_bytes = 0_usize;
    let maximum = usize::try_from(main_limits.maximum_journal_bytes)
        .map_err(|_| aos_sandbox::JournalError::JournalTooLarge)?;
    for native in &history[1..] {
        if native.begin_sequence() != next_sequence {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        if pending {
            let transition = transitions.last_mut().ok_or(HostOwnedJournalErrorV1::Changed)?;
            if native.transaction() != &host_finalize_transaction(transition.intent)?
                || native.next_sequence()
                    != sidecar_sequence_v1(transition.intent.target().ordinal(), false)?
            {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            checkpoint = transition.intent.target();
            transition.finalized = true;
            pending = false;
        } else {
            let records = native.transaction().records();
            if records.len() != 2
                || records[0].key() != INTENT_KEY
                || records[1].key() != TRANSACTION_KEY
            {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            let bytes = records[1].value().ok_or(HostOwnedJournalErrorV1::Changed)?;
            // Bound duplicate typed retention before decoding/reserving. The
            // sole prepared decoder still owns its bounded allocation behavior.
            let charge = size_of::<RetainedTransitionV1>()
                .checked_add(size_of::<JournalRecord>()
                    .checked_mul(main_limits.maximum_records_per_transaction)
                    .ok_or(aos_sandbox::JournalError::SequenceExhausted)?)
                .and_then(|charge| charge.checked_add(bytes.len()))
                .ok_or(aos_sandbox::JournalError::SequenceExhausted)?;
            retained_bytes = retained_bytes.checked_add(charge)
                .filter(|bytes| *bytes <= maximum)
                .ok_or(aos_sandbox::JournalError::LimitExceeded("Host typed native history bytes"))?;
            let count = transitions.len().checked_add(1)
                .filter(|count| *count <= main_limits.maximum_transactions)
                .ok_or(aos_sandbox::JournalError::LimitExceeded("Host typed native history count"))?;
            transitions.try_reserve_exact(count - transitions.len())
                .map_err(|_| aos_sandbox::JournalError::LimitExceeded("Host typed history allocation"))?;
            let transition = decode_preparation(native.transaction(), checkpoint, scope, main_limits)?;
            if native.next_sequence() != sidecar_sequence_v1(checkpoint.ordinal(), true)? {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            transitions.push(transition);
            pending = true;
        }
        next_sequence = native.next_sequence();
    }
    if next_sequence != sidecar_sequence_v1(checkpoint.ordinal(), pending)? {
        return Err(HostOwnedJournalErrorV1::Changed);
    }
    Ok((checkpoint, transitions, next_sequence))
}

fn decode_preparation(
    native: &JournalTransaction,
    checkpoint: HostFloorCheckpointDataV1,
    scope: [u8; 32],
    main_limits: JournalLimits,
) -> Result<RetainedTransitionV1, HostOwnedJournalErrorV1> {
    let records = native.records();
    if records.len() != 2
        || records[0].key() != INTENT_KEY
        || records[1].key() != TRANSACTION_KEY
    {
        return Err(HostOwnedJournalErrorV1::Changed);
    }
    let intent = HostFloorIntentDataV1::decode(
        scope, records[0].value().ok_or(HostOwnedJournalErrorV1::Changed)?,
    )?;
    let transaction = JournalTransaction::decode_prepared_v1(
        records[1].value().ok_or(HostOwnedJournalErrorV1::Changed)?, main_limits,
    )?;
    intent.require_transaction(&transaction)?;
    if intent.predecessor() != checkpoint
        || native != &host_prepare_transaction(intent, &transaction, main_limits)?
    {
        return Err(HostOwnedJournalErrorV1::Changed);
    }
    Ok(RetainedTransitionV1 { intent, transaction, finalized: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox::RecordNamespace;
    use crate::tpm_nv_custody::CHECKPOINT_KEY;

    fn inert_data() -> (
        HostFloorCheckpointDataV1, HostFloorIntentDataV1, JournalTransaction, JournalLimits,
    ) {
        // Shape-valid unsigned DATA only; it cannot create Origins or an owner.
        let limits = JournalLimits {
            maximum_journal_bytes: 1048576,
            maximum_record_bytes: 1024,
            maximum_key_bytes: 32,
            maximum_records_per_transaction: 1,
            maximum_transaction_bytes: 1024,
            maximum_transactions: 321,
            maximum_materialized_bytes: 262144,
            maximum_materialized_records: 321,
        };
        let checkpoint = HostFloorCheckpointDataV1::initial(
            [7; 32], FloorCutV1::new(4, [8; 32]).unwrap(),
        ).unwrap();
        let transaction = JournalTransaction::new([9; 16], vec![JournalRecord::put(
            RecordNamespace::HostCatalogReconciliation, b"phase".to_vec(), vec![10],
        )]).unwrap();
        let intent = HostFloorIntentDataV1::compare_successor(
            [7; 32], checkpoint, FloorCutV1::new(7, [11; 32]).unwrap(), &transaction,
        ).unwrap();
        (checkpoint, intent, transaction, limits)
    }

    #[test]
    fn unrun_host_data_preparation_reuses_exact_shared_codec_and_uuid() {
        let (checkpoint, intent, transaction, limits) = inert_data();
        let native = host_prepare_transaction(intent, &transaction, limits).unwrap();

        let retained = decode_preparation(&native, checkpoint, [7; 32], limits).unwrap();

        assert_eq!(retained.intent, intent);
        assert_eq!(retained.transaction, transaction);
        assert!(!retained.finalized);
        assert_eq!(native.records().len(), 2);
    }

    #[test]
    fn unrun_host_data_preparation_refuses_uuid_order_empty_put_and_transplant() {
        let (checkpoint, intent, transaction, limits) = inert_data();
        let canonical = host_prepare_transaction(intent, &transaction, limits).unwrap();
        let mut reversed = canonical.records().to_vec();
        reversed.reverse();
        let wrong_id = JournalTransaction::new([12; 16], canonical.records().to_vec()).unwrap();
        let wrong_order = JournalTransaction::new(*canonical.id(), reversed).unwrap();
        let empty = JournalTransaction::new(*canonical.id(), vec![
            JournalRecord::put(RecordNamespace::HostCatalogReconciliation, INTENT_KEY.to_vec(), vec![]),
            canonical.records()[1].clone(),
        ]).unwrap();

        for native in [wrong_id, wrong_order, empty] {
            assert!(decode_preparation(&native, checkpoint, [7; 32], limits).is_err());
        }
        assert!(decode_preparation(&canonical, checkpoint, [13; 32], limits).is_err());
    }

    #[test]
    fn unrun_host_data_finalization_preserves_ordered_delete_distinction() {
        let (_, intent, _, _) = inert_data();

        let native = host_finalize_transaction(intent).unwrap();

        assert_eq!(native.records().len(), 3);
        assert_eq!(native.records()[0].key(), CHECKPOINT_KEY);
        assert_eq!(native.records()[0].value(), Some(intent.target().encode().as_slice()));
        assert_eq!(native.records()[1].key(), INTENT_KEY);
        assert_eq!(native.records()[2].key(), TRANSACTION_KEY);
        assert!(native.records()[1].value().is_none());
        assert!(native.records()[2].value().is_none());
    }
}
