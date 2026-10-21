//! Shares passive Create Storage record/head transaction and readback mechanics.
//!
//! These helpers validate bytes and returned positions. They perform no I/O,
//! lend no writer and admit no append. Each closed Native role loan retains its
//! own original, paid capture, transition, final crossing and independent posts.
//! A map readback alone does not prove the complete allowed native suffix.

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
};
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::{
    HistoryPairReadbackDataV1, HistoryPairReadbackBytesDataV1,
};

use super::{CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};


/// Prepares exactly one ordered record/head pair without admitting its append.
///
/// # Errors
/// Rejects malformed envelopes, substituted heads, or native transaction limits.
pub(crate) fn prepare_history_pair_v1(
    key: KeyV1, phase: PhaseV1, record: &[u8], head: &[u8; HEAD_BYTES],
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_protocol::domain_ledger::create_storage_history::prepare_history_pair_v1(
        key, phase, record, head,
    ).map_err(|error| match error {
        aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1::Envelope =>
            JournalError::ProtectedBoundary,
        aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1::Transaction(cause) =>
            JournalError::from(cause),
    })
}

// The untrusted independent reader must reject the constructor's sole possible
// fixed-shape refusal before allocating comparison copies. Ordinary producers
// retain their exact preparation/allocation schedule through the old entry.
pub(crate) fn prepare_readonly_history_pair_v1(
    key: KeyV1,
    phase: PhaseV1,
    record: &[u8],
    head: &[u8; HEAD_BYTES],
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_protocol::prepare_readonly_history_pair_recipe_v1!(
        key = key, phase = phase, record = record,
        invalid = JournalError::ProtectedBoundary,
        prepared = prepare_history_pair_v1(key, phase, record, head)
    )
}


/// Compares the exact materialized pair and returned four-frame NEXT.
///
/// The role separately checks physical names/end and its complete native suffix.
/// This pure map comparison makes no syscall and creates no currentness receipt.
///
/// # Errors
/// Rejects substituted transaction members, missing rows, differing bytes, or a
/// returned COMMIT/NEXT differing from the same supplied preappend NEXT.
pub(crate) fn readback_history_pair_v1<const RECORD: usize>(
    journal: &Journal,
    transaction: &JournalTransaction,
    record: &[u8; RECORD],
    head: &[u8; HEAD_BYTES],
    before_next: u64,
    committed: &CommitResult,
) -> Result<HistoryPairReadbackDataV1<RECORD>, JournalError> {
    let observed = readback_history_pair_bytes_v1(journal, transaction, record, head, before_next, committed)?;
    Ok(HistoryPairReadbackDataV1 {
        record: observed.record.try_into().map_err(|_| JournalError::ProtectedBoundary)?,
        head: observed.head,
        next: observed.next,
    })
}


/// Compares the same atomic pair without copying a variable-width record.
///
/// # Errors
/// Rejects substituted members, missing/differing bytes or returned NEXT.
pub(crate) fn readback_history_pair_bytes_v1<'journal>(
    journal: &'journal Journal,
    transaction: &JournalTransaction,
    record: &[u8],
    head: &[u8; HEAD_BYTES],
    before_next: u64,
    committed: &CommitResult,
) -> Result<HistoryPairReadbackBytesDataV1<'journal>, JournalError> {
    aos_sandbox_protocol::readback_create_storage_history_pair_bytes_data_v1! {
        journal: journal,
        transaction: transaction,
        record: record,
        head: head,
        before_next: before_next,
        committed: committed,
        namespace: RecordNamespace::CreateStorageHistory,
        boundary: JournalError::ProtectedBoundary,
        result: HistoryPairReadbackBytesDataV1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        RECORD_OVERHEAD_BYTES, RecordCoordinatesV1,
    };

    fn pair(owner: OwnerV1) -> (KeyV1, PhaseV1, Vec<u8>, [u8; HEAD_BYTES]) {
        let key = KeyV1::new([7; 16], owner, 1).unwrap();
        let phase = PhaseV1::new(owner, 1).unwrap();
        let mut record = vec![0; RECORD_OVERHEAD_BYTES + 3];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor: [0; 32], correlation: [9; 32],
        }, b"cut", &mut record).unwrap();
        let head = LatestHeadV1::new(1, checksum).unwrap().encode();
        (key, phase, record, head)
    }

    #[test]
    fn shared_root_pair_preserves_original_transaction_identity_and_members() {
        let (key, phase, record, head) = pair(OwnerV1::Root);
        let envelope = RecordEnvelopeV1::decode(&record, key, phase).unwrap();
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.create-storage.root-open.transaction.v1\0")
            .chain_update(envelope.checksum()).finalize();
        let expected = JournalTransaction::new(digest[..16].try_into().unwrap(), vec![
            JournalRecord::put(RecordNamespace::CreateStorageHistory, key.encode().to_vec(), record.clone()),
            JournalRecord::put(RecordNamespace::CreateStorageHistory,
                KeyV1::new(key.lane(), OwnerV1::Root, 0).unwrap().encode().to_vec(), head.to_vec()),
        ]).unwrap();

        let prepared = prepare_history_pair_v1(key, phase, &record, &head).unwrap();

        assert_eq!(prepared, expected);
    }

    #[test]
    fn substituted_record_head_and_owner_are_rejected_before_transaction_creation() {
        let (key, phase, mut record, mut head) = pair(OwnerV1::Source);
        let other = KeyV1::new(key.lane(), OwnerV1::Controller, 1).unwrap();
        assert!(prepare_history_pair_v1(other, phase, &record, &head).is_err());
        head[8] ^= 1;
        assert!(prepare_history_pair_v1(key, phase, &record, &head).is_err());
        head[8] ^= 1;
        record[108] ^= 1;
        assert!(prepare_history_pair_v1(key, phase, &record, &head).is_err());
    }
}

pub(crate) use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::controller::ControllerHistoryNativeSuffixV1;

pub(crate) use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::{
    HistoryPairSuffixErrorV1, HistoryPairNativeSuffixProgressV1, HistoryPairNativeSuffixV1,
};

impl Journal {
    // This role-fixed pure view is reachable only from the genuine joined
    // Ready original. No name open, replay, allocation or general State getter
    // is introduced. Root still independently verifies its own current cut.
    pub(crate) fn create_storage_bundle_admission_data_v1<'data>(
        &'data self,
        original: &crate::controller_resource_reservation::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Result<[&'data [u8]; 3], JournalError> {
        self.ensure_healthy()?;
        let (enrollment, child, claim_id) = original.bundle_admission_accounts_data_v1(self)?;
        let find = |id, kind| -> Result<&'data [u8], JournalError> {
            let bytes = aos_sandbox_protocol::domain_ledger::resource_bank::head_bytes(self.native.state(), id)
                .ok_or(JournalError::ProtectedBoundary)?;
            let head = aos_sandbox_protocol::domain_ledger::resource_bank::AccountHead::decode(bytes)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let fields = head.native_fields();
            if fields.id != id || fields.enrollment != enrollment || fields.kind != kind {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(bytes)
        };
        let controller = find(enrollment.account_id(b"controller"),
            aos_sandbox_protocol::domain_ledger::resource_bank::AccountKind::Controller)?;
        let sandbox = find(child,
            aos_sandbox_protocol::domain_ledger::resource_bank::AccountKind::Sandbox)?;
        let claim = aos_sandbox_protocol::domain_ledger::resource_bank::claim_bytes(self.native.state(), claim_id)
            .ok_or(JournalError::ProtectedBoundary)?;
        let decoded = aos_sandbox_protocol::domain_ledger::resource_bank::Claim::decode(claim)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if decoded.native_fields().enrollment != enrollment || decoded.native_fields().id != claim_id {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok([controller, sandbox, claim])
    }
}


use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairNativeChainDataV1;

#[cfg(test)]
mod controller_chain_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        RECORD_OVERHEAD_BYTES, RecordCoordinatesV1,
    };

    fn recipes() -> ([JournalTransaction; 3], [(u64, u64); 4]) {
        let mut predecessor = [0; 32];
        let mut position = (17_u64, 90_u64);
        let mut positions = [position; 4];
        let transactions = std::array::from_fn(|index| {
            let key = KeyV1::new([7; 16], OwnerV1::Controller, (index + 1) as u64).unwrap();
            let phase = PhaseV1::new(OwnerV1::Controller, [1, 12, 2][index]).unwrap();
            let mut record = vec![0; RECORD_OVERHEAD_BYTES + 1];
            let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                key, phase, predecessor, correlation: [9; 32],
            }, &[index as u8], &mut record).unwrap();
            predecessor = checksum;
            let head = LatestHeadV1::new((index + 1) as u64, checksum).unwrap().encode();
            let transaction = prepare_readonly_history_pair_v1(key, phase, &record, &head).unwrap();
            position = (position.0 + 4,
                position.1 + super::super::encoded_transaction_append_bytes(&transaction).unwrap());
            positions[index + 1] = position;
            transaction
        });
        (transactions, positions)
    }

    #[test]
    fn three_segments_join_only_the_final_actual_file_end() {
        // Canonical transaction comparison DATA. Production supplies each
        // observation only from the same paid validated COMMIT parser.
        let (transactions, positions) = recipes();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;
        {
            let [first, second, third] = &mut progress;
            let mut chain = HistoryPairNativeChainDataV1::new(
                [&transactions[0], &transactions[1], &transactions[2]],
                [first, second, third], &mut active, positions,
            ).unwrap();
            for index in 0..3 {
                chain.observe(&transactions[index], positions[index].0, positions[index + 1].0 - 1,
                    positions[index].1, positions[index + 1].1).unwrap();
            }
            chain.finish(positions[3].0, positions[3].1, positions[3].1).unwrap();
        }

        assert_eq!(active, 2);
        assert!(progress.iter().all(|value| value.is_complete()));
    }

    #[test]
    fn an_interleaved_transaction_keeps_the_first_exact_cause() {
        let (transactions, positions) = recipes();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;
        let [first, second, third] = &mut progress;
        let mut chain = HistoryPairNativeChainDataV1::new(
            [&transactions[0], &transactions[1], &transactions[2]],
            [first, second, third], &mut active, positions,
        ).unwrap();
        chain.observe(&transactions[0], positions[0].0, positions[1].0 - 1,
            positions[0].1, positions[1].1).unwrap();

        assert_eq!(chain.observe(&transactions[2], positions[1].0, positions[2].0 - 1,
            positions[1].1, positions[2].1), Err(HistoryPairSuffixErrorV1::Transaction));
        assert_eq!(chain.finish(positions[3].0, positions[3].1, positions[3].1),
            Err(HistoryPairSuffixErrorV1::Transaction));
        drop(chain);
        assert_eq!(progress[1].failure(), Some(&HistoryPairSuffixErrorV1::Transaction));
        assert!(!progress[1].is_complete());
    }

    #[test]
    fn final_tail_or_reentry_cannot_heal_a_completed_segment() {
        let (transactions, positions) = recipes();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;
        {
            let [first, second, third] = &mut progress;
            let mut chain = HistoryPairNativeChainDataV1::new(
                [&transactions[0], &transactions[1], &transactions[2]],
                [first, second, third], &mut active, positions,
            ).unwrap();
            for index in 0..3 {
                chain.observe(&transactions[index], positions[index].0, positions[index + 1].0 - 1,
                    positions[index].1, positions[index + 1].1).unwrap();
            }
            assert_eq!(chain.finish(positions[3].0, positions[3].1, positions[3].1 + 1),
                Err(HistoryPairSuffixErrorV1::Coordinates));
            assert_eq!(chain.finish(positions[3].0, positions[3].1, positions[3].1),
                Err(HistoryPairSuffixErrorV1::Coordinates));
        }

        assert!(progress[..2].iter().all(|value| value.is_complete()));
        assert!(!progress[2].is_complete());
    }
}

#[cfg(test)]
mod reserved_chain_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        RECORD_OVERHEAD_BYTES, RecordCoordinatesV1,
    };
    use aos_sandbox_protocol::domain_ledger::resource_bank::CreateStorageUseBindingV1;

    fn recipes() -> ([JournalTransaction; 6], [(u64, u64); 7]) {
        let mut predecessor = [0; 32];
        let mut position = (17_u64, 90_u64);
        let mut positions = [position; 7];
        let transactions = std::array::from_fn(|index| {
            let transaction = if index == 4 {
                // Canonical binding comparison DATA only. Financial admission
                // is tested by PhysicalHistory; these rows mint no native loan.
                let mut bytes = [0_u8; 168];
                bytes[..8].copy_from_slice(b"AOSRSU01");
                bytes[8..24].fill(1);
                bytes[24..56].fill(2);
                bytes[56..88].fill(3);
                bytes[88..120].fill(4);
                bytes[120..136].fill(5);
                let checksum = Sha256::digest(&bytes[..136]);
                bytes[136..].copy_from_slice(&checksum);
                let binding = CreateStorageUseBindingV1::decode(&bytes).unwrap();
                JournalTransaction::new(binding.reserve_transaction_id().unwrap(), vec![
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"head".to_vec(), b"reserved-head".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"claim".to_vec(), b"reserved-claim".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"binding".to_vec(), bytes.to_vec()),
                ]).unwrap()
            } else {
                let revision = if index == 5 { 5 } else { index + 1 };
                let key = KeyV1::new([7; 16], OwnerV1::Controller, revision as u64).unwrap();
                let phase = PhaseV1::new(OwnerV1::Controller, [1, 12, 2, 3, 0, 4][index]).unwrap();
                let mut record = vec![0; RECORD_OVERHEAD_BYTES + 1];
                let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                    key, phase, predecessor, correlation: [9; 32],
                }, &[index as u8], &mut record).unwrap();
                predecessor = checksum;
                let head = LatestHeadV1::new(revision as u64, checksum).unwrap().encode();
                prepare_readonly_history_pair_v1(key, phase, &record, &head).unwrap()
            };
            position = (position.0 + transaction.records().len() as u64 + 2,
                position.1 + super::super::encoded_transaction_append_bytes(&transaction).unwrap());
            positions[index + 1] = position;
            transaction
        });
        (transactions, positions)
    }

    #[test]
    fn six_exact_reserved_commits_complete_all_distinct_progress_destinations() {
        let (transactions, positions) = recipes();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;
        {
            let [first, second, third, fourth, bank, sixth] = &mut progress;
            let mut suffix = HistoryPairNativeChainDataV1::<6>::new_reserved(
                std::array::from_fn(|index| &transactions[index]),
                [first, second, third, fourth, bank, sixth], &mut active, positions,
            ).unwrap();
            for index in 0..6 {
                suffix.observe(&transactions[index], positions[index].0,
                    positions[index + 1].0 - 1, positions[index].1, positions[index + 1].1).unwrap();
            }
            suffix.finish(positions[6].0, positions[6].1, positions[6].1).unwrap();
        }
        assert_eq!(active, 5);
        assert!(progress.iter().all(|value| value.is_complete()));
    }

    #[test]
    fn reserved_chain_requires_all_six_exact_commits_and_final_file_end() {
        let (transactions, positions) = recipes();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;
        {
            let [first, second, third, fourth, bank, sixth] = &mut progress;
            let mut suffix = HistoryPairNativeChainDataV1::<6>::new_reserved(
                std::array::from_fn(|index| &transactions[index]),
                [first, second, third, fourth, bank, sixth], &mut active, positions,
            ).unwrap();
            for index in 0..6 {
                suffix.observe(&transactions[index], positions[index].0,
                    positions[index + 1].0 - 1, positions[index].1, positions[index + 1].1).unwrap();
            }
            assert_eq!(suffix.finish(positions[6].0, positions[6].1, positions[6].1 + 1),
                Err(HistoryPairSuffixErrorV1::Coordinates));
            assert_eq!(suffix.finish(positions[6].0, positions[6].1, positions[6].1),
                Err(HistoryPairSuffixErrorV1::Coordinates));
        }
        assert!(progress[..5].iter().all(|value| value.is_complete()));
        assert!(!progress[5].is_complete());
    }

    #[test]
    fn bank_commit_cannot_be_skipped_or_replaced_by_the_final_history_pair() {
        let (transactions, positions) = recipes();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;
        {
            let [first, second, third, fourth, bank, sixth] = &mut progress;
            let mut suffix = HistoryPairNativeChainDataV1::<6>::new_reserved(
                std::array::from_fn(|index| &transactions[index]),
                [first, second, third, fourth, bank, sixth], &mut active, positions,
            ).unwrap();
            for index in 0..4 {
                suffix.observe(&transactions[index], positions[index].0,
                    positions[index + 1].0 - 1, positions[index].1, positions[index + 1].1).unwrap();
            }
            assert_eq!(suffix.observe(&transactions[5], positions[4].0, positions[5].0 - 1,
                positions[4].1, positions[5].1), Err(HistoryPairSuffixErrorV1::Transaction));
            assert_eq!(suffix.observe(&transactions[4], positions[4].0, positions[5].0 - 1,
                positions[4].1, positions[5].1), Err(HistoryPairSuffixErrorV1::Transaction));
        }
        assert_eq!(progress[4].failure(), Some(&HistoryPairSuffixErrorV1::Transaction));
        assert!(!progress[4].is_complete());
    }
}

#[cfg(test)]
mod outcome_native_chain_tests {
    use super::*;
    use std::io::Write as _;
    use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        RECORD_OVERHEAD_BYTES, RecordCoordinatesV1};
    use aos_sandbox_protocol::domain_ledger::resource_bank::CreateStorageUseBindingV1;
    use aos_sandbox_broker::canonical_journal::{CanonicalReplayOriginalV1,
        coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1}};
    fn recipes() -> ([JournalTransaction; 10], [(u64, u64); 11]) {
        let mut predecessor = [0; 32];
        let mut position = (1_u64, 0_u64);
        let mut positions = [position; 11];
        let transactions = std::array::from_fn(|index| {
            let transaction = if index == 4 {
                // Canonical binding comparison DATA only. Financial admission
                // is tested by PhysicalHistory; these rows mint no native loan.
                let mut bytes = [0_u8; 168];
                bytes[..8].copy_from_slice(b"AOSRSU01");
                bytes[8..24].fill(1);
                bytes[24..56].fill(2);
                bytes[56..88].fill(3);
                bytes[88..120].fill(4);
                bytes[120..136].fill(5);
                let checksum = Sha256::digest(&bytes[..136]);
                bytes[136..].copy_from_slice(&checksum);
                let binding = CreateStorageUseBindingV1::decode(&bytes).unwrap();
                JournalTransaction::new(binding.reserve_transaction_id().unwrap(), vec![
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"head".to_vec(), b"reserved-head".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"claim".to_vec(), b"reserved-claim".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"binding".to_vec(), bytes.to_vec()),
                ]).unwrap()
            } else {
                let revision = if index >= 5 { index } else { index + 1 };
                let key = KeyV1::new([7; 16], OwnerV1::Controller, revision as u64).unwrap();
                let phase = PhaseV1::new(OwnerV1::Controller, [1, 12, 2, 3, 0, 4, 5, 6, 7, 8][index]).unwrap();
                let mut record = vec![0; RECORD_OVERHEAD_BYTES + 1];
                let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                    key, phase, predecessor, correlation: [9; 32],
                }, &[index as u8], &mut record).unwrap();
                predecessor = checksum;
                let head = LatestHeadV1::new(revision as u64, checksum).unwrap().encode();
                prepare_readonly_history_pair_v1(key, phase, &record, &head).unwrap()
            };
            position = (position.0 + transaction.records().len() as u64 + 2,
                position.1 + super::super::encoded_transaction_append_bytes(&transaction).unwrap());
            positions[index + 1] = position;
            transaction
        });
        (transactions, positions)
    }

    fn file_for(transactions: &[JournalTransaction]) -> std::fs::File {
        let mut file = tempfile::tempfile().unwrap();
        let mut next = 1;
        for transaction in transactions {
            let frames = encode_transaction(transaction, next).unwrap();
            next += frames.len() as u64;
            for frame in frames { file.write_all(&frame).unwrap(); }
        }
        file
    }

    fn drive(file: &std::fs::File, raw: &mut CanonicalReplayOriginalV1,
        expected: &[JournalTransaction; 10], positions: [(u64, u64); 11],
        progress: &mut [HistoryPairNativeSuffixProgressV1; 10], active: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9] = progress;
        let mut suffix = HistoryPairNativeChainDataV1::<10>::new_outcome(
            std::array::from_fn(|index| &expected[index]), [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9], active, positions)?;
        let mut index = std::collections::BTreeMap::new();
        let mut index_originals = CanonicalReplayIndexOriginalsV1::new();
        let cursor = raw.begin_semantic_cursor_once(file, super::super::JournalLimits::default(), file.metadata()?.len())?;
        let mut cursor = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_originals);
        while cursor.advance_once()? {
            let view = cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
            let (begin, offset) = view.begin_position();
            suffix.observe(view.transaction(), begin, view.commit_sequence(), offset, view.coordinates().offset)?;
            cursor.validate_compaction_once()?;
            cursor.register_and_compare_index_once()?;
            cursor.prepare_change_once()?;
            while cursor.apply_next_record_once()? {}
            cursor.finish_commit_accounting_once()?;
            cursor.finish_commit_once()?;
        }
        let coordinates = cursor.completed_prefix().ok_or(JournalError::ProtectedBoundary)?.coordinates();
        suffix.finish(coordinates.durable_next_sequence, coordinates.durable_end, file.metadata()?.len())?;
        Ok(())
    }

    #[test]
    fn ten_actual_canonical_commits_include_c6_c7_c8_and_c9() {
        let (transactions, positions) = recipes();
        let file = file_for(&transactions);
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;

        drive(&file, &mut raw, &transactions, positions, &mut progress, &mut active).unwrap();

        assert_eq!(active, 9);
        assert!(progress.iter().all(|value| value.is_complete()));
        assert_eq!(raw.report().unwrap().0, positions[10].1);
    }

    #[test]
    fn a_canonical_but_substituted_c9_is_not_accepted_by_receipt_coordinates() {
        let (expected, positions) = recipes();
        let mut actual = expected.clone();
        actual[9] = JournalTransaction::new([99; 16], actual[9].records().to_vec()).unwrap();
        let file = file_for(&actual);
        assert_eq!(file.metadata().unwrap().len(), positions[10].1);
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;

        assert!(drive(&file, &mut raw, &expected, positions, &mut progress, &mut active).is_err());

        assert!(progress[..9].iter().all(|value| value.is_complete()));
        assert_eq!(progress[9].failure(), Some(&HistoryPairSuffixErrorV1::Transaction));
        assert!(raw.report().is_none());
    }
}

#[cfg(test)]
mod signed_native_chain_tests {
    use super::*;
    use std::io::Write as _;
    use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        RECORD_OVERHEAD_BYTES, RecordCoordinatesV1};
    use aos_sandbox_protocol::domain_ledger::resource_bank::CreateStorageUseBindingV1;
    use aos_sandbox_broker::canonical_journal::{CanonicalReplayOriginalV1,
        coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1}};
    pub(super) fn recipes() -> ([JournalTransaction; 7], [(u64, u64); 8]) {
        let mut predecessor = [0; 32];
        let mut position = (1_u64, 0_u64);
        let mut positions = [position; 8];
        let transactions = std::array::from_fn(|index| {
            let transaction = if index == 4 {
                // Canonical binding comparison DATA only. Financial admission
                // is tested by PhysicalHistory; these rows mint no native loan.
                let mut bytes = [0_u8; 168];
                bytes[..8].copy_from_slice(b"AOSRSU01");
                bytes[8..24].fill(1);
                bytes[24..56].fill(2);
                bytes[56..88].fill(3);
                bytes[88..120].fill(4);
                bytes[120..136].fill(5);
                let checksum = Sha256::digest(&bytes[..136]);
                bytes[136..].copy_from_slice(&checksum);
                let binding = CreateStorageUseBindingV1::decode(&bytes).unwrap();
                JournalTransaction::new(binding.reserve_transaction_id().unwrap(), vec![
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"head".to_vec(), b"reserved-head".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"claim".to_vec(), b"reserved-claim".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                        b"binding".to_vec(), bytes.to_vec()),
                ]).unwrap()
            } else {
                let revision = if index >= 5 { index } else { index + 1 };
                let key = KeyV1::new([7; 16], OwnerV1::Controller, revision as u64).unwrap();
                let phase = PhaseV1::new(OwnerV1::Controller, [1, 12, 2, 3, 0, 4, 5, 6, 7, 8][index]).unwrap();
                let mut record = vec![0; RECORD_OVERHEAD_BYTES + 1];
                let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                    key, phase, predecessor, correlation: [9; 32],
                }, &[index as u8], &mut record).unwrap();
                predecessor = checksum;
                let head = LatestHeadV1::new(revision as u64, checksum).unwrap().encode();
                prepare_readonly_history_pair_v1(key, phase, &record, &head).unwrap()
            };
            position = (position.0 + transaction.records().len() as u64 + 2,
                position.1 + super::super::encoded_transaction_append_bytes(&transaction).unwrap());
            positions[index + 1] = position;
            transaction
        });
        (transactions, positions)
    }

    pub(super) fn file_for(transactions: &[JournalTransaction]) -> std::fs::File {
        let mut file = tempfile::tempfile().unwrap();
        let mut next = 1;
        for transaction in transactions {
            let frames = encode_transaction(transaction, next).unwrap();
            next += frames.len() as u64;
            for frame in frames { file.write_all(&frame).unwrap(); }
        }
        file
    }

    fn drive(file: &std::fs::File, raw: &mut CanonicalReplayOriginalV1,
        expected: &[JournalTransaction; 7], positions: [(u64, u64); 8],
        progress: &mut [HistoryPairNativeSuffixProgressV1; 7], active: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let [p0,p1,p2,p3,p4,p5,p6] = progress;
        let mut suffix = HistoryPairNativeChainDataV1::<7>::new_signed(
            std::array::from_fn(|index| &expected[index]), [p0,p1,p2,p3,p4,p5,p6], active, positions)?;
        let mut index = std::collections::BTreeMap::new();
        let mut index_originals = CanonicalReplayIndexOriginalsV1::new();
        let cursor = raw.begin_semantic_cursor_once(file, super::super::JournalLimits::default(), file.metadata()?.len())?;
        let mut cursor = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_originals);
        while cursor.advance_once()? {
            let view = cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
            let (begin, offset) = view.begin_position();
            suffix.observe(view.transaction(), begin, view.commit_sequence(), offset, view.coordinates().offset)?;
            cursor.validate_compaction_once()?;
            cursor.register_and_compare_index_once()?;
            cursor.prepare_change_once()?;
            while cursor.apply_next_record_once()? {}
            cursor.finish_commit_accounting_once()?;
            cursor.finish_commit_once()?;
        }
        let coordinates = cursor.completed_prefix().ok_or(JournalError::ProtectedBoundary)?.coordinates();
        suffix.finish(coordinates.durable_next_sequence, coordinates.durable_end, file.metadata()?.len())?;
        Ok(())
    }

    #[test]
    fn seven_actual_canonical_commits_require_c6_before_root4() {
        let (transactions, positions) = recipes();
        let file = file_for(&transactions);
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;

        drive(&file, &mut raw, &transactions, positions, &mut progress, &mut active).unwrap();

        assert_eq!(active, 6);
        assert!(progress.iter().all(|value| value.is_complete()));
        assert_eq!(raw.report().unwrap().0, positions[7].1);
    }

    #[test]
    fn a_canonical_but_substituted_c6_is_not_accepted_by_prefix_coordinates() {
        let (expected, positions) = recipes();
        let mut actual = expected.clone();
        actual[6] = JournalTransaction::new([99; 16], actual[6].records().to_vec()).unwrap();
        let file = file_for(&actual);
        assert_eq!(file.metadata().unwrap().len(), positions[7].1);
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;

        assert!(drive(&file, &mut raw, &expected, positions, &mut progress, &mut active).is_err());

        assert!(progress[..6].iter().all(|value| value.is_complete()));
        assert_eq!(progress[6].failure(), Some(&HistoryPairSuffixErrorV1::Transaction));
        assert!(raw.report().is_none());
    }
}

#[cfg(test)]
mod closed_native_chain_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{RecordCoordinatesV1, RECORD_OVERHEAD_BYTES};
    use aos_sandbox_protocol::domain_ledger::resource_bank::CreateStorageUseBindingV1;
    use aos_sandbox_broker::canonical_journal::{CanonicalReplayOriginalV1,
        coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1}};

    // These canonical comparison recipes test native suffix identity/extent,
    // not financial admission or an admitted role. The complete bank/history
    // semantic observer remains mandatory in the actual Root6 reader.
    fn recipes() -> ([JournalTransaction; 12], [(u64, u64); 13], CreateStorageUseBindingV1) {
        let (initial, prior_positions) = signed_native_chain_tests::recipes();
        let binding = CreateStorageUseBindingV1::decode(initial[4].records()[2].value().unwrap()).unwrap();
        let mut transactions = initial.to_vec();
        let mut position = prior_positions[7];
        let mut positions = [(0,0);13];
        positions[..8].copy_from_slice(&prior_positions);
        let c6 = initial[6].records()[0].value().unwrap();
        let mut predecessor = RecordEnvelopeV1::decode(c6, KeyV1::new([7;16],OwnerV1::Controller,6).unwrap(),
            PhaseV1::new(OwnerV1::Controller,5).unwrap()).unwrap().checksum();
        for index in 7..12 {
            let transaction = if index == 10 {
                JournalTransaction::new(binding.commit_transaction_id().unwrap(),vec![
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,b"head".to_vec(),b"committed-head".to_vec()),
                    JournalRecord::put(RecordNamespace::ControllerResourceReservation,b"claim".to_vec(),b"committed-claim".to_vec()),
                ]).unwrap()
            } else {
                let revision = if index == 11 { 10 } else { index };
                let key = KeyV1::new([7;16],OwnerV1::Controller,revision as u64).unwrap();
                let phase = PhaseV1::new(OwnerV1::Controller,(revision-1) as u8).unwrap();
                let mut record = vec![0;RECORD_OVERHEAD_BYTES+1];
                let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                    key,phase,predecessor,correlation:[9;32],
                },&[index as u8],&mut record).unwrap();
                predecessor=checksum;
                let head=LatestHeadV1::new(revision as u64,checksum).unwrap().encode();
                prepare_readonly_history_pair_v1(key,phase,&record,&head).unwrap()
            };
            position=(position.0+transaction.records().len() as u64+2,
                position.1+super::super::encoded_transaction_append_bytes(&transaction).unwrap());
            positions[index+1]=position;
            transactions.push(transaction);
        }
        (transactions.try_into().ok().unwrap(),positions,binding)
    }

    fn drive(file:&std::fs::File,raw:&mut CanonicalReplayOriginalV1,expected:&[JournalTransaction;12],
        positions:[(u64,u64);13],binding:CreateStorageUseBindingV1,
        progress:&mut[HistoryPairNativeSuffixProgressV1;12],active:&mut usize)
        ->Result<(),Box<dyn std::error::Error>> {
        let [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11]=progress;
        let mut suffix=HistoryPairNativeChainDataV1::<12>::new_closed(
            std::array::from_fn(|index| &expected[index]),[p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11],
            active,positions,binding)?;
        let mut index=std::collections::BTreeMap::new();
        let mut originals=CanonicalReplayIndexOriginalsV1::new();
        let cursor=raw.begin_semantic_cursor_once(file,super::super::JournalLimits::default(),file.metadata()?.len())?;
        let mut cursor=CanonicalIndexedReplayV1::from_supplied_data_v1(cursor,&mut index,&mut originals);
        while cursor.advance_once()? {
            let actual=cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
            let (begin,offset)=actual.begin_position();
            suffix.observe(actual.transaction(),begin,actual.commit_sequence(),offset,actual.coordinates().offset)?;
            cursor.validate_compaction_once()?;
            cursor.register_and_compare_index_once()?;
            cursor.prepare_change_once()?;
            while cursor.apply_next_record_once()? {}
            cursor.finish_commit_accounting_once()?;
            cursor.finish_commit_once()?;
        }
        let actual=cursor.completed_prefix().ok_or(JournalError::ProtectedBoundary)?.coordinates();
        suffix.finish(actual.durable_next_sequence,actual.durable_end,file.metadata()?.len())?;
        Ok(())
    }

    #[test]
    fn twelve_actual_commits_include_positive_use_before_handoff() {
        let (transactions,positions,binding)=recipes();
        let file=signed_native_chain_tests::file_for(&transactions);
        let mut raw=CanonicalReplayOriginalV1::new();
        let mut progress=std::array::from_fn(|_|HistoryPairNativeSuffixProgressV1::new());
        let mut active=0;

        drive(&file,&mut raw,&transactions,positions,binding,&mut progress,&mut active).unwrap();

        assert_eq!(active,11);
        assert!(progress.iter().all(|progress|progress.is_complete()));
        assert_eq!(raw.report().unwrap().0,positions[12].1);
    }

    #[test]
    fn same_length_replacement_of_positive_use_transaction_fails_before_handoff() {
        let (expected,positions,binding)=recipes();
        let mut actual=expected.clone();
        actual[10]=JournalTransaction::new([99;16],actual[10].records().to_vec()).unwrap();
        let file=signed_native_chain_tests::file_for(&actual);
        assert_eq!(file.metadata().unwrap().len(),positions[12].1);
        let mut raw=CanonicalReplayOriginalV1::new();
        let mut progress=std::array::from_fn(|_|HistoryPairNativeSuffixProgressV1::new());
        let mut active=0;

        assert!(drive(&file,&mut raw,&expected,positions,binding,&mut progress,&mut active).is_err());

        assert!(progress[..10].iter().all(|progress|progress.is_complete()));
        assert_eq!(progress[10].failure(),Some(&HistoryPairSuffixErrorV1::Transaction));
        assert!(!progress[11].is_complete());
        assert!(raw.report().is_none());
    }
}

#[cfg(test)]
mod cache_released_native_chain_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{RECORD_OVERHEAD_BYTES, RecordCoordinatesV1};
    use aos_sandbox_broker::canonical_journal::{CanonicalReplayOriginalV1,
        coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1}};

    fn recipes() -> ([JournalTransaction; 2], [(u64, u64); 3]) {
        let mut predecessor = [0; 32];
        let mut position = (1_u64, 0_u64);
        let mut positions = [position; 3];
        let transactions = std::array::from_fn(|index| {
            // Native framing/transaction comparison DATA. The actual release
            // owner separately runs the complete Cache schema and live gates.
            let revision = (index + 1) as u64;
            let key = KeyV1::new([7; 16], OwnerV1::Cache, revision).unwrap();
            let phase = PhaseV1::new(OwnerV1::Cache, revision as u8).unwrap();
            let mut record = vec![0; RECORD_OVERHEAD_BYTES + 1];
            let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                key, phase, predecessor, correlation: [9; 32],
            }, &[index as u8], &mut record).unwrap();
            predecessor = checksum;
            let head = LatestHeadV1::new(revision, checksum).unwrap().encode();
            let transaction = prepare_readonly_history_pair_v1(key, phase, &record, &head).unwrap();
            position = (position.0 + 4, position.1 + super::super::encoded_transaction_append_bytes(&transaction).unwrap());
            positions[index + 1] = position;
            transaction
        });
        (transactions, positions)
    }

    fn drive(file: &std::fs::File, raw: &mut CanonicalReplayOriginalV1,
        expected: &[JournalTransaction; 2], positions: [(u64, u64); 3],
        progress: &mut [HistoryPairNativeSuffixProgressV1; 2], active: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let [held, released] = progress;
        let mut suffix = HistoryPairNativeChainDataV1::<2>::new_cache_released_v1(
            [&expected[0], &expected[1]], [held, released], active, positions)?;
        let mut index = std::collections::BTreeMap::new();
        let mut index_originals = CanonicalReplayIndexOriginalsV1::new();
        let cursor = raw.begin_semantic_cursor_once(file, super::super::JournalLimits::default(), file.metadata()?.len())?;
        let mut cursor = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_originals);
        while cursor.advance_once()? {
            let view = cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
            let (begin, offset) = view.begin_position();
            suffix.observe(view.transaction(), begin, view.commit_sequence(), offset, view.coordinates().offset)?;
            cursor.validate_compaction_once()?;
            cursor.register_and_compare_index_once()?;
            cursor.prepare_change_once()?;
            while cursor.apply_next_record_once()? {}
            cursor.finish_commit_accounting_once()?;
            cursor.finish_commit_once()?;
        }
        let coordinates = cursor.completed_prefix().ok_or(JournalError::ProtectedBoundary)?.coordinates();
        suffix.finish(coordinates.durable_next_sequence, coordinates.durable_end, file.metadata()?.len())?;
        Ok(())
    }

    #[test]
    fn cache_held_and_released_use_the_same_native_commit_observer() {
        let (transactions, positions) = recipes();
        let file = super::signed_native_chain_tests::file_for(&transactions);
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;

        drive(&file, &mut raw, &transactions, positions, &mut progress, &mut active).unwrap();

        assert_eq!(active, 1);
        assert!(progress.iter().all(|progress| progress.is_complete()));
        assert_eq!(raw.report().unwrap().0, positions[2].1);
    }

    #[test]
    fn an_equal_width_substituted_cache_release_retains_the_native_suffix_refusal() {
        let (expected, positions) = recipes();
        let mut actual = expected.clone();
        actual[1] = JournalTransaction::new([99; 16], actual[1].records().to_vec()).unwrap();
        let file = super::signed_native_chain_tests::file_for(&actual);
        assert_eq!(file.metadata().unwrap().len(), positions[2].1);
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut progress = std::array::from_fn(|_| HistoryPairNativeSuffixProgressV1::new());
        let mut active = 0;

        assert!(drive(&file, &mut raw, &expected, positions, &mut progress, &mut active).is_err());

        assert!(progress[0].is_complete());
        assert_eq!(progress[1].failure(), Some(&HistoryPairSuffixErrorV1::Transaction));
        assert!(raw.report().is_none());
    }
}
