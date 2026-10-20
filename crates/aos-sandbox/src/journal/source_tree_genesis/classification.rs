//! Selects the original native refusal type for canonical key classification.

use super::*;
pub(super) use aos_sandbox_ledger_replay::replay::source_tree_genesis::classification::HierarchyKeyCaptureV1;
pub(super) type SourceGenesisProtectedRecordScanOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_genesis::classification::SourceGenesisProtectedRecordScanOriginalsV1<JournalError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> SourceGenesisRowsV1 {
        SourceGenesisRowsV1 { receipts: BTreeMap::new(), acks: BTreeMap::new(), pending: None }
    }

    fn malformed_key() -> Vec<u8> {
        let key = HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, vec![1; 48]).unwrap();
        let mut bytes = key.as_bytes().to_vec();
        *bytes.last_mut().unwrap() = 0;
        bytes
    }

    #[test]
    fn ignored_identity_failure_stays_false_and_retains_the_actual_error() {
        let records = vec![JournalRecord::put(RecordNamespace::DesiredState, malformed_key(), vec![1])];
        let rows = rows();
        assert!(!records.iter().any(|record| protected_record(record, &rows)));
        let mut original = SourceGenesisProtectedRecordScanOriginalsV1::new();

        assert!(!original.observe_once(&records, &rows).unwrap());
        assert_eq!(original.keys.len(), 1);
        assert!(original.keys[0].failure().is_some());
        assert!(original.cause().is_none());
        assert!(original.current.is_none());
    }

    #[test]
    fn ignored_key_error_does_not_mask_later_protected_record_refusal() {
        let records = vec![
            JournalRecord::put(RecordNamespace::DesiredState, malformed_key(), vec![1]),
            JournalRecord::put(RecordNamespace::DesiredState, PENDING_KEY.to_vec(), vec![0]),
            JournalRecord::put(RecordNamespace::DesiredState, malformed_key(), vec![2]),
        ];
        let transaction = JournalTransaction::new([17; 16], records).unwrap();
        let mut original = SourceGenesisMutationOriginalsV1::new();
        assert!(require_no_mutation(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::None).is_err());

        assert!(original.observe_once(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::None).is_err());
        assert_eq!(original.classification.keys.len(), 1);
        assert!(original.classification.keys[0].failure().is_some());
        assert!(matches!(original.classification.result, Some(Ok(true))));
        assert!(original.classification.cause().is_none());
        assert!(original.cause().is_some());
    }

    #[test]
    fn pending_short_circuit_does_not_enter_classifier_or_allocate() {
        let receipt = super::super::genesis_receipt_data_for_test(b"tree", b"lineage");
        let pending = SourceGenesisPendingV1 {
            instance: receipt.instance(), project: receipt.project(), intent: receipt.intent_digest(),
            receipt: receipt.digest(), nonce: [14; 16],
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
        };
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::DesiredState, receipt_key(receipt.project())), receipt.as_bytes().to_vec());
        state.insert((RecordNamespace::DesiredState, PENDING_KEY.to_vec()), pending.encode().to_vec());
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, malformed_key(), vec![1]),
        ]).unwrap();
        let mut original = SourceGenesisMutationOriginalsV1::new();

        assert!(original.observe_once(&state, &transaction, SourceGenesisTransitionV1::None).is_err());
        assert!(!original.classification.entered);
        assert!(original.classification.allocation.is_none());
        assert!(original.classification.keys.is_empty());
    }

    #[test]
    fn successful_false_scan_cannot_reenter_or_replace_its_key_prefix() {
        let records = vec![JournalRecord::put(RecordNamespace::DesiredState, malformed_key(), vec![1])];
        let mut original = SourceGenesisProtectedRecordScanOriginalsV1::new();
        assert!(!original.observe_once(&records, &rows()).unwrap());
        let cause = original.keys[0].failure().unwrap() as *const _;

        assert!(original.observe_once(&[], &rows()).is_err());
        assert_eq!(original.keys[0].failure().unwrap() as *const _, cause);
        assert!(original.cause().is_some());
        assert!(SourceGenesisProtectedRecordScanOriginalsV1::fixed_footprint_v1().is_some());
        assert!(SourceGenesisProtectedRecordScanOriginalsV1::backing_footprint_v1(usize::MAX).is_none());
    }
}
