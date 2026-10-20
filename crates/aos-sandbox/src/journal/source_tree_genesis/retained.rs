//! Joins pure Source row work to the existing Native mutation boundary.

use super::*;

pub(crate) type SourceGenesisRowsOriginalsV1 =
    aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisRowsOriginalsV1<JournalError, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>;

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(project: ProjectId) -> SourceGenesisAckV1 {
        SourceGenesisAckV1 {
            instance: [1; 32],
            project,
            receipt: ObjectDigest::from_bytes([3; 32]),
            root_floor: ObjectDigest::from_bytes([4; 32]),
            controller_floor: ObjectDigest::from_bytes([5; 32]),
        }
    }

    #[test]
    fn orphan_ack_keeps_the_reached_actual_map_and_first_error() {
        let project = ProjectId::from_bytes([2; 16]);
        let original = ack(project);
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::DesiredState, ack_key(project)), original.encode().to_vec());
        assert!(current_rows(&state).is_err());

        let mut retained = SourceGenesisRowsOriginalsV1::new();
        assert!(retained.observe_once(&state).is_err());
        assert_eq!(retained.acks.as_ref().unwrap().get(&project), Some(&original));
        assert!(retained.receipts.as_ref().unwrap().is_empty());
        assert!(matches!(retained.pending, Some(None)));
        let cause = retained.failure().unwrap() as *const JournalError;

        assert!(retained.observe_once(&BTreeMap::new()).is_err());
        assert_eq!(retained.failure().unwrap() as *const JournalError, cause);
        assert_eq!(retained.acks.as_ref().unwrap().get(&project), Some(&original));
    }

    #[test]
    fn mismatched_key_keeps_the_decoded_ack_before_map_insertion() {
        let project = ProjectId::from_bytes([2; 16]);
        let original = ack(project);
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::DesiredState, ack_key(ProjectId::from_bytes([9; 16]))),
            original.encode().to_vec());
        let mut retained = SourceGenesisRowsOriginalsV1::new();

        assert!(retained.observe_once(&state).is_err());
        assert_eq!(retained.current_ack.as_ref(), Some(&original));
        assert!(retained.acks.as_ref().unwrap().is_empty());
        assert!(retained.rows().is_none());
    }

    #[test]
    fn complete_empty_rows_move_once_and_reentry_closes_borrowing() {
        let mut retained = SourceGenesisRowsOriginalsV1::new();
        retained.observe_once(&BTreeMap::new()).unwrap();
        let rows = retained.take_rows_once().unwrap();

        assert!(rows.receipts.is_empty());
        assert!(rows.acks.is_empty());
        assert!(rows.pending.is_none());
        assert!(retained.take_rows_once().is_err());
        assert!(retained.rows().is_none());
        assert!(SourceGenesisRowsOriginalsV1::fixed_footprint_v1().is_some());
    }
}


// Selects the exact actual native error owners at the existing COMMIT boundary.
pub(in crate::journal) type SourceGenesisMutationOriginalsV1 =
    aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>;

#[cfg(test)]
pub(in crate::journal) mod mutation_tests {
    use super::*;
    use aos_sandbox_protocol::controller_source_seed::{ControllerSourceTreeSeedV1, sign_controller_source_tree_seed_v1};
    use aos_sandbox_core::source_tree_model::TreeLimitsV1;
    use ed25519_dalek::{Signer as _, SigningKey};

    // Only canonical immutable test DATA is constructed here. No Journal,
    // native original, administrative acceptance or receiving loan is created.
    pub(in crate::journal) fn receipt(tree: &[u8], lineage: &[u8]) -> SourceTreeGenesisReceiptV1 {
        let project = ProjectId::from_bytes([1; 16]);
        let limits = TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap();
        let seed = sign_controller_source_tree_seed_v1(
            ControllerSourceTreeSeedV1::new(project, limits, 5,
                ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]), [4; 16], 9).unwrap(),
            7, &SigningKey::from_bytes(&[41; 32]),
        ).unwrap();
        let mut authorization = [0; 224];
        authorization[..8].copy_from_slice(b"AOSPSC02");
        authorization[8..10].copy_from_slice(&2_u16.to_be_bytes());
        authorization[12..20].copy_from_slice(&8_u64.to_be_bytes());
        authorization[20..36].copy_from_slice(project.as_bytes());
        authorization[36..44].copy_from_slice(&5_u64.to_be_bytes());
        authorization[44..76].copy_from_slice(&[2; 32]);
        authorization[76..108].copy_from_slice(&[6; 32]);
        authorization[108..124].copy_from_slice(&[4; 16]);
        authorization[124..132].copy_from_slice(&9_u64.to_be_bytes());
        for (index, limit) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
            authorization[132 + index * 4..136 + index * 4].copy_from_slice(&limit.to_be_bytes());
        }
        let mut signed = b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0".to_vec();
        signed.extend_from_slice(&authorization[..160]);
        authorization[160..].copy_from_slice(&SigningKey::from_bytes(&[42; 32]).sign(&signed).to_bytes());

        let mut bytes = vec![0; 672];
        bytes[..8].copy_from_slice(b"AOSSGR01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(&[9; 32]);
        bytes[48..80].copy_from_slice(&[10; 32]);
        bytes[80..112].copy_from_slice(&[11; 32]);
        bytes[112..128].copy_from_slice(project.as_bytes());
        bytes[128..352].copy_from_slice(&seed);
        bytes[352..576].copy_from_slice(&authorization);
        bytes[576..608].copy_from_slice(&[12; 32]);
        bytes[608..640].copy_from_slice(&[13; 32]);
        let mut hash = Sha256::new().chain_update(b"aos.sandbox.source-tree-genesis.materialization.v1\0");
        for part in [tree, lineage, &bytes[..640]] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        bytes[640..].copy_from_slice(&hash.finalize());
        let receipt = SourceTreeGenesisReceiptV1::decode(&bytes).unwrap();
        assert!(receipt.matches_members(tree, lineage));
        receipt
    }

    fn pending(receipt: &SourceTreeGenesisReceiptV1) -> SourceGenesisPendingV1 {
        SourceGenesisPendingV1 {
            instance: receipt.instance(), project: receipt.project(), intent: receipt.intent_digest(),
            receipt: receipt.digest(), nonce: [14; 16],
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
        }
    }

    fn append(receipt: &SourceTreeGenesisReceiptV1, pending: Vec<u8>, tree_key: Vec<u8>) -> JournalTransaction {
        JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, tree_key, b"tree".to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, b"lineage".to_vec(), b"lineage".to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, receipt_key(receipt.project()), receipt.as_bytes().to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, PENDING_KEY.to_vec(), pending),
        ]).unwrap()
    }

    #[test]
    fn actual_append_keeps_decoded_receipt_before_bad_pending_and_reentry() {
        let receipt = receipt(b"tree", b"lineage");
        let transaction = append(&receipt, vec![0], b"tree".to_vec());
        let state = BTreeMap::new();
        assert!(require_no_mutation(&state, &transaction, SourceGenesisTransitionV1::Append).is_err());
        let mut originals = SourceGenesisMutationOriginalsV1::new();

        assert!(originals.observe_once(&state, &transaction, SourceGenesisTransitionV1::Append).is_err());
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
        assert!(originals.pending.is_none());
        assert!(originals.rows.as_ref().unwrap().receipts.is_empty());
        let cause = originals.cause().unwrap() as *const dyn std::error::Error;

        assert!(originals.observe_once(&state, &transaction, SourceGenesisTransitionV1::None).is_err());
        assert!(std::ptr::addr_eq(originals.cause().unwrap(), cause));
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
    }

    #[test]
    fn actual_required_key_failure_keeps_key_prefix_and_prior_receipt_pending() {
        let receipt = receipt(b"tree", b"lineage");
        let pending = pending(&receipt);
        let key = HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, vec![1; 48]).unwrap();
        let mut malformed = key.as_bytes().to_vec();
        *malformed.last_mut().unwrap() = 0;
        let transaction = append(&receipt, pending.encode().to_vec(), malformed);
        let mut originals = SourceGenesisMutationOriginalsV1::new();

        assert!(require_no_mutation(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::Append).is_err());
        assert!(originals.observe_once(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::Append).is_err());
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
        assert_eq!(originals.pending.as_ref(), Some(&pending));
        let key = originals.key.as_ref().unwrap();
        assert!(key.failure().is_some());
        assert!(std::ptr::addr_eq(originals.cause().unwrap(), key.failure().unwrap() as &dyn std::error::Error));
    }

    #[test]
    fn actual_anchor_failure_keeps_moved_pending_and_remaining_rows() {
        let receipt = receipt(b"tree", b"lineage");
        let pending = pending(&receipt);
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::DesiredState, receipt_key(receipt.project())), receipt.as_bytes().to_vec());
        state.insert((RecordNamespace::DesiredState, PENDING_KEY.to_vec()), pending.encode().to_vec());
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, ack_key(receipt.project()), vec![0]),
        ]).unwrap();
        let mut originals = SourceGenesisMutationOriginalsV1::new();

        assert!(require_no_mutation(&state, &transaction, SourceGenesisTransitionV1::Anchor).is_err());
        assert!(originals.observe_once(&state, &transaction, SourceGenesisTransitionV1::Anchor).is_err());
        assert_eq!(originals.pending.as_ref(), Some(&pending));
        let rows = originals.rows.as_ref().unwrap();
        assert!(rows.pending.is_none());
        assert_eq!(rows.receipts.get(&receipt.project()), Some(&receipt));
        assert!(originals.ack.is_none());
    }

    #[test]
    fn empty_mutation_matches_ordinary_and_actual_row_demand_has_no_fd() {
        use aos_sandbox_core::ResourceDimension as D;
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"ordinary".to_vec(), vec![1]),
        ]).unwrap();
        let mut originals = SourceGenesisMutationOriginalsV1::new();
        require_no_mutation(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::None).unwrap();
        originals.observe_once(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::None).unwrap();
        assert!(originals.cause().is_none());
        let small = SourceGenesisMutationOriginalsV1::dynamic_demand_v1(&BTreeMap::new(), Some(&transaction)).unwrap();
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::DesiredState, receipt_key(ProjectId::from_bytes([1; 16]))), vec![2; 9]);
        let larger = SourceGenesisMutationOriginalsV1::dynamic_demand_v1(&state, Some(&transaction)).unwrap();
        assert!(larger.get(D::MemoryBytes) > small.get(D::MemoryBytes));
        assert!(larger.get(D::MetadataEntries) > small.get(D::MetadataEntries));
        assert_eq!(larger.get(D::OpenFiles), 0);
        assert!(SourceGenesisMutationOriginalsV1::fixed_footprint_v1().is_some());
    }
}

#[cfg(test)]
mod primitive_receipt_tests {
    use super::*;

    fn original() -> SourceTreeGenesisReceiptV1 { super::mutation_tests::receipt(b"tree", b"lineage") }

    #[test]
    fn actual_rows_keep_returned_receipt_error_before_malformed_claims() {
        let original = original();
        let mut bytes = original.encode();
        bytes[352 + 108..352 + 124].fill(0);
        let state = BTreeMap::from([((RecordNamespace::DesiredState, receipt_key(original.project())), bytes)]);
        assert!(current_rows(&state).is_err());
        let mut capture = SourceGenesisRowsOriginalsV1::new();
        assert!(capture.observe_once(&state).is_err());
        let decoder = capture.receipt_decode.as_ref().unwrap();
        assert!(decoder.failure().is_some());
        assert!(capture.receipts.as_ref().unwrap().is_empty());
        assert!(capture.cause().unwrap().downcast_ref::<crate::hierarchy::genesis_profile::SourceGenesisErrorV1>().is_some());
        let cause = capture.cause().unwrap() as *const dyn std::error::Error;
        assert!(capture.observe_once(&BTreeMap::new()).is_err());
        assert!(std::ptr::addr_eq(capture.cause().unwrap(), cause));
    }

    #[test]
    fn actual_rows_keep_returned_receipt_error_before_cross_join_refusal() {
        let original = original();
        let mut bytes = original.encode();
        bytes[352 + 20..352 + 36].fill(8);
        let state = BTreeMap::from([((RecordNamespace::DesiredState, receipt_key(original.project())), bytes)]);
        let mut capture = SourceGenesisRowsOriginalsV1::new();
        assert!(capture.observe_once(&state).is_err());
        let decoder = capture.receipt_decode.as_ref().unwrap();
        assert!(decoder.failure().is_some());
        assert!(capture.current_receipt.is_none());
        assert!(capture.cause().is_some());
    }

    #[test]
    fn completed_row_codec_disposes_only_after_identity_and_actual_map_transfer() {
        let original = original();
        let state = BTreeMap::from([((RecordNamespace::DesiredState, receipt_key(original.project())), original.encode())]);
        let mut capture = SourceGenesisRowsOriginalsV1::new();
        // The later missing-ACK family check fails after this pure codec leaf.
        assert!(capture.observe_once(&state).is_err());
        assert!(capture.receipt_decode.is_none());
        assert_eq!(capture.receipts.as_ref().unwrap().get(&original.project()), Some(&original));
        assert!(SourceGenesisRowsOriginalsV1::fixed_footprint_v1().is_some());
    }

    #[test]
    fn actual_append_keeps_returned_receipt_error_before_bad_authorization() {
        let original = original();
        let mut bytes = original.encode();
        bytes[352 + 108..352 + 124].fill(0);
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"tree".to_vec(), b"tree".to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, b"lineage".to_vec(), b"lineage".to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, receipt_key(original.project()), bytes),
            JournalRecord::put(RecordNamespace::DesiredState, PENDING_KEY.to_vec(), vec![0]),
        ]).unwrap();
        let mut capture = SourceGenesisMutationOriginalsV1::new();
        assert!(capture.observe_once(&BTreeMap::new(), &transaction, SourceGenesisTransitionV1::Append).is_err());
        let decoder = capture.receipt_decode.as_ref().unwrap();
        assert!(decoder.failure().is_some());
        assert!(capture.receipt.is_none());
        assert!(capture.pending.is_none());
        assert!(capture.cause().unwrap().downcast_ref::<crate::hierarchy::genesis_profile::SourceGenesisErrorV1>().is_some());
    }
}

#[cfg(test)]
mod consuming_fixed_row_tests {
    use super::*;

    fn pending() -> SourceGenesisPendingV1 {
        SourceGenesisPendingV1 {
            instance: [1; 32], project: ProjectId::from_bytes([2; 16]),
            intent: ObjectDigest::from_bytes([3; 32]), receipt: ObjectDigest::from_bytes([4; 32]),
            nonce: [5; 16], names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
        }
    }

    #[test]
    fn late_pending_refusal_keeps_input_and_first_actual_returned_error() {
        let mut pending = pending();
        pending.nonce = [0; 16];
        let bytes = pending.encode();
        assert!(matches!(SourceGenesisPendingV1::decode(&bytes).map_err(JournalError::from), Err(JournalError::ProtectedBoundary)));
        let state = BTreeMap::from([((RecordNamespace::DesiredState, PENDING_KEY.to_vec()), bytes.to_vec())]);
        let input = state.clone();
        let mut original = SourceGenesisRowsOriginalsV1::new();

        assert!(original.observe_once(&state).is_err());
        assert!(matches!(original.result, Some(Err(JournalError::ProtectedBoundary))));
        assert_eq!(state, input);
        assert!(original.rows().is_none());
        let cause = original.failure().unwrap() as *const JournalError;

        assert!(original.observe_once(&BTreeMap::new()).is_err());
        assert_eq!(original.failure().unwrap() as *const JournalError, cause);
    }

    #[test]
    fn consuming_names_and_ack_checks_preserve_the_original_semantic_refusals() {
        let mut pending = pending();
        pending.names = ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 0));
        assert!(matches!(SourceGenesisPendingV1::decode(&pending.encode()).map_err(JournalError::from), Err(JournalError::ProtectedBoundary)));
        let ack = SourceGenesisAckV1 {
            instance: [1; 32], project: pending.project,
            receipt: ObjectDigest::from_bytes([3; 32]), root_floor: ObjectDigest::from_bytes([0; 32]),
            controller_floor: ObjectDigest::from_bytes([4; 32]),
        };
        let state = BTreeMap::from([((RecordNamespace::DesiredState, ack_key(ack.project)), ack.encode().to_vec())]);
        let mut original = SourceGenesisRowsOriginalsV1::new();

        assert!(original.observe_once(&state).is_err());
        assert!(original.acks.as_ref().unwrap().is_empty());
        assert!(matches!(original.result, Some(Err(JournalError::ProtectedBoundary))));
        assert!(fixed_row_decode_peak_bytes_v1().is_some());
    }

    #[test]
    fn consuming_fixed_rows_roundtrip_without_creating_a_native_grant() {
        let pending = pending();
        assert_eq!(SourceGenesisPendingV1::decode(&pending.encode()).map_err(JournalError::from).unwrap(), pending);
        let ack = SourceGenesisAckV1 {
            instance: [1; 32], project: pending.project,
            receipt: ObjectDigest::from_bytes([3; 32]), root_floor: ObjectDigest::from_bytes([4; 32]),
            controller_floor: ObjectDigest::from_bytes([5; 32]),
        };
        assert_eq!(SourceGenesisAckV1::decode(&ack.encode()).unwrap(), ack);
        assert!(SourceGenesisRowsOriginalsV1::fixed_footprint_v1().is_some());
        assert!(SourceGenesisMutationOriginalsV1::fixed_footprint_v1().is_some());
    }
}
