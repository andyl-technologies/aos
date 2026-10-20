//! Refuses DATA-only creation, replacement or deletion of Source A8 settlement.
//!
//! Forecast and append share this finite denial in the existing common engine.
//! Only the genuine Source22 loan can select its exact prechecked transaction;
//! canonical checksums, registered names and signed historical DATA cannot.

use super::*;

pub(super) fn require_append_scope_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    cache_gate: &CacheMutationGateV1<'_>,
) -> Result<(), JournalError> {
    if let CacheMutationGateV1::StopCleanupSource(original) = cache_gate {
        return original.require_prechecked_transaction_v1(transaction);
    }
    require_no_generic_settlement_v1(state, transaction)
}

fn require_no_generic_settlement_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_generic_settlement_v1(state, transaction)
        .map_err(JournalError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
        LIFECYCLE_PROTECTED_DOMAIN_V1, LIFECYCLE_PROTECTED_KEY_PREFIX_V1,
        LifecycleAuxiliaryEnvelopeFormatV1, borrow_lifecycle_auxiliary_member_data_v1,
    };
    use aos_sandbox_model::{ObjectDigest, OperationId};
    use aos_sandbox_protocol::domain_ledger::stop_completion::{
        LifecycleStopCompletionBindingDataV1, LifecycleStopCompletionDataV1,
        LifecycleStopCompletionEvidenceDataV1,
    };
    use aos_sandbox_protocol::{
        host_inventory_absence::HostInventoryAbsenceDataV5,
        host_recovered_namespace::{HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7},
        host_stopped_namespace::HostStoppedNamespaceDataV4,
        root_policy_completion::{StopCleanupObservationDataV1,
            stop_cleanup_observation_decision_digest_v1, stop_cleanup_positive_completion_bytes_v1},
    };

    fn payload() -> Vec<u8> {
        // Core uses the public canonical DATA decoder; the validated fence's
        // private representation remains owned by Protocol.
        let runtime = aos_sandbox_protocol::semantics::host::runtime_handle_v1(&[3; 16], 4, &[6; 32]);
        let mut scope = Vec::new();
        for part in [b"AOSHNS04".as_slice(), &[1; 16], &[2; 16], &[3; 16],
            &4_u64.to_le_bytes(), &5_u64.to_le_bytes(), &[6; 32], &[7; 32], &runtime,
            &[8; 16], &[9; 32], &[10; 32], &[11; 16], &[12; 32], &[13; 32]] {
            scope.extend_from_slice(part);
        }
        let historical = HostStoppedNamespaceDataV4::decode_v4(&scope).unwrap();
        let observation = HostInventoryAbsenceDataV5::from_data_v5(
            [14; 16], [15; 16], [16; 16], 17, 18).unwrap();
        let row = HostRecoveredNamespaceDataV7::from_data_v7(
            historical, observation, HostRecoveryStopPhaseDataV7::Complete);
        let decision = stop_cleanup_observation_decision_digest_v1(
            StopCleanupObservationDataV1::Historical(row)).unwrap();
        let data = LifecycleStopCompletionDataV1::from_data_v1(
            LifecycleStopCompletionBindingDataV1 {
                operation: OperationId::from_bytes([19; 16]),
                operation_record: ObjectDigest::from_bytes([20; 32]),
                dispatch_record: ObjectDigest::from_bytes([21; 32]),
                recovery: OperationId::from_bytes([22; 16]),
                recovery_request: ObjectDigest::from_bytes([23; 32]),
                source_root: ObjectDigest::from_bytes([24; 32]), cleanup_request: [25; 16],
                query: ([14; 16], [26; 32], [27; 32]), outcome: [28; 32], body: [29; 32],
                root_query: [30; 32], root_decision: decision,
                root_completion: stop_cleanup_positive_completion_bytes_v1([30; 32], decision, [28; 32]),
            }, LifecycleStopCompletionEvidenceDataV1::ObservedComplete(row)).unwrap();
        let bytes = data.encode().unwrap();
        assert_eq!(LifecycleStopCompletionDataV1::from_bytes(&bytes).unwrap(), data);
        bytes
    }

    // Builds only passive canonical framing for a guard test. The fixture
    // deliberately has no protected/native writer, Source22 or physical proof.
    fn framed(format: LifecycleAuxiliaryEnvelopeFormatV1, kind: u8) -> (Vec<u8>, Vec<u8>) {
        let mut key = LIFECYCLE_PROTECTED_KEY_PREFIX_V1.to_vec();
        key.extend_from_slice(&[1, 5]);
        key.extend_from_slice(&48_u16.to_be_bytes());
        key.extend_from_slice(&[31; 16]);
        key.extend_from_slice(&[32; 16]);
        key.extend_from_slice(&[19; 16]);

        let payload = payload();
        let mut auxiliary = vec![0; 244];
        auxiliary[..8].copy_from_slice(format.magic());
        auxiliary[8..10].copy_from_slice(&format.version().to_be_bytes());
        auxiliary[10] = kind;
        auxiliary[16..32].copy_from_slice(&[31; 16]);
        auxiliary[32..48].copy_from_slice(&[19; 16]);
        auxiliary[48..56].copy_from_slice(&10_u64.to_be_bytes());
        auxiliary[56..88].copy_from_slice(&[20; 32]);
        auxiliary[88..104].copy_from_slice(&[32; 16]);
        auxiliary[104..112].copy_from_slice(&1_u64.to_be_bytes());
        auxiliary[144..160].copy_from_slice(&[33; 16]);
        auxiliary[168..200].copy_from_slice(&[34; 32]);
        auxiliary[200..202].copy_from_slice(&(if kind == 7 { 0x81_u16 } else { 0x101_u16 }).to_be_bytes());
        auxiliary[202..204].copy_from_slice(&2_u16.to_be_bytes());
        auxiliary[208..240].copy_from_slice(&[35; 32]);
        auxiliary[240..244].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        auxiliary.extend_from_slice(&payload);
        let digest = Sha256::new().chain_update(format.digest_domain()).chain_update(&auxiliary).finalize();
        auxiliary.extend_from_slice(&digest);

        let mut reducer = b"AOSRDP01".to_vec();
        reducer.extend_from_slice(&[0, 1, 5, 5, 2, 0, 0, 0]);
        reducer.extend_from_slice(&(auxiliary.len() as u32).to_be_bytes());
        reducer.extend_from_slice(&auxiliary);
        let digest = Sha256::new().chain_update(LIFECYCLE_PROTECTED_DOMAIN_V1)
            .chain_update(b"reducer-payload\0").chain_update(&reducer).finalize();
        reducer.extend_from_slice(&digest);

        let mut envelope = b"AOSLPJ01".to_vec();
        envelope.extend_from_slice(&[0, 1, 5, 0]);
        envelope.extend_from_slice(&1_u64.to_be_bytes());
        envelope.extend_from_slice(&[0; 32]);
        envelope.extend_from_slice(&(reducer.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&reducer);
        let digest = Sha256::new().chain_update(LIFECYCLE_PROTECTED_DOMAIN_V1)
            .chain_update(b"envelope\0").chain_update((key.len() as u32).to_be_bytes())
            .chain_update(&key).chain_update(1_u64.to_be_bytes()).chain_update([0; 32])
            .chain_update((reducer.len() as u64).to_be_bytes()).chain_update(&reducer).finalize();
        envelope.extend_from_slice(&digest);

        let mut member = b"AOSDTX01".to_vec();
        member.extend_from_slice(&[0, 1, 0, 0]);
        member.extend_from_slice(&[36; 16]);
        member.extend_from_slice(&0_u16.to_be_bytes());
        member.extend_from_slice(&2_u16.to_be_bytes());
        member.extend_from_slice(&[37; 32]);
        member.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        member.extend_from_slice(&envelope);
        let digest = Sha256::new().chain_update(LIFECYCLE_PROTECTED_DOMAIN_V1)
            .chain_update(b"durable-member\0").chain_update(&member).finalize();
        member.extend_from_slice(&digest);
        let frame = borrow_lifecycle_auxiliary_member_data_v1(&key, &member, &[36; 16]).unwrap();
        assert_eq!(frame.format, format);
        assert_eq!(frame.kind, kind);
        (key, member)
    }

    #[test]
    fn canonical_a8_data_cannot_enter_an_ordinary_append_or_forecast() {
        let (key, value) = framed(LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion, 8);
        let transaction = JournalTransaction::new([38; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, key, value)]).unwrap();

        assert!(matches!(require_append_scope_v1(&BTreeMap::new(), &transaction,
            &CacheMutationGateV1::Ordinary), Err(JournalError::ProtectedBoundary)));
    }

    #[test]
    fn ordinary_replacement_and_deletion_cannot_erase_either_a8_member() {
        for kind in [0, 8] {
            let (key, value) = framed(LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion, kind);
            let state = BTreeMap::from([((RecordNamespace::DesiredState, key.clone()), value)]);
            for row in [JournalRecord::delete(RecordNamespace::DesiredState, key.clone()),
                JournalRecord::put(RecordNamespace::DesiredState, key.clone(), b"replacement".to_vec())] {
                let transaction = JournalTransaction::new([38; 16], vec![row]).unwrap();
                assert!(matches!(require_no_generic_settlement_v1(&state, &transaction),
                    Err(JournalError::ProtectedBoundary)));
            }
        }
    }

    #[test]
    fn old_a7_framing_does_not_acquire_an_a8_exception_or_global_denial() {
        let (key, value) = framed(LifecycleAuxiliaryEnvelopeFormatV1::StopDispatch, 7);
        let transaction = JournalTransaction::new([38; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, key, value)]).unwrap();

        assert!(require_no_generic_settlement_v1(&BTreeMap::new(), &transaction).is_ok());
    }
}
