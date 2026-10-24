//! Conserves the original exact-lane history comparison assertions.

    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1};
    use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1;
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

    #[test]
    fn current_lane_history_requires_every_exact_member_and_rejects_an_extra_step() {
        // Opaque map-equality DATA only. The production caller first completes
        // actual canonical/role replay, original R gates and the exact suffix.
        let lane = [7; 16];
        let record = [8; 412];
        let receipt = InputsReadyNativeReceiptDataV1 {
            record: &record, latest_head: [9; 40],
            names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
            after_next: 10, after_end: 11,
        };
        let key = |revision| (RecordNamespace::CreateStorageHistory,
            KeyV1::new(lane, OwnerV1::Controller, revision).unwrap().encode().to_vec());
        let mut state = State::from([
            (key(1), b"intent".to_vec()),
            (key(2), b"planned".to_vec()),
            (key(3), record.to_vec()),
            (key(0), receipt.latest_head.to_vec()),
        ]);

        assert!(require_bundle_history_data_v1(&state, lane, b"intent", b"planned", receipt).is_ok());
        assert!(require_bundle_history_data_v1(&state, lane, b"substituted", b"planned", receipt).is_err());
        state.insert(key(4), b"unobserved later phase".to_vec());
        assert!(require_bundle_history_data_v1(&state, lane, b"intent", b"planned", receipt).is_err());
        state.remove(&key(4));
        state.remove(&key(2));
        assert!(require_bundle_history_data_v1(&state, lane, b"intent", b"planned", receipt).is_err());
    }
