//! Checks the strict logical Recover slot using genuine signed native fixtures.
//!
//! These temporary test roots use the existing unscoped test floor. They prove
//! key/profile/history behavior, not installed Required-floor qualification.

use super::*;

#[test]
fn signed_recover_inventory_roundtrip_rejects_ordinary_and_cross_role_keys() {
    let mut fixture = LifecycleTerminalFixture::storage_recover_client();
    let stored = fixture.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap().unwrap();
    let key = canonical_operator_recover_inventory_key_v1();
    let encoded = stored.encode().unwrap();
    assert_eq!(StoredProtocolHistoryV1::decode(&key, &encoded).unwrap(), stored);
    assert!(StoredProtocolHistoryV1::decode(&protocol_key(BrokerSessionProtocolV1::Storage), &encoded).is_err());
    let mut cross_role = key;
    cross_role[8] = protocol_code(BrokerSessionProtocolV1::Host);
    assert!(StoredProtocolHistoryV1::decode(&cross_role, &encoded).is_err());
    let mut missing_checkpoint = stored;
    missing_checkpoint.checkpoint = None;
    assert!(missing_checkpoint.encode().is_err());
}

#[test]
fn recover_slot_preserves_uncertain_ordinary_prefix_and_validates_both_rows() {
    let mut ordinary = LifecycleTerminalFixture::storage_client();
    let mut recovered = LifecycleTerminalFixture::storage_recover_client();
    let mut old = ordinary.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap().unwrap();
    let complete = old.history_model().unwrap();
    let pending = BrokerSessionDurableHistoryV1::from_records(vec![complete.records()[0].clone()]).unwrap();
    old.history = pending.encode().unwrap();
    old.current_head = pending.head_commitment();
    let old_key = protocol_key(BrokerSessionProtocolV1::Storage);
    let old_bytes = old.encode().unwrap();
    let recover = recovered.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap().unwrap();
    assert_eq!(old.stable_endpoint_identity, recover.stable_endpoint_identity);
    let recover_key = canonical_operator_recover_inventory_key_v1();
    let recover_bytes = recover.encode().unwrap();
    let transaction = JournalTransaction::new([91; 16], vec![
        JournalRecord::put(RecordNamespace::BrokerSessionTraffic, old_key.clone(), old_bytes.clone()),
        JournalRecord::put(RecordNamespace::BrokerSessionTraffic, recover_key.clone(), recover_bytes.clone()),
    ]).unwrap();
    ordinary.journal.journal_mut().unwrap().commit(&transaction).unwrap();
    ordinary.journal.purpose = SessionPurpose::OperatorRecoverInventory;
    assert_eq!(ordinary.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap(), Some(recover));
    assert_eq!(ordinary.journal.journal_mut().unwrap().get(RecordNamespace::BrokerSessionTraffic, &old_key), Some(old_bytes.as_slice()));
    ordinary.journal.purpose = SessionPurpose::Ordinary;
    let unchanged = ordinary.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap().unwrap();
    assert_ne!(unchanged.history_model().unwrap().head().unwrap().phase(), BrokerSessionDurablePhaseV1::Terminal);
    assert_eq!(unchanged.encode().unwrap(), old_bytes);
    assert_eq!(ordinary.journal.journal_mut().unwrap().get(RecordNamespace::BrokerSessionTraffic, &recover_key), Some(recover_bytes.as_slice()));
}
