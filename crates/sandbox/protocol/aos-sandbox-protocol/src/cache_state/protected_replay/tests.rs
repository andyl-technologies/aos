//! Canonical historical family and complete transaction-group regressions.

use super::*;
use crate::domain_ledger::records::{encode_reducer_payload_with_validator,
    encode_durable_member, replay_projection_records, domain_transaction_set_digest};

type Schema = CacheResidencyHistoricalSchemaDataV1;

fn observation() -> ProtectedDomainEnvelopeV1<Schema> {
    let observed = CacheEffectObservationDataV1 {
        transaction_id: [1; 16], transaction_digest: ObjectDigest::from_bytes([2; 32]),
        evidence: ObjectDigest::from_bytes([3; 32]), partition: ObjectDigest::from_bytes([4; 32]),
    };
    let limits = CacheRecoveryLimitsV1::default();
    let key = ProtectedDomainKeyV1::<Schema>::new(
        CacheResidencyProtectedRecordKindV1::EffectObservation, observed.transaction_id.to_vec(),
    ).expect("observation key");
    let body = encode_cache_effect_observation(observed);
    let payload = encode_reducer_payload_with_validator::<Schema>(&key, &body, &limits)
        .expect("canonical observation reducer");
    ProtectedDomainEnvelopeV1::new_with_validator(key, 1, None, payload, &limits)
        .expect("canonical observation envelope")
}

#[test]
fn historical_registry_preserves_all_closed_namespaces_and_unknown_refusal() {
    let expected = [RecordNamespace::DesiredState, RecordNamespace::DesiredState,
        RecordNamespace::DesiredState, RecordNamespace::DesiredState,
        RecordNamespace::DesiredState, RecordNamespace::DesiredState,
        RecordNamespace::DesiredState, RecordNamespace::DesiredState,
        RecordNamespace::DesiredState, RecordNamespace::Effect,
        RecordNamespace::AuthorityPublication, RecordNamespace::RuntimeGeneration,
        RecordNamespace::DesiredState];
    for (offset, namespace) in expected.into_iter().enumerate() {
        let code = (offset + 1) as u8;
        let kind = Schema::kind_from_code(code).expect("closed family");
        assert_eq!(Schema::kind_code(kind), code);
        assert_eq!(Schema::namespace(kind), namespace);
    }
    assert!(Schema::kind_from_code(0).is_none());
    assert!(Schema::kind_from_code(14).is_none());
    assert!(Schema::kind_from_code(255).is_none());
}

#[test]
fn recovery_group_rejects_changed_revision_and_missing_original_transaction() {
    let limits = CacheRecoveryLimitsV1::default();
    let envelope = observation();
    validate_cache_transition(CacheResidencyTransactionKindV1::Recovery,
        std::slice::from_ref(&envelope), &limits, limits).expect("exact recovery shape");
    let changed = ProtectedDomainEnvelopeV1::new_with_validator(
        envelope.key().clone(), 2, Some(envelope.digest()), envelope.payload().to_vec(), &limits,
    ).expect("well-framed but invalid recovery revision");
    assert!(matches!(validate_cache_transition(CacheResidencyTransactionKindV1::Recovery,
        &[changed], &limits, limits), Err(DomainLedgerDataError::NonCanonicalRecord)));

    let set = domain_transaction_set_digest([9; 16], std::slice::from_ref(&envelope));
    let member = encode_durable_member([9; 16], 0, 1, set, envelope)
        .expect("canonical durable member");
    let projection = replay_projection_records::<Schema>(std::iter::once((
        RecordNamespace::DesiredState, member.envelope().key().as_bytes(), member.encoded(),
    )), &limits).expect("canonical historical projection");
    assert_eq!(projection.transactions().len(), 1);
    assert!(matches!(validate_projection_transaction_groups_data_v1(&projection, &limits, limits),
        Err(DomainLedgerDataError::NonCanonicalRecord)));
}
