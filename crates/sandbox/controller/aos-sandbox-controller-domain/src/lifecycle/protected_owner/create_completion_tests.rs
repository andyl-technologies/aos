//! Exercises canonical Source completion and its compacted cross-family history.
//!
//! Fixtures are historical DATA. They use the real lifecycle reducers, codecs,
//! retained full-schema replay and latest selector; no fixture mints a C23 loan,
//! Root ACK authority or native currentness owner.

use super::*;
use crate::journal::RecordNamespace;
use crate::lifecycle::*;
use crate::lifecycle::protected_journal::{
    LifecycleProtectedJournalEnvelopeV1, LifecycleSchemaReplayCaptureV1,
};
use aos_sandbox_model::{AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration};
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainSchemaV1, ReplayProjectionRecordsCaptureV1,
    domain_transaction_set_digest, encode_durable_member,
    replay_projection_records_with_schema_capture_v1,
};
use std::collections::BTreeMap;

struct Fixture {
    history: Vec<LifecycleOperationV1>,
    effect: LifecyclePhase6EffectPlanV1,
    inventory: ObjectDigest,
}

fn digest(operation: &LifecycleOperationV1) -> LifecycleRecordDigestV1 {
    let bytes = crate::lifecycle::format::encode_retained_operation_record(operation).unwrap();
    crate::lifecycle::format::record_digest(&bytes).unwrap()
}

fn semantic_commit(operation: &LifecycleOperationV1) -> LifecycleMethodSemanticCommitV1 {
    let sandbox = SandboxId::from_bytes([4; 16]);
    let resource = LifecycleResourceV1::Sandbox(sandbox);
    let state = LifecycleResourceStateDigestV1::commit(b"actual assignment projection");
    let cas = DesiredStateCasV1::new(
        resource, DesiredGeneration::new(0), None, DesiredGeneration::new(1),
        DesiredStateDocumentDigestV1::commit(b"accepted stopped projection"),
    ).unwrap();
    let write = LifecycleCommittedResourceV1::new(
        resource, ResourceExpectedStateV1::Absent, Revision::new(1), state,
        Some(cas.digest()),
    ).unwrap();
    let assignment = LifecycleAssignmentCommitFactV1::new(
        sandbox, ResourceId::from_bytes([8; 16]), AssignmentEpoch::new(1),
    ).unwrap();
    let reservation = LifecycleReservationCommitFactV1::new(
        ResourceId::from_bytes([9; 16]), Revision::new(1),
        LifecycleResourceStateDigestV1::commit(b"inclusive reservation row"),
    ).unwrap();
    let desired = DesiredStateFenceV1::new(
        resource, DesiredGeneration::new(1), Revision::new(1), state,
    ).unwrap();
    let incarnation = LifecycleIncarnationCommitFactV1::new(
        LifecycleIncarnationOriginV1::Created,
        LiveRuntimeFenceV1::new(
            sandbox, desired, IncarnationId::from_bytes([10; 16]),
            AssignmentEpoch::new(1), NamespaceGeneration::new(1),
        ).unwrap(),
    );
    let witness = LifecycleSemanticCommitV1::new(
        1, cas, LifecycleJournalCommitDigestV1::commit(b"semantic transaction"),
        LifecycleTimeV1::new(3).unwrap(),
    ).unwrap();

    LifecycleMethodSemanticCommitV1::new(
        witness,
        LifecycleSemanticCommitFactV1::DesiredState {
            cas, reads: Vec::new(), resources: vec![write],
            assignments: vec![assignment], reservations: vec![reservation],
        },
        LifecycleSemanticEvidenceV1::new(None, None, None, None, Some(incarnation)),
        operation.intent(), operation.expectations(),
    ).unwrap()
}

fn fixture() -> Fixture {
    let operation = OperationId::from_bytes([1; 16]);
    let sandbox = SandboxId::from_bytes([4; 16]);
    let anchor = LifecycleStepV1::unbound(
        0, LifecycleStepClassV1::PostCommitForward, LifecycleStepDomainV1::Controller,
        LifecycleStepRequestDigestV1::commit(b"canonical accepted public Create"), None,
    ).unwrap();
    let accepted = LifecycleOperationV1::new(
        operation, PrincipalId::from_bytes([2; 16]), ProjectId::from_bytes([3; 16]),
        LifecycleIdempotencyDigestV1::commit(b"idempotency"),
        LifecycleIntentV1::Create { sandbox }, LifecycleTimeV1::new(1).unwrap(),
        Revision::new(1),
        vec![ResourceExpectationV1::absent(LifecycleResourceV1::Sandbox(sandbox)).unwrap()],
        vec![anchor.clone()], LifecyclePhaseV1::Accepted, 0, 0,
        None, None, None, None, None, None,
    ).unwrap();
    let effect = LifecyclePhase6EffectPlanV1::new(
        LifecycleEffectDomainV1::Controller, 1, sandbox.into_bytes(),
        ObjectDigest::from_bytes([5; 32]), ObjectDigest::from_bytes([6; 32]),
    ).unwrap();
    let bound = crate::lifecycle::lifecycle_phase6_bind_controller_anchor_v1(
        operation, &anchor, effect,
    ).unwrap();
    let bound = accepted.successor(
        digest(&accepted), LifecyclePhaseV1::Accepted, 0, 0, vec![bound],
        None, None, None, None, None,
    ).unwrap();
    let prepared = bound.successor(
        digest(&bound), LifecyclePhaseV1::Prepared, 0, 0, bound.steps().to_vec(),
        None, None, None, None, None,
    ).unwrap();
    let ready = prepared.successor(
        digest(&prepared), LifecyclePhaseV1::ReadyToCommit, 0, 0,
        prepared.steps().to_vec(), None, None, None, None, None,
    ).unwrap();
    let commit = semantic_commit(&ready);
    let committed = ready.successor(
        digest(&ready), LifecyclePhaseV1::Committed, 0, 0, ready.steps().to_vec(),
        Some(commit.clone()), None, None, None, None,
    ).unwrap();
    let reserved = reserve_forward_step(
        &committed.steps()[0], LifecycleStepAdmissionDigestV1::commit(b"actual reserved attempt"),
        LifecycleTimeV1::new(4).unwrap(),
    ).unwrap();
    let completing = committed.successor(
        digest(&committed), LifecyclePhaseV1::Completing, 0, 0, vec![reserved],
        Some(commit), None, None, None, None,
    ).unwrap();
    let current = CurrentLifecycleOperationV1::from_protected_current(
        completing.clone(), digest(&completing), ObjectDigest::from_bytes([11; 32]),
    );
    let inventory = ObjectDigest::from_bytes([12; 32]);
    let observation = current.recover_reserved_effect(
        effect.domain(), effect.ordinal(), effect.target(), effect.prerequisite(), effect.plan(),
    ).unwrap().observe_controller_readback(ObjectDigest::from_bytes([13; 32]), inventory).unwrap();
    let applied = observe_forward_success(
        &completing.steps()[0], observation, LifecycleTimeV1::new(5).unwrap(),
    ).unwrap();
    let terminal = completing.successor(
        digest(&completing), LifecyclePhaseV1::Terminal, 1, 0, vec![applied],
        completing.method_semantic_commit().cloned(), None, None,
        Some(LifecycleTerminalResultV1::Succeeded), Some(LifecycleTimeV1::new(5).unwrap()),
    ).unwrap();

    Fixture {
        history: vec![accepted, bound, prepared, ready, committed, completing, terminal],
        effect, inventory,
    }
}

fn compacted_rows(
    operations: &[LifecycleOperationV1], verifier: &LifecycleJournalVerifierV1,
) -> BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
    use crate::lifecycle::protected_journal::{
        LifecycleReducerRecordV1, lifecycle_reducer_envelope_v1,
    };
    let mut heads: BTreeMap<LifecycleProtectedJournalKeyV1, LifecycleProtectedJournalEnvelopeV1> = BTreeMap::new();
    let mut rows = BTreeMap::new();
    for operation in operations {
        let kind = operation_record_kind(operation.phase());
        let key = lifecycle_protected_key_v1(
            kind, operation.project(), ResourceId::from_bytes([4; 16]), operation.operation_id(),
        ).unwrap();
        let previous = heads.get(&key);
        let envelope = lifecycle_reducer_envelope_v1(
            key.clone(), previous.map_or(1, |row| row.revision() + 1),
            previous.map(|row| row.digest()), LifecycleReducerRecordV1::Operation(operation), verifier,
        ).unwrap();
        let transaction = operation.record_revision().get().to_be_bytes();
        let mut transaction_id = [0; 16];
        transaction_id[..8].copy_from_slice(&transaction);
        transaction_id[8..].copy_from_slice(&transaction);
        let set = domain_transaction_set_digest(transaction_id, std::slice::from_ref(&envelope));
        let member = encode_durable_member(transaction_id, 0, 1, set, envelope.clone()).unwrap();
        rows.insert((LifecycleProtectedJournalSchemaV1::namespace(kind), key.as_bytes().to_vec()), member.encoded().to_vec());
        heads.insert(key, envelope);
    }
    rows
}

#[test]
fn actual_completion_reducers_roundtrip_and_replay_the_whole_semantic_chain() {
    let fixture = fixture();
    let encoded: Vec<_> = fixture.history.iter().map(|operation|
        crate::lifecycle::format::encode_retained_operation_record(operation).unwrap()).collect();
    let replay = crate::lifecycle::history::LifecycleHistoryV1::replay(encoded.iter().map(Vec::as_slice)).unwrap();
    let terminal = fixture.history.last().unwrap();
    assert_eq!(replay.operation(terminal.operation_id()), Some(terminal));

    let completing = &fixture.history[5];
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_v1(
        completing, digest(completing), terminal, fixture.inventory,
    ).is_ok());
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_v1(
        completing, LifecycleRecordDigestV1::commit(b"substituted historical row"), terminal, fixture.inventory,
    ).is_err());
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_v1(
        completing, digest(completing), terminal, ObjectDigest::from_bytes([14; 32]),
    ).is_err());
    let inventory = terminal.steps()[0].inventory().unwrap();
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_inventory_v2(
        completing, digest(completing), terminal, inventory,
    ).is_ok());
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_inventory_v2(
        completing, digest(completing), terminal,
        crate::lifecycle::LifecycleInventoryDigestV1::commit(b"substituted protected inventory"),
    ).is_err());
    assert!(fixture.history[0].steps()[0].request() == terminal.steps()[0].request());
    assert_eq!(fixture.effect.ordinal(), 1);
}

#[test]
fn latest_per_key_keeps_the_named_completing_effect_after_terminal_operation() {
    let fixture = fixture();
    let verifier = LifecycleJournalVerifierV1::from_verified_authority(
        ObjectDigest::from_bytes([15; 32]), Vec::new(), Vec::new(),
    ).unwrap();
    let rows = compacted_rows(&fixture.history, &verifier);
    assert_eq!(rows.len(), 3);
    let mut captured = ReplayProjectionRecordsCaptureV1::<LifecycleProtectedJournalSchemaV1>::new();
    let mut schema = LifecycleSchemaReplayCaptureV1::new();

    replay_projection_records_with_schema_capture_v1::<LifecycleProtectedJournalSchemaV1>(
        rows.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())),
        &verifier, &mut captured, &mut schema,
    ).unwrap();
    let projection = captured.projection().unwrap();
    let mut selected = LifecycleCurrentOperationSelectionOriginalV1::new();
    selected.select_once_v1(projection, &verifier, fixture.history[0].operation_id()).unwrap();
    assert_eq!(&selected.completed_v1().unwrap().1, fixture.history.last().unwrap());

    let effect = projection.records().iter().find(|row|
        row.key().kind() == LifecycleProtectedRecordKindV1::Effect).unwrap();
    let body = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
        effect.key(), effect.payload(), &verifier,
    ).unwrap();
    let historical = decode_operation_record_v1(body.body()).unwrap();
    assert_eq!(historical, fixture.history[5]);
    assert_eq!(crate::lifecycle::format::record_digest(body.body()).unwrap(), digest(&fixture.history[5]));
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_v1(
        &historical, digest(&historical), &selected.completed_v1().unwrap().1, fixture.inventory,
    ).is_ok());
}

#[test]
fn a_terminal_row_cannot_replace_the_historical_completing_provenance() {
    let fixture = fixture();
    let completing = &fixture.history[5];
    let terminal = fixture.history.last().unwrap();

    assert_ne!(digest(completing), digest(terminal));
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_v1(
        terminal, digest(terminal), terminal, fixture.inventory,
    ).is_err());
    assert!(crate::cold_launch_publication::completion::require_create_terminal_source_v1(
        &fixture.history[4], digest(&fixture.history[4]), terminal, fixture.inventory,
    ).is_err());
}

#[test]
fn completion_retains_the_operation_digest_from_the_same_canonical_envelope_encoder() {
    let fixture = fixture();
    let terminal = fixture.history.last().unwrap();
    let verifier = LifecycleJournalVerifierV1::from_verified_authority(
        ObjectDigest::from_bytes([15; 32]), Vec::new(), Vec::new(),
    ).unwrap();
    let key = lifecycle_protected_key_v1(operation_record_kind(terminal.phase()),
        terminal.project(), ResourceId::from_bytes([4; 16]), terminal.operation_id()).unwrap();
    let ordinary = crate::lifecycle::protected_journal::lifecycle_reducer_envelope_v1(
        key.clone(), 1, None, crate::lifecycle::protected_journal::LifecycleReducerRecordV1::Operation(terminal),
        &verifier).unwrap();
    let mut captured = None;
    let retained = crate::lifecycle::protected_journal::lifecycle_reducer_envelope_with_record_digest_v2(
        key, 1, None, crate::lifecycle::protected_journal::LifecycleReducerRecordV1::Operation(terminal),
        &verifier, Some(&mut captured)).unwrap();

    assert_eq!(ordinary.payload(), retained.payload());
    assert_eq!(ordinary.digest(), retained.digest());
    assert_eq!(captured, Some(digest(terminal)));
    assert_ne!(captured.unwrap().digest(), retained.digest());
}
