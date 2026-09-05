//! Inert namespace-target codec, allocation, and replay regressions.
//!
//! These tests exercise protected audit planning only. They do not construct a
//! live [`CurrentNamespaceTarget`] or qualify attachment replay.

#![allow(
    clippy::unwrap_used,
    reason = "Regression fixtures and assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{OperationId, PrincipalId};

use crate::publication::{AuthorityPublicationStore, tests::activation_claim};
use crate::runtime_authority::{
    RuntimeAuthorityIntentV1, RuntimeAuthorityLimits, RuntimeAuthorityStore,
};
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    OperationPlan, Reconciler, SingleNodeEffectExecutor,
};

use super::*;
use crate::runtime_scope::generation::{Facts as RuntimeFacts, History as RuntimeHistory};

struct NoEffects;

impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("namespace-target tests must not dispatch effects")
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("namespace-target tests must not dispatch effects")
    }
}

fn open(directory: &std::path::Path) -> Journal {
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    Journal::open_protected_at_uid(
        directory,
        "controller.journal",
        JournalLimits::default(),
        std::fs::metadata(directory).unwrap().uid(),
    )
    .unwrap()
    .0
}

fn fixture(journal: Journal) -> (Reconciler<NoEffects>, RuntimeFacts) {
    let mut reconciler = Reconciler::new(journal, NoEffects);
    let (draft, prepared) = crate::publication::tests::runtime_scope_activation_fixture(1);
    let operation = OperationId::from_bytes([1; 16]);
    let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
    let plan = OperationPlan::ownership_gated(
        operation,
        IdempotencyKey::new(vec![1]).unwrap(),
        [1; 32],
        vec![1],
        vec![1],
        vec![effect],
        activation_claim(&draft, 1),
        draft.clone(),
    )
    .unwrap()
    .with_runtime_authority(
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x91; 16]), None).unwrap(),
    )
    .unwrap();
    reconciler.accept(&plan).unwrap();
    let activation = AuthorityPublicationStore::new(reconciler.journal_mut())
        .prepare_gate_activation(&draft, &prepared)
        .unwrap();
    reconciler
        .activate_ownership_gate(operation, activation)
        .unwrap();

    let sandbox = draft.manifest().manifest().sandbox();
    let binding =
        RuntimeAuthorityStore::load(reconciler.journal_mut(), RuntimeAuthorityLimits::default())
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap();
    let facts = RuntimeFacts {
        identity: (
            *sandbox.as_bytes(),
            *binding.manifest().manifest().incarnation().as_bytes(),
        ),
        runtime: aos_sandbox_protocol::semantics::host::runtime_handle_v1(
            binding.manifest().manifest().incarnation().as_bytes(),
            binding.manifest().manifest().epoch().get(),
            binding.assignment_digest().as_bytes(),
        ),
        scope: [3; 32],
        pid: 123,
        leaf_cgroup: 456,
        anchor: 789,
        binding_revision: binding.revision(),
        binding_digest: *binding.digest().as_bytes(),
    };
    (reconciler, facts)
}

fn runtime_record(facts: RuntimeFacts) -> crate::runtime_scope::generation::Record {
    RuntimeHistory::default().select(facts).unwrap().0
}

fn write_runtime(journal: &mut Journal, record: &crate::runtime_scope::generation::Record) {
    journal.commit(&record.transaction().unwrap()).unwrap();
}

fn allocation(
    identity: Identity,
    observed_generation: u64,
    observed_audit_digest: [u8; 32],
    signed_target: u64,
) -> Record {
    History::default()
        .select(
            identity,
            observed_generation,
            observed_audit_digest,
            signed_target,
        )
        .unwrap()
        .0
}

fn write_allocation(journal: &mut Journal, record: &Record) {
    journal.commit(&record.transaction().unwrap()).unwrap();
}

fn replace(journal: &mut Journal, key: Vec<u8>, value: Vec<u8>) {
    journal
        .commit(
            &JournalTransaction::new([0xaa; 16], vec![JournalRecord::put(NAMESPACE, key, value)])
                .unwrap(),
        )
        .unwrap();
}

#[test]
fn codec_is_exact_width_and_checks_every_byte() {
    let record = allocation(([1; 16], [2; 16]), 3, [4; 32], 8);
    let bytes = record.encode();
    assert_eq!(bytes.len(), 152);
    assert_eq!(Record::decode(&bytes).unwrap(), record);
    assert_eq!(record.key().len(), 41);
    assert_eq!(
        format::decode_head(&head_key(record.identity), &record.head()).unwrap(),
        (record.identity, (3, 8, record.digest))
    );
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(Record::decode(&changed).is_err(), "byte {index}");
        assert!(Record::decode(&bytes[..index]).is_err(), "length {index}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Record::decode(&trailing).is_err());
}

#[test]
fn reserved_fields_fail_even_with_a_valid_digest() {
    for field in 0..5 {
        let mut record = allocation(([1; 16], [2; 16]), 3, [4; 32], 8);
        match field {
            0 => record.identity.0 = [0; 16],
            1 => record.identity.1 = [0; 16],
            2 => record.observed_generation = 0,
            3 => record.observed_audit_digest = [0; 32],
            _ => record.target_generation = 0,
        }
        record.digest = record.compute_digest();
        assert!(Record::decode(&record.encode()).is_err(), "field {field}");
    }
}

#[test]
fn current_observation_reuses_target_and_new_observations_advance_by_delta() {
    let identity = ([1; 16], [2; 16]);
    let first = allocation(identity, 3, [3; 32], 8);
    let mut history = History::default();
    history.append(first.clone()).unwrap();
    assert_eq!(
        history.select(identity, 3, [3; 32], 8).unwrap(),
        (first.clone(), false)
    );
    assert!(matches!(
        history.select(identity, 3, [9; 32], 8),
        Err(NamespaceTargetError::Conflict)
    ));

    let (next, changed) = history.select(identity, 5, [5; 32], 8).unwrap();
    assert!(changed);
    assert_eq!(next.target_generation, 10);
    assert_eq!(next.predecessor, first.digest);
    let proposal = next.advance([6; 32]);
    assert_eq!(proposal.target_generation(), 10);
    assert_eq!(proposal.payload_scope_handle(), [6; 32]);
    history.append(next.clone()).unwrap();
    assert_eq!(
        history.select(identity, 5, [5; 32], 8).unwrap(),
        (next, false)
    );
    assert!(matches!(
        history.select(identity, 4, [4; 32], 8),
        Err(NamespaceTargetError::Conflict)
    ));
}

#[test]
fn target_overflow_and_fixed_capacity_fail_closed() {
    let identity = ([1; 16], [2; 16]);
    let first = allocation(identity, 1, [3; 32], u64::MAX);
    let mut history = History::default();
    history.append(first).unwrap();
    assert!(matches!(
        history.select(identity, 2, [4; 32], u64::MAX),
        Err(NamespaceTargetError::Capacity)
    ));
    let full = History {
        count: MAXIMUM_HISTORY,
        ..History::default()
    };
    assert!(matches!(
        full.select(([5; 16], [6; 16]), 1, [7; 32], 1),
        Err(NamespaceTargetError::Capacity)
    ));
}

#[test]
fn replay_and_compaction_require_exact_runtime_audit_references() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let runtime = runtime_record(facts);
    write_runtime(reconciler.journal_mut(), &runtime);
    let target = allocation(
        runtime.facts.identity,
        runtime.generation,
        runtime.digest,
        8,
    );
    write_allocation(reconciler.journal_mut(), &target);
    assert_eq!(
        History::load(reconciler.journal_mut())
            .unwrap()
            .latest
            .get(&target.identity),
        Some(&target)
    );
    reconciler.journal_mut().compact().unwrap();
    drop(reconciler);

    let mut recovered = open(directory.path());
    assert_eq!(
        History::load(&mut recovered)
            .unwrap()
            .latest
            .get(&target.identity),
        Some(&target)
    );
}

#[test]
fn recomputed_allocation_hash_cannot_hide_runtime_reference_substitution() {
    for substitution in 0..2 {
        let directory = tempfile::tempdir().unwrap();
        let (mut reconciler, facts) = fixture(open(directory.path()));
        let runtime = runtime_record(facts);
        write_runtime(reconciler.journal_mut(), &runtime);
        let mut target = allocation(
            runtime.facts.identity,
            runtime.generation,
            runtime.digest,
            8,
        );
        if substitution == 0 {
            target.observed_generation += 1;
        } else {
            target.observed_audit_digest = [9; 32];
        }
        target.digest = target.compute_digest();
        write_allocation(reconciler.journal_mut(), &target);
        assert!(
            History::load(reconciler.journal_mut()).is_err(),
            "substitution {substitution}"
        );
    }
}

#[test]
fn malformed_heads_links_and_target_deltas_fail_closed() {
    for corruption in 0..5 {
        let directory = tempfile::tempdir().unwrap();
        let (mut reconciler, mut facts) = fixture(open(directory.path()));
        let first_runtime = runtime_record(facts.clone());
        write_runtime(reconciler.journal_mut(), &first_runtime);
        facts.scope = [4; 32];
        let second_runtime = RuntimeHistory::load(reconciler.journal_mut())
            .unwrap()
            .select(facts)
            .unwrap()
            .0;
        write_runtime(reconciler.journal_mut(), &second_runtime);

        let first = allocation(
            first_runtime.facts.identity,
            first_runtime.generation,
            first_runtime.digest,
            8,
        );
        write_allocation(reconciler.journal_mut(), &first);
        let second = History::load(reconciler.journal_mut())
            .unwrap()
            .select(
                second_runtime.facts.identity,
                second_runtime.generation,
                second_runtime.digest,
                8,
            )
            .unwrap()
            .0;
        write_allocation(reconciler.journal_mut(), &second);

        match corruption {
            0 => replace(
                reconciler.journal_mut(),
                head_key(second.identity),
                vec![0; 48],
            ),
            1 => replace(reconciler.journal_mut(), vec![b'x'], vec![1]),
            _ => {
                let mut changed = second.clone();
                match corruption {
                    2 => changed.predecessor = [8; 32],
                    3 => changed.target_generation += 1,
                    _ => changed.identity.1 = [9; 16],
                }
                changed.digest = changed.compute_digest();
                replace(reconciler.journal_mut(), second.key(), changed.encode());
            }
        }
        assert!(
            History::load(reconciler.journal_mut()).is_err(),
            "corruption {corruption}"
        );
    }
}

#[test]
fn corrupt_target_history_blocks_reconciler_before_effect_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let runtime = runtime_record(facts);
    write_runtime(reconciler.journal_mut(), &runtime);
    let target = allocation(
        runtime.facts.identity,
        runtime.generation,
        runtime.digest,
        8,
    );
    write_allocation(reconciler.journal_mut(), &target);
    replace(
        reconciler.journal_mut(),
        head_key(target.identity),
        vec![0; 48],
    );
    assert!(matches!(
        reconciler.reconcile_once(OperationId::from_bytes([1; 16])),
        Err(crate::ReconcilerError::NamespaceTarget(error))
            if matches!(*error, NamespaceTargetError::CorruptState)
    ));
}

#[test]
fn oversized_retained_value_is_rejected_before_decode() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let runtime = runtime_record(facts);
    write_runtime(reconciler.journal_mut(), &runtime);
    replace(
        reconciler.journal_mut(),
        allocation(
            runtime.facts.identity,
            runtime.generation,
            runtime.digest,
            8,
        )
        .key(),
        vec![0; MAXIMUM_BYTES],
    );
    assert!(matches!(
        History::load(reconciler.journal_mut()),
        Err(NamespaceTargetError::Capacity)
    ));
}
