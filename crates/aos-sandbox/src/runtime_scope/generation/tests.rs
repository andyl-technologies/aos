//! Inert generation codec and protected-ledger replay regressions.
//!
//! Fixture facts exercise only internal audit planning. These tests cannot
//! construct a live `CurrentRuntimeScope` or `CurrentRuntimeGeneration`.

#![allow(
    clippy::unwrap_used,
    reason = "Regression assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{OperationId, PrincipalId};

use crate::publication::{AuthorityPublicationStore, tests::activation_claim};
use crate::runtime_authority::RuntimeAuthorityIntentV1;
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    OperationPlan, Reconciler, SingleNodeEffectExecutor,
};

use super::*;

struct NoEffects;

impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("audit tests must not dispatch effects")
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("audit tests must not dispatch effects")
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

fn fixture(journal: Journal) -> (Reconciler<NoEffects>, Facts) {
    let mut reconciler = Reconciler::new(journal, NoEffects);
    let facts = activate(
        &mut reconciler,
        1,
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x91; 16]), None).unwrap(),
    );
    (reconciler, facts)
}

fn activate(
    reconciler: &mut Reconciler<NoEffects>,
    generation: u8,
    intent: RuntimeAuthorityIntentV1,
) -> Facts {
    let (draft, prepared) =
        crate::publication::tests::runtime_scope_activation_fixture(u64::from(generation));
    let sandbox = draft.manifest().manifest().sandbox();
    let operation = OperationId::from_bytes([generation; 16]);
    let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
    let plan = OperationPlan::ownership_gated(
        operation,
        IdempotencyKey::new(vec![generation]).unwrap(),
        [generation; 32],
        vec![generation],
        vec![generation],
        vec![effect],
        activation_claim(&draft, u64::from(generation)),
        draft.clone(),
    )
    .unwrap()
    .with_runtime_authority(intent)
    .unwrap();
    reconciler.accept(&plan).unwrap();
    let activation = AuthorityPublicationStore::new(reconciler.journal_mut())
        .prepare_gate_activation(&draft, &prepared)
        .unwrap();
    reconciler
        .activate_ownership_gate(operation, activation)
        .unwrap();
    let binding =
        RuntimeAuthorityStore::load(reconciler.journal_mut(), RuntimeAuthorityLimits::default())
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap();
    Facts {
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
    }
}

fn record(facts: Facts) -> Record {
    History::default().select(facts).unwrap().0
}

fn write(journal: &mut Journal, record: &Record) {
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
    let directory = tempfile::tempdir().unwrap();
    let (_, facts) = fixture(open(directory.path()));
    let record = record(facts);
    let bytes = record.encode();
    assert_eq!(bytes.len(), 236);
    assert_eq!(Record::decode(&bytes).unwrap(), record);
    assert_eq!(record.key().len(), 41);
    assert_eq!(
        format::decode_head(&head_key(record.facts.identity), &record.head()).unwrap(),
        (record.facts.identity, (1, record.digest))
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
    let directory = tempfile::tempdir().unwrap();
    let (_, facts) = fixture(open(directory.path()));
    for field in 0..11 {
        let mut record = record(facts.clone());
        match field {
            0 => record.facts.identity.0 = [0; 16],
            1 => record.facts.identity.1 = [0; 16],
            2 => record.generation = 0,
            3 => record.facts.runtime = [0; 32],
            4 => record.facts.scope = [0; 32],
            5 => record.facts.pid = 0,
            6 => record.facts.leaf_cgroup = 0,
            7 => record.facts.anchor = 0,
            8 => record.facts.binding_revision = 0,
            9 => record.facts.binding_digest = [0; 32],
            _ => record.predecessor = [1; 32],
        }
        record.digest = record.compute_digest();
        assert!(Record::decode(&record.encode()).is_err(), "field {field}");
    }
}

#[test]
fn repeat_observation_and_renewal_keep_generation_but_changed_scope_advances() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let journal = reconciler.journal_mut();
    let first = record(facts.clone());
    write(journal, &first);
    let history = History::load(journal).unwrap();
    assert_eq!(
        history.select(facts.clone()).unwrap(),
        (first.clone(), false)
    );
    let mut renewed = facts.clone();
    renewed.binding_revision += 1;
    renewed.binding_digest = [99; 32];
    assert_eq!(history.select(renewed).unwrap(), (first.clone(), false));

    let mut next = facts.clone();
    next.scope = [4; 32];
    let (second, changed) = history.select(next.clone()).unwrap();
    assert!(changed);
    assert_eq!(second.generation, 2);
    assert_eq!(second.predecessor, first.digest);
    write(journal, &second);
    let history = History::load(journal).unwrap();
    assert_eq!(history.select(next).unwrap(), (second, false));
    assert!(matches!(
        history.select(facts),
        Err(RuntimeGenerationError::Conflict)
    ));
}

#[test]
fn scope_handle_cannot_hide_execution_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let (_, facts) = fixture(open(directory.path()));
    let mut history = History::default();
    history.append(record(facts.clone())).unwrap();
    for field in 0..3 {
        let mut changed = facts.clone();
        match field {
            0 => changed.pid += 1,
            1 => changed.leaf_cgroup += 1,
            _ => changed.anchor += 1,
        }
        assert!(matches!(
            history.select(changed),
            Err(RuntimeGenerationError::Conflict)
        ));
    }
}

#[test]
fn replay_and_compaction_preserve_monotone_audit_only() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, mut facts) = fixture(open(directory.path()));
    let first = record(facts.clone());
    write(reconciler.journal_mut(), &first);
    facts.scope = [44; 32];
    let second = History::load(reconciler.journal_mut())
        .unwrap()
        .select(facts.clone())
        .unwrap()
        .0;
    write(reconciler.journal_mut(), &second);
    reconciler.journal_mut().compact().unwrap();
    drop(reconciler);
    let mut recovered = open(directory.path());
    let history = History::load(&mut recovered).unwrap();
    assert_eq!(history.count, 2);
    assert_eq!(history.select(facts).unwrap(), (second, false));
}

#[test]
fn assignment_alias_change_keeps_the_attested_execution_number() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let first = record(facts.clone());
    write(reconciler.journal_mut(), &first);
    let mut fresh = facts;
    fresh.runtime = [88; 32];
    fresh.binding_revision += 1;
    fresh.binding_digest = [89; 32];
    // This helper plans inert audit records, not current authority. Production
    // only supplies these inputs from a newly authenticated CurrentRuntimeScope.
    let history = History::load(reconciler.journal_mut()).unwrap();
    assert_eq!(history.select(fresh).unwrap(), (first, false));
}

#[test]
fn valid_record_and_head_hashes_do_not_hide_origin_binding_substitution() {
    for substitution in 0..4 {
        let directory = tempfile::tempdir().unwrap();
        let (mut reconciler, facts) = fixture(open(directory.path()));
        let mut forged = record(facts);
        match substitution {
            0 => forged.facts.runtime = [88; 32],
            1 => forged.facts.binding_digest = [89; 32],
            2 => forged.facts.binding_revision += 1,
            _ => forged.facts.identity.1 = [90; 16],
        }
        forged.digest = forged.compute_digest();
        assert_eq!(Record::decode(&forged.encode()).unwrap(), forged);
        // Both the record and head contain the recomputed digest, so only
        // checking their hashes and mutual agreement would accept this state.
        write(reconciler.journal_mut(), &forged);
        assert!(
            History::load(reconciler.journal_mut()).is_err(),
            "substitution {substitution}"
        );
    }
}

#[test]
fn corrupt_heads_keys_links_and_binding_references_fail_closed() {
    for corruption in 0..10 {
        let directory = tempfile::tempdir().unwrap();
        let (mut reconciler, mut facts) = fixture(open(directory.path()));
        let journal = reconciler.journal_mut();
        let first = record(facts.clone());
        write(journal, &first);
        facts.scope = [4; 32];
        let second = History::load(journal).unwrap().select(facts).unwrap().0;
        write(journal, &second);
        match corruption {
            0 => replace(journal, head_key(first.facts.identity), first.head()),
            1 => replace(journal, vec![b'x'], vec![1]),
            2 => replace(journal, vec![b'h'], second.head()),
            3 => replace(journal, head_key(first.facts.identity), vec![0; 40]),
            _ => {
                let mut changed = second.clone();
                match corruption {
                    4 => changed.predecessor = [66; 32],
                    5 => changed.facts.binding_digest = [77; 32],
                    6 => changed.facts.binding_revision += 1,
                    7 => changed.facts.identity.1 = [88; 16],
                    8 => changed.facts.scope = first.facts.scope,
                    _ => changed.facts.runtime = [88; 32],
                }
                changed.digest = changed.compute_digest();
                replace(journal, second.key(), changed.encode());
            }
        }
        assert!(History::load(journal).is_err(), "corruption {corruption}");
    }
}

#[test]
fn missing_history_or_head_is_not_recovered_as_a_new_generation() {
    for delete_head in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (mut reconciler, facts) = fixture(open(directory.path()));
        let journal = reconciler.journal_mut();
        let first = record(facts);
        write(journal, &first);
        let key = if delete_head {
            head_key(first.facts.identity)
        } else {
            first.key()
        };
        journal
            .commit(
                &JournalTransaction::new([0xab; 16], vec![JournalRecord::delete(NAMESPACE, key)])
                    .unwrap(),
            )
            .unwrap();
        assert!(History::load(journal).is_err());
    }
}

#[test]
fn bare_journal_and_exhausted_capacity_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let mut bare = Journal::open(directory.path().join("bare"), JournalLimits::default())
        .unwrap()
        .0;
    assert!(matches!(
        History::load(&mut bare),
        Err(RuntimeGenerationError::Journal(_))
    ));
    let (_, facts) = fixture(open(directory.path()));
    let full = History {
        count: MAXIMUM_HISTORY,
        ..History::default()
    };
    assert!(matches!(
        full.select(facts.clone()),
        Err(RuntimeGenerationError::Capacity)
    ));
    let mut last = record(facts.clone());
    last.generation = u64::MAX;
    let history = History {
        latest: BTreeMap::from([(facts.identity, last)]),
        ..History::default()
    };
    let mut next = facts;
    next.scope = [9; 32];
    assert!(matches!(
        history.select(next),
        Err(RuntimeGenerationError::Capacity)
    ));
}

#[test]
fn oversized_retained_value_is_rejected_before_decode() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let journal = reconciler.journal_mut();
    replace(journal, record(facts).key(), vec![0; MAXIMUM_BYTES]);
    assert!(matches!(
        History::load(journal),
        Err(RuntimeGenerationError::Capacity)
    ));
}

#[test]
fn complete_history_at_capacity_rejects_one_more_record() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let journal = reconciler.journal_mut();
    let mut latest = record(facts);
    let mut records = Vec::new();
    for generation in 1..=u64::try_from(MAXIMUM_HISTORY).unwrap() {
        if generation > 1 {
            latest.predecessor = latest.digest;
            latest.generation = generation;
            latest.facts.scope[..8].copy_from_slice(&generation.to_be_bytes());
            latest.digest = latest.compute_digest();
        }
        records.push(JournalRecord::put(NAMESPACE, latest.key(), latest.encode()));
    }
    journal
        .commit(&JournalTransaction::new([0xac; 16], records).unwrap())
        .unwrap();
    replace(journal, head_key(latest.facts.identity), latest.head());
    let history = History::load(journal).unwrap();
    assert_eq!(history.count, MAXIMUM_HISTORY);
    assert_eq!(
        history.select(latest.facts.clone()).unwrap(),
        (latest.clone(), false)
    );

    latest.predecessor = latest.digest;
    latest.generation += 1;
    latest.facts.scope[..8].copy_from_slice(&latest.generation.to_be_bytes());
    latest.digest = latest.compute_digest();
    write(journal, &latest);
    assert!(matches!(
        History::load(journal),
        Err(RuntimeGenerationError::Capacity)
    ));
}

#[test]
fn corrupt_generation_blocks_reconciler_before_effect_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let first = record(facts);
    write(reconciler.journal_mut(), &first);
    replace(
        reconciler.journal_mut(),
        head_key(first.facts.identity),
        vec![0; 40],
    );
    assert!(matches!(
        reconciler.reconcile_once(OperationId::from_bytes([1; 16])),
        Err(crate::ReconcilerError::RuntimeGeneration(error))
            if matches!(*error, RuntimeGenerationError::CorruptState)
    ));
}

#[test]
fn historical_origin_binding_survives_renewal_and_revocation_as_audit_only() {
    let directory = tempfile::tempdir().unwrap();
    let (mut reconciler, facts) = fixture(open(directory.path()));
    let first = record(facts.clone());
    write(reconciler.journal_mut(), &first);
    let renewed = activate(
        &mut reconciler,
        2,
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x91; 16]), Some(1))
            .unwrap(),
    );
    assert_ne!(renewed.binding_digest, facts.binding_digest);
    assert_eq!(
        History::load(reconciler.journal_mut())
            .unwrap()
            .select(renewed)
            .unwrap(),
        (first.clone(), false)
    );

    activate(
        &mut reconciler,
        3,
        RuntimeAuthorityIntentV1::revoke(Some(2)).unwrap(),
    );
    let history = History::load(reconciler.journal_mut()).unwrap();
    assert_eq!(history.latest.get(&facts.identity), Some(&first));
    // This is deliberately not a current-runtime acquisition: no live proof
    // exists in this test, and the controller cannot track a revoked holder.
}
