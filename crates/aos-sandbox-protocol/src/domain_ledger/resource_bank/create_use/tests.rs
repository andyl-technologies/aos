//! Checks bounded historical U DATA without constructing a native Ready owner.

use super::*;
use crate::domain_ledger::resource_bank::{
    CommitPosition, InputAssociation, Origin, ProtectedJournalNamesV1, TerminalBinding,
};
use aos_sandbox_core::{RecordNamespace, ResourceDimension, ResourceVector};

fn fixture() -> (
    replay::State,
    CoissuanceBinding,
    Claim,
    CreateStorageUseBindingV1,
) {
    let names = ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap();
    let mut original = super::super::physical_history_tests::historical_coissuance(names);
    original.original.claim.amount = ResourceVector::new([5; ResourceDimension::COUNT]);
    original.grant.amount = ResourceVector::new([3; ResourceDimension::COUNT]);
    original.origin = Some(InputAssociation {
        normalized: [40; 32],
        digest: [41; 32],
        bytes: 1,
        continuation: ResourceVector::new([1; ResourceDimension::COUNT]),
        intake: [42; 16],
        observations: 27,
    });
    // This fixture supplies canonical association DATA, not the authenticated
    // compiler input or complete enrolled bank required by native admission.
    let terminal = TerminalBinding {
        input_origin: true,
        original: original.original.claim.id,
        coissuance: Sha256::digest(q04::encode(original).unwrap()).into(),
        transaction: [60; 16],
        names,
        next: 33,
        prior_end: 800,
        root_final: [61; 32],
        origins: std::array::from_fn(|index| Origin {
            id: [u8::try_from(index + 70).unwrap(); 16],
            members: [u8::try_from(index + 80).unwrap(); 32],
            returned: CommitPosition {
                commit_sequence: 11 + index as u64 * 3,
                durable_bytes: (index as u64 + 1) * 100,
            },
        }),
    };
    let claim = original
        .create_storage_use_claim_v1([50; 16], original.use_claim.amount)
        .unwrap();
    let binding = CreateStorageUseBindingV1::new(original, [51; 32], [52; 32], claim).unwrap();
    let (_, head) = settlement::terminal_pair(original).unwrap();
    let mut state = replay::State::new();
    put(
        &mut state,
        q04::PREFIX,
        original.original.claim.id,
        q04::encode(original).unwrap().as_slice(),
    );
    put(
        &mut state,
        settlement::PREFIX,
        original.original.claim.id,
        &settlement::encode(terminal).unwrap(),
    );
    put(
        &mut state,
        replay::HEAD_PREFIX,
        head.id,
        &codec::encode_head(head).unwrap(),
    );
    put(
        &mut state,
        replay::CLAIM_PREFIX,
        original.use_claim.id,
        &codec::encode_claim(Claim {
            state: ClaimState::Committed,
            ..original.use_claim
        })
        .unwrap(),
    );
    (state, original, claim, binding)
}

fn put(state: &mut replay::State, prefix: u8, id: [u8; 16], bytes: &[u8]) {
    state.insert(
        (
            RecordNamespace::ControllerResourceReservation,
            replay::key(prefix, id).to_vec(),
        ),
        bytes.to_vec(),
    );
}

fn apply(state: &mut replay::State, transaction: &JournalTransaction) {
    for record in transaction.records() {
        state.insert(
            (record.namespace(), record.key().to_vec()),
            record.value().unwrap().to_vec(),
        );
    }
}

fn transactions(
    original: CoissuanceBinding,
    claim: Claim,
    binding: CreateStorageUseBindingV1,
) -> (JournalTransaction, JournalTransaction) {
    let (before, reserved, committed) = binding.pairs(original, claim).unwrap();
    let reserve_id = binding.reserve_transaction_id().unwrap();
    let commit_id = binding.commit_transaction_id().unwrap();
    let committed_claim = Claim {
        state: ClaimState::Committed,
        ..claim
    };
    let reserve = AccountMutation::new((
        &reserve_id,
        &before,
        &reserved,
        &claim,
        &None,
        &None,
        &None,
        &None,
    ))
    .with_create_storage_use_v1(&binding)
    .transaction()
    .unwrap();
    let commit = AccountMutation::new((
        &commit_id,
        &reserved,
        &committed,
        &committed_claim,
        &Some(claim),
        &None,
        &None,
        &None,
    ))
    .with_create_storage_use_v1(&binding)
    .transaction()
    .unwrap();
    (reserve, commit)
}

#[test]
fn immutable_binding_rejects_truncation_changed_fields_and_family() {
    let (_, original, claim, binding) = fixture();
    let bytes = binding.encode().unwrap();
    assert_eq!(CreateStorageUseBindingV1::decode(&bytes).unwrap(), binding);
    for end in 0..bytes.len() {
        assert!(CreateStorageUseBindingV1::decode(&bytes[..end]).is_err());
    }
    for offset in [0, 8, 24, 56, 88, 120, 136] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(CreateStorageUseBindingV1::decode(&changed).is_err());
    }
    let changed = Claim {
        operation: [90; 16],
        ..claim
    };
    assert!(CreateStorageUseBindingV1::new(original, [51; 32], [52; 32], changed).is_err());
    assert!(CreateStorageUseBindingV1::new(original, [0; 32], [52; 32], claim).is_err());
    assert_ne!(
        binding.reserve_transaction_id().unwrap(),
        binding.commit_transaction_id().unwrap()
    );
}

#[test]
fn saved_child_has_only_exact_reserved_and_committed_successors() {
    let (mut state, original, claim, binding) = fixture();
    let (reserve, commit) = transactions(original, claim, binding);
    let (_, terminal_head) = settlement::terminal_pair(original).unwrap();

    apply(&mut state, &reserve);
    let reserved = current_child(&state, original, terminal_head).unwrap();
    assert_eq!(reserved.generation, 3);
    assert_eq!(reserve.records().len(), 3);
    assert_eq!(reserved.account.reserved(), claim.amount);
    let immutable = replay::record_bytes(&state, PREFIX, claim.id)
        .unwrap()
        .to_vec();

    apply(&mut state, &commit);
    let committed = current_child(&state, original, terminal_head).unwrap();
    assert_eq!(committed.generation, 4);
    assert_eq!(commit.records().len(), 2);
    assert_eq!(committed.account.reserved(), ResourceVector::ZERO);
    assert_eq!(
        replay::record_bytes(&state, PREFIX, claim.id),
        Some(immutable.as_slice())
    );
    assert!(super::super::account::settled_pair(reserved, claim, false).is_err());
    assert!(
        codec::encode_claim(Claim {
            state: ClaimState::Released,
            ..claim
        })
        .is_err()
    );

    let changed = AccountHead {
        generation: 5,
        ..committed
    };
    put(
        &mut state,
        replay::HEAD_PREFIX,
        changed.id,
        &codec::encode_head(changed).unwrap(),
    );
    assert!(current_child(&state, original, terminal_head).is_err());
}

#[test]
fn duplicate_original_binding_and_changed_claim_or_coissuance_refuse() {
    let (mut state, original, claim, binding) = fixture();
    let (reserve, _) = transactions(original, claim, binding);
    apply(&mut state, &reserve);
    assert!(binding.require_replayed(&state).is_ok());

    let changed_claim = Claim {
        id: [91; 16],
        ..claim
    };
    let duplicate =
        CreateStorageUseBindingV1::new(original, [51; 32], [52; 32], changed_claim).unwrap();
    put(
        &mut state,
        PREFIX,
        duplicate.claim_id(),
        &duplicate.encode().unwrap(),
    );
    let (_, terminal) = settlement::terminal_pair(original).unwrap();
    assert!(current_child(&state, original, terminal).is_err());
    state.remove(&(
        RecordNamespace::ControllerResourceReservation,
        replay::key(PREFIX, duplicate.claim_id()).to_vec(),
    ));

    let changed = Claim {
        owner: [92; 32],
        ..claim
    };
    put(
        &mut state,
        replay::CLAIM_PREFIX,
        claim.id,
        &codec::encode_claim(changed).unwrap(),
    );
    assert!(binding.require_replayed(&state).is_err());
    put(
        &mut state,
        replay::CLAIM_PREFIX,
        claim.id,
        &codec::encode_claim(claim).unwrap(),
    );
    let mut changed = original;
    changed.specification_record = [93; 32];
    put(
        &mut state,
        q04::PREFIX,
        original.original.claim.id,
        q04::encode(changed).unwrap().as_slice(),
    );
    assert!(binding.require_replayed(&state).is_err());
}

#[test]
fn physical_history_requires_real_order_complete_members_and_both_ids() {
    let (mut state, original, claim, binding) = fixture();
    let (reserve, commit) = transactions(original, claim, binding);
    apply(&mut state, &reserve);
    apply(&mut state, &commit);
    let mut history = UsePhysicalHistoryV1::default();
    assert!(
        history
            .observe(&state, &commit, 105, 108, 2000, 3000)
            .is_err()
    );

    let mut history = UsePhysicalHistoryV1::default();
    history
        .observe(&state, &reserve, 100, 104, 1000, 2000)
        .unwrap();
    history
        .observe(&state, &commit, 105, 108, 2000, 3000)
        .unwrap();
    let ids = std::collections::BTreeSet::from([*reserve.id(), *commit.id()]);
    history.finish(&state, &ids).unwrap();
    assert!(
        history
            .finish(&state, &std::collections::BTreeSet::from([*reserve.id()]))
            .is_err()
    );

    let mut reordered = reserve.records().to_vec();
    reordered.swap(0, 1);
    let reordered = JournalTransaction::new(*reserve.id(), reordered).unwrap();
    assert!(
        UsePhysicalHistoryV1::default()
            .observe(&state, &reordered, 100, 104, 1000, 2000)
            .is_err()
    );
    assert!(
        UsePhysicalHistoryV1::default()
            .observe(&state, &reserve, 30, 34, 700, 2000)
            .is_err()
    );
    let demand = UsePhysicalHistoryV1::additional_demand(&state).unwrap();
    assert!(
        demand.get(ResourceDimension::MemoryBytes) >= std::mem::size_of::<UsePosition>() as u64
    );
    assert_eq!(demand.get(ResourceDimension::MetadataEntries), 0);
}

#[test]
fn inherited_use_claim_keeps_all_original_ancestry_and_refuses_aliases() {
    let (_, original, claim, _) = fixture();
    let amount = ResourceVector::new([2; ResourceDimension::COUNT]);
    let derived = original
        .create_storage_use_claim_v1([95; 16], amount)
        .unwrap();

    assert_eq!(
        derived,
        Claim {
            id: [95; 16],
            amount,
            ..claim
        }
    );
    for id in [
        [0; 16],
        original.original.claim.id,
        original.use_claim.id,
        original.grant.id,
    ] {
        assert!(original.create_storage_use_claim_v1(id, amount).is_err());
    }
    assert!(
        original
            .create_storage_use_claim_v1([95; 16], ResourceVector::ZERO)
            .is_err()
    );
    let malformed = CoissuanceBinding {
        use_claim: Claim {
            operation: [96; 16],
            ..original.use_claim
        },
        ..original
    };
    assert!(
        malformed
            .create_storage_use_claim_v1([95; 16], amount)
            .is_err()
    );
}
