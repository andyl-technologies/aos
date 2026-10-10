//! Persistent memory-rule continuation through the production host checkpoint.
//!
//! Commit receipts are modeled ledger inputs, not native execution evidence.
//! These controls do not create a guest, authorize a native role, or claim a
//! committed CPU ticket. The live-node projection fixture below is deliberately
//! synthetic and cannot establish equal physical RAM.

use super::*;
use crucible::model::{
    ByteRange, HexBytes, MemoryAccessClasses, MemoryAccessMutation, NodeOccurrencePolicy,
};

fn persistent_memory_rule() -> ResolvedBindingAction {
    let mut action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    action.kind = BindingActionKind::UpsertPersistent;
    action.binding = object_id("persistent-memory-stuck");
    action.phase = FaultPhase::Load;
    action.target = ResolvedFaultTarget::MemoryRange {
        node: object_id("node-a"),
        address_space: object_id("gva"),
        guest_address: 0x102000,
        vcpu: Some(0),
        length_bytes: 1,
    };
    action.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Node(NodeEffectSpecification::MemoryAccessTransform {
                range: ByteRange::new(0x102000, 1).expect("bounded one-byte range"),
                accesses: MemoryAccessClasses {
                    fetch: false,
                    cpu_load: true,
                    cpu_store: true,
                    dma_read: false,
                    dma_write: false,
                    page_table_walk: false,
                },
                dma_device: None,
                violate_atomicity: false,
                mutation: MemoryAccessMutation::Stuck {
                    mask: HexBytes::parse("01", 1).expect("one-byte mask"),
                    value: HexBytes::parse("00", 1).expect("one-byte forced value"),
                },
                occurrence: NodeOccurrencePolicy::Every,
            }),
        )
        .expect("persistent stuck-bit contract"),
    );
    action
}

fn ledger_receipt(
    action: &ResolvedBindingAction,
    command_sequence: u64,
) -> Vec<(ContentHash, CommittedQemuActionEvidence)> {
    vec![(
        action.id(),
        CommittedQemuActionEvidence {
            command_sequence,
            command_kind: crucible_shmem::FaultCommandKind::MemoryAccessTransform as u16,
            before_hash: [1; 32],
            after_hash: [2; 32],
        },
    )]
}

fn parent_continuation(
    plan: &FaultSignalPlan,
    seed: ContentHash,
    action: &ResolvedBindingAction,
) -> ProductionFaultRuntimeCheckpoint {
    let mut nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan.clone(),
        None,
        SignalBoundarySnapshot::default(),
        seed,
        test_host_manifests(),
        &nodes,
    )
    .expect("existing host runtime fixture");

    runtime
        .update_qemu_action_ledger(std::slice::from_ref(action), ledger_receipt(action, 1))
        .expect("bounded modeled commit enters production ledger");
    runtime
        .checkpoint(&mut nodes)
        .expect("settled host ledger can checkpoint")
}

fn restored_host_branch(
    plan: &FaultSignalPlan,
    seed: ContentHash,
    checkpoint: &ProductionFaultRuntimeCheckpoint,
) -> ProductionFaultRuntime {
    let bytes = checkpoint.to_canonical_bytes().expect("canonical parent");
    let decoded = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, plan, seed)
        .expect("authenticated host continuation");
    assert_eq!(decoded.id(), checkpoint.id());

    ProductionFaultRuntime::restore(
        plan.clone(),
        None,
        seed,
        decoded,
        test_host_manifests(),
        &mut QemuNodeSet::new(),
    )
    .expect("production host restore")
}

fn has_active_rule(runtime: &ProductionFaultRuntime, action: &ResolvedBindingAction) -> bool {
    runtime
        .qemu_active_rule_ids
        .iter()
        .any(|identity| *identity == action.id())
}

#[test]
fn persistent_memory_rule_restores_into_two_independent_host_branches() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"persistent-memory-host-continuation");
    let action = persistent_memory_rule();
    let parent = parent_continuation(&plan, seed, &action);
    let mut first = restored_host_branch(&plan, seed, &parent);
    let mut second = restored_host_branch(&plan, seed, &parent);

    assert!(has_active_rule(&first, &action));
    assert!(has_active_rule(&second, &action));
    assert_eq!(first.qemu_action_commits, second.qemu_action_commits);
    assert_ne!(
        first
            .qemu_issued_actions
            .get(&action.id())
            .expect("first issued rule")
            .binding
            .as_str()
            .as_ptr(),
        second
            .qemu_issued_actions
            .get(&action.id())
            .expect("second issued rule")
            .binding
            .as_str()
            .as_ptr(),
        "restored branches own independent mutable ledgers"
    );
    drop(parent);

    let mut removal = action.clone();
    removal.kind = BindingActionKind::RemovePersistent;
    removal.transition_sequence += 1;
    first
        .update_qemu_action_ledger(std::slice::from_ref(&removal), ledger_receipt(&removal, 2))
        .expect("first branch legally removes its rule");

    assert!(!has_active_rule(&first, &action));
    assert!(has_active_rule(&second, &action));
    assert_eq!(first.qemu_issued_actions.get(&action.id()), Some(&action));
    assert_eq!(second.qemu_issued_actions.get(&action.id()), Some(&action));
    let removed = first
        .checkpoint(&mut QemuNodeSet::new())
        .expect("removed rule history can checkpoint");
    let retained = second
        .checkpoint(&mut QemuNodeSet::new())
        .expect("other branch still checkpoints its active rule");
    assert_ne!(removed.id(), retained.id());

    let mut restored_removed = restored_host_branch(&plan, seed, &removed);
    assert!(!has_active_rule(&restored_removed, &action));
    assert_eq!(
        restored_removed.qemu_issued_actions.get(&action.id()),
        Some(&action)
    );
    assert!(
        restored_removed
            .update_qemu_action_ledger(std::slice::from_ref(&removal), ledger_receipt(&removal, 3))
            .is_err(),
        "restore must not reactivate a removed rule"
    );
    second
        .update_qemu_action_ledger(std::slice::from_ref(&removal), ledger_receipt(&removal, 2))
        .expect("the independent retained branch still permits its first removal");
}

#[test]
fn equal_declared_projection_cannot_authenticate_different_memory_rule_state() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"memory-controller-identity");
    let action = persistent_memory_rule();
    let parent = parent_continuation(&plan, seed, &action);
    let mut branch = restored_host_branch(&plan, seed, &parent);
    let mut removal = action.clone();
    removal.kind = BindingActionKind::RemovePersistent;
    removal.transition_sequence += 1;
    branch
        .update_qemu_action_ledger(std::slice::from_ref(&removal), ledger_receipt(&removal, 2))
        .expect("remove changes only this controller continuation");
    let removed = branch
        .checkpoint(&mut QemuNodeSet::new())
        .expect("removed controller checkpoint");

    // The equal projection is a declared fixture input, not an observed RAM
    // root or a live QEMU owner. Authentication must also bind rule history.
    let node = NodeId {
        name: String::from("node-a"),
    };
    let projection = ContentHash::from_bytes(b"unchanged declared projection");
    let active = parent
        .with_unvalidated_test_node(&plan, node.clone(), projection)
        .expect("bounded synthetic projection");
    let mut removed = removed
        .with_unvalidated_test_node(&plan, node.clone(), projection)
        .expect("same bounded synthetic projection");
    assert_eq!(
        active.qemu_fingerprint(&node),
        removed.qemu_fingerprint(&node)
    );
    assert_ne!(active.id(), removed.id());

    let bytes = removed
        .to_canonical_bytes()
        .expect("removed continuation bytes");
    let decoded = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed)
        .expect("removed continuation authenticates under its own identity");
    assert_eq!(decoded, removed);

    removed.identity = active.id();
    let wrong_basis = removed
        .to_canonical_bytes()
        .expect("encode mismatched identity fixture");
    assert!(matches!(
        ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&wrong_basis, &plan, seed),
        Err(ProductionFaultRuntimeCheckpointCodecError::Invalid)
    ));
}
