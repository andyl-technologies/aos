//! Exercises selected geometry without creating a Main, Source or native loan.

use super::*;

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

#[test]
fn selection_refuses_empty_duplicate_reordered_and_excessive_nodes() {
    let selected = [node("a")];
    let source = crate::QemuAttemptGenerationStorage::prepare(selected.iter()).unwrap();
    assert!(TargetConstructionStorage::prepare(std::iter::empty(), &source).is_err());
    for names in [["a", "a"], ["b", "a"]] {
        let nodes = names.map(node);
        assert!(TargetConstructionStorage::prepare(nodes.iter(), &source).is_err());
        assert!(TargetConstructionStorage::control_bytes(nodes.iter()).is_err());
    }
    let nodes = (0..=crate::MAX_QEMU_ATTEMPT_GENERATION_NODES)
        .map(|index| node(&format!("node-{index:08}")))
        .collect::<Vec<_>>();
    assert!(TargetConstructionStorage::control_bytes(nodes.iter()).is_err());
    assert!(
        TargetConstructionStorage::control_bytes(
            nodes[..crate::MAX_QEMU_ATTEMPT_GENERATION_NODES].iter()
        )
        .is_ok()
    );
}

#[test]
fn geometry_contains_actual_row_layout_and_every_copied_name_byte() {
    let nodes = [node("a"), node("long-second-node")];
    let expected = std::alloc::Layout::array::<TargetConstructionMember>(nodes.len())
        .unwrap()
        .size()
        + nodes.iter().map(|node| node.name.len()).sum::<usize>();
    #[cfg(target_os = "linux")]
    let native =
        crate::LinuxQemuAttemptHostResourceOwner::world_control_bytes(nodes.len()).unwrap();
    #[cfg(not(target_os = "linux"))]
    let native = 0;
    assert_eq!(
        TargetConstructionStorage::control_bytes(nodes.iter()).unwrap(),
        expected as u64
            + crate::QemuAttemptGenerationStorage::control_bytes(nodes.iter()).unwrap()
            + native,
    );

    let source = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let storage = TargetConstructionStorage::prepare(nodes.iter(), &source).unwrap();
    drop(nodes);
    assert_eq!(storage.members.len(), 2);
    assert_eq!(storage.members[0].node.name, "a");
    assert_eq!(storage.members[1].node.name, "long-second-node");
    assert!(storage.members.iter().all(|row| !row.entered));
    assert!(storage.can_restore_to_source());
    #[cfg(target_os = "linux")]
    assert!(
        storage.members.iter().all(|row| row.permit.is_none()
            && row.cleanup.is_none()
            && row.first_cleanup.is_none())
    );
}

#[test]
fn identity_growth_is_priced_without_changing_node_capacity() {
    let short = [node("a")];
    let long = [node("a-longer-selected-identity")];
    let difference = TargetConstructionStorage::control_bytes(long.iter()).unwrap()
        - TargetConstructionStorage::control_bytes(short.iter()).unwrap();
    // The Target-member row and generation row each own one identity copy.
    assert_eq!(
        difference,
        2 * (long[0].name.len() - short[0].name.len()) as u64
    );
}

#[test]
fn selected_rows_cannot_be_prepared_under_another_source_selection() {
    let source_nodes = [node("source-a")];
    let foreign_nodes = [node("foreign-b")];
    let source = crate::QemuAttemptGenerationStorage::prepare(source_nodes.iter()).unwrap();
    assert!(TargetConstructionStorage::prepare(foreign_nodes.iter(), &source).is_err());
}

#[test]
fn existing_loop_registry_alias_prevents_reuse_even_for_never_issued_rows() {
    let nodes = [node("a")];
    let source = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut storage = TargetConstructionStorage::prepare(nodes.iter(), &source).unwrap();
    let existing_alias = storage.generation_storage();
    assert!(storage.can_restore_to_source());
    assert!(!storage.prepare_reuse());
    drop(existing_alias);
    assert!(storage.prepare_reuse());
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_member_refuses_before_calling_a_native_producer() {
    let nodes = [node("a")];
    let source = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut storage = TargetConstructionStorage::prepare(nodes.iter(), &source).unwrap();
    let mut calls = 0;

    let outcome = storage.prepare_member(&node("foreign"), || {
        calls += 1;
        panic!("a foreign request must not enter the actual native producer");
    });

    assert!(outcome.is_err());
    assert_eq!(calls, 0);
    assert!(!storage.members[0].entered);
    assert!(storage.can_restore_to_source());
}

#[cfg(target_os = "linux")]
#[test]
fn preoccupancy_refusal_keeps_the_same_selected_row_unissued() {
    let nodes = [node("a")];
    let source = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut storage = TargetConstructionStorage::prepare(nodes.iter(), &source).unwrap();
    let rows = storage.members.as_ptr();
    let mut calls = 0;

    for _ in 0..2 {
        let outcome = storage.prepare_member(&nodes[0], || {
            calls += 1;
            // This is a local negative transport control. It constructs no
            // native role, permit, loan, Main or accepted admission outcome.
            Err(TargetPreparationFailure::Lifecycle(
                LifecycleApiError::CleanupRetained,
            ))
        });
        assert!(matches!(
            outcome,
            Err(TargetPreparationFailure::Lifecycle(
                LifecycleApiError::CleanupRetained
            ))
        ));
        assert_eq!(storage.members.as_ptr(), rows);
        assert!(!storage.members[0].entered);
        assert!(storage.members[0].permit.is_none());
        assert!(storage.members[0].cleanup.is_none());
        assert!(storage.members[0].first_admission.is_none());
        assert!(storage.take_member_permit(&nodes[0]).is_err());
    }

    assert_eq!(calls, 2);
    assert!(storage.can_restore_to_source());
}

#[test]
fn returned_metadata_is_invalidated_before_a_new_generation_alias_is_lent() {
    let nodes = [node("a")];
    let source = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut storage = TargetConstructionStorage::prepare(nodes.iter(), &source).unwrap();

    assert!(!storage.source_return_is_prepared());
    assert!(storage.prepare_reuse());
    assert!(storage.source_return_is_prepared());
    let alias = storage.generation_storage();
    assert!(!storage.source_return_is_prepared());
    assert!(!storage.prepare_reuse());
    drop(alias);
    assert!(storage.prepare_reuse());
    assert!(storage.source_return_is_prepared());
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_disposal_rejects_unissued_entered_rows_without_a_genuine_loan() {
    let nodes = [node("a")];
    let source = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut storage = TargetConstructionStorage::prepare(nodes.iter(), &source).unwrap();
    // Deliberately corrupt local metadata; this creates no roster or Target.
    // Absence of a real loan must refuse rather than certify native return.
    storage.members[0].entered = true;

    assert!(!storage.can_restore_to_source());
    assert!(!storage.dispose_returned_history_and_reset());
    assert!(!storage.source_return_is_prepared());
    assert!(storage.members[0].entered);
}
