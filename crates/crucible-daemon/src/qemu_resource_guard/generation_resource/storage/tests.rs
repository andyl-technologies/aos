//! Pure selection and backing-geometry controls; these issue no Main authority.

use super::*;

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

#[test]
fn invalid_selection_refuses_before_any_guard_is_consumed() {
    assert!(QemuAttemptGenerationStorage::prepare(std::iter::empty()).is_err());
    let duplicate = [node("a"), node("a")];
    assert!(QemuAttemptGenerationStorage::prepare(duplicate.iter()).is_err());
    let out_of_order = [node("b"), node("a")];
    assert!(QemuAttemptGenerationStorage::prepare(out_of_order.iter()).is_err());

    let nodes = (0..=MAX_QEMU_ATTEMPT_GENERATION_NODES)
        .map(|index| node(&format!("node-{index:08}")))
        .collect::<Vec<_>>();
    assert!(QemuAttemptGenerationStorage::control_bytes(nodes.iter()).is_err());
    assert!(
        QemuAttemptGenerationStorage::control_bytes(
            nodes[..MAX_QEMU_ATTEMPT_GENERATION_NODES].iter()
        )
        .is_ok()
    );
}

#[test]
fn copied_identity_bytes_and_two_live_cells_are_in_prebirth_geometry()
-> Result<(), LifecycleApiError> {
    let short = [node("a")];
    let longer = [node("a-longer-name")];
    let short_bytes = QemuAttemptGenerationStorage::control_bytes(short.iter())?;
    let longer_bytes = QemuAttemptGenerationStorage::control_bytes(longer.iter())?;
    assert_eq!(
        longer_bytes - short_bytes,
        (longer[0].name.len() - 1) as u64
    );

    let storage = QemuAttemptGenerationStorage::prepare(longer.iter())?;
    drop(longer);
    let state = storage.generations.lock().unwrap();
    assert_eq!(state.nodes.len(), 1);
    assert_eq!(state.nodes[0].node.name, "a-longer-name");
    assert_eq!(state.nodes[0].active, [None, None]);
    assert_eq!(state.nodes[0].latest, None);
    assert!(!state.abandoned);
    assert!(short_bytes >= std::mem::size_of::<GenerationNodeState>() as u64 + 1);
    Ok(())
}

#[test]
fn nonowning_selection_matches_only_the_same_actual_registry_allocation() {
    let nodes = [node("a")];
    let source = QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let foreign = QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let selection = source.selection();
    assert!(selection.matches(&source.generations));
    assert!(!selection.matches(&foreign.generations));
    assert!(source.matches_nodes(nodes.iter()).unwrap());
    assert!(!source.matches_nodes([node("other")].iter()).unwrap());
}

#[test]
fn target_metadata_reset_requires_no_aliases_active_leases_or_abandonment() {
    let nodes = [node("a")];
    let mut storage = QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let alias = storage.lend_existing();
    assert!(!storage.reset_after_target_return());
    drop(alias);
    {
        let mut state = storage.generations.lock().unwrap();
        state.nodes[0].latest = Some(8);
        state.nodes[0].active[0] = Some(8);
    }
    assert!(!storage.reset_after_target_return());
    {
        let mut state = storage.generations.lock().unwrap();
        state.nodes[0].active[0] = None;
        state.abandoned = true;
    }
    assert!(!storage.reset_after_target_return());
    {
        let mut state = storage.generations.lock().unwrap();
        state.abandoned = false;
    }
    assert!(storage.reset_after_target_return());
    let state = storage.generations.lock().unwrap();
    assert_eq!(state.nodes[0].active, [None, None]);
    assert_eq!(state.nodes[0].latest, None);
}
