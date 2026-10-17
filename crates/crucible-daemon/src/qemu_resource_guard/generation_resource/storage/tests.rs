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
