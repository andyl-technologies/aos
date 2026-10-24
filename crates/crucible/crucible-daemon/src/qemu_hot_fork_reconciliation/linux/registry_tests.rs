//! Checks registry sharing without constructing a native guard or child.

use super::*;

type ComponentRegistry = LinuxQemuHotForkWorldReconciliationSet<
    crate::ComposedQemuAttemptResourceGuard<crate::LinuxQemuAttemptHostResourceOwner>,
>;

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

#[test]
fn every_child_handle_aliases_the_same_expected_membership_and_registry() {
    let selected = [node("a"), node("b")];
    let registry = ComponentRegistry::new(selected.into_iter().collect());
    let first = registry.clone();
    let second = registry.clone();

    assert!(Arc::ptr_eq(&registry.state, &first.state));
    assert!(Arc::ptr_eq(&registry.state, &second.state));
    let state = registry.state.lock().unwrap();
    let original_name = state.expected.first().unwrap().name.as_ptr();
    drop(state);
    let state = first.state.lock().unwrap();
    assert_eq!(state.expected.first().unwrap().name.as_ptr(), original_name);
    assert_eq!(state.expected.len(), 2);
    assert!(state.reconciliations.is_empty());
    drop(state);

    // Metadata handles alone supply no adoption, shutdown or native receipt.
    assert!(registry.validate_operational_handoff().is_err());
    assert!(first.validate_operational_handoff().is_err());
    assert!(second.validate_operational_handoff().is_err());
}

#[test]
fn poisoned_membership_cannot_be_replaced_by_an_unpoisoned_cloned_snapshot() {
    let registry = ComponentRegistry::new([node("a")].into_iter().collect());
    let alias = registry.clone();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _same_registry = registry.state.lock().unwrap();
        panic!("poison the actual shared component registry");
    }));

    assert!(failed.is_err());
    assert!(registry.validate_operational_handoff().is_err());
    assert!(alias.validate_operational_handoff().is_err());
    let state = match registry.state.lock() {
        Ok(_) => panic!("the actual shared registry must retain its poison"),
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(state.expected.len(), 1);
    assert!(state.reconciliations.is_empty());
}

#[test]
fn missing_child_receipts_never_advance_shared_expected_membership() {
    let registry = ComponentRegistry::new([node("a"), node("b")].into_iter().collect());
    let mut driver = registry.clone();

    for _ in 0..2 {
        assert!(
            driver
                .reconcile_execution_disposition(crate::AttemptExecutionDisposition::Failed,)
                .is_err()
        );
        let state = registry.state.lock().unwrap();
        assert_eq!(state.expected.len(), 2);
        assert!(state.reconciliations.is_empty());
    }
}

#[test]
fn partial_construction_transfer_requires_the_exact_unadopted_partition() {
    let selected = [node("a"), node("b")];
    let mut registry = ComponentRegistry::new(selected.iter().cloned().collect());
    let shared_address = Arc::as_ptr(&registry.state);
    let name_address = registry
        .state
        .lock()
        .unwrap()
        .expected
        .first()
        .unwrap()
        .name
        .as_ptr();

    for incorrect in [
        vec![node("a")],
        vec![node("a"), node("a"), node("b")],
        vec![node("b"), node("a")],
        vec![node("a"), node("foreign")],
    ] {
        assert!(
            registry
                .take_construction_post_body_children(incorrect.iter())
                .is_err()
        );
        assert_eq!(Arc::as_ptr(&registry.state), shared_address);
        let state = registry.state.lock().unwrap();
        assert_eq!(state.expected.first().unwrap().name.as_ptr(), name_address);
        assert_eq!(state.expected.len(), 2);
        assert!(state.reconciliations.is_empty());
    }
    // A published lifecycle still requires actual receipts for every member.
    assert!(registry.take_post_body_children().is_err());

    let children = registry
        .take_construction_post_body_children(selected.iter())
        .unwrap();

    assert!(children.is_empty());
    assert_eq!(Arc::as_ptr(&registry.state), shared_address);
    assert!(registry.state.lock().unwrap().expected.is_empty());
}

#[test]
fn partial_construction_transfer_retains_the_same_registry_until_aliases_close() {
    let selected = [node("a")];
    let mut registry = ComponentRegistry::new(selected.iter().cloned().collect());
    let alias = registry.clone();

    assert!(
        registry
            .take_construction_post_body_children(selected.iter())
            .is_err()
    );
    assert_eq!(alias.state.lock().unwrap().expected.len(), 1);
    drop(alias);

    assert!(
        registry
            .take_construction_post_body_children(selected.iter())
            .unwrap()
            .is_empty()
    );
    assert!(registry.state.lock().unwrap().expected.is_empty());
}
