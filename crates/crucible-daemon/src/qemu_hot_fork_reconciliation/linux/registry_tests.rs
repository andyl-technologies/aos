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
