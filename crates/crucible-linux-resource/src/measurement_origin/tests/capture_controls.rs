//! Exercises actual original capture-roster identity and terminal mechanisms.
//!
//! These private mechanism fixtures do not authenticate a real PID1 producer
//! or certify complete Source, child-control, stack or physical birth payment.

use super::*;
use crate::host_services::{AdmittedHostServiceBootstrap, HostServiceBootstrap};
use crate::host_supervision::*;

fn original() -> (
    HostOperationSupervisor,
    HostOperationGuard,
    AdmittedHostServiceBootstrap,
) {
    let origin = mechanism_origin(Duration::from_millis(10), Duration::from_secs(60));
    let bootstrap = HostSupervisionBootstrap::from_measurement_origin(
        origin,
        finite_budgets(Duration::from_secs(30)),
    )
    .unwrap();
    let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
        .unwrap()
        .reserve_structure(
            HostSupervisionBootstrap::structure_bytes().unwrap()
                + HostServiceBootstrap::control_bytes().unwrap(),
        )
        .unwrap();
    let (root, preparation) = bootstrap.publish(&accounts).unwrap();
    (root, preparation, accounts)
}

#[test]
fn capture_rejects_an_equal_budget_owner_and_a_shared_outer_sibling() {
    let (root, preparation, _accounts) = original();
    let budgets = finite_budgets(Duration::from_secs(30));
    let independent = HostOperationSupervisor::new(budgets, Some(Duration::from_secs(60))).unwrap();
    let sibling = root.new_budget_owner(budgets).unwrap();
    assert!(root.shares_outer_cap(&sibling));

    for substitute in [&independent, &sibling] {
        assert!(matches!(
            preparation.begin_original_capture_supervisor(substitute, budgets),
            Err(OriginalCaptureSupervisionError::Original(
                HostSupervisionError::InvalidBudget
            ))
        ));
    }
    assert!(preparation.wait_slice().is_ok());
}

#[test]
fn capture_preserves_original_start_and_child_completion_does_not_complete_outer() {
    let (root, preparation, _accounts) = original();
    let before = root.outer_cap_binding().unwrap();
    let budgets = finite_budgets(Duration::from_secs(20));
    let child = preparation
        .begin_original_capture_supervisor(&root, budgets)
        .unwrap();
    let binding = child.outer_cap_binding().unwrap();
    assert_eq!(binding.cap_id, before.cap_id);
    assert_eq!(binding.original_monotonic_ns, before.original_monotonic_ns);
    assert_eq!(binding.allowance, before.allowance);
    assert_eq!(child.budgets().unwrap().1, budgets);

    let child_preparation = child.begin(HostOperationClass::Preparation).unwrap();
    child_preparation.complete().unwrap();
    drop(child_preparation);
    assert!(preparation.wait_slice().is_ok());
    assert!(root.verify_original_live().is_ok());

    root.cancel().unwrap();
    assert!(matches!(
        preparation.begin_original_capture_supervisor(&root, budgets),
        Err(OriginalCaptureSupervisionError::Original(
            HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            }
        ))
    ));
    assert!(child.verify_original_live().is_err());
}

#[test]
fn capture_refuses_wrong_class_and_an_unbound_private_clock() {
    let (root, _preparation, _accounts) = original();
    let setup = root.begin(HostOperationClass::Setup).unwrap();
    let budgets = finite_budgets(Duration::from_secs(30));
    assert!(matches!(
        setup.begin_original_capture_supervisor(&root, budgets),
        Err(OriginalCaptureSupervisionError::Original(
            HostSupervisionError::InvalidBudget
        ))
    ));

    let ordinary = HostOperationSupervisor::new(budgets, None).unwrap();
    let preparation = ordinary.begin(HostOperationClass::Preparation).unwrap();
    assert!(matches!(
        preparation.begin_original_capture_supervisor(&ordinary, budgets),
        Err(OriginalCaptureSupervisionError::Original(
            HostSupervisionError::InvalidBudget
        ))
    ));
}

#[test]
fn capture_keeps_actual_invalid_child_policy_as_first_refusal() {
    let (root, preparation, _accounts) = original();
    let mut budgets = finite_budgets(Duration::from_secs(30));
    budgets.classes[HostOperationClass::Setup as usize].total_timeout = Some(Duration::ZERO);

    assert!(matches!(
        preparation.begin_original_capture_supervisor(&root, budgets),
        Err(OriginalCaptureSupervisionError::Construction {
            source: HostSupervisionError::InvalidBudget,
            original: None,
        })
    ));
    assert!(preparation.wait_slice().is_ok());
}

#[test]
fn replaced_original_root_preparation_is_refused() {
    let (root, preparation, _accounts) = original();
    preparation.complete().unwrap();
    drop(preparation);
    let replacement = root.begin(HostOperationClass::Preparation).unwrap();

    assert!(matches!(
        replacement
            .begin_original_capture_supervisor(&root, finite_budgets(Duration::from_secs(30))),
        Err(OriginalCaptureSupervisionError::Original(
            HostSupervisionError::InvalidBudget
        ))
    ));
}

#[test]
fn replaced_original_child_preparation_is_refused() {
    let (root, _preparation, _accounts) = original();
    let budgets = finite_budgets(Duration::from_secs(30));
    let child = root.new_budget_owner(budgets).unwrap();
    let replacement = child.begin(HostOperationClass::Preparation).unwrap();

    assert!(matches!(
        replacement.begin_original_capture_supervisor(&child, budgets),
        Err(OriginalCaptureSupervisionError::Original(
            HostSupervisionError::InvalidBudget
        ))
    ));
}
