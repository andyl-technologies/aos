//! Checks error ownership and actual Original posts without issuing a Main.

use super::*;
use crate::host_services::HostServiceAllocator;
use crate::host_supervision::{HostOperationBudgets, HostOperationClass, HostOperationSupervisor};

#[test]
fn refused_report_keeps_first_post_and_independent_delivery_causes() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    supervisor.cancel().unwrap();
    let post = original.wait_slice().unwrap_err();
    let mut report = NativePoolRefusal {
        cause: ServiceBirthError::Policy(String::from("original admission refusal").into()),
        after: Some(post.into()),
        _retained: None,
        world_assignment_refused: false,
    };
    let ServiceBirthError::Policy(first) = &report.cause else {
        panic!("actual first");
    };
    let first_pointer = first.as_ptr();
    let account = HostServiceAllocator::new(1, 1, 1).unwrap();
    let held = account.reserve_resources(0, 1, 0).unwrap();
    let delivery = match account.reserve_resources(0, 1, 0) {
        Err(first) => first,
        Ok(_) => panic!("the real held descriptor charge must refuse another"),
    };

    assert!(report.take_retained_world().is_none());
    report.retain_world_delivery_error(ServiceBirthError::Resource(delivery));
    report.retain_world_receiver_refusal("same preborn receiver retained its holders");

    let ServiceBirthError::Policy(first) = &report.cause else {
        panic!("same first");
    };
    assert_eq!(first.as_ptr(), first_pointer);
    assert!(
        matches!(report.after.as_ref(), Some(ServiceBirthError::Supervision(actual)) if *actual == post)
    );
    assert!(matches!(
        report.world_delivery_error(),
        Some(ServiceBirthError::Resource(_))
    ));
    assert_eq!(
        report.world_receiver_refusal(),
        Some("same preborn receiver retained its holders")
    );
    assert!(report.take_retained_world().is_none());
    assert!(!report.world_assignment_was_refused());
    assert!(account.reserve_resources(0, 1, 0).is_err());
    drop(held);
    assert!(account.reserve_resources(0, 1, 0).is_ok());
}
