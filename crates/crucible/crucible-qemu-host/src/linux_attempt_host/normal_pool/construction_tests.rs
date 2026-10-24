//! Exercises the actual admission/preparation gate with local finite Originals.
//!
//! These controls issue no Main, World or native receiver. They establish
//! admission/preparation ordering, not native custody transfer or readiness.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use std::cell::Cell;

#[test]
fn post_refusal_preserves_actual_component_cause_and_never_prepares()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor
        .begin(crucible_host_resources::host_supervision::HostOperationClass::Preparation)?;
    let prepared = Cell::new(0);
    supervisor.cancel()?;
    let post = original.wait_slice().unwrap_err();
    let receiver_seen = Cell::new(false);

    let error = complete_world_admission(
        Some(post),
        Err("component custody remains retained"),
        |first, receiver| {
            assert_eq!(receiver, Some("component custody remains retained"));
            receiver_seen.set(true);
            QemuVmRealizationError::ModelCopy {
                source: Box::new(first),
            }
        },
        || {
            prepared.set(prepared.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();

    let QemuVmRealizationError::ModelCopy { source } = error else {
        panic!("same first");
    };
    assert_eq!(
        source.downcast_ref::<crucible_host_resources::host_supervision::HostSupervisionError>(),
        Some(&post)
    );
    assert!(receiver_seen.get());
    assert_eq!(prepared.get(), 0);
    Ok(())
}

#[test]
fn positive_component_admission_prepares_once_but_refused_retention_does_not()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::host_supervision::HostSupervisionError;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor
        .begin(crucible_host_resources::host_supervision::HostOperationClass::Preparation)?;
    let prepared = Cell::new(0);
    complete_world_admission::<HostSupervisionError>(
        None,
        Ok(()),
        |_, _| panic!("no initiating failure"),
        || {
            original
                .wait_slice()
                .map_err(|source| QemuVmRealizationError::ModelCopy {
                    source: Box::new(source),
                })?;
            prepared.set(prepared.get() + 1);
            Ok(())
        },
    )?;
    assert_eq!(prepared.get(), 1);
    original.complete()?;

    let error = complete_world_admission::<HostSupervisionError>(
        None,
        Err("same receiver retained custody"),
        |_, _| panic!("no initiating failure"),
        || {
            prepared.set(prepared.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        QemuVmRealizationError::CleanupRetained {
            operation: "same receiver retained custody"
        }
    ));
    assert_eq!(prepared.get(), 1);
    Ok(())
}
