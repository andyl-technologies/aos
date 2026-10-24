//! Checked permanent-slot and original-counter refusal controls.
//!
//! These manual account fixtures exercise the actual counter and slot code.
//! They do not authenticate a service, a cgroup or a native launch purpose.

use super::*;

fn request() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 1024,
        backing_peak_bytes: 2048,
        metadata_bytes: 256,
        cpu_slots: 1,
        task_slots: 1,
        file_descriptors: 1,
        ..HostResourceVector::default()
    }
}

#[test]
fn registry_and_native_subdivisions_share_every_original_dimension() {
    let ceiling = request();
    let registry = HostResourceVector {
        resident_peak_bytes: 512,
        metadata_bytes: 128,
        file_descriptors: 1,
        ..HostResourceVector::default()
    };
    let native = HostResourceVector {
        resident_peak_bytes: 512,
        metadata_bytes: 128,
        file_descriptors: 0,
        ..ceiling
    };

    let used = checked_assignment(HostResourceVector::default(), registry, ceiling).unwrap();
    let complete = checked_assignment(used, native, ceiling).unwrap();
    assert_eq!(complete, ceiling);

    // Resident or metadata headroom cannot donate a descriptor or task slot.
    for extra in [
        HostResourceVector {
            resident_peak_bytes: 1,
            ..HostResourceVector::default()
        },
        HostResourceVector {
            metadata_bytes: 1,
            ..HostResourceVector::default()
        },
        HostResourceVector {
            task_slots: 1,
            ..HostResourceVector::default()
        },
        HostResourceVector {
            file_descriptors: 1,
            ..HostResourceVector::default()
        },
    ] {
        assert!(checked_assignment(complete, extra, ceiling).is_err());
    }
    assert!(
        checked_assignment(
            HostResourceVector {
                metadata_bytes: u64::MAX,
                ..HostResourceVector::default()
            },
            registry,
            HostResourceVector {
                metadata_bytes: u64::MAX,
                ..ceiling
            },
        )
        .is_err()
    );
}

fn owner() -> &'static AuthenticatedProcessResources {
    let structure = crate::host_services::HostServiceBootstrap::control_bytes().unwrap();
    let bootstrap = crate::host_services::HostServiceBootstrap::new(4, 12, 4096, 1024)
        .unwrap()
        .reserve_structure(structure)
        .unwrap();
    let birth = super::super::tests::birth();
    // The fixture mirrors the permanent main slot. It deliberately retains
    // its small original account rather than refunding a failed incarnation.
    Box::leak(Box::new(birth.publish_original_process(bootstrap).unwrap()))
}

#[test]
fn request_requires_full_finite_dimensions_without_minting_backing() {
    let valid = request();
    validate_request(valid).unwrap();
    for wrong in [
        HostResourceVector {
            resident_peak_bytes: 0,
            ..valid
        },
        HostResourceVector {
            metadata_bytes: 0,
            ..valid
        },
        HostResourceVector {
            metadata_bytes: 1025,
            ..valid
        },
        HostResourceVector {
            backing_peak_bytes: 0,
            ..valid
        },
        HostResourceVector {
            cpu_slots: 0,
            ..valid
        },
        HostResourceVector {
            task_slots: 0,
            ..valid
        },
        HostResourceVector {
            file_descriptors: 0,
            ..valid
        },
        HostResourceVector {
            staging_bytes: 1025,
            ..valid
        },
    ] {
        assert!(validate_request(wrong).is_err());
    }
}

#[test]
fn malformed_first_attempt_permanently_occupies_without_reserving_credit() {
    let owner = owner();
    assert!(
        owner
            .admit_executor_purpose(
                HostResourceVector::default(),
                HostOperationBudgets::default()
            )
            .is_err()
    );
    assert!(owner.executor_purpose.get().is_none());
    assert!(
        owner
            .admit_executor_purpose(request(), HostOperationBudgets::default())
            .is_err()
    );

    let structure = crate::host_services::HostServiceBootstrap::control_bytes().unwrap();
    let remaining = owner.reserve_resident(4, 12, 4096 - structure).unwrap();
    assert!(owner.reserve_resident(0, 0, 1).is_err());
    drop(remaining);
    assert!(owner.reserve_metadata(1024 - structure).is_ok());
}

#[test]
fn ordinary_main_has_no_executor_family_or_renewable_attempt() {
    let owner = owner();
    assert!(owner.retain_executor_family().is_err());
    assert!(
        owner
            .admit_executor_purpose(request(), HostOperationBudgets::default())
            .is_err()
    );
    assert!(owner.executor_purpose.get().is_none());
    assert!(
        owner
            .admit_executor_purpose(request(), HostOperationBudgets::default())
            .is_err()
    );
}

#[test]
fn existing_resource_exhaustion_keeps_its_typed_cause() {
    let owner = owner();
    let structure = crate::host_services::HostServiceBootstrap::control_bytes().unwrap();
    let _sqlite_or_runtime = owner.reserve_resident(4, 12, 4096 - structure).unwrap();
    let refusal = owner.reserve_resident(1, 0, 0).err().unwrap();

    assert!(matches!(
        ServiceBirthError::from(refusal),
        ServiceBirthError::Resource(_)
    ));
}

#[test]
fn native_preparation_requires_actual_shared_outer_running_class() {
    let root = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(30)),
    )
    .unwrap();
    let nested = root
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    let preparation = nested.begin(HostOperationClass::Preparation).unwrap();
    verify_preparation(&root, &preparation).unwrap();
    let page_in = nested.begin(HostOperationClass::PageIn).unwrap();
    assert!(matches!(
        verify_preparation(&root, &page_in),
        Err(ServiceBirthError::Supervision(
            crate::host_supervision::HostSupervisionError::InvalidBudget
        ))
    ));
    let other = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(30)),
    )
    .unwrap();
    let foreign = other.begin(HostOperationClass::Preparation).unwrap();
    assert!(matches!(
        verify_preparation(&root, &foreign),
        Err(ServiceBirthError::Policy(_))
    ));
    preparation.complete().unwrap();
    assert!(verify_preparation(&root, &preparation).is_err());
}

#[test]
fn native_preparation_retains_cancellation_before_identity_refusal() {
    let root = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(30)),
    )
    .unwrap();
    let foreign = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(30)),
    )
    .unwrap();
    let preparation = foreign.begin(HostOperationClass::Preparation).unwrap();
    foreign.cancel().unwrap();

    assert!(matches!(
        verify_preparation(&root, &preparation),
        Err(ServiceBirthError::Supervision(
            crate::host_supervision::HostSupervisionError::Terminal {
                state: crate::host_supervision::HostOperationState::Canceled
            }
        ))
    ));
}
