//! Observes original quota descriptor purposes through actual control frees.
//!
//! These tests use the existing quota service's genuine paired accounts. They
//! perform no binding I/O and establish no installed ext4 quota or retirement.

use super::*;
use crucible_linux_resource::test_support::{ControlObservation, TestAllocationObserver};

fn original_structure_bytes(binder: &LinuxProjectQuotaBinder) -> u64 {
    let projects = usize::try_from(binder.service.resources.maximum_file_descriptors() / 2)
        .unwrap_or_else(|error| panic!("original project roster: {error}"));
    let bootstrap = quota_bootstrap_bytes(BinderPublication::Value)
        .unwrap_or_else(|error| panic!("original bootstrap charge: {error}"));
    let constructor = quota_constructor_bytes(projects)
        .unwrap_or_else(|error| panic!("original constructor charge: {error}"));
    bootstrap + constructor
}

fn original_baselines(binder: &LinuxProjectQuotaBinder) -> [u64; 2] {
    let structure = original_structure_bytes(binder);
    // The existing caller separately retains the resident subset outside Rust
    // metadata. Neither the test nor the purpose grant may spend that subset.
    let caller = binder.service.resources.maximum_resident_bytes()
        - binder.service.metadata.maximum_resident_bytes();
    [structure + caller, structure]
}

fn assert_control_custody(
    records: [Option<ControlObservation>; 3],
    expected: [Option<u64>; 2],
    ordinals: [u8; 3],
) {
    for (record, ordinal) in records.into_iter().zip(ordinals) {
        let record = record.unwrap_or_else(|| panic!("actual control must close"));
        assert_eq!(record.before.original_bytes, expected);
        assert_eq!(record.after.original_bytes, expected);
        assert_eq!(record.ordinal, ordinal);
    }
}

#[test]
fn descriptor_and_paired_controls_keep_both_original_purposes_normal_and_unwind() {
    const BODY_BYTES: u64 = 128;
    for unwind in [false, true] {
        let binder = config().build().unwrap();
        let baselines = original_baselines(&binder);
        let lease_bytes = HostServiceLease::metadata_bytes();
        let charged = BODY_BYTES + 3 * lease_bytes;
        let expected = baselines.map(|baseline| Some(baseline + charged));
        let extent = lease_control_bytes().unwrap();
        let (resources, identities) = TestAllocationObserver::capture_controls([extent; 3], || {
            binder.service.reserve_descriptor_metadata(1, BODY_BYTES)
        });
        let resources = resources.unwrap();
        assert!(identities.iter().all(Option::is_some));
        assert!(
            binder
                .service
                .resources
                .reserve_resources(0, binder.service.resources.maximum_file_descriptors(), 0)
                .is_err()
        );

        let (result, records) = TestAllocationObserver::observe_controls(
            [&binder.service.resources, &binder.service.metadata],
            None,
            identities,
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _resources = resources;
                    if unwind {
                        panic!("intentional quota descriptor admission unwind");
                    }
                }))
            },
        );
        assert_eq!(result.is_err(), unwind);
        // Metadata and resident controls were published first; descriptor
        // custody closes first, then the private pair closes jointly.
        assert_control_custody(records, expected, [3, 2, 1]);
        assert!(
            binder
                .service
                .resources
                .reserve_resources(0, binder.service.resources.maximum_file_descriptors(), 0)
                .is_ok()
        );
        for (account, baseline) in [&binder.service.resources, &binder.service.metadata]
            .into_iter()
            .zip(baselines)
        {
            assert!(
                account
                    .reserve_resources(0, 0, account.maximum_resident_bytes() - baseline)
                    .is_ok()
            );
        }
    }
}

#[test]
fn final_original_operation_refusal_closes_both_controls_before_either_refund() {
    const BODY_BYTES: u64 = 128;
    let binder = config().build().unwrap();
    let baselines = original_baselines(&binder);
    let charged = BODY_BYTES + 2 * HostServiceLease::metadata_bytes();
    let operation = binder
        .service
        .supervisor
        .begin(HostOperationClass::Preparation)
        .unwrap();
    let extent = lease_control_bytes().unwrap();
    let (credit, identities) =
        TestAllocationObserver::capture_controls([extent, extent, 0], || {
            binder.service.reserve_metadata(BODY_BYTES)
        });
    let credit = credit.unwrap();
    assert!(identities[..2].iter().all(Option::is_some));
    binder.service.supervisor.cancel().unwrap();

    let (result, records) = TestAllocationObserver::observe_controls(
        [&binder.service.resources, &binder.service.metadata],
        None,
        identities,
        || credit.complete(&operation),
    );
    let Err(StoreError::Supervision { source }) = result else {
        panic!("retain the actual original cancellation");
    };
    assert!(matches!(
        source.downcast_ref::<HostSupervisionError>(),
        Some(HostSupervisionError::Terminal {
            state: crucible_linux_resource::host_supervision::HostOperationState::Canceled,
        })
    ));
    for (record, ordinal) in records[..2].iter().zip([2, 1]) {
        let record = record.unwrap();
        assert_eq!(
            record.before.original_bytes,
            baselines.map(|baseline| Some(baseline + charged))
        );
        assert_eq!(
            record.after.original_bytes,
            baselines.map(|baseline| Some(baseline + charged))
        );
        assert_eq!(record.ordinal, ordinal);
    }
    assert!(records[2].is_none());
}

#[test]
fn exhausted_metadata_precedes_invalid_descriptor_request_without_lease_publication() {
    let binder = config().build().unwrap();
    let baseline = original_structure_bytes(&binder);
    let metadata = &binder.service.metadata;
    let remaining = metadata.maximum_resident_bytes() - baseline;
    let exhaustion = metadata.reserve_resources(0, 0, remaining).unwrap();
    let extent = lease_control_bytes().unwrap();
    let (result, identities) = TestAllocationObserver::capture_controls([extent; 3], || {
        binder.service.reserve_descriptor_metadata(0, 128)
    });
    let Err(StoreError::Supervision { source }) = result else {
        panic!("retain the first actual metadata refusal");
    };
    assert_eq!(
        source.downcast_ref::<HostServiceError>(),
        Some(&HostServiceError::CapacityExhausted)
    );
    assert!(identities.iter().all(Option::is_none));
    drop(exhaustion);

    let error = binder
        .service
        .reserve_descriptor_metadata(0, 128)
        .err()
        .unwrap();
    let StoreError::Supervision { source } = error else {
        panic!("retain the actual invalid descriptor refusal after metadata recovers");
    };
    assert_eq!(
        source.downcast_ref::<HostServiceError>(),
        Some(&HostServiceError::InvalidContract)
    );
}
