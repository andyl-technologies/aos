//! Actual closed native callback priority and complete linear storage failures.

use super::*;

mod sqlite_scope;
use crucible::BackendOperationalFailureKind;
use crucible_linux_resource::host_supervision::{HostOperationClass, HostSupervisionError};

#[test]
fn first_original_supervision_and_full_storage_failure_survive_repeated_polls() {
    let mut calls = 0;
    let error = read_with_boundary(
        &mut || {
            calls += 1;
            Err(QemuRamReadBoundaryError::Supervision(
                HostSupervisionError::DeadlineExpired {
                    operation_id: 41,
                    class: HostOperationClass::PageIn,
                },
            ))
        },
        |boundary| {
            assert!(matches!(boundary(), Err(RamStoreError::Canceled)));
            assert!(matches!(boundary(), Err(RamStoreError::Canceled)));
            Err::<(), _>(RamStoreError::Invalid("complete original storage failure"))
        },
    )
    .expect_err("complete storage error remains alongside first original supervisor failure");

    assert_eq!(calls, 1);
    assert!(matches!(
        error,
        QemuRamSourceError::RamBackingFailure {
            kind: BackendOperationalFailureKind::Expired,
            first: Some(QemuRamReadBoundaryError::Supervision(
                HostSupervisionError::DeadlineExpired {
                    operation_id: 41,
                    class: HostOperationClass::PageIn,
                }
            )),
            source: RamStoreError::Invalid("complete original storage failure"),
        }
    ));
}

#[test]
fn direct_canceled_marker_returns_original_boundary_without_storage_wrapper() {
    let error = read_with_boundary(
        &mut || Err(QemuRamReadBoundaryError::Canceled),
        |boundary| boundary(),
    )
    .expect_err("original cancellation wins direct marker");

    assert!(matches!(error, QemuRamSourceError::Canceled));
}

#[test]
fn healthy_page_keeps_original_poll_count_and_value() {
    let mut calls = 0;
    let page = read_with_boundary(
        &mut || {
            calls += 1;
            Ok(())
        },
        |boundary| {
            boundary()?;
            boundary()?;
            boundary()?;
            Ok(17)
        },
    )
    .expect("ordinary page accepted");

    assert_eq!(page, 17);
    assert_eq!(calls, 3);
}

#[test]
fn storage_only_failure_remains_the_complete_typed_ram_error() {
    let error = read_with_boundary(&mut || Ok(()), |_| {
        Err::<(), _>(RamStoreError::Invalid("original"))
    })
    .expect_err("storage-only original retained");

    assert!(matches!(
        error,
        QemuRamSourceError::RamBackingFailure {
            first: None,
            source: RamStoreError::Invalid("original"),
            ..
        }
    ));
}
