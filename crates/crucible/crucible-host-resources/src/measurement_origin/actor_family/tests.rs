//! Exercises bounded identity and control reads without issuing an actor purpose.

use super::*;
use std::io::Write;

#[test]
fn directory_identity_distinguishes_a_real_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("workload");
    std::fs::create_dir(&path).unwrap();
    let original = File::open(&path).unwrap();

    std::fs::rename(&path, root.path().join("retained")).unwrap();
    std::fs::create_dir(&path).unwrap();
    let replacement = File::open(&path).unwrap();

    assert!(require_same_directory(&original, &original).is_ok());
    assert!(matches!(
        require_same_directory(&original, &replacement),
        Err(MeasurementOriginError::Authentication(
            "actor family directory identity"
        ))
    ));
}

#[test]
fn control_reads_require_complete_exact_membership() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let path = root.path().join("membership");
    std::fs::write(&path, MEMBERSHIP).unwrap();
    assert!(require_control(&directory, "membership", MEMBERSHIP).is_ok());

    for wrong in [
        b"0::/crucible-measurement-actor/workload\n".as_slice(),
        b"0::/crucible-measurement-actor/guardian-other\n",
        b"0::/crucible-measurement-actor/guardian\ntrailing\n",
        b"0::/crucible-measurement-actor/guardian",
        b"",
    ] {
        std::fs::write(&path, wrong).unwrap();
        assert!(matches!(
            require_control(&directory, "membership", MEMBERSHIP),
            Err(MeasurementOriginError::Authentication(
                "actor family control or membership"
            ))
        ));
    }
}

#[test]
fn control_extent_refuses_before_accepting_a_matching_prefix() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let mut file = File::create(root.path().join("control")).unwrap();
    file.write_all(MEMBERSHIP).unwrap();
    file.write_all(&[b'x'; MAX_CONTROL_BYTES]).unwrap();
    drop(file);

    assert!(matches!(
        require_control(&directory, "control", MEMBERSHIP),
        Err(MeasurementOriginError::Authentication(
            "actor family control extent"
        ))
    ));
}

#[test]
fn control_missing_and_symlink_fail_as_initiating_io() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    assert!(matches!(
        require_control(&directory, "missing", b""),
        Err(MeasurementOriginError::Kernel(_))
    ));

    std::fs::write(root.path().join("target"), b"0\n").unwrap();
    std::os::unix::fs::symlink("target", root.path().join("alias")).unwrap();
    assert!(matches!(
        require_control(&directory, "alias", b"0\n"),
        Err(MeasurementOriginError::Kernel(_))
    ));
}

#[test]
fn ordinary_directory_cannot_become_a_cgroup_family() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    assert!(matches!(
        open_directory(&directory, "."),
        Err(MeasurementOriginError::Authentication(
            "actor family cgroup filesystem"
        ))
    ));
}

#[test]
fn shared_owner_extent_includes_the_real_header_and_body() {
    let extent = AuthenticatedActorFamily::shared_control_extent().unwrap();
    assert!(extent > AuthenticatedActorFamily::control_extent());
    assert_eq!(AuthenticatedActorFamily::descriptor_peak(), 4);
}

#[test]
fn original_cancellation_remains_typed_at_the_family_cut() {
    use crate::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
        HostSupervisionError,
    };
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    assert!(check_original(&original).is_ok());

    supervisor.cancel().unwrap();

    assert!(matches!(
        check_original(&original),
        Err(MeasurementOriginError::OriginalOperation(
            HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
                ..
            }
        ))
    ));
}
