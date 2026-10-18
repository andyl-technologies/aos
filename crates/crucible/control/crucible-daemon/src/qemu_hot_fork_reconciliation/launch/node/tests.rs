//! Local row/identity/file-custody controls without an issuable resource guard.

use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicUsize, Ordering};

// This type has no values. Geometry and vacant metadata can be exercised, but
// these controls cannot fabricate a Source, resource owner or native operation.
enum NeverBornGuard {}

impl crate::QemuAttemptOperationalBoundary for NeverBornGuard {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        match *self {}
    }

    fn cancellation(&self) -> &crate::ExecutionCancellation {
        match *self {}
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        match *self {}
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        match *self {}
    }
}

impl crate::QemuAttemptResourceGuard for NeverBornGuard {
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        match *self {}
    }

    fn quarantine(&mut self) {
        match *self {}
    }
}

type Row = TargetNodeConstruction<NeverBornGuard>;

#[test]
fn selected_row_geometry_prices_the_actual_payload_and_names() {
    let nodes = [
        NodeId {
            name: String::from("east"),
        },
        NodeId {
            name: String::from("west"),
        },
    ];
    let measured = Row::control_bytes(nodes.iter()).unwrap();
    assert_eq!(measured, (2 * std::mem::size_of::<Row>() + 16) as u64);
    assert!(Row::control_bytes(std::iter::empty()).is_err());
    assert!(Row::control_bytes([&nodes[1], &nodes[0]].into_iter()).is_err());
    assert!(Row::control_bytes([&nodes[0], &nodes[0]].into_iter()).is_err());
}

#[test]
fn identical_names_do_not_authorize_return_to_another_registry() {
    let nodes = [NodeId {
        name: String::from("same"),
    }];
    let original = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let foreign = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let rows = Row::prepare(nodes.iter(), &original).unwrap();

    assert!(rows[0].belongs_to(&original.selection()));
    assert!(!rows[0].belongs_to(&foreign.selection()));
    assert!(rows[0].is_vacant());
}

#[test]
fn launch_timing_evidence_requires_the_complete_live_roster_and_fresh_epoch() {
    use crate::ProductionVmHotForkNodeServiceState::{PermanentlyFailed, PoweredOff, Running};

    let nodes = ["east", "failed", "west"].map(|name| NodeId {
        name: name.to_owned(),
    });
    let registry = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut rows = Row::prepare(nodes.iter(), &registry).unwrap();
    for (row, state) in rows
        .iter_mut()
        .zip([Running, PermanentlyFailed, PoweredOff])
    {
        assert!(row.bind_boundary(state, 1));
    }

    rows[0].launch_nanoseconds = Some(10);
    rows[0].record_world_adoption();
    assert_eq!(Row::launch_timing_summary(&rows), None);
    rows[2].launch_nanoseconds = Some(7);
    assert_eq!(Row::launch_timing_summary(&rows), None);

    rows[2].record_world_adoption();
    assert_eq!(Row::launch_timing_summary(&rows), Some((17, 10)));
    rows[1].launch_nanoseconds = Some(u64::MAX);
    assert_eq!(Row::launch_timing_summary(&rows), Some((17, 10)));

    rows[0].launch_nanoseconds = Some(u64::MAX);
    assert_eq!(Row::launch_timing_summary(&rows), None);

    assert!(rows[0].reset_returned());
    assert!(rows[0].bind_boundary(Running, 2));
    rows[0].record_world_adoption();
    assert_eq!(Row::launch_timing_summary(&rows), None);
}

struct PanicFile {
    _file: std::fs::File,
    closed: Arc<AtomicUsize>,
}

impl Drop for PanicFile {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

fn identity(file: &std::fs::File) -> (u64, u64) {
    let metadata = file.metadata().unwrap();
    (metadata.dev(), metadata.ino())
}

fn observes(fd: i32, expected: (u64, u64)) -> bool {
    std::fs::metadata(format!("/proc/self/fd/{fd}"))
        .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == expected)
}

#[test]
fn independent_worker_panics_keep_both_actual_file_owners_until_row_destruction() {
    let nodes = [
        NodeId {
            name: String::from("east"),
        },
        NodeId {
            name: String::from("west"),
        },
    ];
    let registry = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut rows = Row::prepare(nodes.iter(), &registry).unwrap();
    let first = tempfile::tempfile().unwrap();
    let second = tempfile::tempfile().unwrap();
    let descriptors = [
        (first.as_raw_fd(), identity(&first)),
        (second.as_raw_fd(), identity(&second)),
    ];
    let closed = Arc::new(AtomicUsize::new(0));

    rows[0].record_worker_panic(Box::new(PanicFile {
        _file: first,
        closed: Arc::clone(&closed),
    }));
    rows[1].record_worker_panic(Box::new(PanicFile {
        _file: second,
        closed: Arc::clone(&closed),
    }));

    assert!(
        rows.iter()
            .all(|row| row.worker_panic().unwrap().is::<PanicFile>())
    );
    assert!(rows.iter_mut().all(|row| !row.reset_returned()));
    assert!(
        descriptors
            .iter()
            .all(|(fd, expected)| observes(*fd, *expected))
    );
    assert_eq!(closed.load(Ordering::SeqCst), 0);

    drop(rows);

    assert_eq!(closed.load(Ordering::SeqCst), 2);
    assert!(
        descriptors
            .iter()
            .all(|(fd, expected)| !observes(*fd, *expected))
    );
}

#[test]
fn retained_row_history_keeps_both_launch_and_cleanup_causes() {
    let nodes = [NodeId {
        name: String::from("same"),
    }];
    let registry = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut rows = Row::prepare(nodes.iter(), &registry).unwrap();
    rows[0].first = Some(LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(
        QemuHotForkLaunchError::Rejected {
            source: QemuNodeChannelError::new("component launch", "original launch refusal"),
        },
    ));
    let cleanup = String::from("independent cleanup refusal");
    let allocation = cleanup.as_ptr();
    rows[0].first_rollback = Some(QemuVmRealizationError::Executor {
        operation: "component cleanup",
        message: cleanup,
    });

    assert!(rows[0].has_history());
    let rendered = format!("{:?}", rows[0].history());
    assert!(rendered.contains("original launch refusal"));
    assert!(rendered.contains("independent cleanup refusal"));
    assert!(!rows[0].reset_returned());
    let Some(QemuVmRealizationError::Executor { message, .. }) = &rows[0].first_rollback else {
        panic!("the actual typed cleanup cause was lost");
    };
    assert_eq!(message.as_ptr(), allocation);
}

#[test]
fn preborn_exchange_refuses_foreign_origin_and_keeps_actual_payload() {
    let nodes = [NodeId {
        name: String::from("same"),
    }];
    let original = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let foreign = crate::QemuAttemptGenerationStorage::prepare(nodes.iter()).unwrap();
    let mut scratch = Row::prepare(nodes.iter(), &original).unwrap();
    let mut retained = Row::prepare(nodes.iter(), &original).unwrap();
    let mut wrong = Row::prepare(nodes.iter(), &foreign).unwrap();
    let file = tempfile::tempfile().unwrap();
    let descriptor = file.as_raw_fd();
    let expected = identity(&file);
    let closed = Arc::new(AtomicUsize::new(0));
    scratch[0].record_worker_panic(Box::new(PanicFile {
        _file: file,
        closed: Arc::clone(&closed),
    }));

    assert!(!Row::exchange_preborn(&mut scratch, &mut wrong));
    assert!(scratch[0].worker_panic().unwrap().is::<PanicFile>());
    assert!(wrong[0].is_vacant());
    assert!(observes(descriptor, expected));
    assert_eq!(closed.load(Ordering::SeqCst), 0);

    assert!(Row::exchange_preborn(&mut scratch, &mut retained));
    assert!(scratch[0].is_vacant());
    assert!(retained[0].worker_panic().unwrap().is::<PanicFile>());
    assert!(!Row::exchange_preborn(&mut scratch, &mut retained));
    assert!(observes(descriptor, expected));
    drop(scratch);
    assert_eq!(closed.load(Ordering::SeqCst), 0);

    drop(retained);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(!observes(descriptor, expected));
}
