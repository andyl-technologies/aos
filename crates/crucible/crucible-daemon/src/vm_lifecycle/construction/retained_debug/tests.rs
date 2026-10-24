//! Negative authority and pure ownership controls for candidate handback.
//!
//! No test produces a successful Main, native World or replay receipt. History
//! fixtures below carry actual files and diagnostics only; they exercise moves
//! and refusal restoration without attesting physical or native completion.

use super::super::custody::FailureStorage;
use super::*;
use crate::LifecycleHistoryRef;
use std::error::Error;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, thiserror::Error)]
#[error("actual component file {marker}")]
struct FileCause {
    file: File,
    marker: &'static str,
    drops: Arc<AtomicUsize>,
}

impl Drop for FileCause {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct FileProbe {
    cause: *const FileCause,
    descriptor: i32,
    identity: (u64, u64),
    drops: Arc<AtomicUsize>,
}

impl FileProbe {
    fn assert_open(&self) {
        let current = fs::metadata(format!("/proc/self/fd/{}", self.descriptor)).unwrap();
        assert_eq!((current.dev(), current.ino()), self.identity);
        assert_eq!(self.drops.load(Ordering::SeqCst), 0);
    }

    fn assert_first(&self, first: &LifecycleApiError) {
        let LifecycleApiError::ConfigurationCopy(error) = first else {
            panic!("the original typed constructor refusal was replaced");
        };
        let actual = error.source().unwrap().downcast_ref::<FileCause>().unwrap();
        assert_eq!(std::ptr::from_ref(actual), self.cause);
        self.assert_open();
    }

    fn assert_history(&self, body: &ProductionVmConstructionPostBody) {
        let mut found = false;
        body.visit_history(|_, record| {
            if let LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::SourceCleanup(
                history,
            )) = record
            {
                history.visit_history(|_, record| {
                    if let LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::Realization(
                        crucible_qemu_host::QemuVmRealizationError::ModelCopy { source },
                    )) = record
                    {
                        let actual = source.downcast_ref::<FileCause>().unwrap();
                        if std::ptr::from_ref(actual) == self.cause {
                            found = true;
                        }
                    }
                });
            }
        });
        assert!(
            found,
            "the original file-owning cause must remain reachable"
        );
        self.assert_open();
    }
}

fn file_cause(marker: &'static str) -> (Box<FileCause>, FileProbe) {
    let cause = Box::new(FileCause {
        file: tempfile::tempfile().unwrap(),
        marker,
        drops: Arc::new(AtomicUsize::new(0)),
    });
    let metadata = cause.file.metadata().unwrap();
    let probe = FileProbe {
        cause: std::ptr::from_ref(cause.as_ref()),
        descriptor: cause.file.as_raw_fd(),
        identity: (metadata.dev(), metadata.ino()),
        drops: Arc::clone(&cause.drops),
    };
    (cause, probe)
}

fn constructor_first(marker: &'static str) -> (LifecycleApiError, FileProbe) {
    let (cause, mut probe) = file_cause(marker);
    // DecodeAdmissionError owns the concrete cause; retain its final address.
    let first = LifecycleApiError::ConfigurationCopy(
        crucible_engine::owned_decode::DecodeAdmissionError::new(*cause),
    );
    let LifecycleApiError::ConfigurationCopy(error) = &first else {
        unreachable!();
    };
    probe.cause = std::ptr::from_ref(error.source().unwrap().downcast_ref::<FileCause>().unwrap());
    (first, probe)
}

fn loop_without_authority() -> crate::ProductionVmLifecycleLoop {
    let source = crucible_engine::crash_restart_scenario().unwrap().scenario;
    crate::vm_lifecycle::runtime::tests::production_loop_without_backends(&source)
}

#[test]
fn body_only_cleanup_cannot_clear_the_original_failed_candidate() {
    let (first, probe) = constructor_first("unpublished body");
    let custody = Box::new(crate::ProductionVmConstructionCustody::new());
    let address = std::ptr::from_ref(custody.as_ref());
    // This empty component body really closes, but has no Main reservation.
    custody.retry_cleanup().unwrap();
    let mut lifecycle = loop_without_authority();
    *lifecycle.retained_debug_construction.get_mut().unwrap() =
        Some(RetainedDebugConstruction::new(custody.into_failure(first)));

    for _ in 0..2 {
        assert!(lifecycle.retry_retained_debug_construction().is_err());
        let retained = lifecycle.retained_debug_construction.get_mut().unwrap();
        let Some(RetainedDebugConstruction::Unpublished(Some(failure))) = retained else {
            panic!("body-only success cannot consume the owning failure");
        };
        let FailureStorage::Preallocated(custody) = &failure.storage else {
            panic!("the original carrier must remain in its prepaid slot");
        };
        assert_eq!(std::ptr::from_ref(custody.as_ref()), address);
        probe.assert_first(failure.first_error().unwrap());
    }
    drop(lifecycle);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

struct FileOwner {
    _file: File,
    cleanup_calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl crucible_control_api::ProductionVmCleanupOwner for FileOwner {
    type Failure = CleanupError;
    type PostBody = ProductionVmConstructionPostBody;

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
        panic!("unavailable publication cannot run the original body");
    }

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        panic!("unavailable publication cannot extract native obligations");
    }
}

impl Drop for FileOwner {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn refused_original_receiver_keeps_the_same_pair_and_typed_first() {
    let (first, probe) = constructor_first("refused receiver");
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let reservation =
        crate::lifecycle_cleanup::LifecycleCleanupHandle::unavailable_reservation_for_test();
    let owner: Box<
        dyn crucible_control_api::ProductionVmCleanupOwner<
                Failure = CleanupError,
                PostBody = ProductionVmConstructionPostBody,
            >,
    > = Box::new(FileOwner {
        _file: tempfile::tempfile().unwrap(),
        cleanup_calls: Arc::clone(&cleanup_calls),
        drops: Arc::clone(&drops),
    });
    let token = std::ptr::from_ref(reservation.as_ref()).cast::<()>();
    let body = std::ptr::from_ref(owner.as_ref()).cast::<()>();
    let mut lifecycle = loop_without_authority();
    *lifecycle.retained_debug_construction.get_mut().unwrap() = Some(
        RetainedDebugConstruction::new(ProductionVmConstructionFailure {
            storage: FailureStorage::Rejected {
                first,
                returned: std::sync::Mutex::new(Some((reservation, owner))),
            },
            additional: None,
        }),
    );

    for _ in 0..2 {
        assert!(lifecycle.retry_retained_debug_construction().is_err());
        let retained = lifecycle.retained_debug_construction.get_mut().unwrap();
        let Some(RetainedDebugConstruction::Unpublished(Some(failure))) = retained else {
            panic!("the actual refused pair cannot be discarded");
        };
        let FailureStorage::Rejected { first, returned } = &failure.storage else {
            panic!("the same canonical pair must remain owned");
        };
        let returned = returned.lock().unwrap();
        let (reservation, owner) = returned.as_ref().unwrap();
        assert_eq!(std::ptr::from_ref(reservation.as_ref()).cast::<()>(), token);
        assert_eq!(std::ptr::from_ref(owner.as_ref()).cast::<()>(), body);
        probe.assert_first(first);
        assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(lifecycle);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_carrier_keeps_the_actual_incoming_file_owner() {
    let file = tempfile::tempfile().unwrap();
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata().unwrap();
    let identity = (metadata.dev(), metadata.ino());
    let mut failure = super::super::custody::with_inputs(
        Box::new(crate::vm_lifecycle::node_launcher::PackagedProductionVmNodeLauncher),
        None,
        None,
        None,
        Vec::new(),
    )
    .unwrap_err();
    let FailureStorage::Missing(missing) = &mut failure.storage else {
        panic!("the component launcher supplies no construction carrier");
    };
    missing
        .partial
        .get_mut()
        .unwrap()
        .retained_hot_fork_disk_files
        .push(file);
    let mut lifecycle = loop_without_authority();
    *lifecycle.retained_debug_construction.get_mut().unwrap() =
        Some(RetainedDebugConstruction::new(failure));

    assert!(lifecycle.retry_retained_debug_construction().is_err());
    let retained = lifecycle.retained_debug_construction.get_mut().unwrap();
    let Some(RetainedDebugConstruction::Unpublished(Some(failure))) = retained else {
        panic!("a missing carrier must retain the complete incoming body");
    };
    let FailureStorage::Missing(missing) = &mut failure.storage else {
        panic!("the original missing-carrier owner must remain reachable");
    };
    assert_eq!(
        missing
            .partial
            .get_mut()
            .unwrap()
            .retained_hot_fork_disk_files
            .len(),
        1
    );
    let current = fs::metadata(format!("/proc/self/fd/{descriptor}")).unwrap();
    assert_eq!((current.dev(), current.ino()), identity);
    drop(lifecycle);
}

#[test]
fn additional_original_cause_and_poison_never_clear_the_existing_owner() {
    let (first, first_probe) = constructor_first("constructor first");
    let (additional, additional_probe) = constructor_first("additional original");
    let mut failure = Box::new(crate::ProductionVmConstructionCustody::new()).into_failure(first);
    failure.additional = Some(additional);
    let mut lifecycle = loop_without_authority();
    *lifecycle.retained_debug_construction.get_mut().unwrap() =
        Some(RetainedDebugConstruction::new(failure));
    assert!(lifecycle.retry_retained_debug_construction().is_err());
    let retained = lifecycle.retained_debug_construction.get_mut().unwrap();
    let Some(RetainedDebugConstruction::Unpublished(Some(failure))) = retained else {
        panic!("additional cause must retain the complete original failure");
    };
    first_probe.assert_first(failure.first_error().unwrap());
    additional_probe.assert_first(failure.additional.as_ref().unwrap());

    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _same_slot = lifecycle.retained_debug_construction.lock().unwrap();
            panic!("poison only the actual retained component slot");
        }))
        .is_err()
    );
    assert!(matches!(
        lifecycle.retry_retained_debug_construction(),
        Err(ProductionVmConstructionCleanupError::Poisoned)
    ));
    first_probe.assert_open();
    additional_probe.assert_open();
    let retained = match lifecycle.retained_debug_construction.get_mut() {
        Ok(_) => panic!("the actual retained slot must remain poisoned"),
        Err(poisoned) => poisoned.into_inner(),
    };
    assert!(matches!(
        retained,
        Some(RetainedDebugConstruction::Unpublished(Some(_)))
    ));
    drop(lifecycle);
    assert_eq!(first_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(additional_probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn unavailable_canonical_receipt_preserves_both_original_history_inputs() {
    let (first, probe) = constructor_first("terminal refusal");
    let mut first = Some(first);
    let mut receipt =
        Some(crate::lifecycle_cleanup::LifecycleCleanupHandle::unavailable_handoff_for_test());
    let address = std::ptr::from_ref(receipt.as_ref().unwrap().as_ref()).cast::<()>();
    let saved_first = first.take();
    assert!(SourceCleanupHistory::take_returned_constructor(&mut first, &mut receipt).is_err());
    assert!(first.is_none());
    assert_eq!(
        std::ptr::from_ref(receipt.as_ref().unwrap().as_ref()).cast::<()>(),
        address
    );
    first = saved_first;
    let saved_receipt = receipt.take();
    assert!(SourceCleanupHistory::take_returned_constructor(&mut first, &mut receipt).is_err());
    assert!(receipt.is_none());
    probe.assert_first(first.as_ref().unwrap());
    receipt = saved_receipt;

    for _ in 0..2 {
        assert!(SourceCleanupHistory::take_returned_constructor(&mut first, &mut receipt).is_err());
        probe.assert_first(first.as_ref().unwrap());
        assert_eq!(
            std::ptr::from_ref(receipt.as_ref().unwrap().as_ref()).cast::<()>(),
            address
        );
        assert!(receipt.as_ref().unwrap().retained_post_body().is_none());
    }
    assert!(!ProductionVmConstructionPostBody::history_only().has_terminal_custody());
    receipt.take().unwrap().dispose();
    drop(first);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn occupied_history_destination_restores_the_same_actual_diagnostic_owner() {
    // Pure data movement only: these real file-owning diagnostic histories
    // contain no receipt, native loan, Main role or terminal custody.
    let (incoming, incoming_probe) = file_cause("incoming history");
    let history =
        SourceCleanupHistory::from_native(crucible_qemu_host::QemuVmRealizationError::ModelCopy {
            source: incoming,
        });
    let mut retained = RetainedDebugConstruction::History(Some(history));
    let (occupied, occupied_probe) = file_cause("occupied history");
    let mut body = ProductionVmConstructionPostBody::history_only();
    body.retain_source_history(SourceCleanupHistory::from_native(
        crucible_qemu_host::QemuVmRealizationError::ModelCopy { source: occupied },
    ))
    .unwrap();
    let mut destination = Some(body);

    assert!(retained.transfer_history(&mut destination).is_err());
    occupied_probe.assert_history(destination.as_ref().unwrap());
    incoming_probe.assert_open();
    let RetainedDebugConstruction::History(Some(history)) = &retained else {
        panic!("the refused incoming history must remain in its original slot");
    };
    let actual = history
        .source()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<FileCause>()
        .unwrap();
    assert_eq!(std::ptr::from_ref(actual), incoming_probe.cause);

    let occupied_body = destination.take().unwrap();
    retained.transfer_history(&mut destination).unwrap();
    incoming_probe.assert_history(destination.as_ref().unwrap());
    occupied_probe.assert_history(&occupied_body);
    assert!(!destination.as_ref().unwrap().has_terminal_custody());
    assert!(retained.transfer_history(&mut destination).is_err());
    drop(destination);
    drop(occupied_body);
    assert_eq!(incoming_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(occupied_probe.drops.load(Ordering::SeqCst), 1);
}
