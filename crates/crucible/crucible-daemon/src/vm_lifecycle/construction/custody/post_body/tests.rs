//! Pure-data history preservation after a later containing first refuses.
//!
//! The component lifecycle has no native World or Main receipt. Its injected
//! diagnostic history exercises only the actual ownership join and cannot
//! satisfy Source return or the mandatory terminal-custody observation.

use super::*;
use crucible_control_api::ProductionVmCleanupOwner;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, thiserror::Error)]
#[error("actual nested diagnostic file")]
struct HistoryFile {
    _file: File,
    drops: Arc<AtomicUsize>,
}

impl Drop for HistoryFile {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn containing_first_refusal_keeps_the_already_moved_child_history() {
    let file = tempfile::tempfile().unwrap();
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata().unwrap();
    let identity = (metadata.dev(), metadata.ino());
    let drops = Arc::new(AtomicUsize::new(0));
    let cause = Box::new(HistoryFile {
        _file: file,
        drops: Arc::clone(&drops),
    });
    let address = std::ptr::from_ref(cause.as_ref());
    let history = crate::SourceCleanupHistory::from_native(
        crucible_qemu_host::QemuVmRealizationError::ModelCopy { source: cause },
    );
    let source = crucible_engine::crash_restart_scenario().unwrap().scenario;
    let mut lifecycle =
        crate::vm_lifecycle::runtime::tests::production_loop_without_backends(&source);
    *lifecycle.retained_debug_construction.get_mut().unwrap() =
        Some(crate::vm_lifecycle::construction::RetainedDebugConstruction::History(Some(history)));
    let mut custody = ProductionVmConstructionCustody::new();
    custody.complete_with(|_| Ok(lifecycle)).unwrap();
    custody.retry_cleanup().unwrap();
    let mut destination = crate::ProductionVmConstructionPostBody::history_only();
    for message in ["first retained report", "second retained report"] {
        destination
            .retain_constructor_first(LifecycleApiError::LoopFactory {
                message: String::from(message),
            })
            .unwrap();
    }
    custody.post_body = Some(destination);
    let message = String::from("original containing constructor refusal");
    let original_message = message.as_ptr();
    custody.first = Some(LifecycleApiError::LoopFactory { message });

    assert!(ProductionVmCleanupOwner::take_post_body(&mut custody).is_err());
    let Phase::Complete(lifecycle) = custody.phase.get_mut().unwrap() else {
        panic!("the containing component lifecycle must remain in its carrier");
    };
    assert!(
        lifecycle
            .retained_debug_construction
            .get_mut()
            .unwrap()
            .is_none()
    );
    let Some(LifecycleApiError::LoopFactory { message }) = &custody.first else {
        panic!("the containing first must remain in its original slot");
    };
    assert_eq!(message.as_ptr(), original_message);
    let body = custody.post_body.as_ref().unwrap();
    let mut found = false;
    body.visit_history(|_, record| {
        if let crate::LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::SourceCleanup(
            history,
        )) = record
        {
            history.visit_history(|_, record| {
                if let crate::LifecycleHistoryRef::Failure(
                    crate::LifecycleFailureRef::Realization(
                        crucible_qemu_host::QemuVmRealizationError::ModelCopy { source },
                    ),
                ) = record
                {
                    let actual = source.downcast_ref::<HistoryFile>().unwrap();
                    assert_eq!(std::ptr::from_ref(actual), address);
                    found = true;
                }
            });
        }
    });
    assert!(found);
    assert!(!body.has_terminal_custody());
    assert!(!body.has_source_return());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let current = std::fs::metadata(format!("/proc/self/fd/{descriptor}")).unwrap();
    assert_eq!((current.dev(), current.ino()), identity);

    drop(custody);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
