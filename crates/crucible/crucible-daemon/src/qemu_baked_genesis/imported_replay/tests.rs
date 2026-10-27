//! Checks actual file ownership in the existing returned-history error carrier.
//!
//! The history-only component has no Main, terminal custody or native return.
//! These checks cannot construct a positive prepared retirement or activate it.

use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
#[error("retained imported replay file")]
struct HistoryFile {
    file: std::fs::File,
    drops: Arc<AtomicUsize>,
}

impl Drop for HistoryFile {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn terminal_error_owns_the_same_file_history_until_disposal() {
    let file = tempfile::tempfile().unwrap();
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata().unwrap();
    let identity = (metadata.dev(), metadata.ino());
    let drops = Arc::new(AtomicUsize::new(0));
    let first = Box::new(HistoryFile {
        file,
        drops: Arc::clone(&drops),
    });
    let address = std::ptr::from_ref(first.as_ref());
    let history = crate::SourceCleanupHistory::from_native(QemuVmRealizationError::ModelCopy {
        source: first,
    });
    let mut body = crate::ProductionVmConstructionPostBody::history_only();
    body.retain_source_history(history).unwrap();
    assert!(!body.has_terminal_custody());
    assert!(!body.has_source_return());
    assert!(body.first_failure().is_some());

    let error = ImportedProductionReplayError::Terminal(body);
    let ImportedProductionReplayError::Terminal(body) = &error else {
        panic!("the owning terminal error must retain its exact history");
    };
    let mut found = false;
    body.visit_history(|_, record| {
        if let crate::LifecycleHistoryRef::Failure(crate::LifecycleFailureRef::SourceCleanup(
            history,
        )) = record
        {
            history.visit_history(|_, record| {
                if let crate::LifecycleHistoryRef::Failure(
                    crate::LifecycleFailureRef::Realization(QemuVmRealizationError::ModelCopy {
                        source,
                    }),
                ) = record
                {
                    let actual = source.downcast_ref::<HistoryFile>().unwrap();
                    assert_eq!(std::ptr::from_ref(actual), address);
                    assert_eq!(actual.file.as_raw_fd(), descriptor);
                    let metadata = actual.file.metadata().unwrap();
                    assert_eq!((metadata.dev(), metadata.ino()), identity);
                    found = true;
                }
            });
        }
    });
    assert!(found);
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    drop(error);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
