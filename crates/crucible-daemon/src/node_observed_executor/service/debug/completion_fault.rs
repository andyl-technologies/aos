//! Keeps exact native Stop outcomes through completion callback failure.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Storage panic injection and independent original-custody oracles deliberately panic.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_cas::content_store::{BackendCapabilities, ByteRange, PutReceipt, StoreError};
use std::sync::atomic::{AtomicBool, Ordering};

struct CompletionFault {
    inner: Arc<dyn ImmutableBlobBackend>,
    panic: bool,
    fired: Arc<AtomicBool>,
}

impl ImmutableBlobBackend for CompletionFault {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let completion = source
            .read_all(32 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|value| {
                value["format"] == "crucible.live-debug-record"
                    && value["outcome"]["state"] == "stopped"
            });
        if completion && !self.fired.swap(true, Ordering::AcqRel) {
            if self.panic {
                panic!("injected original Debug completion callback panic");
            }
            return Err(StoreError::Incompatible);
        }
        self.inner.put_if_absent(id, source)
    }
}

#[test]
#[ignore = "requires actual source-built installed companion"]
fn original_stop_outcome_survives_completion_error_and_panic_until_durable_reconciliation() {
    for panic in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let callback_flag = fired.clone();
        let (request, service, _, refs) = start_service_with(
            directory.path(),
            |inner| {
                Arc::new(CompletionFault {
                    inner,
                    panic,
                    fired: callback_flag,
                })
            },
            2,
        );
        service.start_debug(request.clone()).unwrap();
        let stopped = wait_for(&service, &request.execution, false);
        assert!(fired.load(Ordering::Acquire));
        assert!(stopped.stop.is_some());
        assert!(
            refs.read_ref(
                &RefName::new(format!(
                    "node-world-coordinators/condition/debug-{}-stop",
                    request.execution
                ))
                .unwrap()
            )
            .unwrap()
            .is_some()
        );
        assert!(
            refs.read_ref(
                &RefName::new(format!(
                    "node-world-coordinators/condition/debug-{}-resume",
                    request.execution
                ))
                .unwrap()
            )
            .unwrap()
            .is_none()
        );
        retire(service);
        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "debug-reconciled-original",
            directory.path().join("blobs"),
        ));
        let ledger = DebugLedger::new(blobs, refs).unwrap();
        let retained = ledger.reserve_start(&request).unwrap();
        assert!(!retained.original_dispatch);
        assert_eq!(encode(&retained.record).unwrap(), encode(&stopped).unwrap());
    }
}
