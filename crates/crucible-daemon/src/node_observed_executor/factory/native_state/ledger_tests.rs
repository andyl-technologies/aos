//! Data-only original reservation tests; these tests issue no native authority.

// Panics identify loss or reinterpretation of an original durable commitment.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
};

use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefBackendCapabilities, RefCasOutcome, RefName,
    RefPublicationGuard, RefScanPage, StoreError,
};

use super::{
    control::{InstalledGem5Isa, NativeCapturePoint, NativeWorldOutcome, NativeWorldRequest},
    ledger::{NativeWorldLedger, record_quota_ref},
};

fn request() -> NativeWorldRequest {
    NativeWorldRequest::Capture {
        execution: "00112233445566778899aabbccddeeff".into(),
        isa: InstalledGem5Isa::X86_64,
        point: NativeCapturePoint::Pending,
    }
}

#[test]
fn exact_native_request_retry_never_reserves_a_second_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = NativeWorldLedger::new(
        Arc::new(DirectoryBlobBackend::new(
            "native-ledger",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    )
    .unwrap();

    let original = ledger.reserve(&request()).unwrap();
    let retry = ledger.reserve(&request()).unwrap();

    assert!(original.original_dispatch);
    assert!(!retry.original_dispatch);
    assert_eq!(retry.record.request, original.record.request);
    assert!(matches!(
        retry.record.state,
        NativeWorldOutcome::Reserved { .. }
    ));
    assert_eq!(ledger.retention_roots().unwrap().len(), 3);
}

#[test]
fn changed_capture_point_and_architecture_cannot_replace_original_nonce() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = NativeWorldLedger::new(
        Arc::new(DirectoryBlobBackend::new(
            "native-ledger",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    )
    .unwrap();
    let original = ledger.reserve(&request()).unwrap();
    let NativeWorldRequest::Capture { execution, .. } = request() else {
        panic!("capture fixture absent");
    };

    for (isa, point) in [
        (InstalledGem5Isa::Aarch64, NativeCapturePoint::Pending),
        (
            InstalledGem5Isa::X86_64,
            NativeCapturePoint::HeldPublication,
        ),
    ] {
        assert!(
            ledger
                .reserve(&NativeWorldRequest::Capture {
                    execution: execution.clone(),
                    isa,
                    point
                })
                .is_err()
        );
    }
    assert_eq!(
        ledger.state(&execution).unwrap().request,
        original.record.request
    );
}

#[test]
fn restart_preserves_ambiguous_original_reservation_without_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "native-ledger",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let original = NativeWorldLedger::new(blobs.clone(), refs.clone())
        .unwrap()
        .reserve(&request())
        .unwrap();

    let restarted = NativeWorldLedger::new(blobs, refs).unwrap();
    let retry = restarted.reserve(&request()).unwrap();

    assert!(!retry.original_dispatch);
    assert_eq!(retry.record.request, original.record.request);
    assert!(matches!(
        retry.record.state,
        NativeWorldOutcome::Reserved { .. }
    ));
}

#[test]
fn uncertain_native_completion_remains_monotonic_on_retry_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "native-ledger",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = NativeWorldLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = ledger.reserve(&request()).unwrap();
    ledger
        .complete(
            &original,
            NativeWorldOutcome::Unknown {
                reason: "original native effect remains unknown".into(),
            },
        )
        .unwrap();

    let restarted = NativeWorldLedger::new(blobs, refs).unwrap();
    let retry = restarted.reserve(&request()).unwrap();

    assert!(!retry.original_dispatch);
    assert!(matches!(
        retry.record.state,
        NativeWorldOutcome::Unknown { .. }
    ));
    assert_eq!(retry.record.request, original.record.request);
    assert_eq!(restarted.retention_roots().unwrap().len(), 3);
}

#[test]
fn status_and_invalid_nonce_cannot_reserve_native_custody() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = NativeWorldLedger::new(
        Arc::new(DirectoryBlobBackend::new(
            "native-ledger",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    )
    .unwrap();
    assert!(
        ledger
            .reserve(&NativeWorldRequest::Status {
                execution: request().execution().to_owned()
            })
            .is_err()
    );
    assert!(
        ledger
            .reserve(&NativeWorldRequest::Capture {
                execution: "00000000000000000000000000000000".into(),
                isa: InstalledGem5Isa::X86_64,
                point: NativeCapturePoint::Pending,
            })
            .is_err()
    );
    assert!(ledger.retention_roots().unwrap().is_empty());
}

#[test]
fn backend_completion_panic_preserves_original_request_and_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let refs = Arc::new(PanicCompletionRefs::new(DirectoryRefBackend::new(
        directory.path().join("refs"),
    )));
    let ledger = NativeWorldLedger::new(
        Arc::new(DirectoryBlobBackend::new(
            "native-ledger",
            directory.path().join("blobs"),
        )),
        refs.clone(),
    )
    .unwrap();
    let original = ledger.reserve(&request()).unwrap();

    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ledger.complete(
            &original,
            NativeWorldOutcome::Unknown {
                reason: "original native effect remains unknown".into(),
            },
        )
    }));
    assert!(failure.is_err());
    assert!(refs.panicked());

    let retry = ledger.reserve(&request()).unwrap();
    assert!(!retry.original_dispatch);
    assert_eq!(retry.record.request, original.record.request);
    assert!(matches!(
        retry.record.state,
        NativeWorldOutcome::Reserved {}
    ));
    assert_eq!(ledger.retention_roots().unwrap().len(), 3);
}

#[test]
fn concurrent_ledgers_share_the_last_durable_record_credit() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "native-quota",
        directory.path().join("blobs"),
    ));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    let quota = crucible_node_contract::canonical::canonical_json(&serde_json::json!({
        "format":"crucible.native-world-record-quota", "version":1, "consumed":4095,
    }))
    .unwrap();
    let initial = ContentId::for_bytes(ObjectKind::Trace, 1, &quota);
    let guard = refs.acquire_publication_guard().unwrap();
    assert!(
        blobs
            .put_if_absent(initial, &BlobHandle::from_bytes(quota))
            .unwrap()
            .is_durable()
    );
    refs.compare_exchange(&record_quota_ref().unwrap(), None, initial)
        .unwrap();
    drop(guard);

    // Already consumed credits may include failed writes. Two genuinely separate
    // Directory backend/ledger instances race that one final durable namespace
    // credit, rather than relying on a per-instance lock or native test tokens.
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for execution in [
        "61728394a5b6c7d8e9fa0b1c2d3e4f50",
        "728394a5b6c7d8e9fa0b1c2d3e4f5061",
    ] {
        let ledger = NativeWorldLedger::new(
            blobs.clone(),
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
        )
        .unwrap();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let request = NativeWorldRequest::Capture {
                execution: execution.into(),
                isa: InstalledGem5Isa::X86_64,
                point: NativeCapturePoint::Pending,
            };
            barrier.wait();
            let accepted = ledger.reserve(&request).is_ok();
            (request, accepted)
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|(_, accepted)| *accepted).count(), 1);
    let page = refs
        .scan_refs(
            &crucible_cas::content_store::RefName::new("node-native-operations").unwrap(),
            None,
            64,
        )
        .unwrap();
    assert_eq!(page.entries().len(), 1);
    let final_quota = refs
        .read_ref(&record_quota_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_ne!(final_quota, initial);
    let bytes = blobs
        .read(final_quota, None)
        .unwrap()
        .read_all(1024)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["consumed"],
        4096
    );

    let refs = Arc::new(refs);
    let ledger = NativeWorldLedger::new(blobs, refs.clone()).unwrap();
    let original = &results.iter().find(|(_, accepted)| *accepted).unwrap().0;
    assert!(!ledger.reserve(original).unwrap().original_dispatch);
    assert_eq!(
        refs.read_ref(&record_quota_ref().unwrap()).unwrap(),
        Some(final_quota)
    );
    assert_eq!(ledger.retention_roots().unwrap().len(), 3);
}

#[test]
fn corrupt_or_understated_record_quota_refuses_before_new_original_reservation() {
    for quota in [
        serde_json::json!({"format":"crucible.native-world-record-quota", "version":2, "consumed":1}),
        serde_json::json!({"format":"crucible.native-world-record-quota", "version":1, "consumed":4097}),
        serde_json::json!({"format":"crucible.native-world-record-quota", "version":1, "consumed":0}),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let blobs = Arc::new(DirectoryBlobBackend::new(
            "native-quota",
            directory.path().join("blobs"),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let ledger = NativeWorldLedger::new(blobs.clone(), refs.clone()).unwrap();
        let original = ledger.reserve(&request()).unwrap();
        let bytes = crucible_node_contract::canonical::canonical_json(&quota).unwrap();
        let next = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let guard = refs.acquire_publication_guard().unwrap();
        blobs
            .put_if_absent(next, &BlobHandle::from_bytes(bytes))
            .unwrap();
        let current = refs.read_ref(&record_quota_ref().unwrap()).unwrap();
        refs.compare_exchange(&record_quota_ref().unwrap(), current, next)
            .unwrap();
        drop(guard);
        let replacement = NativeWorldRequest::Capture {
            execution: "8394a5b6c7d8e9fa0b1c2d3e4f506172".into(),
            isa: InstalledGem5Isa::X86_64,
            point: NativeCapturePoint::Pending,
        };

        assert!(ledger.reserve(&replacement).is_err());
        assert_eq!(
            ledger.state(request().execution()).unwrap().request,
            original.record.request
        );
        assert!(ledger.state(replacement.execution()).is_err());
        assert!(ledger.retention_roots().is_err());
    }
}

/// Injects one backend unwind immediately before an original completion CAS.
pub(super) struct PanicCompletionRefs {
    inner: DirectoryRefBackend,
    panicked: AtomicBool,
}

impl PanicCompletionRefs {
    pub(super) fn new(inner: DirectoryRefBackend) -> Self {
        Self {
            inner,
            panicked: AtomicBool::new(false),
        }
    }

    pub(super) fn panicked(&self) -> bool {
        self.panicked.load(Ordering::Acquire)
    }
}

impl MutableRefBackend for PanicCompletionRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        if name.as_str().starts_with("node-native-operations/")
            && expected.is_some()
            && !self.panicked.swap(true, Ordering::AcqRel)
        {
            panic!("native completion backend failed after original native work");
        }
        self.inner.compare_exchange(name, expected, next)
    }
}
