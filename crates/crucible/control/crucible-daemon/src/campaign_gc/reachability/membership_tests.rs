//! Actual checked SQLite membership, current-row integrity and original cuts.
//!
//! The component catalog retains its existing 256 MiB/128-FD/300-second
//! account. These controls authenticate bytes and count real Read operations;
//! they do not certify installed quotas, native admission or CPU/wall parity.

use std::cell::Cell;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_store::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ObjectKind, PutReceipt, StorePhysicalQuotaGuard,
};
use crucible_host_resources::host_supervision::{
    HostOperationState, HostOperationSupervisor, HostSupervisionError,
};

use super::super::tests::operation::ComponentGcOperation;
use super::*;

fn page(index: u64) -> ContentId {
    ContentId::for_bytes(ObjectKind::RamExtent, 1, &index.to_be_bytes())
}

fn seeded(fixture: &mut ComponentGcOperation, count: u64) -> Reachability {
    let operation = fixture.context();
    let mut marks = Reachability::with_backend(operation.marks(), operation.original()).unwrap();
    let mut pending = sorted_runs::SortOwner::new(&operation).unwrap();
    for index in 0..count {
        pending.insert(page(index)).unwrap();
    }
    pending.finish(&mut marks).unwrap();
    marks
}

fn has_cause(error: &(dyn Error + 'static), predicate: impl Fn(&StoreError) -> bool) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if error.downcast_ref::<StoreError>().is_some_and(&predicate) {
            return true;
        }
        cause = error.source();
    }
    false
}

// Transparent campaign errors delegate source() past the StoreError wrapper.
// Require the actual typed original disposition, rather than its wrapper shape.
fn has_original_cancellation(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if matches!(
            error.downcast_ref::<HostSupervisionError>(),
            Some(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ) {
            return true;
        }
        cause = error.source();
    }
    false
}

/// Observes the real delegated read result, independently of progress callbacks.
#[derive(Default)]
struct CheckedReadCompletion {
    entered: AtomicBool,
    returned: AtomicBool,
    authenticated: AtomicBool,
    corrupt: AtomicBool,
}

impl CheckedReadCompletion {
    fn observe(&self, result: &Result<crucible_store::content_store::OwnedBlobBytes, StoreError>) {
        self.authenticated.store(result.is_ok(), Ordering::Release);
        // Checked SQLite retains its real work error inside diagnostic/scope
        // custody. Observe that typed source chain without detaching its loan.
        let corrupt = result.as_ref().err().is_some_and(|error| {
            has_cause(error, |error| matches!(error, StoreError::Corrupt { .. }))
        });
        self.corrupt.store(corrupt, Ordering::Release);
        self.returned.store(true, Ordering::Release);
    }
}

struct CheckedOnly {
    inner: Arc<dyn ImmutableBlobBackend>,
    reads: AtomicUsize,
    cancel_child: Option<HostOperationSupervisor>,
    truncate_after_metadata: Option<std::path::PathBuf>,
    read_completion: Option<Arc<CheckedReadCompletion>>,
}

impl ImmutableBlobBackend for CheckedOnly {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.inner.metadata_resources()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Err(StoreError::Unsupported {
            capability: "ordinary-mark-read-forbidden",
        })
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        let ordinal = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
        if ordinal == 2
            && let Some(supervisor) = &self.cancel_child
        {
            supervisor.cancel().unwrap();
        }
        let source = self
            .inner
            .read_with_boundary(original, id, range, boundary)?;
        if let Some(path) = &self.truncate_after_metadata {
            let connection = crucible_store::content_store::fixture_sqlite_heap()
                .unwrap()
                .open_connection(path, rusqlite::OpenFlags::default())
                .unwrap();
            connection
                .execute(
                    "UPDATE objects SET body = substr(body, 1, length(body) - 1) WHERE id = ?1",
                    [id.encode()],
                )
                .unwrap();
        }
        Ok(source)
    }

    fn read_merkle_node_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crucible_store::content_store::OwnedBlobBytes, StoreError> {
        if self.truncate_after_metadata.is_some() {
            // Keep the existing held-source mutation control on its original
            // deferred route. Native-close mutations have separate SQL tests.
            let source = self.read_with_boundary(original, id, None, boundary)?;
            return source.read_all_with_boundary(
                original,
                crucible_store::content_store::MAX_MERKLE_NODE_ENVELOPE_BYTES as u64,
                boundary,
            );
        }
        let ordinal = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
        if ordinal == 2
            && let Some(supervisor) = &self.cancel_child
        {
            supervisor.cancel().unwrap();
        }
        if let Some(completion) = &self.read_completion {
            completion.entered.store(true, Ordering::Release);
        }
        let result = self
            .inner
            .read_merkle_node_with_boundary(original, id, boundary);
        if let Some(completion) = &self.read_completion {
            completion.observe(&result);
        }
        result
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

#[test]
fn checked_membership_reuses_original_without_new_catalog_read_operations() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let mut marks = seeded(&mut fixture, 1024);
    let root = marks.root;
    let before = fixture.read_starts();
    for index in 0..128 {
        assert!(marks.contains(&page(index)).unwrap());
        assert!(!marks.contains(&page(4096 + index)).unwrap());
    }
    let ordinary = fixture.read_starts();
    assert!(
        ordinary > before,
        "ordinary node reads begin real catalog operations"
    );

    let checked = Arc::new(CheckedOnly {
        inner: fixture.context().marks(),
        reads: AtomicUsize::new(0),
        cancel_child: None,
        truncate_after_metadata: None,
        read_completion: None,
    });
    marks.map = MerkleMap::new(checked.clone());

    {
        let operation = fixture.context();
        for index in 0..128 {
            assert!(
                marks
                    .contains_with_boundary(&page(index), &mut || operation.check())
                    .unwrap()
            );
            assert!(
                !marks
                    .contains_with_boundary(&page(4096 + index), &mut || operation.check())
                    .unwrap()
            );
        }
    }
    assert_eq!(fixture.read_starts(), ordinary);
    assert!(
        checked.reads.load(Ordering::Relaxed) > 256,
        "actual selected child paths execute"
    );
    assert_eq!(marks.root, root);
    assert_eq!(marks.len(), 1024);
    drop(marks);
    drop(checked);
    drop(fixture);
    resources.reserve_resources(128, 256 * 1024 * 1024).unwrap();
}

#[test]
fn selected_child_cancellation_refuses_without_ordinary_fallback() {
    let mut fixture = ComponentGcOperation::new();
    let mut marks = seeded(&mut fixture, 128);
    let checked = Arc::new(CheckedOnly {
        inner: fixture.context().marks(),
        reads: AtomicUsize::new(0),
        cancel_child: Some(fixture.supervision()),
        truncate_after_metadata: None,
        read_completion: None,
    });
    marks.map = MerkleMap::new(checked.clone());
    let root = marks.root;
    let operation = fixture.context();
    let error = marks
        .contains_with_boundary(&page(0), &mut || operation.check())
        .unwrap_err();
    assert_eq!(checked.reads.load(Ordering::Relaxed), 2);
    assert!(has_original_cancellation(&error), "{error:#?}");
    assert!(!has_cause(&error, |error| matches!(
        error,
        StoreError::Unsupported {
            capability: "ordinary-mark-read-forbidden"
        }
    )));
    assert_eq!(marks.root, root);
}

#[test]
fn body_shortened_after_checked_metadata_is_not_membership_absence() {
    let mut fixture = ComponentGcOperation::new();
    let mut marks = seeded(&mut fixture, 1);
    marks.map = MerkleMap::new(Arc::new(CheckedOnly {
        inner: fixture.context().marks(),
        reads: AtomicUsize::new(0),
        cancel_child: None,
        truncate_after_metadata: Some(fixture.scratch_path().join("objects.sqlite3")),
        read_completion: None,
    }));
    let operation = fixture.context();
    let error = marks
        .contains_with_boundary(&page(0), &mut || operation.check())
        .unwrap_err();
    assert!(has_cause(&error, |error| matches!(
        error,
        StoreError::Corrupt { .. } | StoreError::InvalidSourceLength { .. }
    )));
    assert_eq!(marks.len(), 1);
}

#[test]
fn checked_membership_observes_new_root_and_missing_rows_after_accepted_lookup() {
    let mut fixture = ComponentGcOperation::new();
    let mut marks = seeded(&mut fixture, 128);
    {
        let operation = fixture.context();
        assert!(
            !marks
                .contains_with_boundary(&page(1000), &mut || operation.check())
                .unwrap()
        );
        let mut pending = sorted_runs::SortOwner::new(&operation).unwrap();
        for index in 0..128 {
            pending.insert(page(index)).unwrap();
        }
        pending.insert(page(1000)).unwrap();
        pending.finish(&mut marks).unwrap();
        assert!(
            marks
                .contains_with_boundary(&page(1000), &mut || operation.check())
                .unwrap()
        );
    }
    let root = marks.root;
    // The catalog's actual database path is retained by its admitted fixture.
    // No cached earlier lookup may conceal a separately committed deletion.
    let path = fixture.scratch_path().join("objects.sqlite3");
    let connection = crucible_store::content_store::fixture_sqlite_heap()
        .unwrap()
        .open_connection(path, rusqlite::OpenFlags::default())
        .unwrap();
    connection.execute("DELETE FROM objects", []).unwrap();
    let operation = fixture.context();
    let error = marks
        .contains_with_boundary(&page(1000), &mut || operation.check())
        .unwrap_err();
    assert!(has_cause(&error, |error| matches!(
        error,
        StoreError::NotFound { .. }
    )));
    assert_eq!(marks.root, root);
    assert_eq!(marks.len(), 129);
}

#[test]
fn checked_membership_refuses_actual_original_cancellation_at_semantic_success_boundaries() {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SuccessCut {
        TraversalEntry,
        SelectedNodeEntry,
        CheckedReadEntry,
        DecodedNodeReturn,
        TraversalReturn,
    }

    const CUTS: [SuccessCut; 5] = [
        SuccessCut::TraversalEntry,
        SuccessCut::SelectedNodeEntry,
        SuccessCut::CheckedReadEntry,
        SuccessCut::DecodedNodeReturn,
        SuccessCut::TraversalReturn,
    ];

    // A one-node path has fixed traversal cuts around the actual checked read.
    // SQLite may add progress/lock callbacks inside it; every such callback
    // still checks this operation, without calibrating another read's total.
    for cancel_at in std::iter::once(None).chain(CUTS.into_iter().map(Some)) {
        let mut fixture = ComponentGcOperation::new();
        let mut marks = seeded(&mut fixture, 1);
        let completion = Arc::new(CheckedReadCompletion::default());
        marks.map = MerkleMap::new(Arc::new(CheckedOnly {
            inner: fixture.context().marks(),
            reads: AtomicUsize::new(0),
            cancel_child: None,
            truncate_after_metadata: None,
            read_completion: Some(Arc::clone(&completion)),
        }));
        let root = marks.root;
        let supervisor = fixture.supervision();
        let operation = fixture.context();
        let mut before_read = 0;
        let mut during_read = 0;
        let mut after_read = 0;
        let mut observed = [0; CUTS.len()];
        let mut selected = 0;
        let mut refused = false;
        let mut after_refusal = 0;

        let result = marks.contains_with_boundary(&page(0), &mut || {
            if refused {
                after_refusal += 1;
                return operation.check();
            }
            let cut = if !completion.entered.load(Ordering::Acquire) {
                before_read += 1;
                Some(match before_read {
                    1 => SuccessCut::TraversalEntry,
                    2 => SuccessCut::SelectedNodeEntry,
                    _ => panic!("unreviewed callback before the selected read"),
                })
            } else if !completion.returned.load(Ordering::Acquire) {
                during_read += 1;
                (during_read == 1).then_some(SuccessCut::CheckedReadEntry)
            } else {
                assert!(completion.authenticated.load(Ordering::Acquire));
                after_read += 1;
                Some(match after_read {
                    1 => SuccessCut::DecodedNodeReturn,
                    2 => SuccessCut::TraversalReturn,
                    _ => panic!("unreviewed callback after the selected read"),
                })
            };
            if let Some(cut) = cut {
                observed[cut as usize] += 1;
                if Some(cut) == cancel_at {
                    selected += 1;
                    supervisor.cancel().unwrap();
                }
            }
            let result = operation.check();
            refused = result.is_err();
            result
        });

        match cancel_at {
            None => {
                assert!(result.unwrap());
                assert_eq!(observed, [1; CUTS.len()]);
                assert!(during_read > 0);
                assert!(!refused);
                assert_eq!(selected, 0);
            }
            Some(cut) => {
                let error = result.unwrap_err();
                assert!(has_original_cancellation(&error), "{cut:?}: {error}");
                assert_eq!(selected, 1, "the selected semantic boundary must run");
                assert_eq!(observed[cut as usize], 1);
                assert!(refused);
            }
        }
        assert_eq!(after_refusal, 0, "no callback replaces the first refusal");
        assert_eq!(marks.root, root);
    }
}

#[test]
fn checked_membership_corrupt_body_precedes_a_later_original_refusal() {
    let mut fixture = ComponentGcOperation::new();
    let mut marks = seeded(&mut fixture, 1);
    let path = fixture.scratch_path().join("objects.sqlite3");
    let connection = crucible_store::content_store::fixture_sqlite_heap()
        .unwrap()
        .open_connection(path, rusqlite::OpenFlags::default())
        .unwrap();
    connection
        .execute(
            "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
            [marks.root.content_id().encode()],
        )
        .unwrap();
    let completion = Arc::new(CheckedReadCompletion::default());
    marks.map = MerkleMap::new(Arc::new(CheckedOnly {
        inner: fixture.context().marks(),
        reads: AtomicUsize::new(0),
        cancel_child: None,
        truncate_after_metadata: None,
        read_completion: Some(Arc::clone(&completion)),
    }));
    let operation = fixture.context();
    let root = marks.root;
    let later_callbacks = Cell::new(0);
    let mut boundary = || {
        if completion.returned.load(Ordering::Acquire) {
            later_callbacks.set(later_callbacks.get() + 1);
            Err(StoreError::Unsupported {
                capability: "later-original-refusal",
            })
        } else {
            operation.check()
        }
    };

    let error = marks
        .contains_with_boundary(&page(0), &mut boundary)
        .unwrap_err();

    assert!(completion.returned.load(Ordering::Acquire));
    assert!(completion.corrupt.load(Ordering::Acquire));
    assert!(!completion.authenticated.load(Ordering::Acquire));
    assert_eq!(
        later_callbacks.get(),
        0,
        "no success callback follows the actual corrupt read"
    );
    assert!(has_cause(&error, |error| matches!(
        error, StoreError::Corrupt { id } if *id == root.content_id()
    )));
    // Establish that a later callback really would refuse, without relying on
    // another read's variable SQLite progress/locking callback count.
    assert!(matches!(
        boundary(),
        Err(StoreError::Unsupported {
            capability: "later-original-refusal"
        })
    ));
    assert_eq!(later_callbacks.get(), 1);
    assert!(has_cause(&error, |error| matches!(
        error,
        StoreError::Corrupt { .. }
    )));
    assert!(!has_cause(&error, |error| matches!(
        error,
        StoreError::Unsupported {
            capability: "later-original-refusal"
        }
    )));
    assert_eq!(marks.root, root);
}

#[test]
fn authenticated_invalid_node_keeps_structural_cause_before_postparse_callback() {
    use crucible_campaign::CampaignStoreError;
    use crucible_store::content_envelope::ContentEnvelope;

    let mut fixture = ComponentGcOperation::new();
    let marks = seeded(&mut fixture, 1);
    let operation = fixture.context();
    let account = mark_account(operation.original()).unwrap();
    let _scope = account.enter();
    let backend = operation.marks();
    let original_bytes = backend
        .read(marks.root.content_id(), None)
        .unwrap()
        .read_all(64 * 1024)
        .unwrap();
    let envelope = ContentEnvelope::from_canonical_bytes(&original_bytes).unwrap();
    let mut body = envelope.body().to_vec();
    body[..4].copy_from_slice(&0_u32.to_be_bytes());
    let invalid = ContentEnvelope::new(
        envelope.schema_name(),
        envelope.schema_version(),
        envelope.children().clone(),
        body,
    )
    .unwrap();
    let id = invalid.content_id(ObjectKind::MerkleNode);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(invalid.canonical_bytes()))
        .unwrap();
    assert!(matches!(
        marks.map.get(id, mark_key(page(0))),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "unsupported-node-schema"
        })
    ));

    let completion = Arc::new(CheckedReadCompletion::default());
    let checked = MerkleMap::new(Arc::new(CheckedOnly {
        inner: backend,
        reads: AtomicUsize::new(0),
        cancel_child: None,
        truncate_after_metadata: None,
        read_completion: Some(Arc::clone(&completion)),
    }));
    let later_callbacks = Cell::new(0);
    let mut boundary = || {
        if completion.returned.load(Ordering::Acquire) {
            later_callbacks.set(later_callbacks.get() + 1);
            Err(StoreError::Unsupported {
                capability: "postparse-original-refusal",
            })
        } else {
            operation.check()
        }
    };

    let error = checked
        .get_with_boundary(id, mark_key(page(0)), &account, &mut boundary)
        .unwrap_err();

    assert!(completion.returned.load(Ordering::Acquire));
    assert!(completion.authenticated.load(Ordering::Acquire));
    assert!(!completion.corrupt.load(Ordering::Acquire));
    // read_checked_node decodes and validates before its success-only callback.
    // Its real preparse account/liveness checks still use the same live Original.
    assert_eq!(
        later_callbacks.get(),
        0,
        "structural failure precedes the postparse callback"
    );
    assert!(matches!(
        error,
        CampaignStoreError::InvalidMerkle {
            reason: "unsupported-node-schema"
        }
    ));
    assert!(matches!(
        boundary(),
        Err(StoreError::Unsupported {
            capability: "postparse-original-refusal"
        })
    ));
    assert_eq!(later_callbacks.get(), 1);
}
