//! Actual checked SQLite membership, current-row integrity and original cuts.
//!
//! The component catalog retains its existing 256 MiB/128-FD/300-second
//! account. These controls authenticate bytes and count real Read operations;
//! they do not certify installed quotas, native admission or CPU/wall parity.

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ObjectKind, PutReceipt, StorePhysicalQuotaGuard,
};
use crucible_linux_resource::host_supervision::{
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
    let mut pending = PendingMarks::new(&operation).unwrap();
    for index in 0..count {
        pending.insert(&mut marks, page(index), &operation).unwrap();
    }
    pending.flush(&mut marks, &operation).unwrap();
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

struct CheckedOnly {
    inner: Arc<dyn ImmutableBlobBackend>,
    reads: AtomicUsize,
    cancel_child: Option<HostOperationSupervisor>,
    truncate_after_metadata: Option<std::path::PathBuf>,
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
            let connection = crucible_cas::content_store::fixture_sqlite_heap()
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
        let mut pending = PendingMarks::new(&operation).unwrap();
        pending.insert(&mut marks, page(1000), &operation).unwrap();
        pending.flush(&mut marks, &operation).unwrap();
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
    let connection = crucible_cas::content_store::fixture_sqlite_heap()
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
fn checked_membership_refuses_actual_original_cancellation_at_every_success_cut() {
    // First measure the actual immutable one-node route, then exercise each
    // callback cut with a fresh genuine original supervisor and account.
    let mut probe = ComponentGcOperation::new();
    let marks = seeded(&mut probe, 1);
    let mut cuts = 0;
    {
        let operation = probe.context();
        assert!(
            marks
                .contains_with_boundary(&page(0), &mut || {
                    cuts += 1;
                    operation.check()
                })
                .unwrap()
        );
    }
    assert!(cuts > 4);
    drop(marks);
    drop(probe);

    for cut in 1..=cuts {
        let mut fixture = ComponentGcOperation::new();
        let marks = seeded(&mut fixture, 1);
        let root = marks.root;
        let supervisor = fixture.supervision();
        let operation = fixture.context();
        let mut seen = 0;
        let error = marks
            .contains_with_boundary(&page(0), &mut || {
                seen += 1;
                if seen == cut {
                    supervisor.cancel().unwrap();
                }
                operation.check()
            })
            .unwrap_err();
        assert!(has_original_cancellation(&error), "cut {cut}: {error}");
        assert_eq!(seen, cut, "no success callback replaces the first refusal");
        assert_eq!(marks.root, root);
    }
}

#[test]
fn checked_membership_corrupt_body_precedes_a_later_original_refusal() {
    let mut fixture = ComponentGcOperation::new();
    let marks = seeded(&mut fixture, 1);
    let path = fixture.scratch_path().join("objects.sqlite3");
    let connection = crucible_cas::content_store::fixture_sqlite_heap()
        .unwrap()
        .open_connection(path, rusqlite::OpenFlags::default())
        .unwrap();
    connection
        .execute(
            "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
            [marks.root.content_id().encode()],
        )
        .unwrap();
    let operation = fixture.context();
    let root = marks.root;
    let mut observed = 0;
    let error = marks
        .contains_with_boundary(&page(0), &mut || {
            observed += 1;
            operation.check()
        })
        .unwrap_err();
    assert!(has_cause(
        &error,
        |error| matches!(error, StoreError::Corrupt { id } if *id == root.content_id())
    ));

    let mut seen = 0;
    let error = marks
        .contains_with_boundary(&page(0), &mut || {
            seen += 1;
            if seen > observed {
                Err(StoreError::Unsupported {
                    capability: "later-original-refusal",
                })
            } else {
                operation.check()
            }
        })
        .unwrap_err();
    assert_eq!(seen, observed);
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
    use crucible_cas::content_envelope::ContentEnvelope;

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

    let mut observed = 0;
    let error = marks
        .map
        .get_with_boundary(id, mark_key(page(0)), &account, &mut || {
            observed += 1;
            operation.check()
        })
        .unwrap_err();
    assert!(matches!(
        error,
        CampaignStoreError::InvalidMerkle {
            reason: "unsupported-node-schema"
        }
    ));
    let mut seen = 0;
    let error = marks
        .map
        .get_with_boundary(id, mark_key(page(0)), &account, &mut || {
            seen += 1;
            if seen > observed {
                Err(StoreError::Unsupported {
                    capability: "postparse-original-refusal",
                })
            } else {
                operation.check()
            }
        })
        .unwrap_err();
    assert_eq!(seen, observed);
    assert!(matches!(
        error,
        CampaignStoreError::InvalidMerkle {
            reason: "unsupported-node-schema"
        }
    ));
}
