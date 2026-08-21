//! Exact-checkpoint store regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::{Checkpoint, CheckpointKind, Configuration, ScenarioDef};
use crucible_cas::content_store::{
    BackendCapabilities, BlobSource, ByteRange, DirectoryBlobBackend, MemoryBlobBackend,
    PlacementReceipt,
};
use crucible_qemu::QemuReplayOracleValidation;

use super::*;

const STORE_LIMIT: u64 = 1024 * 1024;

struct TestDurableBackend {
    memory: MemoryBlobBackend,
}

impl TestDurableBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("test-exact-checkpoints", 8 * STORE_LIMIT),
        }
    }

    fn object_count(&self) -> usize {
        self.memory.object_count().expect("count test objects")
    }
}

impl ImmutableBlobBackend for TestDurableBackend {
    fn name(&self) -> &str {
        "test-durable-exact-checkpoints"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.memory.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.memory.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let receipt = self.memory.put_if_absent(id, source)?;
        Ok(PutReceipt {
            id: receipt.id,
            placements: vec![PlacementReceipt {
                backend: String::from(self.name()),
                durable: true,
                logical_length: source.logical_length(),
            }],
        })
    }
}

struct OpenCountingSource {
    logical_length: u64,
    opens: Arc<AtomicUsize>,
}

impl BlobSource for OpenCountingSource {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Cursor::new(Vec::<u8>::new())))
    }
}

#[test]
fn prepare_is_write_free_and_publication_round_trips_streamed_vmstate() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let snapshot = snapshot("round-trip");
    let vmstate_bytes = (0..131_071_u32)
        .map(|value| (value % 251) as u8)
        .collect::<Vec<_>>();

    let prepared = store
        .prepare(&snapshot, BlobHandle::from_bytes(vmstate_bytes.clone()))
        .expect("prepare exact checkpoint");

    assert_eq!(backend.object_count(), 0);
    assert_eq!(prepared.snapshot_identity(), snapshot.id());
    assert_eq!(
        prepared.configuration(),
        snapshot.checkpoint().configuration
    );
    assert_eq!(prepared.vmstate_bytes(), vmstate_bytes.len() as u64);
    assert_eq!(
        prepared.root().content_id().kind(),
        ObjectKind::ExactManifest
    );
    assert_eq!(
        prepared.root().content_id().schema_version(),
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
    );
    assert_eq!(prepared.metadata_id().kind(), ObjectKind::DeviceState);
    assert_eq!(
        prepared.metadata_id().schema_version(),
        QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION
    );
    assert_eq!(prepared.vmstate_id().kind(), ObjectKind::DeviceState);
    assert_eq!(
        prepared.vmstate_id().schema_version(),
        QEMU_VMSTATE_SCHEMA_VERSION
    );

    let publication = store.publish(&prepared).expect("publish exact checkpoint");
    assert_eq!(publication.root(), prepared.root());
    assert_eq!(publication.metadata(), prepared.metadata_id());
    assert_eq!(publication.vmstate(), prepared.vmstate_id());
    assert_eq!(backend.object_count(), 3);

    let loaded = store
        .load(publication.root())
        .expect("load exact checkpoint");
    assert_eq!(loaded.root(), publication.root());
    assert_eq!(loaded.snapshot(), &snapshot);
    assert_eq!(loaded.vmstate_id(), publication.vmstate());
    let mut restored_vmstate = Vec::new();
    assert_eq!(
        loaded
            .copy_vmstate_to(&mut restored_vmstate)
            .expect("authenticate VMState"),
        vmstate_bytes.len() as u64
    );
    assert_eq!(restored_vmstate, vmstate_bytes);

    assert_eq!(
        store.publish(&prepared).expect("idempotent publish"),
        publication
    );
    assert_eq!(backend.object_count(), 3);
}

#[test]
fn directory_publication_is_reloadable_after_store_restart() {
    let directory = tempfile::tempdir().expect("create exact-checkpoint store directory");
    let root_path = directory.path().join("objects");
    let snapshot = snapshot("directory-restart");
    let vmstate_bytes = vec![0xa5; 64 * 1024];

    let first_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "first-exact-checkpoint-store",
        &root_path,
    ));
    let first = ExactCheckpointStore::new(first_backend, STORE_LIMIT).expect("admit first store");
    let prepared = first
        .prepare(&snapshot, BlobHandle::from_bytes(vmstate_bytes.clone()))
        .expect("prepare durable checkpoint");
    let root = first
        .publish(&prepared)
        .expect("publish durable checkpoint")
        .root();
    drop(first);

    let reopened_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "reopened-exact-checkpoint-store",
        root_path,
    ));
    let reopened = ExactCheckpointStore::new(reopened_backend, STORE_LIMIT).expect("reopen store");
    let loaded = reopened.load(root).expect("load after restart");
    let mut restored = Vec::new();
    loaded
        .copy_vmstate_to(&mut restored)
        .expect("authenticate restarted VMState");

    assert_eq!(loaded.snapshot(), &snapshot);
    assert_eq!(restored, vmstate_bytes);
}

#[test]
fn store_requires_durable_streaming_conditional_backend() {
    let memory: Arc<dyn ImmutableBlobBackend> =
        Arc::new(MemoryBlobBackend::new("non-durable", STORE_LIMIT));
    assert!(matches!(
        ExactCheckpointStore::new(memory, STORE_LIMIT),
        Err(ExactCheckpointStoreError::UnsupportedBackend {
            capability: "durable"
        })
    ));

    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(TestDurableBackend::new());
    assert!(matches!(
        ExactCheckpointStore::new(backend, 0),
        Err(ExactCheckpointStoreError::InvalidLimit)
    ));
}

#[test]
fn oversized_vmstate_is_rejected_before_open_or_store_write() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let opens = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(OpenCountingSource {
        logical_length: STORE_LIMIT + 1,
        opens: opens.clone(),
    }));

    assert!(matches!(
        store.prepare(&snapshot("oversized"), source),
        Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "qemu-vmstate",
            length,
            maximum: STORE_LIMIT,
        }) if length == STORE_LIMIT + 1
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    assert_eq!(backend.object_count(), 0);
}

#[test]
fn load_fails_closed_when_a_root_child_is_missing() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let prepared = store
        .prepare(
            &snapshot("missing-child"),
            BlobHandle::from_bytes(vec![7; 512]),
        )
        .expect("prepare root");
    backend
        .put_if_absent(prepared.root.content_id(), &prepared.root_source)
        .expect("publish only root");

    assert!(matches!(
        store.load(prepared.root()),
        Err(ExactCheckpointStoreError::Store(StoreError::NotFound { id }))
            if id == prepared.metadata_id()
    ));
    assert_eq!(backend.object_count(), 1);
}

#[test]
fn load_rejects_extraneous_root_children_before_child_reads() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let prepared = store
        .prepare(
            &snapshot("extra-child"),
            BlobHandle::from_bytes(vec![9; 512]),
        )
        .expect("prepare root");
    let root_bytes = prepared
        .root_source
        .read_all(MAX_ROOT_BYTES)
        .expect("read prepared root");
    let root = ContentEnvelope::from_canonical_bytes(&root_bytes).expect("decode root");
    let extra_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"smuggled");
    let mut children = root.children().clone();
    children.insert(ContentChild::new("extra", extra_id).expect("extra child"));
    let malformed = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        root.body().to_vec(),
    )
    .expect("bounded malformed root");
    let malformed_id =
        ExactCheckpointId::from_content_id(malformed.content_id(ObjectKind::ExactManifest))
            .expect("typed malformed root");
    backend
        .put_if_absent(
            malformed_id.content_id(),
            &BlobHandle::from_bytes(malformed.canonical_bytes()),
        )
        .expect("publish malformed root");

    assert!(matches!(
        store.load(malformed_id),
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "root must contain exactly two children"
        })
    ));
    assert_eq!(backend.object_count(), 1);
}

#[test]
fn root_binds_snapshot_semantics_not_only_child_shape() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let original = store
        .prepare(&snapshot("basis-a"), BlobHandle::from_bytes(vec![1; 512]))
        .expect("prepare original");
    let replacement = store
        .prepare(&snapshot("basis-b"), BlobHandle::from_bytes(vec![1; 512]))
        .expect("prepare replacement");
    backend
        .put_if_absent(replacement.metadata_id, &replacement.metadata_source)
        .expect("publish replacement metadata");

    let original_bytes = original
        .root_source
        .read_all(MAX_ROOT_BYTES)
        .expect("read original root");
    let original_root = ContentEnvelope::from_canonical_bytes(&original_bytes).expect("root");
    let original_body = decode_root_body(original_root.body()).expect("decode original body");
    let forged_body = encode_root_body(
        original_body.snapshot_identity,
        original_body.configuration,
        replacement.metadata_source.logical_length(),
        replacement.vmstate_source.logical_length(),
    );
    let children = BTreeSet::from([
        ContentChild::new(SNAPSHOT_METADATA_ROLE, replacement.metadata_id)
            .expect("replacement metadata child"),
        ContentChild::new(QEMU_VMSTATE_ROLE, replacement.vmstate_id)
            .expect("replacement VMState child"),
    ]);
    let forged = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        forged_body,
    )
    .expect("forge structurally valid root");
    let forged_id =
        ExactCheckpointId::from_content_id(forged.content_id(ObjectKind::ExactManifest))
            .expect("typed forged root");
    backend
        .put_if_absent(
            forged_id.content_id(),
            &BlobHandle::from_bytes(forged.canonical_bytes()),
        )
        .expect("publish forged root");

    let error = store
        .load(forged_id)
        .err()
        .expect("forged root must fail closed");
    assert!(
        matches!(
            error,
            ExactCheckpointStoreError::InvalidRoot {
                reason: "snapshot semantic basis mismatch"
            }
        ),
        "unexpected forged-root error: {error:?}"
    );
}

fn snapshot(name: &str) -> QemuVmSnapshot {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-checkpoint-store",
        name,
    ));
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("build checkpoint");
    QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("build snapshot")
}
