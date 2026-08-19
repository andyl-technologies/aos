//! Conformance tests for content-store identities, leaves, refs, and layers.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use tempfile::TempDir;

use super::composition::{RoutedStore, TieredStore, WriteThroughStore};
use super::directory::{DirectoryBlobBackend, DirectoryRefBackend};
use super::memory::{MemoryBlobBackend, MemoryRefBackend};
use super::*;

#[test]
fn content_identity_is_domain_and_schema_separated() {
    let bytes = b"same bytes";
    let page = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let disk = ContentId::for_bytes(ObjectKind::DiskExtent, 1, bytes);
    let page_v2 = ContentId::for_bytes(ObjectKind::RamExtent, 2, bytes);

    assert_ne!(page, disk);
    assert_ne!(page, page_v2);
    assert_eq!(
        ContentId::parse(&page.encode()).expect("parse content ID"),
        page
    );
    assert!(page.authenticates(bytes));
    assert!(!page.authenticates(b"different"));

    let canonical = page.encode();
    let (prefix, digest) = canonical.rsplit_once('.').expect("digest separator");
    assert!(matches!(
        ContentId::parse(&format!("{prefix}.{}", digest.to_ascii_uppercase())),
        Err(StoreError::InvalidId)
    ));
    assert!(matches!(
        ContentId::parse(&format!("{}.01.{digest}", ObjectKind::RamExtent.as_str())),
        Err(StoreError::InvalidId)
    ));
}

#[test]
fn invalid_ref_names_fail_closed() {
    for invalid in ["", "/absolute", "../escape", "a//b", "a/../b", "snowman-☃"] {
        assert!(matches!(
            RefName::new(invalid),
            Err(StoreError::InvalidRefName { .. })
        ));
    }
    assert!(matches!(
        RefName::new("a".repeat(1_025)),
        Err(StoreError::InvalidRefName { .. })
    ));
    assert!(matches!(
        RefName::new(format!("campaigns/{}", "a".repeat(256))),
        Err(StoreError::InvalidRefName { .. })
    ));
    assert_eq!(
        RefName::new("campaigns/network-recovery")
            .expect("valid ref")
            .as_str(),
        "campaigns/network-recovery"
    );
}

#[test]
fn memory_blob_and_ref_contracts_are_idempotent() {
    let blobs = MemoryBlobBackend::new("memory", 1_024);
    let bytes = b"campaign snapshot";
    let id = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, bytes);

    assert!(!blobs.contains(id).expect("query empty memory store"));
    let first = blobs.put_if_absent(id, bytes).expect("first put");
    let second = blobs.put_if_absent(id, bytes).expect("duplicate put");
    assert_eq!(first, second);
    assert_eq!(blobs.object_count().expect("object count"), 1);
    assert_eq!(blobs.logical_bytes().expect("logical bytes"), 17);
    assert_eq!(
        blobs
            .read(id, Some(ByteRange::new(9, 8).expect("valid range")))
            .expect("range read"),
        b"snapshot"
    );

    let refs = MemoryRefBackend::new();
    let name = RefName::new("campaigns/demo").expect("valid ref");
    assert_eq!(refs.read_ref(&name).expect("empty ref"), None);
    assert_eq!(
        refs.compare_exchange(&name, None, id).expect("initial CAS"),
        RefCasOutcome::Advanced { next: id }
    );
    assert_eq!(
        refs.compare_exchange(&name, None, id).expect("stale CAS"),
        RefCasOutcome::Conflict {
            expected: None,
            current: Some(id)
        }
    );
}

#[test]
fn directory_backend_publishes_objects_and_refs_durably() {
    let temp = TempDir::new().expect("temporary directory");
    let blobs = DirectoryBlobBackend::new("directory", temp.path().join("blobs"));
    let refs = DirectoryRefBackend::new(temp.path().join("authority"));
    let bytes = b"exact ram extent bytes";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);

    let receipt = blobs.put_if_absent(id, bytes).expect("directory put");
    assert!(receipt.is_durable());
    assert_eq!(blobs.read(id, None).expect("directory read"), bytes);
    assert_eq!(
        blobs
            .read(id, Some(ByteRange::new(6, 3).expect("valid range")))
            .expect("directory range"),
        b"ram"
    );
    assert_eq!(
        blobs.put_if_absent(id, bytes).expect("idempotent put"),
        receipt
    );

    let name = RefName::new("campaigns/demo").expect("valid ref");
    assert_eq!(
        refs.compare_exchange(&name, None, id)
            .expect("directory CAS"),
        RefCasOutcome::Advanced { next: id }
    );
    assert_eq!(refs.read_ref(&name).expect("directory ref read"), Some(id));

    let reopened_blobs = DirectoryBlobBackend::new("reopened", temp.path().join("blobs"));
    let reopened_refs = DirectoryRefBackend::new(temp.path().join("authority"));
    assert_eq!(
        reopened_blobs.read(id, None).expect("reopened object"),
        bytes
    );
    assert_eq!(
        reopened_refs.read_ref(&name).expect("reopened ref"),
        Some(id)
    );

    fs::write(object_path(reopened_blobs.root(), id), b"corrupt").expect("corrupt object body");
    assert!(matches!(
        reopened_blobs.read(id, None),
        Err(StoreError::Corrupt { .. })
    ));
    fs::write(
        reopened_refs.root().join("refs").join(name.as_str()),
        format!(" {}\n", id.encode()),
    )
    .expect("corrupt ref record");
    assert!(matches!(
        reopened_refs.read_ref(&name),
        Err(StoreError::InvalidId)
    ));
}

#[test]
fn tiered_reads_promote_only_verified_objects() {
    let cache = Arc::new(MemoryBlobBackend::new("cache", 1_024));
    let durable = Arc::new(MemoryBlobBackend::new("durable-test", 1_024));
    let bytes = b"finding bundle";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    durable.put_if_absent(id, bytes).expect("seed lower tier");

    let tiers: Vec<Arc<dyn ImmutableBlobBackend>> = vec![cache.clone(), durable];
    let store = TieredStore::new("tiered", tiers, 1, true).expect("valid tiers");
    assert_eq!(store.read(id, None).expect("tiered read"), bytes);
    assert!(cache.contains(id).expect("promoted cache object"));
}

#[test]
fn routed_and_write_through_stores_preserve_logical_identity() {
    let metadata_a = Arc::new(MemoryBlobBackend::new("metadata-a", 1_024));
    let metadata_b = Arc::new(MemoryBlobBackend::new("metadata-b", 1_024));
    let mirror_children: Vec<Arc<dyn ImmutableBlobBackend>> =
        vec![metadata_a.clone(), metadata_b.clone()];
    let mirror =
        Arc::new(WriteThroughStore::new("metadata-mirror", mirror_children).expect("valid mirror"));
    let ram = Arc::new(MemoryBlobBackend::new("ram", 1_024));
    let mut routes: BTreeMap<ObjectKind, Arc<dyn ImmutableBlobBackend>> = BTreeMap::new();
    routes.insert(ObjectKind::CampaignFact, mirror);
    routes.insert(ObjectKind::RamExtent, ram.clone());
    let routed = RoutedStore::new("router", routes).expect("valid routes");

    let fact_bytes = b"fact";
    let fact = ContentId::for_bytes(ObjectKind::CampaignFact, 1, fact_bytes);
    let receipt = routed
        .put_if_absent(fact, fact_bytes)
        .expect("mirrored fact put");
    assert_eq!(receipt.placements.len(), 2);
    assert!(metadata_a.contains(fact).expect("first mirror"));
    assert!(metadata_b.contains(fact).expect("second mirror"));

    let ram_bytes = b"page";
    let page = ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);
    routed
        .put_if_absent(page, ram_bytes)
        .expect("routed page put");
    assert!(ram.contains(page).expect("ram route"));
}

#[test]
fn invalid_ranges_and_mismatched_puts_are_rejected() {
    let store = MemoryBlobBackend::new("memory", 3);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"abc");
    assert!(matches!(
        store.put_if_absent(id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    store.put_if_absent(id, b"abc").expect("valid put");
    let overflow_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"d");
    assert!(matches!(
        store.put_if_absent(overflow_id, b"d"),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        store.read(
            id,
            Some(ByteRange::new(2, 2).expect("non-overflowing range"))
        ),
        Err(StoreError::InvalidRange { .. })
    ));
}

#[test]
fn directory_put_and_ref_cas_are_process_concurrent() {
    let temp = TempDir::new().expect("temporary directory");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "directory",
        temp.path().join("blobs"),
    ));
    let bytes = b"shared immutable bytes";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    let barrier = Arc::new(Barrier::new(8));
    let mut putters = Vec::new();
    for _ in 0..8 {
        let blobs = blobs.clone();
        let barrier = barrier.clone();
        putters.push(thread::spawn(move || {
            barrier.wait();
            blobs.put_if_absent(id, bytes)
        }));
    }
    for putter in putters {
        assert!(putter.join().expect("put thread").is_ok());
    }
    assert_eq!(blobs.read(id, None).expect("concurrent object"), bytes);

    let refs = Arc::new(DirectoryRefBackend::new(temp.path().join("authority")));
    let name = RefName::new("campaigns/race").expect("valid ref");
    let candidates: Vec<_> = (0_u8..8)
        .map(|value| ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, &[value]))
        .collect();
    let barrier = Arc::new(Barrier::new(candidates.len()));
    let mut writers = Vec::new();
    for next in candidates.iter().copied() {
        let refs = refs.clone();
        let name = name.clone();
        let barrier = barrier.clone();
        writers.push(thread::spawn(move || {
            barrier.wait();
            refs.compare_exchange(&name, None, next)
        }));
    }
    let outcomes: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().expect("ref thread").expect("ref CAS"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RefCasOutcome::Advanced { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RefCasOutcome::Conflict { .. }))
            .count(),
        candidates.len() - 1
    );
    assert!(
        candidates.contains(
            &refs
                .read_ref(&name)
                .expect("read winning ref")
                .expect("winning ref")
        )
    );
}

#[test]
fn capabilities_and_composed_failures_are_truthful() {
    let temp = TempDir::new().expect("temporary directory");
    let directory = Arc::new(DirectoryBlobBackend::new(
        "directory",
        temp.path().join("blobs"),
    ));
    assert_eq!(
        directory.capabilities(),
        BackendCapabilities {
            durable: true,
            range_read: true,
            conditional_create: true,
            streaming_put: false,
            repair_inventory: false,
            planned_delete: false,
        }
    );

    let memory = Arc::new(MemoryBlobBackend::new("memory", 1_024));
    let children: Vec<Arc<dyn ImmutableBlobBackend>> = vec![memory.clone(), directory];
    let write_through =
        WriteThroughStore::new("write-through", children).expect("valid write-through");
    assert!(write_through.capabilities().durable);

    let lower = Arc::new(MemoryBlobBackend::new("lower", 1_024));
    let bytes = b"lower bytes";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    lower.put_if_absent(id, bytes).expect("seed lower tier");
    let unavailable: Arc<dyn ImmutableBlobBackend> = Arc::new(UnavailableReadBackend);
    let lower_trait: Arc<dyn ImmutableBlobBackend> = lower;
    let tiered = TieredStore::new("tiered", vec![unavailable, lower_trait], 1, false)
        .expect("valid tiered store");
    assert!(matches!(
        tiered.read(id, None),
        Err(StoreError::Unavailable)
    ));
}

#[test]
fn partial_write_through_is_retryable() {
    let first = Arc::new(MemoryBlobBackend::new("first", 1_024));
    let second = Arc::new(FailFirstPutBackend::new());
    let children: Vec<Arc<dyn ImmutableBlobBackend>> = vec![first.clone(), second.clone()];
    let store = WriteThroughStore::new("mirror", children).expect("valid mirror");
    let bytes = b"retryable immutable object";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);

    assert!(matches!(
        store.put_if_absent(id, bytes),
        Err(StoreError::Unavailable)
    ));
    assert!(first.contains(id).expect("first orphan is readable"));
    assert!(!second.contains(id).expect("second placement absent"));

    let receipt = store.put_if_absent(id, bytes).expect("retry mirror put");
    assert_eq!(receipt.placements.len(), 2);
    assert!(second.contains(id).expect("second placement repaired"));
}

fn object_path(root: &Path, id: ContentId) -> PathBuf {
    let encoded = id.encode();
    let digest = encoded.rsplit_once('.').expect("digest separator").1;
    root.join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest)
}

struct UnavailableReadBackend;

impl ImmutableBlobBackend for UnavailableReadBackend {
    fn name(&self) -> &str {
        "unavailable"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        Err(StoreError::Unavailable)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::Unavailable)
    }

    fn put_if_absent(&self, _id: ContentId, _bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unavailable)
    }
}

struct FailFirstPutBackend {
    failed: AtomicBool,
    inner: MemoryBlobBackend,
}

impl FailFirstPutBackend {
    fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            inner: MemoryBlobBackend::new("fail-first-inner", 1_024),
        }
    }
}

impl ImmutableBlobBackend for FailFirstPutBackend {
    fn name(&self) -> &str {
        "fail-first"
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.put_if_absent(id, bytes)
    }
}
