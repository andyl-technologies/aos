//! Conformance tests for content-store identities, leaves, refs, and layers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use super::composition::{
    MetricsStore, ReadThroughStore, RoutedStore, TieredStore, TieredStoreChild, WriteThroughStore,
};
use super::directory::{DirectoryBlobBackend, DirectoryRefBackend};
use super::graph::{
    StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeKind, StoreNodeSpec, StoreTierPolicy,
};
use super::memory::{MemoryBlobBackend, MemoryRefBackend};
use super::*;

const TEST_READ_LIMIT: u64 = 1024 * 1024;

fn tier(
    backend: Arc<dyn ImmutableBlobBackend>,
    readable: bool,
    writable: bool,
    promote_reads: bool,
) -> TieredStoreChild {
    TieredStoreChild {
        backend,
        readable,
        writable,
        promote_reads,
    }
}

#[cfg(feature = "destructive-recovery-faults")]
const CORRUPT_TIER_COPY_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_CORRUPT_TIER_COPY_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const CORRUPT_TIER_COPY_ROOT_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_CORRUPT_TIER_COPY_ROOT";
#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const CORRUPT_TIER_COPY_TRIGGER: &str = "crucible.destructive-recovery.corrupt-tier-copy";
#[cfg(feature = "destructive-recovery-faults")]
const CORRUPT_TIER_COPY_TEST_NAME: &str = "content_store::tests::tier::corrupt_tier_copy_fails_closed_then_repairs_from_authenticated_lower_tier";
#[cfg(feature = "destructive-recovery-faults")]
const CORRUPT_TIER_COPY_CHILD_EXIT_CODE: i32 = 90;
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_PACK_INDEX_INTERRUPTION_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_ROOT_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_PACK_INDEX_INTERRUPTION_ROOT";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_TRIGGER: &str =
    "crucible.destructive-recovery.pack-index-interruption";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_TEST_NAME: &str =
    "content_store::tests::packed::pack_index_interruption_recovers_old_generation_and_retries";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_CHILD_EXIT_CODE: i32 = 91;

// Cross-instance directory fences can include filesystem sync work after the
// lock is released. Leave enough headroom for highly parallel test runners.
const FILESYSTEM_FENCE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct RecordingNamespaceAuthorizer {
    allowed: AtomicBool,
    calls: Mutex<Vec<(StoreNamespaceOperation, ContentId)>>,
}

impl RecordingNamespaceAuthorizer {
    fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
    }

    fn calls(&self) -> Vec<(StoreNamespaceOperation, ContentId)> {
        self.calls.lock().expect("namespace call lock").clone()
    }
}

impl StoreNamespaceAuthorizer for RecordingNamespaceAuthorizer {
    fn authorize(
        &self,
        operation: StoreNamespaceOperation,
        id: ContentId,
    ) -> Result<(), StoreError> {
        self.calls
            .lock()
            .expect("namespace call lock")
            .push((operation, id));
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }
}

struct RecordingObjectProfiler {
    allowed: AtomicBool,
    calls: AtomicUsize,
    returned_kind: Mutex<Option<ObjectKind>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedPhysicalQuotaBinding {
    root: PathBuf,
    project_id: u32,
    maximum_physical_bytes: u64,
    maximum_inodes: u64,
}

#[derive(Default)]
struct RecordingPhysicalQuotaGuard {
    allowed: AtomicBool,
    calls: AtomicUsize,
}

impl RecordingPhysicalQuotaGuard {
    fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for RecordingPhysicalQuotaGuard {
    fn verify(&self) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Quota)
        }
    }
}

struct RecordingPhysicalQuotaBinder {
    guard: Arc<RecordingPhysicalQuotaGuard>,
    bindings: Mutex<Vec<RecordedPhysicalQuotaBinding>>,
}

impl RecordingPhysicalQuotaBinder {
    fn new(allowed: bool) -> Self {
        let guard = Arc::new(RecordingPhysicalQuotaGuard::default());
        guard.set_allowed(allowed);
        Self {
            guard,
            bindings: Mutex::new(Vec::new()),
        }
    }

    fn bindings(&self) -> Vec<RecordedPhysicalQuotaBinding> {
        self.bindings.lock().expect("quota binding lock").clone()
    }
}

impl StorePhysicalQuotaBinder for RecordingPhysicalQuotaBinder {
    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.bindings
            .lock()
            .expect("quota binding lock")
            .push(RecordedPhysicalQuotaBinding {
                root: root.to_owned(),
                project_id,
                maximum_physical_bytes,
                maximum_inodes,
            });
        self.guard.verify()?;
        Ok(self.guard.clone())
    }
}

impl RecordingObjectProfiler {
    fn new(allowed: bool) -> Self {
        Self {
            allowed: AtomicBool::new(allowed),
            calls: AtomicUsize::new(0),
            returned_kind: Mutex::new(None),
        }
    }

    fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
    }

    fn set_returned_kind(&self, kind: Option<ObjectKind>) {
        *self.returned_kind.lock().expect("profile kind lock") = kind;
    }
}

impl StoreObjectProfiler for RecordingObjectProfiler {
    fn derive_profile(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<ObjectProfile, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.allowed.load(Ordering::SeqCst) {
            return Err(StoreError::Unauthorized);
        }
        let kind = self
            .returned_kind
            .lock()
            .expect("profile kind lock")
            .unwrap_or(id.kind());
        Ok(ObjectProfile::new(
            kind,
            source.logical_length(),
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        ))
    }
}

fn put_bytes(
    store: &dyn ImmutableBlobBackend,
    id: ContentId,
    bytes: &[u8],
) -> Result<PutReceipt, StoreError> {
    store.put_if_absent(id, &BlobHandle::from_bytes(bytes))
}

fn read_bytes(
    store: &dyn ImmutableBlobBackend,
    id: ContentId,
    range: Option<ByteRange>,
) -> Result<Vec<u8>, StoreError> {
    store.read(id, range)?.read_all(TEST_READ_LIMIT)
}

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
    let first = put_bytes(&blobs, id, bytes).expect("first put");
    let second = put_bytes(&blobs, id, bytes).expect("duplicate put");
    assert_eq!(first, second);
    assert_eq!(blobs.object_count().expect("object count"), 1);
    assert_eq!(blobs.logical_bytes().expect("logical bytes"), 17);
    assert_eq!(
        read_bytes(&blobs, id, Some(ByteRange::new(9, 8).expect("valid range")))
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

fn assert_bounded_ref_scan_contract(refs: &dyn MutableRefBackend) {
    let namespace = RefName::new("campaigns").expect("campaign namespace");
    let alpha = RefName::new("campaigns/alpha").expect("alpha ref");
    let zeta = RefName::new("campaigns/zeta").expect("zeta ref");
    let unrelated = RefName::new("other/ignored").expect("unrelated ref");
    let alpha_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"alpha");
    let zeta_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"zeta");
    let unrelated_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"unrelated");
    refs.compare_exchange(&zeta, None, zeta_target)
        .expect("create zeta ref");
    refs.compare_exchange(&unrelated, None, unrelated_target)
        .expect("create unrelated ref");
    refs.compare_exchange(&alpha, None, alpha_target)
        .expect("create alpha ref");

    let first = refs
        .scan_refs(&namespace, None, 1)
        .expect("scan first campaign ref page");
    assert_eq!(first.entries().len(), 1);
    assert_eq!(first.entries()[0].name(), &alpha);
    assert_eq!(first.entries()[0].target(), alpha_target);
    assert_eq!(first.next_after(), Some(&alpha));
    assert!(first.visited() > 0);

    let second = refs
        .scan_refs(&namespace, Some(&alpha), 1)
        .expect("scan second campaign ref page");
    assert_eq!(second.entries().len(), 1);
    assert_eq!(second.entries()[0].name(), &zeta);
    assert_eq!(second.entries()[0].target(), zeta_target);
    assert_eq!(second.next_after(), None);

    assert!(matches!(
        refs.scan_refs(&namespace, Some(&unrelated), 1),
        Err(StoreError::InvalidComposition {
            reason: "authoritative ref scan cursor is outside its namespace"
        })
    ));
    assert!(matches!(
        refs.scan_refs(&namespace, None, 0),
        Err(StoreError::Quota)
    ));
}

#[test]
fn memory_ref_scan_is_bounded_ordered_and_namespaced() {
    assert_bounded_ref_scan_contract(&MemoryRefBackend::new());
}

#[test]
fn directory_ref_scan_is_bounded_ordered_and_namespaced() {
    let temp = TempDir::new().expect("temporary directory");
    assert_bounded_ref_scan_contract(&DirectoryRefBackend::new(temp.path()));
}

#[test]
fn directory_leafs_pass_the_shared_persistent_conformance_suite() {
    let temp = TempDir::new().expect("temporary directory conformance root");
    super::conformance::assert_blob_leaf_conformance(&DirectoryBlobBackend::new(
        "directory-conformance",
        temp.path().join("objects"),
    ));
    super::conformance::assert_ref_leaf_conformance(&DirectoryRefBackend::new(
        temp.path().join("refs"),
    ));
}

#[test]
fn memory_ref_inventory_is_exclusive_and_aba_bound() {
    let refs = Arc::new(MemoryRefBackend::new());
    let first_name = RefName::new("campaigns/first").expect("first ref name");
    let second_name = RefName::new("campaigns/second").expect("second ref name");
    let first = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"first");
    let second = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"second");
    let third = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"third");
    refs.compare_exchange(&first_name, None, first)
        .expect("create first memory ref");
    refs.compare_exchange(&second_name, None, second)
        .expect("create second memory ref");

    let mut fence = refs
        .acquire_ref_inventory_fence()
        .expect("acquire memory ref fence");
    let mut inventory = BTreeMap::new();
    let before = fence
        .visit_refs(&mut |record| {
            inventory.insert(record.name().clone(), record.target());
            Ok(())
        })
        .expect("visit memory refs");
    assert_eq!(before.refs(), 2);
    assert_eq!(
        inventory,
        BTreeMap::from([(first_name.clone(), first), (second_name, second)])
    );
    drop(fence);

    assert_eq!(
        refs.compare_exchange(&first_name, Some(third), second)
            .expect("reject stale memory ref replacement"),
        RefCasOutcome::Conflict {
            expected: Some(third),
            current: Some(first),
        }
    );
    let mut fence = refs
        .acquire_ref_inventory_fence()
        .expect("reacquire memory ref fence after conflict");
    let after_conflict = fence
        .visit_refs(&mut |_| Ok(()))
        .expect("visit memory refs after conflict");
    assert_eq!(after_conflict.generation(), before.generation());

    let writer_refs = Arc::clone(&refs);
    let writer_name = first_name.clone();
    let writer_started = Arc::new(AtomicBool::new(false));
    let writer_finished = Arc::new(AtomicBool::new(false));
    let writer_started_clone = Arc::clone(&writer_started);
    let writer_finished_clone = Arc::clone(&writer_finished);
    let writer = thread::spawn(move || {
        writer_started_clone.store(true, Ordering::Release);
        writer_refs
            .compare_exchange(&writer_name, Some(first), third)
            .expect("update fenced memory ref");
        writer_finished_clone.store(true, Ordering::Release);
    });
    while !writer_started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(std::time::Duration::from_millis(10));
    assert!(!writer_finished.load(Ordering::Acquire));
    drop(fence);
    writer.join().expect("join memory ref writer");

    refs.compare_exchange(&first_name, Some(third), first)
        .expect("restore memory ref after ABA");
    let mut after_fence = refs
        .acquire_ref_inventory_fence()
        .expect("reacquire memory ref fence");
    let after = after_fence
        .visit_refs(&mut |_| Ok(()))
        .expect("visit memory refs after ABA");
    assert_ne!(after.generation(), before.generation());
    assert_eq!(after.refs(), before.refs());
}

#[test]
fn memory_ref_inventory_waits_for_in_flight_publication() {
    let refs = Arc::new(MemoryRefBackend::new());
    let publication = refs
        .acquire_publication_guard()
        .expect("acquire memory publication guard");
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let worker_refs = Arc::clone(&refs);
    let worker = thread::spawn(move || {
        started_tx.send(()).expect("signal inventory attempt");
        let _fence = worker_refs
            .acquire_ref_inventory_fence()
            .expect("acquire memory inventory fence");
        acquired_tx.send(()).expect("signal acquired inventory");
    });

    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("inventory worker started");
    assert!(matches!(
        acquired_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    drop(publication);
    acquired_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("inventory acquired after publication completed");
    worker.join().expect("join memory inventory worker");
}

#[test]
fn memory_administration_is_generation_bound_and_idempotent() {
    let blobs = MemoryBlobBackend::new("memory-admin", 1_024);
    let first_bytes = b"first retained object";
    let second_bytes = b"second retained object";
    let first = ContentId::for_bytes(ObjectKind::CampaignFact, 1, first_bytes);
    let second = ContentId::for_bytes(ObjectKind::Observation, 1, second_bytes);
    put_bytes(&blobs, first, first_bytes).expect("put first object");
    put_bytes(&blobs, second, second_bytes).expect("put second object");

    let mut fence = blobs
        .acquire_inventory_fence()
        .expect("acquire memory inventory fence");
    let mut records = Vec::new();
    let before = fence
        .visit_inventory(&mut |record| {
            records.push(record);
            Ok(())
        })
        .expect("visit initial inventory");
    assert_eq!(before.backend(), "memory-admin");
    assert_eq!(before.objects(), 2);
    assert_eq!(
        before.logical_bytes(),
        u64::try_from(first_bytes.len() + second_bytes.len()).expect("test byte count")
    );
    assert_eq!(
        records.iter().map(|record| record.id()).collect::<Vec<_>>(),
        BTreeSet::from([first, second])
            .into_iter()
            .collect::<Vec<_>>()
    );

    let mut bounded_visits = 0_u8;
    assert!(matches!(
        fence.visit_inventory(&mut |_| {
            bounded_visits = bounded_visits.saturating_add(1);
            Err(StoreError::Quota)
        }),
        Err(StoreError::Quota)
    ));
    assert_eq!(bounded_visits, 1);

    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete planned candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("repeat candidate deletion"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    let mut retained = Vec::new();
    let after = fence
        .visit_inventory(&mut |record| {
            retained.push(record);
            Ok(())
        })
        .expect("visit retained inventory");
    assert_ne!(after.generation(), before.generation());
    assert_eq!(after.objects(), 1);
    assert_eq!(
        retained,
        [BlobInventoryRecord::new(
            second,
            u64::try_from(second_bytes.len()).expect("test byte count"),
        )]
    );
    drop(fence);

    assert!(!blobs.contains(first).expect("query deleted candidate"));
    assert!(blobs.contains(second).expect("query retained object"));
    put_bytes(&blobs, first, first_bytes).expect("reinsert deleted object");
    let mut reinserted_fence = blobs
        .acquire_inventory_fence()
        .expect("acquire reinserted inventory fence");
    let reinserted = reinserted_fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("visit reinserted inventory");
    assert_eq!(reinserted.objects(), before.objects());
    assert_ne!(reinserted.generation(), before.generation());
    drop(reinserted_fence);
    assert_eq!(blobs.object_count().expect("reinserted object count"), 2);
}

#[test]
fn directory_backend_publishes_objects_and_refs_durably() {
    let temp = TempDir::new().expect("temporary directory");
    let blobs = DirectoryBlobBackend::new("directory", temp.path().join("blobs"));
    let refs = DirectoryRefBackend::new(temp.path().join("authority"));
    let bytes = b"exact ram extent bytes";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);

    let receipt = put_bytes(&blobs, id, bytes).expect("directory put");
    assert!(receipt.is_durable());
    assert_eq!(read_bytes(&blobs, id, None).expect("directory read"), bytes);
    assert_eq!(
        read_bytes(&blobs, id, Some(ByteRange::new(6, 3).expect("valid range")))
            .expect("directory range"),
        b"ram"
    );
    assert_eq!(
        put_bytes(&blobs, id, bytes).expect("idempotent put"),
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
        read_bytes(&reopened_blobs, id, None).expect("reopened object"),
        bytes
    );
    assert_eq!(
        reopened_refs.read_ref(&name).expect("reopened ref"),
        Some(id)
    );

    fs::write(object_path(reopened_blobs.root(), id), b"corrupt").expect("corrupt object body");
    assert!(matches!(
        read_bytes(&reopened_blobs, id, None),
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
fn compressed_directory_is_a_bounded_versioned_graph_leaf() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("compressed");
    let config = |maximum_logical_object_bytes| StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
        nodes: BTreeMap::from([(
            root.clone(),
            StoreNodeSpec::CompressedDirectory {
                root: temp.path().join("objects"),
                maximum_logical_object_bytes,
            },
        )]),
    };
    let (graph, admin) =
        StoreGraph::build_with_admin(config(1024 * 1024)).expect("compressed graph");
    let restarted = StoreGraph::build(config(1024 * 1024)).expect("restarted compressed graph");
    let changed = StoreGraph::build(config(2 * 1024 * 1024)).expect("changed compressed graph");

    assert_eq!(graph.configuration_id(), admin.configuration_id());
    assert_eq!(graph.configuration_id(), restarted.configuration_id());
    assert_ne!(graph.configuration_id(), changed.configuration_id());
    assert_eq!(graph.describe()[0].kind, StoreNodeKind::CompressedDirectory);
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &root);
    let bytes = vec![0x77; 256 * 1024];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    put_bytes(&graph, id, &bytes).expect("compressed graph put");
    assert_eq!(
        read_bytes(&restarted, id, None).expect("graph restart read"),
        bytes
    );
    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("graph compressed inventory fence");
    assert_eq!(
        fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("graph compressed inventory")
            .objects(),
        1
    );

    assert!(matches!(
        StoreGraph::build(config(0)),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidCompressedObjectLimit,
            ..
        })
    ));

    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let compressed = node_id("compressed-overlap");
    let shared_root = temp.path().join("overlap");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![directory.clone(), compressed.clone()],
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: shared_root.clone(),
                    },
                ),
                (
                    compressed,
                    StoreNodeSpec::CompressedDirectory {
                        root: shared_root,
                        maximum_logical_object_bytes: 1024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::OverlappingAdministrativePath,
            ..
        })
    ));
}

#[test]
fn encrypted_directory_graph_identity_excludes_secret_key_material() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("encrypted");
    let key_id = StoreEncryptionKeyId::new("campaign-key-10").expect("key ID");
    let config = |maximum_logical_object_bytes, key_id: StoreEncryptionKeyId| StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
        nodes: BTreeMap::from([(
            root.clone(),
            StoreNodeSpec::EncryptedDirectory {
                root: temp.path().join("objects"),
                maximum_logical_object_bytes,
                key_id,
            },
        )]),
    };
    let mut first_keys = StoreGraphKeyring::new();
    first_keys
        .insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x55; 32]).expect("first key"),
        )
        .expect("insert first key");
    let first_config = config(1024 * 1024, key_id.clone());
    assert!(!format!("{first_config:?}").contains(&"55".repeat(32)));
    let (first, admin) = StoreGraph::build_with_admin_and_keys(first_config, &first_keys)
        .expect("first encrypted graph");
    assert_eq!(first.describe()[0].kind, StoreNodeKind::EncryptedDirectory);
    assert_eq!(admin.physical().len(), 1);
    assert!(!format!("{:?}", first.describe()).contains(key_id.as_str()));
    let golden = StoreGraph::build_with_keys(
        StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
            nodes: BTreeMap::from([(
                root.clone(),
                StoreNodeSpec::EncryptedDirectory {
                    root: PathBuf::from("/var/lib/crucible/campaign-encrypted-objects"),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                },
            )]),
        },
        &first_keys,
    )
    .expect("golden encrypted graph");
    assert_eq!(
        encode_hex(&golden.configuration_id().as_bytes()),
        "383f1484965a1c7d4293081e20478ef0ded0eb99db25c7c7a55c6c47ce6ada0c"
    );

    let bytes = vec![0x71; 96 * 1024];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    put_bytes(&first, id, &bytes).expect("encrypted graph put");

    let mut same_keys = StoreGraphKeyring::new();
    same_keys
        .insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x55; 32]).expect("restart key"),
        )
        .expect("insert restart key");
    assert!(matches!(
        same_keys.insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x56; 32]).expect("duplicate key"),
        ),
        Err(StoreError::InvalidComposition { .. })
    ));
    let restarted = StoreGraph::build_with_keys(config(1024 * 1024, key_id.clone()), &same_keys)
        .expect("restart encrypted graph");
    assert_eq!(first.configuration_id(), restarted.configuration_id());
    assert_eq!(
        read_bytes(&restarted, id, None).expect("restart read"),
        bytes
    );

    let mut different_keys = StoreGraphKeyring::new();
    different_keys
        .insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x56; 32]).expect("different key"),
        )
        .expect("insert different key");
    let different_secret =
        StoreGraph::build_with_keys(config(1024 * 1024, key_id.clone()), &different_keys)
            .expect("different-secret graph");
    assert_eq!(
        first.configuration_id(),
        different_secret.configuration_id()
    );
    assert!(matches!(
        read_bytes(&different_secret, id, None),
        Err(StoreError::Unauthorized)
    ));

    let changed_limit =
        StoreGraph::build_with_keys(config(2 * 1024 * 1024, key_id.clone()), &same_keys)
            .expect("changed-limit graph");
    assert_ne!(first.configuration_id(), changed_limit.configuration_id());
    let second_key_id = StoreEncryptionKeyId::new("campaign-key-11").expect("second key ID");
    let mut second_keys = StoreGraphKeyring::new();
    second_keys
        .insert(
            second_key_id.clone(),
            StoreEncryptionKey::new([0x55; 32]).expect("second key"),
        )
        .expect("insert second key");
    let changed_key_id =
        StoreGraph::build_with_keys(config(1024 * 1024, second_key_id), &second_keys)
            .expect("changed-key-ID graph");
    assert_ne!(first.configuration_id(), changed_key_id.configuration_id());

    assert!(matches!(
        StoreGraph::build(config(1024 * 1024, key_id.clone())),
        Err(StoreError::Unauthorized)
    ));
    assert!(matches!(
        StoreGraph::build_with_keys(config(0, key_id.clone()), &same_keys),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidEncryptedObjectLimit,
            ..
        })
    ));
    assert!(matches!(
        StoreGraph::build_with_keys(config(64 * 1024 * 1024 + 1, key_id), &same_keys),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidEncryptedObjectLimit,
            ..
        })
    ));
}

#[test]
fn compressed_encrypted_directory_is_a_versioned_graph_leaf() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("compressed-encrypted");
    let key_id = StoreEncryptionKeyId::new("campaign-key-12").expect("key ID");
    let config = |maximum_logical_object_bytes| StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
        nodes: BTreeMap::from([(
            root.clone(),
            StoreNodeSpec::CompressedEncryptedDirectory {
                root: temp.path().join("objects"),
                maximum_logical_object_bytes,
                key_id: key_id.clone(),
            },
        )]),
    };
    let mut keys = StoreGraphKeyring::new();
    keys.insert(
        key_id.clone(),
        StoreEncryptionKey::new([0x57; 32]).expect("key"),
    )
    .expect("insert key");
    let (graph, admin) =
        StoreGraph::build_with_admin_and_keys(config(1024 * 1024), &keys).expect("graph");
    let restarted = StoreGraph::build_with_keys(config(1024 * 1024), &keys).expect("restart graph");
    let changed =
        StoreGraph::build_with_keys(config(2 * 1024 * 1024), &keys).expect("changed graph");

    assert_eq!(graph.configuration_id(), admin.configuration_id());
    assert_eq!(graph.configuration_id(), restarted.configuration_id());
    assert_ne!(graph.configuration_id(), changed.configuration_id());
    assert_eq!(
        graph.describe()[0].kind,
        StoreNodeKind::CompressedEncryptedDirectory
    );
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &root);
    let golden = StoreGraph::build_with_keys(
        StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
            nodes: BTreeMap::from([(
                root.clone(),
                StoreNodeSpec::CompressedEncryptedDirectory {
                    root: PathBuf::from("/var/lib/crucible/campaign-compressed-encrypted-objects"),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                },
            )]),
        },
        &keys,
    )
    .expect("golden compressed encrypted graph");
    assert_eq!(
        encode_hex(&golden.configuration_id().as_bytes()),
        "ba348b3fed11cd970bd559e0b3e97bb69f94a23db61cb07bca296449026b91a8"
    );

    let bytes = vec![0x5a; 256 * 1024];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    put_bytes(&graph, id, &bytes).expect("graph put");
    assert_eq!(
        read_bytes(&restarted, id, None).expect("restart read"),
        bytes
    );
    assert_eq!(
        admin.physical()[0]
            .admin()
            .acquire_inventory_fence()
            .expect("inventory fence")
            .visit_inventory(&mut |_| Ok(()))
            .expect("inventory")
            .objects(),
        1
    );

    assert!(matches!(
        StoreGraph::build(config(1024 * 1024)),
        Err(StoreError::Unauthorized)
    ));
    assert!(matches!(
        StoreGraph::build_with_keys(config(0), &keys),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidEncryptedObjectLimit,
            ..
        })
    ));
}

mod write_back;

mod packed;

mod graph_metrics;

mod directory;

mod tier;

mod graph_authorization;

mod quotas;

fn object_path(root: &Path, id: ContentId) -> PathBuf {
    let encoded = id.encode();
    let digest = encoded.rsplit_once('.').expect("digest separator").1;
    root.join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest)
}

fn node_id(value: &str) -> StoreNodeId {
    StoreNodeId::new(value).expect("valid store node ID")
}

fn write_back_graph(
    root: &Path,
    maximum_pending_objects: u64,
    maximum_pending_bytes: u64,
) -> Result<StoreGraph, StoreError> {
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    StoreGraph::build(StoreGraphConfig {
        root: write_back.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                write_back,
                StoreNodeSpec::WriteBack {
                    staging: staging.clone(),
                    destination: destination.clone(),
                    journal_root: root.join("journal"),
                    maximum_pending_objects,
                    maximum_pending_bytes,
                },
            ),
            (
                staging,
                StoreNodeSpec::Directory {
                    root: root.join("staging"),
                },
            ),
            (
                destination,
                StoreNodeSpec::Directory {
                    root: root.join("archive"),
                },
            ),
        ]),
    })
}

fn pack_file_count(root: &Path) -> usize {
    fs::read_dir(root.join("packs"))
        .expect("read pack directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".pack"))
        })
        .count()
}

fn pack_staging_file_count(root: &Path) -> usize {
    fs::read_dir(root.join("packs"))
        .expect("read pack directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".pack.tmp-")
        })
        .count()
}

fn only_pack_path(root: &Path) -> PathBuf {
    let packs = fs::read_dir(root.join("packs"))
        .expect("read pack directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".pack"))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(packs.len(), 1);
    packs[0].clone()
}

fn metrics_for<'a>(
    metrics: &'a [StoreNodeMetricsDescription],
    id: &StoreNodeId,
) -> &'a StoreNodeMetrics {
    &metrics
        .iter()
        .find(|entry| &entry.id == id)
        .expect("metrics node exists")
        .metrics
}

fn assert_no_staging(root: &Path, id: ContentId) {
    let path = object_path(root, id);
    let directory = path.parent().expect("object directory");
    if !directory.exists() {
        return;
    }
    assert!(
        fs::read_dir(directory)
            .expect("read object directory")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-"))
    );
}

struct UnavailableReadBackend;

struct CountingSource {
    bytes: Arc<[u8]>,
    opens: Arc<AtomicUsize>,
    bytes_read: Arc<AtomicUsize>,
}

impl BlobSource for CountingSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CountingReader {
            cursor: Cursor::new(self.bytes.clone()),
            bytes_read: self.bytes_read.clone(),
        }))
    }
}

struct CountingReader {
    cursor: Cursor<Arc<[u8]>>,
    bytes_read: Arc<AtomicUsize>,
}

impl Read for CountingReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.cursor.read(output)?;
        self.bytes_read.fetch_add(read, Ordering::SeqCst);
        Ok(read)
    }
}

struct BlockingSource {
    bytes: Arc<[u8]>,
    opened: mpsc::Sender<()>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl BlobSource for BlockingSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let release = self
            .release
            .lock()
            .expect("blocking source release lock")
            .take()
            .expect("blocking source opens once");
        self.opened.send(()).expect("signal blocking source open");
        Ok(Box::new(BlockingReader {
            cursor: Cursor::new(Arc::clone(&self.bytes)),
            release: Some(release),
        }))
    }
}

struct BlockingReader {
    cursor: Cursor<Arc<[u8]>>,
    release: Option<mpsc::Receiver<()>>,
}

impl Read for BlockingReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if let Some(release) = self.release.take() {
            release
                .recv()
                .map_err(|_| std::io::Error::other("blocking source release dropped"))?;
        }
        self.cursor.read(output)
    }
}

struct ChangingSource {
    opens: AtomicUsize,
    first: &'static [u8],
    later: &'static [u8],
}

impl BlobSource for ChangingSource {
    fn logical_length(&self) -> u64 {
        self.first.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let bytes = if self.opens.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first
        } else {
            self.later
        };
        Ok(Box::new(Cursor::new(bytes)))
    }
}

struct FailingSource {
    bytes: &'static [u8],
    fail_after: usize,
}

impl BlobSource for FailingSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(FailingReader {
            bytes: self.bytes,
            fail_after: self.fail_after,
            position: 0,
        }))
    }
}

struct FailingReader {
    bytes: &'static [u8],
    fail_after: usize,
    position: usize,
}

impl Read for FailingReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.fail_after {
            return Err(std::io::Error::other("injected mid-stream failure"));
        }
        let end = self
            .bytes
            .len()
            .min(self.fail_after)
            .min(self.position.saturating_add(output.len()));
        let bytes = &self.bytes[self.position..end];
        output[..bytes.len()].copy_from_slice(bytes);
        self.position = end;
        Ok(bytes.len())
    }
}

struct InterruptOnceSource {
    bytes: &'static [u8],
}

impl BlobSource for InterruptOnceSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(InterruptOnceReader {
            cursor: Cursor::new(self.bytes),
            interrupted: false,
        }))
    }
}

struct InterruptOnceReader {
    cursor: Cursor<&'static [u8]>,
    interrupted: bool,
}

impl Read for InterruptOnceReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        self.cursor.read(output)
    }
}

struct RepeatSource {
    byte: u8,
    logical_length: u64,
}

impl BlobSource for RepeatSource {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(
            std::io::repeat(self.byte).take(self.logical_length),
        ))
    }
}

struct MismatchedLengthSource {
    declared: u64,
    bytes: &'static [u8],
}

impl BlobSource for MismatchedLengthSource {
    fn logical_length(&self) -> u64 {
        self.declared
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(Cursor::new(self.bytes)))
    }
}

struct FixedReadBackend {
    source: BlobHandle,
}

impl ImmutableBlobBackend for FixedReadBackend {
    fn name(&self) -> &str {
        "fixed-read"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        Ok(true)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Ok(self.source.clone())
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unsupported {
            capability: "fixed-read test put",
        })
    }
}

struct DelayedMetricsBackend {
    child: Arc<MemoryBlobBackend>,
    delay: Duration,
}

impl ImmutableBlobBackend for DelayedMetricsBackend {
    fn name(&self) -> &str {
        "delayed-metrics"
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        thread::sleep(self.delay);
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        thread::sleep(self.delay);
        let blob = self.child.read(id, range)?;
        let source = Arc::new(DelayedBlobSource {
            source: blob.clone(),
            delay: self.delay,
        });
        Ok(blob.with_observed_source(source))
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        thread::sleep(self.delay);
        self.child.put_if_absent(id, source)
    }
}

struct DelayedBlobSource {
    source: BlobHandle,
    delay: Duration,
}

impl BlobSource for DelayedBlobSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        thread::sleep(self.delay);
        Ok(Box::new(DelayedBlobReader {
            reader: self.source.open()?,
            delay: self.delay,
        }))
    }
}

struct DelayedBlobReader {
    reader: Box<dyn Read + Send>,
    delay: Duration,
}

impl Read for DelayedBlobReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        thread::sleep(self.delay);
        self.reader.read(output)
    }
}

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

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Err(StoreError::Unavailable)
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
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

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.put_if_absent(id, source)
    }
}
