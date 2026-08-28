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
    MetricsStore, ReadThroughStore, RoutedStore, TieredStore, WriteThroughStore,
};
use super::directory::{DirectoryBlobBackend, DirectoryRefBackend};
use super::graph::{StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeKind, StoreNodeSpec};
use super::memory::{MemoryBlobBackend, MemoryRefBackend};
use super::*;

const TEST_READ_LIMIT: u64 = 1024 * 1024;

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
fn compressed_directory_streams_plaintext_identity_ranges_and_inventory_across_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed");
    let store = CompressedDirectoryBlobBackend::new("compressed", &root, 4 * 1024 * 1024)
        .expect("compressed directory");
    let bytes = vec![0x5a; 2 * 1024 * 1024];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);

    let receipt = put_bytes(&store, id, &bytes).expect("compressed put");
    assert!(receipt.is_durable());
    assert_eq!(receipt.id, id);
    let physical = object_path(&root, id);
    assert!(
        fs::metadata(&physical)
            .expect("compressed object metadata")
            .len()
            < bytes.len() as u64 / 8
    );
    assert_eq!(
        put_bytes(&store, id, &bytes).expect("idempotent compressed put"),
        receipt
    );

    let reopened = CompressedDirectoryBlobBackend::new("compressed", &root, 4 * 1024 * 1024)
        .expect("reopened compressed directory");
    assert_eq!(
        read_bytes(
            &reopened,
            id,
            Some(ByteRange::new(1_048_571, 17).expect("valid compressed range")),
        )
        .expect("authenticated compressed range"),
        vec![0x5a; 17]
    );
    assert_eq!(
        reopened
            .read(id, None)
            .expect("restart handle")
            .read_all(4 * 1024 * 1024)
            .expect("restart read"),
        bytes
    );
    let concurrent_handle = reopened.read(id, None).expect("concurrent restart handle");
    let first_handle = concurrent_handle.clone();
    let first_reader = thread::spawn(move || first_handle.read_all(4 * 1024 * 1024));
    let second_reader = thread::spawn(move || concurrent_handle.read_all(4 * 1024 * 1024));
    assert_eq!(
        first_reader
            .join()
            .expect("join first compressed reader")
            .expect("first compressed reader"),
        bytes
    );
    assert_eq!(
        second_reader
            .join()
            .expect("join second compressed reader")
            .expect("second compressed reader"),
        bytes
    );

    let mut fence = reopened
        .acquire_inventory_fence()
        .expect("compressed inventory fence");
    let mut records = Vec::new();
    let summary = fence
        .visit_inventory(&mut |record| {
            records.push(record);
            Ok(())
        })
        .expect("compressed inventory");
    assert_eq!(summary.objects(), 1);
    assert_eq!(summary.logical_bytes(), bytes.len() as u64);
    assert_eq!(
        records,
        vec![BlobInventoryRecord::new(id, bytes.len() as u64)]
    );
    assert_eq!(
        fence
            .delete_candidate(id)
            .expect("planned compressed delete"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(id)
            .expect("repeated compressed delete"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    drop(fence);
    assert!(!reopened.contains(id).expect("deleted compressed object"));
}

#[test]
fn compressed_directory_rejects_oversized_sources_and_corrupt_physical_records() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed");
    let store =
        CompressedDirectoryBlobBackend::new("compressed", &root, 64).expect("compressed directory");
    let oversized_bytes = Arc::<[u8]>::from(vec![0x44; 65]);
    let oversized_id = ContentId::for_bytes(ObjectKind::Trace, 1, &oversized_bytes);
    let opens = Arc::new(AtomicUsize::new(0));
    let oversized = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::clone(&oversized_bytes),
        opens: Arc::clone(&opens),
        bytes_read: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(matches!(
        store.put_if_absent(oversized_id, &oversized),
        Err(StoreError::Quota)
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);

    let wrong_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"expected");
    assert!(matches!(
        put_bytes(&store, wrong_id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    let wrong_path = object_path(&root, wrong_id);
    assert!(!wrong_path.exists());
    assert!(
        fs::read_dir(wrong_path.parent().expect("wrong-ID parent"))
            .expect("read wrong-ID parent")
            .all(|entry| !entry
                .expect("wrong-ID directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-"))
    );

    let bytes = vec![0x31; 64];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    put_bytes(&store, id, &bytes).expect("bounded compressed put");
    let physical = object_path(&root, id);
    let physical_length = fs::metadata(&physical)
        .expect("compressed physical metadata")
        .len();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&physical)
        .expect("open compressed physical record");
    file.set_len(physical_length - 1)
        .expect("truncate compressed physical record");
    assert!(matches!(
        store.read(id, None),
        Err(StoreError::Corrupt { .. })
    ));

    let symlink_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"symlink");
    let symlink_path = object_path(&root, symlink_id);
    fs::create_dir_all(symlink_path.parent().expect("symlink object parent"))
        .expect("create symlink parent");
    std::os::unix::fs::symlink(&physical, &symlink_path).expect("create compressed symlink");
    assert!(matches!(
        store.read(symlink_id, None),
        Err(StoreError::Io { .. })
    ));

    let oversized_frame_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"x");
    let oversized_frame_path = object_path(&root, oversized_frame_id);
    fs::create_dir_all(
        oversized_frame_path
            .parent()
            .expect("oversized frame parent"),
    )
    .expect("create oversized frame parent");
    let oversized_frame_length = zstd::zstd_safe::compress_bound(1) + 1;
    let mut oversized_frame_record = Vec::with_capacity(24 + oversized_frame_length);
    oversized_frame_record.extend_from_slice(b"CRUCZ001");
    oversized_frame_record.extend_from_slice(&1_u64.to_be_bytes());
    oversized_frame_record.extend_from_slice(&(oversized_frame_length as u64).to_be_bytes());
    oversized_frame_record.resize(24 + oversized_frame_length, 0);
    fs::write(&oversized_frame_path, oversized_frame_record).expect("write oversized frame");
    assert!(matches!(
        store.read(oversized_frame_id, None),
        Err(StoreError::Corrupt { .. })
    ));

    let range_root = temp.path().join("compressed-range");
    let range_store =
        CompressedDirectoryBlobBackend::new("compressed-range", &range_root, 128 * 1024)
            .expect("compressed range directory");
    let range_bytes = (0_u32..64 * 1024)
        .map(|value| value.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) as u8)
        .collect::<Vec<_>>();
    let range_id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &range_bytes);
    put_bytes(&range_store, range_id, &range_bytes).expect("compressed range put");
    let range_path = object_path(&range_root, range_id);
    let mut changed_plaintext = range_bytes.clone();
    *changed_plaintext.last_mut().expect("plaintext tail") ^= 0x80;
    let changed_frame = zstd::stream::encode_all(Cursor::new(&changed_plaintext), 3)
        .expect("encode changed compressed frame");
    let mut changed_record = Vec::with_capacity(24 + changed_frame.len());
    changed_record.extend_from_slice(b"CRUCZ001");
    changed_record.extend_from_slice(&(changed_plaintext.len() as u64).to_be_bytes());
    changed_record.extend_from_slice(&(changed_frame.len() as u64).to_be_bytes());
    changed_record.extend_from_slice(&changed_frame);
    fs::write(&range_path, changed_record).expect("replace compressed frame plaintext");
    let range = range_store
        .read(
            range_id,
            Some(ByteRange::new(0, 16).expect("valid leading range")),
        )
        .expect("open compressed range with changed plaintext");
    assert!(matches!(
        range.read_all(1024),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn encrypted_directory_authenticates_ranges_and_inventory_across_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("encrypted");
    let key_id = StoreEncryptionKeyId::new("campaign-key-7").expect("key ID");
    let key_bytes = [0xa5; 32];
    let store = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        4 * 1024 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new(key_bytes).expect("key"),
    )
    .expect("encrypted directory");

    let mut expected = BTreeMap::new();
    let mut largest = None;
    for length in [0_usize, 65_535, 65_536, 65_537, 2 * 65_536 + 17] {
        let bytes = (0..length)
            .map(|index| (index as u32).wrapping_mul(17).wrapping_add(91) as u8)
            .collect::<Vec<_>>();
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let receipt = put_bytes(&store, id, &bytes).expect("encrypted put");
        assert!(receipt.is_durable());
        assert_eq!(receipt.id, id);
        assert_eq!(
            put_bytes(&store, id, &bytes).expect("idempotent encrypted put"),
            receipt
        );
        expected.insert(id, bytes);
        largest = Some(id);
    }

    let largest = largest.expect("largest object ID");
    let largest_bytes = &expected[&largest];
    let physical = fs::read(object_path(&root, largest)).expect("encrypted physical record");
    assert!(
        !physical
            .windows(key_bytes.len())
            .any(|window| window == key_bytes)
    );
    let key_state = fs::read(root.join(".inventory-admin/encryption-key-v1"))
        .expect("encrypted key-generation state");
    assert!(
        !key_state
            .windows(key_bytes.len())
            .any(|window| window == key_bytes)
    );
    assert!(
        !physical
            .windows(largest_bytes.len())
            .any(|window| window == largest_bytes)
    );

    let reopened = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        4 * 1024 * 1024,
        key_id,
        StoreEncryptionKey::new(key_bytes).expect("restart key"),
    )
    .expect("reopened encrypted directory");
    for (id, bytes) in &expected {
        assert_eq!(
            read_bytes(&reopened, *id, None).expect("restart encrypted read"),
            *bytes
        );
    }
    assert_eq!(
        read_bytes(
            &reopened,
            largest,
            Some(ByteRange::new(65_530, 19).expect("cross-chunk range")),
        )
        .expect("authenticated encrypted range"),
        largest_bytes[65_530..65_549]
    );

    let mut fence = reopened
        .acquire_inventory_fence()
        .expect("encrypted inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("encrypted inventory");
    assert_eq!(summary.objects(), expected.len() as u64);
    assert_eq!(
        summary.logical_bytes(),
        expected.values().map(|bytes| bytes.len() as u64).sum()
    );
    assert_eq!(
        fence
            .delete_candidate(largest)
            .expect("planned encrypted delete"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(largest)
            .expect("repeated encrypted delete"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
}

#[test]
fn compressed_encrypted_directory_streams_round_trip_and_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed-encrypted");
    let key_id = StoreEncryptionKeyId::new("compressed-key-1").expect("key ID");
    let key_bytes = [0x6d; 32];
    let store = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted",
        &root,
        4 * 1024 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new(key_bytes).expect("key"),
    )
    .expect("compressed encrypted directory");

    let mut expected = BTreeMap::new();
    for length in [0_usize, 1, 65_535, 65_536, 65_537, 256 * 1024] {
        let bytes = (0..length)
            .map(|index| ((index / 257) as u32).wrapping_mul(13) as u8)
            .collect::<Vec<_>>();
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let receipt = put_bytes(&store, id, &bytes).expect("compressed encrypted put");
        assert!(receipt.is_durable());
        assert_eq!(receipt.id, id);
        assert_eq!(
            put_bytes(&store, id, &bytes).expect("idempotent compressed encrypted put"),
            receipt
        );
        let physical = fs::read(object_path(&root, id)).expect("physical record");
        assert_eq!(&physical[..8], b"CRUCC001");
        if bytes.len() >= 64 {
            assert!(!physical.windows(bytes.len()).any(|window| window == bytes));
        }
        expected.insert(id, bytes);
    }

    let largest = *expected
        .iter()
        .max_by_key(|(_, bytes)| bytes.len())
        .map(|(id, _)| id)
        .expect("largest ID");
    let largest_bytes = &expected[&largest];
    let alternate_root = temp.path().join("compressed-encrypted-alternate-key-id");
    let alternate = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted-alternate-key-id",
        &alternate_root,
        4 * 1024 * 1024,
        StoreEncryptionKeyId::new("compressed-key-1b").expect("alternate key ID"),
        StoreEncryptionKey::new(key_bytes).expect("reused master key"),
    )
    .expect("alternate compressed encrypted directory");
    put_bytes(&alternate, largest, largest_bytes).expect("alternate-key-ID put");
    let physical = fs::read(object_path(&root, largest)).expect("primary physical record");
    let alternate_physical =
        fs::read(object_path(&alternate_root, largest)).expect("alternate physical record");
    assert_ne!(physical[92..108], alternate_physical[92..108]);

    let reopened = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted",
        &root,
        4 * 1024 * 1024,
        key_id,
        StoreEncryptionKey::new(key_bytes).expect("restart key"),
    )
    .expect("reopened compressed encrypted directory");
    for (id, bytes) in &expected {
        assert_eq!(
            read_bytes(&reopened, *id, None).expect("restart read"),
            *bytes
        );
    }
    if largest_bytes.len() >= 65_549 {
        assert_eq!(
            read_bytes(
                &reopened,
                largest,
                Some(ByteRange::new(65_530, 19).expect("cross-chunk range")),
            )
            .expect("authenticated compressed encrypted range"),
            largest_bytes[65_530..65_549]
        );
    }

    let mut fence = reopened
        .acquire_inventory_fence()
        .expect("compressed encrypted inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("compressed encrypted inventory");
    assert_eq!(summary.objects(), expected.len() as u64);
    assert_eq!(
        summary.logical_bytes(),
        expected.values().map(|bytes| bytes.len() as u64).sum()
    );
}

#[test]
fn compressed_encrypted_directory_rejects_format_substitution_and_corruption() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed-encrypted");
    let key_id = StoreEncryptionKeyId::new("compressed-key-2").expect("key ID");
    let key_bytes = [0x7e; 32];
    let store = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted",
        &root,
        512 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new(key_bytes).expect("key"),
    )
    .expect("compressed encrypted directory");
    let bytes = vec![0x41; 192 * 1024];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    put_bytes(&store, id, &bytes).expect("compressed encrypted put");

    let plain = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        512 * 1024,
        key_id,
        StoreEncryptionKey::new(key_bytes).expect("same key"),
    )
    .expect("plain encrypted directory view");
    assert!(matches!(
        plain.read(id, None),
        Err(StoreError::Corrupt { .. })
    ));

    let physical_path = object_path(&root, id);
    let mut physical = fs::read(&physical_path).expect("physical record");
    let original = physical.clone();
    physical[8..16].copy_from_slice(&1_u64.to_be_bytes());
    fs::write(&physical_path, &physical).expect("forge logical length");
    let mut fence = store
        .acquire_inventory_fence()
        .expect("inventory fence with forged header");
    assert!(matches!(
        fence.visit_inventory(&mut |_| Ok(())),
        Err(StoreError::Corrupt { .. })
    ));
    drop(fence);

    physical = original;
    *physical.last_mut().expect("ciphertext tail") ^= 0x80;
    fs::write(&physical_path, physical).expect("corrupt ciphertext tail");
    let leading = store
        .read(id, Some(ByteRange::new(0, 16).expect("leading range")))
        .expect("open corrupted range");
    assert!(matches!(
        leading.read_all(1024),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn encrypted_directory_fails_closed_on_limits_wrong_keys_and_corruption() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("encrypted");
    for invalid in ["", "bad/key", "bad:key", "space key"] {
        assert!(matches!(
            StoreEncryptionKeyId::new(invalid),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    assert!(matches!(
        StoreEncryptionKey::new([0; 32]),
        Err(StoreError::InvalidComposition { .. })
    ));
    let key_id = StoreEncryptionKeyId::new("campaign-key-8").expect("key ID");
    let store = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        128 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new([0x18; 32]).expect("key"),
    )
    .expect("encrypted directory");

    let oversized_bytes = Arc::<[u8]>::from(vec![0x44; 128 * 1024 + 1]);
    let oversized_id = ContentId::for_bytes(ObjectKind::Trace, 1, &oversized_bytes);
    let opens = Arc::new(AtomicUsize::new(0));
    let oversized = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::clone(&oversized_bytes),
        opens: Arc::clone(&opens),
        bytes_read: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(matches!(
        store.put_if_absent(oversized_id, &oversized),
        Err(StoreError::Quota)
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);

    let wrong_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"expected");
    assert!(matches!(
        put_bytes(&store, wrong_id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(!object_path(&root, wrong_id).exists());

    let bytes = (0_u32..96 * 1024)
        .map(|value| value.wrapping_mul(1_103_515_245).wrapping_add(12_345) as u8)
        .collect::<Vec<_>>();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    put_bytes(&store, id, &bytes).expect("encrypted put");

    let wrong_key = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        128 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new([0x19; 32]).expect("wrong key"),
    )
    .expect("wrong-key store");
    assert!(matches!(
        read_bytes(&wrong_key, id, None),
        Err(StoreError::Unauthorized)
    ));
    let wrong_key_bytes = b"wrong-key-new-object";
    let wrong_key_new_id = ContentId::for_bytes(ObjectKind::Trace, 1, wrong_key_bytes);
    assert!(matches!(
        put_bytes(&wrong_key, wrong_key_new_id, wrong_key_bytes),
        Err(StoreError::Unauthorized)
    ));
    assert!(!object_path(&root, wrong_key_new_id).exists());
    let wrong_key_id = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        128 * 1024,
        StoreEncryptionKeyId::new("campaign-key-9").expect("wrong key ID"),
        StoreEncryptionKey::new([0x18; 32]).expect("right key"),
    )
    .expect("wrong-key-ID store");
    assert!(matches!(
        wrong_key_id.read(id, None),
        Err(StoreError::InvalidComposition { .. })
    ));

    let physical_path = object_path(&root, id);
    let mut physical = fs::read(&physical_path).expect("encrypted physical record");
    *physical.last_mut().expect("ciphertext tail") ^= 0x80;
    fs::write(&physical_path, &physical).expect("corrupt ciphertext tail");
    let leading = store
        .read(id, Some(ByteRange::new(0, 16).expect("leading range")))
        .expect("open corrupted encrypted range");
    assert!(matches!(
        leading.read_all(1024),
        Err(StoreError::Corrupt { .. })
    ));

    let symlink_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"symlink");
    let symlink_path = object_path(&root, symlink_id);
    fs::create_dir_all(symlink_path.parent().expect("symlink parent"))
        .expect("create symlink parent");
    std::os::unix::fs::symlink(&physical_path, &symlink_path).expect("create encrypted symlink");
    assert!(matches!(
        store.read(symlink_id, None),
        Err(StoreError::Io { .. })
    ));

    let key_state_path = root.join(".inventory-admin/encryption-key-v1");
    let mut key_state = fs::read(&key_state_path).expect("read key state");
    *key_state.last_mut().expect("key-state checksum") ^= 0x01;
    fs::write(&key_state_path, key_state).expect("corrupt key state");
    assert!(matches!(
        store.read(id, None),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn encrypted_directory_serializes_first_key_generation_across_instances() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("encrypted");
    let key_id = StoreEncryptionKeyId::new("campaign-key-race").expect("key ID");
    let first = Arc::new(
        EncryptedDirectoryBlobBackend::new(
            "first",
            &root,
            1024,
            key_id.clone(),
            StoreEncryptionKey::new([0x31; 32]).expect("first key"),
        )
        .expect("first encrypted directory"),
    );
    let second = Arc::new(
        EncryptedDirectoryBlobBackend::new(
            "second",
            &root,
            1024,
            key_id,
            StoreEncryptionKey::new([0x32; 32]).expect("second key"),
        )
        .expect("second encrypted directory"),
    );
    let first_bytes = b"first-generation-object";
    let second_bytes = b"second-generation-object";
    let first_id = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
    let second_id = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
    let barrier = Arc::new(Barrier::new(3));

    let first_worker = {
        let store = Arc::clone(&first);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            put_bytes(store.as_ref(), first_id, first_bytes)
        })
    };
    let second_worker = {
        let store = Arc::clone(&second);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            put_bytes(store.as_ref(), second_id, second_bytes)
        })
    };
    barrier.wait();
    let first_result = first_worker.join().expect("join first key writer");
    let second_result = second_worker.join().expect("join second key writer");

    match (&first_result, &second_result) {
        (Ok(_), Err(StoreError::Unauthorized)) => {
            assert_eq!(
                read_bytes(first.as_ref(), first_id, None).expect("first read"),
                first_bytes
            );
            assert!(!object_path(&root, second_id).exists());
        }
        (Err(StoreError::Unauthorized), Ok(_)) => {
            assert_eq!(
                read_bytes(second.as_ref(), second_id, None).expect("second read"),
                second_bytes
            );
            assert!(!object_path(&root, first_id).exists());
        }
        results => panic!("exactly one key generation must win: {results:?}"),
    }
}

#[test]
fn directory_ref_inventory_is_persistent_fenced_and_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("authority");
    let refs = Arc::new(DirectoryRefBackend::new(&root));
    let first_name = RefName::new("campaigns/first").expect("first ref name");
    let staging_prefix_name =
        RefName::new(".ref-staging-user").expect("valid staging-prefix ref name");
    let third_name = RefName::new("campaigns/third").expect("third ref name");
    let first = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"first");
    let second = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"second");
    let third = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"third");
    refs.compare_exchange(&first_name, None, first)
        .expect("create first directory ref");
    refs.compare_exchange(&staging_prefix_name, None, second)
        .expect("create staging-prefix directory ref");

    let mut fence = refs
        .acquire_ref_inventory_fence()
        .expect("acquire directory ref fence");
    let mut inventory = BTreeMap::new();
    let before = fence
        .visit_refs(&mut |record| {
            inventory.insert(record.name().clone(), record.target());
            Ok(())
        })
        .expect("visit directory refs");
    assert_eq!(before.refs(), 2);
    assert_eq!(
        inventory,
        BTreeMap::from([(first_name.clone(), first), (staging_prefix_name, second),])
    );

    let writer_refs = Arc::clone(&refs);
    let writer_started = Arc::new(AtomicBool::new(false));
    let writer_finished = Arc::new(AtomicBool::new(false));
    let writer_started_clone = Arc::clone(&writer_started);
    let writer_finished_clone = Arc::clone(&writer_finished);
    let writer = thread::spawn(move || {
        writer_started_clone.store(true, Ordering::Release);
        writer_refs
            .compare_exchange(&third_name, None, third)
            .expect("create fenced directory ref");
        writer_finished_clone.store(true, Ordering::Release);
    });
    while !writer_started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(std::time::Duration::from_millis(10));
    assert!(!writer_finished.load(Ordering::Acquire));
    drop(fence);
    writer.join().expect("join directory ref writer");

    refs.compare_exchange(&first_name, Some(first), second)
        .expect("advance directory ref away from original");
    refs.compare_exchange(&first_name, Some(second), first)
        .expect("restore directory ref after ABA");
    let reopened = DirectoryRefBackend::new(&root);
    let mut reopened_fence = reopened
        .acquire_ref_inventory_fence()
        .expect("reopen directory ref fence");
    let reopened_summary = reopened_fence
        .visit_refs(&mut |_| Ok(()))
        .expect("visit reopened refs");
    assert_ne!(reopened_summary.generation(), before.generation());
    assert_eq!(reopened_summary.refs(), 3);
    drop(reopened_fence);

    fs::write(root.join("refs/campaigns/first"), [0_u8; 257]).expect("inject oversized ref record");
    let mut malformed_fence = reopened
        .acquire_ref_inventory_fence()
        .expect("acquire malformed directory ref fence");
    assert!(matches!(
        malformed_fence.visit_refs(&mut |_| Ok(())),
        Err(StoreError::InvalidId)
    ));
    drop(malformed_fence);

    fs::write(root.join(".ref-admin/state-v1"), [0_u8; 257])
        .expect("inject oversized ref inventory state");
    assert!(matches!(
        reopened.acquire_ref_inventory_fence(),
        Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state exceeds its byte limit"
        })
    ));
}

#[test]
fn directory_ref_inventory_waits_for_cross_instance_publication() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("authority");
    let publisher = DirectoryRefBackend::new(&root);
    let publication = publisher
        .acquire_publication_guard()
        .expect("acquire directory publication guard");
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let inventor = DirectoryRefBackend::new(root);
        started_tx.send(()).expect("signal inventory attempt");
        let _fence = inventor
            .acquire_ref_inventory_fence()
            .expect("acquire directory inventory fence");
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
    worker.join().expect("join directory inventory worker");
}

#[test]
fn directory_administration_is_persistent_fenced_and_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("blobs");
    let blobs = Arc::new(DirectoryBlobBackend::new("directory-admin", &root));
    let first_bytes = b"first durable object";
    let second_bytes = b"second durable object";
    let first = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, first_bytes);
    let second = ContentId::for_bytes(ObjectKind::Observation, 1, second_bytes);
    put_bytes(blobs.as_ref(), first, first_bytes).expect("put first object");
    put_bytes(blobs.as_ref(), second, second_bytes).expect("put second object");

    let mut fence = blobs
        .acquire_inventory_fence()
        .expect("acquire directory inventory fence");
    let mut records = BTreeSet::new();
    let before = fence
        .visit_inventory(&mut |record| {
            records.insert(record.id());
            Ok(())
        })
        .expect("visit directory inventory");
    assert_eq!(before.backend(), "directory-admin");
    assert_eq!(before.objects(), 2);
    assert_eq!(records, BTreeSet::from([first, second]));

    let writer_store = Arc::clone(&blobs);
    let writer_started = Arc::new(AtomicBool::new(false));
    let writer_completed = Arc::new(AtomicBool::new(false));
    let writer_started_clone = Arc::clone(&writer_started);
    let writer_completed_clone = Arc::clone(&writer_completed);
    let third_bytes = b"third durable object";
    let third = ContentId::for_bytes(ObjectKind::CampaignFact, 1, third_bytes);
    let writer = thread::spawn(move || {
        writer_started_clone.store(true, Ordering::Release);
        put_bytes(writer_store.as_ref(), third, third_bytes).expect("fenced writer put");
        writer_completed_clone.store(true, Ordering::Release);
    });
    while !writer_started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(std::time::Duration::from_millis(10));
    assert!(!writer_completed.load(Ordering::Acquire));

    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete durable candidate"),
        PlannedDeleteDisposition::Deleted
    );
    let after_delete = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("visit after deletion");
    assert_ne!(after_delete.generation(), before.generation());
    drop(fence);
    writer.join().expect("join fenced writer");
    assert!(writer_completed.load(Ordering::Acquire));
    put_bytes(blobs.as_ref(), first, first_bytes).expect("reinsert deleted durable object");

    let reopened = DirectoryBlobBackend::new("directory-admin", &root);
    let mut reopened_fence = reopened
        .acquire_inventory_fence()
        .expect("reopen directory inventory fence");
    let reopened_summary = reopened_fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("visit reopened inventory");
    assert_ne!(reopened_summary.generation(), after_delete.generation());
    assert_ne!(reopened_summary.generation(), before.generation());
    assert_eq!(reopened_summary.objects(), 3);
    drop(reopened_fence);

    fs::write(root.join("unexpected-physical-entry"), b"unowned")
        .expect("inject malformed physical entry");
    let mut malformed_fence = reopened
        .acquire_inventory_fence()
        .expect("acquire malformed inventory fence");
    assert!(matches!(
        malformed_fence.visit_inventory(&mut |_| Ok(())),
        Err(StoreError::InvalidComposition {
            reason: "inventory contains an unknown object-kind directory"
        })
    ));
    drop(malformed_fence);

    fs::remove_file(root.join("unexpected-physical-entry"))
        .expect("remove malformed physical entry");
    fs::write(root.join(".inventory-admin/state-v1"), [0_u8; 257])
        .expect("inject oversized inventory state");
    assert!(matches!(
        reopened.acquire_inventory_fence(),
        Err(StoreError::InvalidComposition {
            reason: "directory inventory state exceeds its byte limit"
        })
    ));
}

#[test]
fn tiered_reads_promote_only_verified_objects() {
    let cache = Arc::new(MemoryBlobBackend::new("cache", 1_024));
    let durable = Arc::new(MemoryBlobBackend::new("durable-test", 1_024));
    let bytes = b"finding bundle";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(durable.as_ref(), id, bytes).expect("seed lower tier");

    let tiers: Vec<Arc<dyn ImmutableBlobBackend>> = vec![cache.clone(), durable];
    let store = TieredStore::new("tiered", tiers, 1, true).expect("valid tiers");
    assert!(!store.capabilities().streaming_read);
    assert_eq!(read_bytes(&store, id, None).expect("tiered read"), bytes);
    assert!(cache.contains(id).expect("promoted cache object"));
}

#[test]
fn read_through_cache_failure_does_not_hide_authenticated_source_bytes() {
    let cache = Arc::new(MemoryBlobBackend::new("full-cache", 0));
    let source = Arc::new(MemoryBlobBackend::new("source", 1_024));
    let bytes = b"source remains authoritative";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(source.as_ref(), id, bytes).expect("seed source");
    let store = ReadThroughStore::new("read-through", cache.clone(), source.clone());

    assert_eq!(
        read_bytes(&store, id, None).expect("read despite cache quota"),
        bytes
    );
    assert!(!cache.contains(id).expect("failed promotion remains absent"));

    let unavailable_cache: Arc<dyn ImmutableBlobBackend> = Arc::new(UnavailableReadBackend);
    let strict = ReadThroughStore::new("strict-read-through", unavailable_cache, source);
    assert!(matches!(
        read_bytes(&strict, id, None),
        Err(StoreError::Unavailable)
    ));
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
    let receipt = put_bytes(&routed, fact, fact_bytes).expect("mirrored fact put");
    assert_eq!(receipt.placements.len(), 2);
    assert!(metadata_a.contains(fact).expect("first mirror"));
    assert!(metadata_b.contains(fact).expect("second mirror"));

    let ram_bytes = b"page";
    let page = ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);
    put_bytes(&routed, page, ram_bytes).expect("routed page put");
    assert!(ram.contains(page).expect("ram route"));
}

#[test]
fn invalid_ranges_and_mismatched_puts_are_rejected() {
    let store = MemoryBlobBackend::new("memory", 3);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"abc");
    assert!(matches!(
        put_bytes(&store, id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    put_bytes(&store, id, b"abc").expect("valid put");
    let overflow_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"d");
    assert!(matches!(
        put_bytes(&store, overflow_id, b"d"),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        read_bytes(
            &store,
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
            put_bytes(blobs.as_ref(), id, bytes)
        }));
    }
    for putter in putters {
        assert!(putter.join().expect("put thread").is_ok());
    }
    assert_eq!(
        read_bytes(blobs.as_ref(), id, None).expect("concurrent object"),
        bytes
    );

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
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
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
    put_bytes(lower.as_ref(), id, bytes).expect("seed lower tier");
    let unavailable: Arc<dyn ImmutableBlobBackend> = Arc::new(UnavailableReadBackend);
    let lower_trait: Arc<dyn ImmutableBlobBackend> = lower;
    let tiered = TieredStore::new("tiered", vec![unavailable, lower_trait], 1, false)
        .expect("valid tiered store");
    assert!(matches!(
        read_bytes(&tiered, id, None),
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
        put_bytes(&store, id, bytes),
        Err(StoreError::Unavailable)
    ));
    assert!(first.contains(id).expect("first orphan is readable"));
    assert!(!second.contains(id).expect("second placement absent"));
    assert!(store.contains(id).expect("partial mirror is readable"));
    assert_eq!(
        read_bytes(&store, id, None).expect("partial mirror read"),
        bytes
    );

    let receipt = put_bytes(&store, id, bytes).expect("retry mirror put");
    assert_eq!(receipt.placements.len(), 2);
    assert!(second.contains(id).expect("second placement repaired"));
}

#[test]
fn streaming_sources_are_reopenable_and_length_checked() {
    let temp = TempDir::new().expect("temporary directory");
    let store = DirectoryBlobBackend::new("directory", temp.path().join("blobs"));
    let source = Arc::new(RepeatSource {
        byte: 0xab,
        logical_length: 4 * 1024 * 1024,
    });
    let id = ContentId::for_source(ObjectKind::RamExtent, 1, source.as_ref())
        .expect("stream source identity");
    let source = BlobHandle::new(source);
    let receipt = store
        .put_if_absent(id, &source)
        .expect("stream directory put");
    assert_eq!(
        receipt.placements[0].logical_length,
        source.logical_length()
    );

    let stored = store.read(id, None).expect("stream directory read");
    let mut copied = Vec::new();
    assert_eq!(
        stored.copy_to(&mut copied).expect("bounded streaming copy"),
        source.logical_length()
    );
    assert_eq!(copied, vec![0xab; source.logical_length() as usize]);
    assert_eq!(
        ContentId::for_source(ObjectKind::RamExtent, 1, &stored).expect("stored stream identity"),
        id
    );
    assert_eq!(
        store
            .read(
                id,
                Some(ByteRange::new(source.logical_length() - 16, 16).expect("valid tail range"))
            )
            .expect("tail stream")
            .read_all(16)
            .expect("tail bytes"),
        vec![0xab; 16]
    );

    let too_long = Arc::new(MismatchedLengthSource {
        declared: 2,
        bytes: b"abc",
    });
    assert!(matches!(
        ContentId::for_source(ObjectKind::Trace, 1, too_long.as_ref()),
        Err(StoreError::InvalidSourceLength { .. })
    ));
    let expected = ContentId::for_bytes(ObjectKind::Trace, 1, b"ab");
    let too_long = BlobHandle::new(too_long);
    assert!(matches!(
        store.put_if_absent(expected, &too_long),
        Err(StoreError::Corrupt { .. })
    ));

    let too_short = MismatchedLengthSource {
        declared: 4,
        bytes: b"abc",
    };
    assert!(matches!(
        ContentId::for_source(ObjectKind::Trace, 1, &too_short),
        Err(StoreError::InvalidSourceLength { .. })
    ));

    let enormous = BlobHandle::new(Arc::new(MismatchedLengthSource {
        declared: u64::MAX,
        bytes: b"",
    }));
    assert!(matches!(
        enormous.read_all(u64::MAX),
        Err(StoreError::Quota)
    ));
}

#[test]
fn verification_evidence_bounds_source_passes_through_a_mirror_graph() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("root");
    let router = node_id("router");
    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let memory = node_id("memory");
    let graph = StoreGraph::build(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                root,
                StoreNodeSpec::Verified {
                    child: router.clone(),
                },
            ),
            (
                router,
                StoreNodeSpec::Routed {
                    routes: BTreeMap::from([(ObjectKind::CampaignFact, mirror.clone())]),
                },
            ),
            (
                mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![directory.clone(), memory.clone()],
                },
            ),
            (
                directory,
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
            (
                memory,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1024 * 1024,
                },
            ),
        ]),
    })
    .expect("valid mirror graph");
    let bytes = vec![0x5a; 128 * 1024];
    let opens = Arc::new(AtomicUsize::new(0));
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.clone()),
        opens: opens.clone(),
        bytes_read: bytes_read.clone(),
    }));
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
    let receipt = graph
        .put_if_absent(id, &source)
        .expect("mirrored streaming put");

    assert_eq!(receipt.placements.len(), 2);
    assert_eq!(opens.load(Ordering::SeqCst), 3);
    assert_eq!(bytes_read.load(Ordering::SeqCst), bytes.len() * 3);
}

#[test]
fn directory_handles_pin_inodes_and_authenticate_ranges_at_eof() {
    let temp = TempDir::new().expect("temporary directory");
    let store = DirectoryBlobBackend::new("directory", temp.path().join("objects"));
    let bytes = b"stable pinned bytes";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(&store, id, bytes).expect("put pinned object");
    let handle = store.read(id, None).expect("open pinned handle");
    fs::remove_file(object_path(store.root(), id)).expect("unlink object path");
    assert_eq!(handle.read_all(1_024).expect("read unlinked inode"), bytes);
    assert_eq!(
        handle.read_all(1_024).expect("reopen unlinked inode"),
        bytes
    );
    assert!(matches!(
        store.read(id, None),
        Err(StoreError::NotFound { .. })
    ));

    let mutated = b"mutable-object";
    let mutated_id = ContentId::for_bytes(ObjectKind::Trace, 1, mutated);
    put_bytes(&store, mutated_id, mutated).expect("put mutation object");
    let mutated_handle = store.read(mutated_id, None).expect("open mutation handle");
    fs::write(object_path(store.root(), mutated_id), b"changed-object")
        .expect("mutate pinned inode");
    assert!(matches!(
        mutated_handle.read_all(1_024),
        Err(StoreError::Corrupt { .. })
    ));

    let range_bytes = vec![0x11; 4_096];
    let range_id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &range_bytes);
    put_bytes(&store, range_id, &range_bytes).expect("put range object");
    let range = store
        .read(range_id, Some(ByteRange::new(0, 16).expect("valid range")))
        .expect("open range handle");
    let mut corrupt = range_bytes;
    corrupt[4_095] ^= 0xff;
    fs::write(object_path(store.root(), range_id), corrupt).expect("corrupt outside range");
    assert!(matches!(
        range.read_all(16),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn changing_and_failing_sources_leave_no_published_object_or_staging_file() {
    let temp = TempDir::new().expect("temporary directory");
    let directory = Arc::new(DirectoryBlobBackend::new(
        "directory",
        temp.path().join("objects"),
    ));
    let verified = super::composition::VerifiedStore::new("verified", directory.clone());
    let expected_bytes = b"first opening is valid";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, expected_bytes);
    let source = BlobHandle::new(Arc::new(ChangingSource {
        opens: AtomicUsize::new(0),
        first: expected_bytes,
        later: b"second opening differs",
    }));
    assert!(matches!(
        verified.put_if_absent(id, &source),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(
        !directory
            .contains(id)
            .expect("changed source not published")
    );
    assert_no_staging(directory.root(), id);

    let failing_bytes = b"reader fails in the middle";
    let failing_id = ContentId::for_bytes(ObjectKind::Trace, 1, failing_bytes);
    let failing = BlobHandle::new(Arc::new(FailingSource {
        bytes: failing_bytes,
        fail_after: 8,
    }));
    assert!(matches!(
        directory.put_if_absent(failing_id, &failing),
        Err(StoreError::StreamIo { .. })
    ));
    assert!(
        !directory
            .contains(failing_id)
            .expect("failed source not published")
    );
    assert_no_staging(directory.root(), failing_id);

    let interrupted = InterruptOnceSource {
        bytes: b"retry interrupted reads",
    };
    assert_eq!(
        ContentId::for_source(ObjectKind::Trace, 1, &interrupted)
            .expect("interrupted read retried"),
        ContentId::for_bytes(ObjectKind::Trace, 1, interrupted.bytes)
    );
}

#[test]
fn source_chunk_boundaries_do_not_change_content_identity() {
    for length in [65_535_usize, 65_536, 65_537] {
        let bytes = vec![0x7c; length];
        let source = RepeatSource {
            byte: 0x7c,
            logical_length: length as u64,
        };
        assert_eq!(
            ContentId::for_source(ObjectKind::RamExtent, 1, &source).expect("chunked identity"),
            ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes)
        );
    }
}

#[test]
fn closed_store_graph_routes_shared_leaves_and_is_introspectable() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("root");
    let router = node_id("router");
    let mirror = node_id("metadata-mirror");
    let ram_tiers = node_id("ram-tiers");
    let directory = node_id("directory");
    let metadata_cache = node_id("metadata-cache");
    let ram_cache = node_id("ram-cache");
    let nodes = BTreeMap::from([
        (
            root.clone(),
            StoreNodeSpec::Verified {
                child: router.clone(),
            },
        ),
        (
            router,
            StoreNodeSpec::Routed {
                routes: BTreeMap::from([
                    (ObjectKind::CampaignFact, mirror.clone()),
                    (ObjectKind::RamExtent, ram_tiers.clone()),
                ]),
            },
        ),
        (
            mirror,
            StoreNodeSpec::WriteThrough {
                children: vec![metadata_cache.clone(), directory.clone()],
            },
        ),
        (
            ram_tiers,
            StoreNodeSpec::Tiered {
                tiers: vec![ram_cache.clone(), directory.clone()],
                write_tier: 1,
                promote_reads: true,
            },
        ),
        (
            directory,
            StoreNodeSpec::Directory {
                root: temp.path().join("objects"),
            },
        ),
        (
            metadata_cache,
            StoreNodeSpec::Memory {
                max_logical_bytes: 1_024,
            },
        ),
        (
            ram_cache,
            StoreNodeSpec::Memory {
                max_logical_bytes: 1_024,
            },
        ),
    ]);
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact, ObjectKind::RamExtent]),
        nodes,
    })
    .expect("valid closed graph");
    assert_eq!(graph.root_id(), &root);
    assert_eq!(graph.configuration_id(), admin.configuration_id());
    assert_eq!(graph.describe().len(), 7);
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::Routed)
    );
    assert_eq!(
        admin
            .physical()
            .into_iter()
            .map(|physical| physical.node().as_str())
            .collect::<Vec<_>>(),
        vec!["directory", "metadata-cache", "ram-cache"]
    );

    let fact_bytes = b"graph fact";
    let fact = ContentId::for_bytes(ObjectKind::CampaignFact, 1, fact_bytes);
    let fact_receipt = put_bytes(&graph, fact, fact_bytes).expect("graph fact put");
    assert_eq!(fact_receipt.placements.len(), 2);
    assert!(fact_receipt.is_durable());

    let ram_bytes = b"graph ram";
    let ram = ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);
    assert!(
        put_bytes(&graph, ram, ram_bytes)
            .expect("graph RAM put")
            .is_durable()
    );
    assert_eq!(
        read_bytes(&graph, ram, None).expect("graph RAM read"),
        ram_bytes
    );

    let trace = ContentId::for_bytes(ObjectKind::Trace, 1, b"trace");
    assert!(matches!(
        put_bytes(&graph, trace, b"trace"),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::RouteCoverage,
            ..
        })
    ));
}

#[test]
fn durability_policy_enforces_distinct_placements_and_exact_kind_coverage() {
    let temp = TempDir::new().expect("temporary directory");
    let policy = node_id("durability");
    let mirror = node_id("mirror");
    let first = node_id("first");
    let second = node_id("second");
    let requirement = DurabilityRequirement::new(2, false).expect("durability requirement");
    let config = |requirement| StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: mirror.clone(),
                    requirements: BTreeMap::from([(ObjectKind::CampaignFact, requirement)]),
                },
            ),
            (
                mirror.clone(),
                StoreNodeSpec::WriteThrough {
                    children: vec![first.clone(), second.clone()],
                },
            ),
            (
                first.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("first"),
                },
            ),
            (
                second.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("second"),
                },
            ),
        ]),
    };
    let graph = StoreGraph::build(config(requirement)).expect("durability graph");
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::DurabilityPolicy)
    );
    let bytes = b"durable campaign fact";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    let receipt = put_bytes(&graph, id, bytes).expect("durability-qualified put");
    assert_eq!(receipt.durable_placements(), 2);
    assert_eq!(read_bytes(&graph, id, None).expect("policy read"), bytes);

    let restarted = StoreGraph::build(config(requirement)).expect("restart durability graph");
    assert_eq!(graph.configuration_id(), restarted.configuration_id());
    assert_eq!(
        read_bytes(&restarted, id, None).expect("restart read"),
        bytes
    );
    let weaker = StoreGraph::build(config(
        DurabilityRequirement::new(1, false).expect("weaker requirement"),
    ))
    .expect("weaker durability graph");
    assert_ne!(graph.configuration_id(), weaker.configuration_id());

    let golden_policy = node_id("durability");
    let golden_mirror = node_id("mirror");
    let golden_first = node_id("first");
    let golden_second = node_id("second");
    let golden = StoreGraph::build(StoreGraphConfig {
        root: golden_policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                golden_policy,
                StoreNodeSpec::DurabilityPolicy {
                    child: golden_mirror.clone(),
                    requirements: BTreeMap::from([(ObjectKind::CampaignFact, requirement)]),
                },
            ),
            (
                golden_mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![golden_first.clone(), golden_second.clone()],
                },
            ),
            (
                golden_first,
                StoreNodeSpec::Directory {
                    root: PathBuf::from("/var/lib/crucible/campaign-primary"),
                },
            ),
            (
                golden_second,
                StoreNodeSpec::Directory {
                    root: PathBuf::from("/var/lib/crucible/campaign-archive"),
                },
            ),
        ]),
    })
    .expect("golden durability graph");
    assert_eq!(
        encode_hex(&golden.configuration_id().as_bytes()),
        "372a1deab92e040856d4a5f88b315c444f93d4e694887a0bf7eb0e92ae0aa34c"
    );

    let missing = StoreGraph::build(StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: first.clone(),
                    requirements: BTreeMap::new(),
                },
            ),
            (
                first.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("missing"),
                },
            ),
        ]),
    });
    assert!(matches!(
        missing,
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::DurabilityCoverage,
            ..
        })
    ));

    let extraneous = StoreGraph::build(StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy,
                StoreNodeSpec::DurabilityPolicy {
                    child: first.clone(),
                    requirements: BTreeMap::from([
                        (ObjectKind::CampaignFact, requirement),
                        (ObjectKind::Trace, requirement),
                    ]),
                },
            ),
            (
                first,
                StoreNodeSpec::Directory {
                    root: temp.path().join("extraneous"),
                },
            ),
        ]),
    });
    assert!(matches!(
        extraneous,
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::DurabilityCoverage,
            ..
        })
    ));
}

#[test]
fn durability_policy_rejects_duplicate_receipts_and_unadmitted_deferral() {
    let temp = TempDir::new().expect("temporary directory");
    let policy = node_id("durability");
    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let requirement = DurabilityRequirement::new(2, false).expect("durability requirement");
    let duplicate = StoreGraph::build(StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: mirror.clone(),
                    requirements: BTreeMap::from([(ObjectKind::CampaignFact, requirement)]),
                },
            ),
            (
                mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![directory.clone(), directory.clone()],
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("duplicate"),
                },
            ),
        ]),
    })
    .expect("duplicate-child graph remains structurally valid");
    let bytes = b"one physical placement";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    assert!(matches!(
        put_bytes(&duplicate, id, bytes),
        Err(StoreError::DurabilityUnsatisfied {
            minimum_durable_placements: 2,
            observed_durable_placements: 1,
            ..
        })
    ));

    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let deferred_config = |allow_deferred_write| StoreGraphConfig {
        root: policy.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                policy.clone(),
                StoreNodeSpec::DurabilityPolicy {
                    child: write_back.clone(),
                    requirements: BTreeMap::from([(
                        ObjectKind::Finding,
                        DurabilityRequirement::new(1, allow_deferred_write)
                            .expect("deferred requirement"),
                    )]),
                },
            ),
            (
                write_back.clone(),
                StoreNodeSpec::WriteBack {
                    staging: staging.clone(),
                    destination: destination.clone(),
                    journal_root: temp.path().join("journal"),
                    maximum_pending_objects: 8,
                    maximum_pending_bytes: 1_024,
                },
            ),
            (
                staging.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("staging"),
                },
            ),
            (
                destination.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("destination"),
                },
            ),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(deferred_config(false)),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnsupportedChild,
            ..
        })
    ));
    let deferred = StoreGraph::build(deferred_config(true)).expect("admitted deferred policy");
    let finding_bytes = b"journaled durable staging";
    let finding = ContentId::for_bytes(ObjectKind::Finding, 1, finding_bytes);
    assert_eq!(
        put_bytes(&deferred, finding, finding_bytes)
            .expect("allowed deferred put")
            .durable_placements(),
        1
    );

    assert!(matches!(
        DurabilityRequirement::new(0, false),
        Err(StoreError::InvalidComposition { .. })
    ));
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: policy.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    policy,
                    StoreNodeSpec::DurabilityPolicy {
                        child: directory.clone(),
                        requirements: BTreeMap::from([(
                            ObjectKind::Finding,
                            DurabilityRequirement::new(1, false).expect("memory requirement"),
                        )]),
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnsupportedChild,
            ..
        })
    ));
}

#[test]
fn store_graph_configuration_identity_is_canonical_and_complete() {
    let root = node_id("root");
    let config = |maximum| StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            root.clone(),
            StoreNodeSpec::Memory {
                max_logical_bytes: maximum,
            },
        )]),
    };

    let (first, first_admin) = StoreGraph::build_with_admin(config(1_024)).expect("first graph");
    let (restarted, restarted_admin) =
        StoreGraph::build_with_admin(config(1_024)).expect("restarted graph");
    let (changed, changed_admin) =
        StoreGraph::build_with_admin(config(2_048)).expect("changed graph");

    assert_eq!(first.configuration_id(), first_admin.configuration_id());
    assert_eq!(first.configuration_id(), restarted.configuration_id());
    assert_eq!(first.configuration_id(), restarted_admin.configuration_id());
    assert_eq!(changed.configuration_id(), changed_admin.configuration_id());
    assert_ne!(first.configuration_id(), changed.configuration_id());
    assert_eq!(
        encode_hex(&first.configuration_id().as_bytes()),
        "9054c4182515f09b43494c07f5bb3f8e93b62d6251b449ebf128d7142a8528d5"
    );
}

#[test]
fn namespaced_graph_authorizes_every_operation_before_child_access() {
    for invalid in ["", "/absolute", "a//b", "a/../b", "snowman-☃"] {
        assert!(matches!(
            StoreNamespaceId::new(invalid),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    assert!(matches!(
        StoreNamespaceId::new("a".repeat(256)),
        Err(StoreError::InvalidComposition { .. })
    ));
    assert!(matches!(
        StoreNamespaceId::new(format!("{}/{}/c", "a".repeat(255), "b".repeat(255))),
        Err(StoreError::InvalidComposition { .. })
    ));

    let namespace = StoreNamespaceId::new("tenant-a/campaigns").expect("namespace");
    let namespaced = node_id("namespaced");
    let memory = node_id("memory");
    let config = |namespace| StoreGraphConfig {
        root: namespaced.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                namespaced.clone(),
                StoreNodeSpec::Namespaced {
                    child: memory.clone(),
                    namespace,
                },
            ),
            (
                memory.clone(),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    };

    assert!(matches!(
        StoreGraph::build(config(namespace.clone())),
        Err(StoreError::Unauthorized)
    ));
    let bypass = node_id("bypass");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: bypass.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    bypass,
                    StoreNodeSpec::WriteThrough {
                        children: vec![namespaced.clone(), memory.clone()],
                    },
                ),
                (
                    namespaced.clone(),
                    StoreNodeSpec::Namespaced {
                        child: memory.clone(),
                        namespace: namespace.clone(),
                    },
                ),
                (
                    memory.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidNamespaceBoundary,
            ..
        })
    ));
    let nested = node_id("nested-namespace");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: namespaced.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    namespaced.clone(),
                    StoreNodeSpec::Namespaced {
                        child: nested.clone(),
                        namespace: namespace.clone(),
                    },
                ),
                (
                    nested,
                    StoreNodeSpec::Namespaced {
                        child: memory.clone(),
                        namespace: namespace.clone(),
                    },
                ),
                (
                    memory.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidNamespaceBoundary,
            ..
        })
    ));
    let unrelated = StoreNamespaceId::new("tenant-b/campaigns").expect("other namespace");
    let authorizer = Arc::new(RecordingNamespaceAuthorizer::default());
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    authorizers
        .insert(unrelated.clone(), authorizer.clone())
        .expect("unrelated capability");
    assert!(matches!(
        StoreGraph::build_with_authorizers(config(namespace.clone()), &authorizers),
        Err(StoreError::Unauthorized)
    ));
    authorizers
        .insert(namespace.clone(), authorizer.clone())
        .expect("namespace capability");
    assert!(matches!(
        authorizers.insert(namespace.clone(), authorizer.clone()),
        Err(StoreError::InvalidComposition { .. })
    ));

    let graph = StoreGraph::build_with_authorizers(config(namespace.clone()), &authorizers)
        .expect("authorized namespace graph");
    assert_eq!(graph.describe()[1].kind, StoreNodeKind::Namespaced);
    let bytes = b"namespace protected object";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    let denied_opens = Arc::new(AtomicUsize::new(0));
    let denied_bytes = Arc::new(AtomicUsize::new(0));
    let denied_source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.as_slice()),
        opens: denied_opens.clone(),
        bytes_read: denied_bytes.clone(),
    }));
    assert!(matches!(
        graph.put_if_absent(id, &denied_source),
        Err(StoreError::Unauthorized)
    ));
    assert_eq!(denied_opens.load(Ordering::SeqCst), 0);
    assert_eq!(denied_bytes.load(Ordering::SeqCst), 0);

    authorizer.set_allowed(true);
    assert!(!graph.contains(id).expect("denied put reached no child"));
    put_bytes(&graph, id, bytes).expect("authorized put");
    assert!(graph.contains(id).expect("authorized contains"));
    assert_eq!(
        read_bytes(&graph, id, None).expect("authorized read"),
        bytes
    );

    authorizer.set_allowed(false);
    assert!(matches!(graph.contains(id), Err(StoreError::Unauthorized)));
    assert!(matches!(
        graph.read(id, None),
        Err(StoreError::Unauthorized)
    ));
    assert_eq!(
        authorizer.calls(),
        vec![
            (StoreNamespaceOperation::Put, id),
            (StoreNamespaceOperation::Contains, id),
            (StoreNamespaceOperation::Put, id),
            (StoreNamespaceOperation::Contains, id),
            (StoreNamespaceOperation::Read, id),
            (StoreNamespaceOperation::Contains, id),
            (StoreNamespaceOperation::Read, id),
        ]
    );

    let mut alternate_authorizers = StoreGraphNamespaceAuthorizers::new();
    alternate_authorizers
        .insert(unrelated.clone(), authorizer)
        .expect("alternate namespace capability");
    let alternate = StoreGraph::build_with_authorizers(config(unrelated), &alternate_authorizers)
        .expect("alternate namespace graph");
    assert_ne!(graph.configuration_id(), alternate.configuration_id());
    assert_eq!(
        encode_hex(&graph.configuration_id().as_bytes()),
        "7f8907cc7694835950ccadf6b47458a019af583119e279e6757e102e74fc0d78"
    );
}

#[test]
fn profile_graph_derives_authenticated_classes_without_caller_hints() {
    for invalid in ["", "/absolute", "a//b", "a/../b", "snowman-☃"] {
        assert!(matches!(
            StoreObjectProfilePolicyId::new(invalid),
            Err(StoreError::InvalidComposition { .. })
        ));
    }

    let policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v1")
        .expect("profile policy");
    let profile = node_id("profile");
    let memory = node_id("memory");
    let config = |policy| StoreGraphConfig {
        root: profile.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                profile.clone(),
                StoreNodeSpec::ProfileValidated {
                    child: memory.clone(),
                    policy,
                },
            ),
            (
                memory.clone(),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(config(policy.clone())),
        Err(StoreError::Unauthorized)
    ));

    let profiler = Arc::new(RecordingObjectProfiler::new(false));
    let mut profilers = StoreGraphObjectProfilers::new();
    profilers
        .insert(policy.clone(), profiler.clone())
        .expect("profile capability");
    assert!(matches!(
        profilers.insert(policy.clone(), profiler.clone()),
        Err(StoreError::InvalidComposition { .. })
    ));
    let keys = StoreGraphKeyring::new();
    let authorizers = StoreGraphNamespaceAuthorizers::new();
    let graph = StoreGraph::build_with_all_capabilities(
        config(policy.clone()),
        &keys,
        &authorizers,
        &profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
    )
    .expect("profile graph");
    assert_eq!(graph.describe()[1].kind, StoreNodeKind::ProfileValidated);

    let bytes = b"profiled trace";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    assert!(matches!(
        put_bytes(&graph, id, bytes),
        Err(StoreError::Unauthorized)
    ));

    profiler.set_allowed(true);
    assert!(!graph.contains(id).expect("denied put left child empty"));
    put_bytes(&graph, id, bytes).expect("profiled put");
    assert!(graph.contains(id).expect("profiled contains"));
    assert_eq!(
        read_bytes(
            &graph,
            id,
            Some(ByteRange::new(2, 5).expect("profiled range")),
        )
        .expect("profiled range read"),
        b"ofile"
    );
    assert_eq!(profiler.calls.load(Ordering::SeqCst), 4);

    profiler.set_returned_kind(Some(ObjectKind::Finding));
    assert!(matches!(graph.contains(id), Err(StoreError::Incompatible)));

    let other_policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v2")
        .expect("other profile policy");
    let other_profiler = Arc::new(RecordingObjectProfiler::new(true));
    let mut other_profilers = StoreGraphObjectProfilers::new();
    other_profilers
        .insert(other_policy.clone(), other_profiler)
        .expect("other profile capability");
    let other = StoreGraph::build_with_all_capabilities(
        config(other_policy),
        &keys,
        &authorizers,
        &other_profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
    )
    .expect("other profile graph");
    assert_ne!(graph.configuration_id(), other.configuration_id());
    assert_eq!(
        encode_hex(&graph.configuration_id().as_bytes()),
        "5b47533ebd3efc0261bd493bde4f11ec9009cf67614bd356784234c3c4bca12c"
    );

    let bypass = node_id("bypass");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: bypass.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    bypass,
                    StoreNodeSpec::WriteThrough {
                        children: vec![profile.clone(), memory.clone()],
                    },
                ),
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: memory.clone(),
                        policy,
                    },
                ),
                (
                    memory,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidProfileBoundary,
            ..
        })
    ));
}

#[test]
fn profile_and_namespace_boundaries_compose_at_the_graph_root() {
    let policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v1")
        .expect("profile policy");
    let namespace = StoreNamespaceId::new("tenant-a/profiled").expect("namespace");
    let profile = node_id("profile");
    let namespaced = node_id("namespaced");
    let memory = node_id("memory");
    let profiler = Arc::new(RecordingObjectProfiler::new(true));
    let authorizer = Arc::new(RecordingNamespaceAuthorizer::default());
    authorizer.set_allowed(true);
    let mut profilers = StoreGraphObjectProfilers::new();
    profilers
        .insert(policy.clone(), profiler)
        .expect("profile capability");
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    authorizers
        .insert(namespace.clone(), authorizer)
        .expect("namespace capability");
    let graph = StoreGraph::build_with_all_capabilities(
        StoreGraphConfig {
            root: profile.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: namespaced.clone(),
                        policy,
                    },
                ),
                (
                    namespaced,
                    StoreNodeSpec::Namespaced {
                        child: memory.clone(),
                        namespace,
                    },
                ),
                (
                    memory,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &authorizers,
        &profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
    )
    .expect("composed boundaries");
    let bytes = b"composed operational boundaries";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(&graph, id, bytes).expect("composed put");
    assert_eq!(read_bytes(&graph, id, None).expect("composed read"), bytes);
}

#[test]
fn profile_graph_validates_deferred_transfer_and_root_inventory() {
    let temp = TempDir::new().expect("temporary directory");
    let policy = StoreObjectProfilePolicyId::new("crucible.campaign.object-profile.v1")
        .expect("profile policy");
    let profile = node_id("profile");
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let profiler = Arc::new(RecordingObjectProfiler::new(true));
    let mut profilers = StoreGraphObjectProfilers::new();
    profilers
        .insert(policy.clone(), profiler.clone())
        .expect("profile capability");
    let graph = StoreGraph::build_with_all_capabilities(
        StoreGraphConfig {
            root: profile.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: write_back.clone(),
                        policy,
                    },
                ),
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("staging"),
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("destination"),
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &profilers,
        &StoreGraphPhysicalQuotaBinders::new(),
    )
    .expect("profiled write-back graph");
    let bytes = b"profiled deferred finding";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("profiled staging put");

    profiler.set_allowed(false);
    assert!(matches!(
        graph.flush_write_back(1),
        Err(StoreError::Unauthorized)
    ));
    {
        let mut fence = graph
            .acquire_write_back_retention_fence()
            .expect("retention fence");
        assert!(matches!(
            fence.visit_roots(&mut |_root| Ok(())),
            Err(StoreError::Unauthorized)
        ));
    }
    let destination = DirectoryBlobBackend::new("inspection", temp.path().join("destination"));
    assert!(!destination.contains(id).expect("destination remains empty"));

    profiler.set_allowed(true);
    assert_eq!(
        graph
            .flush_write_back(1)
            .expect("profiled flush")
            .completed(),
        1
    );
    let mut fence = graph
        .acquire_write_back_retention_fence()
        .expect("empty retention fence");
    assert_eq!(
        fence
            .visit_roots(&mut |_root| Ok(()))
            .expect("empty inventory")
            .roots(),
        0
    );
}

#[test]
fn namespaced_graph_authorizes_deferred_transfer_and_root_inventory() {
    let temp = TempDir::new().expect("temporary directory");
    let namespace = StoreNamespaceId::new("tenant-a/archive").expect("namespace");
    let namespaced = node_id("namespaced");
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let authorizer = Arc::new(RecordingNamespaceAuthorizer::default());
    authorizer.set_allowed(true);
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    authorizers
        .insert(namespace.clone(), authorizer.clone())
        .expect("namespace capability");
    let graph = StoreGraph::build_with_authorizers(
        StoreGraphConfig {
            root: namespaced.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    namespaced,
                    StoreNodeSpec::Namespaced {
                        child: write_back.clone(),
                        namespace,
                    },
                ),
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("staging"),
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("destination"),
                    },
                ),
            ]),
        },
        &authorizers,
    )
    .expect("namespaced write-back graph");
    let bytes = b"authorized deferred finding";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("authorized staging put");

    authorizer.set_allowed(false);
    assert!(matches!(
        graph.flush_write_back(1),
        Err(StoreError::Unauthorized)
    ));
    let destination = DirectoryBlobBackend::new("inspection", temp.path().join("destination"));
    assert!(!destination.contains(id).expect("destination remains empty"));
    {
        let mut fence = graph
            .acquire_write_back_retention_fence()
            .expect("retention fence");
        assert!(matches!(
            fence.visit_roots(&mut |_root| Ok(())),
            Err(StoreError::Unauthorized)
        ));
    }

    authorizer.set_allowed(true);
    let summary = graph.flush_write_back(1).expect("authorized transfer");
    assert_eq!(summary.completed(), 1);
    assert_eq!(summary.pending(), 0);
    assert_eq!(
        read_bytes(&destination, id, None).expect("destination bytes"),
        bytes
    );
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
        "267c8bb7bffff4a036092332e038d3c451b50058bda3a76628d147ec07b12378"
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
        "4aef4520268f7fa30a99c075a3f176237da5be4815b7e2e55bd12b7478615b89"
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

#[test]
fn physical_quota_binds_exact_leaf_limits_and_survives_restart_and_admin() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let directory = node_id("directory");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/campaign-store").expect("physical quota policy");
    let object_root = temp.path().join("objects");
    let config = |root: PathBuf, maximum_physical_bytes| StoreGraphConfig {
        root: physical.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                physical.clone(),
                StoreNodeSpec::PhysicalQuota {
                    child: directory.clone(),
                    policy: policy.clone(),
                    project_id: 41,
                    maximum_physical_bytes,
                    maximum_inodes: 64,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::CompressedDirectory {
                    root,
                    maximum_logical_object_bytes: 1_024,
                },
            ),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(config(object_root.clone(), 128 * 1024)),
        Err(StoreError::Unauthorized)
    ));

    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(true));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder.clone())
        .expect("physical quota capability");
    assert!(matches!(
        binders.insert(policy.clone(), binder.clone()),
        Err(StoreError::InvalidComposition { .. })
    ));
    let build = |config| {
        StoreGraph::build_with_admin_and_all_capabilities(
            config,
            &StoreGraphKeyring::new(),
            &StoreGraphNamespaceAuthorizers::new(),
            &StoreGraphObjectProfilers::new(),
            &binders,
        )
    };
    let (graph, admin) =
        build(config(object_root.clone(), 128 * 1024)).expect("physical quota graph");
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &physical);
    assert_eq!(
        binder.bindings(),
        vec![RecordedPhysicalQuotaBinding {
            root: object_root.clone(),
            project_id: 41,
            maximum_physical_bytes: 128 * 1024,
            maximum_inodes: 64,
        }]
    );

    let bytes = b"physically bounded trace";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    let receipt = put_bytes(&graph, id, bytes).expect("physical quota put");
    assert_eq!(receipt.placements[0].backend, "physical-quota");
    assert!(graph.contains(id).expect("physical quota contains"));
    assert_eq!(
        read_bytes(&graph, id, None).expect("physical quota read"),
        bytes
    );
    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("physical quota inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("physical quota inventory");
    assert_eq!(summary.backend(), "physical-quota");
    assert_eq!(summary.objects(), 1);
    drop(fence);
    drop(admin);
    drop(graph);

    let (restarted, restarted_admin) =
        build(config(object_root.clone(), 128 * 1024)).expect("restarted physical quota graph");
    assert!(restarted.contains(id).expect("restart retained object"));
    let mut fence = restarted_admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("restarted inventory fence");
    assert_eq!(
        fence.delete_candidate(id).expect("quota deletion"),
        PlannedDeleteDisposition::Deleted
    );
    drop(fence);
    assert!(!restarted.contains(id).expect("deleted object absent"));

    binder.guard.set_allowed(false);
    let rejected_bytes = b"rejected before child allocation";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        put_bytes(&restarted, rejected, rejected_bytes),
        Err(StoreError::Quota)
    ));
    binder.guard.set_allowed(true);
    let direct = CompressedDirectoryBlobBackend::new("direct", &object_root, 1_024)
        .expect("direct compressed leaf");
    assert!(!direct.contains(rejected).expect("rejected child absent"));

    let (changed, _admin) =
        build(config(object_root, 256 * 1024)).expect("changed physical quota graph");
    assert_ne!(restarted.configuration_id(), changed.configuration_id());
    let (golden, _admin) = build(config(
        PathBuf::from("/var/lib/crucible/campaign-store/objects"),
        128 * 1024,
    ))
    .expect("golden physical quota graph");
    assert_eq!(
        encode_hex(&golden.configuration_id().as_bytes()),
        "60249effc2190eab11c6a0996cedfb82ded56b39871711b680a03a53f6c6c491"
    );
}

#[test]
fn physical_quota_admission_rejects_invalid_shared_and_nonleaf_children() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let directory = node_id("directory");
    let policy = StorePhysicalQuotaPolicyId::new("host/ext4").expect("quota policy");
    let config = |project_id, maximum_physical_bytes, maximum_inodes| StoreGraphConfig {
        root: physical.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                physical.clone(),
                StoreNodeSpec::PhysicalQuota {
                    child: directory.clone(),
                    policy: policy.clone(),
                    project_id,
                    maximum_physical_bytes,
                    maximum_inodes,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
        ]),
    };
    for invalid in [config(0, 1, 1), config(1, 0, 1), config(1, 1, 0)] {
        assert!(matches!(
            StoreGraph::build(invalid),
            Err(StoreError::InvalidGraph {
                violation: GraphViolation::InvalidPhysicalQuotaBounds,
                ..
            })
        ));
    }

    let metrics = node_id("metrics");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    physical.clone(),
                    StoreNodeSpec::PhysicalQuota {
                        child: metrics.clone(),
                        policy: policy.clone(),
                        project_id: 1,
                        maximum_physical_bytes: 1,
                        maximum_inodes: 1,
                    },
                ),
                (
                    metrics,
                    StoreNodeSpec::Metrics {
                        child: directory.clone(),
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Directory {
                        root: temp.path().join("nonleaf"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidPhysicalQuotaChild,
            ..
        })
    ));

    let mirror = node_id("mirror");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![physical.clone(), directory.clone()],
                    },
                ),
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: directory.clone(),
                        policy,
                        project_id: 1,
                        maximum_physical_bytes: 1,
                        maximum_inodes: 1,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("shared"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidPhysicalQuotaChild,
            ..
        })
    ));
}

#[test]
fn physical_quota_binding_precedes_allocating_leaf_construction() {
    let temp = TempDir::new().expect("temporary directory");
    let physical = node_id("physical-quota");
    let packed = node_id("packed");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/preflight").expect("physical quota policy");
    let pack_root = temp.path().join("packs");
    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(false));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder)
        .expect("physical quota capability");
    let result = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: packed.clone(),
                        policy,
                        project_id: 43,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    packed,
                    StoreNodeSpec::Packed {
                        root: pack_root.clone(),
                        target_pack_bytes: 4 * 1024,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
    );
    assert!(matches!(result, Err(StoreError::Quota)));
    assert!(!pack_root.exists());
}

#[test]
fn logical_and_physical_quotas_compose_without_an_admin_bypass() {
    let temp = TempDir::new().expect("temporary directory");
    let logical = node_id("logical-quota");
    let physical = node_id("physical-quota");
    let directory = node_id("directory");
    let policy =
        StorePhysicalQuotaPolicyId::new("host/ext4/composed").expect("physical quota policy");
    let binder = Arc::new(RecordingPhysicalQuotaBinder::new(true));
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(policy.clone(), binder)
        .expect("physical quota capability");
    let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root: logical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    logical.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: physical.clone(),
                        state_root: temp.path().join("logical-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 64,
                    },
                ),
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: directory.clone(),
                        policy,
                        project_id: 42,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("objects"),
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
    )
    .expect("composed quota graph");
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &logical);

    let bytes = b"one quota-owned object";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(&graph, id, bytes).expect("composed quota put");
    let rejected_bytes = b"second object";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        put_bytes(&graph, rejected, rejected_bytes),
        Err(StoreError::Quota)
    ));
}

#[test]
fn logical_quota_reclaims_accounting_through_graph_admin_and_survives_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let state_root = temp.path().join("quota-state");
    let object_root = temp.path().join("objects");
    let config = || StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: state_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 10,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::CompressedDirectory {
                    root: object_root.clone(),
                    maximum_logical_object_bytes: 1_024,
                },
            ),
        ]),
    };
    let (graph, admin) = StoreGraph::build_with_admin(config()).expect("logical quota graph");
    assert_eq!(graph.describe().len(), 2);
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::LogicalQuota)
    );
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &quota);

    let first_bytes = b"four";
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
    let first_receipt = put_bytes(&graph, first, first_bytes).expect("first quota put");
    assert_eq!(first_receipt.placements[0].backend, "quota");
    put_bytes(&graph, first, first_bytes).expect("idempotent quota put");
    let second_bytes = b"second";
    let second = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
    put_bytes(&graph, second, second_bytes).expect("second quota put");
    let rejected_bytes = b"more";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    let rejected_opens = Arc::new(AtomicUsize::new(0));
    let rejected_source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(rejected_bytes.as_slice()),
        opens: Arc::clone(&rejected_opens),
        bytes_read: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(matches!(
        graph.put_if_absent(rejected, &rejected_source),
        Err(StoreError::Quota)
    ));
    assert_eq!(rejected_opens.load(Ordering::SeqCst), 0);

    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("logical quota inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("logical quota inventory");
    assert_eq!(summary.backend(), "quota");
    assert_eq!(summary.objects(), 2);
    assert_eq!(summary.logical_bytes(), 10);
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete quota candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("repeat quota candidate deletion"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    drop(fence);
    put_bytes(&graph, rejected, rejected_bytes).expect("reclaimed quota put");
    drop(admin);
    drop(graph);

    let (restarted, restarted_admin) =
        StoreGraph::build_with_admin(config()).expect("restart logical quota graph");
    assert!(!restarted.contains(first).expect("deleted object absent"));
    assert!(restarted.contains(second).expect("second object retained"));
    assert!(restarted.contains(rejected).expect("replacement retained"));
    let mut fence = restarted_admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("restarted logical quota fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("restarted logical quota inventory");
    assert_eq!(summary.objects(), 2);
    assert_eq!(summary.logical_bytes(), 10);
}

#[test]
fn dirty_logical_quota_state_recovers_from_the_owned_child_inventory() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let state_root = temp.path().join("quota-state");
    let object_root = temp.path().join("objects");
    let config = || StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: state_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 16,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: object_root.clone(),
                },
            ),
        ]),
    };
    let graph = StoreGraph::build(config()).expect("logical quota graph");
    let first_bytes = b"first";
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
    put_bytes(&graph, first, first_bytes).expect("first quota put");
    super::quota::mark_quota_state_dirty(&state_root).expect("mark interrupted quota state");

    let child = DirectoryBlobBackend::new("directory", &object_root);
    let second_bytes = b"second";
    let second = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
    put_bytes(&child, second, second_bytes).expect("simulate committed child put");
    drop(graph);

    let (restarted, admin) =
        StoreGraph::build_with_admin(config()).expect("recover logical quota graph");
    let third_bytes = b"third";
    let third = ContentId::for_bytes(ObjectKind::Trace, 1, third_bytes);
    assert!(matches!(
        put_bytes(&restarted, third, third_bytes),
        Err(StoreError::Quota)
    ));
    let mut fence = admin.physical()[0]
        .admin()
        .acquire_inventory_fence()
        .expect("recovered quota fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("recovered quota inventory");
    assert_eq!(summary.objects(), 2);
    assert_eq!(summary.logical_bytes(), 11);
    drop(fence);
    drop(admin);
    drop(restarted);

    let changed = StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota,
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root,
                    maximum_objects: 3,
                    maximum_logical_bytes: 16,
                },
            ),
            (directory, StoreNodeSpec::Directory { root: object_root }),
        ]),
    };
    assert!(matches!(
        StoreGraph::build(changed),
        Err(StoreError::InvalidComposition {
            reason: "logical quota state belongs to another graph configuration"
        })
    ));
}

#[test]
fn concurrent_logical_quota_instances_share_one_durable_admission_lock() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let config = || StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: temp.path().join("quota-state"),
                    maximum_objects: 1,
                    maximum_logical_bytes: 16,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
        ]),
    };
    let first = Arc::new(StoreGraph::build(config()).expect("first quota instance"));
    let second = Arc::new(StoreGraph::build(config()).expect("second quota instance"));
    let barrier = Arc::new(Barrier::new(3));
    let launch = |graph: Arc<StoreGraph>, byte| {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let bytes = [byte; 8];
            let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            barrier.wait();
            graph.put_if_absent(id, &BlobHandle::from_bytes(bytes))
        })
    };
    let first_put = launch(first, 0x31);
    let second_put = launch(second, 0x32);
    barrier.wait();
    let results = [
        first_put.join().expect("first quota writer"),
        second_put.join().expect("second quota writer"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Quota)))
            .count(),
        1
    );
}

#[test]
fn logical_quota_admission_rejects_unbounded_shared_and_nonleaf_children() {
    let temp = TempDir::new().expect("temporary directory");
    let quota = node_id("quota");
    let directory = node_id("directory");
    let config = |maximum_objects, maximum_logical_bytes| StoreGraphConfig {
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: temp.path().join("quota-state"),
                    maximum_objects,
                    maximum_logical_bytes,
                },
            ),
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
        ]),
    };
    for invalid in [config(0, 1), config(1, 0), config(u64::MAX, 1)] {
        assert!(matches!(
            StoreGraph::build(invalid),
            Err(StoreError::InvalidGraph {
                violation: GraphViolation::InvalidLogicalQuotaBounds,
                ..
            })
        ));
    }

    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    quota.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: directory.clone(),
                        state_root: temp.path().join("memory-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1,
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidLogicalQuotaChild,
            ..
        })
    ));

    let metrics = node_id("metrics");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    quota.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: metrics.clone(),
                        state_root: temp.path().join("nonleaf-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    metrics,
                    StoreNodeSpec::Metrics {
                        child: directory.clone(),
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Directory {
                        root: temp.path().join("nonleaf-objects"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidLogicalQuotaChild,
            ..
        })
    ));

    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: quota.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    quota.clone(),
                    StoreNodeSpec::LogicalQuota {
                        child: directory.clone(),
                        state_root: temp.path().join("overlap"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    directory.clone(),
                    StoreNodeSpec::Directory {
                        root: temp.path().join("overlap").join("objects"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::OverlappingAdministrativePath,
            ..
        })
    ));

    let mirror = node_id("mirror");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![quota.clone(), directory.clone()],
                    },
                ),
                (
                    quota,
                    StoreNodeSpec::LogicalQuota {
                        child: directory.clone(),
                        state_root: temp.path().join("shared-state"),
                        maximum_objects: 1,
                        maximum_logical_bytes: 1,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("shared-objects"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::InvalidLogicalQuotaChild,
            ..
        })
    ));
}

#[test]
fn durable_write_back_survives_restart_and_exposes_exact_retention_roots() {
    let temp = TempDir::new().expect("temporary directory");
    let graph = write_back_graph(temp.path(), 8, 1_024).expect("write-back graph");
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::WriteBack)
    );

    let bytes = b"durable deferred transfer";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    let opens = Arc::new(AtomicUsize::new(0));
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.as_slice()),
        opens: Arc::clone(&opens),
        bytes_read: Arc::clone(&bytes_read),
    }));
    let receipt = graph
        .put_if_absent(id, &source)
        .expect("stage write-back object");
    assert!(receipt.is_durable());
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    assert_eq!(bytes_read.load(Ordering::SeqCst), bytes.len());
    assert!(matches!(
        write_back_graph(temp.path(), 9, 1_024),
        Err(StoreError::Incompatible)
    ));

    let destination = DirectoryBlobBackend::new("destination-check", temp.path().join("archive"));
    assert!(!destination.contains(id).expect("destination absence"));
    let mut fence = graph
        .acquire_write_back_retention_fence()
        .expect("write-back retention fence");
    let mut roots = Vec::new();
    let summary = fence
        .visit_roots(&mut |root| {
            roots.push(root);
            Ok(())
        })
        .expect("pending roots");
    assert_eq!(summary.roots(), 1);
    assert_eq!(summary.logical_bytes(), bytes.len() as u64);
    assert_eq!(roots[0].node(), "write-back");
    assert_eq!(roots[0].id(), id);
    drop(fence);

    let restarted = write_back_graph(temp.path(), 8, 1_024).expect("restart write-back graph");
    let flush = restarted
        .flush_write_back(1)
        .expect("flush pending transfer");
    assert_eq!(flush.completed(), 1);
    assert_eq!(flush.pending(), 0);
    assert_eq!(
        read_bytes(&destination, id, None).expect("destination object"),
        bytes
    );

    let reopened = write_back_graph(temp.path(), 8, 1_024).expect("reopen completed journal");
    assert_eq!(
        reopened
            .flush_write_back(1)
            .expect("idempotent empty flush")
            .completed(),
        0
    );
}

#[test]
fn write_back_retention_fence_excludes_children_before_journal_publication() {
    let temp = TempDir::new().expect("temporary directory");
    let graph = write_back_graph(temp.path(), 8, 1_024).expect("write-back graph");
    let fence = graph
        .acquire_write_back_retention_fence()
        .expect("exclusive transfer fence");
    let bytes = b"fenced transfer";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    let started = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let worker_graph = write_back_graph(temp.path(), 8, 1_024).expect("second graph instance");
    let worker_started = Arc::clone(&started);
    let worker_finished = Arc::clone(&finished);
    let worker = thread::spawn(move || {
        worker_started.store(true, Ordering::Release);
        put_bytes(&worker_graph, id, bytes).expect("fenced write-back put");
        worker_finished.store(true, Ordering::Release);
    });
    while !started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(Duration::from_millis(25));
    assert!(!finished.load(Ordering::Acquire));
    drop(fence);
    worker.join().expect("fenced writer");
    assert!(finished.load(Ordering::Acquire));
}

#[test]
fn write_back_journal_recovers_torn_tail_and_rejects_corruption() {
    let temp = TempDir::new().expect("temporary directory");
    let bytes = b"journal recovery";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    {
        let graph = write_back_graph(temp.path(), 8, 1_024).expect("write-back graph");
        put_bytes(&graph, id, bytes).expect("pending transfer");
    }

    let journal = temp.path().join("journal/transfers-v1.log");
    let original = fs::read(&journal).expect("journal bytes");
    let mut torn = original.clone();
    torn.extend_from_slice(&[0, 0]);
    fs::write(&journal, torn).expect("write torn tail");
    let recovered = write_back_graph(temp.path(), 8, 1_024).expect("recover torn tail");
    let mut fence = recovered
        .acquire_write_back_retention_fence()
        .expect("retention fence");
    assert_eq!(
        fence
            .visit_roots(&mut |_root| Ok(()))
            .expect("recovered roots")
            .roots(),
        1
    );
    drop(fence);
    assert_eq!(fs::read(&journal).expect("truncated journal"), original);

    fs::write(&journal, &original[..8]).expect("write truncated journal header");
    assert!(matches!(
        write_back_graph(temp.path(), 8, 1_024),
        Err(StoreError::Incompatible)
    ));

    fs::write(&journal, &original).expect("restore complete journal");
    let mut corrupt = original;
    let last = corrupt.last_mut().expect("journal record checksum");
    *last ^= 0x80;
    fs::write(&journal, corrupt).expect("corrupt journal");
    assert!(matches!(
        write_back_graph(temp.path(), 8, 1_024),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn write_back_bounds_and_durable_child_requirements_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let graph = write_back_graph(temp.path(), 8, 4).expect("bounded write-back graph");
    let first = ContentId::for_bytes(ObjectKind::Finding, 1, b"four");
    put_bytes(&graph, first, b"four").expect("first bounded transfer");
    let overflow = ContentId::for_bytes(ObjectKind::Finding, 1, b"five!");
    assert!(matches!(
        put_bytes(&graph, overflow, b"five!"),
        Err(StoreError::Quota)
    ));
    let staging_check = DirectoryBlobBackend::new("staging-check", temp.path().join("staging"));
    assert!(
        !staging_check
            .contains(overflow)
            .expect("quota rejection leaves staging unchanged")
    );

    let root = node_id("write-back");
    let staging = node_id("memory-staging");
    let destination = node_id("destination");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    root,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("invalid-journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("invalid-destination"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidComposition { .. })
    ));

    let outer = node_id("outer-write-back");
    let inner = node_id("inner-write-back");
    let inner_staging = node_id("inner-staging");
    let inner_destination = node_id("inner-destination");
    let outer_destination = node_id("outer-destination");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: outer.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    outer,
                    StoreNodeSpec::WriteBack {
                        staging: inner.clone(),
                        destination: outer_destination.clone(),
                        journal_root: temp.path().join("outer-journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    inner,
                    StoreNodeSpec::WriteBack {
                        staging: inner_staging.clone(),
                        destination: inner_destination.clone(),
                        journal_root: temp.path().join("inner-journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    inner_staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("inner-staging"),
                    },
                ),
                (
                    inner_destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("inner-destination"),
                    },
                ),
                (
                    outer_destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("outer-destination"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn write_back_journal_paths_cannot_overlap_blob_or_other_journal_roots() {
    let temp = TempDir::new().expect("temporary directory");
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let staging_root = temp.path().join("staging");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: write_back.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: staging_root.join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (staging, StoreNodeSpec::Directory { root: staging_root },),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("destination"),
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
fn packed_backend_restarts_repackages_and_keeps_old_reader_inodes_valid() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let first_bytes = vec![0x31; 8 * 1024];
    let second_bytes = vec![0x72; 12 * 1024];
    let first = ContentId::for_bytes(ObjectKind::RamExtent, 1, &first_bytes);
    let second = ContentId::for_bytes(ObjectKind::DiskExtent, 1, &second_bytes);
    put_bytes(&store, first, &first_bytes).expect("first packed put");
    put_bytes(&store, second, &second_bytes).expect("second packed put");

    let pinned_before_repack = store.read(first, None).expect("pinned old pack reader");
    let release_old_reader = Arc::new(Barrier::new(2));
    let old_reader_release = Arc::clone(&release_old_reader);
    let old_reader = thread::spawn(move || {
        old_reader_release.wait();
        pinned_before_repack.read_all(TEST_READ_LIMIT)
    });
    assert_eq!(
        read_bytes(
            &store,
            second,
            Some(ByteRange::new(4_096, 2_048).expect("packed range")),
        )
        .expect("authenticated packed range"),
        vec![0x72; 2_048]
    );
    let before = store.accounting().expect("packed accounting");
    assert_eq!(before.logical_objects(), 2);
    assert_eq!(before.logical_bytes(), 20 * 1024);
    assert_eq!(before.packs(), 2);

    let plan = store.plan_repack().expect("exact-generation repack plan");
    let canonical_plan = plan.canonical_bytes();
    let decoded_plan =
        PackedRepackPlan::from_canonical_bytes(&canonical_plan).expect("canonical repack plan");
    assert_eq!(decoded_plan, plan);
    assert_eq!(plan.before(), before);
    let report = store
        .apply_repack(&decoded_plan)
        .expect("deterministic repack");
    assert_eq!(report.plan(), plan.id());
    assert!(!report.replayed());
    assert_eq!(report.before(), before);
    assert_eq!(report.after().logical_objects(), 2);
    assert_eq!(report.after().packs(), 1);
    assert_eq!(report.removed_packs(), 2);
    release_old_reader.wait();
    assert_eq!(
        old_reader
            .join()
            .expect("old reader thread")
            .expect("old inode remains readable"),
        first_bytes
    );

    let restarted =
        PackedBlobBackend::open("packed", &root, 64 * 1024).expect("restart packed backend");
    let replay = restarted
        .apply_repack(&plan)
        .expect("restart replay of committed plan");
    assert!(replay.replayed());
    assert_eq!(replay.plan(), plan.id());
    assert_eq!(replay.removed_packs(), 0);
    assert_eq!(replay.after(), report.after());
    assert_eq!(
        read_bytes(&restarted, second, None).expect("restart packed read"),
        second_bytes
    );
    assert!(matches!(
        PackedBlobBackend::open("packed", &root, 128 * 1024),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn packed_inventory_deletes_logical_entries_without_removing_live_pack_bytes() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let first = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"first packed page");
    let second = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"second packed page");
    put_bytes(&store, first, b"first packed page").expect("first packed object");
    put_bytes(&store, second, b"second packed page").expect("second packed object");
    let plan = store.plan_repack().expect("coalescing plan");
    store.apply_repack(&plan).expect("coalesce physical pack");
    assert_eq!(pack_file_count(&root), 1);

    let mut fence = store
        .acquire_inventory_fence()
        .expect("packed inventory fence");
    let before = fence
        .visit_inventory(&mut |_record| Ok(()))
        .expect("packed inventory");
    assert_eq!(before.objects(), 2);
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete first logical candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(pack_file_count(&root), 1);
    assert_eq!(
        fence
            .delete_candidate(second)
            .expect("delete last logical candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(pack_file_count(&root), 0);
    drop(fence);
    assert!(!store.contains(first).expect("first logical absence"));
    assert!(!store.contains(second).expect("second logical absence"));
}

#[test]
fn packed_repack_rejects_stale_or_corrupt_plans_and_preserves_empty_objects() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let empty = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"");
    put_bytes(&store, empty, b"").expect("empty packed object");
    assert_eq!(
        read_bytes(&store, empty, None).expect("read empty object"),
        b""
    );

    let stale = store.plan_repack().expect("stale plan basis");
    let second_bytes = b"intervening logical mutation";
    let second = ContentId::for_bytes(ObjectKind::DiskExtent, 1, second_bytes);
    put_bytes(&store, second, second_bytes).expect("intervening packed put");
    assert!(matches!(
        store.apply_repack(&stale),
        Err(StoreError::Incompatible)
    ));
    assert!(store.contains(empty).expect("empty object retained"));
    assert!(store.contains(second).expect("second object retained"));

    let current = store.plan_repack().expect("current plan");
    let mut corrupt = current.canonical_bytes();
    *corrupt.last_mut().expect("plan checksum byte") ^= 0x01;
    assert!(matches!(
        PackedRepackPlan::from_canonical_bytes(&corrupt),
        Err(StoreError::Incompatible)
    ));
    let report = store.apply_repack(&current).expect("current plan apply");
    assert_eq!(report.after().logical_objects(), 2);
    assert_eq!(report.after().logical_bytes(), second_bytes.len() as u64);
    assert_eq!(
        read_bytes(&store, empty, None).expect("empty after repack"),
        b""
    );
}

#[test]
fn packed_backend_rejects_corruption_and_cleans_unindexed_complete_packs() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let bytes = b"authenticated packed body";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    put_bytes(&store, id, bytes).expect("packed put");
    let pack = only_pack_path(&root);
    let mut corrupt = fs::read(&pack).expect("pack bytes");
    *corrupt.last_mut().expect("pack body byte") ^= 0x80;
    fs::write(&pack, corrupt).expect("corrupt pack body");
    assert!(matches!(
        store
            .read(id, Some(ByteRange::new(0, 1).expect("corrupt range")))
            .and_then(|handle| handle.read_all(TEST_READ_LIMIT)),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(matches!(
        put_bytes(&store, id, bytes),
        Err(StoreError::Corrupt { .. })
    ));

    let second_root = temp.path().join("recovery");
    let recovery =
        PackedBlobBackend::open("recovery", &second_root, 64 * 1024).expect("recovery backend");
    put_bytes(&recovery, id, bytes).expect("recovery packed put");
    let referenced = only_pack_path(&second_root);
    let orphan = second_root
        .join("packs")
        .join(format!("{}{}", "0".repeat(64), ".pack"));
    fs::copy(&referenced, &orphan).expect("simulate pack-before-index interruption");
    assert_eq!(pack_file_count(&second_root), 2);
    let reopened =
        PackedBlobBackend::open("recovery", &second_root, 64 * 1024).expect("recover orphan pack");
    assert_eq!(pack_file_count(&second_root), 1);
    assert_eq!(
        read_bytes(&reopened, id, None).expect("recovered logical object"),
        bytes
    );

    fs::write(second_root.join(".packed-admin/index-v1"), b"truncated")
        .expect("truncate packed index");
    assert!(matches!(
        PackedBlobBackend::open("recovery", &second_root, 64 * 1024),
        Err(StoreError::Incompatible)
    ));

    let missing_root = temp.path().join("missing-pack");
    let missing =
        PackedBlobBackend::open("missing", &missing_root, 64 * 1024).expect("missing-pack backend");
    put_bytes(&missing, id, bytes).expect("missing-pack put");
    fs::remove_file(only_pack_path(&missing_root)).expect("remove referenced pack");
    assert!(matches!(
        PackedBlobBackend::open("missing", &missing_root, 64 * 1024),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn packed_store_graph_is_admitted_and_requires_an_isolated_persistent_root() {
    let temp = TempDir::new().expect("temporary directory");
    let packed = node_id("packed");
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: packed.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
        nodes: BTreeMap::from([(
            packed.clone(),
            StoreNodeSpec::Packed {
                root: temp.path().join("packed"),
                target_pack_bytes: 64 * 1024,
            },
        )]),
    })
    .expect("packed store graph");
    assert_eq!(graph.describe()[0].kind, StoreNodeKind::Packed);
    let physical = admin.physical();
    assert_eq!(physical.len(), 1);
    assert_eq!(physical[0].node(), &packed);
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence()
        .expect("packed graph maintenance fence");
    let empty = fence
        .visit_inventory(&mut |_record| Ok(()))
        .expect("empty packed graph inventory");
    assert_eq!(empty.backend(), packed.as_str());
    assert_eq!(empty.objects(), 0);
    drop(fence);
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"graph packed page");
    put_bytes(&graph, id, b"graph packed page").expect("graph packed put");

    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let shared = temp.path().join("overlap");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![packed.clone(), directory.clone()],
                    },
                ),
                (
                    packed,
                    StoreNodeSpec::Packed {
                        root: shared.clone(),
                        target_pack_bytes: 64 * 1024,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: shared.join("loose"),
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
fn read_through_and_metrics_nodes_report_exact_operations_and_streams() {
    let root = node_id("root-metrics");
    let read_through = node_id("read-through");
    let cache_metrics = node_id("cache-metrics");
    let source_metrics = node_id("source-metrics");
    let cache = node_id("cache");
    let source = node_id("source");
    let graph = StoreGraph::build(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                root.clone(),
                StoreNodeSpec::Metrics {
                    child: read_through.clone(),
                },
            ),
            (
                read_through,
                StoreNodeSpec::ReadThrough {
                    cache: cache_metrics.clone(),
                    source: source_metrics.clone(),
                },
            ),
            (
                cache_metrics.clone(),
                StoreNodeSpec::Metrics {
                    child: cache.clone(),
                },
            ),
            (
                source_metrics.clone(),
                StoreNodeSpec::Metrics {
                    child: source.clone(),
                },
            ),
            (
                cache,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
            (
                source,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1_024,
                },
            ),
        ]),
    })
    .expect("valid read-through metrics graph");
    assert_eq!(graph.metrics().len(), 3);
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::ReadThrough)
    );
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::Metrics)
    );

    let bytes = b"metric bytes";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    put_bytes(&graph, id, bytes).expect("source-only logical put");
    assert_eq!(
        read_bytes(&graph, id, None).expect("source read and promotion"),
        bytes
    );
    assert_eq!(
        read_bytes(&graph, id, Some(ByteRange::new(7, 5).expect("valid range")))
            .expect("cache range read"),
        b"bytes"
    );
    assert!(graph.contains(id).expect("cached object present"));

    let metrics = graph.metrics();
    let root_snapshot = metrics_for(&metrics, &root);
    assert_eq!(root_snapshot.put_calls, 1);
    assert_eq!(root_snapshot.put_logical_bytes, bytes.len() as u64);
    assert_eq!(root_snapshot.read_calls, 2);
    assert_eq!(root_snapshot.read_logical_bytes, bytes.len() as u64 + 5);
    assert_eq!(root_snapshot.read_stream_opens, 2);
    assert_eq!(root_snapshot.read_stream_completions, 2);
    assert_eq!(root_snapshot.read_stream_abandons, 0);
    assert_eq!(root_snapshot.read_stream_failures, 0);
    assert_eq!(root_snapshot.read_stream_bytes, bytes.len() as u64 + 5);
    assert_eq!(root_snapshot.contains_calls, 1);
    assert_eq!(root_snapshot.contains_hits, 1);
    assert_eq!(root_snapshot.failures, 0);

    let cache_snapshot = metrics_for(&metrics, &cache_metrics);
    assert_eq!(cache_snapshot.read_calls, 3);
    assert_eq!(cache_snapshot.failures, 1);
    assert_eq!(cache_snapshot.put_calls, 1);
    assert_eq!(cache_snapshot.put_logical_bytes, bytes.len() as u64);

    let source_snapshot = metrics_for(&metrics, &source_metrics);
    assert_eq!(source_snapshot.put_calls, 1);
    assert_eq!(source_snapshot.read_calls, 1);
    assert_eq!(source_snapshot.read_logical_bytes, bytes.len() as u64);
    assert_eq!(source_snapshot.read_stream_opens, 2);
    assert_eq!(source_snapshot.read_stream_completions, 2);
    assert_eq!(source_snapshot.read_stream_abandons, 0);
    assert_eq!(source_snapshot.read_stream_failures, 0);
    assert_eq!(source_snapshot.read_stream_bytes, 2 * bytes.len() as u64);
    assert_eq!(source_snapshot.failures, 0);
}

#[test]
fn metrics_distinguish_complete_abandoned_and_failed_deferred_reads() {
    let child = Arc::new(MemoryBlobBackend::new("metrics-child", 1_024));
    let (store, state) = MetricsStore::new("metrics", child.clone());
    let bytes = b"authenticated stream";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(child.as_ref(), id, bytes).expect("seed metrics child");

    let complete = store.read(id, None).expect("complete handle");
    assert_eq!(
        complete.read_all(TEST_READ_LIMIT).expect("complete read"),
        bytes
    );
    let partial = store.read(id, None).expect("partial handle");
    let mut reader = partial.open().expect("open partial stream");
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).expect("read partial prefix");
    drop(reader);

    let snapshot = state.snapshot();
    assert_eq!(snapshot.read_calls, 2);
    assert_eq!(snapshot.read_stream_opens, 2);
    assert_eq!(snapshot.read_stream_completions, 1);
    assert_eq!(snapshot.read_stream_abandons, 1);
    assert_eq!(snapshot.read_stream_failures, 0);
    assert_eq!(snapshot.read_stream_bytes, bytes.len() as u64 + 4);

    let broken = Arc::new(FixedReadBackend {
        source: BlobHandle::new(Arc::new(MismatchedLengthSource {
            declared: 4,
            bytes: b"abc",
        })),
    });
    let (broken_metrics, broken_state) = MetricsStore::new("broken-metrics", broken);
    assert!(matches!(
        broken_metrics
            .read(id, None)
            .expect("deferred failure handle")
            .read_all(TEST_READ_LIMIT),
        Err(StoreError::InvalidSourceLength { .. })
    ));
    let snapshot = broken_state.snapshot();
    assert_eq!(snapshot.read_stream_opens, 1);
    assert_eq!(snapshot.read_stream_completions, 0);
    assert_eq!(snapshot.read_stream_abandons, 0);
    assert_eq!(snapshot.read_stream_failures, 1);
    assert_eq!(snapshot.read_stream_bytes, 3);
}

#[test]
fn metrics_measure_synchronous_and_deferred_host_latency() {
    let delay = Duration::from_millis(2);
    let child = Arc::new(MemoryBlobBackend::new("latency-child", 1_024));
    let delayed = Arc::new(DelayedMetricsBackend {
        child: child.clone(),
        delay,
    });
    let (store, state) = MetricsStore::new("latency-metrics", delayed);
    let bytes = b"latency bytes";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    put_bytes(child.as_ref(), id, bytes).expect("seed latency child");

    assert!(store.contains(id).expect("delayed contains"));
    assert_eq!(
        store
            .read(id, None)
            .expect("delayed handle")
            .read_all(TEST_READ_LIMIT)
            .expect("delayed stream"),
        bytes
    );
    let second = b"second latency object";
    let second_id = ContentId::for_bytes(ObjectKind::Trace, 1, second);
    put_bytes(&store, second_id, second).expect("delayed put");

    let minimum = u64::try_from(delay.as_nanos()).expect("test duration fits u64");
    let snapshot = state.snapshot();
    assert!(snapshot.contains_elapsed_nanoseconds >= minimum);
    assert!(snapshot.read_elapsed_nanoseconds >= minimum);
    assert!(snapshot.read_stream_open_elapsed_nanoseconds >= minimum);
    assert!(snapshot.read_stream_read_elapsed_nanoseconds >= minimum);
    assert!(snapshot.put_elapsed_nanoseconds >= minimum);
}

#[test]
fn closed_store_graph_rejects_cycles_missing_routes_and_unreachable_nodes() {
    let root = node_id("root");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([(
                root.clone(),
                StoreNodeSpec::Verified {
                    child: root.clone()
                }
            )]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::Cycle,
            ..
        })
    ));

    let router = node_id("router");
    let leaf = node_id("leaf");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: router.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact, ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    router,
                    StoreNodeSpec::Routed {
                        routes: BTreeMap::from([(ObjectKind::CampaignFact, leaf.clone())])
                    }
                ),
                (
                    leaf,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024
                    }
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::RouteCoverage,
            ..
        })
    ));

    let root = node_id("root");
    let unused = node_id("unused");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
            nodes: BTreeMap::from([
                (
                    root,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024
                    }
                ),
                (
                    unused,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024
                    }
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnreachableNode,
            ..
        })
    ));
}

#[test]
fn closed_store_graph_rejects_unbounded_or_ambient_administrative_paths() {
    let root = node_id("directory");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::Directory {
                    root: PathBuf::from("relative-store-root"),
                },
            )]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::RelativeAdministrativePath,
            ..
        })
    ));

    let root = node_id("oversized-directory");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::Directory {
                    root: PathBuf::from(format!("/{}", "a".repeat(4_096))),
                },
            )]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::AdministrativePathTooLong,
            ..
        })
    ));
}

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
