//! S3-backed generation-fenced global-GC integration tests.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible_campaign::{ActiveAttemptPolicy, CampaignHash, CampaignRepository, CampaignState};
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryRefBackend, ImmutableBlobBackend, ObjectKind, RefName,
    StoreError, StoreGraph, StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
    StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNodeId,
    StoreNodeSpec, StoreS3BlobAdminClient, StoreS3Client, StoreS3ConditionalDeleteOutcome,
    StoreS3ConditionalPutOutcome, StoreS3ConditionalWriteOutcome, StoreS3EndpointId,
    StoreS3MultipartListCursor, StoreS3MultipartListPage, StoreS3MultipartUpload,
    StoreS3ObjectDownload, StoreS3ObjectListCursor, StoreS3ObjectListPage, StoreS3ObjectScan,
    StoreS3ObjectVersion, StoreS3StrongCasClient, StoreS3UploadedPart, StoreS3VersionedObject,
    StoreS3VersionedObjectMetadata,
};

use super::*;

const BUCKET: &str = "campaign-gc-integration";
const PREFIX: &str = "tests/s3-gc";
const MAXIMUM_OBJECT_BYTES: u64 = 8 * 1024 * 1024;
const MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
const S3_AVAILABLE: u8 = 0;
const S3_UNAVAILABLE: u8 = 1;
const S3_CREDENTIALS_EXPIRED: u8 = 2;
type S3Location = (String, String);
type MemoryObjectMap = BTreeMap<S3Location, Arc<[u8]>>;
type MemoryVersionedStateMap = BTreeMap<S3Location, (Arc<[u8]>, u64)>;

#[derive(Default)]
struct UploadState {
    bucket: String,
    key: String,
    parts: BTreeMap<u32, Arc<[u8]>>,
}

struct MemoryS3Service {
    endpoint: StoreS3EndpointId,
    objects: Mutex<MemoryObjectMap>,
    uploads: Mutex<BTreeMap<String, UploadState>>,
    state: Mutex<MemoryVersionedStateMap>,
    next_upload: AtomicU64,
    next_version: AtomicU64,
    fault: AtomicU8,
}

impl MemoryS3Service {
    fn new() -> Self {
        Self {
            endpoint: StoreS3EndpointId::new("tests/memory-s3-gc").expect("endpoint"),
            objects: Mutex::new(BTreeMap::new()),
            uploads: Mutex::new(BTreeMap::new()),
            state: Mutex::new(BTreeMap::new()),
            next_upload: AtomicU64::new(1),
            next_version: AtomicU64::new(1),
            fault: AtomicU8::new(S3_AVAILABLE),
        }
    }

    fn set_fault(&self, fault: u8) {
        self.fault.store(fault, Ordering::SeqCst);
    }

    fn require_available(&self) -> Result<(), StoreError> {
        match self.fault.load(Ordering::SeqCst) {
            S3_AVAILABLE => Ok(()),
            S3_UNAVAILABLE => Err(StoreError::Unavailable),
            S3_CREDENTIALS_EXPIRED => Err(StoreError::Unauthorized),
            _ => Err(StoreError::Incompatible),
        }
    }

    fn next_state_version(&self) -> (u64, StoreS3ObjectVersion) {
        let version = self.next_version.fetch_add(1, Ordering::SeqCst);
        (
            version,
            StoreS3ObjectVersion::new(format!("state-{version}")).expect("state version"),
        )
    }

    fn object_version(bytes: &[u8]) -> StoreS3ObjectVersion {
        StoreS3ObjectVersion::new(format!("object-{}", blake3::hash(bytes).to_hex()))
            .expect("object version")
    }

    fn metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
        self.require_available()?;
        if let Some((bytes, version)) = self
            .state
            .lock()
            .expect("state lock")
            .get(&(bucket.to_string(), key.to_string()))
            .cloned()
        {
            return Ok(Some(StoreS3VersionedObjectMetadata::new(
                bytes.len() as u64,
                StoreS3ObjectVersion::new(format!("state-{version}"))?,
            )));
        }
        Ok(self
            .objects
            .lock()
            .expect("object lock")
            .get(&(bucket.to_string(), key.to_string()))
            .map(|bytes| {
                StoreS3VersionedObjectMetadata::new(bytes.len() as u64, Self::object_version(bytes))
            }))
    }
}

impl StoreS3Client for MemoryS3Service {
    fn endpoint_id(&self) -> &StoreS3EndpointId {
        &self.endpoint
    }

    fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StoreError> {
        self.require_available()?;
        Ok(self
            .objects
            .lock()
            .expect("object lock")
            .get(&(bucket.to_string(), key.to_string()))
            .map(|bytes| bytes.len() as u64))
    }

    fn get_object(&self, bucket: &str, key: &str) -> Result<StoreS3ObjectDownload, StoreError> {
        self.require_available()?;
        let bytes = self
            .objects
            .lock()
            .expect("object lock")
            .get(&(bucket.to_string(), key.to_string()))
            .cloned()
            .ok_or(StoreError::Incompatible)?;
        Ok(StoreS3ObjectDownload::new(
            bytes.len() as u64,
            Box::new(Cursor::new(bytes)),
        ))
    }

    fn put_empty_if_absent(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
        let mut objects = self.objects.lock().expect("object lock");
        match objects.entry((bucket.to_string(), key.to_string())) {
            Entry::Occupied(_) => Ok(StoreS3ConditionalPutOutcome::AlreadyExists),
            Entry::Vacant(entry) => {
                entry.insert(Arc::from([]));
                Ok(StoreS3ConditionalPutOutcome::Created)
            }
        }
    }

    fn begin_multipart(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoreS3MultipartUpload, StoreError> {
        let ordinal = self.next_upload.fetch_add(1, Ordering::SeqCst);
        let upload = StoreS3MultipartUpload::new(format!("upload-{ordinal}"))?;
        self.uploads.lock().expect("upload lock").insert(
            upload.as_str().to_string(),
            UploadState {
                bucket: bucket.to_string(),
                key: key.to_string(),
                parts: BTreeMap::new(),
            },
        );
        Ok(upload)
    }

    fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
        part_number: u32,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3UploadedPart, StoreError> {
        let mut uploads = self.uploads.lock().expect("upload lock");
        let state = uploads
            .get_mut(upload.as_str())
            .ok_or(StoreError::Incompatible)?;
        if state.bucket != bucket || state.key != key {
            return Err(StoreError::Incompatible);
        }
        state.parts.insert(part_number, bytes);
        StoreS3UploadedPart::new(part_number, format!("etag-{part_number}"))
    }

    fn complete_multipart_if_absent(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
        parts: &[StoreS3UploadedPart],
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
        let location = (bucket.to_string(), key.to_string());
        if self
            .objects
            .lock()
            .expect("object lock")
            .contains_key(&location)
        {
            return Ok(StoreS3ConditionalPutOutcome::AlreadyExists);
        }
        let state = self
            .uploads
            .lock()
            .expect("upload lock")
            .remove(upload.as_str())
            .ok_or(StoreError::Incompatible)?;
        if state.bucket != bucket || state.key != key || state.parts.len() != parts.len() {
            return Err(StoreError::Incompatible);
        }
        let mut body = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let ordinal = u32::try_from(index + 1).map_err(|_| StoreError::Quota)?;
            if part.part_number() != ordinal || part.provider_tag() != format!("etag-{ordinal}") {
                return Err(StoreError::Incompatible);
            }
            body.extend_from_slice(state.parts.get(&ordinal).ok_or(StoreError::Incompatible)?);
        }
        self.objects
            .lock()
            .expect("object lock")
            .insert(location, Arc::from(body));
        Ok(StoreS3ConditionalPutOutcome::Created)
    }

    fn abort_multipart(
        &self,
        _bucket: &str,
        _key: &str,
        upload: &StoreS3MultipartUpload,
    ) -> Result<(), StoreError> {
        self.uploads
            .lock()
            .expect("upload lock")
            .remove(upload.as_str());
        Ok(())
    }

    fn list_multipart_uploads(
        &self,
        _bucket: &str,
        _prefix: &str,
        after: Option<&StoreS3MultipartListCursor>,
        maximum_items: u16,
    ) -> Result<StoreS3MultipartListPage, StoreError> {
        StoreS3MultipartListPage::new(Vec::new(), None, after, maximum_items)
    }
}

impl StoreS3StrongCasClient for MemoryS3Service {
    fn endpoint_id(&self) -> &StoreS3EndpointId {
        &self.endpoint
    }

    fn get_small_versioned_object(
        &self,
        bucket: &str,
        key: &str,
        maximum_bytes: u16,
    ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
        self.require_available()?;
        self.state
            .lock()
            .expect("state lock")
            .get(&(bucket.to_string(), key.to_string()))
            .cloned()
            .map(|(bytes, version)| {
                if bytes.len() > usize::from(maximum_bytes) {
                    return Err(StoreError::Quota);
                }
                StoreS3VersionedObject::new(
                    bytes,
                    StoreS3ObjectVersion::new(format!("state-{version}"))?,
                )
            })
            .transpose()
    }

    fn put_small_if_absent(
        &self,
        bucket: &str,
        key: &str,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3ConditionalWriteOutcome, StoreError> {
        let mut state = self.state.lock().expect("state lock");
        match state.entry((bucket.to_string(), key.to_string())) {
            Entry::Occupied(_) => Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed),
            Entry::Vacant(entry) => {
                let (version, token) = self.next_state_version();
                entry.insert((bytes, version));
                Ok(StoreS3ConditionalWriteOutcome::Committed(token))
            }
        }
    }

    fn replace_small_if_version(
        &self,
        bucket: &str,
        key: &str,
        expected: &StoreS3ObjectVersion,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3ConditionalWriteOutcome, StoreError> {
        let mut state = self.state.lock().expect("state lock");
        let Some((body, version)) = state.get_mut(&(bucket.to_string(), key.to_string())) else {
            return Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed);
        };
        if expected.as_str() != format!("state-{version}") {
            return Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed);
        }
        let (next, token) = self.next_state_version();
        *body = bytes;
        *version = next;
        Ok(StoreS3ConditionalWriteOutcome::Committed(token))
    }

    fn begin_small_object_scan(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Box<dyn StoreS3ObjectScan + '_>, StoreError> {
        self.require_available()?;
        Ok(Box::new(MemoryS3Scan {
            service: self,
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            after: None,
            finished: false,
        }))
    }
}

impl StoreS3BlobAdminClient for MemoryS3Service {
    fn head_versioned_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
        self.metadata(bucket, key)
    }

    fn delete_object_if_version(
        &self,
        bucket: &str,
        key: &str,
        expected: &StoreS3ObjectVersion,
    ) -> Result<StoreS3ConditionalDeleteOutcome, StoreError> {
        self.require_available()?;
        let mut objects = self.objects.lock().expect("object lock");
        let location = (bucket.to_string(), key.to_string());
        let Some(body) = objects.get(&location) else {
            return Ok(StoreS3ConditionalDeleteOutcome::Deleted);
        };
        if &Self::object_version(body) != expected {
            return Ok(StoreS3ConditionalDeleteOutcome::PreconditionFailed);
        }
        objects.remove(&location);
        Ok(StoreS3ConditionalDeleteOutcome::Deleted)
    }
}

struct MemoryS3Scan<'a> {
    service: &'a MemoryS3Service,
    bucket: String,
    prefix: String,
    after: Option<StoreS3ObjectListCursor>,
    finished: bool,
}

impl StoreS3ObjectScan for MemoryS3Scan<'_> {
    fn next_page(&mut self, maximum_items: u16) -> Result<StoreS3ObjectListPage, StoreError> {
        self.service.require_available()?;
        if self.finished {
            return Err(StoreError::Incompatible);
        }
        let mut keys = self
            .service
            .objects
            .lock()
            .expect("object lock")
            .keys()
            .filter(|(bucket, key)| bucket == &self.bucket && key.starts_with(&self.prefix))
            .map(|(_bucket, key)| key.clone())
            .filter(|key| {
                self.after
                    .as_ref()
                    .is_none_or(|after| key.as_str() > after.as_str())
            })
            .collect::<Vec<_>>();
        keys.sort();
        let truncated = keys.len() > usize::from(maximum_items);
        keys.truncate(usize::from(maximum_items));
        let next = truncated
            .then(|| keys.last().cloned())
            .flatten()
            .map(StoreS3ObjectListCursor::new)
            .transpose()?;
        let page =
            StoreS3ObjectListPage::new(keys, next.clone(), self.after.as_ref(), maximum_items)?;
        self.after = next;
        self.finished = self.after.is_none();
        Ok(page)
    }

    fn get_small_versioned_object(
        &self,
        key: &str,
        maximum_bytes: u16,
    ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
        self.service.require_available()?;
        self.service
            .get_small_versioned_object(&self.bucket, key, maximum_bytes)
    }

    fn head_versioned_object(
        &self,
        key: &str,
    ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
        self.service.metadata(&self.bucket, key)
    }
}

fn graph_config(endpoint: StoreS3EndpointId) -> StoreGraphConfig {
    let root = StoreNodeId::new("s3-primary").expect("S3 node");
    StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            root,
            StoreNodeSpec::S3 {
                endpoint,
                bucket: BUCKET.to_string(),
                prefix: PREFIX.to_string(),
                maximum_logical_object_bytes: MAXIMUM_OBJECT_BYTES,
                multipart_part_bytes: MULTIPART_PART_BYTES,
            },
        )]),
    }
}

fn build_graph(
    service: Arc<MemoryS3Service>,
) -> (StoreGraph, crucible_cas::content_store::StoreGraphAdmin) {
    let config = graph_config(service.endpoint.clone());
    build_graph_with_config(service, config)
}

fn build_graph_with_config(
    service: Arc<MemoryS3Service>,
    config: StoreGraphConfig,
) -> (StoreGraph, crucible_cas::content_store::StoreGraphAdmin) {
    let mut clients = StoreGraphS3Clients::new();
    clients
        .insert(service.endpoint.clone(), service.clone())
        .expect("ordinary S3 capability");
    clients
        .insert_administration(service.endpoint.clone(), service.clone())
        .expect("administrative S3 capability");
    StoreGraph::build_with_admin_and_all_capabilities(
        config,
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &StoreGraphPhysicalQuotaBinders::new(),
        &clients,
    )
    .expect("administrable S3 graph")
}

fn write_back_graph_config(endpoint: StoreS3EndpointId, root: &Path) -> StoreGraphConfig {
    let write_back = StoreNodeId::new("write-back").expect("write-back node");
    let staging = StoreNodeId::new("staging").expect("staging node");
    let destination = StoreNodeId::new("s3-primary").expect("S3 node");
    StoreGraphConfig {
        root: write_back.clone(),
        admitted_kinds: BTreeSet::from([
            ObjectKind::CampaignFact,
            ObjectKind::CampaignSnapshot,
            ObjectKind::MerkleNode,
            ObjectKind::Scenario,
            ObjectKind::Configuration,
            ObjectKind::Policy,
            ObjectKind::ExactManifest,
            ObjectKind::RamExtent,
            ObjectKind::DiskExtent,
            ObjectKind::DeviceState,
            ObjectKind::Observation,
            ObjectKind::Finding,
            ObjectKind::Projection,
            ObjectKind::Trace,
        ]),
        nodes: BTreeMap::from([
            (
                write_back,
                StoreNodeSpec::WriteBack {
                    staging: staging.clone(),
                    destination: destination.clone(),
                    journal_root: root.join("write-back-journal"),
                    maximum_pending_objects: 1024,
                    maximum_pending_bytes: 16 * 1024 * 1024,
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
                StoreNodeSpec::S3 {
                    endpoint,
                    bucket: BUCKET.to_string(),
                    prefix: PREFIX.to_string(),
                    maximum_logical_object_bytes: MAXIMUM_OBJECT_BYTES,
                    multipart_part_bytes: MULTIPART_PART_BYTES,
                },
            ),
        ]),
    }
}

#[test]
fn s3_graph_admin_drives_global_gc_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary S3 GC root");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let service = Arc::new(MemoryS3Service::new());
    let (graph, admin) = build_graph(service.clone());
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());

    let live = ContentEnvelope::new(
        "crucible.test.gc-s3-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live S3 object");
    refs.compare_exchange(
        &RefName::new("retained/s3-gc").expect("S3 ref"),
        None,
        live_id,
    )
    .expect("publish S3 root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store S3 orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open S3 ledger");
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan S3 GC");
    assert_eq!(prepared.plan().physical().len(), 1);
    assert_eq!(prepared.plan().physical()[0].backend(), "s3-primary");
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) =
        DirectoryCampaignGcJournal::create(&journal_root, &prepared).expect("create S3 GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) = build_graph(service);
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen S3 ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen S3 GC journal");
    let report = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply S3 GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live S3 placement"));
    assert!(!graph.contains(orphan).expect("orphan S3 placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read live S3 object")
            .read_all(1024 * 1024)
            .expect("authenticate live S3 object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn s3_publication_after_planning_invalidates_apply_without_deletion() {
    let temp = tempfile::TempDir::new().expect("temporary stale S3 GC root");
    let service = Arc::new(MemoryS3Service::new());
    let (graph, admin) = build_graph(service);
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(temp.path().join("refs")));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let orphan_bytes = b"planned S3 orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store planned S3 orphan");
    let mut ledger =
        DirectoryAssignmentLedger::open(temp.path().join("ledger")).expect("open stale S3 ledger");
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan stale S3 GC");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &prepared)
            .expect("create stale S3 journal");

    let late_bytes = b"publication after S3 planning";
    let late = ContentId::for_bytes(ObjectKind::Trace, 1, late_bytes);
    graph
        .put_if_absent(late, &BlobHandle::from_bytes(late_bytes))
        .expect("publish after S3 planning");
    assert!(matches!(
        super::super::apply_single_host_campaign_gc(
            &mut journal,
            &repository,
            refs.as_ref(),
            &mut ledger,
            None,
            None,
            &admin,
        ),
        Err(CampaignGcApplyError::PhysicalBasisChanged { backend })
            if backend == "s3-primary"
    ));
    assert!(graph.contains(orphan).expect("planned orphan retained"));
    assert!(graph.contains(late).expect("late publication retained"));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
}

#[test]
fn s3_gc_retains_multiple_refs_and_transfer_during_backend_faults() {
    let temp = tempfile::TempDir::new().expect("temporary S3 recovery root");
    let service = Arc::new(MemoryS3Service::new());
    let (graph, admin) = build_graph(service.clone());
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(temp.path().join("refs")));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(temp.path().join("ledger"))
        .expect("open S3 recovery ledger");

    let mut retained = Vec::new();
    for name in ["east", "west"] {
        let envelope = ContentEnvelope::new(
            "crucible.test.gc-s3-derived-ref",
            1,
            BTreeSet::new(),
            name.as_bytes().to_vec(),
        )
        .expect("retained envelope");
        let bytes = envelope.canonical_bytes();
        let id = envelope.content_id(ObjectKind::RamExtent);
        graph
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
            .expect("store retained object");
        refs.compare_exchange(
            &RefName::new(format!("retained/s3-{name}")).expect("retained ref"),
            None,
            id,
        )
        .expect("publish retained ref");
        retained.push((name, id, bytes));
    }

    let transfer = ContentEnvelope::new(
        "crucible.test.gc-s3-transfer",
        1,
        BTreeSet::new(),
        b"active transfer".to_vec(),
    )
    .expect("transfer envelope");
    let transfer_bytes = transfer.canonical_bytes();
    let transfer_id = transfer.content_id(ObjectKind::Trace);
    graph
        .put_if_absent(transfer_id, &BlobHandle::from_bytes(transfer_bytes.clone()))
        .expect("store transfer root");
    let transfers = TestCampaignTransferRoots::default();
    transfers.replace(vec![CampaignTransferRetentionRoot::new(
        transfer_id,
        transfer_bytes.len() as u64,
    )]);
    let hot = MemoryHotCheckpointFallbackRetentionStore::new();

    let orphan_bytes = b"unreachable S3 recovery object";
    let orphan_id = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan_id, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store recovery orphan");

    for fault in [S3_UNAVAILABLE, S3_CREDENTIALS_EXPIRED] {
        service.set_fault(fault);
        match fault {
            S3_UNAVAILABLE => assert!(matches!(
                graph.contains(retained[0].1),
                Err(StoreError::Unavailable)
            )),
            S3_CREDENTIALS_EXPIRED => assert!(matches!(
                graph.contains(retained[0].1),
                Err(StoreError::Unauthorized)
            )),
            _ => unreachable!("the fault matrix has only two declared cases"),
        }
        assert!(
            super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
                &repository,
                refs.as_ref(),
                &mut ledger,
                None,
                CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
                &admin,
            )
            .is_err(),
            "GC planning accepted S3 fault {fault}"
        );
    }
    service.set_fault(S3_AVAILABLE);

    let (corrupt_location, original) = {
        let mut objects = service.objects.lock().expect("S3 object lock");
        let (location, stored) = objects
            .iter_mut()
            .find(|(_location, bytes)| bytes.as_ref() == retained[0].2.as_slice())
            .expect("east retained S3 payload");
        let original = stored.clone();
        let mut corrupt = retained[0].2.clone();
        corrupt[0] ^= 0xff;
        *stored = Arc::from(corrupt);
        (location.clone(), original)
    };
    assert!(matches!(
        graph
            .read(retained[0].1, None)
            .and_then(|handle| handle.read_all(1024 * 1024)),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(
        super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
            &repository,
            refs.as_ref(),
            &mut ledger,
            None,
            CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
            &admin,
        )
        .is_err(),
        "GC planning accepted corrupted retained S3 bytes"
    );
    {
        let mut objects = service.objects.lock().expect("S3 object lock");
        let stored = objects
            .get_mut(&corrupt_location)
            .expect("corrupted east S3 payload");
        *stored = original;
    }

    let prepared = super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        &admin,
    )
    .expect("plan healthy S3 recovery GC");
    assert!(prepared.roots().iter().any(|id| id == transfer_id));
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan_id
    );

    let (mut interrupted, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("interrupted"), &prepared)
            .expect("create interrupted S3 recovery journal");
    service.set_fault(S3_UNAVAILABLE);
    assert!(
        super::super::apply_single_host_campaign_gc_with_hot_checkpoints(
            &mut interrupted,
            &repository,
            refs.as_ref(),
            &mut ledger,
            None,
            CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
            &admin,
        )
        .is_err(),
        "GC apply accepted S3 outage"
    );
    service.set_fault(S3_AVAILABLE);
    assert!(graph.contains(orphan_id).expect("orphan survived outage"));

    let recovered = super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        &admin,
    )
    .expect("replan after S3 recovery");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("recovered"), &recovered)
            .expect("create recovered S3 GC journal");
    let report = super::super::apply_single_host_campaign_gc_with_hot_checkpoints(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        &admin,
    )
    .expect("apply S3 recovery GC");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(!graph.contains(orphan_id).expect("orphan reclaimed"));
    assert!(graph.contains(transfer_id).expect("transfer root retained"));
    for (name, id, bytes) in retained {
        assert_eq!(
            refs.read_ref(&RefName::new(format!("retained/s3-{name}")).expect("retained ref"))
                .expect("read retained ref"),
            Some(id)
        );
        assert_eq!(
            graph
                .read(id, None)
                .expect("read retained S3 object")
                .read_all(1024 * 1024)
                .expect("authenticate retained S3 object"),
            bytes
        );
    }
}

fn publish_paused_s3_campaign(repository: &CampaignRepository) -> [CampaignSnapshotId; 3] {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "crucible.test.gc-s3-campaign",
        b"scenario",
    ));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.gc-s3-campaign",
        b"genesis",
    ));
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"S3 recovery scenario".to_vec())
        .expect("publish S3 scenario");
    let genesis_content = repository
        .publish_configuration_artifact(
            scenario,
            scenario_content,
            genesis,
            1,
            b"S3 recovery genesis".to_vec(),
        )
        .expect("publish S3 genesis");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-s3-recovery-test",
        "qemu-s3-recovery-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("S3 recovery lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x73; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("S3 recovery fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("S3 recovery policy");
    let created = repository
        .create("s3-source", &lineage, &policy, &BTreeMap::new())
        .expect("create S3 recovery campaign");
    let resumed = repository
        .apply_control(
            "s3-source",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.gc-s3-campaign",
                    b"resume",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume S3 recovery campaign");
    let paused = repository
        .apply_control(
            "s3-source",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.gc-s3-campaign",
                    b"pause",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
            },
        )
        .expect("pause S3 recovery campaign");
    let east = repository
        .derive_campaign("s3-source", paused.new_snapshot, "s3-east", None)
        .expect("derive east from paused campaign");
    let west = repository
        .derive_campaign("s3-east", east.new_snapshot, "s3-west", None)
        .expect("derive west from paused east");
    assert_eq!(
        repository.state("s3-east").expect("east state"),
        CampaignState::Paused
    );
    assert_eq!(
        repository.state("s3-west").expect("west state"),
        CampaignState::Paused
    );
    [paused.new_snapshot, east.new_snapshot, west.new_snapshot]
}

#[test]
fn paused_derived_s3_campaign_recovers_with_pending_write_back_transfer_and_gc() {
    let temp = tempfile::TempDir::new().expect("temporary paused S3 recovery root");
    let service = Arc::new(MemoryS3Service::new());
    let config = write_back_graph_config(service.endpoint.clone(), temp.path());
    let (graph, admin) = build_graph_with_config(service.clone(), config);
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(temp.path().join("refs")));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(temp.path().join("ledger"))
        .expect("open paused S3 recovery ledger");
    let [paused, east, west] = publish_paused_s3_campaign(&repository);

    let orphan = ContentEnvelope::new(
        "crucible.test.gc-s3-orphan",
        1,
        BTreeSet::new(),
        b"unreachable paused-campaign object".to_vec(),
    )
    .expect("S3 recovery orphan");
    let orphan_id = orphan.content_id(ObjectKind::Trace);
    graph
        .put_if_absent(orphan_id, &BlobHandle::from_bytes(orphan.canonical_bytes()))
        .expect("stage S3 recovery orphan");
    let flushed = graph
        .flush_write_back(1024)
        .expect("flush paused campaign to S3");
    assert_eq!(flushed.pending(), 0);

    // Evict the completed staging copy so the paused head must authenticate
    // through S3 while another transfer remains pending in write-back.
    let staging = DirectoryBlobBackend::new("staging", temp.path().join("staging"));
    let mut stage_fence = staging
        .acquire_inventory_fence()
        .expect("fence staging tier");
    assert_eq!(
        stage_fence
            .delete_candidate(west.content_id())
            .expect("evict flushed paused head"),
        PlannedDeleteDisposition::Deleted
    );
    drop(stage_fence);

    let transfer = ContentEnvelope::new(
        "crucible.test.gc-s3-active-transfer",
        1,
        BTreeSet::new(),
        b"pending S3 transfer".to_vec(),
    )
    .expect("pending S3 transfer");
    let transfer_bytes = transfer.canonical_bytes();
    let transfer_id = transfer.content_id(ObjectKind::Trace);
    graph
        .put_if_absent(transfer_id, &BlobHandle::from_bytes(transfer_bytes.clone()))
        .expect("stage active S3 transfer");
    let transfers = TestCampaignTransferRoots::default();
    transfers.replace(vec![CampaignTransferRetentionRoot::new(
        transfer_id,
        transfer_bytes.len() as u64,
    )]);
    let hot = MemoryHotCheckpointFallbackRetentionStore::new();

    for fault in [S3_UNAVAILABLE, S3_CREDENTIALS_EXPIRED] {
        service.set_fault(fault);
        assert!(
            repository.head("s3-west").is_err(),
            "paused head survived fault {fault}"
        );
        assert!(
            graph.flush_write_back(1).is_err(),
            "write-back ignored fault {fault}"
        );
        assert!(
            super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
                &repository,
                refs.as_ref(),
                &mut ledger,
                Some(graph.as_ref()),
                CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
                &admin,
            )
            .is_err(),
            "GC planning accepted fault {fault}"
        );
    }
    service.set_fault(S3_AVAILABLE);

    let west_bytes = graph
        .read(west.content_id(), None)
        .expect("read recovered paused head")
        .read_all(1024 * 1024)
        .expect("authenticate recovered paused head");
    let (west_location, original) = {
        let mut objects = service.objects.lock().expect("S3 object lock");
        let (location, stored) = objects
            .iter_mut()
            .find(|(_location, bytes)| bytes.as_ref() == west_bytes.as_slice())
            .expect("west paused head in S3");
        let original = stored.clone();
        let mut corrupt = west_bytes.clone();
        corrupt[0] ^= 0xff;
        *stored = Arc::from(corrupt);
        (location.clone(), original)
    };
    assert!(matches!(
        graph
            .read(west.content_id(), None)
            .and_then(|handle| handle.read_all(1024 * 1024)),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(repository.head("s3-west").is_err());
    assert!(
        super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
            &repository,
            refs.as_ref(),
            &mut ledger,
            Some(graph.as_ref()),
            CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
            &admin,
        )
        .is_err(),
        "GC planning accepted corrupt paused S3 head"
    );
    service
        .objects
        .lock()
        .expect("S3 object lock")
        .insert(west_location, original);

    let prepared = super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        Some(graph.as_ref()),
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        &admin,
    )
    .expect("plan recovered paused campaign GC");
    assert!(prepared.roots().iter().any(|id| id == transfer_id));
    assert!(
        prepared
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == orphan_id)
    );
    let (mut stale, _) = DirectoryCampaignGcJournal::create(temp.path().join("stale"), &prepared)
        .expect("journal pre-publication GC");
    let north = repository
        .derive_campaign("s3-east", east, "s3-north", None)
        .expect("publish third derived head after planning");
    assert!(matches!(
        super::super::apply_single_host_campaign_gc_with_hot_checkpoints(
            &mut stale,
            &repository,
            refs.as_ref(),
            &mut ledger,
            Some(graph.as_ref()),
            CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
            &admin,
        ),
        Err(CampaignGcApplyError::PhysicalBasisChanged { .. })
            | Err(CampaignGcApplyError::RefBasisChanged)
    ));
    assert!(
        graph
            .contains(orphan_id)
            .expect("orphan survived stale plan")
    );

    let recovered = super::super::plan_single_host_campaign_gc_with_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        Some(graph.as_ref()),
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        &admin,
    )
    .expect("replan after third derived publication");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("recovered"), &recovered)
            .expect("journal recovered paused campaign GC");
    let report = super::super::apply_single_host_campaign_gc_with_hot_checkpoints(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        Some(graph.as_ref()),
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        &admin,
    )
    .expect("apply recovered paused campaign GC");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(!graph.contains(orphan_id).expect("orphan reclaimed"));
    assert!(
        graph
            .contains(transfer_id)
            .expect("pending transfer retained")
    );
    for (name, expected) in [
        ("s3-source", paused),
        ("s3-east", east),
        ("s3-west", west),
        ("s3-north", north.new_snapshot),
    ] {
        assert_eq!(
            repository
                .head(name)
                .expect("recovered campaign head")
                .snapshot_id(),
            expected
        );
        assert_eq!(
            repository.state(name).expect("recovered campaign state"),
            CampaignState::Paused
        );
    }

    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(staging);

    let reopened_config = write_back_graph_config(service.endpoint.clone(), temp.path());
    let (reopened_graph, _) = build_graph_with_config(service, reopened_config);
    let reopened_refs = Arc::new(DirectoryRefBackend::new(temp.path().join("refs")));
    let reopened = CampaignRepository::new(Arc::new(reopened_graph), reopened_refs);
    assert_eq!(
        reopened.state("s3-west").expect("reopen paused west"),
        CampaignState::Paused
    );
    let resumed = reopened
        .apply_control(
            "s3-west",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.gc-s3-campaign",
                    b"resume-after-recovery",
                )),
                expected_snapshot: west,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume west after backend recovery and graph restart");
    assert_ne!(resumed.new_snapshot, west);
    assert_eq!(
        reopened.state("s3-west").expect("resumed west"),
        CampaignState::Running
    );
}
