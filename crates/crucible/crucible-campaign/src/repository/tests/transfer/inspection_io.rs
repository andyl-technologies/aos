//! Bounded archive-inspection reads under genuine directory authority.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_store::content_envelope::{ContentChild, ContentEnvelope};
use crucible_store::content_store::{
    BackendCapabilities, BlobHandle, BlobSource, ByteRange, CheckedBlobReader, CheckedReadAccess,
    CheckedReader, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, PutReceipt, RefBackendCapabilities, RefCasOutcome, RefName,
    RefPublicationGuard, RefRemoveOutcome, RefScanPage, StoreError, StorePhysicalQuotaGuard,
};
use crucible_store::owned_decode::{DecodeBudget, DecodeScratch};

use super::*;

struct ObservedCheckedBackend {
    child: Arc<dyn ImmutableBlobBackend>,
    progress: BTreeMap<ContentId, Arc<AtomicU64>>,
}

impl ImmutableBlobBackend for ObservedCheckedBackend {
    fn name(&self) -> &str {
        self.child.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.child.metadata_resources()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.child.read(id, range)
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        let source = self
            .child
            .read_with_boundary(original, id, range, boundary)?;
        let Some(progress) = self.progress.get(&id) else {
            return Ok(source);
        };
        let credit = original
            .reserve_scratch_bytes(BlobHandle::source_allocation_bytes::<ObservedSource>())
            .map_err(|source| admission_error(original, source))?;
        Ok(BlobHandle::new(ObservedSource {
            source,
            original: original.clone(),
            progress: progress.clone(),
            _credit: credit,
        }))
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.child.put_if_absent(id, source)
    }
}

struct ObservedSource {
    source: BlobHandle,
    original: DecodeBudget,
    progress: Arc<AtomicU64>,
    _credit: DecodeScratch,
}

impl BlobSource for ObservedSource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        self.source.open()
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        let reader = BlobSource::open_with_boundary(&self.source, original, boundary)?;
        CheckedReader::new_prepaid(
            ObservedReader {
                reader,
                original: self.original.clone(),
                progress: self.progress.clone(),
            },
            original,
        )
    }
}

struct ObservedReader {
    reader: CheckedReader,
    original: DecodeBudget,
    progress: Arc<AtomicU64>,
}

impl CheckedBlobReader for ObservedReader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        let count = self.reader.read_with_boundary(output, boundary)?;
        self.progress.fetch_add(count as u64, Ordering::SeqCst);
        Ok(count)
    }
}

fn admission_error(
    original: &DecodeBudget,
    source: crucible_store::owned_decode::DecodeAdmissionError,
) -> StoreError {
    let crucible_store::ram::RamStoreError::Store(source) =
        crucible_store::ram::RamStoreError::from_admission(original, source)
    else {
        unreachable!("decode admission is store-shaped")
    };
    source
}

struct ReadObservedRefs {
    child: Arc<dyn MutableRefBackend>,
    reads: AtomicU64,
}

impl MutableRefBackend for ReadObservedRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.child.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard>, StoreError> {
        self.child.acquire_publication_guard()
    }

    fn compare_remove(
        &self,
        name: &RefName,
        expected: ContentId,
    ) -> Result<RefRemoveOutcome, StoreError> {
        self.child.compare_remove(name, expected)
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.child.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.child.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        self.child.compare_exchange(name, expected, next)
    }
}

#[test]
fn named_checked_inspection_refuses_callback_revocation_before_ref_dispatch() {
    let (source, lineage, policy) = fixture();
    let head = source
        .create(
            "named-inspection-revocation",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("source campaign");
    let plan = source
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Metadata,
            [],
            None,
        )
        .expect("metadata archive plan");
    source
        .publish_campaign_archive("revocation", None, &plan)
        .expect("ordinary named archive");

    let resources = Arc::new(resources::TransferResources::new(32, 8 * 1024 * 1024));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = resources.clone();
    let original = DecodeBudget::for_store(quota).expect("finite named-inspection authority");
    let observed_refs = Arc::new(ReadObservedRefs {
        child: source.refs.clone(),
        reads: AtomicU64::new(0),
    });
    let inspected = CampaignRepository::new(
        source.blobs.clone(),
        observed_refs.clone(),
        crate::CampaignRamAdmission::Available(original),
    );
    let baseline = resources.usage();

    let refused = inspected.inspect_campaign_archive_ref_with_boundary("revocation", &mut || {
        resources.revoke();
        Ok(())
    });
    assert!(matches!(
        &refused,
        Err(CampaignRepositoryError::Store(
            StoreError::DecodeAdmission { .. }
        ))
    ));
    assert_eq!(observed_refs.reads.load(Ordering::SeqCst), 0);
    drop(refused);
    assert_eq!(resources.usage(), baseline);
}

#[test]
fn checked_inspection_cancels_during_large_page_and_streams_large_opaque_object() {
    let (_memory_source, lineage, policy, memory_blobs) = counted_fixture();
    let directory = tempfile::tempdir().expect("durable inspection directory");
    let resources = Arc::new(resources::TransferResources::new(128, 512 * 1024 * 1024));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = resources.clone();
    let original = DecodeBudget::for_store(quota.clone()).expect("finite inspection authority");
    let blobs = DirectoryBlobBackend::new_with_physical_quota(
        "checked-inspection-source",
        directory.path().join("objects"),
        quota,
    )
    .expect("quota-bound inspection objects");
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));

    let mut seed_ids = Vec::new();
    memory_blobs
        .acquire_inventory_fence()
        .expect("metadata source inventory")
        .visit_inventory(&mut |record| {
            seed_ids.push(record.id());
            Ok(())
        })
        .expect("metadata source identities");
    for id in seed_ids {
        let bytes = memory_blobs.read(id, None).expect("metadata source bytes");
        blobs
            .put_if_absent(id, &bytes)
            .expect("durable metadata source");
    }
    let source = CampaignRepository::new(
        blobs.clone(),
        refs.clone(),
        crate::CampaignRamAdmission::Available(original.clone()),
    );
    let head = source
        .create("checked-inspection", &lineage, &policy, &BTreeMap::new())
        .expect("source campaign");

    let mut children = BTreeSet::new();
    for index in 0_u32..1024 {
        let bytes = index.to_be_bytes();
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("unique selected leaf");
        children
            .insert(ContentChild::new(format!("leaf-{index:08}"), id).expect("bounded leaf role"));
    }
    const LARGE_TRACE_BYTES: usize = 5 * 1024 * 1024;
    let large_trace_bytes = vec![0x5a; LARGE_TRACE_BYTES];
    let large_trace = ContentId::for_bytes(ObjectKind::Trace, 1, &large_trace_bytes);
    blobs
        .put_if_absent(large_trace, &BlobHandle::from_bytes(large_trace_bytes))
        .expect("large opaque selected object");
    children.insert(ContentChild::new("large-trace", large_trace).expect("large trace role"));
    let root = ContentEnvelope::new(
        "crucible.test.checked-inspection-root",
        6,
        children,
        b"checked archive inspection root".to_vec(),
    )
    .expect("bounded retained root");
    let root_id = root.content_id(ObjectKind::ExactManifest);
    blobs
        .put_if_absent(root_id, &BlobHandle::from_bytes(root.canonical_bytes()))
        .expect("retained root");
    let plan = source
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Mirror,
            [root_id],
            None,
        )
        .expect("large inspection plan");
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("source archive metadata");
    let (page_id, page_length) = plan
        .page_envelopes
        .iter()
        .map(|envelope| {
            (
                envelope.content_id(),
                envelope.canonical_bytes().len() as u64,
            )
        })
        .max_by_key(|(_, length)| *length)
        .expect("at least one inventory page");
    assert!(page_length > 64 * 1024);
    assert!(
        plan.selected()
            .iter()
            .any(|entry| entry.id() == large_trace)
    );

    let page_progress = Arc::new(AtomicU64::new(0));
    let opaque_progress = Arc::new(AtomicU64::new(0));
    let observed: Arc<dyn ImmutableBlobBackend> = Arc::new(ObservedCheckedBackend {
        child: blobs,
        progress: BTreeMap::from([
            (page_id, page_progress.clone()),
            (large_trace, opaque_progress.clone()),
        ]),
    });
    let inspected = CampaignRepository::new(
        observed,
        refs,
        crate::CampaignRamAdmission::Available(original),
    );
    let baseline = resources.usage();
    let cancel = AtomicBool::new(true);
    let refused = inspected.inspect_campaign_archive_with_boundary(plan.manifest_id(), &mut || {
        if cancel.load(Ordering::SeqCst) && page_progress.load(Ordering::SeqCst) >= 64 * 1024 {
            Err(crucible_store::ram::RamStoreError::Canceled)
        } else {
            Ok(())
        }
    });
    let Err(CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::Store(
        StoreError::RamReadBoundary { source: cause },
    ))) = &refused
    else {
        panic!("checked page cancellation must retain its typed read boundary");
    };
    assert!(matches!(
        cause.first_boundary(),
        Some(crucible_store::ram::RamStoreError::Canceled)
    ));
    assert!(page_progress.load(Ordering::SeqCst) >= 64 * 1024);
    assert_eq!(opaque_progress.load(Ordering::SeqCst), 0);
    assert_ne!(resources.usage(), baseline);
    drop(refused);
    assert_eq!(resources.usage(), baseline);

    cancel.store(false, Ordering::SeqCst);
    let inspection = inspected
        .inspect_campaign_archive_with_boundary(plan.manifest_id(), &mut || Ok(()))
        .expect("checked inspection retry");
    assert_eq!(inspection.manifest(), plan.manifest());
    assert!(page_progress.load(Ordering::SeqCst) >= page_length);
    assert!(opaque_progress.load(Ordering::SeqCst) >= LARGE_TRACE_BYTES as u64);
    assert_eq!(resources.usage(), baseline);
}
