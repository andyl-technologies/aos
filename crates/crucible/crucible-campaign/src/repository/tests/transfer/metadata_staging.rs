//! Checked source archive-metadata staging regressions.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_store::content_envelope::{ContentChild, ContentEnvelope};
use crucible_store::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, CheckedPublicationMetadata, ContentId,
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, ObjectKind, PutBatchReceipt,
    PutReceipt, StoreError, StorePhysicalQuotaGuard,
};
use crucible_store::owned_decode::DecodeBudget;

use super::*;

fn direct_staging_file_at_least(directory: &Path, minimum: u64) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".staging"))
            && entry
                .metadata()
                .is_ok_and(|metadata| metadata.len() >= minimum)
    })
}

fn object_parent(root: &Path, id: ContentId) -> PathBuf {
    root.join("objects").join(format!("{:02x}", id.digest()[0]))
}

struct CheckedOnlyMetadataBackend {
    child: Arc<dyn ImmutableBlobBackend>,
    ordinary_reads: AtomicU64,
}

impl ImmutableBlobBackend for CheckedOnlyMetadataBackend {
    fn name(&self) -> &str {
        self.child.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.child.metadata_resources()
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        self.child.checked_publication_metadata(kind)
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        self.ordinary_reads.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unsupported {
            capability: "metadata-staging-test-ordinary-contains",
        })
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.ordinary_reads.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unsupported {
            capability: "metadata-staging-test-ordinary-read",
        })
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.child.read_with_boundary(original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.child.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.child
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }
}

#[test]
fn large_archive_metadata_staging_cancels_privately_and_retries_idempotently() {
    let (_memory_source, lineage, policy, memory_blobs) = counted_fixture();
    let directory = tempfile::tempdir().expect("durable source directory");
    let object_root = directory.path().join("objects");
    let resources: Arc<dyn crucible_store::content_store::StorePhysicalQuotaGuard> =
        Arc::new(resources::TransferResources::new(128, 512 * 1024 * 1024));
    let original = crucible_store::owned_decode::DecodeBudget::for_store(resources.clone())
        .expect("finite source operation authority");
    let blobs = DirectoryBlobBackend::new_with_physical_quota(
        "metadata-staging-source",
        &object_root,
        resources,
    )
    .expect("quota-bound source objects");
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
        .create(
            "metadata-staging-source",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
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
    let root = ContentEnvelope::new(
        "crucible.test.archive-staging-root",
        6,
        children,
        b"large archive metadata staging root".to_vec(),
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
        .expect("large metadata archive plan");
    let (page_id, page_bytes) = plan
        .page_envelopes
        .iter()
        .map(|envelope| (envelope.content_id(), envelope.canonical_bytes()))
        .max_by_key(|(_, bytes)| bytes.len())
        .expect("at least one archive inventory page");
    assert!(page_bytes.len() > 64 * 1024);
    let page_parent = object_parent(&object_root, page_id);

    let checked_blobs = Arc::new(CheckedOnlyMetadataBackend {
        child: blobs.clone(),
        ordinary_reads: AtomicU64::new(0),
    });
    let checked_source = CampaignRepository::new(
        checked_blobs.clone(),
        refs,
        crate::CampaignRamAdmission::Available(original),
    );

    let _gc = checked_source
        .acquire_gc_exclusion_guard()
        .expect("source publication guard");
    let mut observed_private_page = false;
    let canceled = checked_source.stage_campaign_archive_metadata_with_boundary(&plan, &mut || {
        if direct_staging_file_at_least(&page_parent, 64 * 1024) {
            observed_private_page = true;
            Err(crucible_store::ram::RamStoreError::Canceled)
        } else {
            Ok(())
        }
    });
    let Err(CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::Boundary(cause))) =
        &canceled
    else {
        panic!("mid-page cancellation must retain its typed private-staging outcome");
    };
    assert!(observed_private_page);
    assert!(matches!(
        cause.first_boundary(),
        Some(crucible_store::ram::RamStoreError::Canceled)
    ));
    let crucible_store::ram::RamStoreError::Store(
        crucible_store::content_store::StoreError::DirectoryScope { source: scope },
    ) = cause.storage_failure()
    else {
        panic!("directory cleanup outcome stays attached to metadata cancellation");
    };
    assert_eq!(scope.outcome().published_objects, 0);
    assert!(scope.cleanup_failure().is_none());
    drop(canceled);
    assert!(matches!(
        blobs.read(page_id, None),
        Err(crucible_store::content_store::StoreError::NotFound { .. })
    ));
    assert!(matches!(
        blobs.read(plan.manifest_id().content_id(), None),
        Err(crucible_store::content_store::StoreError::NotFound { .. })
    ));
    assert!(!direct_staging_file_at_least(&page_parent, 0));

    checked_source
        .stage_campaign_archive_metadata_with_boundary(&plan, &mut || Ok(()))
        .expect("successful checked metadata staging");
    checked_source
        .stage_campaign_archive_metadata_with_boundary(&plan, &mut || Ok(()))
        .expect("idempotent checked metadata staging");
    assert_eq!(checked_blobs.ordinary_reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        blobs
            .read(page_id, None)
            .expect("published inventory page")
            .read_all((page_bytes.len() + 1) as u64)
            .expect("authenticated inventory page"),
        page_bytes
    );
    let manifest_bytes = plan.manifest_envelope.canonical_bytes();
    assert_eq!(
        blobs
            .read(plan.manifest_id().content_id(), None)
            .expect("published archive manifest")
            .read_all((manifest_bytes.len() + 1) as u64)
            .expect("authenticated archive manifest"),
        manifest_bytes
    );
    let inspection = source
        .inspect_campaign_archive(plan.manifest_id())
        .expect("staged archive inspection");
    assert_eq!(inspection.manifest(), plan.manifest());
    assert!(!direct_staging_file_at_least(&page_parent, 0));
}
