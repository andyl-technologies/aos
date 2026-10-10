//! GC retains each lazy reader's authenticated RAM graph without freezing unrelated collection.

use super::*;
use crucible_api::host_operational::{
    HostRamCaptureScope as Scope, HostRamInventoryLimits as Limits,
    HostRamInventoryRegion as RegionDescriptor, HostRamInventoryRegionClass as RegionClass,
    HostRamInventoryTopology as Topology,
};
use crucible_cas::ram::{RamStore, RamStoreLimits};

#[test]
fn live_lazy_ram_reader_and_fork_allow_unrelated_gc_then_release_the_exact_graph() {
    let mut gc_fixture = crate::campaign_gc::ComponentGcOperation::new();
    let gc_operation = gc_fixture.context();

    let directory = tempfile::tempdir().expect("reader storage");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "reader-gc",
        directory.path().join("objects"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let admitted = Arc::new(ComponentRamBackend::new(blobs.clone(), None));
    let ram_original = crucible_cas::owned_decode::DecodeBudget::for_store(
        admitted
            .metadata_resources()
            .expect("original RAM resources"),
    )
    .expect("admitted component RAM namespace");
    let repository = CampaignRepository::new(
        admitted.clone(),
        refs.clone(),
        crucible_campaign::CampaignRamAdmission::Available(ram_original.clone()),
    );
    let ram = RamStore::new(
        admitted,
        crucible_cas::content_store::DurabilityRequirement::new(1, false).expect("durable reader"),
        RamStoreLimits::default(),
    )
    .expect("RAM store");
    let publication = repository
        .ram_retention_authority()
        .acquire()
        .expect("short publication fence");
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 4096 * 5 + 19)
                .expect("RAM descriptor"),
        ],
        Limits::default(),
    )
    .expect("topology");
    let capture_original = ram_original.child().expect("capture operation");
    let source = ram
        .capture(
            topology,
            Scope::Exact,
            &mut |_, index, bytes| {
                bytes.fill((index + 1) as u8);
                Ok(())
            },
            &publication,
            &capture_original,
            &mut || Ok(()),
        )
        .expect("root publication");
    drop(capture_original);
    let fork = source.clone();
    drop(publication);

    let orphan_bytes = b"unrelated reclaimable object".to_vec();
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("unrelated object");
    let physical =
        CampaignGcRawPhysicalStore::new("reader-gc", blobs.as_ref()).expect("physical authority");
    let graph = hash("crucible.test.reader-gc.graph.v1", 0x31);
    let mut ledger = MemoryAssignmentLedger::default();
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        (&[physical], &gc_operation),
    )
    .expect("GC inventory proceeds while lazy source and fork exist");
    assert_eq!(
        prepared.roots().iter().collect::<Vec<_>>(),
        vec![source.object_id()]
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        directory.path().join("first-gc"),
        &prepared,
        &gc_operation,
    )
    .expect("first GC journal");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
        &gc_operation,
    )
    .expect("unrelated object is collectible during lazy reads");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(!blobs.contains(orphan).expect("orphan absent"));

    drop(source);
    let page_original = ram_original.child().expect("page operation");
    let page = ram
        .read_page_with_proof(&fork, "machine.ram", 5, &page_original, &mut || Ok(()))
        .expect("fork still reads actual retained tail page");
    assert_eq!(page.bytes(), vec![6; 19]);
    page.proof()
        .verify(page.bytes(), fork.record(), fork.logical_digest())
        .expect("retained page proof");
    drop(page);
    drop(page_original);
    let root = fork.object_id();
    drop(fork);

    let released = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        (&[physical], &gc_operation),
    )
    .expect("last reader releases only its exact graph");
    assert!(released.roots().iter().next().is_none());
    assert!(
        released
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == root)
    );
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        directory.path().join("released-gc"),
        &released,
        &gc_operation,
    )
    .expect("released GC journal");
    apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
        &gc_operation,
    )
    .expect("released graph reclaimed");
    assert!(!blobs.contains(root).expect("released root absent"));
}

/// Adds finite component decode credit to a real directory reader without
/// certifying installed physical quota or native paging admission.
struct ComponentRamBackend {
    backend: Arc<DirectoryBlobBackend>,
    page_read: Option<Arc<std::sync::atomic::AtomicBool>>,
    resources: Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>,
}

impl ComponentRamBackend {
    fn new(
        backend: Arc<DirectoryBlobBackend>,
        page_read: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
            .expect("finite component RAM decode authority");
        Self {
            backend,
            page_read,
            resources,
        }
    }
}

impl ImmutableBlobBackend for ComponentRamBackend {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.backend.capabilities()
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<crucible_cas::content_store::CheckedPublicationMetadata, StoreError> {
        self.backend.checked_publication_metadata(kind)
    }

    fn metadata_resources(
        &self,
    ) -> Result<Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.resources.clone())
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.backend.admit_object_graph(objects)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.backend.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let handle = self.backend.read(id, range)?;
        if id.kind() == ObjectKind::RamExtent
            && let Some(page_read) = &self.page_read
        {
            page_read.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(handle)
    }

    fn put_if_absent(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<crucible_cas::content_store::PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }

    fn read_with_boundary(
        &self,
        original: &crucible_cas::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        let handle = self
            .backend
            .read_with_boundary(original, id, range, boundary)?;
        if id.kind() == ObjectKind::RamExtent
            && let Some(page_read) = &self.page_read
        {
            page_read.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(handle)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &crucible_cas::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crucible_cas::content_store::PutBatchReceipt, StoreError> {
        self.backend
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }
}

#[test]
fn nested_authenticated_ram_walk_preserves_original_supervision_cause() {
    let mut fixture = crate::campaign_gc::ComponentGcOperation::new();
    let original = fixture.context();
    let directory = tempfile::tempdir().expect("RAM cause storage");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "nested-ram-cause",
        directory.path().join("objects"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let page_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::new(ComponentRamBackend::new(blobs, Some(page_read.clone())));
    let ram_original = crucible_cas::owned_decode::DecodeBudget::for_store(
        observed
            .metadata_resources()
            .expect("original RAM resources"),
    )
    .expect("admitted component RAM namespace");
    let repository = CampaignRepository::new(
        observed.clone(),
        refs.clone(),
        crucible_campaign::CampaignRamAdmission::Available(ram_original.clone()),
    );
    let ram = RamStore::new(
        observed,
        crucible_cas::content_store::DurabilityRequirement::new(1, false).expect("durability"),
        RamStoreLimits::default(),
    )
    .expect("RAM store");
    let publication = repository
        .ram_retention_authority()
        .acquire()
        .expect("real ref publication fence");
    let capture_original = ram_original.child().expect("capture operation");
    let root = ram
        .capture(
            Topology::new(
                vec![
                    RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 8192)
                        .expect("descriptor"),
                ],
                Limits::default(),
            )
            .expect("topology"),
            Scope::Exact,
            &mut |_, index, bytes| {
                bytes.fill(index as u8);
                Ok(())
            },
            &publication,
            &capture_original,
            &mut || Ok(()),
        )
        .expect("real authenticated RAM graph");
    drop(capture_original);
    drop(publication);
    page_read.store(false, std::sync::atomic::Ordering::SeqCst);
    let fence = refs
        .acquire_ref_inventory_fence()
        .expect("actual root inventory fence");
    let mut boundary = || {
        original.check()?;
        if page_read.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::Supervision {
                source: Box::new(super::batch_apply::OriginalBoundaryFailure),
            });
        }
        Ok(())
    };
    let operation =
        CampaignGcOperationContext::new(original.marks(), original.original(), &mut boundary)
            .expect("original admitted mark resources");

    let result = super::super::reachability::Reachability::authenticate(
        &repository,
        [root.object_id()],
        [],
        fence.as_ref(),
        &operation,
    );
    let error = match result {
        Ok(_) => panic!("nested page traversal must preserve original stop"),
        Err(error) => error,
    };

    assert!(page_read.load(std::sync::atomic::Ordering::SeqCst));
    assert!(super::batch_apply::has_original_boundary(&error));
}
