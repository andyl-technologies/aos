//! GC retains each lazy reader's authenticated RAM graph without freezing unrelated collection.

use super::*;
use crucible_campaign::{CampaignExecutorStore, FindingExactCheckpointAuthenticator};
use crucible_control_api::host_operational::{
    HostRamCaptureScope as Scope, HostRamInventoryLimits as Limits,
    HostRamInventoryRegion as RegionDescriptor, HostRamInventoryRegionClass as RegionClass,
    HostRamInventoryTopology as Topology,
};
use crucible_store::ram::{RamStore, RamStoreLimits};

use crate::ExactCheckpointStore;
use crate::automatic_finding_runner::{
    CampaignRunFindingExactRetentionSource, FindingExactCandidateInventoryError,
    FindingExactRetentionSource, FindingTerminalCheckpointIdentity,
};

#[test]
fn failed_post_capture_handoff_withdraws_candidate_before_real_gc() {
    let _fixture_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let mut gc_fixture = crate::campaign_gc::ComponentGcOperation::new();
    let gc_operation = gc_fixture.context();
    let directory = tempfile::tempdir().expect("failed capture retention storage");
    let fixture_directory = tempfile::tempdir().expect("production checkpoint fixture");
    let fixture =
        crate::build_exact_ram_production_checkpoint_codec_fixture(fixture_directory.path())
            .expect("production checkpoint fixture");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "failed-capture-retention-gc",
        directory.path().join("objects"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let admitted = Arc::new(ComponentRamBackend::new(blobs.clone(), None));
    let original = crucible_store::owned_decode::DecodeBudget::for_store(
        admitted
            .metadata_resources()
            .expect("failed capture metadata resources"),
    )
    .expect("failed capture original");
    let repository = Arc::new(CampaignRepository::new(
        admitted.clone(),
        refs.clone(),
        crucible_campaign::CampaignRamAdmission::Available(original.clone()),
    ));
    let scenario = fixture.source().scenario_def();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let encoded_scenario = crate::encode_crucible_scenario_artifact(fixture.source())
        .expect("encode scenario artifact");
    let scenario_artifact = repository
        .publish_scenario_artifact(
            scenario_id,
            encoded_scenario.payload_schema(),
            encoded_scenario.payload().to_vec(),
        )
        .expect("publish scenario artifact");
    let configuration =
        ConfigurationId::from_hash(CampaignHash::from_bytes(fixture.configuration().id().bytes));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(
            admitted.clone(),
            u64::MAX,
            repository.ram_retention_authority(),
        )
        .expect("checkpoint store")
        .with_ram_root_resources(
            crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
                .expect("checkpoint root resources"),
        ),
    );
    let prepared = checkpoints
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare production checkpoint");
    let checkpoint = checkpoints
        .publish_production_closure(&prepared)
        .expect("publish production checkpoint")
        .root();
    let owner = hash("crucible.test.failed-capture-retention-owner.v1", 0x51);
    let store = CampaignExecutorStore::new(repository.clone());
    let source =
        CampaignRunFindingExactRetentionSource::new(store.clone(), checkpoints.clone(), owner)
            .expect("exact candidate source");
    let authenticated = source
        .authenticate_finding_exact_checkpoint(
            checkpoint,
            scenario_id,
            scenario_artifact,
            configuration,
            crate::automatic_finding_runner::MAX_FINDING_EXACT_METADATA_BYTES,
        )
        .expect("authenticate captured checkpoint");
    let context = crate::AttemptExecutionContext::new(
        AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, 4)
            .expect("attempt limits"),
        ExecutionRetentionIntent::RetainOnFailure,
        crate::ExecutionCancellation::default(),
        crate::ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    source
        .retain_terminal_checkpoint(
            &crate::CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone()),
            &context,
            FindingTerminalCheckpointIdentity {
                scenario: scenario_id,
                scenario_artifact,
                configuration,
                event_count: authenticated.event_count(),
            },
        )
        .expect("capture candidate before runner failure");
    assert_eq!(
        source
            .candidate_checkpoints(configuration, 1)
            .expect("captured candidate inventory"),
        vec![checkpoint],
    );

    let foreign_repository = CampaignRepository::new(
        admitted,
        Arc::new(MemoryRefBackend::new()),
        crucible_campaign::CampaignRamAdmission::Available(original),
    );
    let foreign_guard = foreign_repository
        .acquire_gc_exclusion_guard()
        .expect("foreign handoff guard");
    assert!(source.retain_execution_catalog(&foreign_guard).is_err());
    source.abandon_unretained_candidates();
    assert_eq!(
        source.candidate_checkpoints(configuration, 1),
        Err(FindingExactCandidateInventoryError::LimitExceeded),
        "a failed post-capture handoff must withdraw the unprotected candidate",
    );
    drop(foreign_guard);
    drop(source);

    let physical = CampaignGcRawPhysicalStore::new("failed-capture-retention-gc", blobs.as_ref())
        .expect("physical GC authority");
    let graph = hash("crucible.test.failed-capture-retention-graph.v1", 0x52);
    let mut ledger = MemoryAssignmentLedger::default();
    let prepared_gc = plan_single_host_campaign_gc(
        repository.as_ref(),
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        (&[physical], &gc_operation),
    )
    .expect("plan GC after failed capture handoff");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        directory.path().join("failed-capture-gc"),
        &prepared_gc,
        &gc_operation,
    )
    .expect("failed capture GC journal");
    apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(repository.as_ref(), refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
        &gc_operation,
    )
    .expect("apply GC after failed capture handoff");
    assert!(
        !blobs
            .contains(checkpoint.content_id())
            .expect("captured root inventory"),
        "withdrawn post-capture root must remain an ordinary collectible orphan",
    );
}

#[test]
fn executor_exact_result_handoff_survives_restart_and_real_gc_until_terminal_retirement() {
    let _fixture_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let mut gc_fixture = crate::campaign_gc::ComponentGcOperation::new();
    let gc_operation = gc_fixture.context();
    let directory = tempfile::tempdir().expect("executor exact-retention storage");
    let fixture_directory = tempfile::tempdir().expect("production checkpoint fixture");
    let fixture =
        crate::build_exact_ram_production_checkpoint_codec_fixture(fixture_directory.path())
            .expect("production checkpoint fixture");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "executor-exact-retention-gc",
        directory.path().join("objects"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let admitted = Arc::new(ComponentRamBackend::new(blobs.clone(), None));
    let original = crucible_store::owned_decode::DecodeBudget::for_store(
        admitted
            .metadata_resources()
            .expect("exact-retention metadata resources"),
    )
    .expect("exact-retention original");
    let repository = CampaignRepository::new(
        admitted.clone(),
        refs.clone(),
        crucible_campaign::CampaignRamAdmission::Available(original.clone()),
    );
    let checkpoints = ExactCheckpointStore::new(
        admitted.clone(),
        u64::MAX,
        repository.ram_retention_authority(),
    )
    .expect("checkpoint store")
    .with_ram_root_resources(
        crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
            .expect("checkpoint root resources"),
    );
    let prepared = checkpoints
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare production checkpoint");
    let root = checkpoints
        .publish_production_closure(&prepared)
        .expect("publish production checkpoint")
        .root();
    let root_content = root.content_id();
    let ram_descendant = admitted
        .published_ram_descendant()
        .expect("production checkpoint publishes a RAM descendant");
    let configuration =
        ConfigurationId::from_hash(CampaignHash::from_bytes(fixture.configuration().id().bytes));
    let owner = hash("crucible.test.executor-exact-retention-owner.v1", 0x42);
    repository
        .replace_executor_exact_catalog(
            owner,
            crucible_campaign::ExecutorExactRetentionCatalog::new(
                vec![(root, configuration)],
                BTreeSet::new(),
                false,
            )
            .expect("bounded owner catalog"),
        )
        .expect("install catalog predecessor");

    let execution = ExecutionId::from_bytes([0x43; 16]).expect("result execution");
    let handoff = repository
        .acquire_gc_exclusion_guard()
        .expect("result handoff guard");
    repository
        .retain_executor_exact_result_under(
            &handoff,
            owner,
            crucible_campaign::ExecutorExactRetentionCatalog::default(),
            execution,
            &BTreeSet::from([root]),
        )
        .expect("install successor before catalog eviction");
    drop(handoff);

    let orphan_bytes = b"executor exact unrelated orphan".to_vec();
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("publish unrelated orphan");
    let physical = CampaignGcRawPhysicalStore::new("executor-exact-retention-gc", blobs.as_ref())
        .expect("physical GC authority");
    let graph = hash("crucible.test.executor-exact-retention-graph.v1", 0x44);
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
    .expect("plan GC through exact-result successor");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        directory.path().join("retained-gc"),
        &prepared,
        &gc_operation,
    )
    .expect("retained GC journal");
    apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
        &gc_operation,
    )
    .expect("apply GC through exact-result successor");
    assert!(
        blobs
            .contains(root_content)
            .expect("retained root inventory")
    );
    assert!(
        blobs
            .contains(ram_descendant)
            .expect("retained RAM descendant inventory")
    );
    assert!(!blobs.contains(orphan).expect("orphan inventory"));

    drop(repository);
    let restarted = CampaignRepository::new(
        admitted,
        refs.clone(),
        crucible_campaign::CampaignRamAdmission::Available(original),
    );
    assert_eq!(
        restarted
            .load_executor_exact_retention()
            .expect("reopen exact-result successor")
            .result(execution),
        Some(&BTreeSet::from([root]))
    );
    let ledger_root = directory.path().join("terminal-ledger");
    let lineage = CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"lineage").encode()
    ))
    .expect("terminal lineage");
    let attempt = AttemptId::parse(&format!(
        "crucible.campaign.attempt@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 9, b"attempt").encode()
    ))
    .expect("terminal attempt");
    let request = pending_finding_request(lineage, attempt);
    let key = AttemptExecutionKey::for_request(&request);
    let terminal = AttemptRuntimeState::Canceled {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
    };
    {
        let mut terminal_ledger =
            DirectoryAssignmentLedger::open(&ledger_root).expect("terminal ledger");
        assert_eq!(
            terminal_ledger
                .compare_exchange_attempt(key, None, Some(terminal))
                .expect("publish durable terminal successor"),
            AttemptStateCas::Advanced,
        );
    }
    let terminal_ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen terminal ledger");
    assert_eq!(
        terminal_ledger
            .load_attempt(key)
            .expect("authenticate terminal successor after restart"),
        Some(terminal),
    );
    restarted
        .retire_executor_exact_result(execution)
        .expect("retire after authenticated terminal successor");

    let released = plan_single_host_campaign_gc(
        &restarted,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        (&[physical], &gc_operation),
    )
    .expect("plan GC after terminal retirement");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        directory.path().join("released-gc"),
        &released,
        &gc_operation,
    )
    .expect("released GC journal");
    apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&restarted, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
        &gc_operation,
    )
    .expect("apply GC after terminal retirement");
    assert!(
        !blobs
            .contains(root_content)
            .expect("released root inventory")
    );
    assert!(
        !blobs
            .contains(ram_descendant)
            .expect("released RAM descendant inventory")
    );
}

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
    let ram_original = crucible_store::owned_decode::DecodeBudget::for_store(
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
        crucible_store::content_store::DurabilityRequirement::new(1, false)
            .expect("durable reader"),
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
    published: std::sync::Mutex<BTreeSet<ContentId>>,
    resources: Arc<dyn crucible_store::content_store::StorePhysicalQuotaGuard>,
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
            published: std::sync::Mutex::new(BTreeSet::new()),
            resources,
        }
    }

    fn published_ram_descendant(&self) -> Option<ContentId> {
        self.published
            .lock()
            .expect("component publication inventory")
            .iter()
            .copied()
            .find(|id| matches!(id.kind(), ObjectKind::RamExtent | ObjectKind::RamTree))
    }
}

impl ImmutableBlobBackend for ComponentRamBackend {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> crucible_store::content_store::BackendCapabilities {
        self.backend.capabilities()
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<crucible_store::content_store::CheckedPublicationMetadata, StoreError> {
        self.backend.checked_publication_metadata(kind)
    }

    fn metadata_resources(
        &self,
    ) -> Result<Arc<dyn crucible_store::content_store::StorePhysicalQuotaGuard>, StoreError> {
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
        range: Option<crucible_store::content_store::ByteRange>,
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
    ) -> Result<crucible_store::content_store::PutReceipt, StoreError> {
        let receipt = self.backend.put_if_absent(id, source)?;
        self.published
            .lock()
            .expect("component publication inventory")
            .insert(id);
        Ok(receipt)
    }

    fn read_with_boundary(
        &self,
        original: &crucible_store::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<crucible_store::content_store::ByteRange>,
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
        original: &crucible_store::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crucible_store::content_store::PutBatchReceipt, StoreError> {
        let receipt = self
            .backend
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        self.published
            .lock()
            .expect("component publication inventory")
            .extend(objects.iter().map(|(id, _)| *id));
        Ok(receipt)
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
    let ram_original = crucible_store::owned_decode::DecodeBudget::for_store(
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
        crucible_store::content_store::DurabilityRequirement::new(1, false).expect("durability"),
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
