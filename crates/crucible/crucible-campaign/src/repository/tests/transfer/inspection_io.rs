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

#[path = "inspection_io/planner.rs"]
mod planner;

#[path = "inspection_io/expansion.rs"]
mod expansion;
#[path = "inspection_io/replay.rs"]
mod replay;

use replay::assert_checked_archive;
pub(in crate::repository::tests) use replay::assert_checked_mirror_archive;

struct ObservedCheckedBackend {
    child: Arc<dyn ImmutableBlobBackend>,
    progress: BTreeMap<ContentId, Arc<AtomicU64>>,
    ordinary_reads: AtomicU64,
    write_attempts: AtomicU64,
    reject_ordinary: bool,
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
        self.ordinary_reads.fetch_add(1, Ordering::SeqCst);
        if self.reject_ordinary {
            return Err(StoreError::Unsupported {
                capability: "inspection-test-ordinary-contains",
            });
        }
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.ordinary_reads.fetch_add(1, Ordering::SeqCst);
        if self.reject_ordinary {
            return Err(StoreError::Unsupported {
                capability: "inspection-test-ordinary-read",
            });
        }
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
        self.write_attempts.fetch_add(1, Ordering::SeqCst);
        if self.reject_ordinary {
            return Err(StoreError::Unsupported {
                capability: "inspection-test-publication",
            });
        }
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
        ordinary_reads: AtomicU64::new(0),
        write_attempts: AtomicU64::new(0),
        reject_ordinary: false,
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
    let retained_usage = resources.usage();
    assert_eq!(retained_usage.0, baseline.0);
    assert!(retained_usage.1 > baseline.1);

    let retained = inspection.clone();
    assert!(std::ptr::eq(inspection.manifest(), retained.manifest()));
    assert!(std::ptr::eq(inspection.selected(), retained.selected()));
    assert!(std::ptr::eq(
        inspection.retained_objects(),
        retained.retained_objects(),
    ));
    assert_eq!(resources.usage(), retained_usage);
    drop(inspection);
    assert_eq!(resources.usage(), retained_usage);
    drop(retained);
    assert_eq!(resources.usage(), baseline);
}

fn publish_inspection_savepoint_continuation(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    parent: CampaignSnapshotId,
    origin_id: AttemptId,
    checkpoint: ExactCheckpointId,
) -> CampaignSnapshotId {
    const NAME: &str = "checked-closure";
    let running = repository
        .apply_control(
            NAME,
            &command(
                "checked-capture-resume",
                parent,
                CampaignControlAction::Resume,
            ),
        )
        .expect("running capture source");
    let origin = repository.load_attempt(origin_id).expect("capture origin");
    let request = SavepointCaptureRequest::new(
        crate::CampaignCommandId::from_hash(CampaignHash::derive("checked-capture", b"request")),
        running.new_snapshot,
        origin_id,
        lineage.genesis_content(),
        lineage.genesis(),
        origin.stop().clone(),
        "checked archive savepoint ancestry",
    )
    .expect("capture request");
    let captured = repository
        .request_savepoint_capture(NAME, &request)
        .expect("accepted capture");

    let assignment = crate::SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x31; 16]).expect("assignment ID"),
        crate::DaemonEpoch::from_bytes([0x32; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage ID"),
        origin_id,
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("capture limits"),
        ExecutionRetentionIntent::RetainAlways,
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        crate::SubmitAttemptRequest::new_savepoint_capture(
            assignment,
            captured.request,
            captured.configuration,
        )
    })
    .expect("scoped capture assignment");
    let query = crate::GetAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x33; 16]).expect("execution ID"),
    )
    .expect("capture query");
    let status = crate::GetAttemptExecutionResponse::new(
        &query,
        crate::GetAttemptExecutionDisposition::Paused { checkpoint },
    )
    .expect("ready capture status");
    let resolution = SavepointCaptureResolution {
        command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "checked-capture",
            b"ready",
        )),
        expected_snapshot: captured.new_snapshot,
        request: captured.request,
        outcome: SavepointCaptureOutcome::Ready,
    };
    let ready = repository
        .resolve_savepoint_capture(NAME, &resolution, &assignment, &status)
        .expect("ready capture");

    let continuation = Attempt::new(
        AttemptStart::AfterAttempt {
            origin: origin_id,
            reached: lineage.genesis_content(),
        },
        origin.path(),
        StopCondition::ExecutionQuanta(2),
    )
    .expect("savepoint continuation");
    let selection = SavepointContinuationSelection {
        command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "checked-capture",
            b"selection",
        )),
        expected_snapshot: ready.new_snapshot,
        request: captured.request,
        ready: CampaignFact::SavepointCaptureResolved(resolution)
            .id()
            .expect("ready fact ID"),
        continuation: continuation.id().expect("continuation ID"),
    };
    repository
        .select_savepoint_continuation(NAME, &selection, &continuation)
        .expect("selected continuation")
        .new_snapshot
}

#[test]
fn every_checked_archive_policy_uses_only_checked_blob_reads() {
    let (_memory_source, lineage, policy, memory_blobs) = counted_fixture();
    let directory = tempfile::tempdir().expect("durable closure inspection directory");
    let resources = Arc::new(resources::TransferResources::new(128, 512 * 1024 * 1024));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = resources.clone();
    let original = DecodeBudget::for_store(quota.clone()).expect("finite closure authority");
    let blobs = DirectoryBlobBackend::new_with_physical_quota(
        "checked-closure-source",
        directory.path().join("objects"),
        quota,
    )
    .expect("quota-bound closure objects");
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
            .expect("durable source seed");
    }
    let source = CampaignRepository::new(
        blobs.clone(),
        refs.clone(),
        crate::CampaignRamAdmission::Available(original.clone()),
    );
    let (_, admitted, observation) =
        admitted_observation_fixture(&source, &lineage, &policy, "checked-closure");
    let observed = source
        .publish_observation("checked-closure", admitted.new_snapshot, &observation)
        .expect("representative observed source");
    let properties = source
        .load_property_verdict_set(observation.properties())
        .expect("objective observation properties");
    let evaluation =
        crate::evaluate_objectives(&policy, &observation, &properties, BTreeMap::new())
            .expect("representative objective evaluation");
    let evaluated = source
        .publish_objective_evaluation("checked-closure", observed.new_snapshot, &evaluation)
        .expect("representative evaluated source");
    let checkpoint_envelope = ContentEnvelope::new(
        "crucible.test.checked-inspection-exact-checkpoint",
        6,
        BTreeSet::new(),
        b"checked inspection checkpoint".to_vec(),
    )
    .expect("representative exact checkpoint");
    let checkpoint_content = checkpoint_envelope.content_id(ObjectKind::ExactManifest);
    source
        .blobs
        .put_if_absent(
            checkpoint_content,
            &BlobHandle::from_bytes(checkpoint_envelope.canonical_bytes()),
        )
        .expect("publish exact checkpoint");
    let checkpoint = ExactCheckpointId::try_from(checkpoint_content).expect("exact checkpoint ID");
    let continued = publish_inspection_savepoint_continuation(
        &source,
        &lineage,
        evaluated.new_snapshot,
        admitted.attempt,
        checkpoint,
    );
    let fingerprint = CampaignHash::derive("checked-inspection-finding", b"all policies");
    let reproduction = source
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"checked inspection reproduction".to_vec(),
        )
        .expect("representative reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.checked-inspection".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::from([observation.properties().content_id()]),
    )
    .expect("representative finding signature");
    let found = source
        .publish_incomplete_test_finding(
            "checked-closure",
            continued,
            signature,
            observed.observation,
            reproduction,
        )
        .expect("representative finding");
    source
        .apply_pin(
            "checked-closure",
            &PinRequest {
                command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
                    "checked-inspection-exact-pin",
                    b"checked-closure",
                )),
                expected_snapshot: found.new_snapshot,
                change: PinChange::new(
                    observation.child(),
                    Some(PinRetention::Exact),
                    "retain checked inspection checkpoint",
                )
                .expect("exact pin change"),
            },
        )
        .expect("pin representative configuration");
    let head = source
        .head("checked-closure")
        .expect("source campaign head");
    let checked_backend = Arc::new(ObservedCheckedBackend {
        child: blobs,
        progress: BTreeMap::new(),
        ordinary_reads: AtomicU64::new(0),
        write_attempts: AtomicU64::new(0),
        reject_ordinary: true,
    });
    let inspected = CampaignRepository::new(
        checked_backend.clone(),
        refs,
        crate::CampaignRamAdmission::Available(original),
    );
    let policies = [
        CampaignArchivePolicy::Metadata,
        CampaignArchivePolicy::Findings,
        CampaignArchivePolicy::Debug,
        CampaignArchivePolicy::Executable,
        CampaignArchivePolicy::Mirror,
    ];

    for archive_policy in policies {
        let mut checkpoint_resolver = FixedCheckpoint(checkpoint);
        let resolver = matches!(
            archive_policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        )
        .then_some(&mut checkpoint_resolver as &mut dyn CampaignArchiveCheckpointResolver);
        let plan = source
            .plan_campaign_archive(head.snapshot_id(), archive_policy, [], resolver)
            .expect("representative archive policy plan");
        source
            .stage_campaign_archive_metadata(&plan)
            .expect("stage policy inventory");
        let expected = source
            .inspect_campaign_archive(plan.manifest_id())
            .expect("compatibility inspection");
        let baseline = resources.usage();

        let actual = inspected
            .inspect_campaign_archive_with_boundary(plan.manifest_id(), &mut || Ok(()))
            .unwrap_or_else(|error| panic!("{archive_policy:?} checked inspection: {error:?}"));

        assert_eq!(actual, expected, "{archive_policy:?} semantic result");
        assert_eq!(checked_backend.ordinary_reads.load(Ordering::SeqCst), 0);
        drop(actual);
        assert_eq!(
            resources.usage(),
            baseline,
            "{archive_policy:?} custody closes"
        );

        if matches!(
            archive_policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            let finding = inspected
                .inspect_archived_finding_with_boundary(
                    plan.manifest_id(),
                    found.finding,
                    &mut || Ok(()),
                )
                .expect("checked finding handoff");
            assert_eq!(finding.id().expect("finding identity"), found.finding);
            assert_eq!(checked_backend.ordinary_reads.load(Ordering::SeqCst), 0);
            let finding_usage = resources.usage();
            assert_eq!(finding_usage.0, baseline.0);
            assert!(finding_usage.1 > baseline.1);

            let retained = finding.clone();
            assert!(std::ptr::eq(finding.signature(), retained.signature()));
            assert!(std::ptr::eq(finding.exact_pins(), retained.exact_pins()));
            assert_eq!(resources.usage(), finding_usage);
            drop(finding);
            assert_eq!(resources.usage(), finding_usage);
            drop(retained);
            assert_eq!(resources.usage(), baseline);

            let exact = inspected.inspect_archived_exact_finding_with_boundary(
                plan.manifest_id(),
                found.finding,
                &mut || Ok(()),
            );
            assert!(matches!(
                &exact,
                Err(CampaignRepositoryError::InvalidRequest {
                    reason: "archived finding has no retained exact checkpoint",
                })
            ));
            drop(exact);
            assert_eq!(checked_backend.ordinary_reads.load(Ordering::SeqCst), 0);
            assert_eq!(resources.usage(), baseline);
        }
    }

    drop(inspected);
    drop(source);
    drop(checked_backend);
    assert_eq!(resources.usage(), (0, 0));
}
