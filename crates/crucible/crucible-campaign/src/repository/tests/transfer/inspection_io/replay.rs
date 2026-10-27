//! Real retained-planner replay through checked directory-backed archives.

use super::*;

/// Authenticates a complete retained request without ordinary backend dispatch.
pub(in crate::repository::tests) fn assert_checked_mirror_archive(
    source: &CampaignRepository,
    snapshot: CampaignSnapshotId,
    request_id: ContentId,
) {
    let envelope = source
        .require_record_kind(
            request_id,
            crate::CampaignRecordKind::RetainedPlannerRequest,
        )
        .expect("retained planner request envelope");
    let request = PlannerRequest::from_canonical_bytes(envelope.body())
        .expect("canonical retained planner request");
    assert_eq!(request.id().expect("request ID").content_id(), request_id);

    // Retaining the request also retains its embedded inputs as graph children.
    // Materialize them before the independent complete-graph validation below.
    for id in request.input_bundle().object_ids() {
        let envelope = request
            .input_bundle()
            .object(id)
            .expect("canonical retained input")
            .expect("present retained input");
        assert_eq!(envelope.content_id(), id);
        source
            .put_envelope(envelope)
            .expect("materialize retained input child");
    }
    assert_eq!(
        source
            .read_planner_request(request_id)
            .expect("valid complete retained planner request"),
        request
    );
    assert_checked_archive(source, snapshot, [request_id]);
}

/// Authenticates retained graph roots without ordinary dispatch or publication.
pub(super) fn assert_checked_archive(
    source: &CampaignRepository,
    snapshot: CampaignSnapshotId,
    retained_roots: impl IntoIterator<Item = ContentId>,
) {
    let plan = source
        .plan_campaign_archive(
            snapshot,
            CampaignArchivePolicy::Mirror,
            retained_roots,
            None,
        )
        .expect("complete retained planner archive");
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("stage retained planner archive");
    let expected = source
        .inspect_campaign_archive(plan.manifest_id())
        .expect("ordinary retained planner archive");

    let directory = tempfile::tempdir().expect("checked replay directory");
    let resources = Arc::new(resources::TransferResources::new(128, 512 * 1024 * 1024));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = resources.clone();
    let original = DecodeBudget::for_store(quota.clone()).expect("finite replay authority");
    let blobs = DirectoryBlobBackend::new_with_physical_quota(
        "checked-planner-replay",
        directory.path().join("objects"),
        quota,
    )
    .expect("quota-bound replay objects");
    for id in expected.retained_objects() {
        let bytes = source.blobs.read(*id, None).expect("staged archive bytes");
        blobs
            .put_if_absent(*id, &bytes)
            .expect("durable replay object");
    }
    let backend = Arc::new(ObservedCheckedBackend {
        child: blobs,
        progress: BTreeMap::new(),
        ordinary_reads: AtomicU64::new(0),
        write_attempts: AtomicU64::new(0),
        reject_ordinary: true,
    });
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let inspected = CampaignRepository::new(
        backend.clone(),
        refs,
        crate::CampaignRamAdmission::Available(original.clone()),
    );
    let baseline = resources.usage();

    let actual = inspected
        .inspect_campaign_archive_with_boundary(plan.manifest_id(), &mut || Ok(()))
        .expect("checked retained planner replay");

    assert_eq!(actual, expected);
    assert_eq!(backend.ordinary_reads.load(Ordering::SeqCst), 0);
    assert_eq!(backend.write_attempts.load(Ordering::SeqCst), 0);
    let retained_usage = resources.usage();
    assert!(retained_usage.1 > baseline.1);

    let shared = actual.clone();
    drop(actual);
    assert_eq!(resources.usage(), retained_usage);
    drop(shared);
    assert_eq!(resources.usage(), baseline);

    drop(inspected);
    drop(backend);
    drop(original);
    assert_eq!(resources.usage(), (0, 0));
}
