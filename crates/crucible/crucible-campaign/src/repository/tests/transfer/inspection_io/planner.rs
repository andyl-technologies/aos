//! Checked archive replay of retained planner request semantics.

use super::*;
use crate::object_profile::profile_authenticated_campaign_envelope;
use crate::{ArchiveObjectEntry, CampaignArchiveInventoryPageId, CampaignArchiveManifestId};
use crucible_store::content_store::{
    ObjectProfile, Reconstructibility, RetentionRole, SensitivityClass,
};

fn archive_pages(
    disposition: ArchiveInventoryDisposition,
    entries: &[ArchiveObjectEntry],
) -> (Vec<CampaignArchiveInventoryPageId>, Vec<ObjectEnvelope>) {
    let mut ids = Vec::new();
    let mut envelopes = Vec::new();
    for (ordinal, chunk) in entries
        .chunks(crate::MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES)
        .enumerate()
    {
        let page = CampaignArchiveInventoryPage::new(
            disposition,
            u32::try_from(ordinal).expect("bounded archive page ordinal"),
            chunk.to_vec(),
        )
        .expect("bounded archive page");
        let envelope =
            ObjectEnvelope::for_archive_inventory_page(&page).expect("archive inventory envelope");
        ids.push(page.id().expect("archive inventory page ID"));
        envelopes.push(envelope);
    }
    (ids, envelopes)
}

fn replacement_entry(id: ContentId, envelope: &ObjectEnvelope) -> ArchiveObjectEntry {
    let length =
        u64::try_from(envelope.canonical_bytes().len()).expect("campaign envelope logical length");
    let profile = profile_authenticated_campaign_envelope(id, envelope, length)
        .expect("authenticated campaign profile");
    ArchiveObjectEntry::from_profile(id, profile)
}

#[test]
fn archive_inventory_digest_preserves_finite_original_refusal_custody() {
    let resources = Arc::new(resources::TransferResources::new(8, 64 * 1024));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = resources.clone();
    let original = DecodeBudget::for_store(quota).expect("finite inventory authority");
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"inventory-digest-refusal");
    let entry = ArchiveObjectEntry::from_profile(
        id,
        ObjectProfile::new(
            ObjectKind::Trace,
            1,
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        ),
    );
    let entries = vec![entry; 4_096];

    let refusal = {
        let _scope = original.enter();
        crate::archive::inventory_digest_admitted(&entries)
    };
    assert!(matches!(
        &refusal,
        Err(crate::CampaignCodecError::DecodeAdmission(_))
    ));

    drop(original);
    assert_ne!(resources.usage(), (0, 0));
    drop(refusal);
    assert_eq!(resources.usage(), (0, 0));
}

#[test]
fn checked_archive_rejects_forged_retained_planner_derived_inputs_without_ordinary_reads() {
    let (_memory_source, lineage, policy, memory_blobs) = counted_fixture();
    let directory = tempfile::tempdir().expect("durable planner archive directory");
    let resources = Arc::new(resources::TransferResources::new(128, 512 * 1024 * 1024));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = resources.clone();
    let original = DecodeBudget::for_store(quota.clone()).expect("finite planner authority");
    let blobs = DirectoryBlobBackend::new_with_physical_quota(
        "checked-planner-archive",
        directory.path().join("objects"),
        quota,
    )
    .expect("quota-bound planner objects");
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));

    let mut seed_ids = Vec::new();
    memory_blobs
        .acquire_inventory_fence()
        .expect("planner source inventory")
        .visit_inventory(&mut |record| {
            seed_ids.push(record.id());
            Ok(())
        })
        .expect("planner source identities");
    for id in seed_ids {
        let bytes = memory_blobs.read(id, None).expect("planner source bytes");
        blobs
            .put_if_absent(id, &bytes)
            .expect("durable planner source");
    }
    let source = CampaignRepository::new(
        blobs.clone(),
        refs.clone(),
        crate::CampaignRamAdmission::Available(original.clone()),
    );

    const NAME: &str = "checked-retained-planner";
    let created = source
        .create_funded(NAME, &lineage, &policy, &BTreeMap::new())
        .expect("create planner campaign");
    let branch = branch_request(
        &source,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checked-retained-planner-branch",
    );
    let requested = source
        .submit_known_branch_request(NAME, created.snapshot_id(), &branch)
        .expect("submit planner branch");
    let basis = source
        .publish_canonical_frontier_planner_basis()
        .expect("publish canonical planner basis");
    let invocation = source
        .prepare_planner_invocation(
            NAME,
            requested.new_snapshot,
            basis.engine(),
            basis.artifact(),
            basis.initial_state(),
            None,
            1,
            PlanningBudget::new(1, 1, 8, 8_192, 100).expect("planner budget"),
        )
        .expect("prepare planner invocation");
    let valid = source
        .build_planner_request(
            requested.new_snapshot,
            invocation.id().expect("planner invocation ID"),
        )
        .expect("build valid retained request");
    for id in valid.input_bundle().object_ids() {
        let envelope = valid
            .input_bundle()
            .object(id)
            .expect("decode valid bundle object")
            .expect("valid bundle object");
        assert_eq!(envelope.content_id(), id);
        source
            .put_envelope(envelope)
            .expect("publish retained planner bundle object");
    }
    let valid_id = source
        .put_planner_request(&valid)
        .expect("publish valid retained request");
    let original_offer = valid
        .input_bundle()
        .candidate_inputs(&valid)
        .expect("valid candidate inputs")
        .into_values()
        .next()
        .and_then(|input| input.offer)
        .expect("ready planner offer");
    let forged_offer = Proposal::new(
        original_offer.branch_point(),
        original_offer.request(),
        original_offer.domain(),
        original_offer.value().clone(),
        original_offer.policy(),
        original_offer.planner_invocation(),
        original_offer.ordinal() + 1,
        original_offer.guidance_basis(),
    )
    .expect("structurally valid forged offer");

    let mut replacements = BTreeMap::new();
    let mut forged_objects = Vec::new();
    for id in valid.input_bundle().object_ids() {
        let object = valid
            .input_bundle()
            .object(id)
            .expect("decode valid bundle object")
            .expect("valid bundle object");
        let forged = match object.record_kind() {
            crate::CampaignRecordKind::Proposal => ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::Proposal,
                forged_offer.schema_version(),
                crate::object::content_children(forged_offer.content_children())
                    .expect("forged offer children"),
                forged_offer.canonical_bytes(),
            )
            .expect("forged offer envelope"),
            crate::CampaignRecordKind::PlannerCandidateBudget => {
                let budget = crate::PlannerCandidateBudget::from_canonical_bytes(object.body())
                    .expect("valid candidate budget");
                let forged_budget = crate::PlannerCandidateBudget::new(
                    &forged_offer,
                    budget.remaining_proposals(),
                    budget.remaining_attempts(),
                    budget.requires_new_attempt(),
                    budget.remaining_request_attempts(),
                )
                .expect("forged candidate budget");
                ObjectEnvelope::for_candidate_budget(&forged_budget)
                    .expect("forged candidate budget envelope")
            }
            _ => object,
        };
        replacements.insert(id, forged.content_id());
        source
            .put_envelope(forged.clone())
            .expect("publish forged bundle object");
        forged_objects.push(forged);
    }
    let forged = PlannerRequest::new(
        valid.expected_snapshot(),
        valid.invocation().clone(),
        valid.engine().clone(),
        valid.policy_artifact().clone(),
        valid.policy().clone(),
        valid.planner_state().clone(),
        *valid.input_view(),
        CampaignPlanningBundle::new(forged_objects).expect("forged planning bundle"),
    )
    .expect("structurally valid forged retained request");
    let forged_id = source
        .put_planner_request(&forged)
        .expect("publish forged retained request");
    replacements.insert(valid_id, forged_id);

    let valid_plan = source
        .plan_campaign_archive(
            requested.new_snapshot,
            CampaignArchivePolicy::Mirror,
            [valid_id],
            None,
        )
        .expect("valid retained-request archive plan");
    source
        .stage_campaign_archive_metadata(&valid_plan)
        .expect("stage valid retained-request archive");
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
    let baseline = resources.usage();
    let expected = source
        .inspect_campaign_archive(valid_plan.manifest_id())
        .expect("ordinary valid retained-request inspection");
    let actual = inspected
        .inspect_campaign_archive_with_boundary(valid_plan.manifest_id(), &mut || Ok(()))
        .expect("checked valid retained-request inspection");
    assert_eq!(actual, expected);
    assert_eq!(checked_backend.ordinary_reads.load(Ordering::SeqCst), 0);
    drop(actual);
    drop(expected);
    assert_eq!(resources.usage(), baseline);

    let mut selected = valid_plan
        .selected()
        .iter()
        .map(|entry| {
            let replacement = replacements.get(&entry.id()).copied().unwrap_or(entry.id());
            if replacement == entry.id() {
                *entry
            } else {
                let envelope = source
                    .read_envelope(replacement)
                    .expect("replacement campaign envelope");
                replacement_entry(replacement, &envelope)
            }
        })
        .collect::<Vec<_>>();
    selected.sort_unstable();
    let omitted = valid_plan.omitted().to_vec();
    let (selected_pages, mut page_envelopes) =
        archive_pages(ArchiveInventoryDisposition::Selected, &selected);
    let (omitted_pages, omitted_envelopes) =
        archive_pages(ArchiveInventoryDisposition::Omitted, &omitted);
    page_envelopes.extend(omitted_envelopes);
    for envelope in page_envelopes {
        source
            .put_envelope(envelope)
            .expect("publish forged archive page");
    }
    let manifest = CampaignArchiveManifest::new(crate::archive::CampaignArchiveManifestBasis {
        source_snapshot: requested.new_snapshot,
        policy: CampaignArchivePolicy::Mirror,
        checkpoint_selections: Vec::new(),
        retained_roots: vec![forged_id],
        ram_roots: Vec::new(),
        selected_pages,
        omitted_pages,
        selected: &selected,
        omitted: &omitted,
    })
    .expect("forged retained-request manifest");
    let manifest_envelope =
        ObjectEnvelope::for_archive_manifest(&manifest).expect("archive manifest envelope");
    let manifest_id = CampaignArchiveManifestId::from_content_id(manifest_envelope.content_id())
        .expect("archive manifest ID");
    source
        .put_envelope(manifest_envelope)
        .expect("publish forged archive manifest");

    let ordinary_rejected = source.inspect_campaign_archive(manifest_id);
    assert!(matches!(
        &ordinary_rejected,
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-candidate-projection-mismatch",
        })
    ));
    drop(ordinary_rejected);

    let rejected = inspected.inspect_campaign_archive_with_boundary(manifest_id, &mut || Ok(()));
    assert!(matches!(
        &rejected,
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-candidate-projection-mismatch",
        })
    ));
    assert_eq!(checked_backend.ordinary_reads.load(Ordering::SeqCst), 0);
    drop(rejected);
    assert_eq!(resources.usage(), baseline);

    drop(inspected);
    drop(source);
    drop(checked_backend);
    assert_eq!(resources.usage(), (0, 0));
}
