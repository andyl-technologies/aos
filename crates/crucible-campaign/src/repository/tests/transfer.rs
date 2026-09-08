//! Archive selection, partial-boundary, and transfer regressions.

use std::sync::Arc;

use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement, ObjectKind,
};

use super::*;
use crate::{
    ArchiveInventoryDisposition, CampaignArchiveCheckpointSelection, CampaignArchiveInventoryPage,
    CampaignArchiveManifest, CampaignArchivePolicy, CampaignFactId, ExactCheckpointId,
    ObjectEnvelope,
};

#[test]
fn archive_manifest_rejects_duplicate_configuration_pin_pairs() {
    let (_repository, lineage, _policy) = fixture();
    let configuration = lineage.genesis();
    let pin_fact =
        CampaignFactId::from_content_id(ContentId::for_bytes(ObjectKind::CampaignFact, 2, b"pin"))
            .expect("pin fact");
    let first = ExactCheckpointId::from_content_id(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"first checkpoint",
    ))
    .expect("first checkpoint");
    let second = ExactCheckpointId::from_content_id(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"second checkpoint",
    ))
    .expect("second checkpoint");
    let mut selections = vec![
        CampaignArchiveCheckpointSelection::new(configuration, pin_fact, first),
        CampaignArchiveCheckpointSelection::new(configuration, pin_fact, second),
    ];
    selections.sort();
    let snapshot = crate::CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        2,
        b"snapshot",
    ))
    .expect("snapshot");

    assert!(matches!(
        CampaignArchiveManifest::new(
            snapshot,
            CampaignArchivePolicy::Executable,
            selections,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &[],
            &[],
        ),
        Err(crate::CampaignCodecError::InvalidValue {
            reason: "archive checkpoint selection pair is duplicated"
        })
    ));
}

#[test]
fn metadata_archive_inspects_without_becoming_a_campaign_head() {
    let (source, lineage, policy) = fixture();
    let head = source
        .create("source", &lineage, &policy, &BTreeMap::new())
        .expect("create source campaign");
    let plan = source
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Metadata,
            [],
            None,
        )
        .expect("plan metadata archive");
    assert!(!plan.omitted().is_empty());

    let temporary = tempfile::tempdir().expect("temporary destination");
    let destination = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "archive-destination",
            temporary.path().join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs"))),
    );
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("stage source archive metadata");
    source
        .transfer_campaign_archive_objects(
            &destination,
            &plan,
            DurabilityRequirement::new(1, false).expect("destination durability"),
        )
        .expect("transfer partial archive");
    destination
        .publish_campaign_archive("metadata", None, &plan)
        .expect("publish archive ref");

    let inspection = destination
        .inspect_campaign_archive_ref("metadata")
        .expect("inspect archive boundary");
    assert_eq!(inspection.manifest_id(), plan.manifest_id());
    assert!(!inspection.omitted_inventory_verified());
    assert!(
        destination
            .publish_transferred_campaign("invalid-head", None, plan.manifest_id())
            .is_err()
    );
}

#[test]
fn existing_destination_objects_must_meet_the_explicit_durability_requirement() {
    let (source, lineage, policy) = fixture();
    let head = source
        .create("source", &lineage, &policy, &BTreeMap::new())
        .expect("create source campaign");
    let plan = source
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Metadata,
            [],
            None,
        )
        .expect("plan metadata archive");
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("stage source archive metadata");

    let temporary = tempfile::tempdir().expect("temporary destination");
    let destination = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "single-durable-placement",
            temporary.path().join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs"))),
    );
    let one = DurabilityRequirement::new(1, false).expect("one durable placement");
    source
        .transfer_campaign_archive_objects(&destination, &plan, one)
        .expect("seed complete destination objects");

    let two = DurabilityRequirement::new(2, false).expect("two durable placements");
    assert!(matches!(
        source.transfer_campaign_archive_objects(&destination, &plan, two),
        Err(CampaignRepositoryError::Store(
            crucible_cas::content_store::StoreError::DurabilityUnsatisfied {
                minimum_durable_placements: 2,
                observed_durable_placements: 1,
                ..
            }
        ))
    ));
}

#[test]
fn mirror_rejects_a_nested_partial_archive_without_its_direct_inventory() {
    let (repository, lineage, policy) = fixture();
    let head = repository
        .create("source", &lineage, &policy, &BTreeMap::new())
        .expect("create source campaign");
    let partial = repository
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Metadata,
            [],
            None,
        )
        .expect("plan partial archive");
    repository
        .stage_campaign_archive_metadata(&partial)
        .expect("stage partial archive metadata");

    assert!(matches!(
        repository.plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Mirror,
            [partial.manifest_id().content_id()],
            None,
        ),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "mirror retained roots cannot contain archive metadata"
        })
    ));
}

#[test]
fn archive_with_undeclared_snapshot_children_fails_closed() {
    let (repository, lineage, policy) = fixture();
    let head = repository
        .create("source", &lineage, &policy, &BTreeMap::new())
        .expect("create source campaign");
    let valid = repository
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Metadata,
            [],
            None,
        )
        .expect("plan metadata archive");
    let snapshot_entry = *valid
        .selected()
        .iter()
        .find(|entry| entry.id() == head.snapshot_id().content_id())
        .expect("selected source snapshot");
    let page = CampaignArchiveInventoryPage::new(
        ArchiveInventoryDisposition::Selected,
        0,
        vec![snapshot_entry],
    )
    .expect("forged selected page");
    let page_envelope =
        ObjectEnvelope::for_archive_inventory_page(&page).expect("forged selected page envelope");
    repository
        .put_envelope(page_envelope)
        .expect("publish forged page");
    let manifest = CampaignArchiveManifest::new(
        head.snapshot_id(),
        CampaignArchivePolicy::Metadata,
        Vec::new(),
        Vec::new(),
        vec![page.id().expect("page ID")],
        Vec::new(),
        &[snapshot_entry],
        &[],
    )
    .expect("forged manifest");
    let envelope = ObjectEnvelope::for_archive_manifest(&manifest).expect("manifest envelope");
    let id = crate::CampaignArchiveManifestId::from_content_id(envelope.content_id())
        .expect("manifest ID");
    repository
        .put_envelope(envelope)
        .expect("publish forged manifest");

    assert!(matches!(
        repository.inspect_campaign_archive(id),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-archive-selected-child-is-undeclared"
        })
    ));
}
