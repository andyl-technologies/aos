//! Archive selection, partial-boundary, and transfer regressions.

use std::sync::Arc;

use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement,
    ObjectKind,
};

use super::*;
use crate::{
    ArchiveInventoryDisposition, CampaignArchiveCheckpointResolver,
    CampaignArchiveCheckpointSelection, CampaignArchiveInventoryPage, CampaignArchiveManifest,
    CampaignArchivePolicy, CampaignFactId, ExactCheckpointId, FindingKind, FindingSignature,
    FindingTarget, ObjectEnvelope, PinChange, PinRequest, PinRetention,
};

struct FixedCheckpoint(ExactCheckpointId);

impl CampaignArchiveCheckpointResolver for FixedCheckpoint {
    fn resolve_checkpoint(
        &mut self,
        _configuration: ConfigurationId,
        _pin_fact: CampaignFactId,
    ) -> Result<ExactCheckpointId, CampaignRepositoryError> {
        Ok(self.0)
    }
}

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
fn every_archive_policy_preserves_its_partition_and_head_eligibility() {
    let (source, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&source, &lineage, &policy, "policy-source");
    let observed = source
        .publish_observation("policy-source", admitted.new_snapshot, &observation)
        .expect("publish representative observation");
    let checkpoint_envelope = ContentEnvelope::new(
        "crucible.test.archive-exact-checkpoint",
        4,
        BTreeSet::new(),
        b"representative exact checkpoint".to_vec(),
    )
    .expect("exact checkpoint envelope");
    let checkpoint_content = checkpoint_envelope.content_id(ObjectKind::ExactManifest);
    source
        .blobs
        .put_if_absent(
            checkpoint_content,
            &BlobHandle::from_bytes(checkpoint_envelope.canonical_bytes()),
        )
        .expect("publish representative exact checkpoint");
    let checkpoint = ExactCheckpointId::try_from(checkpoint_content).expect("exact checkpoint ID");
    let fingerprint = CampaignHash::derive("test-archive-finding", b"policy matrix");
    let reproduction = source
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"representative reproduction".to_vec(),
        )
        .expect("publish representative reproduction");
    let reproduction_content = reproduction.content_id();
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.archive-policy-matrix".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::from([observation.properties().content_id()]),
    )
    .expect("representative finding signature");
    let found = source
        .publish_finding(
            "policy-source",
            observed.new_snapshot,
            signature,
            observed.observation,
            reproduction,
            None,
            BTreeSet::from([checkpoint]),
        )
        .expect("publish representative finding");
    source
        .apply_pin(
            "policy-source",
            &PinRequest {
                command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
                    "test-policy-archive-exact-pin",
                    b"policy-source",
                )),
                expected_snapshot: found.new_snapshot,
                change: PinChange::new(
                    observation.child(),
                    Some(PinRetention::Exact),
                    "retain representative exact checkpoint",
                )
                .expect("exact pin change"),
            },
        )
        .expect("pin representative configuration");
    let head = source.head("policy-source").expect("policy source head");
    let mirror_bytes = b"mirror-only retained trace".to_vec();
    let mirror_root = ContentId::for_bytes(ObjectKind::Trace, 1, &mirror_bytes);
    source
        .blobs
        .put_if_absent(mirror_root, &BlobHandle::from_bytes(mirror_bytes))
        .expect("publish mirror-only retained root");
    let temporary = tempfile::tempdir().expect("temporary policy destinations");
    let policies = [
        CampaignArchivePolicy::Metadata,
        CampaignArchivePolicy::Findings,
        CampaignArchivePolicy::Debug,
        CampaignArchivePolicy::Executable,
        CampaignArchivePolicy::Mirror,
    ];

    for (index, archive_policy) in policies.into_iter().enumerate() {
        let mut checkpoint_resolver = FixedCheckpoint(checkpoint);
        let resolver = matches!(
            archive_policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        )
        .then_some(&mut checkpoint_resolver as &mut dyn CampaignArchiveCheckpointResolver);
        let retained_roots = if archive_policy == CampaignArchivePolicy::Mirror {
            vec![mirror_root]
        } else {
            Vec::new()
        };
        let plan = source
            .plan_campaign_archive(head.snapshot_id(), archive_policy, retained_roots, resolver)
            .expect("plan policy archive");
        source
            .stage_campaign_archive_metadata(&plan)
            .expect("stage source archive metadata");
        let destination = CampaignRepository::new(
            Arc::new(DirectoryBlobBackend::new(
                format!("policy-destination-{index}"),
                temporary.path().join(format!("objects-{index}")),
            )),
            Arc::new(DirectoryRefBackend::new(
                temporary.path().join(format!("refs-{index}")),
            )),
        );
        source
            .transfer_campaign_archive_objects(
                &destination,
                &plan,
                DurabilityRequirement::new(1, false).expect("destination durability"),
            )
            .expect("transfer policy archive");
        destination
            .publish_campaign_archive("policy", None, &plan)
            .expect("publish policy archive");

        let inspection = destination
            .inspect_campaign_archive_ref("policy")
            .expect("inspect transferred policy archive");
        assert_eq!(inspection.manifest().policy(), archive_policy);
        assert_eq!(inspection.selected(), plan.selected());
        assert_eq!(inspection.omitted(), plan.omitted());
        assert_eq!(
            inspection.omitted_inventory_verified(),
            plan.omitted().is_empty()
        );
        assert_eq!(
            inspection
                .selected()
                .iter()
                .any(|entry| entry.id() == mirror_root),
            archive_policy == CampaignArchivePolicy::Mirror
        );
        assert_eq!(
            inspection
                .selected()
                .iter()
                .any(|entry| entry.id() == checkpoint.content_id()),
            matches!(
                archive_policy,
                CampaignArchivePolicy::Debug
                    | CampaignArchivePolicy::Executable
                    | CampaignArchivePolicy::Mirror
            )
        );
        assert_eq!(
            inspection
                .selected()
                .iter()
                .any(|entry| entry.id() == reproduction_content),
            archive_policy != CampaignArchivePolicy::Metadata
        );

        let head_result = destination.publish_transferred_campaign(
            &format!("imported-{index}"),
            None,
            plan.manifest_id(),
        );
        if matches!(
            archive_policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            assert_eq!(
                head_result.expect("complete policy publishes campaign"),
                head.snapshot_id()
            );
        } else {
            assert!(matches!(
                head_result,
                Err(CampaignRepositoryError::InvalidRequest {
                    reason: "partial campaign archive cannot publish a campaign head"
                })
            ));
        }
    }
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
