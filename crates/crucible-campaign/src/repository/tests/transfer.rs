//! Archive selection, partial-boundary, and transfer regressions.

use std::sync::Arc;

#[path = "transfer_resources.rs"]
mod resources;

#[path = "transfer/no_ram.rs"]
mod no_ram;

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
        CampaignFactId::from_content_id(ContentId::for_bytes(ObjectKind::CampaignFact, 15, b"pin"))
            .expect("pin fact");
    let first = ExactCheckpointId::from_content_id(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        6,
        b"first checkpoint",
    ))
    .expect("first checkpoint");
    let second = ExactCheckpointId::from_content_id(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        6,
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
        3,
        b"snapshot",
    ))
    .expect("snapshot");

    assert!(matches!(
        CampaignArchiveManifest::new(crate::archive::CampaignArchiveManifestBasis {
            source_snapshot: snapshot,
            policy: CampaignArchivePolicy::Executable,
            checkpoint_selections: selections,
            retained_roots: Vec::new(),
            ram_roots: Vec::new(),
            selected_pages: Vec::new(),
            omitted_pages: Vec::new(),
            selected: &[],
            omitted: &[],
        }),
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
        crate::CampaignRamAdmission::Unavailable,
    );
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("stage source archive metadata");
    source
        .transfer_campaign_archive_objects(
            &destination,
            &plan,
            DurabilityRequirement::new(1, false).expect("destination durability"),
            source.ram_admission().original(),
            destination.ram_admission().original(),
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
        6,
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
        .publish_incomplete_test_finding(
            "policy-source",
            observed.new_snapshot,
            signature,
            observed.observation,
            reproduction,
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
            crate::CampaignRamAdmission::Unavailable,
        );
        source
            .transfer_campaign_archive_objects(
                &destination,
                &plan,
                DurabilityRequirement::new(1, false).expect("destination durability"),
                source.ram_admission().original(),
                destination.ram_admission().original(),
            )
            .expect("transfer policy archive");
        destination
            .publish_campaign_archive("policy", None, &plan)
            .expect("publish policy archive");

        let inspection = destination
            .inspect_campaign_archive_ref("policy")
            .expect("inspect transferred policy archive");
        assert_eq!(inspection.manifest().policy(), archive_policy);
        let general_handoff =
            destination.inspect_archived_finding(plan.manifest_id(), found.finding);
        if matches!(
            archive_policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            assert_eq!(
                general_handoff
                    .expect("complete finding handoff")
                    .id()
                    .expect("retained finding ID"),
                found.finding
            );
        } else {
            assert!(matches!(
                general_handoff,
                Err(CampaignRepositoryError::InvalidRequest {
                    reason: "finding handoff requires an executable archive"
                })
            ));
        }
        let exact_handoff =
            destination.inspect_archived_exact_finding(plan.manifest_id(), found.finding);
        let expected_reason = if matches!(
            archive_policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            "archived finding has no retained exact checkpoint"
        } else {
            "finding handoff requires an executable archive"
        };
        assert!(matches!(
            exact_handoff,
            Err(CampaignRepositoryError::InvalidRequest { reason }) if reason == expected_reason
        ));
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
                CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
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
        crate::CampaignRamAdmission::Unavailable,
    );
    let one = DurabilityRequirement::new(1, false).expect("one durable placement");
    source
        .transfer_campaign_archive_objects(
            &destination,
            &plan,
            one,
            source.ram_admission().original(),
            destination.ram_admission().original(),
        )
        .expect("seed complete destination objects");

    let two = DurabilityRequirement::new(2, false).expect("two durable placements");
    assert!(matches!(
        source.transfer_campaign_archive_objects(
            &destination,
            &plan,
            two,
            source.ram_admission().original(),
            destination.ram_admission().original(),
        ),
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
    let selected = [snapshot_entry];
    let manifest = CampaignArchiveManifest::new(crate::archive::CampaignArchiveManifestBasis {
        source_snapshot: head.snapshot_id(),
        policy: CampaignArchivePolicy::Metadata,
        checkpoint_selections: Vec::new(),
        retained_roots: Vec::new(),
        ram_roots: Vec::new(),
        selected_pages: vec![page.id().expect("page ID")],
        omitted_pages: Vec::new(),
        selected: &selected,
        omitted: &[],
    })
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

fn publish_paged_ram_fixture(repository: &CampaignRepository) -> (ContentId, Vec<ContentId>) {
    use crucible_cas::ram::{RamStore, RamStoreLimits};
    use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

    let store = RamStore::new(
        Arc::clone(&repository.blobs),
        DurabilityRequirement::new(1, false).expect("RAM durability"),
        RamStoreLimits::default(),
    )
    .expect("RAM store");
    let original = repository
        .ram_operation_account()
        .expect("saved source RAM operation");
    let retention = repository
        .ram_retention_authority()
        .acquire()
        .expect("real source fence");
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 5 * 4096 + 19)
                .expect("RAM region"),
        ],
        Limits::default(),
    )
    .expect("RAM topology");
    let root = store
        .capture(
            topology,
            Scope::Exact,
            &mut |_, index, output| {
                output.fill((index + 1) as u8);
                Ok(())
            },
            &retention,
            &original,
            &mut || Ok(()),
        )
        .expect("durable RAM capture");
    let id = root.object_id();
    let identities = repository
        .authenticated_closure_ids([id])
        .expect("full fixture graph")
        .into_iter()
        .collect();
    (id, identities)
}

#[test]
fn archive_ram_graphs_have_compact_inventories_and_real_transitive_possession() {
    use crucible_cas::content_envelope::ContentChild;
    use crucible_cas::content_store::{BlobStoreAdmin, RefStoreAdmin};
    use crucible_cas::ram::{RamStore, RamStoreLimits};

    let (_memory_source, lineage, policy, memory_blobs) = counted_fixture();
    let source_directory = tempfile::tempdir().expect("durable source directory");
    let resources: Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard> =
        Arc::new(resources::TransferResources::new(128, 256 * 1024 * 1024));
    let original = crucible_cas::owned_decode::DecodeBudget::for_store(resources.clone())
        .expect("original source and receiver fixture namespace");
    let (source_blobs, _source_admin) = DirectoryBlobBackend::new_with_physical_quota_and_admin(
        "ram-source",
        source_directory.path().join("objects"),
        resources.clone(),
    )
    .expect("durable source with original finite component metadata");
    let source_refs = Arc::new(DirectoryRefBackend::new(
        source_directory.path().join("refs"),
    ));
    let mut seed_ids = Vec::new();
    memory_blobs
        .acquire_inventory_fence()
        .expect("metadata seed inventory")
        .visit_inventory(&mut |record| {
            seed_ids.push(record.id());
            Ok(())
        })
        .expect("metadata seed identities");
    for id in seed_ids {
        let bytes = memory_blobs.read(id, None).expect("metadata seed bytes");
        source_blobs
            .put_if_absent(id, &bytes)
            .expect("durable metadata seed");
    }
    let source = CampaignRepository::new(
        source_blobs,
        source_refs,
        crate::CampaignRamAdmission::Available(original.clone()),
    );
    let head = source
        .create("ram-source", &lineage, &policy, &BTreeMap::new())
        .expect("source head");
    let (ram_root, ram_objects) = publish_paged_ram_fixture(&source);
    let world = ContentEnvelope::new(
        "crucible.executor.exact-checkpoint-root",
        6,
        BTreeSet::from([ContentChild::new("ram-root-00000000", ram_root).expect("RAM role")]),
        b"storage traversal fixture; no execution authority".to_vec(),
    )
    .expect("world root envelope");
    let world_id = world.content_id(ObjectKind::ExactManifest);
    source
        .blobs
        .put_if_absent(world_id, &BlobHandle::from_bytes(world.canonical_bytes()))
        .expect("world root stored");
    let plan = source
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Mirror,
            [world_id],
            None,
        )
        .expect("compact RAM archive");

    assert_eq!(plan.ram_roots(), &[ram_root]);
    assert_eq!(
        plan.ram_root_bindings(),
        &[(
            ExactCheckpointId::from_content_id(world_id).expect("world ID"),
            ram_root
        )]
    );
    assert!(plan.selected().iter().any(|entry| entry.id() == world_id));
    assert!(plan.selected().iter().any(|entry| entry.id() == ram_root));
    assert!(plan.selected().iter().all(|entry| !matches!(
        entry.id().kind(),
        ObjectKind::RamTree | ObjectKind::RamExtent
    )));
    assert!(
        source
            .authenticated_closure_ids([ram_root])
            .expect("ordinary full closure")
            .len()
            > 1
    );
    let mut ram_boundaries = 0_u64;
    let canceled = source.authenticate_ram_root(ram_root, true, &mut || {
        ram_boundaries += 1;
        if ram_boundaries == 4 {
            Err(crucible_cas::ram::RamStoreError::Canceled)
        } else {
            Ok(())
        }
    });
    let Err(CampaignRepositoryError::Ram(crucible_cas::ram::RamStoreError::Store(
        crucible_cas::content_store::StoreError::RamReadBoundary { source: cause },
    ))) = &canceled
    else {
        panic!("the observed callback refusal retains its complete direct boundary carrier");
    };
    assert!(matches!(
        cause.first_boundary(),
        Some(crucible_cas::ram::RamStoreError::Canceled)
    ));
    assert!(matches!(
        cause.storage_failure(),
        crucible_cas::ram::RamStoreError::Store(
            crucible_cas::content_store::StoreError::RamBoundary { .. }
        )
    ));
    let alias = cause.clone();
    assert_eq!(
        &alias, cause,
        "the first cause and storage marker share original custody"
    );
    drop(alias);
    assert_eq!(
        ram_boundaries, 4,
        "the actual RAM tree polls its operation owner"
    );
    drop(canceled);
    let refused_plan = source.plan_campaign_archive_with_boundary(
        head.snapshot_id(),
        CampaignArchivePolicy::Mirror,
        [world_id],
        None,
        &mut || Err(crucible_cas::ram::RamStoreError::Canceled),
    );
    assert!(matches!(
        refused_plan,
        Err(CampaignRepositoryError::Ram(
            crucible_cas::ram::RamStoreError::Canceled
        ))
    ));
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("stage compact archive");
    no_ram::assert_hidden_ram_refuses_before_dispatch(&source, &plan);
    let mut inspection_boundaries = 0_u64;
    let refused_inspection =
        source.inspect_campaign_archive_with_boundary(plan.manifest_id(), &mut || {
            inspection_boundaries += 1;
            if inspection_boundaries == 8 {
                Err(crucible_cas::ram::RamStoreError::Canceled)
            } else {
                Ok(())
            }
        });
    let Err(CampaignRepositoryError::Ram(crucible_cas::ram::RamStoreError::Store(
        crucible_cas::content_store::StoreError::RamReadBoundary { source: cause },
    ))) = &refused_inspection
    else {
        panic!("the observed callback refusal retains its complete direct boundary carrier");
    };
    assert!(matches!(
        cause.first_boundary(),
        Some(crucible_cas::ram::RamStoreError::Canceled)
    ));
    assert!(matches!(
        cause.storage_failure(),
        crucible_cas::ram::RamStoreError::Store(
            crucible_cas::content_store::StoreError::RamBoundary { .. }
        )
    ));
    let alias = cause.clone();
    assert_eq!(
        &alias, cause,
        "the first cause and storage marker share original custody"
    );
    drop(alias);
    assert_eq!(inspection_boundaries, 8);
    drop(refused_inspection);

    let temporary = tempfile::tempdir().expect("destination directory");
    let (blobs, blob_admin) = DirectoryBlobBackend::new_with_physical_quota_and_admin(
        "ram-destination",
        temporary.path().join("objects"),
        resources.clone(),
    )
    .expect("durable receiver with the same finite component metadata");
    assert!(Arc::ptr_eq(
        &blobs.metadata_resources().expect("receiver origin"),
        &resources
    ));
    let refs = Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let destination = CampaignRepository::new(
        blobs.clone(),
        refs.clone(),
        crate::CampaignRamAdmission::Available(original),
    );
    let durability = DurabilityRequirement::new(1, false).expect("destination durability");
    source
        .transfer_campaign_archive_objects(
            &destination,
            &plan,
            durability,
            source.ram_admission().original(),
            destination.ram_admission().original(),
        )
        .expect("complete descendant transfer");
    destination
        .inspect_campaign_archive(plan.manifest_id())
        .expect("complete RAM availability");
    for id in &ram_objects {
        assert!(
            blobs.read(*id, None).is_ok(),
            "RAM descendant {id} must be present"
        );
    }

    let page = ram_objects
        .iter()
        .copied()
        .find(|id| id.kind() == ObjectKind::RamExtent)
        .expect("real RAM page");
    blob_admin
        .acquire_inventory_fence()
        .expect("fixture destructive inventory")
        .delete_candidate(page)
        .expect("remove one real page");
    assert!(
        destination
            .inspect_campaign_archive(plan.manifest_id())
            .is_err(),
        "root metadata alone cannot establish archive availability"
    );

    let original = destination
        .ram_operation_account()
        .expect("saved inventory namespace");
    let inventory = refs
        .acquire_ref_inventory_fence()
        .expect("actual exclusive GC authority");
    let metadata = destination
        .inspect_campaign_archive_for_gc(plan.manifest_id(), inventory.as_ref())
        .expect("metadata-only inventory under exclusive fence");
    assert_eq!(metadata.manifest().ram_roots(), &[ram_root]);
    let split = destination
        .authenticated_storage_closure([ram_root], inventory.as_ref())
        .expect("bounded RAM frontier");
    assert_eq!(split.objects(), &BTreeSet::from([ram_root]));
    assert_eq!(split.ram_roots(), &[ram_root]);
    let store =
        RamStore::new(blobs, durability, RamStoreLimits::default()).expect("inventory RAM store");
    assert!(
        store
            .visit_inventory_graph(
                ram_root,
                inventory.as_ref(),
                &original,
                &mut || Ok(()),
                &mut |_| Ok(())
            )
            .is_err(),
        "destructive inventory must refuse the missing descendant"
    );
}
