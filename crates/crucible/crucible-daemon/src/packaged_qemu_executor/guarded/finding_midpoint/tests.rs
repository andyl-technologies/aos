//! Real namespace ownership tests for the finding-archive import join.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

use crucible_campaign::{
    CampaignArchiveCheckpointResolver, CampaignArchivePlan, CampaignArchivePolicy,
    CampaignCommandId, CampaignFactId, CampaignHash, CampaignLineage, CampaignMode, CampaignPolicy,
    CampaignRepository, CampaignRepositoryError, CampaignSeed, ConfigurationId, ExactCheckpointId,
    ExplorerPolicy, FairnessPolicy, PinChange, PinRequest, PinRetention, RetentionPolicy,
    ScenarioDefId,
};
use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};
use crucible_store::content_envelope::{ContentChild, ContentEnvelope};
use crucible_store::content_store::{
    BlobHandle, ContentId, DurabilityRequirement, ImmutableBlobBackend, ObjectKind, RefName,
};
use crucible_store::ram::{RamStore, RamStoreError, RamStoreLimits};
use rustix::fs::{FlockOperation, flock};

use super::*;
use crate::{
    CampaignGcMaintenance, CampaignGcOperationContext, DirectoryCampaignGcJournal,
    DirectoryCampaignTransferJournal, MemoryAssignmentLedger,
    apply_single_host_campaign_gc_with_transfers, plan_single_host_campaign_gc_with_transfers,
};

#[path = "../../../campaign_transfer/tests/catalog_gc/fixture.rs"]
mod fixture;
use fixture::{OriginalNamespace, RepositoryNamespace};

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

#[derive(Clone, Copy)]
struct RamClosureWitness {
    root: ContentId,
    region_tree: ContentId,
    leaf_tree: ContentId,
    page: ContentId,
}

impl RamClosureWitness {
    fn ids(self) -> [ContentId; 4] {
        [self.root, self.region_tree, self.leaf_tree, self.page]
    }
}

fn executable_plan(repository: &CampaignRepository) -> CampaignArchivePlan {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "finding-import-lease-test",
        b"scenario",
    ));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "finding-import-lease-test",
        b"genesis",
    ));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_artifact = repository
        .publish_configuration_artifact(
            scenario,
            scenario_artifact,
            genesis,
            1,
            b"genesis".to_vec(),
        )
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "finding-import-lease-test",
        "finding-import-lease-qemu",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x41; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy");
    let head = repository
        .create("source", &lineage, &policy, &BTreeMap::new())
        .expect("source campaign");
    let plan = repository
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Executable,
            BTreeSet::new(),
            None,
        )
        .expect("executable archive plan");
    repository
        .publish_campaign_archive(FINDING_BUNDLE_ARCHIVE_NAME, None, &plan)
        .expect("published finding bundle archive");
    plan
}

fn envelope(namespace: &RepositoryNamespace, id: ContentId) -> ContentEnvelope {
    let handle = namespace
        .graph
        .read_with_boundary(&namespace.original, id, None, &mut || Ok(()))
        .expect("authenticated RAM closure handle");
    let bytes = handle
        .read_all_with_boundary(&namespace.original, 4 * 1024 * 1024, &mut || Ok(()))
        .expect("authenticated RAM closure bytes");
    assert!(id.authenticates(&bytes));
    ContentEnvelope::from_canonical_bytes(&bytes).expect("canonical RAM closure envelope")
}

fn ram_backed_executable_plan(
    source: &RepositoryNamespace,
) -> (CampaignArchivePlan, RamClosureWitness) {
    let previous = executable_plan(&source.repository);
    let ram = RamStore::new(
        source.graph.clone(),
        DurabilityRequirement::new(1, false).expect("RAM durability"),
        RamStoreLimits::default(),
    )
    .expect("source RAM store");
    let retention = source
        .repository
        .ram_retention_authority()
        .acquire()
        .expect("real source RAM publication fence");
    let capture = source
        .original
        .child()
        .expect("original source RAM capture");
    let retained_root = ram
        .capture(
            Topology::new(
                vec![
                    RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 8192)
                        .expect("two-page RAM region"),
                ],
                Limits::default(),
            )
            .expect("finite RAM topology"),
            Scope::Exact,
            &mut |_, index, output| {
                output.fill((index + 1) as u8);
                Ok(())
            },
            &retention,
            &capture,
            &mut || Ok(()),
        )
        .expect("actual nonzero RAM tree");
    drop(capture);
    drop(retention);

    let root = retained_root.object_id();
    let region_tree = envelope(source, root)
        .children()
        .iter()
        .next()
        .expect("RAM region tree")
        .id();
    let region = envelope(source, region_tree);
    let leaf_tree = region.children().iter().next().expect("RAM leaf tree").id();
    let page = envelope(source, leaf_tree)
        .children()
        .iter()
        .next()
        .expect("RAM page")
        .id();
    assert_eq!(root.kind(), ObjectKind::ExactManifest);
    assert_eq!(region_tree.kind(), ObjectKind::RamTree);
    assert_eq!(leaf_tree.kind(), ObjectKind::RamTree);
    assert_eq!(page.kind(), ObjectKind::RamExtent);

    let checkpoint = ContentEnvelope::new(
        "crucible.executor.exact-checkpoint-root",
        6,
        BTreeSet::from([
            ContentChild::new("ram-root-00000000", root).expect("RAM checkpoint binding")
        ]),
        b"finding import lease RAM checkpoint".to_vec(),
    )
    .expect("exact checkpoint envelope");
    let checkpoint_id = checkpoint.content_id(ObjectKind::ExactManifest);
    source
        .graph
        .put_if_absent(
            checkpoint_id,
            &BlobHandle::from_bytes(checkpoint.canonical_bytes()),
        )
        .expect("exact checkpoint object");
    let checkpoint =
        ExactCheckpointId::try_from(checkpoint_id).expect("exact checkpoint identity schema");

    let configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "finding-import-lease-test",
        b"genesis",
    ));
    let head = source
        .repository
        .head("source")
        .expect("source campaign before exact pin");
    source
        .repository
        .apply_pin(
            "source",
            &PinRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "finding-import-lease-test",
                    b"exact-pin",
                )),
                expected_snapshot: head.snapshot_id(),
                change: PinChange::new(
                    configuration,
                    Some(PinRetention::Exact),
                    "retain finding import RAM checkpoint",
                )
                .expect("exact pin change"),
            },
        )
        .expect("publish exact pin");
    let head = source
        .repository
        .head("source")
        .expect("source campaign after exact pin");
    let mut resolver = FixedCheckpoint(checkpoint);
    let plan = source
        .repository
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Executable,
            [],
            Some(&mut resolver),
        )
        .expect("RAM-backed executable archive plan");
    source
        .repository
        .publish_campaign_archive(
            FINDING_BUNDLE_ARCHIVE_NAME,
            Some(previous.manifest_id()),
            &plan,
        )
        .expect("replace bundle with RAM-backed executable archive");
    assert_eq!(plan.ram_roots(), &[root]);
    assert_eq!(plan.manifest().checkpoint_selections().len(), 1);
    assert!(plan.selected().iter().all(|entry| !matches!(
        entry.id().kind(),
        ObjectKind::RamTree | ObjectKind::RamExtent
    )));
    drop(retained_root);

    (
        plan,
        RamClosureWitness {
            root,
            region_tree,
            leaf_tree,
            page,
        },
    )
}

fn publication_lock(path: &std::path::Path) -> File {
    File::open(path.join(".ref-admin/publication-lock")).expect("real publication lock")
}

fn count_reader_claims(namespace: &RepositoryNamespace) -> usize {
    count_refs(namespace).1
}

fn count_refs(namespace: &RepositoryNamespace) -> (usize, usize) {
    let mut total = 0;
    let mut readers = 0;
    namespace
        .refs_admin
        .acquire_ref_inventory_fence()
        .expect("exclusive ref inventory")
        .visit_refs(&mut |record| {
            total += 1;
            if record.name().as_str().starts_with("archive-readers/") {
                readers += 1;
            }
            Ok(())
        })
        .expect("reader inventory");
    (total, readers)
}

fn apply_real_gc(
    namespace: &RepositoryNamespace,
    root: &std::path::Path,
    scope: &str,
) -> Vec<ContentId> {
    let marks = namespace
        .admin
        .gc_mark_backend("primary", scope)
        .expect("real Directory GC marks");
    let mut check = || Ok(());
    let operation = CampaignGcOperationContext::new(marks, &namespace.original, &mut check)
        .expect("same-original GC operation");
    let maintenance = CampaignGcMaintenance::new(&namespace.admin, &operation);
    let mut ledger = MemoryAssignmentLedger::default();
    let transfers = DirectoryCampaignTransferJournal::open(root.with_extension("transfers"))
        .expect("empty transfer retention inventory");
    let prepared = plan_single_host_campaign_gc_with_transfers(
        &namespace.repository,
        namespace.refs_admin.as_ref(),
        &mut ledger,
        None,
        &transfers,
        None,
        maintenance,
    )
    .expect("real GC plan");
    let candidates = prepared
        .candidates()
        .iter()
        .map(|candidate| candidate.id())
        .collect::<Vec<_>>();
    let (mut journal, _) = DirectoryCampaignGcJournal::create(root, &prepared, &operation)
        .expect("durable GC journal");
    let report = apply_single_host_campaign_gc_with_transfers(
        &mut journal,
        &namespace.repository,
        namespace.refs_admin.as_ref(),
        &mut ledger,
        None,
        &transfers,
        None,
        maintenance,
    )
    .expect("real GC apply");
    assert_eq!(report.status(), crate::CampaignGcApplyStatus::Applied);
    candidates
}

#[test]
fn finding_import_lease_releases_source_fence_before_destination_handoff() {
    let temporary = tempfile::tempdir().expect("finding import namespaces");
    let source_owner = OriginalNamespace::new(&temporary.path().join("source-objects"));
    let destination_owner = OriginalNamespace::new(&temporary.path().join("destination-objects"));
    {
        let source_refs = temporary.path().join("source-refs");
        let destination_refs = temporary.path().join("destination-refs");
        let source = source_owner.open(&source_refs);
        let destination = destination_owner.open(&destination_refs);
        let _scope = source.original.enter();
        let _fixture = source
            .original
            .reserve_scratch_bytes(65_536)
            .expect("finite archive fixture metadata");
        let (plan, ram) = ram_backed_executable_plan(&source);
        let manifest = plan.manifest_id().content_id();
        assert!(ram.ids().iter().all(|id| {
            source
                .graph
                .contains(*id)
                .expect("source RAM closure before transfer")
        }));
        let garbage =
            ContentId::for_bytes(ObjectKind::DiskExtent, 1, b"finding-import-source-garbage");
        source
            .graph
            .put_if_absent(
                garbage,
                &BlobHandle::from_bytes(b"finding-import-source-garbage".to_vec()),
            )
            .expect("unrelated source object");

        let retained = RetainedFindingArchiveTransfer::retain(
            &source.repository,
            &destination.repository,
            plan.manifest_id(),
            &mut || Ok(()),
        )
        .expect("independent source reader claim");
        assert_eq!(count_reader_claims(&source), 1);

        let public_archive =
            RefName::new(format!("archives/{FINDING_BUNDLE_ARCHIVE_NAME}")).expect("archive ref");
        source
            .refs
            .compare_remove(&public_archive, manifest)
            .expect("remove public source archive");
        let public_campaign = RefName::new("campaigns/source").expect("campaign ref");
        source
            .refs
            .compare_remove(
                &public_campaign,
                plan.manifest().source_snapshot().content_id(),
            )
            .expect("remove public source campaign");
        assert_eq!(count_refs(&source), (1, 1));

        let mut observed_handoff = false;
        retained
            .transfer_with_handoff(
                &plan,
                DurabilityRequirement::new(1, false).expect("durable destination"),
                Some(&source.original),
                Some(&destination.original),
                &mut || {
                    if !observed_handoff {
                        let source_lock = publication_lock(&source_refs);
                        if flock(&source_lock, FlockOperation::NonBlockingLockExclusive).is_ok() {
                            drop(source_lock);
                            let destination_lock = publication_lock(&destination_refs);
                            assert_eq!(
                                flock(&destination_lock, FlockOperation::NonBlockingLockExclusive),
                                Err(rustix::io::Errno::WOULDBLOCK)
                            );
                            drop(destination_lock);

                            let candidates = apply_real_gc(
                                &source,
                                &temporary.path().join("source-owned-gc"),
                                "finding-import-source-owned",
                            );
                            assert!(candidates.contains(&garbage));
                            assert!(!candidates.contains(&manifest));
                            assert!(
                                plan.selected()
                                    .iter()
                                    .all(|entry| !candidates.contains(&entry.id()))
                            );
                            assert!(ram.ids().iter().all(|id| !candidates.contains(id)));
                            observed_handoff = true;
                        }
                    }
                    Ok(())
                },
                |boundary| {
                    destination
                        .repository
                        .publish_campaign_archive_with_boundary(
                            "received-finding",
                            None,
                            &plan,
                            boundary,
                        )?;
                    destination
                        .repository
                        .publish_transferred_campaign_with_boundary(
                            "received-finding",
                            None,
                            plan.manifest_id(),
                            boundary,
                        )?;
                    Ok::<_, CampaignRepositoryError>(())
                },
            )
            .expect("destination publication handoff");

        assert!(observed_handoff);
        assert_eq!(count_reader_claims(&source), 0);
        destination
            .repository
            .inspect_campaign_archive_ref("received-finding")
            .expect("destination successor retains the archive");
        flock(
            &publication_lock(&destination_refs),
            FlockOperation::NonBlockingLockExclusive,
        )
        .expect("destination exclusion closed after handoff");

        let source_candidates = apply_real_gc(
            &source,
            &temporary.path().join("source-retired-gc"),
            "finding-import-source-retired",
        );
        assert!(source_candidates.contains(&manifest));
        assert!(ram.ids().iter().all(|id| source_candidates.contains(id)));
        assert!(
            !source
                .graph
                .contains(manifest)
                .expect("manifest membership")
        );
        assert!(ram.ids().iter().all(|id| {
            !source
                .graph
                .contains(*id)
                .expect("source RAM closure membership")
        }));

        // The archive must retain RAM independently of live campaign pins.
        // This fixture publishes no receiver checkpoint materialization store.
        destination
            .refs
            .compare_remove(
                &RefName::new("campaigns/received-finding").expect("receiver campaign ref"),
                plan.manifest().source_snapshot().content_id(),
            )
            .expect("retire receiver campaign while archive remains");

        let destination_candidates = apply_real_gc(
            &destination,
            &temporary.path().join("destination-published-gc"),
            "finding-import-destination-published",
        );
        assert!(!destination_candidates.contains(&manifest));
        assert!(
            ram.ids()
                .iter()
                .all(|id| !destination_candidates.contains(id))
        );
        assert!(ram.ids().iter().all(|id| {
            destination
                .graph
                .contains(*id)
                .expect("destination RAM closure membership")
        }));
        destination
            .repository
            .inspect_campaign_archive_ref("received-finding")
            .expect("real GC preserves destination successor");
    }
    source_owner.assert_idle();
    destination_owner.assert_idle();
}

#[test]
fn finding_import_cancellation_retires_claim_without_destination_publication() {
    let temporary = tempfile::tempdir().expect("canceled finding import namespaces");
    let source_owner = OriginalNamespace::new(&temporary.path().join("source-objects"));
    let destination_owner = OriginalNamespace::new(&temporary.path().join("destination-objects"));
    {
        let source_refs = temporary.path().join("source-refs");
        let destination_refs = temporary.path().join("destination-refs");
        let source = source_owner.open(&source_refs);
        let destination = destination_owner.open(&destination_refs);
        let _scope = source.original.enter();
        let _fixture = source
            .original
            .reserve_scratch_bytes(65_536)
            .expect("finite archive fixture metadata");
        let plan = executable_plan(&source.repository);
        let copied_before_cancellation = plan
            .selected()
            .first()
            .expect("executable archive has a selected object")
            .id();
        let retained = RetainedFindingArchiveTransfer::retain(
            &source.repository,
            &destination.repository,
            plan.manifest_id(),
            &mut || Ok(()),
        )
        .expect("independent source reader claim");

        let mut canceled_under_destination = false;
        let mut handoff_called = false;
        let result: Result<(), CampaignRepositoryError> = retained.transfer_with_handoff(
            &plan,
            DurabilityRequirement::new(1, false).expect("durable destination"),
            Some(&source.original),
            Some(&destination.original),
            &mut || {
                if !destination
                    .graph
                    .contains(copied_before_cancellation)
                    .expect("observe completed destination object")
                {
                    return Ok(());
                }
                let source_lock = publication_lock(&source_refs);
                if flock(&source_lock, FlockOperation::NonBlockingLockExclusive).is_ok() {
                    drop(source_lock);
                    let destination_lock = publication_lock(&destination_refs);
                    assert_eq!(
                        flock(&destination_lock, FlockOperation::NonBlockingLockExclusive),
                        Err(rustix::io::Errno::WOULDBLOCK)
                    );
                    canceled_under_destination = true;
                    return Err(RamStoreError::Canceled);
                }
                Ok(())
            },
            |_| {
                handoff_called = true;
                Ok(())
            },
        );
        match &result {
            Err(CampaignRepositoryError::Ram(RamStoreError::Canceled)) => {}
            Err(CampaignRepositoryError::Ram(RamStoreError::Boundary(cause))) => {
                assert!(matches!(
                    cause.first_boundary(),
                    Some(RamStoreError::Canceled)
                ));
            }
            _ => panic!("unexpected import result: {result:?}"),
        }
        assert!(canceled_under_destination);
        assert!(!handoff_called);
        assert_eq!(count_reader_claims(&source), 0);
        assert!(
            destination
                .graph
                .contains(copied_before_cancellation)
                .expect("completed destination object before GC")
        );
        assert!(matches!(
            destination
                .repository
                .inspect_campaign_archive_ref("received-finding"),
            Err(CampaignRepositoryError::NotFound)
        ));
        flock(
            &publication_lock(&source_refs),
            FlockOperation::NonBlockingLockExclusive,
        )
        .expect("source exclusion closed after cancellation");
        flock(
            &publication_lock(&destination_refs),
            FlockOperation::NonBlockingLockExclusive,
        )
        .expect("destination exclusion closed after cancellation");

        let candidates = apply_real_gc(
            &destination,
            &temporary.path().join("destination-canceled-gc"),
            "finding-import-destination-canceled",
        );
        assert!(candidates.contains(&copied_before_cancellation));
        assert!(candidates.iter().all(|id| {
            !destination
                .repository
                .blob_backend()
                .contains(*id)
                .expect("candidate removed")
        }));
    }
    source_owner.assert_idle();
    destination_owner.assert_idle();
}

#[test]
fn finding_import_lease_refuses_a_different_archive_plan_before_copy() {
    let temporary = tempfile::tempdir().expect("mismatched finding import namespaces");
    let source_owner = OriginalNamespace::new(&temporary.path().join("source-objects"));
    let destination_owner = OriginalNamespace::new(&temporary.path().join("destination-objects"));
    {
        let source_refs = temporary.path().join("source-refs");
        let destination_refs = temporary.path().join("destination-refs");
        let source = source_owner.open(&source_refs);
        let destination = destination_owner.open(&destination_refs);
        let _scope = source.original.enter();
        let _fixture = source
            .original
            .reserve_scratch_bytes(65_536)
            .expect("finite archive fixture metadata");
        let retained_plan = executable_plan(&source.repository);
        let different_plan = source
            .repository
            .plan_campaign_archive(
                retained_plan.manifest().source_snapshot(),
                CampaignArchivePolicy::Metadata,
                BTreeSet::new(),
                None,
            )
            .expect("different archive plan");
        assert_ne!(different_plan.manifest_id(), retained_plan.manifest_id());
        let retained = RetainedFindingArchiveTransfer::retain(
            &source.repository,
            &destination.repository,
            retained_plan.manifest_id(),
            &mut || Ok(()),
        )
        .expect("independent source reader claim");

        let mut boundary_called = false;
        let mut handoff_called = false;
        let result: Result<(), CampaignRepositoryError> = retained.transfer_with_handoff(
            &different_plan,
            DurabilityRequirement::new(1, false).expect("durable destination"),
            Some(&source.original),
            Some(&destination.original),
            &mut || {
                boundary_called = true;
                Ok(())
            },
            |_| {
                handoff_called = true;
                Ok(())
            },
        );

        assert!(matches!(
            result,
            Err(CampaignRepositoryError::Integrity {
                reason: "retained-finding-archive-plan-mismatch"
            })
        ));
        assert!(!boundary_called);
        assert!(!handoff_called);
        assert_eq!(count_reader_claims(&source), 0);
        assert!(matches!(
            destination
                .repository
                .inspect_campaign_archive_ref("received-finding"),
            Err(CampaignRepositoryError::NotFound)
        ));
        assert!(
            !destination_refs
                .join(".ref-admin/publication-lock")
                .exists()
        );
    }
    source_owner.assert_idle();
    destination_owner.assert_idle();
}
