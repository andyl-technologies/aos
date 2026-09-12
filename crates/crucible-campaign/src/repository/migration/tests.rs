//! Focused one-way campaign migration regressions.

use super::*;
use crate::repository::migration::legacy::LegacyCampaignSnapshot;
use crate::{CampaignBudgetLedgerId, PlannerCandidateBudgetId, PlannerCandidateGuidanceId};

const CAMPAIGN: &str = "migration-fixture";

fn migration_budget(maximum_objects: usize) -> CampaignMigrationBudget {
    CampaignMigrationBudget::new(
        maximum_objects,
        64 * 1024 * 1024,
        64 * 1024 * 1024,
        2 * 1024 * 1024,
        8,
    )
    .expect("migration budget")
}

fn install_legacy_genesis(
    repository: &CampaignRepository,
    roots: Option<CampaignRoots>,
) -> (CampaignSnapshotId, CampaignMigrationHead) {
    let current = repository.head(CAMPAIGN).expect("current head");
    let snapshot = LegacyCampaignSnapshot {
        parent: None,
        lineage: current.snapshot().lineage(),
        active_policy: current.snapshot().active_policy(),
        roots: roots.unwrap_or_else(|| current.snapshot().roots()),
        transition: None,
    };
    let content = repository
        .put_envelope(snapshot.envelope().expect("legacy envelope"))
        .expect("publish legacy envelope");
    let legacy = CampaignMigrationHead::from_content_id(content).expect("legacy snapshot ID");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(
                &campaign_ref(CAMPAIGN).expect("campaign ref"),
                Some(current.content_id()),
                content,
            )
            .expect("install legacy head"),
        RefCasOutcome::Advanced { .. }
    ));
    (current.snapshot_id(), legacy)
}

#[test]
fn explicit_migration_rewrites_and_publishes_one_current_genesis() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let (_, legacy) = install_legacy_genesis(&repository, None);

    repository
        .head(CAMPAIGN)
        .expect_err("normal reads reject an unmigrated head");
    let result = repository
        .migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(100_000))
                .expect("migration request"),
        )
        .expect("migrate legacy campaign");

    assert_eq!(result.prior_head(), legacy);
    assert_ne!(result.new_head().content_id(), legacy.content_id());
    assert_eq!(result.ancestry(), 1);
    assert!(result.input_objects() > 1);
    assert!(result.output_objects() > 1);
    assert!(result.mapped_entries() > 0);
    let current = repository.head(CAMPAIGN).expect("current migrated head");
    assert_eq!(current.snapshot_id(), result.new_head());
    assert_eq!(current.snapshot_id().content_id().schema_version(), 3);
    let ledger = repository
        .read_budget_ledger(current.snapshot().budget_ledger())
        .expect("current budget ledger");
    repository
        .merkle
        .inspect_shallow(ledger.request_spending())
        .expect("current request-spending index");
}

#[test]
fn migration_budget_exhaustion_leaves_the_ref_unchanged() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let (_, legacy) = install_legacy_genesis(&repository, None);

    assert!(matches!(
        repository.migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(1))
                .expect("migration request")
        ),
        Err(CampaignRepositoryError::MigrationBudgetExceeded {
            limit: CampaignMigrationLimit::InputObjects
        })
    ));
    assert_eq!(
        repository
            .refs
            .read_ref(&campaign_ref(CAMPAIGN).expect("campaign ref"))
            .expect("read unchanged ref"),
        Some(legacy.content_id())
    );
}

#[test]
fn migration_head_is_the_only_typed_admission_for_a_historical_snapshot() {
    let content = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 2, b"historical snapshot");
    let migration = CampaignMigrationHead::from_content_id(content).expect("migration head");

    assert_eq!(
        CampaignMigrationHead::parse(&migration.to_text()).expect("parsed migration head"),
        migration
    );
    assert!(CampaignSnapshotId::from_content_id(content).is_err());
    assert!(
        CampaignMigrationHead::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            3,
            b"current snapshot",
        ))
        .is_err()
    );
}

#[test]
fn normal_typed_ids_reject_every_migration_owned_schema() {
    let id =
        |kind: ObjectKind, version: u32, label: &[u8]| ContentId::for_bytes(kind, version, label);

    assert!(
        CampaignBudgetLedgerId::from_content_id(id(
            ObjectKind::CampaignFact,
            1,
            b"historical ledger",
        ))
        .is_err()
    );
    assert!(
        PlannerStepId::from_content_id(
            id(ObjectKind::CampaignFact, 3, b"historical planner step",)
        )
        .is_err()
    );
    assert!(
        BranchPathId::from_content_id(id(ObjectKind::CampaignFact, 1, b"historical branch path",))
            .is_err()
    );
    assert!(
        AttemptAdmissionId::from_content_id(id(
            ObjectKind::CampaignFact,
            2,
            b"historical admission",
        ))
        .is_err()
    );
    assert!(
        FindingId::from_content_id(id(ObjectKind::Finding, 3, b"historical finding",)).is_err()
    );
    assert!(
        MeasurementSetId::from_content_id(id(
            ObjectKind::Observation,
            1,
            b"historical measurements",
        ))
        .is_err()
    );
    assert!(
        PlannerCandidateGuidanceId::from_content_id(id(
            ObjectKind::Projection,
            1,
            b"historical guidance",
        ))
        .is_err()
    );
    assert!(
        PlannerCandidateBudgetId::from_content_id(id(
            ObjectKind::Projection,
            1,
            b"historical budget",
        ))
        .is_err()
    );
}

#[test]
fn unverifiable_legacy_measurements_are_rejected_before_publication() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    let current = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let mut body = Encoder::new();
    1_u32.encode(&mut body);
    BTreeMap::<String, u8>::new().encode(&mut body);
    let measurement = repository
        .put_envelope(
            ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::MeasurementSet,
                1,
                BTreeSet::new(),
                body.finish(),
            )
            .expect("legacy measurement envelope"),
        )
        .expect("publish legacy measurement");
    let mut roots = current.snapshot().roots();
    roots.observations = repository
        .merkle
        .insert(
            roots.observations,
            map_key_content("observations.measurement", measurement),
            measurement,
        )
        .expect("reference legacy measurement")
        .content_id();
    let (_, legacy) = install_legacy_genesis(&repository, Some(roots));

    assert!(matches!(
        repository.migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(100_000))
                .expect("migration request")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "legacy-measurement-set-has-no-verifiable-evaluation"
        })
    ));
    assert_eq!(
        repository
            .refs
            .read_ref(&campaign_ref(CAMPAIGN).expect("campaign ref"))
            .expect("read unchanged ref"),
        Some(legacy.content_id())
    );
}

#[test]
fn unscoped_legacy_branch_paths_are_rejected_before_publication() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    let current = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let mut body = Encoder::new();
    1_u32.encode(&mut body);
    Vec::<crate::BranchEdgeId>::new().encode(&mut body);
    let path = repository
        .put_envelope(
            ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::BranchPath,
                1,
                BTreeSet::new(),
                body.finish(),
            )
            .expect("legacy branch-path envelope"),
        )
        .expect("publish legacy branch path");
    let mut roots = current.snapshot().roots();
    roots.graph = repository
        .merkle
        .insert(roots.graph, map_key_content("graph.path", path), path)
        .expect("reference legacy branch path")
        .content_id();
    let (_, legacy) = install_legacy_genesis(&repository, Some(roots));

    assert!(matches!(
        repository.migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(100_000))
                .expect("migration request")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "obsolete-campaign-record-has-no-current-translation"
        })
    ));
    assert_eq!(
        repository
            .refs
            .read_ref(&campaign_ref(CAMPAIGN).expect("campaign ref"))
            .expect("read unchanged ref"),
        Some(legacy.content_id())
    );
}

#[test]
fn obsolete_packaged_planner_engines_are_rejected_before_publication() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    let current = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let engine = crate::PlannerEngine::new(
        "crucible-canonical-frontier",
        7,
        1,
        BTreeSet::from([
            crate::CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned(),
            crate::CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned(),
            crate::CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY.to_owned(),
        ]),
    )
    .expect("obsolete packaged engine");
    let engine = repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerEngine,
                BTreeSet::new(),
                crate::codec::encode(&engine),
            )
            .expect("planner engine envelope"),
        )
        .expect("publish obsolete planner engine");
    let mut roots = current.snapshot().roots();
    roots.coordination = repository
        .merkle
        .insert(
            roots.coordination,
            map_key_content("coordination.engine", engine),
            engine,
        )
        .expect("reference obsolete planner engine")
        .content_id();
    let (_, legacy) = install_legacy_genesis(&repository, Some(roots));

    assert!(matches!(
        repository.migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(100_000))
                .expect("migration request")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "obsolete-packaged-planner-engine-is-not-migratable"
        })
    ));
    assert_eq!(
        repository
            .refs
            .read_ref(&campaign_ref(CAMPAIGN).expect("campaign ref"))
            .expect("read unchanged ref"),
        Some(legacy.content_id())
    );
}

#[test]
fn obsolete_scenario_payloads_are_rejected_before_publication() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    let current = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let artifact = crate::ScenarioArtifact::new(
        lineage.scenario(),
        1,
        b"crucible.scenario-def-form.v6\0historical".to_vec(),
    )
    .expect("obsolete scenario artifact");
    let artifact = repository
        .put_scenario_artifact(&artifact)
        .expect("publish obsolete scenario artifact");
    let mut roots = current.snapshot().roots();
    roots.graph = repository
        .merkle
        .insert(
            roots.graph,
            map_key_content("graph.scenario-artifact", artifact),
            artifact,
        )
        .expect("reference obsolete scenario artifact")
        .content_id();
    let (_, legacy) = install_legacy_genesis(&repository, Some(roots));

    assert!(matches!(
        repository.migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(100_000))
                .expect("migration request")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "obsolete-scenario-payload-is-not-migratable"
        })
    ));
    assert_eq!(
        repository
            .refs
            .read_ref(&campaign_ref(CAMPAIGN).expect("campaign ref"))
            .expect("read unchanged ref"),
        Some(legacy.content_id())
    );
}

#[test]
fn obsolete_reproduction_payloads_are_rejected_before_publication() {
    let (repository, lineage, policy) = crate::repository::tests::fixture();
    let current = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create current campaign");
    let artifact = crate::ReproductionArtifact::new(
        lineage.scenario(),
        lineage.scenario_content(),
        lineage.genesis(),
        lineage.genesis_content(),
        CampaignHash::derive("test.obsolete-reproduction-fingerprint", b"historical"),
        1,
        b"crucible.reproduction-artifact.v5\0historical".to_vec(),
    )
    .expect("obsolete reproduction artifact");
    let artifact = repository
        .put_reproduction_artifact(&artifact)
        .expect("publish obsolete reproduction artifact");
    let mut roots = current.snapshot().roots();
    roots.findings = repository
        .merkle
        .insert(
            roots.findings,
            map_key_content("findings.reproduction", artifact),
            artifact,
        )
        .expect("reference obsolete reproduction artifact")
        .content_id();
    let (_, legacy) = install_legacy_genesis(&repository, Some(roots));

    assert!(matches!(
        repository.migrate_legacy_campaign(
            CampaignMigrationRequest::new(CAMPAIGN, legacy, migration_budget(100_000))
                .expect("migration request")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "obsolete-reproduction-payload-is-not-migratable"
        })
    ));
    assert_eq!(
        repository
            .refs
            .read_ref(&campaign_ref(CAMPAIGN).expect("campaign ref"))
            .expect("read unchanged ref"),
        Some(legacy.content_id())
    );
}
