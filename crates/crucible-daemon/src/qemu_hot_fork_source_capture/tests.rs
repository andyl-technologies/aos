//! Authenticated production source-basis regressions.

// crucible-lint: allow panic-shortcut -- fixture construction and assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::Configuration;
use crucible_campaign::{
    CampaignExecutorStore, CampaignLineage, CampaignMode, CampaignPolicy, CampaignRepository,
    CampaignSeed, ExactRational, ExecutorCompatibilityProfile, ExplorerPolicy, FairnessPolicy,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

use super::*;
use crate::{encode_crucible_configuration_artifact, encode_crucible_scenario_artifact};

fn authenticated_lineage_fixture() -> (CampaignExecutorStore, CampaignLineage) {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "hot-fork-source-basis",
            16 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("encode scenario artifact");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish scenario artifact");
    let genesis = Configuration::genesis(scenario.scenario_def());
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &genesis.schedule)
            .expect("encode genesis artifact");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            configuration_artifact.scenario_artifact(),
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish genesis artifact");
    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_content,
        configuration_artifact.configuration(),
        configuration_content,
        "crucible-source-basis-test",
        "qemu-source-basis-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("source basis lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening numerator"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    let policy = CampaignPolicy::new(
        scenario_artifact.scenario(),
        CampaignSeed::from_bytes([0x51; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("source basis policy");
    repository
        .create("hot-fork-source-basis", &lineage, &policy, &BTreeMap::new())
        .expect("create source basis campaign");

    (CampaignExecutorStore::new(repository), lineage)
}

#[test]
fn authenticated_source_basis_rejects_a_profile_relabel_before_launch() {
    let (store, lineage) = authenticated_lineage_fixture();
    let relabeled = ExecutorCompatibilityProfile::new(
        lineage.crucible_version().to_owned(),
        "relabeled-qemu-build",
        lineage.protocol_versions().clone(),
        lineage.scenario_schema(),
        lineage.exact_closure_schema(),
    )
    .expect("relabeled compatibility profile");

    let error = match AuthenticatedQemuHotForkSourceBasis::authenticate(
        &store,
        lineage.id().expect("lineage id"),
        &relabeled,
    ) {
        Ok(_) => panic!("a relabeled packaged profile must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        AuthenticatedQemuHotForkSourceBasisError::ProfileMismatch { .. }
    ));
}

#[test]
fn authenticated_source_basis_retains_exact_genesis_and_thin_fallback() {
    let (store, lineage) = authenticated_lineage_fixture();
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let basis = AuthenticatedQemuHotForkSourceBasis::authenticate(
        &store,
        lineage.id().expect("lineage id"),
        &profile,
    )
    .expect("authenticate canonical source basis");

    assert_eq!(basis.lineage(), &lineage);
    assert_eq!(basis.scenario_artifact(), lineage.scenario_content());
    assert_eq!(basis.source_artifact(), lineage.genesis_content());
    assert_eq!(
        basis.source(),
        &Configuration::genesis(basis.scenario().scenario_def())
    );
}
