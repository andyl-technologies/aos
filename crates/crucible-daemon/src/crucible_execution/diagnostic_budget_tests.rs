//! Process-local admission of real phase and materialization receipt producers.

// crucible-lint: allow clippy-disallowed-method -- subprocesses isolate the original environment-cached diagnostic budget.
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::process::Command;
use std::sync::Arc;

use crucible_campaign::{
    BudgetGrant, CampaignCommandId, CampaignControlAction, CampaignHash, CampaignMode,
    CampaignPolicy, CampaignRepository, CampaignSeed, ConfigurationId, ControlRequest,
    ExplorerPolicy, FairnessPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

use super::*;

const CHILD_SETTING: &str = "CRUCIBLE_MATERIALIZATION_BUDGET_TEST_CHILD";
const TEST_NAME: &str =
    "crucible_execution::diagnostic_budget_tests::phase_notices_preserve_the_later_tier_receipt";

#[test]
fn phase_notices_preserve_the_later_tier_receipt() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(CHILD_SETTING).is_some() {
        let input = repository_input()?;
        // A replay emits these original phase notices before its tier receipt.
        for _ in 0..16 {
            record_execution_phase_diagnostic("seal-test", format_args!("events=2224"));
        }
        record_materialization_diagnostic(&input, CrucibleMaterializationTier::ThinReplay);

        // The first seventeen records must not remove the original hard bound.
        for _ in 0..256 {
            record_execution_phase_diagnostic("after-tier", format_args!("events=2224"));
        }
        return Ok(());
    }

    for (budget, expected_phases, expected_receipts) in [("16", 16, 0), ("256", 255, 1)] {
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_SETTING, "1")
            .env("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS", budget)
            .output()?;
        assert!(output.status.success(), "diagnostic producer child failed");
        let stderr = std::str::from_utf8(&output.stderr)?;
        let phases = stderr
            .lines()
            .filter(|line| line.starts_with("CRUCIBLE-EXECUTION-PHASE-V1 "))
            .count();
        let receipts = stderr
            .lines()
            .filter(|line| line.starts_with("CRUCIBLE-MATERIALIZATION-V1 "))
            .collect::<Vec<_>>();
        assert_eq!(phases, expected_phases);
        assert_eq!(receipts.len(), expected_receipts);
        if let Some(receipt) = receipts.first() {
            let expected = format!(
                "CRUCIBLE-MATERIALIZATION-V1 attempt={} tier=ThinReplay",
                repository_input()?.attempt().id()?
            );
            assert_eq!(*receipt, expected);
        }
    }
    Ok(())
}

fn repository_input() -> Result<AttemptExecutionInput, Box<dyn Error>> {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("receipt-budget", 1024 * 1024)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("receipt-budget", b"scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("receipt-budget", b"genesis"));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, b"scenario".to_vec())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        b"genesis".to_vec(),
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-receipt-test",
        "qemu-receipt-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x74; 32]),
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
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )?;
    let created = repository.create("receipt-budget", &lineage, &policy, &BTreeMap::new())?;
    repository.apply_control(
        "receipt-budget",
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive("receipt-budget", b"fund")),
            expected_snapshot: created.snapshot_id(),
            action: CampaignControlAction::GrantBudget(BudgetGrant::new(0, 1)?),
        },
    )?;
    let head = repository.head("receipt-budget")?;
    repository.apply_control(
        "receipt-budget",
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "receipt-budget",
                b"resume",
            )),
            expected_snapshot: head.snapshot_id(),
            action: CampaignControlAction::Resume,
        },
    )?;
    let attempt = repository
        .admit_initial_discovery_if_ready("receipt-budget")?
        .ok_or("funded repository did not admit discovery")?;
    Ok(crate::resolve_attempt_execution_input(
        &CampaignExecutorStore::new(repository),
        crate::AttemptExecutionKey::new(lineage.id()?, attempt),
    )?)
}
