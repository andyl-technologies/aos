//! Ready-for-PR verification of a final-gated candidate.
//!
//! `prepare-pr` owns the `final-gated -> ready-for-pr` transition. It reads the
//! check results the controller already retains for the current attempt and
//! verifies that they describe one completed candidate:
//!
//! - deterministic materialization of the plan's sources;
//! - the accepted repair lineage, when the candidate is a repair attempt;
//! - a fully successful quick gate set bound to the accepted patch digest;
//! - a fully successful final gate set bound to the exact candidate commit.
//!
//! Pull-request drafts and publications bind the canonical digest of the final
//! gate set, which in turn binds the candidate commit. No separate dossier is
//! written.

use anyhow::{Result, anyhow, bail};
use aos_core::Sha256Digest;
use aos_package_maintenance::PACKAGE_UPDATE_GATE_RESULTS_V1;
use aos_package_maintenance::identity::PlanId;
use aos_package_maintenance::plan::PackageUpdatePlanV1;
use aos_package_maintenance::run::{GateResultsV1, MaterializationRecordV1, PackageUpdateRunV1};
use aos_package_maintenance::workflow::{ActorClass, RunState};

use super::state::{self, StateStore};

/// Verified retained check results of one completed candidate.
pub(super) struct CompletedCandidate {
    /// Deterministic attempt-zero source materialization.
    pub(super) materialization: MaterializationRecordV1,
    /// Successful quick gates bound to the accepted patch.
    pub(super) quick_gates: GateResultsV1,
    /// Successful final gates bound to the exact candidate commit.
    pub(super) final_gates: GateResultsV1,
    /// Canonical digest of `final_gates`, bound by pull-request drafts and
    /// publications.
    pub(super) gate_results_digest: Sha256Digest,
}

/// Verifies a final-gated candidate and records it as ready for a pull request.
///
/// A run already in `ready-for-pr` is re-verified without a new transition, so
/// repeated PR preparation is idempotent.
///
/// # Errors
///
/// Returns an error when the run is in any other state, when its retained
/// check results do not form one completed candidate, or when the journal
/// transition cannot be recorded.
pub(super) fn mark_ready(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &mut PackageUpdateRunV1,
) -> Result<CompletedCandidate> {
    if !matches!(run.state, RunState::FinalGated | RunState::ReadyForPr) {
        bail!("PR preparation requires an exact-commit successful final gate set");
    }

    let candidate = completed_candidate(store, &plan.plan_id, run)?;

    if run.state == RunState::FinalGated {
        store.transition(
            run,
            RunState::ReadyForPr,
            ActorClass::Controller,
            state::now_unix()?,
        )?;
    }
    Ok(candidate)
}

/// Reads and cross-checks the retained check results of a committed candidate.
///
/// # Errors
///
/// Returns an error when a required record is missing or malformed, when the
/// records belong to another run, plan, or attempt, when the quick or final
/// gates did not all succeed, or when they bind another patch or commit.
pub(super) fn completed_candidate(
    store: &StateStore,
    plan_id: &PlanId,
    run: &PackageUpdateRunV1,
) -> Result<CompletedCandidate> {
    let run_id = run.run_id.as_str();
    let materialization = store
        .read_materialization(run_id)?
        .ok_or_else(|| anyhow!("materialization evidence is missing"))?;
    let repair_attempts = store.read_repair_attempts(run)?;
    let quick_gates = store
        .read_gate_results(run_id, "quick")?
        .ok_or_else(|| anyhow!("quick gate evidence is missing"))?;
    let final_gates = store
        .read_gate_results(run_id, "final")?
        .ok_or_else(|| anyhow!("final gate evidence is missing"))?;
    let candidate_commit = run
        .candidate_commit
        .as_ref()
        .ok_or_else(|| anyhow!("candidate commit identity is missing"))?;
    let patch_digest = run
        .accepted_candidate
        .ok_or_else(|| anyhow!("accepted patch identity is missing"))?;

    // The state store already ties gate sets to this run's current attempt and
    // the repair records to a contiguous lineage; these checks tie every record
    // to the same plan and to the accepted patch and committed head.
    let candidate_patch = repair_attempts
        .last()
        .map_or(materialization.patch_digest, |repair| {
            repair.candidate_digest
        });
    let commit_digest = Sha256Digest::separated(
        "aos.package-update-commit/v1",
        candidate_commit.value.as_bytes(),
    );
    if run.plan_id != *plan_id
        || materialization.plan_id != *plan_id
        || quick_gates.plan_id != *plan_id
        || final_gates.plan_id != *plan_id
        || candidate_patch != patch_digest
        || quick_gates.candidate_digest != patch_digest
        || final_gates.candidate_digest != commit_digest
        || !quick_gates.all_succeeded()
        || !final_gates.all_succeeded()
    {
        bail!("retained check results do not form one completed candidate");
    }

    let gate_results_digest =
        Sha256Digest::of_canonical(PACKAGE_UPDATE_GATE_RESULTS_V1, &final_gates)?;
    Ok(CompletedCandidate {
        materialization,
        quick_gates,
        final_gates,
        gate_results_digest,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aos_package_maintenance::envelope::{GitObjectFormat, GitObjectId};
    use aos_package_maintenance::identity::RunId;
    use aos_package_maintenance::run::{ConfinementEvidence, GateResult};
    use aos_package_maintenance::workflow::GateOutcome;
    use aos_package_maintenance::{PACKAGE_UPDATE_MATERIALIZATION_V1, PACKAGE_UPDATE_RUN_V1};

    use super::*;

    const COMMIT: &str = "1111111111111111111111111111111111111111";

    /// Retained records of one attempt-zero candidate that passed every gate.
    struct Fixture {
        _temporary: tempfile::TempDir,
        store: StateStore,
        run: PackageUpdateRunV1,
        plan_id: PlanId,
        materialization: MaterializationRecordV1,
        quick_gates: GateResultsV1,
        final_gates: GateResultsV1,
    }

    fn confinement() -> ConfinementEvidence {
        ConfinementEvidence {
            backend: "aos.linux-userns-landlock/v2".to_string(),
            landlock_abi: 4,
            filesystem_policy_digest: Sha256Digest::of_bytes(b"fs"),
            resource_limits_digest: Sha256Digest::of_bytes(b"limits"),
            private_user_namespace: true,
            private_process_namespaces: true,
            network_isolated: true,
            worker_tree_reaped: true,
            resource_limited: true,
            nix_sandbox_verified: true,
        }
    }

    fn gates(run: &PackageUpdateRunV1, phase: &str, candidate: Sha256Digest) -> GateResultsV1 {
        let log = phase.as_bytes();
        GateResultsV1 {
            schema: PACKAGE_UPDATE_GATE_RESULTS_V1.to_string(),
            run_id: run.run_id.clone(),
            plan_id: run.plan_id.clone(),
            attempt: run.attempt,
            phase: phase.to_string(),
            candidate_digest: candidate,
            confinement: confinement(),
            results: vec![GateResult {
                gate_id: "fmt".to_string(),
                argv: vec!["aos".to_string(), "fmt".to_string()],
                outcome: GateOutcome::Success,
                exit_code: Some(0),
                log_digest: Sha256Digest::separated("aos.package-update-gate-log/v1", log),
                log_bytes: log.len() as u64,
                elapsed_ms: 1,
            }],
            completed_at_unix: 10,
        }
    }

    fn write_gates(store: &StateStore, record: &GateResultsV1) -> Result<()> {
        let log = record.phase.as_bytes().to_vec();
        store.write_gate_results(record, &[("fmt".to_string(), log)])
    }

    fn fixture() -> Result<Fixture> {
        let temporary = tempfile::tempdir()?;
        let store = StateStore::open_fixture(temporary.path())?;
        let plan_id = PlanId::parse("plan-fixture")?;
        let patch = b"--- a/pkgs/fixture.nix\n+++ b/pkgs/fixture.nix\n";
        let patch_digest = Sha256Digest::separated("aos.package-update-patch/v1", patch);
        let run = PackageUpdateRunV1 {
            schema: PACKAGE_UPDATE_RUN_V1.to_string(),
            run_id: RunId::parse("run-fixture")?,
            plan_id: plan_id.clone(),
            plan_digest: Sha256Digest::of_bytes(b"plan"),
            state: RunState::FinalGated,
            branch: "dplecki/upgrade-fixture".to_string(),
            worktree: "/tmp/aos-maintain-readiness-fixture".to_string(),
            worktree_cleaned: false,
            accepted_candidate: Some(patch_digest),
            candidate_commit: Some(GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: COMMIT.to_string(),
            }),
            base_commit: GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: "0".repeat(40),
            },
            attempt: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        };
        fs::create_dir(store.root().join("repository/runs/run-fixture"))?;
        store.write_run(&run)?;

        let materialization = MaterializationRecordV1 {
            schema: PACKAGE_UPDATE_MATERIALIZATION_V1.to_string(),
            run_id: run.run_id.clone(),
            plan_id: plan_id.clone(),
            attempt: 0,
            sources: Vec::new(),
            artifacts: Vec::new(),
            confinement: confinement(),
            patch_digest,
            changed_paths: vec!["pkgs/fixture.nix".to_string()],
            completed_at_unix: 5,
        };
        store.write_materialization(&materialization, patch)?;

        let commit_digest =
            Sha256Digest::separated("aos.package-update-commit/v1", COMMIT.as_bytes());
        let quick_gates = gates(&run, "quick", patch_digest);
        let final_gates = gates(&run, "final", commit_digest);
        write_gates(&store, &quick_gates)?;
        write_gates(&store, &final_gates)?;

        Ok(Fixture {
            _temporary: temporary,
            store,
            run,
            plan_id,
            materialization,
            quick_gates,
            final_gates,
        })
    }

    #[test]
    fn completed_candidate_binds_the_final_gate_set() -> Result<()> {
        let fixture = fixture()?;

        let candidate = completed_candidate(&fixture.store, &fixture.plan_id, &fixture.run)?;

        assert_eq!(candidate.materialization, fixture.materialization);
        assert_eq!(candidate.quick_gates, fixture.quick_gates);
        assert_eq!(candidate.final_gates, fixture.final_gates);
        assert_eq!(
            candidate.gate_results_digest,
            Sha256Digest::of_canonical(PACKAGE_UPDATE_GATE_RESULTS_V1, &fixture.final_gates)?
        );
        Ok(())
    }

    #[test]
    fn completed_candidate_rejects_unbound_or_failed_checks() -> Result<()> {
        let fixture = fixture()?;
        let other_plan = PlanId::parse("plan-other")?;
        assert!(completed_candidate(&fixture.store, &other_plan, &fixture.run).is_err());

        let mut other_commit = fixture.run.clone();
        other_commit.candidate_commit = Some(GitObjectId {
            algorithm: GitObjectFormat::Sha1,
            value: "2".repeat(40),
        });
        assert!(completed_candidate(&fixture.store, &fixture.plan_id, &other_commit).is_err());

        let mut failed = fixture.final_gates.clone();
        failed.results[0].outcome = GateOutcome::Failure;
        failed.results[0].exit_code = Some(1);
        failed.completed_at_unix = 11;
        write_gates(&fixture.store, &failed)?;
        assert!(completed_candidate(&fixture.store, &fixture.plan_id, &fixture.run).is_err());
        Ok(())
    }
}
