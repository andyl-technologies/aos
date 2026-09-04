//! Complete local evidence construction and final consistency checks.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use aos_maintain::PACKAGE_UPDATE_EVIDENCE_V1;
use aos_maintain::plan::PackageUpdatePlanV1;
use aos_maintain::run::{PackageUpdateEvidenceV1, PackageUpdateRunV1};
use aos_maintain::workflow::{ActorClass, RunState, verify_journal};

use super::state::{self, StateStore};

/// Generates or reconciles the immutable final local evidence dossier.
///
/// # Errors
///
/// Returns an error unless the exact committed candidate has successful quick
/// and final gates and a verified journal prefix.
pub(super) fn generate(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &mut PackageUpdateRunV1,
) -> Result<(PackageUpdateEvidenceV1, Sha256Digest)> {
    if run.state == RunState::ReadyForPr {
        let evidence = store
            .read_evidence(run.run_id.as_str())?
            .ok_or_else(|| anyhow::anyhow!("ready run has no final evidence"))?;
        let digest = Sha256Digest::of_canonical(PACKAGE_UPDATE_EVIDENCE_V1, &evidence)?;
        if run.evidence_digest != Some(digest) {
            bail!("run projection disagrees with final evidence identity");
        }
        return Ok((evidence, digest));
    }
    if run.state != RunState::FinalGated {
        bail!("final evidence requires an exact-commit successful final gate set");
    }
    let events = store.read_journal(run.run_id.as_str())?;
    if verify_journal(&events)? != RunState::FinalGated {
        bail!("journal is not at the final-gated boundary");
    }
    let journal_tip = events
        .last()
        .map(|event| event.record_digest)
        .ok_or_else(|| anyhow::anyhow!("run journal is empty"))?;
    let materialization = store
        .read_materialization(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("materialization evidence is missing"))?;
    let repair_attempts = store.read_repair_attempts(run)?;
    let quick_gates = store
        .read_gate_results(run.run_id.as_str(), "quick")?
        .ok_or_else(|| anyhow::anyhow!("quick gate evidence is missing"))?;
    let final_gates = store
        .read_gate_results(run.run_id.as_str(), "final")?
        .ok_or_else(|| anyhow::anyhow!("final gate evidence is missing"))?;
    let candidate_commit = run
        .candidate_commit
        .clone()
        .ok_or_else(|| anyhow::anyhow!("candidate commit identity is missing"))?;
    let patch_digest = run
        .accepted_candidate
        .ok_or_else(|| anyhow::anyhow!("accepted patch identity is missing"))?;
    let evidence = PackageUpdateEvidenceV1 {
        schema: PACKAGE_UPDATE_EVIDENCE_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: plan.plan_id.clone(),
        attempt: run.attempt,
        plan_digest: run.plan_digest,
        base_commit: plan.base_commit.clone(),
        candidate_commit,
        patch_digest,
        materialization,
        repair_attempts,
        quick_gates,
        final_gates,
        journal_tip,
        completed_at_unix: state::now_unix()?,
    };
    evidence.validate()?;
    let digest = store.write_evidence(&evidence)?;
    run.evidence_digest = Some(digest);
    run.updated_at_unix = state::now_unix()?;
    store.write_run(run)?;
    store.transition(
        run,
        RunState::ReadyForPr,
        ActorClass::Controller,
        state::now_unix()?,
    )?;
    Ok((evidence, digest))
}
