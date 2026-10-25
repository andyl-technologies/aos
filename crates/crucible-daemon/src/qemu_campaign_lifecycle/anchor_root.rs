//! Anchor roots: replay worlds kept at a branch parent's network fault park.
//!
//! A branch attempt whose own selection is a recorded network fault branch at
//! its parent `A` has no exact retained source when `A` was never kept. Thin
//! replay of the attempt would cross exactly one host-proven exact boundary on
//! its way: the all-VM park at `A`, joined to the recorded frontier, just
//! before the branch is appended. The fresh runner can stop replay there and
//! keep that world as an ordinary published-boundary root:
//!
//! ```text
//! preconditions (no effects)
//!   -> fresh lifecycle for the attempt's own target
//!   -> start replay with an anchor stop at A
//!   -> every VM parked, exact-checkpoint ready, network queues empty
//!   -> non-destructive final drain proves no entries remain
//!   -> rebind and prepare the world as a source at A
//!   -> authenticate the prepared world against the replay proof
//!   -> pool admission with one child of headroom, Thin(A) persisted first
//! ```
//!
//! The anchor's thin fallback names `A`'s stored configuration artifact,
//! which already exists because an accepted observation published `A`, so
//! admission happens at once rather than after a later disposition. Anchoring
//! never produces a semantic result. Once a root is kept, the router ends
//! the execution and the attempt's next execution runs as a hot child of the
//! root; when anything here declines, the attempt replays thin.
//!
//! A decline leaves no root and no product, but it is not free: the
//! anchoring replay has already charged its quanta to the current execution
//! and spent wall time. Every check that needs no lifecycle, including the
//! pool's state at the root coordinate and the attempt's one anchor claim,
//! therefore runs before replay starts.

use std::io::Write;

use super::*;
use crate::QemuSavepointReplayProof;
use crate::qemu_hot_fork_source_capture::{
    AuthenticatedPublishedRootQemuHotForkSource, QemuPublishedRootOrigin,
    QemuPublishedRootProvenance,
};

/// Result of trying to keep an anchor root for one branch attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QemuAnchorRootOutcome {
    /// No anchor was kept; the stable token names the first refusal.
    Declined(&'static str),
    /// A root at the attempt's parent is now reusable from the pool.
    ///
    /// The root is either the one just admitted or an equal root that was
    /// already retained.
    Admitted,
}

/// Lower-tier runners that may keep an anchor root before thin replay.
///
/// Runners without the capability decline every attempt.
pub(crate) trait QemuAnchorRootMaterializer: CrucibleExecutionRunner {
    /// Tries to keep a root at the attempt's network fault branch parent.
    ///
    /// # Errors
    ///
    /// Returns a classified failure when:
    ///
    /// - the anchoring lifecycle cannot be started, with the lifecycle
    ///   factory's own class, which may be retryable;
    /// - the attempt is canceled during the anchoring replay;
    /// - the final drain of the replayed world fails, or shutting down an
    ///   anchoring world that is not kept fails (terminal cleanup failures);
    /// - a prepared world that does not match the replay, or a root the pool
    ///   refused, cannot be retired, or the pool cannot settle the admission
    ///   (terminal retention failures).
    ///
    /// Every other refusal, including any authoritative replay failure that
    /// thin replay will reproduce, is [`QemuAnchorRootOutcome::Declined`].
    fn materialize_anchor_root(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuAnchorRootOutcome, AttemptWorkerFailure<Self::Error>> {
        let _ = context;
        Ok(declined(input, None, "anchor-runner-unsupported"))
    }
}

/// Eligibility proven before any anchoring lifecycle exists.
struct QemuAnchorPlan {
    sink: Arc<dyn QemuPublishedRootSink>,
    /// The pool coordinate a root at `anchor` occupies.
    key: crate::QemuHotForkSourceWorldKey,
    /// The attempt across executions, for its one anchor claim.
    attempt: crate::AttemptExecutionKey,
    /// The branch parent `A`, where replay stops.
    anchor: Configuration,
    /// The stored artifact that published `A`, the root's thin fallback.
    published: crucible_campaign::ConfigurationArtifactId,
    /// The attempt's own target, whose lifecycle configuration replays `A`.
    selected: Configuration,
    branch: crucible::NetworkFaultCampaignBranch,
}

type AnchorFailure<F, D> = AttemptWorkerFailure<
    QemuFreshExecutionRunnerError<
        <F as QemuFreshAttemptLifecycleFactory>::Error,
        <D as QemuFreshAttemptDriver>::Error,
    >,
>;

impl<F, D> QemuAnchorRootMaterializer for QemuFreshExecutionRunner<F, D>
where
    F: QemuFreshAttemptLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    fn materialize_anchor_root(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuAnchorRootOutcome, AnchorFailure<F, D>> {
        // Anchoring is part of published-root retention and off without it.
        let Some(sink) = self.published_root_retention.clone() else {
            return Ok(declined(input, None, "anchor-retention-disabled"));
        };
        let plan = match anchor_plan(sink, input, context) {
            Ok(plan) => plan,
            Err(reason) => return Ok(declined(input, None, reason)),
        };
        // The pool is asked before any replay. An invalidated root keeps its
        // coordinate, so replaying would only end in a refused admission; a
        // live root already serves the attempt. Every path to an admitted
        // outcome spends the attempt's one anchor claim, so an attempt that
        // still declines hot after anchoring runs thin instead of anchoring
        // again.
        match plan.sink.root_state(&plan.key) {
            QemuPublishedRootState::Unusable => {
                return Ok(declined(
                    input,
                    Some(&plan.anchor),
                    "anchor-root-invalidated",
                ));
            }
            QemuPublishedRootState::Live => {
                if !plan.sink.claim_anchor(plan.attempt) {
                    return Ok(declined(
                        input,
                        Some(&plan.anchor),
                        "anchor-already-attempted",
                    ));
                }
                record_anchor_decision(
                    input,
                    Some(&plan.anchor),
                    "admitted",
                    &"anchor-root-retained".into(),
                );
                return Ok(QemuAnchorRootOutcome::Admitted);
            }
            QemuPublishedRootState::Absent => {}
        }
        if !plan.sink.may_admit() {
            return Ok(declined(input, Some(&plan.anchor), "anchor-pool-full"));
        }
        if !plan.sink.claim_anchor(plan.attempt) {
            return Ok(declined(
                input,
                Some(&plan.anchor),
                "anchor-already-attempted",
            ));
        }

        self.lifecycles.configure_attempt_continuations(&[]);
        self.lifecycles.configure_authenticated_start(input.start());
        let scenario = input.scenario().scenario_def();
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                input.scenario(),
                &plan.selected,
                input.signal_fault_replay(),
                context,
            )
            .map_err(map_fresh_lifecycle_failure)?;

        let proof =
            match replay_to_anchor::<F::Error, D::Error>(&mut lifecycle, input, context, &plan) {
                Ok(Ok(proof)) => proof,
                Ok(Err(reason)) => {
                    shut_down_anchor(&mut lifecycle)?;
                    return Ok(declined(input, Some(&plan.anchor), reason));
                }
                Err(failure) => {
                    shut_down_anchor(&mut lifecycle)?;
                    // Thin replay reproduces any authoritative replay failure;
                    // only cancellation belongs to the attempt itself.
                    if matches!(failure, AttemptWorkerFailure::Canceled(_)) {
                        return Err(failure);
                    }
                    return Ok(declined(
                        input,
                        Some(&plan.anchor),
                        HotForkRefusal::with_detail(
                            "anchor-replay-failed",
                            anchor_replay_failure_detail(&failure),
                        ),
                    ));
                }
            };

        match lifecycle.drain_final_events_for_retention() {
            Ok(QemuFinalBoundaryDrain::Retainable) => {}
            Ok(QemuFinalBoundaryDrain::Drained(_) | QemuFinalBoundaryDrain::Ineligible(_)) => {
                shut_down_anchor(&mut lifecycle)?;
                return Ok(declined(
                    input,
                    Some(&plan.anchor),
                    "anchor-boundary-not-retainable",
                ));
            }
            Err(error) => {
                let _cleanup = lifecycle.shutdown();
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::Cleanup(error),
                ));
            }
        }

        let world = match self.lifecycles.prepare_retained_source(
            lifecycle,
            input.scenario(),
            &plan.anchor,
            input.signal_fault_replay(),
        ) {
            QemuRetainedSourcePreparation::Prepared(world) => world,
            QemuRetainedSourcePreparation::Recovered(mut lifecycle) => {
                shut_down_anchor(&mut lifecycle)?;
                return Ok(declined(
                    input,
                    Some(&plan.anchor),
                    "anchor-source-preparation-declined",
                ));
            }
            QemuRetainedSourcePreparation::Quarantined => {
                record_anchor_decision(
                    input,
                    Some(&plan.anchor),
                    "quarantined",
                    &"anchor-source-preparation-failed".into(),
                );
                return Ok(QemuAnchorRootOutcome::Declined(
                    "anchor-source-preparation-failed",
                ));
            }
        };
        if let Some(reason) = anchor_world_mismatch(&world, &plan, proof, input) {
            world.retire().map_err(|error| {
                AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::PublishedRootRetention(error.to_string()),
                )
            })?;
            return Ok(declined(input, Some(&plan.anchor), reason));
        }

        admit_anchor(plan, *world, input)
    }
}

/// Returns the anchor plan or the stable token of the first refusal.
fn anchor_plan(
    sink: Arc<dyn QemuPublishedRootSink>,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
) -> Result<QemuAnchorPlan, HotForkRefusal> {
    let CrucibleResolvedAttemptStart::Branch {
        parent, selected, ..
    } = input.start()
    else {
        return Err("anchor-not-branch-start".into());
    };
    let crucible_campaign::AttemptStart::Branch {
        parent: published, ..
    } = input.attempt().start()
    else {
        return Err("anchor-not-branch-start".into());
    };
    let continuation_free = input.attempt().continuation_input().is_none()
        && validated_attempt_continuations(input)
            .is_ok_and(|continuations| continuations.controls().is_empty());
    let refusal = [
        (!continuation_free, "anchor-continuation-input"),
        (
            context.start_mode() != AttemptStartMode::Execute,
            "anchor-start-mode-not-execute",
        ),
        (
            context.resume_checkpoint().is_some(),
            "anchor-resume-checkpoint",
        ),
        (
            context.cancellation().is_canceled(),
            "anchor-attempt-canceled",
        ),
        (parent.is_genesis(), "anchor-parent-is-genesis"),
    ]
    .into_iter()
    .find_map(|(refused, reason)| refused.then_some(reason));
    if let Some(reason) = refusal {
        return Err(reason.into());
    }

    // Only the recorded network fault branch at the parent leaves a joined,
    // exact-ready park on the replay path to the attempt.
    let branch = recorded_branch_at(input, parent)
        .filter(|branch| {
            selected
                .schedule
                .decision_history()
                .get(parent.schedule.len())
                == Some(branch.decision())
        })
        .ok_or("anchor-parent-not-network-branch")?
        .clone();
    if unsupported_fresh_replay_decision(selected, input.signal_fault_replay()).is_some() {
        return Err("anchor-unsupported-replay-decision".into());
    }
    // The attempt will run as a child of the root, so its edge must pass the
    // very predicate the hot factory applies to children of published roots.
    // That also refuses a signal-fault branch still pending at the parent,
    // which would keep the boundary from being exact-ready.
    let edge = parent.schedule.len();
    if crate::qemu_hot_fork_world_factory::configuration_carried_decision(
        input, selected, edge, edge,
    )
    .is_some()
    {
        return Err("anchor-edge-not-replayable".into());
    }

    let lineage = input.lineage().id().map_err(|error| {
        HotForkRefusal::with_detail("anchor-lineage-identity-unavailable", error)
    })?;
    let basis = context
        .runtime_basis()
        .ok_or("anchor-runtime-basis-absent")?;
    if basis.key().lineage() != lineage {
        return Err("anchor-runtime-basis-lineage-mismatch".into());
    }

    Ok(QemuAnchorPlan {
        sink,
        key: crate::QemuHotForkSourceWorldKey::new_published(
            lineage,
            parent.def.id(),
            parent.id(),
            crucible_campaign::ExecutorCompatibilityProfile::from_lineage(input.lineage()),
        ),
        attempt: basis.key(),
        anchor: parent.clone(),
        published,
        selected: selected.clone(),
        branch,
    })
}

/// Replays from genesis to the anchor and seals its boundary proof.
///
/// Returns a refusal when replay reached the anchor but its boundary is not
/// the exact, quiet park a root may keep. A check that could not run carries
/// its error text.
fn replay_to_anchor<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    plan: &QemuAnchorPlan,
) -> Result<
    Result<QemuSavepointReplayProof, HotForkRefusal>,
    AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
> {
    let start = QemuFreshStartMaterialization::at_quanta(lifecycle.completed_quanta())
        .with_anchor_stop(plan.anchor.id());
    let replay = materialize_start_from::<F, D>(
        lifecycle,
        input,
        Configuration::genesis(plan.selected.def.clone()),
        &plan.selected,
        context,
        start,
    )?;
    if !replay.anchor_reached() || replay.restored_configuration() != Some(&plan.anchor) {
        return Ok(Err("anchor-boundary-not-reached".into()));
    }
    if lifecycle.completed_quanta() != replay.completed_quanta {
        return Ok(Err("anchor-quantum-coordinate-mismatch".into()));
    }

    // Thin replay never checks these at a crossed park; a kept world must
    // hold every VM parked at an exact-ready boundary with quiet queues,
    // exactly as the modeled driver requires before it offers the choice.
    match every_vm_parked_for::<F, D>(lifecycle, input, &plan.branch) {
        Ok(true) => {}
        Ok(false) => return Ok(Err("anchor-boundary-not-parked".into())),
        Err(failure) => {
            return Ok(Err(HotForkRefusal::with_detail(
                "anchor-boundary-not-parked",
                anchor_replay_failure_detail(&failure),
            )));
        }
    }
    let exact_ready = lifecycle
        .exact_checkpoint_ready()
        .and_then(|ready| Ok(ready && lifecycle.campaign_network_queues_empty()?));
    match exact_ready {
        Ok(true) => {}
        Ok(false) => return Ok(Err("anchor-boundary-not-exact-ready".into())),
        Err(error) => {
            return Ok(Err(HotForkRefusal::with_detail(
                "anchor-boundary-not-exact-ready",
                error,
            )));
        }
    }
    // RUN grouping is identical with or without the choice-free boot mark.
    // Anchors still stay outside the audited boot prefix, whose replay
    // re-arms that mark's fail-closed choice check.
    match crate::qemu_campaign_driver::envoy_choice_free_boot_replay_eligible(
        input,
        &replay.event_log,
    ) {
        Ok(false) => {}
        Ok(true) => return Ok(Err("anchor-parallel-boot-active".into())),
        Err(error) => {
            return Ok(Err(HotForkRefusal::with_detail(
                "anchor-parallel-boot-active",
                error,
            )));
        }
    }

    // The scheduler's segment chain and the replay's retained log must count
    // the same events; a refusal names both sides.
    let offset = match lifecycle.event_log_offset() {
        Ok(offset) => offset,
        Err(error) => {
            return Ok(Err(HotForkRefusal::with_detail(
                "anchor-replay-proof-unavailable",
                format!("offset: {error}"),
            )));
        }
    };
    let proof = QemuSavepointReplayProof::from_retained_boundary(
        &plan.anchor,
        replay.completed_quanta,
        replay.frontier,
        &replay.event_log,
    )
    .and_then(|proof| proof.with_event_log_offset(offset));
    Ok(proof.map_err(|error| {
        HotForkRefusal::with_detail(
            "anchor-replay-proof-unavailable",
            format!(
                "{error}; offset_events={} retained_events={}",
                offset.events,
                replay.event_log.len()
            ),
        )
    }))
}

/// Returns why a prepared world differs from the replayed anchor boundary.
fn anchor_world_mismatch(
    world: &crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld,
    plan: &QemuAnchorPlan,
    proof: QemuSavepointReplayProof,
    input: &CrucibleAttemptExecution,
) -> Option<&'static str> {
    let continuation = world.continuation();
    if continuation.configuration() != &plan.anchor {
        return Some("anchor-prepared-configuration-mismatch");
    }
    if continuation.configuration().def.id() != input.scenario().scenario_def().id() {
        return Some("anchor-prepared-scenario-mismatch");
    }
    if !proof.matches_checkpoint(
        continuation.configuration(),
        continuation.scheduler(),
        continuation.event_log_segments(),
    ) {
        return Some("anchor-prepared-boundary-mismatch");
    }
    if continuation.terminal_verdict().is_some() {
        return Some("anchor-prepared-terminal-verdict");
    }
    None
}

/// Offers an authenticated anchor world to the pool.
fn admit_anchor<FE, DE>(
    plan: QemuAnchorPlan,
    world: crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld,
    input: &CrucibleAttemptExecution,
) -> Result<QemuAnchorRootOutcome, AttemptWorkerFailure<QemuFreshExecutionRunnerError<FE, DE>>> {
    // The whole prefix to the anchor ran under the attempt's own replay mode.
    let provenance = QemuPublishedRootProvenance::new(
        QemuPublishedRootOrigin::BranchParentAnchor,
        plan.anchor.clone(),
        Some(replay_pauses_before_live_network_choice(&plan.selected)),
    );
    let root = AuthenticatedPublishedRootQemuHotForkSource::new(
        plan.key,
        plan.published,
        world,
        provenance,
    );

    let admission = plan.sink.admit_anchor(root).map_err(|error| {
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::PublishedRootRetention(
            error.to_string(),
        ))
    })?;
    Ok(match admission {
        QemuPublishedRootAdmission::Admitted => {
            record_anchor_decision(
                input,
                Some(&plan.anchor),
                "admitted",
                &"anchor-admitted".into(),
            );
            QemuAnchorRootOutcome::Admitted
        }
        QemuPublishedRootAdmission::AlreadyRetained => {
            record_anchor_decision(
                input,
                Some(&plan.anchor),
                "admitted",
                &"anchor-duplicate-root".into(),
            );
            QemuAnchorRootOutcome::Admitted
        }
        QemuPublishedRootAdmission::Rejected(reason) => {
            let token = if reason.starts_with("anchor-child-capacity") {
                "anchor-child-capacity"
            } else {
                "anchor-pool-rejected"
            };
            record_anchor_decision(
                input,
                Some(&plan.anchor),
                "rejected",
                &HotForkRefusal::with_detail(token, reason),
            );
            QemuAnchorRootOutcome::Declined(token)
        }
    })
}

/// Shuts down an anchoring world that is not kept.
///
/// Its final entries belong to no product, so they are discarded.
fn shut_down_anchor<L, FE, DE>(
    lifecycle: &mut L,
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<FE, DE>>>
where
    L: QemuFreshAttemptLifecycleOwner + ?Sized,
{
    lifecycle
        .shutdown()
        .map(|_final_entries| ())
        .map_err(|error| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Cleanup(error))
        })
}

/// Describes an anchor replay failure that the decline would otherwise hide.
fn anchor_replay_failure_detail<FE, DE>(
    failure: &AttemptWorkerFailure<QemuFreshExecutionRunnerError<FE, DE>>,
) -> String {
    let (AttemptWorkerFailure::Retryable(error)
    | AttemptWorkerFailure::Terminal(error)
    | AttemptWorkerFailure::Canceled(error)) = failure;
    // Lifecycle and driver errors carry no formatting bound here; the start
    // replay error is the one that names a divergence.
    match error {
        QemuFreshExecutionRunnerError::StartReplay(replay) => format!("start-replay: {replay}"),
        QemuFreshExecutionRunnerError::Lifecycle(_) => String::from("lifecycle failure"),
        QemuFreshExecutionRunnerError::Driver(_) => String::from("driver failure"),
        QemuFreshExecutionRunnerError::Cleanup(error) => format!("cleanup: {error}"),
        _ => String::from("runner failure"),
    }
}

/// Records one decline and returns it as the outcome.
fn declined(
    input: &CrucibleAttemptExecution,
    anchor: Option<&Configuration>,
    refusal: impl Into<HotForkRefusal>,
) -> QemuAnchorRootOutcome {
    let refusal = refusal.into();
    record_anchor_decision(input, anchor, "declined", &refusal);
    QemuAnchorRootOutcome::Declined(refusal.reason())
}

/// Writes one bounded operational anchor diagnostic.
///
/// A refusal whose check failed to run appends its error text:
///
/// ```text
/// CRUCIBLE-HOT-FORK-ANCHOR-V1 attempt=<id> anchor=<configuration-hex> decision=<decision> reason=<token>[ detail="<error>"]
/// ```
fn record_anchor_decision(
    input: &CrucibleAttemptExecution,
    anchor: Option<&Configuration>,
    decision: &str,
    refusal: &HotForkRefusal,
) {
    let attempt = input
        .attempt()
        .id()
        .map_or_else(|_| String::from("unavailable"), |id| id.to_string());
    let anchor = anchor.map_or_else(|| String::from("none"), |anchor| anchor.id().to_hex());
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-ANCHOR-V1 attempt={attempt} anchor={anchor} decision={decision} {refusal}"
    );
}
