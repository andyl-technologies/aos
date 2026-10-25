//! Retention of a thin attempt's stopped world as a published-boundary root.
//!
//! A thin attempt that stops at a published next-choice boundary already owns
//! a complete live world at exactly the configuration later branches start
//! from. Instead of tearing it down, the fresh runner may keep it as a root
//! source for the hot-fork pool:
//!
//! ```text
//! drive -> terminal fingerprints -> final drain (non-destructive)
//!   empty drain:     seal(no final events) -> prepare source -> authenticate
//!                    -> pending root -> durable disposition
//!                       Observation: pool admission (Thin(child) persisted first)
//!                       otherwise:   retire
//!   nonempty drain:  shutdown -> seal(drained ++ shutdown events)
//!   ineligible:      shutdown -> seal(shutdown events)
//! ```
//!
//! Retention is purely operational. The sealed product is identical whether
//! or not the world is kept, because sealing receives no final events only
//! after the drain proved there were none, and every declined, failed, or
//! rejected retention reaches the same product through ordinary teardown or
//! retirement. Admission waits for the durable observation disposition
//! because the root's thin fallback names the stored child configuration
//! artifact, and fallback authentication reads that artifact.
//!
//! The same sink also admits anchor roots, which the fresh runner keeps at a
//! branch parent's network fault park before the branch runs (see
//! `anchor_root`). Their parent artifact is already stored, so they are
//! admitted at once, and only when the pool can still hold one child.

use std::io::Write;
use std::sync::Arc;

use crucible::{
    Configuration, ScenarioDefForm, SchedulerError, SchedulerEventLogEntry,
    SignalFaultCampaignReplayPlan,
};
use crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld;
use crucible_api::{ProductionVmLifecycleConfig, ProductionVmLifecycleLoop};
use crucible_campaign::{
    AttemptStartMode, CampaignHash, CampaignLineageId, ConfigurationId,
    ExecutorCompatibilityProfile,
};

use super::continuation::production_lifecycle_config_for_start;
use super::{AppRandomLaunchWindow, HotForkRefusal};
use super::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure,
    CrucibleAttemptExecution, CrucibleResolvedAttemptStart, QemuFreshAttemptDriver,
    QemuFreshAttemptLifecycleFactory, QemuFreshAttemptLifecycleOwner, QemuFreshExecutionRunner,
    QemuFreshExecutionRunnerError, QemuSavepointReplayProof, map_fresh_driver_failure,
};
use crate::qemu_hot_fork_source_capture::{
    AuthenticatedPublishedRootQemuHotForkSource, QemuPublishedRootOrigin,
    QemuPublishedRootProvenance,
};
use crate::{AttemptExecutionDisposition, AttemptExecutionKey, QemuHotForkSourceWorldKey};

/// Outcome of settling a stopped world's final boundary without teardown.
#[derive(Debug, PartialEq, Eq)]
pub enum QemuFinalBoundaryDrain {
    /// The boundary settled with no new entries; the world may be retained.
    Retainable,
    /// Entries were appended and must precede shutdown's entries when sealing.
    Drained(Vec<SchedulerEventLogEntry>),
    /// Nothing changed; ordinary shutdown must run as before.
    ///
    /// The stable kebab-case token names the first check that refused, for
    /// the retention diagnostic.
    Ineligible(&'static str),
}

/// Token for lifecycle owners that cannot keep their world at all.
pub(crate) const RETENTION_UNSUPPORTED_OWNER: &str = "lifecycle-owner-cannot-retain";

/// Result of preparing a drained lifecycle as a retained source.
pub(crate) enum QemuRetainedSourcePreparation<L> {
    /// The complete world is a prepared, paused source.
    Prepared(Box<ProductionVmHotForkSourceWorld>),
    /// Preparation declined or rolled back; the lifecycle must be shut down.
    Recovered(L),
    /// Preparation failed after mutating QEMU state; authority is quarantined.
    Quarantined,
}

/// Pool policy decision for one published root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QemuPublishedRootAdmission {
    /// The root is retained and reusable by later branches from its boundary.
    Admitted,
    /// An equal root is already retained; the candidate was retired.
    ///
    /// Branches from the boundary reuse the retained root, so for an anchor
    /// this is as good as admission.
    AlreadyRetained,
    /// Policy declined the root and it was retired; the reason is diagnostic.
    Rejected(String),
}

/// What the pool holds at one published-boundary root coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QemuPublishedRootState {
    /// No source occupies the coordinate.
    Absent,
    /// A source with exactly this key can lease another child.
    Live,
    /// The coordinate is occupied by a source that can serve no child.
    ///
    /// An invalidated source stays in place, holding its template slot, until
    /// orderly shutdown, so a new root at the same coordinate cannot be
    /// admitted either. A coordinate held under a different complete key is
    /// unusable for the same reason.
    Unusable,
}

/// A rejected or unadmittable root could not be retired completely.
///
/// The source's authority was transferred to process-lifetime quarantine.
#[derive(Debug, thiserror::Error)]
#[error("retire published-root source: {message}")]
pub(crate) struct QemuPublishedRootRetirementError {
    message: String,
}

impl QemuPublishedRootRetirementError {
    /// Records why a root's authority could not be released.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Managed pool admission for thin-attempt worlds kept at a published boundary.
pub(crate) trait QemuPublishedRootSink: Send + Sync {
    /// Reports whether the pool could currently admit another root at all.
    ///
    /// A false result lets the runner shut the world down instead of
    /// preparing a source it would only retire. The answer is advisory;
    /// admission rechecks every limit.
    fn may_admit(&self) -> bool;

    /// Reports what the pool holds at `key`'s coordinate.
    ///
    /// Anchoring asks before any replay: only a [`QemuPublishedRootState::Live`]
    /// root can serve the attempt, and an unusable coordinate can neither
    /// serve it nor accept a new root. Sinks that cannot read the pool answer
    /// [`QemuPublishedRootState::Unusable`], which declines.
    fn root_state(&self, key: &QemuHotForkSourceWorldKey) -> QemuPublishedRootState;

    /// Claims `attempt`'s only anchored execution, returning whether it was free.
    ///
    /// An admitted anchor ends its execution as retryable so the attempt runs
    /// again with a full budget from the kept root. The claim keeps that
    /// from repeating: an attempt that already anchored once runs thin when
    /// hot fork still declines. Claims span the sink's executions, not one
    /// runner, because a requeued attempt may land on any worker.
    fn claim_anchor(&self, attempt: AttemptExecutionKey) -> bool;

    /// Admits one authenticated root, retiring it when policy rejects it.
    ///
    /// The thin fallback for the root's published child artifact is persisted
    /// before the source becomes reusable.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPublishedRootRetirementError`] when a declined root could
    /// not be retired; its authority then remains quarantined.
    fn admit(
        &self,
        root: AuthenticatedPublishedRootQemuHotForkSource,
    ) -> Result<QemuPublishedRootAdmission, QemuPublishedRootRetirementError>;

    /// Admits one anchor root only when the pool could still lease it a child.
    ///
    /// An anchor exists only so the attempt that made it can fork from it, so
    /// the pool must hold the root plus one child reservation. A refusal for
    /// that reason is reported as `anchor-child-capacity`, and a root equal
    /// to one already retained as [`QemuPublishedRootAdmission::AlreadyRetained`].
    /// A coordinate held by an unusable source is refused as
    /// `anchor-root-invalidated`: it is not retained in any useful sense.
    /// Sinks without anchor support retire every anchor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPublishedRootRetirementError`] when a declined root could
    /// not be retired; its authority then remains quarantined.
    fn admit_anchor(
        &self,
        root: AuthenticatedPublishedRootQemuHotForkSource,
    ) -> Result<QemuPublishedRootAdmission, QemuPublishedRootRetirementError> {
        let (_key, _published, source, _provenance) = root.into_parts();
        source
            .retire()
            .map(|()| {
                QemuPublishedRootAdmission::Rejected(String::from("anchor-roots-unsupported"))
            })
            .map_err(|error| QemuPublishedRootRetirementError::new(error.to_string()))
    }
}

/// Eligibility proven before a thin attempt's final boundary is settled.
pub(super) struct QemuPublishedRootPlan {
    sink: Arc<dyn QemuPublishedRootSink>,
    lineage: CampaignLineageId,
    profile: ExecutorCompatibilityProfile,
    boundary: Configuration,
    proof: QemuSavepointReplayProof,
}

/// A retained world awaiting its attempt's durable disposition.
pub(super) struct QemuPendingPublishedRoot {
    sink: Arc<dyn QemuPublishedRootSink>,
    root: Box<AuthenticatedPublishedRootQemuHotForkSource>,
}

/// A sealed product and the root its world may have become.
pub(super) type QemuRetainedProduct = (AttemptExecutionProduct, Option<QemuPendingPublishedRoot>);

/// Where the retention path left one observed thin attempt.
pub(super) enum QemuPublishedRootAttempt<L, P, E> {
    /// Retention did not take the world; ordinary shutdown and sealing follow.
    Declined {
        lifecycle: L,
        pending: P,
        trace: Option<crucible::model::ResolvedEffectTrace>,
        /// Entries a nonempty final drain appended before shutdown.
        drained: Vec<SchedulerEventLogEntry>,
    },
    /// The attempt finished on the retention path, possibly with a pending root.
    Finished(Result<QemuRetainedProduct, E>),
}

type RunnerFailure<F, D> = AttemptWorkerFailure<
    QemuFreshExecutionRunnerError<
        <F as QemuFreshAttemptLifecycleFactory>::Error,
        <D as QemuFreshAttemptDriver>::Error,
    >,
>;

type RetentionAttempt<F, D> = QemuPublishedRootAttempt<
    <F as QemuFreshAttemptLifecycleFactory>::Lifecycle,
    <D as QemuFreshAttemptDriver>::Pending,
    RunnerFailure<F, D>,
>;

/// Rebinds and prepares one attempt-launched production world as a source.
///
/// Children forked from a source inherit its configuration, so the world is
/// rebound to exactly what an exact resume at `boundary` would use: the
/// boundary's own replay inputs, the attempt's network fault branches the
/// boundary has already committed, no attempt-start network selections or
/// signal-fault branches, and unbounded advance completion in place of the
/// attempt's watchdog deadline.
pub(super) fn prepare_production_retained_source(
    base: &ProductionVmLifecycleConfig,
    lifecycle: ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
    boundary: &Configuration,
    replay: &SignalFaultCampaignReplayPlan,
) -> QemuRetainedSourcePreparation<ProductionVmLifecycleLoop> {
    let boundary_replay = match boundary_network_replay(replay, boundary) {
        Ok(boundary_replay) => boundary_replay,
        Err(error) => {
            note_source_preparation_decline(&HotForkRefusal::with_detail(
                "source-network-replay-unavailable",
                error,
            ));
            return QemuRetainedSourcePreparation::Recovered(lifecycle);
        }
    };
    let config = match production_lifecycle_config_for_start(
        base,
        source,
        boundary,
        AppRandomLaunchWindow::RestoredTarget,
        boundary_replay.as_ref(),
        &[],
    ) {
        Ok(config) => config.with_unbounded_advance_completion(),
        Err(error) => {
            note_source_preparation_decline(&HotForkRefusal::with_detail(
                "source-config-unavailable",
                error,
            ));
            return QemuRetainedSourcePreparation::Recovered(lifecycle);
        }
    };
    match lifecycle.prepare_hot_fork_source_world_with_config(config) {
        Ok(world) => QemuRetainedSourcePreparation::Prepared(Box::new(world)),
        Err(failure) => {
            note_source_preparation_decline(&HotForkRefusal::with_detail(
                "source-preparation-failed",
                &failure,
            ));
            match failure.into_recovered_lifecycle() {
                Ok(lifecycle) => QemuRetainedSourcePreparation::Recovered(lifecycle),
                // Dropping the failure quarantines every source whose rollback
                // could not be attested; no live authority returns to the caller.
                Err(_failure) => QemuRetainedSourcePreparation::Quarantined,
            }
        }
    }
}

/// Returns the network fault replay an exact resume at `boundary` installs.
///
/// The world's network adapter has committed every branch of `replay` whose
/// decision `boundary` already contains, and the source rebind requires the
/// resume plan to name exactly those. Branches still ahead of the boundary
/// belong to the attempt, not to children of the source, and signal-fault
/// branches are already settled in the boundary's history. Returns `None`
/// when the boundary has committed no network fault branch.
///
/// # Errors
///
/// Returns [`crucible::NetworkFaultSelectableError`] when the committed
/// branches do not certify `boundary`.
pub(super) fn boundary_network_replay(
    replay: &SignalFaultCampaignReplayPlan,
    boundary: &Configuration,
) -> Result<Option<SignalFaultCampaignReplayPlan>, crucible::NetworkFaultSelectableError> {
    let history = boundary.schedule.decision_history();
    let committed = replay
        .network_branches()
        .iter()
        .filter(|branch| {
            let index = branch.parent().schedule.len();
            index < boundary.schedule.len() && history.get(index) == Some(branch.decision())
        })
        .cloned()
        .collect::<Vec<_>>();
    if committed.is_empty() {
        return Ok(None);
    }

    SignalFaultCampaignReplayPlan::empty(boundary.clone())
        .with_network_branches(committed)
        .map(Some)
}

/// Writes why a drained world could not become a retained source.
fn note_source_preparation_decline(refusal: &HotForkRefusal) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-SOURCE-PREPARATION-V1 {refusal}"
    );
}

impl<F, D> QemuFreshExecutionRunner<F, D>
where
    F: QemuFreshAttemptLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    /// Selects the managed pool that admits retained thin-attempt worlds.
    pub(crate) fn with_published_root_retention(
        mut self,
        sink: Arc<dyn QemuPublishedRootSink>,
    ) -> Self {
        self.published_root_retention = Some(sink);
        self
    }

    /// Checks every retention precondition that needs no lifecycle effect.
    ///
    /// Only ordinary executions of an authenticated discovery or branch start,
    /// with no continuation input, resume checkpoint, cancellation, or
    /// property failure, may keep their world. With retention enabled, every
    /// refusal writes one skipped diagnostic naming the failed check.
    pub(super) fn published_root_plan(
        &self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        continuation_free: bool,
        pending: &D::Pending,
    ) -> Option<QemuPublishedRootPlan> {
        let sink = self.published_root_retention.as_ref()?;
        let (lineage, boundary, proof) =
            match self.published_root_boundary(input, context, continuation_free, pending) {
                Ok(eligible) => eligible,
                Err(refusal) => {
                    record_retention_refusal("skipped", &refusal);
                    return None;
                }
            };
        if !sink.may_admit() {
            record_retention_decision("declined", "hot-fork pool has no free template slot");
            return None;
        }

        Some(QemuPublishedRootPlan {
            sink: Arc::clone(sink),
            lineage,
            profile: ExecutorCompatibilityProfile::from_lineage(input.lineage()),
            boundary,
            proof,
        })
    }

    /// Returns the retainable boundary or the stable token of the first refusal.
    fn published_root_boundary(
        &self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        continuation_free: bool,
        pending: &D::Pending,
    ) -> Result<(CampaignLineageId, Configuration, QemuSavepointReplayProof), HotForkRefusal> {
        let ordinary_start = matches!(
            input.start(),
            CrucibleResolvedAttemptStart::Discover { .. }
                | CrucibleResolvedAttemptStart::Branch { .. }
        );
        let start_refusal = [
            (!continuation_free, "continuation-input"),
            (!ordinary_start, "not-ordinary-start"),
            (
                context.start_mode() != AttemptStartMode::Execute,
                "start-mode-not-execute",
            ),
            (context.resume_checkpoint().is_some(), "resume-checkpoint"),
            (context.cancellation().is_canceled(), "attempt-canceled"),
        ]
        .into_iter()
        .find_map(|(refused, reason)| refused.then_some(reason));
        if let Some(reason) = start_refusal {
            return Err(reason.into());
        }
        // An assertion check that cannot run refuses retention as a failure.
        match self.driver.has_terminal_assertion_failure(pending) {
            Ok(false) => {}
            Ok(true) => return Err("terminal-assertion-failure".into()),
            Err(error) => {
                return Err(HotForkRefusal::with_detail(
                    "assertion-check-unavailable",
                    error,
                ));
            }
        }

        let lineage = input
            .lineage()
            .id()
            .map_err(|error| HotForkRefusal::with_detail("lineage-identity-unavailable", error))?;
        let basis = context.runtime_basis().ok_or("runtime-basis-absent")?;
        if basis.key().lineage() != lineage {
            return Err("runtime-basis-lineage-mismatch".into());
        }
        let (boundary, proof) = self.driver.retention_boundary(pending)?;
        Ok((lineage, boundary, proof))
    }

    /// Settles the final boundary and, when it is empty, keeps the world.
    pub(super) fn retain_published_root(
        &mut self,
        mut lifecycle: F::Lifecycle,
        pending: D::Pending,
        trace: Option<crucible::model::ResolvedEffectTrace>,
        plan: QemuPublishedRootPlan,
        input: &CrucibleAttemptExecution,
    ) -> RetentionAttempt<F, D> {
        match lifecycle.drain_final_events_for_retention() {
            Ok(QemuFinalBoundaryDrain::Retainable) => {}
            Ok(QemuFinalBoundaryDrain::Drained(drained)) => {
                record_retention_decision("declined", "final drain published entries");
                return QemuPublishedRootAttempt::Declined {
                    lifecycle,
                    pending,
                    trace,
                    drained,
                };
            }
            Ok(QemuFinalBoundaryDrain::Ineligible(reason)) => {
                record_retention_decision("skipped", reason);
                return QemuPublishedRootAttempt::Declined {
                    lifecycle,
                    pending,
                    trace,
                    drained: Vec::new(),
                };
            }
            Err(error) => {
                // Shutdown would have reported the same settlement failure;
                // it still runs so every process is reaped or quarantined.
                let _cleanup = lifecycle.shutdown();
                return QemuPublishedRootAttempt::Finished(Err(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::Cleanup(error),
                )));
            }
        }

        // The drain proved no final entries exist, so this is the product
        // ordinary shutdown and sealing would produce.
        let product = match self.driver.seal_with_trace(pending, Vec::new(), trace) {
            Ok(product) => product,
            Err(failure) => {
                return QemuPublishedRootAttempt::Finished(match lifecycle.shutdown() {
                    Ok(_events) => Err(map_fresh_driver_failure(failure)),
                    Err(cleanup) => Err(AttemptWorkerFailure::Terminal(
                        QemuFreshExecutionRunnerError::Cleanup(cleanup),
                    )),
                });
            }
        };
        let published = match &product {
            AttemptExecutionProduct::PreparedSemantic(result) => {
                match published_child_mismatch(result, &plan, input) {
                    Some(reason) => Err(reason.into()),
                    None => result.observation().child().id().map_err(|error| {
                        HotForkRefusal::with_detail(
                            "child configuration artifact identity failed",
                            error,
                        )
                    }),
                }
            }
            AttemptExecutionProduct::ExactCheckpoint(_) => {
                Err("sealed product is not a semantic observation".into())
            }
        };
        let published = match published {
            Ok(published) => published,
            Err(refusal) => {
                record_retention_refusal("declined", &refusal);
                return QemuPublishedRootAttempt::Finished(shut_down_unretained(
                    lifecycle, product,
                ));
            }
        };

        let world = match self.lifecycles.prepare_retained_source(
            lifecycle,
            input.scenario(),
            &plan.boundary,
            input.signal_fault_replay(),
        ) {
            QemuRetainedSourcePreparation::Prepared(world) => world,
            QemuRetainedSourcePreparation::Recovered(lifecycle) => {
                record_retention_decision("declined", "source preparation declined");
                return QemuPublishedRootAttempt::Finished(shut_down_unretained(
                    lifecycle, product,
                ));
            }
            QemuRetainedSourcePreparation::Quarantined => {
                // The product was sealed before preparation and stays valid;
                // only the operational world is lost to quarantine.
                record_retention_decision("quarantined", "source preparation failed");
                return QemuPublishedRootAttempt::Finished(Ok((product, None)));
            }
        };
        if let Some(reason) = prepared_world_mismatch(&world, &plan, input) {
            record_retention_decision("retired", reason);
            return QemuPublishedRootAttempt::Finished(match world.retire() {
                Ok(()) => Ok((product, None)),
                Err(error) => Err(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::PublishedRootRetention(error.to_string()),
                )),
            });
        }

        let key = crate::QemuHotForkSourceWorldKey::new_published(
            plan.lineage,
            plan.boundary.def.id(),
            plan.boundary.id(),
            plan.profile,
        );
        record_retention_decision("retained", "awaiting durable observation disposition");
        let provenance = QemuPublishedRootProvenance::new(
            QemuPublishedRootOrigin::AttemptStop,
            plan.boundary,
            attempt_stop_live_network_choice_pause(input),
        );
        let root = Box::new(AuthenticatedPublishedRootQemuHotForkSource::new(
            key, published, *world, provenance,
        ));
        QemuPublishedRootAttempt::Finished(Ok((
            product,
            Some(QemuPendingPublishedRoot {
                sink: plan.sink,
                root,
            }),
        )))
    }
}

/// Admits or retires a pending root once its attempt's disposition is durable.
///
/// Only an accepted observation proves the child artifact the root's thin
/// fallback names is stored; every other disposition retires the world.
///
/// # Errors
///
/// Returns [`QemuPublishedRootRetirementError`] when the root could not be
/// retired completely; its authority then remains quarantined for the
/// process lifetime.
pub(super) fn reconcile_published_root(
    pending: QemuPendingPublishedRoot,
    disposition: &AttemptExecutionDisposition,
) -> Result<(), QemuPublishedRootRetirementError> {
    let QemuPendingPublishedRoot { sink, root } = pending;
    if matches!(disposition, AttemptExecutionDisposition::Observation(_)) {
        return match sink.admit(*root) {
            Ok(QemuPublishedRootAdmission::Admitted) => {
                record_retention_decision("admitted", "observation disposition is durable");
                Ok(())
            }
            Ok(QemuPublishedRootAdmission::Rejected(reason)) => {
                record_retention_decision("rejected", &reason);
                Ok(())
            }
            Ok(QemuPublishedRootAdmission::AlreadyRetained) => {
                record_retention_decision("rejected", "an equal root is already retained");
                Ok(())
            }
            Err(error) => Err(error),
        };
    }

    record_retention_decision("retired", "attempt disposition is not an observation");
    let (_key, _published, source, _provenance) = (*root).into_parts();
    source
        .retire()
        .map_err(|error| QemuPublishedRootRetirementError::new(error.to_string()))
}

/// Transfers a pending root to process-lifetime quarantine.
pub(super) fn quarantine_published_root(pending: QemuPendingPublishedRoot) {
    let _retained_for_process_lifetime = Box::leak(pending.root);
}

/// Shuts down a world that was drained for retention but is not kept.
///
/// The product was sealed with no final events, so shutdown must publish
/// none; anything else means the paused-boundary invariant broke and the
/// sealed product could differ from ordinary teardown.
fn shut_down_unretained<L, FE, DE>(
    mut lifecycle: L,
    product: AttemptExecutionProduct,
) -> Result<QemuRetainedProduct, AttemptWorkerFailure<QemuFreshExecutionRunnerError<FE, DE>>>
where
    L: QemuFreshAttemptLifecycleOwner,
{
    let cleanup = match lifecycle.shutdown() {
        Ok(events) if events.is_empty() => return Ok((product, None)),
        Ok(_events) => SchedulerError::BoundaryViolation {
            message: String::from("shutdown published entries after an empty retention drain"),
        },
        Err(cleanup) => cleanup,
    };
    Err(AttemptWorkerFailure::Terminal(
        QemuFreshExecutionRunnerError::Cleanup(cleanup),
    ))
}

/// Returns the live-network pause mode over a stop root's whole prefix.
///
/// Start replay to a non-genesis start pauses before live-network choices
/// exactly when that start carries a campaign branch; the modeled driver then
/// pauses only for a next-choice stop. A prefix that crossed both segments
/// under different modes has no single mode, so it returns `None`.
fn attempt_stop_live_network_choice_pause(input: &CrucibleAttemptExecution) -> Option<bool> {
    let driven = input.attempt().stop().accepts_next_choice();
    let start = input.start().configuration();
    if start.schedule.is_empty() {
        return Some(driven);
    }
    let replayed = super::replay_pauses_before_live_network_choice(start);
    (replayed == driven).then_some(driven)
}

/// Returns why the sealed observation cannot name the retained boundary.
fn published_child_mismatch(
    result: &crate::PreparedSemanticAttemptResult,
    plan: &QemuPublishedRootPlan,
    input: &CrucibleAttemptExecution,
) -> Option<&'static str> {
    let observation = result.observation();
    let child = observation.child();
    let boundary = ConfigurationId::from_hash(CampaignHash::from_bytes(plan.boundary.id().bytes));
    if child.configuration() != boundary {
        return Some("published child configuration differs from the stop boundary");
    }
    if child.scenario_artifact() != input.lineage().scenario_content() {
        return Some("published child names another scenario artifact");
    }
    if observation.discovered_choices().is_empty() {
        return Some("published observation discovered no choices");
    }
    None
}

/// Returns why a prepared world differs from the sealed stop boundary.
fn prepared_world_mismatch(
    world: &ProductionVmHotForkSourceWorld,
    plan: &QemuPublishedRootPlan,
    input: &CrucibleAttemptExecution,
) -> Option<&'static str> {
    let continuation = world.continuation();
    if continuation.configuration() != &plan.boundary {
        return Some("prepared configuration differs from the stop boundary");
    }
    if continuation.configuration().def.id() != input.scenario().scenario_def().id() {
        return Some("prepared scenario differs from the authenticated attempt");
    }
    if !plan.proof.matches_checkpoint(
        continuation.configuration(),
        continuation.scheduler(),
        continuation.event_log_segments(),
    ) {
        return Some("prepared scheduler boundary differs from the sealed replay proof");
    }
    if continuation.terminal_verdict().is_some() {
        return Some("prepared world carries a terminal verdict");
    }
    None
}

/// Writes one bounded operational retention diagnostic.
fn record_retention_decision(decision: &str, reason: &str) {
    let reason = reason.chars().take(256).collect::<String>();
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-RETENTION-V1 decision={decision} reason={reason:?}"
    );
}

/// Writes a retention refusal, with the error text of a check that failed.
fn record_retention_refusal(decision: &str, refusal: &HotForkRefusal) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-RETENTION-V1 decision={decision} reason={:?}{}",
        refusal.reason(),
        refusal
            .detail()
            .map_or_else(String::new, |detail| format!(" detail={detail:?}"))
    );
}
