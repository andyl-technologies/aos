//! Hot-first execution routing with exact-origin fallback.
//!
//! Initial executions attempt a whole-world retained source before delegating
//! an explicit decline to the configured lower-tier runner. Durable checkpoint
//! resumes bypass hot fork, and the selected route retains exclusive semantic
//! reconciliation ownership until completion.
//!
//! Between a hot decline and thin replay, the lower tier may keep an anchor
//! root at the attempt's network fault branch parent. Once one is admitted,
//! the execution ends as retryable without running anything else:
//!
//! ```text
//! hot --executed or failed---------------------> HotFork (or the failure)
//!  `--declined--> anchor --admitted-------------> Retryable
//!                   `--declined-------------------> thin
//! ```
//!
//! # Anchored executions
//!
//! Anchoring replays the attempt's prefix to its parent and charges those
//! quanta to the current execution. Running the attempt after that, hot or
//! thin, in the same execution could exhaust a budget the attempt would have
//! passed with thin replay alone and turn it into a terminal resource
//! refusal. The router therefore never continues an anchored execution. The
//! requeued execution starts with a full budget and finds the kept root, so
//! its hot child spends only the attempt's own quanta, never more than thin
//! replay of the whole attempt would.
//!
//! The requeued execution routes like any other, and every hot failure
//! there, terminal, canceled, or retryable, propagates unchanged. Each attempt
//! anchors at most once: the anchor tier claims the attempt before it replays
//! or reports a retained root, so when hot fork declines again (the root was
//! invalidated or could not be leased) the attempt replays thin.

use crucible_campaign::AttemptStartMode;

use crate::qemu_hot_fork_world_factory::AttemptWorkerFailureExt;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, QemuAnchorRootMaterializer, QemuAnchorRootOutcome,
    QemuFreshAttemptDriver, QemuHotForkWorldExecutionAttempt, QemuHotForkWorldExecutionRunner,
    QemuHotForkWorldExecutionRunnerError, QemuHotForkWorldLifecycleFactory,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QemuHotFirstPendingRoute {
    HotFork,
    Fallback,
}

/// Hot-first execution router with an exact-origin fallback runner.
///
/// Executions resumed from a durable checkpoint bypass hot fork because their
/// origin is the checkpoint itself. Initial executions try one exact retained
/// source world and use `fallback` only when the hot-fork factory explicitly
/// declines the requested scenario and configuration.
pub(crate) struct QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    hot_fork: QemuHotForkWorldExecutionRunner<F, D>,
    fallback: R,
    pending: Option<QemuHotFirstPendingRoute>,
}

impl<F, D, R> QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    /// Creates a router from a whole-world hot-fork runner and exact-origin fallback.
    #[must_use]
    pub(crate) const fn new(hot_fork: QemuHotForkWorldExecutionRunner<F, D>, fallback: R) -> Self {
        Self {
            hot_fork,
            fallback,
            pending: None,
        }
    }
}

type RouterFailure<F, D, R> = AttemptWorkerFailure<
    QemuHotFirstExecutionRouterError<
        QemuHotForkWorldExecutionRunnerError<
            <F as QemuHotForkWorldLifecycleFactory>::Error,
            <D as QemuFreshAttemptDriver>::Error,
        >,
        <R as CrucibleExecutionRunner>::Error,
    >,
>;

impl<F, D, R> QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
    R: QemuAnchorRootMaterializer,
{
    /// Runs the attempt hot, or keeps an anchor root for its next execution.
    ///
    /// Returns `None` when the attempt should replay thin.
    ///
    /// # Errors
    ///
    /// Returns every hot or anchoring failure unchanged, and
    /// [`QemuHotFirstExecutionRouterError::AnchorRootAdmitted`] as retryable
    /// once an anchor root is kept.
    fn try_hot_fork(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Option<CrucibleExecutionOutcome>, RouterFailure<F, D, R>> {
        if let Some(outcome) = self.hot_attempt(input, context)? {
            return Ok(Some(outcome));
        }

        let anchored = self
            .fallback
            .materialize_anchor_root(input, context)
            .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::Fallback))?;
        match anchored {
            QemuAnchorRootOutcome::Declined(_) => Ok(None),
            // The anchoring replay already spent part of this budget; the
            // attempt runs again from the kept root with a full one.
            QemuAnchorRootOutcome::Admitted => Err(AttemptWorkerFailure::Retryable(
                QemuHotFirstExecutionRouterError::AnchorRootAdmitted,
            )),
        }
    }

    /// Runs one hot-fork attempt; `None` is an explicit decline.
    fn hot_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Option<CrucibleExecutionOutcome>, RouterFailure<F, D, R>> {
        match self
            .hot_fork
            .try_execute(input, context)
            .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::HotFork))?
        {
            QemuHotForkWorldExecutionAttempt::Declined => Ok(None),
            QemuHotForkWorldExecutionAttempt::Executed(outcome) => Ok(Some(outcome)),
        }
    }
}

/// Failure from hot-first materialization routing or its selected runner.
#[derive(Debug, thiserror::Error)]
pub(crate) enum QemuHotFirstExecutionRouterError<H, R> {
    /// A previous successful result still owns post-publication authority.
    #[error("hot-first QEMU router still awaits prior semantic reconciliation")]
    PriorReconciliationPending,
    /// Whole-world hot-fork execution failed after exact source selection.
    #[error("whole-world hot-fork execution failed")]
    HotFork(#[source] H),
    /// Exact-origin fallback execution failed.
    #[error("fallback QEMU execution failed")]
    Fallback(#[source] R),
    /// An anchor root was kept; the attempt runs again from it with a full
    /// execution budget.
    #[error("hot-first QEMU router kept an anchor root; the attempt runs again from it")]
    AnchorRootAdmitted,
    /// Reconciliation arrived before any successful routed execution.
    #[error("hot-first QEMU router has no pending reconciliation")]
    NoPendingReconciliation,
}

impl<F, D, R> CrucibleExecutionRunner for QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
    R: QemuAnchorRootMaterializer,
{
    type Error = QemuHotFirstExecutionRouterError<
        QemuHotForkWorldExecutionRunnerError<F::Error, D::Error>,
        R::Error,
    >;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotFirstExecutionRouterError::PriorReconciliationPending,
            ));
        }

        if context.resume_checkpoint().is_none()
            && context.start_mode() == AttemptStartMode::Execute
            && let Some(outcome) = self.try_hot_fork(input, context)?
        {
            self.pending = Some(QemuHotFirstPendingRoute::HotFork);
            return Ok(outcome);
        }

        let outcome = self
            .fallback
            .execute(input, context)
            .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::Fallback))?;
        self.pending = Some(QemuHotFirstPendingRoute::Fallback);
        Ok(outcome)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let route = self.pending.ok_or_else(|| {
            AttemptWorkerFailure::Terminal(
                QemuHotFirstExecutionRouterError::NoPendingReconciliation,
            )
        })?;
        let reconciled = match route {
            QemuHotFirstPendingRoute::HotFork => self
                .hot_fork
                .reconcile_execution(disposition)
                .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::HotFork)),
            QemuHotFirstPendingRoute::Fallback => self
                .fallback
                .reconcile_execution(disposition)
                .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::Fallback)),
        };
        match reconciled {
            Ok(AttemptExecutionReconciliationStep::Complete) => {
                self.pending = None;
                Ok(AttemptExecutionReconciliationStep::Complete)
            }
            Ok(AttemptExecutionReconciliationStep::Progressed) => {
                Ok(AttemptExecutionReconciliationStep::Progressed)
            }
            Err(failure @ AttemptWorkerFailure::Retryable(_)) => Err(failure),
            Err(
                failure @ (AttemptWorkerFailure::Canceled(_) | AttemptWorkerFailure::Terminal(_)),
            ) => {
                self.pending = None;
                Err(failure)
            }
        }
    }

    fn quarantine_pending_execution(&mut self) {
        let Some(route) = self.pending.take() else {
            return;
        };
        match route {
            QemuHotFirstPendingRoute::HotFork => {
                self.hot_fork.quarantine_pending_execution();
            }
            QemuHotFirstPendingRoute::Fallback => {
                self.fallback.quarantine_pending_execution();
            }
        }
    }
}

impl<F, D, R> crate::QemuSelectedOriginVerifier for QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
    R: crate::QemuSelectedOriginVerifier + QemuAnchorRootMaterializer,
{
    fn verify_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<crate::QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>> {
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotFirstExecutionRouterError::PriorReconciliationPending,
            ));
        }
        self.fallback
            .verify_selected_origin(input, context, target)
            .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::Fallback))
    }
}

impl<F, D, R> crate::QemuAttemptStartVerifier for QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
    R: crate::QemuAttemptStartVerifier + QemuAnchorRootMaterializer,
{
    fn verify_attempt_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<crate::QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>> {
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotFirstExecutionRouterError::PriorReconciliationPending,
            ));
        }
        self.fallback
            .verify_attempt_start(input, context)
            .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::Fallback))
    }
}
