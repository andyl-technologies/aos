//! Hot-first execution routing with exact-origin fallback.
//!
//! Initial executions attempt a whole-world retained source before delegating
//! an explicit decline to the configured lower-tier runner. Durable checkpoint
//! resumes bypass hot fork, and the selected route retains exclusive semantic
//! reconciliation ownership until completion.

use crate::qemu_hot_fork_world_factory::AttemptWorkerFailureExt;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, QemuFreshAttemptDriver, QemuHotForkWorldExecutionAttempt,
    QemuHotForkWorldExecutionRunner, QemuHotForkWorldExecutionRunnerError,
    QemuHotForkWorldLifecycleFactory,
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
pub struct QemuHotFirstExecutionRouter<F, D, R>
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
    pub const fn new(hot_fork: QemuHotForkWorldExecutionRunner<F, D>, fallback: R) -> Self {
        Self {
            hot_fork,
            fallback,
            pending: None,
        }
    }

    /// Returns the whole-world hot-fork runner.
    #[must_use]
    pub const fn hot_fork(&self) -> &QemuHotForkWorldExecutionRunner<F, D> {
        &self.hot_fork
    }

    /// Returns mutable access to the whole-world hot-fork runner.
    #[must_use]
    pub const fn hot_fork_mut(&mut self) -> &mut QemuHotForkWorldExecutionRunner<F, D> {
        &mut self.hot_fork
    }

    /// Returns the exact-origin fallback runner.
    #[must_use]
    pub const fn fallback(&self) -> &R {
        &self.fallback
    }

    /// Returns mutable access to the exact-origin fallback runner.
    #[must_use]
    pub const fn fallback_mut(&mut self) -> &mut R {
        &mut self.fallback
    }

    /// Consumes the router into its hot-fork and fallback runners.
    #[must_use]
    pub fn into_parts(self) -> (QemuHotForkWorldExecutionRunner<F, D>, R) {
        (self.hot_fork, self.fallback)
    }
}

/// Failure from hot-first materialization routing or its selected runner.
#[derive(Debug, thiserror::Error)]
pub enum QemuHotFirstExecutionRouterError<H, R> {
    /// A previous successful result still owns post-publication authority.
    #[error("hot-first QEMU router still awaits prior semantic reconciliation")]
    PriorReconciliationPending,
    /// Whole-world hot-fork execution failed after exact source selection.
    #[error("whole-world hot-fork execution failed")]
    HotFork(#[source] H),
    /// Exact-origin fallback execution failed.
    #[error("fallback QEMU execution failed")]
    Fallback(#[source] R),
    /// Reconciliation arrived before any successful routed execution.
    #[error("hot-first QEMU router has no pending reconciliation")]
    NoPendingReconciliation,
}

impl<F, D, R> CrucibleExecutionRunner for QemuHotFirstExecutionRouter<F, D, R>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
    R: CrucibleExecutionRunner,
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

        if context.resume_checkpoint().is_none() {
            match self
                .hot_fork
                .try_execute(input, context)
                .map_err(|failure| failure.map(QemuHotFirstExecutionRouterError::HotFork))?
            {
                QemuHotForkWorldExecutionAttempt::Declined => {}
                QemuHotForkWorldExecutionAttempt::Executed(outcome) => {
                    self.pending = Some(QemuHotFirstPendingRoute::HotFork);
                    return Ok(outcome);
                }
            }
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
}
