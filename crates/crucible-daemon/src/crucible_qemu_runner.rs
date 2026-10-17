//! Exact-resume and fresh-execution QEMU runner for local campaign attempts.
//!
//! This module connects the campaign execution boundary to the existing QEMU
//! realization coordinator. It deliberately does not emulate hot fork: the
//! GPL-side fork protocol must land and pass its safety gates before a runner
//! may report hot-fork materialization. The exact-origin router
//! keeps fresh execution and durable paused-root resume on disjoint runners.

use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, QemuAttemptStartReplayProof, QemuSavepointReplayProof,
};

#[cfg(test)]
use crate::CrucibleResolvedAttemptStart;

/// Independent cold-replay authority for a selected continuation origin.
pub trait QemuSelectedOriginVerifier: CrucibleExecutionRunner {
    /// Reconstructs the selected semantic boundary without using its physical source.
    ///
    /// # Errors
    ///
    /// Returns a classified execution failure when cold replay cannot reproduce
    /// the complete configuration, quantum, frontier, and event-prefix basis.
    fn verify_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>>;
}

/// Independent cold-replay authority for an ordinary attempt's start boundary.
///
/// The exact-checkpoint version-five envelope does not retain an authenticated
/// attempt-local event count. Implementations therefore launch a fresh lifecycle
/// and replay only genesis through the immutable Discover or Branch start. This
/// adds one lifecycle launch and start-prefix replay to each ordinary EventCount
/// resume; it does not replay the resumed attempt's own progress.
pub trait QemuAttemptStartVerifier: CrucibleExecutionRunner {
    /// Reconstructs the immutable start and authenticates its inherited event prefix.
    ///
    /// # Errors
    ///
    /// Returns a classified execution failure when cold replay cannot reproduce
    /// the admitted start configuration and complete inherited event prefix.
    fn verify_attempt_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>>;
}

/// Exact-resume authority that consumes an independently reconstructed origin proof.
pub trait QemuSelectedOriginResumeRunner: CrucibleExecutionRunner {
    /// Authenticates the portable source boundary without launching QEMU.
    ///
    /// `None` means an initial preferred source is absent and permits cold
    /// execution. A later own resume never returns `None` for absence.
    ///
    /// # Errors
    ///
    /// Returns a classified failure for unavailable or malformed source state.
    fn authenticate_selected_resume_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    >;

    /// Resumes a physical source only after comparing it with `proof`.
    ///
    /// # Errors
    ///
    /// Returns a classified execution failure when the physical checkpoint is
    /// unavailable, malformed, or differs from the independent semantic proof.
    fn execute_verified_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: QemuSavepointReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>>;
}

/// Exact-resume authority that consumes an independently replayed attempt start.
pub trait QemuOrdinaryResumeRunner: CrucibleExecutionRunner {
    /// Resumes an ordinary attempt after authenticating its inherited event prefix.
    ///
    /// # Errors
    ///
    /// Returns a classified execution failure when the physical checkpoint is
    /// unavailable, malformed, or does not begin with the independently replayed
    /// start evidence.
    fn execute_verified_attempt_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: QemuAttemptStartReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>>;
}

/// Retains the legacy QEMU replay contracts over common original-route orchestration.
pub struct QemuAttemptExecutionRouter<F, R> {
    inner: crate::attempt_execution_router::AttemptExecutionRouter<
        QemuFreshCompatibility<F>,
        QemuResumeCompatibility<R>,
    >,
}

impl<F, R> QemuAttemptExecutionRouter<F, R> {
    /// Creates the unchanged legacy exact-origin routing adapter.
    #[must_use]
    pub const fn new(fresh: F, resume: R) -> Self {
        Self {
            inner: crate::attempt_execution_router::AttemptExecutionRouter::legacy_qemu(
                QemuFreshCompatibility(fresh),
                QemuResumeCompatibility(resume),
            ),
        }
    }

    /// Returns the runner used for executions without a durable resume root.
    #[must_use]
    pub const fn fresh(&self) -> &F {
        &self.inner.fresh().0
    }

    /// Returns mutable access to the fresh execution runner.
    #[must_use]
    pub const fn fresh_mut(&mut self) -> &mut F {
        &mut self.inner.fresh_mut().0
    }

    /// Returns the runner used only for exact durable resume origins.
    #[must_use]
    pub const fn resume(&self) -> &R {
        &self.inner.resume().0
    }

    /// Consumes the adapter into its original disjoint execution paths.
    #[must_use]
    pub fn into_parts(self) -> (F, R) {
        let (fresh, resume) = self.inner.into_parts();
        (fresh.0, resume.0)
    }
}

/// Failure from one exact-origin branch of [`QemuAttemptExecutionRouter`].
#[derive(Debug, thiserror::Error)]
pub enum QemuAttemptExecutionRouterError<F, R> {
    /// A previous successful route still owns post-publication authority.
    #[error("QEMU execution router still awaits prior semantic reconciliation")]
    PriorReconciliationPending,
    /// The fresh execution path failed.
    #[error("fresh campaign QEMU execution failed")]
    Fresh(#[source] F),
    /// The exact durable-resume path failed.
    #[error("resumed campaign QEMU execution failed")]
    Resume(#[source] R),
    /// Reconciliation arrived before a routed execution succeeded.
    #[error("QEMU execution router has no pending reconciliation")]
    NoPendingReconciliation,
}

// Private owning wrappers isolate the legacy undeclared contract without
// reserving neutral trait implementations on callers' concrete runner types.
struct QemuFreshCompatibility<T>(T);

struct QemuResumeCompatibility<T>(T);

impl<T: CrucibleExecutionRunner> CrucibleExecutionRunner for QemuFreshCompatibility<T> {
    type Error = T::Error;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.0.execute(input, context)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.0.reconcile_execution(disposition)
    }

    fn quarantine_pending_execution(&mut self) {
        self.0.quarantine_pending_execution();
    }
}

impl<T: CrucibleExecutionRunner> CrucibleExecutionRunner for QemuResumeCompatibility<T> {
    type Error = T::Error;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.0.execute(input, context)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.0.reconcile_execution(disposition)
    }

    fn quarantine_pending_execution(&mut self) {
        self.0.quarantine_pending_execution();
    }
}

impl<T> crate::attempt_execution_router::AttemptOriginVerifier for QemuFreshCompatibility<T>
where
    T: QemuAttemptStartVerifier + QemuSelectedOriginVerifier,
{
    type SelectedBoundary = crate::qemu_campaign_driver::QemuSelectedResumeBoundary;
    type SelectedProof = QemuSavepointReplayProof;
    type StartProof = QemuAttemptStartReplayProof;

    fn replay_contract(&self) -> Option<crate::attempt_execution_router::AttemptReplayContract> {
        None
    }

    fn verify_selected_resume(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &Self::SelectedBoundary,
    ) -> Result<Self::SelectedProof, AttemptWorkerFailure<Self::Error>> {
        QemuSelectedOriginVerifier::verify_selected_origin(&mut self.0, input, context, target)
    }

    fn verify_start_prefix(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Self::StartProof, AttemptWorkerFailure<Self::Error>> {
        QemuAttemptStartVerifier::verify_attempt_start(&mut self.0, input, context)
    }
}

impl<T> crate::attempt_execution_router::AttemptOriginResumeRunner for QemuResumeCompatibility<T>
where
    T: QemuOrdinaryResumeRunner + QemuSelectedOriginResumeRunner,
{
    type SelectedBoundary = crate::qemu_campaign_driver::QemuSelectedResumeBoundary;
    type SelectedProof = QemuSavepointReplayProof;
    type StartProof = QemuAttemptStartReplayProof;

    fn replay_contract(&self) -> Option<crate::attempt_execution_router::AttemptReplayContract> {
        None
    }

    fn authenticate_resume_source(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Option<Self::SelectedBoundary>, AttemptWorkerFailure<Self::Error>> {
        QemuSelectedOriginResumeRunner::authenticate_selected_resume_boundary(
            &mut self.0,
            input,
            context,
        )
    }

    fn resume_verified_source(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: Self::SelectedProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        QemuSelectedOriginResumeRunner::execute_verified_selected_origin(
            &mut self.0,
            input,
            context,
            proof,
        )
    }

    fn resume_verified_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: Self::StartProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        QemuOrdinaryResumeRunner::execute_verified_attempt_start(&mut self.0, input, context, proof)
    }
}

impl<F, R> CrucibleExecutionRunner for QemuAttemptExecutionRouter<F, R>
where
    F: QemuAttemptStartVerifier + QemuSelectedOriginVerifier,
    R: QemuOrdinaryResumeRunner + QemuSelectedOriginResumeRunner,
{
    type Error = QemuAttemptExecutionRouterError<F::Error, R::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .execute(input, context)
            .map_err(map_legacy_failure)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .reconcile_execution(disposition)
            .map_err(map_legacy_failure)
    }

    fn quarantine_pending_execution(&mut self) {
        self.inner.quarantine_pending_execution();
    }
}

fn map_legacy_failure<F, R>(
    failure: AttemptWorkerFailure<
        crate::attempt_execution_router::AttemptExecutionRouterError<F, R>,
    >,
) -> AttemptWorkerFailure<QemuAttemptExecutionRouterError<F, R>> {
    use crate::attempt_execution_router::AttemptExecutionRouterError as Common;
    let wrap = |error| match error {
        Common::PriorReconciliationPending => {
            QemuAttemptExecutionRouterError::PriorReconciliationPending
        }
        Common::Fresh(error) => QemuAttemptExecutionRouterError::Fresh(error),
        Common::Resume(error) => QemuAttemptExecutionRouterError::Resume(error),
        Common::NoPendingReconciliation => QemuAttemptExecutionRouterError::NoPendingReconciliation,
        // Both private legacy adapters return fixed None contracts; this common
        // failure is unreachable here. Keep the original legacy error surface.
        Common::ReplayContractChanged => {
            QemuAttemptExecutionRouterError::PriorReconciliationPending
        }
    };
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(wrap(error)),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(wrap(error)),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(wrap(error)),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
    #![allow(clippy::expect_used)]

    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crucible::Configuration;
    use crucible_campaign::{
        Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
        ConfigurationArtifact, ConfigurationId, ExactCheckpointId, ExecutionRetentionIntent,
        ScenarioArtifact, ScenarioDefId, StopCondition,
    };

    use super::*;
    use crate::ExecutionCancellation;

    #[derive(Clone, Copy)]
    enum RoutedFailureDisposition {
        Retryable,
        Canceled,
        Terminal,
    }

    struct RoutedFailureRunner {
        calls: Arc<AtomicUsize>,
        expects_resume: bool,
        disposition: RoutedFailureDisposition,
        message: &'static str,
    }

    impl RoutedFailureRunner {
        fn failure(&self) -> AttemptWorkerFailure<&'static str> {
            match self.disposition {
                RoutedFailureDisposition::Retryable => {
                    AttemptWorkerFailure::Retryable(self.message)
                }
                RoutedFailureDisposition::Canceled => AttemptWorkerFailure::Canceled(self.message),
                RoutedFailureDisposition::Terminal => AttemptWorkerFailure::Terminal(self.message),
            }
        }
    }

    impl CrucibleExecutionRunner for RoutedFailureRunner {
        type Error = &'static str;

        fn execute(
            &mut self,
            _input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(context.resume_checkpoint().is_some(), self.expects_resume);
            Err(self.failure())
        }
    }

    impl QemuSelectedOriginVerifier for RoutedFailureRunner {
        fn verify_selected_origin(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
            _target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
        ) -> Result<QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>> {
            panic!("ordinary routing fixture has no selected origin")
        }
    }

    impl QemuAttemptStartVerifier for RoutedFailureRunner {
        fn verify_attempt_start(
            &mut self,
            input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>> {
            assert!(context.resume_checkpoint().is_some());
            self.calls.fetch_add(1, Ordering::SeqCst);
            QemuAttemptStartReplayProof::from_reached_boundary(input.start().configuration(), &[])
                .map_err(|_| AttemptWorkerFailure::Terminal("build attempt-start proof"))
        }
    }

    impl QemuSelectedOriginResumeRunner for RoutedFailureRunner {
        fn authenticate_selected_resume_boundary(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
        ) -> Result<
            Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
            AttemptWorkerFailure<Self::Error>,
        > {
            panic!("ordinary routing fixture has no selected origin")
        }

        fn execute_verified_selected_origin(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
            _proof: QemuSavepointReplayProof,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            panic!("ordinary routing fixture has no selected origin")
        }
    }

    impl QemuOrdinaryResumeRunner for RoutedFailureRunner {
        fn execute_verified_attempt_start(
            &mut self,
            _input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
            _proof: QemuAttemptStartReplayProof,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            assert!(context.resume_checkpoint().is_some());
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(self.failure())
        }
    }

    fn routed_input() -> CrucibleAttemptExecution {
        routed_input_for_stop(StopCondition::Terminal)
    }

    fn routed_input_for_stop(stop: StopCondition) -> CrucibleAttemptExecution {
        let scenario = crucible::crash_restart_scenario()
            .expect("built-in scenario")
            .scenario;
        let definition = scenario.scenario_def();
        let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(definition.id().bytes));
        let scenario_artifact =
            ScenarioArtifact::new(scenario_id, 1, b"scenario".to_vec()).expect("scenario artifact");
        let scenario_content = scenario_artifact.id().expect("scenario artifact id");
        let configuration = Configuration::genesis(definition);
        let configuration_id =
            ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
        let configuration_artifact = ConfigurationArtifact::new(
            scenario_id,
            scenario_content,
            configuration_id,
            1,
            b"configuration".to_vec(),
        )
        .expect("configuration artifact");
        let configuration_content = configuration_artifact
            .id()
            .expect("configuration artifact id");
        let lineage = CampaignLineage::new(
            scenario_id,
            scenario_content,
            configuration_id,
            configuration_content,
            "crucible-test",
            "qemu-test",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )
        .expect("campaign lineage");
        let path = BranchPath::new(Vec::new()).expect("genesis branch path");
        let attempt = Attempt::new(
            AttemptStart::Discover {
                configuration: configuration_content,
            },
            path.id().expect("branch path id"),
            stop,
        )
        .expect("discovery attempt");

        CrucibleAttemptExecution::from_test_parts(
            lineage,
            scenario,
            attempt,
            path,
            CrucibleResolvedAttemptStart::Discover { configuration },
        )
    }

    fn routed_context(checkpoint: Option<ExactCheckpointId>) -> AttemptExecutionContext {
        AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 1).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            crate::ExecutionCheckpointRequest::default(),
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
        )
        .with_resume_checkpoint(checkpoint)
    }

    #[test]
    fn exact_origin_router_keeps_non_event_count_resumes_off_the_fresh_path() {
        let fresh_calls = Arc::new(AtomicUsize::new(0));
        let resume_calls = Arc::new(AtomicUsize::new(0));
        let mut router = QemuAttemptExecutionRouter::new(
            RoutedFailureRunner {
                calls: Arc::clone(&fresh_calls),
                expects_resume: false,
                disposition: RoutedFailureDisposition::Retryable,
                message: "fresh unavailable",
            },
            RoutedFailureRunner {
                calls: Arc::clone(&resume_calls),
                expects_resume: true,
                disposition: RoutedFailureDisposition::Canceled,
                message: "resume canceled",
            },
        );
        let input = routed_input();

        assert!(matches!(
            router.execute(&input, &routed_context(None)),
            Err(AttemptWorkerFailure::Retryable(
                QemuAttemptExecutionRouterError::Fresh("fresh unavailable")
            ))
        ));
        assert_eq!(fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resume_calls.load(Ordering::SeqCst), 0);

        let checkpoint = exact_checkpoint_id(b"router-resume-origin");
        assert!(matches!(
            router.execute(&input, &routed_context(Some(checkpoint))),
            Err(AttemptWorkerFailure::Canceled(
                QemuAttemptExecutionRouterError::Resume("resume canceled")
            ))
        ));
        assert_eq!(fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resume_calls.load(Ordering::SeqCst), 1);

        router.fresh_mut().disposition = RoutedFailureDisposition::Terminal;
        router.fresh_mut().message = "fresh incompatible";
        assert!(matches!(
            router.execute(&input, &routed_context(None)),
            Err(AttemptWorkerFailure::Terminal(
                QemuAttemptExecutionRouterError::Fresh("fresh incompatible")
            ))
        ));
        assert_eq!(fresh_calls.load(Ordering::SeqCst), 2);
        assert_eq!(resume_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exact_origin_router_verifies_event_count_resumes_before_restore() {
        let fresh_calls = Arc::new(AtomicUsize::new(0));
        let resume_calls = Arc::new(AtomicUsize::new(0));
        let mut router = QemuAttemptExecutionRouter::new(
            RoutedFailureRunner {
                calls: Arc::clone(&fresh_calls),
                expects_resume: false,
                disposition: RoutedFailureDisposition::Retryable,
                message: "unused fresh failure",
            },
            RoutedFailureRunner {
                calls: Arc::clone(&resume_calls),
                expects_resume: true,
                disposition: RoutedFailureDisposition::Canceled,
                message: "verified resume canceled",
            },
        );
        let input = routed_input_for_stop(StopCondition::EventCount(4));
        let checkpoint = exact_checkpoint_id(b"router-event-count-resume");

        assert!(matches!(
            router.execute(&input, &routed_context(Some(checkpoint))),
            Err(AttemptWorkerFailure::Canceled(
                QemuAttemptExecutionRouterError::Resume("verified resume canceled")
            ))
        ));
        assert_eq!(fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resume_calls.load(Ordering::SeqCst), 1);
    }

    fn exact_checkpoint_id(material: &[u8]) -> crucible_campaign::ExactCheckpointId {
        crucible_campaign::ExactCheckpointId::try_from(
            crucible_cas::content_store::ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::ExactManifest,
                5,
                material,
            ),
        )
        .expect("exact checkpoint root")
    }
}
