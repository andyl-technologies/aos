//! Exact-resume and fresh-execution QEMU runner for local campaign attempts.
//!
//! This module connects the campaign execution boundary to the existing QEMU
//! realization coordinator. It deliberately does not emulate hot fork: the
//! GPL-side fork protocol must land and pass its safety gates before a runner
//! may report hot-fork materialization. The exact-origin router
//! keeps fresh execution and durable paused-root resume on disjoint runners.

use crucible_campaign::StopCondition;

use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, CrucibleResolvedAttemptStart, QemuAttemptStartReplayProof,
    QemuSavepointReplayProof,
};

/// Exact-origin router for fresh and durable-resume QEMU execution paths.
///
/// The resume root in [`AttemptExecutionContext`] is an operational execution
/// origin, not a materialization hint. A context with a root normally obtains
/// its execution outcome from `resume`; `fresh` may only authenticate its
/// immutable semantic basis. Modeled continuation control is the exception:
/// exact checkpoints do not carry that newly selected input, so the router cold
/// executes the continuation from its authenticated semantic source after the
/// resume path has validated the supplied exact closure. A context without a
/// root executes through `fresh`.
/// Ordinary `EventCount` resumes first cold replay the immutable attempt start
/// so the resumed driver can distinguish inherited evidence from same-attempt
/// progress. Other stop modes do not consume that counter and retain the direct
/// exact-resume path, including starts unsupported by cold replay.
pub struct QemuAttemptExecutionRouter<F, R> {
    fresh: F,
    resume: R,
    pending: Option<QemuAttemptExecutionPendingRoute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QemuAttemptExecutionPendingRoute {
    Fresh,
    Resume,
}

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

impl<F, R> QemuAttemptExecutionRouter<F, R> {
    /// Creates an exact-origin execution router.
    #[must_use]
    pub const fn new(fresh: F, resume: R) -> Self {
        Self {
            fresh,
            resume,
            pending: None,
        }
    }

    /// Returns the runner used for executions without a durable resume root.
    #[must_use]
    pub const fn fresh(&self) -> &F {
        &self.fresh
    }

    /// Returns mutable access to the fresh execution runner.
    #[must_use]
    pub const fn fresh_mut(&mut self) -> &mut F {
        &mut self.fresh
    }

    /// Returns the runner used only for exact durable resume origins.
    #[must_use]
    pub const fn resume(&self) -> &R {
        &self.resume
    }

    /// Consumes the router into its disjoint execution paths.
    #[must_use]
    pub fn into_parts(self) -> (F, R) {
        (self.fresh, self.resume)
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
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuAttemptExecutionRouterError::PriorReconciliationPending,
            ));
        }

        if context.resume_checkpoint().is_none() {
            let outcome = self
                .fresh
                .execute(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            self.pending = Some(QemuAttemptExecutionPendingRoute::Fresh);
            Ok(outcome)
        } else if input.attempt().continuation_input().is_some() {
            if matches!(
                input.start(),
                CrucibleResolvedAttemptStart::AfterAttempt { .. }
            ) {
                self.resume
                    .authenticate_selected_resume_boundary(input, context)
                    .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            }
            let cold_context = context.for_absent_selected_source();
            let outcome = self
                .fresh
                .execute(input, &cold_context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            self.pending = Some(QemuAttemptExecutionPendingRoute::Fresh);
            Ok(outcome)
        } else if matches!(
            input.start(),
            CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            let Some(target) = self
                .resume
                .authenticate_selected_resume_boundary(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?
            else {
                let cold_context = context.for_absent_selected_source();
                let outcome = self
                    .fresh
                    .execute(input, &cold_context)
                    .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
                self.pending = Some(QemuAttemptExecutionPendingRoute::Fresh);
                return Ok(outcome);
            };
            let proof = self
                .fresh
                .verify_selected_origin(input, context, &target)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            let outcome = self
                .resume
                .execute_verified_selected_origin(input, context, proof)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            self.pending = Some(QemuAttemptExecutionPendingRoute::Resume);
            Ok(outcome)
        } else if matches!(input.attempt().stop(), StopCondition::EventCount(_)) {
            let proof = self
                .fresh
                .verify_attempt_start(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            let outcome = self
                .resume
                .execute_verified_attempt_start(input, context, proof)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            self.pending = Some(QemuAttemptExecutionPendingRoute::Resume);
            Ok(outcome)
        } else {
            let outcome = self
                .resume
                .execute(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            self.pending = Some(QemuAttemptExecutionPendingRoute::Resume);
            Ok(outcome)
        }
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let route = self.pending.ok_or_else(|| {
            AttemptWorkerFailure::Terminal(QemuAttemptExecutionRouterError::NoPendingReconciliation)
        })?;
        let reconciled = match route {
            QemuAttemptExecutionPendingRoute::Fresh => self
                .fresh
                .reconcile_execution(disposition)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh)),
            QemuAttemptExecutionPendingRoute::Resume => self
                .resume
                .reconcile_execution(disposition)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume)),
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
            QemuAttemptExecutionPendingRoute::Fresh => {
                self.fresh.quarantine_pending_execution();
            }
            QemuAttemptExecutionPendingRoute::Resume => {
                self.resume.quarantine_pending_execution();
            }
        }
    }
}

fn map_routed_failure<E, T>(
    failure: AttemptWorkerFailure<E>,
    wrap: impl FnOnce(E) -> T,
) -> AttemptWorkerFailure<T> {
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
