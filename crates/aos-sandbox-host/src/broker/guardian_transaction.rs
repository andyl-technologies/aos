//! Guardian-first launch, composite stop, and exact two-unit compensation.
//!
//! Completion requires one fresh observation of the exact live Guardian and
//! payload pair plus the worker's bound runtime proof. Every cleanup effect is
//! durably selected before dispatch and names the observed invocation; recovery
//! never turns an observation-only payload proof into a second start. Terminal
//! compensation is committed only after both unit roles are absent, including
//! the no-effect case where they disappeared before recovery.
//!
//! Composite Stop uses the same exact binding, invocation, manager-reference,
//! and cgroup-quiescence evidence.

use aos_sandbox_broker::BrokerEffectIntentV2;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimeRequest};
use aos_systemd::{ExactUnitRole, GuardianUnitSpec};

use super::{
    HostBroker, composite_stop_pending, encode_observation, ensure_response_bound,
    guardian_authority_freshness, guardian_pending, guardian_quarantined, guardian_rejected,
    guardian_unit_observation,
};
use crate::plan::{HostCatalog, PreparedLaunch};
use crate::state::transition::{
    AuthorityFreshness, CleanupProgress, CompositeStopPhase, CompositeStopTarget, DurableExecution,
    ExecutionContext, GuardianDecision, GuardianDecisionInput, GuardianLaunchPhase, PlannedEffect,
    PresentUnitState, StartJobEvidence, StopDecision, StopDecisionInput, StopProgress,
    StopUnitTarget, UnitObservation, decide_composite_stop, decide_guardian_launch,
};
use crate::state::{GuardianLineage, HostAction, HostStateStore};
use crate::worker::{
    ExactWorkerStopOutcome, GuardianObservedState, HostRuntimeIdentity, HostWorker,
    ObservedRuntimeState, WorkerObservation,
};
use crate::{HostError, Result};

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    pub(super) async fn prepare_composite_stop_execution(
        &self,
        request: &ValidatedRuntimeRequest,
        request_digest: [u8; 32],
    ) -> Result<DurableExecution>
    where
        W: Sync,
    {
        if let Some(record) = self
            .state
            .composite_stop_execution(request.header().request_id())
        {
            return Ok(DurableExecution::CompositeStop(record));
        }

        let identity = HostRuntimeIdentity::from(request.fence());
        let lineage = self.state.completed_guardian_lineage(
            request.fence().sandbox_id(),
            request.fence().incarnation_id(),
            &self.authority,
        )?;
        let target = if let GuardianLineage::Complete(lineage) = lineage {
            CompositeStopTarget::GuardianComposite {
                source_launch_request_id: lineage.source_request_id,
                incarnation_id: lineage.incarnation_id,
                launch_binding: lineage.binding,
                payload: StopUnitTarget::Exact {
                    binding: Some(lineage.binding),
                    invocation: lineage.payload_invocation,
                },
                guardian: StopUnitTarget::Exact {
                    binding: Some(lineage.binding),
                    invocation: lineage.guardian_invocation,
                },
            }
        } else {
            match self.state.current_execution(request.fence().sandbox_id()) {
                Some((_, HostAction::Launch, incarnation_id, execution))
                    if incarnation_id == *request.fence().incarnation_id()
                        && execution.guardian_attempt().is_some_and(|attempt| {
                            matches!(attempt.phase, GuardianLaunchPhase::Compensated { .. })
                        }) =>
                {
                    let payload = self.worker.observe_bound_payload(&identity).await?;
                    let guardian = self.worker.observe_guardian(&identity).await?;
                    if payload.state != GuardianObservedState::Absent
                        || guardian.state != GuardianObservedState::Absent
                    {
                        return Err(guardian_quarantined());
                    }
                    CompositeStopTarget::Absent
                }
                Some(_) | None => {
                    let payload = self.worker.observe_bound_payload(&identity).await?;
                    let guardian = self.worker.observe_guardian(&identity).await?;
                    if payload.state != GuardianObservedState::Absent
                        || guardian.state != GuardianObservedState::Absent
                    {
                        return Err(guardian_quarantined());
                    }
                    CompositeStopTarget::Absent
                }
            }
        };
        let context = ExecutionContext {
            action: HostAction::Stop,
            request_id: *request.header().request_id(),
            request_digest,
            sandbox_id: *request.fence().sandbox_id(),
            incarnation_id: *request.fence().incarnation_id(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: *request.fence().assignment_digest(),
            receipt_present: false,
        };
        DurableExecution::composite_stop(context, target)
            .ok_or_else(|| HostError::State("composite Stop durable target is invalid".to_owned()))
    }

    pub(super) async fn advance_composite_stop(
        &mut self,
        fence: &ValidatedAssignmentFence,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        maximum_response_bytes: u32,
        trusted_clock: &mut (impl FnMut() -> Result<RawPairedClockSample> + Send),
    ) -> Result<Vec<u8>>
    where
        W: Sync,
    {
        let identity = HostRuntimeIdentity::from(fence);
        for _ in 0..8 {
            let record = self
                .state
                .composite_stop_execution(&request_id)
                .ok_or_else(|| {
                    HostError::State("composite Stop lost its durable execution".to_owned())
                })?;
            let progress = match record.phase {
                CompositeStopPhase::StopEffectIssued { progress } => Some(progress),
                CompositeStopPhase::StopAuthorized | CompositeStopPhase::Complete { .. } => None,
            };
            let payload = self
                .observe_stop_unit(
                    &identity,
                    ExactUnitRole::Payload,
                    &record.target.payload(),
                    progress == Some(StopProgress::PayloadAwaitingAbsence),
                )
                .await?;
            let guardian = self
                .observe_stop_unit(
                    &identity,
                    ExactUnitRole::Guardian,
                    &record.target.guardian(),
                    progress == Some(StopProgress::GuardianAwaitingAbsence),
                )
                .await?;

            let both_absent =
                payload == UnitObservation::Absent && guardian == UnitObservation::Absent;
            let mut proposed = self.state.clone();
            let observation_sequence = if both_absent {
                proposed.next_observation_sequence(*identity.incarnation_id())?
            } else {
                0
            };
            let decision = decide_composite_stop(StopDecisionInput {
                target: &record.target,
                phase: &record.phase,
                freshness: guardian_authority_freshness(&self.authority, effect, trusted_clock),
                payload,
                guardian,
                observation_sequence,
            });
            match decision {
                StopDecision::PersistThen { phase, effect } => {
                    // Persisting the exact target is the authority
                    // linearization point. The worker may retry this same
                    // containment effect after a crash or lease expiry.
                    proposed.set_composite_stop_phase(
                        &request_id,
                        phase.clone(),
                        &self.authority,
                    )?;
                    self.commit_state(&proposed)?;
                    let (role, target, awaiting) = match effect {
                        PlannedEffect::StopPayload(target) => (
                            ExactUnitRole::Payload,
                            target,
                            StopProgress::PayloadAwaitingAbsence,
                        ),
                        PlannedEffect::StopGuardian(target) => (
                            ExactUnitRole::Guardian,
                            target,
                            StopProgress::GuardianAwaitingAbsence,
                        ),
                        PlannedEffect::StartGuardian | PlannedEffect::StartPayload => {
                            return Err(HostError::State(
                                "composite Stop planned a start effect".to_owned(),
                            ));
                        }
                    };
                    self.execute_exact_stop(&identity, request_id, role, target, awaiting)
                        .await?;
                }
                StopDecision::RetryIssued(effect) => {
                    let (role, target, awaiting) = match effect {
                        PlannedEffect::StopPayload(target) => (
                            ExactUnitRole::Payload,
                            target,
                            StopProgress::PayloadAwaitingAbsence,
                        ),
                        PlannedEffect::StopGuardian(target) => (
                            ExactUnitRole::Guardian,
                            target,
                            StopProgress::GuardianAwaitingAbsence,
                        ),
                        PlannedEffect::StartGuardian | PlannedEffect::StartPayload => {
                            return Err(HostError::State(
                                "composite Stop retried a start effect".to_owned(),
                            ));
                        }
                    };
                    self.execute_exact_stop(&identity, request_id, role, target, awaiting)
                        .await?;
                }
                StopDecision::Persist(complete @ CompositeStopPhase::Complete { .. }) => {
                    let observation = WorkerObservation {
                        state: ObservedRuntimeState::Absent,
                        invocation_id: None,
                        leader: None,
                        payload: None,
                    };
                    let response =
                        encode_observation(&identity, observation_sequence, &observation)?;
                    ensure_response_bound(&response, maximum_response_bytes)?;
                    let completed = effect
                        .clone()
                        .complete(response.clone())
                        .map_err(|_| HostError::Fence("completed host effect is invalid"))?;
                    let sealed_completed = self.authority.seal_effect(&request_id, &completed)?;
                    proposed.set_composite_stop_phase(&request_id, complete, &self.authority)?;
                    proposed.complete(
                        request_id,
                        request_digest,
                        sealed_completed,
                        response.clone(),
                    )?;
                    self.commit_state(&proposed)?;
                    self.retain_runtime_observation(identity, observation)?;
                    return Ok(response);
                }
                StopDecision::ObserveAgain => return Err(composite_stop_pending()),
                StopDecision::Reject(_) => {
                    return Err(HostError::Worker(
                        "composite Stop is not authorized by current durable evidence".to_owned(),
                    ));
                }
                StopDecision::Quarantine => {
                    return Err(HostError::Worker(
                        "composite Stop observation requires quarantine".to_owned(),
                    ));
                }
                StopDecision::HistoricalComplete | StopDecision::Persist(_) => {
                    return Err(HostError::State(
                        "composite Stop reached an invalid completion phase".to_owned(),
                    ));
                }
            }
        }
        Err(composite_stop_pending())
    }

    async fn observe_stop_unit(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
        target: &StopUnitTarget,
        post_unref: bool,
    ) -> Result<UnitObservation>
    where
        W: Sync,
    {
        let observed = if post_unref {
            self.worker.observe_post_unref(identity, role).await?
        } else {
            match role {
                ExactUnitRole::Payload => self.worker.observe_bound_payload(identity).await?,
                ExactUnitRole::Guardian => self.worker.observe_guardian(identity).await?,
            }
        };
        let projected = guardian_unit_observation(observed);
        if matches!(target, StopUnitTarget::Absent) && projected != UnitObservation::Absent {
            return Ok(projected);
        }
        Ok(projected)
    }

    async fn execute_exact_stop(
        &mut self,
        identity: &HostRuntimeIdentity,
        request_id: [u8; 16],
        role: ExactUnitRole,
        target: StopUnitTarget,
        awaiting: StopProgress,
    ) -> Result<()>
    where
        W: Sync,
    {
        let Some((Some(binding), invocation)) = target.exact_identity() else {
            return Err(HostError::State(
                "composite Stop effect lost its exact bound target".to_owned(),
            ));
        };
        match self
            .worker
            .stop_exact_unit(identity, role, binding, invocation)
            .await?
        {
            ExactWorkerStopOutcome::AwaitingAbsence(_) | ExactWorkerStopOutcome::Missing => {
                let mut proposed = self.state.clone();
                proposed.set_composite_stop_phase(
                    &request_id,
                    CompositeStopPhase::StopEffectIssued { progress: awaiting },
                    &self.authority,
                )?;
                self.commit_state(&proposed)
            }
            ExactWorkerStopOutcome::Residual(_) => Err(composite_stop_pending()),
            ExactWorkerStopOutcome::Foreign(_) => Err(HostError::Worker(
                "composite Stop exact target became foreign".to_owned(),
            )),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Guardian advancement joins one complete durable request and its retained pins"
    )]
    pub(super) async fn advance_guardian_start(
        &mut self,
        fence: &ValidatedAssignmentFence,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        spec: GuardianUnitSpec,
        payload: PreparedLaunch,
        maximum_response_bytes: u32,
        trusted_clock: &mut (impl FnMut() -> Result<RawPairedClockSample> + Send),
    ) -> Result<Vec<u8>>
    where
        W: Sync,
    {
        let identity = HostRuntimeIdentity::new(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
        );
        let attempt = self.state.guardian_attempt(&request_id).ok_or_else(|| {
            HostError::State("Guardian launch lost its durable attempt".to_owned())
        })?;
        let binding = attempt.binding;
        let mut phase = attempt.phase.clone();

        if matches!(phase, GuardianLaunchPhase::CleanupIssued { .. }) {
            return self
                .advance_guardian_compensation(
                    &identity,
                    request_id,
                    request_digest,
                    effect,
                    maximum_response_bytes,
                    binding,
                )
                .await;
        }

        if matches!(
            phase,
            GuardianLaunchPhase::Authorized | GuardianLaunchPhase::GuardianStartIssued
        ) {
            let guardian =
                guardian_unit_observation(self.worker.observe_guardian(&identity).await?);
            let payload_observation =
                guardian_unit_observation(self.worker.observe_bound_payload(&identity).await?);
            let decision = decide_guardian_launch(GuardianDecisionInput {
                binding,
                phase: &phase,
                freshness: guardian_authority_freshness(&self.authority, effect, trusted_clock),
                guardian_job: StartJobEvidence::None,
                payload_job: StartJobEvidence::None,
                guardian,
                payload: payload_observation,
                worker_proof: None,
            });
            match decision {
                GuardianDecision::PersistThen {
                    phase: committed,
                    effect: PlannedEffect::StartGuardian,
                } => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, committed.clone(), &self.authority)?;
                    self.commit_state(&proposed)?;
                    phase = committed;
                }
                GuardianDecision::RetryIssued(PlannedEffect::StartGuardian) => {}
                GuardianDecision::PersistThen {
                    phase: cleanup @ GuardianLaunchPhase::CleanupIssued { .. },
                    effect: cleanup_effect,
                } => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, cleanup, &self.authority)?;
                    self.commit_state(&proposed)?;
                    self.execute_guardian_cleanup_effect(&identity, request_id, cleanup_effect)
                        .await?;
                    return self
                        .advance_guardian_compensation(
                            &identity,
                            request_id,
                            request_digest,
                            effect,
                            maximum_response_bytes,
                            binding,
                        )
                        .await;
                }
                GuardianDecision::Compensated => {
                    return self.complete_guardian_compensation(
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        identity,
                    );
                }
                GuardianDecision::Reject(_) => return Err(guardian_rejected()),
                GuardianDecision::Quarantine => return Err(guardian_quarantined()),
                GuardianDecision::Persist(_)
                | GuardianDecision::PersistThen { .. }
                | GuardianDecision::RetryIssued(_)
                | GuardianDecision::ObserveAgain
                | GuardianDecision::HistoricalComplete => {
                    return Err(unexpected_guardian_decision("pre-start recovery"));
                }
            }

            let start = {
                let authority = &self.authority;
                let mut before_effect = || {
                    authority
                        .check_before_effect(effect, &mut || {
                            trusted_clock().map_err(|_| {
                                aos_sandbox_broker::BrokerAdmissionError::FenceRejected
                            })
                        })
                        .map_err(HostError::from)
                };
                self.worker
                    .start_guardian(&spec, &identity, &mut before_effect)
                    .await?
            };
            let payload_observation =
                guardian_unit_observation(self.worker.observe_bound_payload(&identity).await?);
            let decision = decide_guardian_launch(GuardianDecisionInput {
                binding,
                phase: &phase,
                freshness: guardian_authority_freshness(&self.authority, effect, trusted_clock),
                guardian_job: if start.job_done {
                    StartJobEvidence::DoneForCurrentSubmission
                } else {
                    StartJobEvidence::FailedForCurrentSubmission
                },
                payload_job: StartJobEvidence::None,
                guardian: guardian_unit_observation(start.observation),
                payload: payload_observation,
                worker_proof: None,
            });
            phase = match decision {
                GuardianDecision::Persist(ready @ GuardianLaunchPhase::GuardianReady { .. }) => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, ready.clone(), &self.authority)?;
                    self.commit_state(&proposed)?;
                    ready
                }
                GuardianDecision::PersistThen {
                    phase: cleanup @ GuardianLaunchPhase::CleanupIssued { .. },
                    effect: cleanup_effect,
                } => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, cleanup, &self.authority)?;
                    self.commit_state(&proposed)?;
                    self.execute_guardian_cleanup_effect(&identity, request_id, cleanup_effect)
                        .await?;
                    return self
                        .advance_guardian_compensation(
                            &identity,
                            request_id,
                            request_digest,
                            effect,
                            maximum_response_bytes,
                            binding,
                        )
                        .await;
                }
                GuardianDecision::Compensated => {
                    return self.complete_guardian_compensation(
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        identity,
                    );
                }
                GuardianDecision::Reject(_) => return Err(guardian_rejected()),
                GuardianDecision::Quarantine => return Err(guardian_quarantined()),
                GuardianDecision::Persist(_)
                | GuardianDecision::PersistThen { .. }
                | GuardianDecision::RetryIssued(_)
                | GuardianDecision::ObserveAgain
                | GuardianDecision::HistoricalComplete => {
                    return Err(unexpected_guardian_decision("Guardian start result"));
                }
            };
        }

        let mut payload_submission_committed_here = false;
        if let GuardianLaunchPhase::GuardianReady { .. } = phase {
            let guardian =
                guardian_unit_observation(self.worker.observe_guardian(&identity).await?);
            let payload_observation =
                guardian_unit_observation(self.worker.observe_bound_payload(&identity).await?);
            let decision = decide_guardian_launch(GuardianDecisionInput {
                binding,
                phase: &phase,
                freshness: guardian_authority_freshness(&self.authority, effect, trusted_clock),
                guardian_job: StartJobEvidence::None,
                payload_job: StartJobEvidence::None,
                guardian,
                payload: payload_observation,
                worker_proof: None,
            });
            match decision {
                GuardianDecision::PersistThen {
                    phase: committed @ GuardianLaunchPhase::PayloadStartIssued { .. },
                    effect: PlannedEffect::StartPayload,
                } => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, committed.clone(), &self.authority)?;
                    self.commit_state(&proposed)?;
                    phase = committed;
                    payload_submission_committed_here = true;
                }
                GuardianDecision::PersistThen {
                    phase: cleanup @ GuardianLaunchPhase::CleanupIssued { .. },
                    effect: cleanup_effect,
                } => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, cleanup, &self.authority)?;
                    self.commit_state(&proposed)?;
                    self.execute_guardian_cleanup_effect(&identity, request_id, cleanup_effect)
                        .await?;
                    return self
                        .advance_guardian_compensation(
                            &identity,
                            request_id,
                            request_digest,
                            effect,
                            maximum_response_bytes,
                            binding,
                        )
                        .await;
                }
                GuardianDecision::Compensated => {
                    return self.complete_guardian_compensation(
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        identity,
                    );
                }
                GuardianDecision::Reject(_) => return Err(guardian_rejected()),
                GuardianDecision::Quarantine => return Err(guardian_quarantined()),
                GuardianDecision::Persist(_)
                | GuardianDecision::PersistThen { .. }
                | GuardianDecision::RetryIssued(_)
                | GuardianDecision::ObserveAgain
                | GuardianDecision::HistoricalComplete => {
                    return Err(unexpected_guardian_decision("Guardian readiness"));
                }
            }
        }

        if matches!(phase, GuardianLaunchPhase::PayloadVerified { .. }) {
            return self
                .finalize_guardian_payload_verified(
                    request_id,
                    request_digest,
                    effect,
                    payload,
                    maximum_response_bytes,
                    identity,
                    binding,
                    phase,
                    trusted_clock,
                )
                .await;
        }

        let GuardianLaunchPhase::PayloadStartIssued {
            guardian_invocation,
        } = &phase
        else {
            return Err(guardian_pending());
        };
        let verification = if payload_submission_committed_here {
            let authority = &self.authority;
            let mut before_effect = || {
                authority
                    .check_before_effect(effect, &mut || {
                        trusted_clock()
                            .map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
                    })
                    .map_err(HostError::from)
            };
            self.worker
                .start_bound_payload(
                    payload.spec(),
                    payload.pins(),
                    &identity,
                    *guardian_invocation,
                    &mut before_effect,
                )
                .await
                .map(|done| {
                    (
                        done.verification,
                        StartJobEvidence::DoneForCurrentSubmission,
                    )
                })
        } else {
            self.worker
                .prove_bound_payload(payload.spec(), payload.pins(), &identity)
                .await
                .map(|proof| (proof.verification, StartJobEvidence::RecoveredExactProof))
        };
        let (verified, payload_job) = match verification {
            Ok(verified) => verified,
            Err(_) => {
                return self
                    .begin_guardian_compensation(
                        &identity,
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        binding,
                    )
                    .await;
            }
        };
        let guardian = guardian_unit_observation(self.worker.observe_guardian(&identity).await?);
        let payload_observation = UnitObservation::Present {
            binding: verified.binding,
            invocation: verified.invocation_id,
            state: PresentUnitState::ActiveRunning,
        };
        let mut proposed = self.state.clone();
        let observation_sequence =
            proposed.next_observation_sequence(*identity.incarnation_id())?;
        let decision = decide_guardian_launch(GuardianDecisionInput {
            binding,
            phase: &phase,
            freshness: guardian_authority_freshness(&self.authority, effect, trusted_clock),
            guardian_job: StartJobEvidence::None,
            payload_job,
            guardian,
            payload: payload_observation,
            worker_proof: Some(crate::state::transition::WorkerProof {
                observation_sequence,
                runtime: verified.proof,
            }),
        });
        let verified_phase = match decision {
            GuardianDecision::Persist(verified @ GuardianLaunchPhase::PayloadVerified { .. }) => {
                verified
            }
            GuardianDecision::PersistThen {
                phase: cleanup @ GuardianLaunchPhase::CleanupIssued { .. },
                effect: cleanup_effect,
            } => {
                let mut cleanup_state = self.state.clone();
                cleanup_state.set_guardian_phase(&request_id, cleanup, &self.authority)?;
                self.commit_state(&cleanup_state)?;
                self.execute_guardian_cleanup_effect(&identity, request_id, cleanup_effect)
                    .await?;
                return self
                    .advance_guardian_compensation(
                        &identity,
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        binding,
                    )
                    .await;
            }
            GuardianDecision::Compensated => {
                return self.complete_guardian_compensation(
                    request_id,
                    request_digest,
                    effect,
                    maximum_response_bytes,
                    identity,
                );
            }
            GuardianDecision::Reject(_) => return Err(guardian_rejected()),
            GuardianDecision::Quarantine => return Err(guardian_quarantined()),
            GuardianDecision::Persist(_)
            | GuardianDecision::PersistThen { .. }
            | GuardianDecision::RetryIssued(_)
            | GuardianDecision::ObserveAgain
            | GuardianDecision::HistoricalComplete => {
                return Err(unexpected_guardian_decision("payload start result"));
            }
        };
        proposed.set_guardian_phase(&request_id, verified_phase.clone(), &self.authority)?;
        self.commit_state(&proposed)?;
        self.finalize_guardian_payload_verified(
            request_id,
            request_digest,
            effect,
            payload,
            maximum_response_bytes,
            identity,
            binding,
            verified_phase,
            trusted_clock,
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "verified launch finalization joins one durable request and fresh pair proof"
    )]
    pub(super) async fn finalize_guardian_payload_verified(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        payload: PreparedLaunch,
        maximum_response_bytes: u32,
        identity: HostRuntimeIdentity,
        binding: [u8; 32],
        phase: GuardianLaunchPhase,
        trusted_clock: &mut (impl FnMut() -> Result<RawPairedClockSample> + Send),
    ) -> Result<Vec<u8>>
    where
        W: Sync,
    {
        let GuardianLaunchPhase::PayloadVerified {
            guardian_invocation,
            payload_invocation,
            observation_sequence,
            worker_proof,
        } = phase
        else {
            return Err(HostError::State(
                "Guardian finalization lost its verified payload phase".to_owned(),
            ));
        };
        let verified = match self
            .worker
            .prove_bound_payload(payload.spec(), payload.pins(), &identity)
            .await
        {
            Ok(proof) => proof.verification,
            Err(_) => {
                return self
                    .begin_guardian_compensation(
                        &identity,
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        binding,
                    )
                    .await;
            }
        };
        let guardian = guardian_unit_observation(self.worker.observe_guardian(&identity).await?);
        let freshness = guardian_authority_freshness(&self.authority, effect, trusted_clock);
        let verified_phase = GuardianLaunchPhase::PayloadVerified {
            guardian_invocation,
            payload_invocation,
            observation_sequence,
            worker_proof,
        };
        let decision = decide_guardian_launch(GuardianDecisionInput {
            binding,
            phase: &verified_phase,
            freshness,
            guardian_job: StartJobEvidence::None,
            payload_job: StartJobEvidence::RecoveredExactProof,
            guardian,
            payload: UnitObservation::Present {
                binding: verified.binding,
                invocation: verified.invocation_id,
                state: PresentUnitState::ActiveRunning,
            },
            worker_proof: Some(crate::state::transition::WorkerProof {
                observation_sequence,
                runtime: verified.proof,
            }),
        });
        match decision {
            GuardianDecision::Persist(GuardianLaunchPhase::Complete { .. }) => self
                .complete_guardian_launch(
                    request_id,
                    request_digest,
                    effect,
                    maximum_response_bytes,
                    identity,
                    observation_sequence,
                    verified.observation,
                    verified_phase,
                ),
            GuardianDecision::PersistThen {
                phase: cleanup @ GuardianLaunchPhase::CleanupIssued { .. },
                effect: cleanup_effect,
            } => {
                let mut proposed = self.state.clone();
                proposed.set_guardian_phase(&request_id, cleanup, &self.authority)?;
                self.commit_state(&proposed)?;
                self.execute_guardian_cleanup_effect(&identity, request_id, cleanup_effect)
                    .await?;
                self.advance_guardian_compensation(
                    &identity,
                    request_id,
                    request_digest,
                    effect,
                    maximum_response_bytes,
                    binding,
                )
                .await
            }
            GuardianDecision::Compensated => self.complete_guardian_compensation(
                request_id,
                request_digest,
                effect,
                maximum_response_bytes,
                identity,
            ),
            GuardianDecision::Reject(_) => Err(guardian_rejected()),
            GuardianDecision::Quarantine => Err(guardian_quarantined()),
            GuardianDecision::Persist(_)
            | GuardianDecision::PersistThen { .. }
            | GuardianDecision::RetryIssued(_)
            | GuardianDecision::ObserveAgain
            | GuardianDecision::HistoricalComplete => {
                Err(unexpected_guardian_decision("payload finalization"))
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "durable launch completion joins one exact request, proof, and receipt"
    )]
    fn complete_guardian_launch(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        maximum_response_bytes: u32,
        identity: HostRuntimeIdentity,
        observation_sequence: u64,
        observation: WorkerObservation,
        verified_phase: GuardianLaunchPhase,
    ) -> Result<Vec<u8>> {
        let GuardianLaunchPhase::PayloadVerified {
            guardian_invocation,
            payload_invocation,
            worker_proof,
            ..
        } = verified_phase
        else {
            return Err(HostError::State(
                "Guardian completion did not retain a verified payload".to_owned(),
            ));
        };
        let response = encode_observation(&identity, observation_sequence, &observation)?;
        ensure_response_bound(&response, maximum_response_bytes)?;
        let completed = effect
            .clone()
            .complete(response.clone())
            .map_err(|_| HostError::Fence("completed host effect is invalid"))?;
        let sealed_completed = self.authority.seal_effect(&request_id, &completed)?;
        let complete_phase = GuardianLaunchPhase::Complete {
            guardian_invocation,
            payload_invocation,
            observation_sequence,
            worker_proof,
        };

        let mut proposed = self.state.clone();
        proposed.set_guardian_phase(&request_id, complete_phase, &self.authority)?;
        proposed.complete(
            request_id,
            request_digest,
            sealed_completed,
            response.clone(),
        )?;
        self.retain_runtime_observation(identity, observation)?;
        self.commit_state(&proposed)?;
        Ok(response)
    }

    pub(super) async fn begin_guardian_compensation(
        &mut self,
        identity: &HostRuntimeIdentity,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        maximum_response_bytes: u32,
        binding: [u8; 32],
    ) -> Result<Vec<u8>>
    where
        W: Sync,
    {
        let attempt = self.state.guardian_attempt(&request_id).ok_or_else(|| {
            HostError::State("Guardian compensation lost its durable attempt".to_owned())
        })?;
        let phase = attempt.phase.clone();
        let decision = decide_guardian_launch(GuardianDecisionInput {
            binding,
            phase: &phase,
            freshness: AuthorityFreshness::Expired,
            guardian_job: StartJobEvidence::None,
            payload_job: StartJobEvidence::FailedForCurrentSubmission,
            guardian: guardian_unit_observation(self.worker.observe_guardian(identity).await?),
            payload: guardian_unit_observation(self.worker.observe_bound_payload(identity).await?),
            worker_proof: None,
        });
        match decision {
            GuardianDecision::PersistThen {
                phase: cleanup @ GuardianLaunchPhase::CleanupIssued { .. },
                effect: cleanup_effect,
            } => {
                let mut proposed = self.state.clone();
                proposed.set_guardian_phase(&request_id, cleanup, &self.authority)?;
                self.commit_state(&proposed)?;
                self.execute_guardian_cleanup_effect(identity, request_id, cleanup_effect)
                    .await?;
                self.advance_guardian_compensation(
                    identity,
                    request_id,
                    request_digest,
                    effect,
                    maximum_response_bytes,
                    binding,
                )
                .await
            }
            GuardianDecision::Compensated => self.complete_guardian_compensation(
                request_id,
                request_digest,
                effect,
                maximum_response_bytes,
                *identity,
            ),
            GuardianDecision::Reject(_) => Err(guardian_rejected()),
            GuardianDecision::Quarantine => Err(guardian_quarantined()),
            GuardianDecision::Persist(_)
            | GuardianDecision::PersistThen { .. }
            | GuardianDecision::RetryIssued(_)
            | GuardianDecision::ObserveAgain
            | GuardianDecision::HistoricalComplete => {
                Err(unexpected_guardian_decision("compensation entry"))
            }
        }
    }

    pub(super) async fn advance_guardian_compensation(
        &mut self,
        identity: &HostRuntimeIdentity,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        maximum_response_bytes: u32,
        binding: [u8; 32],
    ) -> Result<Vec<u8>>
    where
        W: Sync,
    {
        for _ in 0..8 {
            let attempt = self.state.guardian_attempt(&request_id).ok_or_else(|| {
                HostError::State("Guardian cleanup lost its durable attempt".to_owned())
            })?;
            let phase = attempt.phase.clone();
            let GuardianLaunchPhase::CleanupIssued { progress, .. } = &phase else {
                return Err(guardian_pending());
            };
            let payload_observation = self
                .observe_guardian_cleanup_unit(
                    identity,
                    ExactUnitRole::Payload,
                    *progress == CleanupProgress::PayloadAwaitingAbsence,
                )
                .await?;
            let guardian_observation = self
                .observe_guardian_cleanup_unit(
                    identity,
                    ExactUnitRole::Guardian,
                    *progress == CleanupProgress::GuardianAwaitingAbsence,
                )
                .await?;
            let decision = decide_guardian_launch(GuardianDecisionInput {
                binding,
                phase: &phase,
                freshness: AuthorityFreshness::Expired,
                guardian_job: StartJobEvidence::None,
                payload_job: StartJobEvidence::None,
                guardian: guardian_observation,
                payload: payload_observation,
                worker_proof: None,
            });
            match decision {
                GuardianDecision::PersistThen { phase, effect } => {
                    let mut proposed = self.state.clone();
                    proposed.set_guardian_phase(&request_id, phase, &self.authority)?;
                    self.commit_state(&proposed)?;
                    self.execute_guardian_cleanup_effect(identity, request_id, effect)
                        .await?;
                }
                GuardianDecision::RetryIssued(effect) => {
                    self.execute_guardian_cleanup_effect(identity, request_id, effect)
                        .await?;
                }
                GuardianDecision::Compensated => {
                    return self.complete_guardian_compensation(
                        request_id,
                        request_digest,
                        effect,
                        maximum_response_bytes,
                        *identity,
                    );
                }
                GuardianDecision::ObserveAgain => return Err(guardian_pending()),
                GuardianDecision::Quarantine => return Err(guardian_quarantined()),
                GuardianDecision::Reject(_) => return Err(guardian_rejected()),
                GuardianDecision::Persist(_) | GuardianDecision::HistoricalComplete => {
                    return Err(HostError::State(
                        "Guardian cleanup reached an invalid transition".to_owned(),
                    ));
                }
            }
        }
        Err(guardian_pending())
    }

    fn complete_guardian_compensation(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        effect: &BrokerEffectIntentV2,
        maximum_response_bytes: u32,
        identity: HostRuntimeIdentity,
    ) -> Result<Vec<u8>> {
        let mut proposed = self.state.clone();
        let observation_sequence =
            proposed.next_observation_sequence(*identity.incarnation_id())?;
        let observation = WorkerObservation {
            state: ObservedRuntimeState::Absent,
            invocation_id: None,
            leader: None,
            payload: None,
        };
        let response = encode_observation(&identity, observation_sequence, &observation)?;
        ensure_response_bound(&response, maximum_response_bytes)?;
        let completed = effect
            .clone()
            .complete(response.clone())
            .map_err(|_| HostError::Fence("completed host effect is invalid"))?;
        let sealed_completed = self.authority.seal_effect(&request_id, &completed)?;

        proposed.set_guardian_phase(
            &request_id,
            GuardianLaunchPhase::Compensated {
                observation_sequence,
            },
            &self.authority,
        )?;
        proposed.complete(
            request_id,
            request_digest,
            sealed_completed,
            response.clone(),
        )?;
        self.commit_state(&proposed)?;
        self.retain_runtime_observation(identity, observation)?;
        Ok(response)
    }

    async fn observe_guardian_cleanup_unit(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
        post_unref: bool,
    ) -> Result<UnitObservation>
    where
        W: Sync,
    {
        let observed = if post_unref {
            self.worker.observe_post_unref(identity, role).await?
        } else {
            match role {
                ExactUnitRole::Payload => self.worker.observe_bound_payload(identity).await?,
                ExactUnitRole::Guardian => self.worker.observe_guardian(identity).await?,
            }
        };
        Ok(guardian_unit_observation(observed))
    }

    pub(super) async fn execute_guardian_cleanup_effect(
        &mut self,
        identity: &HostRuntimeIdentity,
        request_id: [u8; 16],
        effect: PlannedEffect,
    ) -> Result<()>
    where
        W: Sync,
    {
        let (role, target, awaiting) = match effect {
            PlannedEffect::StopPayload(target) => (
                ExactUnitRole::Payload,
                target,
                CleanupProgress::PayloadAwaitingAbsence,
            ),
            PlannedEffect::StopGuardian(target) => (
                ExactUnitRole::Guardian,
                target,
                CleanupProgress::GuardianAwaitingAbsence,
            ),
            PlannedEffect::StartGuardian | PlannedEffect::StartPayload => {
                return Err(HostError::State(
                    "Guardian cleanup planned a start effect".to_owned(),
                ));
            }
        };
        let Some((Some(binding), invocation)) = target.exact_identity() else {
            return Err(HostError::State(
                "Guardian cleanup lost its exact bound target".to_owned(),
            ));
        };
        match self
            .worker
            .stop_exact_unit(identity, role, binding, invocation)
            .await?
        {
            ExactWorkerStopOutcome::AwaitingAbsence(_) | ExactWorkerStopOutcome::Missing => {
                let attempt = self.state.guardian_attempt(&request_id).ok_or_else(|| {
                    HostError::State("Guardian cleanup lost its durable attempt".to_owned())
                })?;
                let GuardianLaunchPhase::CleanupIssued {
                    payload, guardian, ..
                } = attempt.phase
                else {
                    return Err(HostError::State(
                        "Guardian cleanup lost its committed phase".to_owned(),
                    ));
                };
                let phase = GuardianLaunchPhase::CleanupIssued {
                    payload: payload.clone(),
                    guardian: guardian.clone(),
                    progress: awaiting,
                };
                let mut proposed = self.state.clone();
                proposed.set_guardian_phase(&request_id, phase, &self.authority)?;
                self.commit_state(&proposed)
            }
            ExactWorkerStopOutcome::Residual(_) => Err(guardian_pending()),
            ExactWorkerStopOutcome::Foreign(_) => Err(guardian_quarantined()),
        }
    }
}

fn unexpected_guardian_decision(stage: &str) -> HostError {
    HostError::State(format!(
        "Guardian reducer returned an invalid decision during {stage}"
    ))
}
