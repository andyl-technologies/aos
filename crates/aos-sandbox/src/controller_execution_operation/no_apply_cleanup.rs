//! Enters fresh cleanup on the same genuine Controller18 native engine.
//!
//! A cold terminal operation cannot enter through the ordinary accepted-Apply
//! decoder. This distinct finite receiver pays before decoding actual C rows,
//! retains its own fresh native clock and two kernel nonces, and lends only
//! current cleanup Source reception. It has no Environment, Apply, positive
//! retirement or ordinary execution projection. Old64/39 coordinates select
//! history; Root must independently authenticate them before acquisition.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use super::*;

pub(super) struct ControllerExecutionCleanupOriginalV2 {
    entered: bool,
    native: Option<Box<Native>>,
    reentry: Option<ResourceReservationErrorV1>,
}

struct Native {
    target: OperationId,
    history_current: Option<Result<(), ResourceReservationErrorV1>>,
    admission: crate::policy_compiler::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2,
    cutoff: Option<Result<u64, ResourceReservationErrorV1>>,
    clock: Option<
        Result<
            RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError,
        >,
    >,
    entropy: [RetainedKernelNonceOriginalV1; 2],
    observed: [Option<Result<[u8; 16], EntropyError>>; 2],
    nonce: Option<Result<[u8; 32], ResourceReservationErrorV1>>,
    decoded: Option<Result<crate::reconciler::ClosedCreateFailurePlanDataV2, ReconcilerError>>,
}

impl ControllerExecutionCleanupOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            native: None,
            reentry: None,
        }
    }

    fn demand(
        controller: &Journal,
        runtime: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Native>()
            .checked_mul(2)
            .and_then(|n| {
                n.checked_add(
                    size_of::<ControllerExecutionCleanupReceivingLoanV2<'_>>().checked_mul(2)?,
                )
            })
            .and_then(|n| {
                n.checked_add(
                    size_of::<ControllerExecutionCleanupSourceLoanV2<'_, '_>>().checked_mul(2)?,
                )
            })
            .and_then(|n| {
                n.checked_add(
                    RetainedKernelNonceOriginalV1::construction_bytes_v1()?.checked_mul(2)?,
                )
            })
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        crate::reconciler::ClosedCreateFailurePlanDataV2::receiving_demand_data_v2(controller)?
            .checked_add(
                ControllerExecutionClockOriginalV1::fixed_demand_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
            )?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?
            .checked_add(runtime)
            .map_err(Into::into)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native_failure()
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn native_failure(&self) -> Option<&(dyn Error + 'static)> {
        let native = self.native.as_deref();
        native
            .and_then(|native| error(&native.clock))
            .or_else(|| native.and_then(|native| error(&native.cutoff)))
            .or_else(|| native.and_then(|native| native.entropy[0].failure()))
            .or_else(|| native.and_then(|native| error(&native.observed[0])))
            .or_else(|| native.and_then(|native| native.entropy[1].failure()))
            .or_else(|| native.and_then(|native| error(&native.observed[1])))
            .or_else(|| native.and_then(|native| error(&native.nonce)))
            .or_else(|| native.and_then(|native| error(&native.history_current)))
            .or_else(|| native.and_then(|native| error(&native.decoded)))
    }

    fn require_native(&self) -> Result<&Native, ResourceReservationErrorV1> {
        let native = self
            .native
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.failure().is_some()
            || !matches!(native.nonce, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(native)
    }
}

impl ControllerExecutionOperationOriginalV1 {
    /// Enters a fresh cleanup-only C18 before any canonical history decode.
    ///
    /// The completed current kind3 Recover association checks the actual target
    /// before a NEW interval is consumed. History decode follows paid Source
    /// and cold Session reception; an old Apply scope cannot enter again.
    /// Genuine Root/Host history and current policy remain mandatory before42.
    /// A returned loan can contain an entered failure and must still finish
    /// its independent native post before reporting that retained cause.
    ///
    /// # Errors
    /// Rejects another cleanup, overlap, an admission handoff, failed funding,
    /// arithmetic overflow or a representation beyond the same declaration.
    pub fn begin_no_apply_cleanup_once_v2<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        completed: &crate::controller_resource_reservation::OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'_>,
        target: OperationId,
        runtime: Demand,
    ) -> Result<ControllerExecutionCleanupReceivingLoanV2<'owner>, ResourceReservationErrorV1> {
        if self.cleanup.entered || self.predurable_entered || self.predurable_prefix.is_some() {
            self.cleanup
                .reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        completed.require_fresh_execution_cleanup_v2(bank, controller, profile, target)?;
        let (key, raw) = completed.admission_record_data_v2(controller)?;
        let decoded = aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::CreateFinalityObservationAdmissionDataV1::decode_v1(raw)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let reference = crate::policy_compiler::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2 {
            key,
            commitment: aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::finality_admission_commitment_v1(raw),
            original: decoded.original,
            cutoff: decoded.cutoff,
            wall_expiry: decoded.wall_expiry,
        };
        let prefix = ControllerExecutionCleanupOriginalV2::demand(controller, runtime.demand_v1())?;
        self.cleanup.entered = true;
        let mut admission = self.begin_native_engine_v2(bank, controller, profile, prefix)?;
        if matches!(admission.entry, Some(Ok(()))) {
            admission.cleanup.native = Some(Box::new(Native {
                target,
                history_current: None,
                admission: reference,
                cutoff: None,
                clock: None,
                entropy: std::array::from_fn(|_| RetainedKernelNonceOriginalV1::new()),
                observed: std::array::from_fn(|_| None),
                nonce: None,
                decoded: None,
            }));
            let native = admission
                .cleanup
                .native
                .as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            native.clock = Some(admission.clock.sample_v1());
            if matches!(native.clock, Some(Ok(_))) {
                native.cutoff = Some((|| {
                    let first = native.clock.as_ref().and_then(|value| value.as_ref().ok())
                        .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
                    let expiry = first.conservative_expiry_deadline_data_v1(reference.wall_expiry)
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    let cutoff = reference.cutoff.min(expiry);
                    if reference.original.validate_same_boot_elapsed_data_v1(first).is_err()
                        || first.boottime_nanoseconds() >= cutoff
                    {
                        return Err(ResourceReservationErrorV1::Conflict);
                    }
                    Ok(cutoff)
                })());
                if !matches!(native.cutoff, Some(Ok(_))) {
                    return Ok(ControllerExecutionCleanupReceivingLoanV2 { admission });
                }
                native.observed[0] = Some(native.entropy[0].observe_once());
                if matches!(native.observed[0], Some(Ok(_))) {
                    native.observed[1] = Some(native.entropy[1].observe_once());
                }
                native.nonce = Some((|| {
                    let first = native.observed[0]
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    let second = native.observed[1]
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    // The fresh42 request ID is exactly this first half. A
                    // zero prefix is a paid failure, never an unpaid redraw.
                    if first == &[0; 16] {
                        return Err(ResourceReservationErrorV1::Conflict);
                    }
                    let mut nonce = [0; 32];
                    nonce[..16].copy_from_slice(first);
                    nonce[16..].copy_from_slice(second);
                    Ok(nonce)
                })());
            }
        }
        Ok(ControllerExecutionCleanupReceivingLoanV2 { admission })
    }
}

/// Borrows fresh native C18 custody without an accepted-Apply context.
#[must_use]
pub struct ControllerExecutionCleanupReceivingLoanV2<'owner> {
    admission: ControllerExecutionAdmissionReceivingLoanV2<'owner>,
}

impl<'owner> ControllerExecutionCleanupReceivingLoanV2<'owner> {
    /// Borrows this actual newly generated nonce as nonauthorizing request DATA.
    ///
    /// # Errors
    /// Refuses failed native entry, entropy, canonical rows or owed completion.
    pub fn controller_nonce_data_v2(&self) -> Result<[u8; 32], ResourceReservationErrorV1> {
        if !matches!(self.admission.entry, Some(Ok(()))) || self.admission.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.admission
            .cleanup
            .require_native()?
            .nonce
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the genuine first native cleanup sample, without inventing a deadline.
    ///
    /// # Errors
    /// Refuses an incomplete or failed fresh native cleanup receiver.
    pub fn first_clock_data_v2(&self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.controller_nonce_data_v2()?;
        self.admission
            .cleanup
            .require_native()?
            .clock
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Lends the same actual current Source owner only for cleanup reception.
    ///
    /// # Errors
    /// Refuses failed C18/history, a finished interval, foreign enrollment or
    /// changed Source currentness. No old execution Environment is required.
    pub fn prepare_source_once_v2<'scope>(
        &'scope mut self,
        bank: &ControllerResourceBankOpeningV1,
        source: &'scope mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        completed: &crate::controller_resource_reservation::OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'_>,
    ) -> Result<ControllerExecutionCleanupSourceLoanV2<'scope, 'owner>, ResourceReservationErrorV1>
    {
        self.controller_nonce_data_v2()?;
        completed.require_fresh_execution_cleanup_source_v2(source)?;
        self.admission.borrow_cleanup_source_once_v2(bank, source, controller, profile)
    }

    /// Runs the independently owed native C18 post after an entered refusal.
    pub fn finish_without_source_once_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        self.admission
            .finish_without_source_v2(bank, controller, profile);
    }
}

/// Retains genuine fresh cleanup Source/C custody without exposing execution ports.
#[must_use]
pub struct ControllerExecutionCleanupSourceLoanV2<'scope, 'owner> {
    source:
        crate::controller_resource_reservation::ControllerExecutionSourceScopeV1<'scope, 'owner>,
    cleanup: &'scope mut ControllerExecutionCleanupOriginalV2,
    post: &'scope mut Option<Result<(), ResourceReservationErrorV1>>,
    complete: ResourceVector,
    append_demand: &'scope mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    journal_identity: &'scope crate::journal::ExecutionObservationJournalIdentityV4,
    evidence: &'scope mut EnvironmentExecutionEvidenceOriginalV1,
    accepted: &'scope mut Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    clock: &'scope mut ControllerExecutionClockOriginalV1,
    active: &'scope mut bool,
    cold_session: Option<Result<Option<crate::ControllerInitialBrokerSessionReceivingV1>, ResourceReservationErrorV1>>,
}

impl<'scope, 'owner> ControllerExecutionCleanupSourceLoanV2<'scope, 'owner> {
    /// Checks one actual cold-clock frontier on the held Source/C18 interval.
    ///
    /// # Errors
    /// Refuses changed native custody, failed clock or the original horizon.
    #[doc(hidden)]
    pub fn check_cold_frontier_v2(&mut self, bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.admit_stage_v2(bank, controller, profile, Demand::from_demand_v1(ResourceVector::ZERO))?;
        self.observe_cold_clock_inner_v2()
    }

    fn observe_cold_clock_inner_v2(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        let sample = self.clock.sample_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let native = self.cleanup.require_native()?;
        let first = native.clock.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let cutoff = native.cutoff.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if first.validate_later_sample(sample).is_err()
            || sample.wall_seconds() >= native.admission.wall_expiry
            || sample.boottime_nanoseconds() >= *cutoff
        { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(sample)
    }

    /// Runs the separately owed cold clock post without a healthy-entry gate.
    ///
    /// # Errors
    /// Retains actual native clock failure or refuses the unchanged horizon.
    #[doc(hidden)]
    pub fn observe_cold_owed_clock_after_v2(&mut self)
        -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.observe_cold_clock_inner_v2()
    }

    /// Prepares one genuine initial cold receiver under this actual Source.
    ///
    /// # Errors
    /// Retains repeated entry, failed currentness or same-flight preparation.
    #[doc(hidden)]
    pub fn prepare_cold_session_once_v2(&mut self, bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal, profile: std::sync::Arc<ProductionControllerNormalRootProfileV1>,
        shape: crate::ControllerInitialBrokerSessionShapeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.cold_session.is_some() {
            self.retain_cold_sdk_refusal_v2();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.admit_stage_v2(bank, controller, &profile, Demand::from_demand_v1(ResourceVector::ZERO))?;
        let cutoff = *self.cleanup.require_native()?.cutoff.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        self.cold_session = Some(bank.prepare_execution_cleanup_session_v2(
            &mut self.source, controller, profile, shape, cutoff).map(Some));
        match self.cold_session.as_ref() {
            Some(Ok(Some(_))) => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Transfers the actual once-only receiver into the shared cold engine.
    ///
    /// # Errors
    /// Refuses missing, failed or already transferred native preparation.
    #[doc(hidden)]
    pub fn take_cold_session_receiver_once_v2(&mut self)
        -> Result<crate::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.controller_nonce_data_v2()?;
        self.cold_session.as_mut().and_then(|value| value.as_mut().ok())
            .and_then(Option::take).ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Joins only this Source's actual completed cold receiving original.
    ///
    /// # Errors
    /// Refuses another payer, receiver, finished Source or changed native cut.
    #[doc(hidden)]
    pub fn require_cold_session_original_v2(&self,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.controller_nonce_data_v2()?;
        receiving.require_execution_cleanup_source_v2(&self.source)
    }

    /// Parks SDK refusal on the same actual cleanup owner without further IO.
    #[doc(hidden)]
    pub fn retain_cold_sdk_refusal_v2(&mut self) {
        self.cleanup.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_actual_admission_v2(
        source: crate::controller_resource_reservation::ControllerExecutionSourceScopeV1<'scope, 'owner>,
        cleanup: &'scope mut ControllerExecutionCleanupOriginalV2,
        post: &'scope mut Option<Result<(), ResourceReservationErrorV1>>,
        complete: ResourceVector,
        append_demand: &'scope mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
        journal_identity: &'scope crate::journal::ExecutionObservationJournalIdentityV4,
        evidence: &'scope mut EnvironmentExecutionEvidenceOriginalV1,
        accepted: &'scope mut Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
        clock: &'scope mut ControllerExecutionClockOriginalV1,
        active: &'scope mut bool,
    ) -> Self {
        Self { source, cleanup, post, complete, append_demand, journal_identity,
            evidence, accepted, clock, active, cold_session: None }
    }

    /// Returns the target bound by the genuine completed kind3 association.
    ///
    /// This is comparison DATA for the paid private historical Session reader;
    /// it neither authenticates history nor authorizes42, Seal, CAS or Apply.
    ///
    /// # Errors
    /// Refuses a finished or failed fresh Source/C18 original.
    #[doc(hidden)]
    pub fn target_operation_data_v2(&self) -> Result<OperationId, ResourceReservationErrorV1> {
        self.controller_nonce_data_v2()?;
        Ok(self.cleanup.require_native()?.target)
    }

    /// Borrows retained cleanup and Source/C causes without entering a frontier.
    ///
    /// This passive diagnostic remains available after failed body or owed
    /// posts. It neither samples a clock nor reconstructs a financial owner.
    #[doc(hidden)]
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup.native_failure()
            .or_else(|| self.source.failure())
            .or_else(|| error(self.append_demand))
            .or_else(|| self.clock.failure())
            .or_else(|| self.evidence.failure())
            .or_else(|| error(self.post))
            .or_else(|| self.cleanup.reentry.as_ref().map(|cause| cause as _))
    }

    /// Holds genuine fresh cleanup Source/C posts through matching disposal.
    ///
    /// This financial token grants no Apply or terminal authority. The SDK's
    /// actual four-turn and Root completion must independently retire first.
    ///
    /// # Errors
    /// Refuses failed/missing Source/C posts, clock, canonical append demand,
    /// actual Source custody or fresh cleanup native entry.
    #[doc(hidden)]
    pub fn prepare_positive_disposal_v2<'disposal>(
        &'disposal mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &'disposal Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionPositiveDisposalV1<'disposal>, ResourceReservationErrorV1> {
        self.cleanup.require_native()?;
        if !matches!(self.post, Some(Ok(())))
            || self.clock.failure().is_some() || self.evidence.failure().is_some()
            || self.append_demand.as_ref().is_some_and(Result::is_err)
        { return Err(ResourceReservationErrorV1::Conflict); }
        let operation = self.plan_data_v2()?.operation_data_v2();
        let native = bank.prepare_execution_source_disposal_v1(&mut self.source, controller, profile)?;
        Ok(ControllerExecutionPositiveDisposalV1 {
            cleanup: Some(self.cleanup), operation, journal_identity: self.journal_identity,
            native, evidence: self.evidence, accepted: self.accepted,
            append_demand: self.append_demand, clock: self.clock, post: self.post,
            active: self.active,
        })
    }

    /// Borrows fresh cleanup Source/C and the actual finite Host Session.
    ///
    /// Historical arguments select independent Root verification only. Host42
    /// remains unavailable until this same loan receives a genuine acquisition.
    /// No Environment or ordinary execution port is exposed.
    ///
    /// # Errors
    /// Retains fresh funding, native Session, history-join or original refusal.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn borrow_no_apply_client_once_v2<'turn>(
        &'turn mut self,
        original: &'turn mut ControllerExecutionNoApplyOriginalV2,
        controller: &'turn mut Journal,
        bank: &'turn ControllerResourceBankOpeningV1,
        profile: &'turn ProductionControllerNormalRootProfileV1,
        historical_terminal: aos_sandbox_protocol::host_execution_no_apply::ClosedHostTerminalArchiveDataV2,
        historical_availability: aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2,
        host_journal: &Journal,
        host_socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        host_transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ControllerExecutionNoApplyClientLoanV2<'turn, 'turn, 'owner>, ResourceReservationErrorV1> {
        self.controller_nonce_data_v2()?;
        let current = bank.require_execution_source_complete_v1(&mut self.source, controller, profile,
            Demand::from_demand_v1(self.complete));
        let native = self.cleanup.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        native.history_current = Some(current);
        if !matches!(native.history_current, Some(Ok(()))) || native.decoded.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.decoded = Some((|| {
            let marker = historical_terminal.marker();
            if marker.fields().source.fields().create_operation != *native.target.as_bytes() {
                return Err(ReconcilerError::InvalidExecutorOutput("cleanup historical terminal targets another Create"));
            }
            // This canonical model was included in the genuine initial C18
            // prefix before Source/HELLO/archive reception. Its supplied wall
            // selects comparison DATA only; Root independently establishes
            // historical prepare/floor wall and phase before granting42.
            let first = native.clock.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ReconcilerError::InvalidExecutorOutput("cleanup first clock is absent"))?;
            let wall = controller.get(crate::RecordNamespace::ControllerCreateFailurePrepare, native.target.as_bytes())
                .map(|raw| aos_sandbox_protocol::host_execution_no_apply::closed_controller::ClosedCreateFailurePrepareDataV2::decode_canonical(native.target.as_bytes(), raw)
                    .map(|prepare| prepare.wall_seconds)
                    .map_err(|_| ReconcilerError::InvalidExecutorOutput("cleanup stored prepare is malformed")))
                .transpose()?.unwrap_or(first.wall_seconds());
            crate::reconciler::plan_closed_create_failure_rows_data_v2(controller, marker,
                historical_terminal.archive_head(), historical_terminal.signed_terminal_outcome(), wall)
        })());
        let native = self.cleanup.require_native()?;
        let plan = self.plan_data_v2()?;
        if plan.marker_data_v2() != historical_terminal.marker()
            || plan.terminal_archive_data_v2() != historical_terminal.archive_head()
            || plan.signed_terminal_data_v2() != historical_terminal.signed_terminal_outcome()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let operation = plan.operation_data_v2();
        let first = native.clock.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let cutoff = native.cutoff.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let nonce = self.controller_nonce_data_v2()?;
        let admission = native.admission;
        let (_, receiving) = self.source.split_execution_read_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let receiving = ControllerExecutionReadReceivingLoanV1 {
            operation, receiving, complete: &mut self.complete, append_demand: self.append_demand,
        };
        original.borrow_cleanup_no_apply_client_once_v2(controller, bank, profile, receiving,
            admission, first, cutoff, nonce, historical_terminal, historical_availability,
            host_journal, host_socket, host_transcript)
    }

    pub(crate) fn plan_data_v2(
        &self,
    ) -> Result<&crate::reconciler::ClosedCreateFailurePlanDataV2, ResourceReservationErrorV1> {
        self.cleanup
            .require_native()?
            .decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the original fresh nonce while the actual Source/C loan stays held.
    ///
    /// # Errors
    /// Refuses a finished interval or failed original native/row receiver.
    pub fn controller_nonce_data_v2(&self) -> Result<[u8; 32], ResourceReservationErrorV1> {
        if self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.cleanup
            .require_native()?
            .nonce
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Checks actual cumulative cleanup reception on the same consumed declaration.
    ///
    /// # Errors
    /// Refuses finished, failed or changed native originals and excess demand.
    pub fn admit_stage_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        demand: Demand,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.cleanup.require_native()?;
        if self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let complete = self.complete.checked_add(demand.demand_v1())?;
        bank.require_execution_source_complete_v1(
            &mut self.source,
            controller,
            profile,
            Demand::from_demand_v1(complete),
        )?;
        self.complete = complete;
        Ok(())
    }

    /// Runs both independent prepaid Source/C posts on either cleanup outcome.
    pub fn finish_native_once_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.post.is_none() {
            *self.post = Some(bank.finish_execution_source_native_once_v1(
                &mut self.source,
                controller,
                profile,
            ));
        }
    }
}
