//! Retains the paid preaccept Host receiver and its four actual journal writers.
//!
//! Availability consumes Prepare19 before codec, snapshot, clock or native
//! growth; a later accepted bind extends that operation on the same writers.
//! Recovery uses a distinct fresh current-Control payer and Root read-only
//! acquisition on the same native engine. Replies carry comparison DATA;
//! negative prefixes and independently owed observations remain on the stage.

use super::*;
use crate::state::HostStateReadAttemptV2;

mod held_settlement;
mod initial;
mod output;
mod program;
mod root_trust;
use aos_sandbox_api::aos::sandbox::local::v1::PrepareExecutionAvailabilityResponseV2;
use aos_sandbox_protocol::execution_availability::ExecutionAvailabilityPhaseV2;
use aos_sandbox_protocol::host_execution_availability::{
    HostExecutionAvailabilityProposalV2,
    observation::{
        HostExecutionAvailabilityObservationFieldsV2, HostExecutionAvailabilityObservationV2,
    },
};
use aos_sandbox_protocol::host_execution_no_apply::BeforeArgumentNoApplySourceDataV2;

pub(super) struct HostAvailabilityOriginalV2 {
    origin: HostAvailabilityOriginV2,
    accepted: Option<BeforeArgumentNoApplySourceDataV2>,
    first_clock: RawPairedClockSample,
    cutoff: u64,
    original: crate::plan::HostExecutionRequestBindingV2,
    original_round: usize,
    prepared: Option<crate::plan::HostExecutionRequestBindingV2>,
    accept: Option<crate::plan::HostExecutionRequestBindingV2>,
    prepared_reservation: Option<super::super::HostExecutionGrantReservationV1>,
    prepared_writes: Option<Arc<Mutex<ArgumentStateWritesV2>>>,
    output_reservation: Option<super::super::HostExecutionGrantReservationV1>,
    output_writes: Option<Arc<Mutex<ArgumentStateWritesV2>>>,
    terminal:
        Option<aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2>,
    terminal_archive: Option<held_settlement::RetainedTerminalIdentityV2>,
    settlement: Option<Box<held_settlement::HeldNoApplyOriginalV2>>,
    output_append: Option<
        std::result::Result<
            ResourceVector,
            aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1,
        >,
    >,
    accept_snapshot: HostStateReadAttemptV2,
    snapshot: HostStateReadAttemptV2,
    claim_demand: Option<
        std::result::Result<
            ResourceVector,
            aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1,
        >,
    >,
    observation: Option<HostExecutionAvailabilityObservationV2>,
    intervals: Vec<AvailabilityNativeIntervalV2>,
    allocation: Option<std::result::Result<(), std::collections::TryReserveError>>,
}

enum HostAvailabilityOriginV2 {
    Active(HostExecutionAvailabilityProposalV2),
    Cleanup {
        token: Option<crate::plan::HostControlCleanupTokenV1>,
    },
}

enum HostAvailabilityBirthV2<'history> {
    Active(HostExecutionAvailabilityProposalV2),
    Cleanup(&'history aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionFieldsV2),
}

struct AvailabilityNativeIntervalV2 {
    snapshot: HostStateReadAttemptV2,
    observation_round: usize,
    request: (BrokerMethod, [u8; 16], [u8; 32], [u8; 32]),
    authenticated: bool,
}

impl HostAvailabilityOriginalV2 {
    fn from_paid_source_v2(
        birth: HostAvailabilityBirthV2<'_>,
        first_clock: RawPairedClockSample,
        cutoff: u64,
        original: crate::plan::HostExecutionRequestBindingV2,
        original_round: usize,
    ) -> Self {
        let (origin, accepted, terminal, terminal_archive, observation, settlement) = match birth {
            HostAvailabilityBirthV2::Active(proposal) => (
                HostAvailabilityOriginV2::Active(proposal),
                None,
                None,
                None,
                None,
                None,
            ),
            HostAvailabilityBirthV2::Cleanup(fields) => (
                HostAvailabilityOriginV2::Cleanup { token: None },
                Some(fields.accepted_source),
                Some(fields.marker),
                Some(held_settlement::RetainedTerminalIdentityV2 {
                    marker: fields.marker,
                    archive_head: aos_sandbox_model::ObjectDigest::from_bytes(
                        fields.terminal_archive,
                    ),
                    signed_terminal_outcome: aos_sandbox_model::ObjectDigest::from_bytes(
                        fields.signed_terminal,
                    ),
                }),
                Some(fields.historical_availability),
                Some(Box::new(
                    held_settlement::HeldNoApplyOriginalV2::new_cleanup_v2(
                        root_trust::HostNoApplyRootTrustOriginalV2::new(),
                        *fields,
                    ),
                )),
            ),
        };
        Self {
            origin,
            accepted,
            first_clock,
            cutoff,
            original,
            original_round,
            prepared: None,
            accept: None,
            prepared_reservation: None,
            prepared_writes: None,
            output_reservation: None,
            output_writes: None,
            terminal,
            terminal_archive,
            settlement,
            output_append: None,
            accept_snapshot: HostStateReadAttemptV2::new(),
            snapshot: HostStateReadAttemptV2::new(),
            claim_demand: None,
            observation,
            intervals: Vec::new(),
            allocation: None,
        }
    }

    pub(super) fn require_cleanup_control_original_v1(
        &self,
        token: &crate::plan::HostControlCleanupTokenV1,
    ) -> Result<()> {
        if !matches!(&self.origin, HostAvailabilityOriginV2::Cleanup { token: Some(original) }
            if original.rejoins_same_original_v1(token))
        {
            return Err(HostError::Fence("Host NoApply cleanup payer differs"));
        }
        Ok(())
    }

    fn active_proposal_v2(&self) -> Result<HostExecutionAvailabilityProposalV2> {
        match self.origin {
            HostAvailabilityOriginV2::Active(proposal) => Ok(proposal),
            HostAvailabilityOriginV2::Cleanup { .. } => Err(HostError::Fence(
                "Host cleanup original cannot lend execution availability",
            )),
        }
    }

    fn require_source_current_v2(
        &self,
        claim: &aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionClaimV1<'_>,
        boot: [u8; 16],
    ) -> std::result::Result<(), ArgumentStageErrorV2> {
        match self.origin {
            HostAvailabilityOriginV2::Active(proposal) => require_proposal_current(proposal, claim, boot).map_err(Into::into),
            HostAvailabilityOriginV2::Cleanup { .. } => {
                if claim.host_verifier().boot_id() != boot {
                    return Err(HostError::Fence("Host cleanup current native boot changed").into());
                }
                claim.require_held_closed_no_apply_history_v2(self.terminal.ok_or(
                    HostError::Fence("Host cleanup durable terminal history is absent"),
                )?).map_err(Into::into)
            }
        }
    }

    pub(super) fn retain_claim_demand_v2(
        &mut self,
        quote: std::result::Result<
            ResourceVector,
            aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1,
        >,
    ) -> Option<ResourceVector> {
        self.claim_demand = Some(quote);
        self.claim_demand
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.claim_demand
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.output_append
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.snapshot.failure())
            .or_else(|| self.accept_snapshot.failure())
            .or_else(|| self.settlement.as_ref().and_then(|original| original.failure()))
            .or_else(|| {
                self.allocation
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.intervals
                    .iter()
                    .find_map(|interval| interval.snapshot.failure())
            })
    }
    pub(super) fn fixed_demand_v2() -> Option<ResourceVector> {
        let read = HostStateReadAttemptV2::receiving_demand_v2()?;
        // The existing reader covers input/model planes. A second set covers
        // canonical snapshot encoding/comparison while those inputs stay live.
        // JSON/allocator uncertainty uses the same installed Host backstop.
        read.with(
                D::MemoryBytes,
                read.get(D::MemoryBytes)
                    .checked_mul(2)?
                    .checked_add(u64::try_from(2 * std::mem::size_of::<Self>()
                        + 2 * std::mem::size_of::<HostAvailabilityBirthV2<'static>>()
                        + 2 * std::mem::size_of::<initial::HostInitialPreparationPurposeV2>()).ok()?)?,
            )
        .checked_add(held_settlement::HeldNoApplyOriginalV2::receiving_demand_v2()?)
        .ok()
    }

    fn native_interval_demand_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Option<ResourceVector> {
        let read = HostStateReadAttemptV2::receiving_demand_v2()?;
        let memory = read
            .get(D::MemoryBytes)
            .checked_mul(2)?
            .checked_add(
                u64::try_from(
                    self.intervals
                        .len()
                        .checked_add(1)?
                        .checked_mul(2 * std::mem::size_of::<AvailabilityNativeIntervalV2>())?,
                )
                .ok()?,
            )?
            .checked_add(u64::try_from(request.exact_body().len().checked_mul(8)?).ok()?)?;
        Some(
            read.with(D::MemoryBytes, memory)
                .with(D::OutputBytes, 368 + 16),
        )
    }
}

impl ArgumentStageOriginalV2 {
    fn append_availability_interval_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation_round: usize,
    ) -> Result<()> {
        let available = self.availability.as_mut().ok_or(HostError::Fence(
            "Host availability source disappeared after admission",
        ))?;
        available.allocation = Some(available.intervals.try_reserve_exact(1));
        if !matches!(available.allocation, Some(Ok(()))) {
            self.first.get_or_insert(ArgumentFirstV2::Primary);
            return Err(HostError::Fence(
                "Host native interval allocation failed; cause retained",
            ));
        }
        available.intervals.push(AvailabilityNativeIntervalV2 {
            snapshot: HostStateReadAttemptV2::new(),
            observation_round,
            request: (
                request.method(),
                request.request_id(),
                request.session_binding(),
                request.signed_request_digest(),
            ),
            authenticated: false,
        });
        Ok(())
    }
}

fn request_identity(
    request: &AuthenticatedBrokerMethodRequestV1,
) -> crate::plan::HostExecutionRequestBindingV2 {
    crate::plan::HostExecutionRequestBindingV2 {
        id: request.request_id(),
        session: request.session_binding(),
        signed: request.signed_request_digest(),
    }
}

fn require_proposal_current(
    proposal: HostExecutionAvailabilityProposalV2,
    claim: &aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionClaimV1<'_>,
    boot: [u8; 16],
) -> Result<()> {
    let expected = proposal.fields();
    let current = claim.currentness().runtime().currentness();
    if current.sandbox().as_bytes() != &expected.sandbox
        || current.incarnation().as_bytes() != &expected.incarnation
        || current.node().as_bytes() != &expected.node
        || current.assignment_epoch().get() != expected.assignment_epoch
        || current.desired_generation().get() != expected.desired_generation
        || current.assignment_digest().as_bytes() != &expected.assignment_digest
        || claim.host_verifier().boot_id() != boot
    {
        return Err(HostError::Fence(
            "Host availability protected assignment or boot differs",
        ));
    }
    Ok(())
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker>
    super::super::HostBroker<C, S, W>
{
    pub(crate) fn retain_sent_execution_availability_response_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<()> {
        let stage = self.argument_stages[0]
            .as_ref()
            .ok_or(HostError::Fence("Host terminal original is absent"))?;
        let mut capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host terminal original is poisoned"))?;
        if !matches!(request.method(), BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2)
            || outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ServerSend
            || capture.authenticated || capture.first.is_some() || capture.primary.is_some()
            || !matches!(capture.before, Some(Ok(()))) || !matches!(capture.after, Some(Ok(())))
            || !matches!(capture.native_finish, Some(Ok(())))
            || capture.request != (request.method(), request.request_id(), request.session_binding(), request.signed_request_digest())
            || outcome.request().canonical_packet() != request.canonical_packet()
        { return Err(HostError::Fence("Host terminal Sent differs from its actual native interval")); }
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY {
            let available = capture
                .availability
                .as_mut()
                .ok_or(HostError::Fence("Host held NoApply source is absent"))?;
            available
                .settlement
                .as_mut()
                .ok_or(HostError::Fence("Host held NoApply original is absent"))?
                .retain_sent_once_v2(request, outcome)?;
            if let HostAvailabilityOriginV2::Cleanup { token: Some(token) } = &available.origin {
                self.component_control
                    .as_ref()
                    .ok_or(HostError::Fence(
                        "Host cleanup current-Control original is absent",
                    ))?
                    .lock()
                    .map_err(|_| HostError::Fence("Host cleanup current-Control is poisoned"))?
                    .mark_cleanup_authenticated_sent_v1(token, outcome)?;
            }
            return Ok(());
        }
        if request.host_before_argument_no_apply_data_v2().is_none() {
            return Err(HostError::Fence("Host terminal source is absent"));
        }
        let archive =
            aos_sandbox_protocol::host_execution_no_apply::closed_host_terminal_archive_data_v2(
                outcome,
            )?;
        let available = capture
            .availability
            .as_mut()
            .ok_or(HostError::Fence("Host terminal source disappeared"))?;
        if available.terminal != Some(archive.marker())
            || available.terminal_archive.is_some()
            || available.accepted != Some(archive.marker().fields().source)
        {
            return Err(HostError::Fence(
                "Host terminal archive differs from its durable closure",
            ));
        }
        available.terminal_archive = Some(archive.into());
        Ok(())
    }

    async fn bind_execution_availability_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16],
        header_cutoff: u64,
    ) -> Result<Vec<u8>> {
        let stage = self.argument_stages[0]
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence("Host availability original is absent"))?;
        let mut capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host availability stage is poisoned"))?;
        if !capture.authenticated
            || capture.first.is_some()
            || capture.owner.is_none()
            || capture.primary.is_some()
            || capture
                .availability
                .as_ref()
                .is_none_or(|available| available.accepted.is_some())
        {
            return Err(HostError::Fence(
                "Host availability cannot bind another accepted Create",
            ));
        }
        let original = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host availability financial original disappeared",
            ))?;
        let mut original = original
            .lock()
            .map_err(|_| HostError::Fence("Host availability financial original is poisoned"))?;
        original.require_argument_boot_v2(boot)?;
        let available = capture
            .availability
            .as_ref()
            .ok_or(HostError::Fence("Host availability source disappeared"))?;
        let identity = available.original;
        let (observations, maximum) = original.availability_interval_demand_v2(identity)?;
        let extra = available
            .native_interval_demand_v2(request)
            .and_then(|demand| demand.checked_add(observations).ok())
            .ok_or(HostError::ResourceExhausted)?;
        let complete = capture
            .complete_demand
            .checked_add(extra)
            .map_err(|_| HostError::ResourceExhausted)?;
        let mut receiving = ArgumentNativeReceivingV2::Active(
            original.begin_availability_interval_v2(identity, request, complete, maximum)?,
        );
        capture.complete_demand = complete;
        capture.begin_retained_phase_v2(request);
        capture.append_availability_interval_v2(
            request,
            receiving.observation_round_start_data_v2(),
        )?;
        capture.before = Some(receiving.observe_before_v2().await);
        if capture.before.as_ref().is_some_and(Result::is_err) {
            capture.first.get_or_insert(ArgumentFirstV2::Before);
        }
        if capture.before.as_ref().is_some_and(Result::is_ok) {
            capture.frontier = ArgumentFirstV2::Primary;
            let primary = (|| -> std::result::Result<Vec<u8>, ArgumentStageErrorV2> {
                let ArgumentStageOriginalV2 {
                    owner,
                    clock,
                    availability,
                    ..
                } = &mut *capture;
                let available = availability
                    .as_mut()
                    .ok_or(HostError::Fence("Host availability source disappeared"))?;
                let proposal = available.active_proposal_v2()?;
                let interval = available.intervals.last_mut().ok_or(HostError::Fence(
                    "Host availability native interval disappeared",
                ))?;
                let clock = clock.as_mut().ok_or(HostError::Fence(
                    "Host availability original clock disappeared",
                ))?;
                let decoded = request
                    .execution_availability_data_v2()
                    .ok_or(HostError::Fence(
                        "Host availability canonical context is absent",
                    ))?;
                let cutoff = available.cutoff.min(header_cutoff);
                let sample = clock.sample()?;
                if decoded.phase() != ExecutionAvailabilityPhaseV2::AcceptedBind
                    || decoded.canonical_proposal() != proposal.encode_canonical()
                    || decoded.header().deadline_boottime_nanoseconds() != header_cutoff
                    || request.session_binding() != identity.session
                    || request.request_id() == identity.id
                    || sample.boottime_nanoseconds() >= cutoff
                {
                    return Err(HostError::Fence(
                        "Host availability accepted bind differs from its original",
                    )
                    .into());
                }
                let accepted = BeforeArgumentNoApplySourceDataV2::decode_canonical(
                    decoded.canonical_accepted_source(),
                )?;
                proposal.require_accepted_source(accepted)?;
                if accepted.fields().host_boot != boot {
                    return Err(HostError::Fence("Host availability accepted boot differs").into());
                }
                let snapshot = self.store.load_retaining_v2(&mut interval.snapshot)?;
                snapshot.validate_authenticated(&self.authority)?;
                if snapshot != self.state {
                    return Err(
                        HostError::Fence("Host availability physical HostState changed").into(),
                    );
                }
                let state_cut = snapshot.protected_snapshot_digest_v2()?;
                let claim = owner
                    .as_mut()
                    .ok_or(HostError::Fence("Host availability writer disappeared"))?
                    .claim()?;
                available.require_source_current_v2(&claim, boot)?;
                let cut = claim.protected_host_settlement_cut_v1()?;
                let sample = clock.sample()?;
                if sample.boottime_nanoseconds() >= cutoff {
                    return Err(
                        HostError::Fence("Host availability accepted bind cutoff expired").into(),
                    );
                }
                let observation = HostExecutionAvailabilityObservationV2::new(
                    HostExecutionAvailabilityObservationFieldsV2 {
                        phase: ExecutionAvailabilityPhaseV2::AcceptedBind,
                        proposal_digest: *proposal.digest().as_bytes(),
                        request: request.request_id(),
                        session: request.session_binding(),
                        signed_request: request.signed_request_digest(),
                        runtime_handle: *claim.currentness().runtime().handle().as_bytes(),
                        execution_store: *claim.execution_store_binding_data_v2().as_bytes(),
                        execution_cut: *cut.digest().as_bytes(),
                        host_state_cut: state_cut,
                        boot,
                        epoch: cut.epoch(),
                        first_clock: available.first_clock.boottime_nanoseconds(),
                        cutoff: available.cutoff,
                        observed_clock: sample.boottime_nanoseconds(),
                        bound_source_digest: *accepted.digest().as_bytes(),
                    },
                )?;
                claim.revalidate()?;
                if claim.protected_host_settlement_cut_v1()? != cut {
                    return Err(HostError::Fence(
                        "Host availability accepted execution cut changed",
                    )
                    .into());
                }
                available.accepted = Some(accepted);
                available.observation = Some(observation);
                Ok(PrepareExecutionAvailabilityResponseV2 {
                    canonical_observation: observation.encode_canonical().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec())
            })();
            if primary.is_err() {
                capture.first.get_or_insert(ArgumentFirstV2::Primary);
            }
            capture.primary = Some(primary);
        }
        let response = capture.finish_native_response_v2(&mut receiving).await?;
        drop(capture);
        receiving.retain_pending_authenticated_v2()?;
        Ok(response)
    }

    pub(in crate::broker) fn retain_authenticated_availability_response_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        let stage = self.argument_stages[0]
            .as_ref()
            .ok_or(HostError::Fence("Host availability original is absent"))?;
        let mut capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host availability stage is poisoned"))?;
        if capture.request
            != (
                request.method(),
                request.request_id(),
                request.session_binding(),
                request.signed_request_digest(),
            )
            || capture.authenticated
            || capture.first.is_some()
            || capture.primary.is_some()
            || !capture.before.as_ref().is_some_and(Result::is_ok)
            || !capture.after.as_ref().is_some_and(Result::is_ok)
            || !capture.native_finish.as_ref().is_some_and(Result::is_ok)
            || request.method() == BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                && capture
                    .availability
                    .as_ref()
                    .is_none_or(|available| available.terminal_archive.is_none())
            || matches!(request.method(), BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2)
                && capture.availability.as_ref()
                    .and_then(|available| available.settlement.as_ref())
                    .is_none_or(|original| !original.has_sent_phase_v2(request))
            || request.method() == BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                && (capture.reservation.is_none()
                    || capture
                        .availability
                        .as_ref()
                        .is_some_and(|available| available.output_reservation.is_some()))
        {
            return Err(HostError::Fence(
                "Host availability authenticated completion differs from its native interval",
            ));
        }
        let original = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host availability financial original is absent",
            ))?;
        let mut original = original
            .lock()
            .map_err(|_| HostError::Fence("Host availability financial original is poisoned"))?;
        let available = capture
            .availability
            .as_mut()
            .ok_or(HostError::Fence("Host availability source is absent"))?;
        if let HostAvailabilityOriginV2::Cleanup { token: Some(token) } = &available.origin {
            original.require_cleanup_authenticated_response_v1(token, request)?;
            if let Some(interval) = available.intervals.last_mut() {
                if interval.authenticated
                    || interval.request
                        != (
                            request.method(),
                            request.request_id(),
                            request.session_binding(),
                            request.signed_request_digest(),
                        )
                {
                    return Err(HostError::Fence(
                        "Host cleanup authenticated interval differs",
                    ));
                }
                interval.authenticated = true;
            }
        } else if matches!(
            available.origin,
            HostAvailabilityOriginV2::Cleanup { token: None }
        ) {
            return Err(HostError::Fence(
                "Host cleanup authenticated token is absent",
            ));
        } else if available.intervals.is_empty() {
            original.retire_authenticated_argument_v2(request)?;
        } else {
            let interval = available.intervals.last_mut().ok_or(HostError::Fence(
                "Host availability native interval is absent",
            ))?;
            if interval.authenticated
                || interval.request
                    != (
                        request.method(),
                        request.request_id(),
                        request.session_binding(),
                        request.signed_request_digest(),
                    )
            {
                return Err(HostError::Fence(
                    "Host availability native interval differs",
                ));
            }
            original.finish_authenticated_availability_interval_v2(available.original, request)?;
            interval.authenticated = true;
        }
        capture.authenticated = true;
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT {
            let ArgumentStageOriginalV2 {
                availability,
                reservation,
                writes,
                ..
            } = &mut *capture;
            let available = availability
                .as_mut()
                .ok_or(HostError::Fence("Host output source disappeared"))?;
            available.output_reservation = reservation.take();
            available.output_writes = Some(std::mem::replace(
                writes,
                Arc::new(Mutex::new(ArgumentStateWritesV2::new())),
            ));
        }
        Ok(())
    }

    pub(crate) async fn execute_execution_availability_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16],
        header_cutoff: u64,
    ) -> Result<Vec<u8>> {
        if matches!(request.host_held_no_apply_settlement_data_v2()
            .map(|value| value.command_v2()),
            Some(aos_sandbox_protocol::host_execution_no_apply::held_settlement_transport::HostNoApplyHeldCommandV2::RecoveryPreliminary { .. }))
        {
            return self.execute_initial_native_preparation_v2(request, boot, header_cutoff, initial::HostInitialPreparationPurposeV2::Cleanup).await;
        }
        if matches!(
            request.method(),
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
                | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
        ) {
            return self
                .execute_availability_preparation_effect_v2(request, boot, header_cutoff)
                .await;
        }
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
            || request.authorization().is_some()
            || !self.state_healthy
            || self.active_argument_writes.is_some()
        {
            return Err(HostError::Fence(
                "Host availability purpose or resident State is unavailable",
            ));
        }
        if self.argument_stages[0].is_some() {
            return self
                .bind_execution_availability_v2(request, boot, header_cutoff)
                .await;
        }
        self.execute_initial_native_preparation_v2(
            request,
            boot,
            header_cutoff,
            initial::HostInitialPreparationPurposeV2::Availability,
        )
        .await
    }
}
