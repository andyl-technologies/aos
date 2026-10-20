//! Runs the single initial availability or fresh cleanup native preparation.
//!
//! Availability keeps its actual Prepare19. Cleanup uses a newly paid current
//! Control, verifies its dedicated Root acquisition signature before opening,
//! and retains old64/39/42/Root records as history. Both enter the same native
//! recipe and keep their own original boot/deadline; neither issues Apply.

use super::*;
use aos_sandbox_protocol::host_execution_no_apply::{
    current_lease::MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
    held_settlement_transport::HostNoApplyHeldCommandV2,
    recovery_acquisition::RootNoApplyRecoveryAcquisitionDataV2,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum HostInitialPreparationPurposeV2 {
    Availability,
    Cleanup,
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker>
    super::super::super::HostBroker<C, S, W>
{
    pub(super) async fn execute_initial_native_preparation_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16],
        header_cutoff: u64,
        purpose: HostInitialPreparationPurposeV2,
    ) -> Result<Vec<u8>> {
        if request.authorization().is_some()
            || !self.state_healthy
            || self.no_apply_settlement_frozen_v2
            || self.argument_stages.iter().any(Option::is_some)
            || self.active_argument_writes.is_some()
            || self.active_launch_writes.is_some()
        {
            return Err(HostError::Fence(
                "Host initial preparation native custody is occupied",
            ));
        }
        match purpose {
            HostInitialPreparationPurposeV2::Availability
                if request.method()
                    == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => {}
            HostInitialPreparationPurposeV2::Cleanup
                if matches!(
                    request
                        .host_held_no_apply_settlement_data_v2()
                        .map(|value| value.command_v2()),
                    Some(HostNoApplyHeldCommandV2::RecoveryPreliminary { .. })
                ) => {}
            _ => return Err(HostError::Fence("Host initial preparation purpose differs")),
        }
        let node = *self.authority.node_identity_data_v2().as_bytes();
        let component = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host initial preparation has no current-Control original",
            ))?;
        let mut component = component.lock().map_err(|_| {
            HostError::Fence("Host initial preparation current-Control original is poisoned")
        })?;
        component.require_argument_boot_v2(boot)?;
        let extra =
            match purpose {
                HostInitialPreparationPurposeV2::Availability => {
                    component.argument_observation_demand_v2(request)?
                }
                HostInitialPreparationPurposeV2::Cleanup => {
                    HostAvailabilityOriginalV2::fixed_demand_v2()
                        .and_then(|fixed| {
                            fixed
                                .checked_add(ResourceVector::ZERO.with(
                                    D::OutputBytes,
                                    u64::from(request.maximum_response_bytes()),
                                ))
                                .ok()
                        })
                        .ok_or(HostError::ResourceExhausted)?
                }
            };
        let complete = ArgumentStageOriginalV2::fixed_demand(request)
            .and_then(|fixed| fixed.checked_add(extra).ok())
            .ok_or(HostError::ResourceExhausted)?;
        let mut receiving = match purpose {
            HostInitialPreparationPurposeV2::Availability => ArgumentNativeReceivingV2::Active(
                component.begin_argument_receiving_v2(request, complete)?,
            ),
            // This fresh Control preparation cannot reconsume old Prepare19.
            HostInitialPreparationPurposeV2::Cleanup => ArgumentNativeReceivingV2::Cleanup(
                component.begin_no_apply_cleanup_receiving_v1(request, complete)?,
            ),
        };
        let stage = Arc::new(Mutex::new(ArgumentStageOriginalV2::new(request, complete)));
        self.argument_stages[0] = Some(Arc::clone(&stage));
        let mut capture = stage.lock().map_err(|_| {
            HostError::Fence("Host initial preparation native destination is poisoned")
        })?;
        capture.clock = Some(match purpose {
            HostInitialPreparationPurposeV2::Availability => ArgumentClockV2::capture(boot),
            HostInitialPreparationPurposeV2::Cleanup => ArgumentClockV2::capture_cleanup_v2(boot),
        });
        capture.source_cutoff = Some((|| -> std::result::Result<u64, ArgumentStageErrorV2> {
            let first = capture
                .clock
                .as_mut()
                .ok_or(HostError::Fence("Host initial preparation clock is absent"))?
                .sample()?;
            if header_cutoff != request.deadline_boottime_nanoseconds()
                || first.boottime_nanoseconds() >= header_cutoff
            {
                return Err(HostError::Fence("Host initial immutable deadline differs").into());
            }
            let round = receiving.observation_round_start_data_v2();
            capture.availability = Some(match purpose {
                HostInitialPreparationPurposeV2::Availability => {
                    let decoded =
                        request
                            .execution_availability_data_v2()
                            .ok_or(HostError::Fence(
                                "Host initial availability context disappeared",
                            ))?;
                    if decoded.phase() != ExecutionAvailabilityPhaseV2::Preaccept
                        || decoded.header().deadline_boottime_nanoseconds() != header_cutoff
                    {
                        return Err(
                            HostError::Fence("Host initial availability cutoff differs").into()
                        );
                    }
                    let proposal = HostExecutionAvailabilityProposalV2::decode_canonical(
                        decoded.canonical_proposal(),
                    )?;
                    HostAvailabilityOriginalV2::from_paid_source_v2(
                        HostAvailabilityBirthV2::Active(proposal),
                        first,
                        header_cutoff,
                        request_identity(request),
                        round,
                    )
                }
                HostInitialPreparationPurposeV2::Cleanup => {
                    let Some(HostNoApplyHeldCommandV2::RecoveryPreliminary {
                        canonical_root_acquisition,
                    }) = request
                        .host_held_no_apply_settlement_data_v2()
                        .map(|value| value.command_v2())
                    else {
                        return Err(HostError::Fence("Host cleanup acquisition disappeared").into());
                    };
                    let fields = RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(
                        canonical_root_acquisition,
                    )?
                    .fields_v2();
                    if header_cutoff > fields.cutoff
                        || usize::try_from(request.maximum_response_bytes())
                            .map_or(true, |maximum| {
                                maximum < MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2
                            })
                    {
                        return Err(
                            HostError::Fence("Host cleanup acquisition bounds differ").into()
                        );
                    }
                    HostAvailabilityOriginalV2::from_paid_source_v2(
                        HostAvailabilityBirthV2::Cleanup(&fields),
                        first,
                        header_cutoff,
                        request_identity(request),
                        round,
                    )
                }
            });
            Ok(header_cutoff)
        })());
        let cutoff = capture
            .source_cutoff
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied();
        if cutoff.is_none() {
            capture.first.get_or_insert(ArgumentFirstV2::Clock);
        }
        capture.before = Some(match cutoff {
            Some(_) => receiving.observe_before_v2().await,
            None => Err(HostError::Fence(
                "Host initial preparation cutoff is unavailable",
            )),
        });
        if !matches!(capture.before, Some(Ok(()))) {
            capture.first.get_or_insert(ArgumentFirstV2::Before);
        }
        if let Some(cutoff) = cutoff.filter(|_| matches!(capture.before, Some(Ok(())))) {
            let primary = (|| -> std::result::Result<Vec<u8>, ArgumentStageErrorV2> {
                if purpose == HostInitialPreparationPurposeV2::Cleanup {
                    let ArgumentStageOriginalV2 {
                        availability,
                        clock,
                        ..
                    } = &mut *capture;
                    let available = availability.as_mut().ok_or(HostError::Fence(
                        "Host initial preparation source is absent",
                    ))?;
                    available
                        .settlement
                        .as_mut()
                        .ok_or(HostError::Fence(
                            "Host initial preparation acquisition destination is absent",
                        ))?
                        .verify_acquisition_before_open_v2(
                            request,
                            node,
                            clock.as_mut().ok_or(HostError::Fence(
                                "Host initial preparation clock is absent",
                            ))?,
                            cutoff,
                        )?;
                }
                capture.open_runtime_once_v2(&mut receiving, cutoff)?;
                let quote = capture
                    .owner
                    .as_ref()
                    .ok_or(HostError::Fence(
                        "Host initial preparation four-writer owner is absent",
                    ))?
                    .execution_claim_receiving_demand_v2();
                let quote = capture
                    .availability
                    .as_mut()
                    .ok_or(HostError::Fence(
                        "Host initial preparation source disappeared",
                    ))?
                    .retain_claim_demand_v2(quote)
                    .ok_or(HostError::Fence(
                        "Host initial preparation current-claim quote failed",
                    ))?;
                capture.complete_demand = capture
                    .complete_demand
                    .checked_add(quote)
                    .map_err(|_| HostError::ResourceExhausted)?;
                receiving.require_complete_v2(capture.complete_demand)?;
                capture.frontier = ArgumentFirstV2::Primary;

                let ArgumentStageOriginalV2 {
                    owner,
                    availability,
                    clock,
                    ..
                } = &mut *capture;
                let available = availability.as_mut().ok_or(HostError::Fence(
                    "Host initial preparation source disappeared",
                ))?;
                let snapshot = self.store.load_retaining_v2(&mut available.snapshot)?;
                snapshot.validate_authenticated(&self.authority)?;
                if snapshot != self.state {
                    return Err(HostError::Fence(
                        "Host initial preparation physical State changed",
                    )
                    .into());
                }
                let host_state_cut = snapshot.protected_snapshot_digest_v2()?;
                let mut claim = owner
                    .as_mut()
                    .ok_or(HostError::Fence(
                        "Host initial preparation writer disappeared",
                    ))?
                    .claim()?;
                available.require_source_current_v2(&claim, boot)?;
                if purpose == HostInitialPreparationPurposeV2::Cleanup {
                    let archive = available.terminal_archive.ok_or(HostError::Fence(
                        "Host initial preparation terminal history disappeared",
                    ))?;
                    return available
                        .settlement
                        .as_mut()
                        .ok_or(HostError::Fence(
                            "Host initial preparation settlement disappeared",
                        ))?
                        .execute_once_v2(held_settlement::HeldNoApplyNativeTurnV2 {
                            request,
                            claim: &mut claim,
                            clock: clock.as_mut().ok_or(HostError::Fence(
                                "Host initial preparation clock disappeared",
                            ))?,
                            effective_deadline: cutoff,
                            original_first_clock: available.first_clock.boottime_nanoseconds(),
                            original_cutoff: available.cutoff,
                            availability: available.observation.ok_or(HostError::Fence(
                                "Host initial preparation historical availability disappeared",
                            ))?,
                            archive,
                            host_state_cut,
                        });
                }
                let cut = claim.protected_host_settlement_cut_v1()?;
                let sample = clock
                    .as_mut()
                    .ok_or(HostError::Fence("Host initial clock disappeared"))?
                    .sample()?;
                if sample.boottime_nanoseconds() >= cutoff {
                    return Err(HostError::Fence("Host initial availability cutoff expired").into());
                }
                let observation = HostExecutionAvailabilityObservationV2::new(
                    HostExecutionAvailabilityObservationFieldsV2 {
                        phase: ExecutionAvailabilityPhaseV2::Preaccept,
                        proposal_digest: *available.active_proposal_v2()?.digest().as_bytes(),
                        request: request.request_id(),
                        session: request.session_binding(),
                        signed_request: request.signed_request_digest(),
                        runtime_handle: *claim.currentness().runtime().handle().as_bytes(),
                        execution_store: *claim.execution_store_binding_data_v2().as_bytes(),
                        execution_cut: *cut.digest().as_bytes(),
                        host_state_cut,
                        boot,
                        epoch: cut.epoch(),
                        first_clock: available.first_clock.boottime_nanoseconds(),
                        cutoff,
                        observed_clock: sample.boottime_nanoseconds(),
                        bound_source_digest: [0; 32],
                    },
                )?;
                claim.revalidate()?;
                if claim.protected_host_settlement_cut_v1()? != cut {
                    return Err(HostError::Fence(
                        "Host initial availability execution cut changed",
                    )
                    .into());
                }
                available.observation = Some(observation);
                Ok(PrepareExecutionAvailabilityResponseV2 {
                    canonical_observation: observation.encode_canonical().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec())
            })();
            if capture
                .availability
                .as_ref()
                .and_then(|available| available.settlement.as_ref())
                .is_some_and(|original| original.has_comparison_v2())
            {
                self.no_apply_settlement_frozen_v2 = true;
            }
            if primary.is_err() {
                let frontier = capture.frontier;
                capture.first.get_or_insert(frontier);
            }
            capture.primary = Some(primary);
        }
        let response = capture.finish_native_response_v2(&mut receiving).await?;
        drop(capture);
        match (purpose, receiving.retain_pending_authenticated_v2()?) {
            (HostInitialPreparationPurposeV2::Availability, None) => {}
            (HostInitialPreparationPurposeV2::Cleanup, Some(token)) => {
                let mut capture = stage
                    .lock()
                    .map_err(|_| HostError::Fence("Host cleanup token destination is poisoned"))?;
                match capture
                    .availability
                    .as_mut()
                    .map(|available| &mut available.origin)
                {
                    Some(HostAvailabilityOriginV2::Cleanup { token: slot }) if slot.is_none() => {
                        *slot = Some(token)
                    }
                    _ => return Err(HostError::Fence("Host cleanup token destination changed")),
                }
            }
            _ => return Err(HostError::Fence("Host initial financial purpose changed")),
        }
        Ok(response)
    }
}
