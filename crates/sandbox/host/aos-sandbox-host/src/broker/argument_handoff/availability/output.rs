//! Runs output preparation and early closure on the retained four writers.
//!
//! Controller35 and independently authenticated Storage48 keep their own signed
//! purpose and Session. Both extend the same consumed19 before native/model
//! growth. Active and fresh cleanup settlement borrow their concrete payer
//! through the same retained clock, Source observation and outcome engine.

use super::*;
use aos_sandbox_protocol::host_output::HostOutputReservationLocatorV1;

fn require_bound_output_v2(
    locator: HostOutputReservationLocatorV1,
    accepted: BeforeArgumentNoApplySourceDataV2,
) -> Result<()> {
    let source = accepted.fields();
    if locator.execution().as_bytes() != &source.execution
        || locator.create_operation().as_bytes() != &source.create_operation
        || locator.assignment_digest().as_bytes() != &source.assignment_digest
        || locator.host_boot_id() != source.host_boot
    {
        return Err(HostError::Fence(
            "Host output differs from its actual accepted bind",
        ));
    }
    Ok(())
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker>
    super::super::super::HostBroker<C, S, W>
{
    pub(crate) fn has_execution_availability_v2(&self) -> bool {
        self.argument_stages[0].as_ref().is_some_and(|stage| {
            stage
                .lock()
                .map_or(true, |capture| capture.availability.is_some())
        })
    }

    pub(super) async fn execute_availability_preparation_effect_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16],
        header: u64,
    ) -> Result<Vec<u8>> {
        let (reserve, terminal, held) = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => (true, false, false),
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => (false, false, false),
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => (false, true, false),
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                if request.host_held_no_apply_settlement_data_v2().is_some() => (false, false, true),
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
                if request.host_no_apply_current_lease_query_data_v2().is_some() => (false, false, true),
            _ => return Err(HostError::Fence("Host availability output purpose differs")),
        };
        if !self.state_healthy
            || request.authorization().is_some() == held
            || self.active_argument_writes.is_some()
            || self.argument_stages[1].is_some()
        {
            return Err(HostError::Fence(
                "Host availability output State is unavailable",
            ));
        }
        let stage = self.argument_stages[0]
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence("Host availability output stage is absent"))?;
        let mut capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host availability output stage is poisoned"))?;
        let available = capture.availability.as_ref().ok_or(HostError::Fence(
            "Host availability output source is absent",
        ))?;
        if !capture.authenticated
            || capture.first.is_some()
            || capture.primary.is_some()
            || !held && capture.reservation.is_some()
            || available.accepted.is_none()
            || !held && !matches!(available.origin, HostAvailabilityOriginV2::Active(_))
            || available.prepared.is_some()
            || available.terminal.is_some() != held
            || capture.argument.is_some()
            || capture.accepted.is_some()
            || available.failure().is_some()
            || available
                .intervals
                .iter()
                .any(|interval| !interval.authenticated || !held && interval.request.0 == request.method())
            || reserve
                && (request.session_binding() != available.original.session
                    || available.output_reservation.is_some())
            || !reserve && !terminal && !held && available.output_reservation.is_none()
            || held && (available.terminal_archive.is_none()
                || request.session_binding() != available.original.session
                || request.maximum_response_bytes() < 1408)
            || terminal
                && (request.session_binding() != available.original.session
                    || request
                        .host_before_argument_no_apply_data_v2()
                        .is_none_or(|source| {
                            source.is_query() || Some(source.source()) != available.accepted
                        }))
        {
            return Err(HostError::Fence(
                "Host availability output lacks its original predecessor",
            ));
        }
        let identity = available.original;
        let accepted = available.accepted.ok_or(HostError::Fence(
            "Host availability accepted source disappeared",
        ))?;
        let original = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host availability output financial original is absent",
            ))?;
        let mut original = original.lock().map_err(|_| {
            HostError::Fence("Host availability output financial original is poisoned")
        })?;
        original.require_argument_boot_v2(boot)?;
        let observation = match available.origin {
            HostAvailabilityOriginV2::Active(_) => {
                Some(original.availability_interval_demand_v2(identity)?)
            }
            HostAvailabilityOriginV2::Cleanup { .. } => None,
        };
        let extra = ArgumentStageOriginalV2::fixed_demand_for_runtime_v2(
            request,
            RuntimeOpeningV2::Resident,
        )
        .and_then(|fixed| {
            fixed
                .checked_add(available.native_interval_demand_v2(request)?)
                .ok()
        })
        .and_then(|fixed| fixed.checked_add(observation.map_or(ResourceVector::ZERO, |value| value.0)).ok())
        .and_then(|fixed| {
            let bytes = if terminal {
                aos_sandbox_protocol::host_execution_no_apply::closed_host_terminal_archive_receiving_bytes_v2(
                    448 + 16,
                )?
            } else {
                0
            };
            fixed
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
                .ok()
        })
        .and_then(|fixed| {
            fixed
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::OutputBytes, u64::from(request.maximum_response_bytes())),
                )
                .ok()
        })
        .ok_or(HostError::ResourceExhausted)?;
        let complete = capture
            .complete_demand
            .checked_add(extra)
            .map_err(|_| HostError::ResourceExhausted)?;
        let mut receiving = match &available.origin {
            HostAvailabilityOriginV2::Active(_) => ArgumentNativeReceivingV2::Active(
                original.begin_availability_interval_v2(
                    identity,
                    request,
                    complete,
                    observation
                        .ok_or(HostError::Fence(
                            "Host active source observations disappeared",
                        ))?
                        .1,
                )?,
            ),
            HostAvailabilityOriginV2::Cleanup { token: Some(token) } => {
                ArgumentNativeReceivingV2::Cleanup(
                    original.resume_no_apply_cleanup_receiving_v1(token, request, complete)?,
                )
            }
            HostAvailabilityOriginV2::Cleanup { token: None } => {
                return Err(HostError::Fence(
                    "Host cleanup original has no genuine current-Control continuation",
                ));
            }
        };
        capture.complete_demand = complete;
        capture.begin_retained_phase_v2(request);
        capture.append_availability_interval_v2(
            request,
            receiving.observation_round_start_data_v2(),
        )?;
        capture.source_cutoff = Some((|| {
            let available = capture
                .availability
                .as_ref()
                .ok_or(HostError::Fence("Host output cutoff source disappeared"))?;
            let cutoff = available.cutoff.min(header);
            let clock = capture
                .clock
                .as_mut()
                .ok_or(HostError::Fence("Host output original clock disappeared"))?;
            clock.advance_argument_stage_v2(request.method())?;
            require_original_cutoff_v2(cutoff, header, clock.sample()?.boottime_nanoseconds())
                .map_err(Into::into)
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
                "Host output original cutoff is unavailable",
            )),
        });
        if !matches!(capture.before, Some(Ok(()))) {
            capture.first.get_or_insert(ArgumentFirstV2::Before);
        }
        if let Some(cutoff) = cutoff.filter(|_| matches!(capture.before, Some(Ok(())))) {
            let mut held_state_cut = None;
            let prepare = (|| -> std::result::Result<(), ArgumentStageErrorV2> {
                let interval = capture
                    .availability
                    .as_mut()
                    .and_then(|available| available.intervals.last_mut())
                    .ok_or(HostError::Fence("Host output native interval disappeared"))?;
                let snapshot = self.store.load_retaining_v2(&mut interval.snapshot)?;
                snapshot.validate_authenticated(&self.authority)?;
                if snapshot != self.state {
                    return Err(HostError::Fence("Host output physical State changed").into());
                }
                if held {
                    held_state_cut = Some(snapshot.protected_snapshot_digest_v2()?);
                }
                capture.prepare_argument_native_v2(
                    &mut receiving,
                    cutoff,
                    RuntimeOpeningV2::Resident,
                )?;
                if reserve {
                    let quote = capture
                        .owner
                        .as_ref()
                        .ok_or(HostError::Fence("Host output writer disappeared"))?
                        .host_output_reservation_append_demand_v2();
                    let available = capture
                        .availability
                        .as_mut()
                        .ok_or(HostError::Fence("Host output source disappeared"))?;
                    available.output_append = Some(quote);
                    let quote = available
                        .output_append
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .copied()
                        .ok_or(HostError::Fence("Host output append quote failed"))?;
                    capture.complete_demand = capture
                        .complete_demand
                        .checked_add(quote)
                        .map_err(|_| HostError::ResourceExhausted)?;
                    receiving.require_complete_v2(capture.complete_demand)?;
                } else if terminal {
                    capture.future_append = Some(
                        capture
                            .owner
                            .as_ref()
                            .ok_or(HostError::Fence("Host terminal writer disappeared"))?
                            .before_argument_no_apply_append_demand_v2(),
                    );
                    let quote = capture
                        .future_append
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .copied()
                        .ok_or(HostError::Fence("Host terminal append quote failed"))?;
                    capture.complete_demand = capture
                        .complete_demand
                        .checked_add(quote)
                        .map_err(|_| HostError::ResourceExhausted)?;
                    receiving.require_complete_v2(capture.complete_demand)?;
                }
                Ok(())
            })();
            if reserve || terminal {
                self.active_argument_writes = Some(Arc::clone(&capture.writes));
            }
            let primary = prepare.and_then(|()| {
                let ArgumentStageOriginalV2 { owner, clock, reservation, availability, .. } = &mut *capture;
                let mut claim = owner.as_mut().ok_or(HostError::Fence("Host output writer is absent"))?.claim()?;
                let available = availability.as_mut().ok_or(HostError::Fence("Host output original source is absent"))?;
                available.require_source_current_v2(&claim, boot)?;
                let clock = clock.as_mut().ok_or(HostError::Fence("Host output retained clock is absent"))?;
                if held {
                    let observation = available.observation.ok_or(HostError::Fence(
                        "Host held NoApply accepted observation is absent",
                    ))?;
                    let archive = available.terminal_archive.ok_or(HostError::Fence(
                        "Host held NoApply actual terminal archive is absent",
                    ))?;
                    let state_cut = held_state_cut.ok_or(HostError::Fence(
                        "Host held NoApply State snapshot is absent",
                    ))?;
                    let original = available.settlement.get_or_insert_with(|| {
                        Box::new(held_settlement::HeldNoApplyOriginalV2::new())
                    });
                    return original.execute_once_v2(held_settlement::HeldNoApplyNativeTurnV2 {
                        request, claim: &mut claim, clock, effective_deadline: cutoff,
                        original_first_clock: available.first_clock.boottime_nanoseconds(),
                        original_cutoff: available.cutoff, availability: observation,
                        archive, host_state_cut: state_cut,
                    });
                }
                let mut sample = || {
                    let sample = clock.sample()?;
                    if sample.boottime_nanoseconds() >= cutoff { return Err(HostError::Fence("Host output original cutoff expired")); }
                    Ok(sample)
                };
                if terminal {
                    *reservation = Some(self.reserve_host_execution(
                        &claim, request, None, boot, &mut sample,
                    )?);
                    let reservation = reservation.as_ref().ok_or(HostError::Fence(
                        "Host terminal reservation disappeared",
                    ))?;
                    let marker =
                        reservation.commit_before_argument_no_apply_v2(&mut claim, request)?;
                    let response =
                        aos_sandbox_api::aos::sandbox::local::v1::TerminalHostExecutionArgumentNoApplyResponseV1 {
                            canonical_record: marker.encode_canonical().to_vec(),
                            ..Default::default()
                        }
                        .encode_to_vec();
                    available.terminal = Some(marker);

                    claim.revalidate()?;
                    sample()?;
                    self.complete_host_execution_reservation(reservation, &claim, &response)?;
                    Ok(response)
                } else if reserve {
                    *reservation = Some(self.reserve_host_execution(&claim, request, None, boot, &mut sample)?);
                    let reservation = reservation.as_ref().ok_or(HostError::Fence("Host output actual reservation disappeared"))?;
                    let locator = match reservation.request() {
                        super::super::super::HostExecutionGrantRequestV1::ReserveOutput(source) => source.locator(),
                        _ => return Err(HostError::Fence("Host output signed purpose differs").into()),
                    };
                    require_bound_output_v2(locator, accepted)?;
                    let source = reservation.verified_output_source().ok_or(HostError::Fence("Host output signed source is absent"))?;
                    let receipt = claim.reserve_host_output_v1(source)?;
                    let response = crate::execution_effect::output_reservation_response(locator, Some(receipt))?;
                    claim.revalidate()?;
                    sample()?;
                    self.complete_host_execution_reservation(reservation, &claim, &response)?;
                    Ok(response)
                } else {
                    let source = aos_sandbox_protocol::host_storage_output_readback::decode_captured_host_storage_output_readback_request_v1(
                        request.exact_body(), request.peer(), request.peer_policy(), sample()?.boottime_nanoseconds())?;
                    let locator = source.records().host_locator();
                    require_bound_output_v2(locator, accepted)?;
                    let prior = available.output_reservation.as_ref().ok_or(HostError::Fence("Host Storage readback lost its original35"))?;
                    if !matches!(prior.request(), super::super::super::HostExecutionGrantRequestV1::ReserveOutput(original)
                        if original.locator() == locator) {
                        return Err(HostError::Fence("Host Storage readback changed its protected output attempt").into());
                    }
                    Ok(self.observe_storage_output(&claim, request, boot, &mut sample)?)
                }
            });
            self.active_argument_writes = None;
            if held && capture.availability.as_ref()
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
        if let Some(token) = receiving.retain_pending_authenticated_v2()? {
            let mut capture = stage
                .lock()
                .map_err(|_| HostError::Fence("Host cleanup pending destination is poisoned"))?;
            match capture
                .availability
                .as_mut()
                .map(|available| &mut available.origin)
            {
                Some(HostAvailabilityOriginV2::Cleanup { token: slot }) => *slot = Some(token),
                _ => return Err(HostError::Fence("Host cleanup pending original changed")),
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::host_execution_no_apply::BeforeArgumentNoApplySourceFieldsV2;

    #[test]
    fn same_assignment_output_cannot_substitute_another_accepted_create_or_execution() {
        let mut source = [0; 688];
        source[..8].copy_from_slice(b"AOSCIR01");
        source[8..16].copy_from_slice(b"AOSCIP01");
        source[16..32].fill(1);
        source[32..48].fill(2);
        source[104..120].fill(3);
        source[160..192].fill(4);
        source[192..200].copy_from_slice(b"AOSEOR02");
        source[200..216].fill(1);
        source[216..232].fill(2);
        source[624..656].fill(5);
        source[656..688].fill(6);
        let locator =
            aos_sandbox_protocol::host_output::host_output_locator_from_source_v1(&source, [7; 16])
                .unwrap();
        let fields = BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: [2; 16],
            execution: [1; 16],
            sandbox: [8; 16],
            incarnation: [9; 16],
            node: [10; 16],
            assignment_epoch: 1,
            desired_generation: 1,
            accepted_request_digest: [11; 32],
            assignment_digest: [5; 32],
            host_boot: [3; 16],
        };

        require_bound_output_v2(
            locator,
            BeforeArgumentNoApplySourceDataV2::new(fields).unwrap(),
        )
        .unwrap();
        for changed in [
            BeforeArgumentNoApplySourceFieldsV2 {
                create_operation: [12; 16],
                ..fields
            },
            BeforeArgumentNoApplySourceFieldsV2 {
                execution: [12; 16],
                ..fields
            },
            BeforeArgumentNoApplySourceFieldsV2 {
                assignment_digest: [12; 32],
                ..fields
            },
            BeforeArgumentNoApplySourceFieldsV2 {
                host_boot: [12; 16],
                ..fields
            },
        ] {
            assert!(
                require_bound_output_v2(
                    locator,
                    BeforeArgumentNoApplySourceDataV2::new(changed).unwrap()
                )
                .is_err()
            );
        }
    }
}
