//! Carries the paid19 native prefix into the genuine funded59 stage.
//!
//! Prepare19 stays consumed until the existing whole terminal disposer drops
//! the actual four writers. Accept20 funds additional fifth/Guest work; neither
//! stage reopens a journal, remints a deadline or adopts DATA as live custody.

use super::*;

impl ArgumentStageOriginalV2 {
    pub(super) fn begin_retained_phase_v2(&mut self, request: &AuthenticatedBrokerMethodRequestV1) {
        self.request = (
            request.method(),
            request.request_id(),
            request.session_binding(),
            request.signed_request_digest(),
        );
        self.authenticated = false;
        self.before = None;
        self.after = None;
        self.native_finish = None;
    }

    fn retained_argument_cutoff_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16],
        header: u64,
    ) -> std::result::Result<u64, ArgumentStageErrorV2> {
        let available = self.availability.as_ref().ok_or(HostError::Fence(
            "Host retained availability association is absent",
        ))?;
        let accepted = available
            .accepted
            .ok_or(HostError::Fence(
                "Host retained availability has no accepted source",
            ))?
            .fields();
        let sample = self
            .clock
            .as_mut()
            .ok_or(HostError::Fence(
                "Host retained availability clock is absent",
            ))?
            .sample()?;
        let source = original_argument_source_v2(request, sample.boottime_nanoseconds())?;
        if request.session_binding() != available.original.session
            || source.execution().as_bytes() != &accepted.execution
            || source.create_operation().as_bytes() != &accepted.create_operation
            || source.assignment_digest().as_bytes() != &accepted.assignment_digest
            || source.host_boot_id() != accepted.host_boot
            || accepted.host_boot != boot
        {
            return Err(
                HostError::Fence("Host argument differs from its actual accepted bind").into(),
            );
        }
        require_original_cutoff_v2(
            available.cutoff.min(source.deadline_boottime_nanoseconds()),
            header,
            sample.boottime_nanoseconds(),
        )
        .map_err(Into::into)
    }

    pub(in crate::broker) fn retained_availability_binding_v2(
        &self,
    ) -> Option<crate::plan::HostExecutionRequestBindingV2> {
        self.availability
            .as_ref()
            .map(|available| available.original)
    }

    pub(in crate::broker) fn retained_availability_observation_rounds_v2(
        &self,
    ) -> impl Iterator<Item = usize> + '_ {
        self.availability.iter().flat_map(|available| {
            std::iter::once(available.original_round).chain(
                available
                    .intervals
                    .iter()
                    .map(|interval| interval.observation_round),
            )
        })
    }

    pub(in crate::broker) fn require_retained_availability_terminal_v2(&self) -> Result<()> {
        let Some(available) = self.availability.as_ref() else {
            return Ok(());
        };
        let accept = available.accept.ok_or(HostError::Fence(
            "terminal availability lacks funded Accept",
        ))?;
        if available.accepted.is_none()
            || available.prepared.is_none()
            || available.prepared_reservation.is_none()
            || available.output_reservation.is_none()
            || available.failure().is_some()
            || self.request
                != (
                    BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2,
                    accept.id,
                    accept.session,
                    accept.signed,
                )
            || available
                .intervals
                .iter()
                .any(|interval| !interval.authenticated)
        {
            return Err(HostError::Fence(
                "terminal availability retains incomplete original custody",
            ));
        }
        let writes = available.prepared_writes.as_ref().ok_or(HostError::Fence(
            "terminal availability lost its original State prefix",
        ))?;
        if Arc::strong_count(writes) != 1 {
            return Err(HostError::Fence(
                "terminal availability State prefix remains aliased",
            ));
        }
        writes
            .lock()
            .map_err(|_| HostError::Fence("terminal availability State prefix is poisoned"))?
            .require_positive_disposal_v2()?;
        let output = available.output_writes.as_ref().ok_or(HostError::Fence(
            "terminal availability lost original output State writes",
        ))?;
        if Arc::strong_count(output) != 1 {
            return Err(HostError::Fence(
                "terminal output State prefix remains aliased",
            ));
        }
        output
            .lock()
            .map_err(|_| HostError::Fence("terminal output State prefix is poisoned"))?
            .require_positive_disposal_v2()
    }
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker>
    super::super::super::HostBroker<C, S, W>
{
    pub(in crate::broker) async fn execute_retained_availability_argument_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16],
        agent: &mut crate::live_agent::HostAgentLiveSessionV1,
        header: u64,
    ) -> Result<Vec<u8>> {
        let accepting = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => false,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => true,
            _ => return Err(HostError::Fence("Host retained argument purpose differs")),
        };
        if !self.state_healthy
            || self.active_argument_writes.is_some()
            || self.argument_stages[1].is_some()
        {
            return Err(HostError::Fence(
                "Host retained argument State or next stage is unavailable",
            ));
        }
        let stage = self.argument_stages[0]
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host retained availability stage is absent",
            ))?;
        let mut capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host retained availability stage is poisoned"))?;
        let available = capture.availability.as_ref().ok_or(HostError::Fence(
            "Host retained availability source is absent",
        ))?;
        if !capture.authenticated
            || capture.first.is_some()
            || capture.primary.is_some()
            || capture.owner.is_none()
            || available.accepted.is_none()
            || available.terminal.is_some()
            || available.output_reservation.is_none()
            || !available.intervals.iter().any(|interval| {
                interval.authenticated
                    && interval.request.0 == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            })
            || available.accept.is_some()
            || available.failure().is_some()
            || available.prepared.is_some() != accepting
            || available
                .intervals
                .iter()
                .any(|interval| !interval.authenticated)
            || accepting && capture.reservation.is_none()
        {
            return Err(HostError::Fence(
                "Host retained argument lacks its genuine prior Sent",
            ));
        }
        let identity = available.original;
        available.active_proposal_v2()?;
        let preparation = available.prepared;
        let original = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host retained financial original is absent",
            ))?;
        let mut original = original
            .lock()
            .map_err(|_| HostError::Fence("Host retained financial original is poisoned"))?;
        original.require_argument_boot_v2(boot)?;
        let fixed = ArgumentStageOriginalV2::fixed_demand_for_runtime_v2(
            request,
            RuntimeOpeningV2::Resident,
        )
        .and_then(|fixed| {
            fixed
                .checked_add(available.native_interval_demand_v2(request)?)
                .ok()
        })
        .ok_or(HostError::ResourceExhausted)?;
        let mut receiving = ArgumentNativeReceivingV2::Active(if accepting {
            let complete = fixed
                .checked_add(original.retained_accept_observation_demand_v2()?)
                .map_err(|_| HostError::ResourceExhausted)?;
            let receiving = original.begin_accept_with_retained_availability_v2(
                identity,
                preparation.ok_or(HostError::Fence("Host retained preparation is absent"))?,
                request,
                complete,
            )?;
            capture.complete_demand = complete;
            let ArgumentStageOriginalV2 {
                availability,
                writes,
                reservation,
                argument,
                accepted,
                ..
            } = &mut *capture;
            let available = availability.as_mut().ok_or(HostError::Fence(
                "Host retained source disappeared after funding",
            ))?;
            available.prepared_reservation = reservation.take();
            available.prepared_writes = Some(std::mem::replace(
                writes,
                Arc::new(Mutex::new(ArgumentStateWritesV2::new())),
            ));
            available.accept = Some(request_identity(request));
            *argument = Some(HostArgumentAttemptOpeningV2::new());
            *accepted =
                Some(super::super::super::accepted_execution::AcceptedExecutionOriginalV2::new());
            // The original four writers and all retained19 debt cross together.
            // No opener, positive19 disposal, fresh clock or second Arc stage.
            self.argument_stages[1] = self.argument_stages[0].take();
            receiving
        } else {
            let (observations, maximum) = original.availability_interval_demand_v2(identity)?;
            let complete = capture
                .complete_demand
                .checked_add(fixed)
                .and_then(|value| value.checked_add(observations))
                .map_err(|_| HostError::ResourceExhausted)?;
            let receiving =
                original.begin_availability_interval_v2(identity, request, complete, maximum)?;
            capture.complete_demand = complete;
            capture.append_availability_interval_v2(
                request,
                receiving.observation_round_start_data_v2(),
            )?;
            receiving
        });
        capture.begin_retained_phase_v2(request);
        capture.source_cutoff = Some((|| {
            capture
                .clock
                .as_mut()
                .ok_or(HostError::Fence("Host retained clock disappeared"))?
                .advance_argument_stage_v2(request.method())?;
            capture.retained_argument_cutoff_v2(request, boot, header)
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
                "Host retained argument cutoff is unavailable",
            )),
        });
        if !matches!(capture.before, Some(Ok(()))) {
            capture.first.get_or_insert(ArgumentFirstV2::Before);
        }
        if let Some(cutoff) = cutoff.filter(|_| matches!(capture.before, Some(Ok(())))) {
            let primary = (|| {
                let available = capture
                    .availability
                    .as_mut()
                    .ok_or(HostError::Fence("Host retained source disappeared"))?;
                let snapshot = if accepting {
                    &mut available.accept_snapshot
                } else {
                    &mut available
                        .intervals
                        .last_mut()
                        .ok_or(HostError::Fence(
                            "Host retained preparation interval disappeared",
                        ))?
                        .snapshot
                };
                let current = self.store.load_retaining_v2(snapshot)?;
                current.validate_authenticated(&self.authority)?;
                if current != self.state {
                    return Err(
                        HostError::Fence("Host retained argument physical State changed").into(),
                    );
                }
                capture.prepare_argument_native_v2(
                    &mut receiving,
                    cutoff,
                    RuntimeOpeningV2::Resident,
                )?;
                self.execute_argument_primary_v2(&mut capture, request, boot, agent, cutoff)
            })();
            if primary.is_err() {
                let frontier = capture.frontier;
                capture.first.get_or_insert(frontier);
            }
            capture.primary = Some(primary);
        }
        let response = capture.finish_native_response_v2(&mut receiving).await?;
        drop(capture);
        receiving.retain_pending_authenticated_v2()?;
        Ok(response)
    }

    pub(in crate::broker) fn retain_authenticated_availability_preparation_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        let stage = self.argument_stages[0].as_ref().ok_or(HostError::Fence(
            "Host retained preparation stage is absent",
        ))?;
        let mut capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host retained preparation stage is poisoned"))?;
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            || capture.authenticated
            || capture.first.is_some()
            || capture.primary.is_some()
            || !matches!(capture.before, Some(Ok(())))
            || !matches!(capture.after, Some(Ok(())))
            || !matches!(capture.native_finish, Some(Ok(())))
            || capture.reservation.is_none()
            || capture.request
                != (
                    request.method(),
                    request.request_id(),
                    request.session_binding(),
                    request.signed_request_digest(),
                )
        {
            return Err(HostError::Fence(
                "Host retained preparation differs from its native interval",
            ));
        }
        let actual_request = capture.request;
        let available = capture.availability.as_mut().ok_or(HostError::Fence(
            "Host retained preparation source is absent",
        ))?;
        let interval = available.intervals.last_mut().ok_or(HostError::Fence(
            "Host retained preparation interval is absent",
        ))?;
        if available.prepared.is_some()
            || interval.authenticated
            || interval.request != actual_request
        {
            return Err(HostError::Fence(
                "Host retained preparation interval differs",
            ));
        }
        let original = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence(
                "Host retained preparation financial original is absent",
            ))?;
        original
            .lock()
            .map_err(|_| {
                HostError::Fence("Host retained preparation financial original is poisoned")
            })?
            .retain_authenticated_availability_preparation_v2(available.original, request)?;
        available.prepared = Some(request_identity(request));
        interval.authenticated = true;
        capture.authenticated = true;
        Ok(())
    }
}
