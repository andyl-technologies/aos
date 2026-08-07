//! Authoritative single-scheduler implementation of the quantum-loop boundary.

use super::*;

impl QuantumLoop for SingleScheduler {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.drive_authoritative_quantum(request)
    }

    fn backend_step_ceiling(
        &self,
        outcome: &QuantumOutcome,
    ) -> Result<VirtualTime, SchedulerError> {
        match (&outcome.advanced_node, &self.last_advance) {
            (None, None) => Ok(outcome.frontier),
            (Some(selected), Some(advance)) if selected == &advance.node => Ok(VirtualTime {
                ticks: advance.after.ticks,
            }),
            _ => Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum outcome selected node does not match the scheduler's last RUN",
                ),
            }),
        }
    }

    fn backend_effect_time(
        &self,
        node: &NodeId,
        at: VirtualTime,
    ) -> Result<VirtualTime, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let counter =
            self.node_counter_for_time_ceil(&self.nodes[index], SimInstant { nanos: at.ticks })?;
        let projected = self.node_time_for_counter(&self.nodes[index], counter)?;
        if projected != (SimInstant { nanos: at.ticks }) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "backend effect for node `{}` at scheduler time {} has no exact physical counter (next counter {} projects to {})",
                    node.name, at.ticks, counter.ticks, projected.nanos
                ),
            });
        }
        Ok(VirtualTime {
            ticks: counter.ticks,
        })
    }

    fn backend_network_output_time(
        &self,
        node: &NodeId,
        at: Icount,
    ) -> Result<VirtualTime, SchedulerError> {
        Ok(VirtualTime {
            ticks: self.vm_delivery_time_for_icount(node, at)?.nanos,
        })
    }

    fn backend_observation_time(
        &self,
        node: &NodeId,
        at: VirtualTime,
    ) -> Result<VirtualTime, SchedulerError> {
        let index = self.vm_node_index(node)?;
        Ok(VirtualTime {
            ticks: self
                .node_time_for_counter(&self.nodes[index], NodeCounter { ticks: at.ticks })?
                .nanos,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.admit_control_at_boundary(control);
        let SchedulerControlDrain {
            events,
            applications,
        } = self.drain_control_events()?;
        let at = SimInstant {
            nanos: self.frontier.ticks,
        };
        let event_log = self.emit_quantum_event_log(&events, &[], &[], at, false)?;
        self.commit_control_applications(applications);
        self.yield_to_control_inbox();
        Ok(event_log.entries)
    }

    fn append_backend_observable_events(
        &mut self,
        events: Vec<ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.append_observable_events(events)
    }

    fn append_backend_evaluation_boundary(
        &mut self,
        at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let at = at.max(self.event_log.condition_prefix().point().at());
        self.append_evaluation_boundary(at, SchedulerEvaluationBoundaryKind::Quantum)
    }

    fn append_backend_observations_at_boundary(
        &mut self,
        events: Vec<ObservableEvent>,
        at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let at = at.max(self.event_log.condition_prefix().point().at());
        let events = events
            .into_iter()
            .map(|event| event.normalize_backend_poll_boundary(at));
        self.append_observations_at_boundary(events, at, SchedulerEvaluationBoundaryKind::Quantum)
    }

    fn append_backend_causal_decisions(
        &mut self,
        decisions: Vec<Decision>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        let original_len = self.configuration.schedule.decisions().len();
        let mut recorder = DecisionRecorder::from_seed_and_positions(
            self.configuration.clone(),
            self.decision_seed,
            &self.decision_rng_cursor,
        );
        for decision in decisions {
            let Decision::AppRandom(expected) = decision else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "live backend emitted a causal decision other than app-random",
                    ),
                });
            };
            let actual = recorder
                .serve_app_random_request(
                    expected.node.clone(),
                    expected.stream.clone(),
                    expected.request_id,
                    expected.width,
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("live backend app-random decision was rejected: {error}"),
                })?;
            if actual != expected.value {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "live backend app-random value {} differs from seeded value {actual}",
                        expected.value
                    ),
                });
            }
        }
        for decision in &recorder.schedule().decisions()[original_len..] {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        let configuration = recorder.into_configuration();
        let recorded = configuration.schedule.decisions()[original_len..].to_vec();
        let at = SimInstant {
            nanos: self
                .frontier
                .max(self.event_log.condition_prefix().point().at())
                .ticks,
        };
        let append = self.emit_quantum_event_log(&[], &recorded, &[], at, true)?;
        self.configuration = configuration.clone();
        Ok((recorded, configuration, append))
    }

    fn append_backend_network_outputs(
        &mut self,
        mut outputs: Vec<BackendNetworkOutput>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        if !self.world_network_decisions.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live backend network outputs reached a scheduler with pending link decisions",
                ),
            });
        }
        outputs.sort_by(|left, right| {
            (
                left.emit_icount,
                &left.source,
                left.sequence,
                &left.destination,
                &left.payload,
            )
                .cmp(&(
                    right.emit_icount,
                    &right.source,
                    right.sequence,
                    &right.destination,
                    &right.payload,
                ))
        });
        let admission_boundary = self
            .frontier
            .max(self.event_log.condition_prefix().point().at());
        let mut recorded = Vec::new();
        for output in outputs {
            let source_index = self.vm_node_index(&output.source)?;
            let source_counter = self.nodes[source_index].counter.ticks;
            if output.emit_icount.retired > source_counter {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU node `{}` emitted frame {} at icount {} beyond committed boundary {}",
                        output.source.name,
                        output.sequence,
                        output.emit_icount.retired,
                        source_counter
                    ),
                });
            }
            let destination_mac: [u8; 6] = output
                .payload
                .get(..6)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU node `{}` emitted frame {} shorter than an Ethernet header",
                        output.source.name, output.sequence
                    ),
                })?
                .try_into()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("Ethernet destination width changed during routing"),
                })?;
            let flood = destination_mac == [0xff; 6] || destination_mac[0] & 1 == 1;
            let routes = self
                .world_network_links
                .iter()
                .filter(|(_key, runtime)| {
                    runtime.source() == &output.source
                        && (flood
                            || crate::deterministic_node_mac(runtime.target()) == destination_mac)
                })
                .map(|((link, direction), _runtime)| (link.clone(), *direction))
                .collect::<Vec<_>>();
            if routes.is_empty() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU frame {} from {} through router {} has no World route for destination MAC {:02x?}",
                        output.sequence,
                        output.source.name,
                        output.destination.name,
                        destination_mac
                    ),
                });
            }
            let frame_id =
                u32::try_from(output.sequence).map_err(|_| SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU node `{}` frame sequence {} exceeds the modeled frame-id width",
                        output.source.name, output.sequence
                    ),
                })?;
            for (link, direction) in routes {
                let emit_time =
                    self.vm_delivery_time_for_icount(&output.source, output.emit_icount)?;
                let logical_emit_icount = self.network_icount_for_time_ceil(emit_time)?;
                let frame = crucible_device::Frame::new(
                    logical_emit_icount,
                    frame_id,
                    output.payload.clone(),
                );
                let seed = self.decision_seed;
                let (record, branch_choices) = self.resolve_live_world_network_frame(
                    &link,
                    direction,
                    seed,
                    &frame,
                    crucible_device::PastDeliveryPolicy::FailLoud,
                )?;
                let projected = record
                    .decisions
                    .into_iter()
                    .map(|decision| match decision {
                        Decision::FaultFires(mut fault) => {
                            // The frame retains its exact guest TX icount for
                            // link delivery arithmetic. The probabilistic link
                            // choice becomes causal when the shared frontier
                            // admits the buffered TX batch.
                            fault.at = admission_boundary;
                            Decision::FaultFires(fault)
                        }
                        other => other,
                    })
                    .collect::<Vec<_>>();
                if !branch_choices.is_empty() {
                    let branch_configuration = self.step_quantum(&recorded);
                    let projected_choices = branch_choices
                        .into_iter()
                        .map(|choice| {
                            choice
                                .into_iter()
                                .map(|decision| match decision {
                                    Decision::FaultFires(mut fault) => {
                                        fault.at = admission_boundary;
                                        Decision::FaultFires(fault)
                                    }
                                    other => other,
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    self.search_frontiers.push(SearchRuntimeFrontier {
                        configuration: branch_configuration,
                        at: admission_boundary,
                        choices: SearchFrontierChoices::from_decision_sequences(projected_choices),
                    });
                }
                recorded.extend(projected);
            }
        }
        self.world_network_decisions.clear();
        for decision in &recorded {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        let configuration = self.step_quantum(&recorded);
        let at = SimInstant {
            nanos: admission_boundary.ticks,
        };
        let append = self.emit_quantum_event_log(&[], &recorded, &[], at, true)?;
        self.configuration = configuration.clone();
        Ok((recorded, configuration, append))
    }
}

impl SingleScheduler {
    fn resolve_live_world_network_frame(
        &mut self,
        link: &LinkId,
        direction: NetworkLinkDirection,
        seed: Seed,
        frame: &crucible_device::Frame,
        policy: crucible_device::PastDeliveryPolicy,
    ) -> Result<(crate::LinkEmitDecisionRecord, Vec<Vec<Decision>>), SchedulerError> {
        let runtime_key = self
            .world_network_links
            .iter()
            .find_map(|(key, candidate)| candidate.matches(link, direction).then(|| key.clone()))
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "World network link is unknown or ambiguous: {:?} ({direction:?})",
                    link.name
                ),
            })?;
        let rng_position = self
            .world_network_rng_positions
            .get(&runtime_key.0)
            .copied()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "World network link {:?} has no logical RNG cursor",
                    runtime_key.0.name
                ),
            })?;
        // The link direction and logical RNG position identify one causal
        // emission. Do not include the live guest's raw TX icount: QEMU may
        // report a slightly different instruction count for the same hostless
        // probe across fresh process launches, while the scheduler-owned stream
        // ordinal and frame correlation remain the canonical replay identity.
        let point = SchedulingPoint {
            key: format!(
                "live-world-network/{}/{}/{}/{}",
                runtime_key.0.name,
                network_direction_label(direction),
                frame.frame_id,
                rng_position
            ),
        };
        let preview = {
            let mut runtime = self
                .world_network_links
                .get(&runtime_key)
                .cloned()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "World network link disappeared while previewing a search frontier",
                    ),
                })?;
            runtime
                .emit_from_position(seed, rng_position, frame, policy)
                .map_err(|source| SchedulerError::BoundaryViolation {
                    message: format!(
                        "World network link {:?} ({direction:?}) rejected a preview frame: {source}",
                        runtime.canonical_id.name
                    ),
                })?
        };
        let faults = self
            .world_network_links
            .get(&runtime_key)
            .map(|runtime| runtime.link.faults().clone())
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "World network link disappeared while reading its fault table",
                ),
            })?;
        let branch_choices = live_network_branch_choices(&faults, &preview.draws)
            .into_iter()
            .map(|choice| {
                self.preview_live_network_choice(
                    &runtime_key,
                    rng_position,
                    frame,
                    policy,
                    point.clone(),
                    choice,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let installed = self
            .branch_network_choices
            .iter()
            .position(|choice| choice.point == point)
            .map(|index| self.branch_network_choices.remove(index));
        let record = match installed {
            Some(override_decision) => {
                let draws = live_network_branch_draws(
                    &faults,
                    &preview.draws,
                    &override_decision.choice.name,
                )
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "live World-network choice `{}` is impossible for point `{}`",
                        override_decision.choice.name, override_decision.point.key
                    ),
                })?;
                let mut record = self.emit_live_network_injected(
                    &runtime_key,
                    rng_position,
                    frame,
                    draws,
                    policy,
                )?;
                record
                    .decisions
                    .insert(0, Decision::Override(override_decision));
                record
            }
            None => {
                let runtime = self
                    .world_network_links
                    .get_mut(&runtime_key)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "World network link disappeared during live emission",
                        ),
                    })?;
                runtime
                    .emit_from_position(seed, rng_position, frame, policy)
                    .map_err(|source| SchedulerError::BoundaryViolation {
                        message: format!(
                            "World network link {:?} ({direction:?}) rejected a frame: {source}",
                            runtime.canonical_id.name
                        ),
                    })?
            }
        };
        let next_rng_position = self
            .world_network_links
            .get(&runtime_key)
            .map(|runtime| runtime.link.rng_position())
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "World network link disappeared after resolving a live frame",
                ),
            })?;
        self.world_network_rng_positions
            .insert(runtime_key.0, next_rng_position);
        self.refresh_device_horizons()?;
        Ok((record, branch_choices))
    }

    fn preview_live_network_choice(
        &self,
        runtime_key: &(LinkId, NetworkLinkDirection),
        rng_position: u64,
        frame: &crucible_device::Frame,
        policy: crucible_device::PastDeliveryPolicy,
        point: SchedulingPoint,
        choice: LiveNetworkBranchChoice,
    ) -> Result<Vec<Decision>, SchedulerError> {
        let mut runtime = self
            .world_network_links
            .get(runtime_key)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "World network link disappeared while enumerating a search choice",
                ),
            })?;
        let record = runtime
            .emit_injected_from_position(rng_position, frame, choice.draws, policy)
            .map_err(|source| SchedulerError::BoundaryViolation {
                message: format!(
                    "World network link {:?} rejected a search choice: {source}",
                    runtime.canonical_id.name
                ),
            })?;
        let mut decisions = Vec::with_capacity(record.decisions.len().saturating_add(1));
        decisions.push(Decision::Override(OverrideDecision {
            point,
            choice: ChoiceTag { name: choice.name },
        }));
        decisions.extend(record.decisions);
        Ok(decisions)
    }

    fn emit_live_network_injected(
        &mut self,
        runtime_key: &(LinkId, NetworkLinkDirection),
        rng_position: u64,
        frame: &crucible_device::Frame,
        draws: crucible_device::FrameDraws,
        policy: crucible_device::PastDeliveryPolicy,
    ) -> Result<crate::LinkEmitDecisionRecord, SchedulerError> {
        let runtime = self
            .world_network_links
            .get_mut(runtime_key)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "World network link disappeared while applying a search choice",
                ),
            })?;
        runtime
            .emit_injected_from_position(rng_position, frame, draws, policy)
            .map_err(|source| SchedulerError::BoundaryViolation {
                message: format!(
                    "World network link {:?} rejected an injected search choice: {source}",
                    runtime.canonical_id.name
                ),
            })
    }
}

fn network_direction_label(direction: NetworkLinkDirection) -> &'static str {
    match direction {
        NetworkLinkDirection::EndpointAToEndpointB => "a-to-b",
        NetworkLinkDirection::EndpointBToEndpointA => "b-to-a",
    }
}
