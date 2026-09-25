//! Authoritative single-scheduler implementation of the quantum-loop boundary.

use super::*;

struct LiveNetworkFrameResolutionRequest<'a> {
    link: &'a LinkId,
    direction: NetworkLinkDirection,
    seed: Seed,
    frame: &'a crucible_device::Frame,
    policy: crucible_device::PastDeliveryPolicy,
    parent: &'a Configuration,
    at: VirtualTime,
}

struct LiveNetworkFrameResolution {
    record: crate::LinkEmitDecisionRecord,
    branch_choices: Vec<Vec<Decision>>,
    discovery: Option<crucible_campaign::ChoiceDiscovery>,
}

/// A live frame choice observed before its default changes the World network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveNetworkPreselection {
    /// Exact configuration from which the choice can be replayed.
    pub parent: Configuration,
    /// Scheduler boundary at which the frame is offered.
    pub at: VirtualTime,
    /// Self-contained opportunity and domain offered at this boundary.
    pub discovery: crucible_campaign::ChoiceDiscovery,
    /// Exact replay alternatives before any default decision mutates the route.
    pub frontier: SearchRuntimeFrontier,
    /// Original frame retained until the choice is resolved or handed off.
    pub output: BackendNetworkOutput,
    /// Exact directed route to which the choice applies.
    pub route: BackendNetworkRoute,
}

impl SingleScheduler {
    /// Resolves and validates every directed World route for one backend frame.
    ///
    /// A route already selected by an in-loop interceptor is accepted only when
    /// it remains a member of the scheduler-derived route set. This keeps route
    /// expansion deterministic while preventing an interceptor from bypassing
    /// World connectivity or Ethernet destination resolution.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the frame is shorter than an Ethernet
    /// header, no route exists, or a route lock is not valid for the frame.
    pub fn resolve_backend_network_routes(
        &self,
        output: &BackendNetworkOutput,
    ) -> Result<Vec<BackendNetworkRoute>, SchedulerError> {
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
        let forced_destination = output.fault_continuation.forced_route_destination();
        let candidates = self
            .world_network_links
            .iter()
            .filter(|(_key, runtime)| {
                runtime.source() == &output.source
                    && forced_destination.map_or_else(
                        || {
                            flood
                                || crate::deterministic_node_mac(runtime.target())
                                    == destination_mac
                        },
                        |forced| runtime.target() == forced,
                    )
            })
            .map(|((link, direction), runtime)| BackendNetworkRoute {
                link: link.clone(),
                direction: *direction,
                destination: runtime.target().clone(),
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU frame {} from {} through router {} has no World route for destination MAC {:02x?}",
                    output.sequence, output.source.name, output.destination.name, destination_mac
                ),
            });
        }
        match &output.route {
            Some(route) if candidates.contains(route) => Ok(vec![route.clone()]),
            Some(route) => Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU frame {} from {} carries invalid World route `{}` {:?}",
                    output.sequence, output.source.name, route.link.name, route.direction
                ),
            }),
            None => Ok(candidates),
        }
    }
}

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
            self.node_counter_for_time_ceil(&self.nodes[index], SimInstant { ticks: at.ticks })?;
        let projected = self.node_time_for_counter(&self.nodes[index], counter)?;
        if projected != (SimInstant { ticks: at.ticks }) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "backend effect for node `{}` at scheduler time {} has no exact physical counter (next counter {} projects to {})",
                    node.name, at.ticks, counter.ticks, projected.ticks
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
            ticks: self.vm_delivery_time_for_icount(node, at)?.ticks,
        })
    }

    fn backend_network_route_count(
        &self,
        output: &BackendNetworkOutput,
    ) -> Result<usize, SchedulerError> {
        self.resolve_backend_network_routes(output)
            .map(|routes| routes.len())
    }

    fn backend_network_routes(
        &self,
        output: BackendNetworkOutput,
    ) -> Result<Vec<BackendNetworkOutput>, SchedulerError> {
        let routes = self
            .resolve_backend_network_routes(&output)?
            .into_iter()
            .map(|route| {
                let mut routed = output.clone();
                routed.route = Some(route);
                routed
            })
            .collect();
        Ok(routes)
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
                .ticks,
        })
    }

    fn resolved_event_observation(
        &self,
        event: &ScheduledEvent,
    ) -> Result<Option<ObservableEvent>, SchedulerError> {
        self.resolved_io_observation(event)
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
            ticks: self.frontier.ticks,
        };
        let event_log = self.emit_quantum_event_log(&events, &[], &[], at, false)?;
        self.commit_control_applications(applications);
        self.yield_to_control_inbox();
        Ok(event_log.entries)
    }

    fn append_noncanonical_debug_event_log_entries(
        &mut self,
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(self.event_log.append_entries(entries)?.entries)
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

    fn append_backend_rng_evidence(
        &mut self,
        evidence: Vec<BackendRngEvidence>,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        let original_len = self.configuration.schedule.decisions().len();
        let mut recorder = DecisionRecorder::from_seed_and_positions(
            self.configuration.clone(),
            self.decision_seed,
            &self.decision_rng_cursor,
        );
        let mut discovered_choices = Vec::with_capacity(evidence.len());
        for expected in evidence {
            let parent = recorder
                .app_random_selection_parent(&expected)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("live backend app-random decision was rejected: {error}"),
                })?;
            let discovery = if let Some(selection) = self.app_random_branch_selections.get(&parent)
            {
                let selection =
                    selection
                        .selection()
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "installed app-random branch selection is not canonical: {error}"
                            ),
                        })?;
                let discovery = recorder
                    .apply_app_random_selection(expected, &selection)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "live backend app-random branch selection was rejected: {error}"
                        ),
                    })?;
                self.app_random_branch_selections.remove(&parent);
                discovery
            } else {
                recorder
                    .admit_backend_rng_evidence(expected)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("live backend app-random decision was rejected: {error}"),
                    })?
            };
            discovered_choices.push(discovery);
        }
        let configuration = recorder.into_configuration();
        let recorded = configuration.schedule.decisions()[original_len..].to_vec();
        let advanced_streams = recorded
            .iter()
            .filter_map(|decision| match decision {
                Decision::RngDraw(draw) => Some(draw.stream.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let at = SimInstant {
            ticks: self
                .frontier
                .max(self.event_log.condition_prefix().point().at())
                .ticks,
        };
        let append = self.emit_quantum_event_log(&[], &recorded, &[], at, true)?;
        for stream in advanced_streams {
            self.advance_decision_rng_cursor_for(stream);
        }
        self.configuration = configuration.clone();
        Ok((recorded, discovered_choices, configuration, append))
    }

    fn append_backend_network_outputs(
        &mut self,
        outputs: Vec<BackendNetworkOutput>,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        match self.admit_backend_network_outputs(outputs, false)? {
            BackendNetworkAdmission::Settled {
                decisions,
                discoveries,
                configuration,
                append,
            } => Ok((decisions, discoveries, configuration, append)),
            BackendNetworkAdmission::Preselection { .. } => {
                Err(SchedulerError::BoundaryViolation {
                    message: String::from("network admission paused without a choice request"),
                })
            }
        }
    }

    fn append_backend_network_outputs_until_choice(
        &mut self,
        outputs: Vec<BackendNetworkOutput>,
    ) -> Result<BackendNetworkAdmission, SchedulerError> {
        self.admit_backend_network_outputs(outputs, true)
    }
}

impl SingleScheduler {
    fn admit_backend_network_outputs(
        &mut self,
        mut outputs: Vec<BackendNetworkOutput>,
        pause_at_choice: bool,
    ) -> Result<BackendNetworkAdmission, SchedulerError> {
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
                &left.route,
                &left.fault_continuation,
                &left.payload,
            )
                .cmp(&(
                    right.emit_icount,
                    &right.source,
                    right.sequence,
                    &right.destination,
                    &right.route,
                    &right.fault_continuation,
                    &right.payload,
                ))
        });
        let admission_boundary = self
            .frontier
            .max(self.event_log.condition_prefix().point().at());
        let mut recorded = Vec::new();
        let mut discovered_choices = Vec::new();
        for (output_index, output) in outputs.iter().enumerate() {
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
            let routes = self.resolve_backend_network_routes(output)?;
            let frame_id =
                u32::try_from(output.sequence).map_err(|_| SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU node `{}` frame sequence {} exceeds the modeled frame-id width",
                        output.source.name, output.sequence
                    ),
                })?;
            for (route_index, route) in routes.iter().enumerate() {
                let branch_configuration = self.step_quantum(&recorded)?;
                let emit_time = self
                    .vm_delivery_time_for_icount(&output.source, output.emit_icount)?
                    .max(SimInstant {
                        ticks: output.fault_continuation.cursor().release_nanos(),
                    });
                let logical_emit_icount = self.network_icount_for_time_ceil(emit_time)?;
                let frame = crucible_device::Frame::new(
                    logical_emit_icount,
                    frame_id,
                    output.payload.clone(),
                )
                .with_resolved_effects(output.fault_continuation.resolved_frame_effects().clone());
                if pause_at_choice
                    && let Some(reservation) = self.preview_live_network_preselection(
                        output,
                        route,
                        &branch_configuration,
                        admission_boundary,
                    )?
                {
                    let remaining = routes[route_index..]
                        .iter()
                        .map(|route| {
                            let mut routed = output.clone();
                            routed.route = Some(route.clone());
                            routed
                        })
                        .chain(outputs[output_index + 1..].iter().cloned())
                        .collect();
                    discovered_choices.push(reservation.discovery.clone());
                    self.world_network_decisions.clear();
                    for decision in &recorded {
                        if let Decision::RngDraw(draw) = decision {
                            self.advance_decision_rng_cursor_for(draw.stream.clone());
                        }
                    }
                    let at = SimInstant {
                        ticks: admission_boundary.ticks,
                    };
                    let append = self.emit_quantum_event_log(&[], &recorded, &[], at, true)?;
                    self.configuration = branch_configuration.clone();
                    return Ok(BackendNetworkAdmission::Preselection {
                        decisions: recorded,
                        discoveries: discovered_choices,
                        configuration: branch_configuration,
                        append,
                        reservation: Box::new(reservation),
                        remaining,
                    });
                }
                let seed = self.decision_seed;
                let resolution =
                    self.resolve_live_world_network_frame(LiveNetworkFrameResolutionRequest {
                        link: &route.link,
                        direction: route.direction,
                        seed,
                        frame: &frame,
                        policy: crucible_device::PastDeliveryPolicy::FailLoud,
                        parent: &branch_configuration,
                        at: admission_boundary,
                    })?;
                let LiveNetworkFrameResolution {
                    record,
                    branch_choices,
                    discovery,
                } = resolution;
                let projected = record.decisions;
                if !branch_choices.is_empty() {
                    self.search_frontiers.push(SearchRuntimeFrontier {
                        configuration: branch_configuration,
                        at: admission_boundary,
                        choices: SearchFrontierChoices::from_decision_sequences(branch_choices),
                    });
                }
                if let Some(discovery) = discovery {
                    discovered_choices.push(discovery);
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
        let configuration = self.step_quantum(&recorded)?;
        let at = SimInstant {
            ticks: admission_boundary.ticks,
        };
        let append = self.emit_quantum_event_log(&[], &recorded, &[], at, true)?;
        self.configuration = configuration.clone();
        Ok(BackendNetworkAdmission::Settled {
            decisions: recorded,
            discoveries: discovered_choices,
            configuration,
            append,
        })
    }

    /// Previews a directed live frame without committing a default selection.
    ///
    /// A cloned scheduler performs the ordinary resolution so opportunity IDs
    /// and replay alternatives come from the same producer as a settled frame.
    /// An already installed campaign branch is not offered again.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the frame or route cannot be admitted.
    pub fn preview_live_network_preselection(
        &self,
        output: &BackendNetworkOutput,
        route: &BackendNetworkRoute,
        parent: &Configuration,
        at: VirtualTime,
    ) -> Result<Option<LiveNetworkPreselection>, SchedulerError> {
        let source_index = self.vm_node_index(&output.source)?;
        let source_counter = self.nodes[source_index].counter.ticks;
        if output.emit_icount.retired > source_counter
            || !self.resolve_backend_network_routes(output)?.contains(route)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU node `{}` frame {} is not committed on the requested World route",
                    output.source.name, output.sequence
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
        let emit_time = self
            .vm_delivery_time_for_icount(&output.source, output.emit_icount)?
            .max(SimInstant {
                ticks: output.fault_continuation.cursor().release_nanos(),
            });
        let logical_emit_icount = self.network_icount_for_time_ceil(emit_time)?;
        let frame =
            crucible_device::Frame::new(logical_emit_icount, frame_id, output.payload.clone())
                .with_resolved_effects(output.fault_continuation.resolved_frame_effects().clone());
        let mut preview = self.clone();
        let pending_branches = preview.branch_network_choices.len();
        let resolution =
            preview.resolve_live_world_network_frame(LiveNetworkFrameResolutionRequest {
                link: &route.link,
                direction: route.direction,
                seed: self.decision_seed,
                frame: &frame,
                policy: crucible_device::PastDeliveryPolicy::FailLoud,
                parent,
                at,
            })?;
        if preview.branch_network_choices.len() < pending_branches {
            return Ok(None);
        }
        Ok(resolution
            .discovery
            .map(|discovery| LiveNetworkPreselection {
                parent: parent.clone(),
                at,
                discovery,
                frontier: SearchRuntimeFrontier {
                    configuration: parent.clone(),
                    at,
                    choices: SearchFrontierChoices::from_decision_sequences(
                        resolution.branch_choices,
                    ),
                },
                output: output.clone(),
                route: route.clone(),
            }))
    }

    fn resolve_live_world_network_frame(
        &mut self,
        request: LiveNetworkFrameResolutionRequest<'_>,
    ) -> Result<LiveNetworkFrameResolution, SchedulerError> {
        let LiveNetworkFrameResolutionRequest {
            link,
            direction,
            seed,
            frame,
            policy,
            parent,
            at,
        } = request;
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
        let choices = live_network_branch_choices(&faults, &preview.draws);
        let selectable = if choices.is_empty() {
            None
        } else {
            Some(
                LiveNetworkSelectable::new(parent, at, &point, &choices, &faults, &preview.draws)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("live World-network choice could not be typed: {error}"),
                })?,
            )
        };
        let branch_choices = choices
            .iter()
            .map(|choice| {
                let selection = selectable
                    .as_ref()
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("live World-network selectable disappeared"),
                    })?
                    .branch_selection(parent, &choice.name)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "live World-network branch selection could not be built: {error}"
                        ),
                    })?;
                self.preview_live_network_choice(
                    &runtime_key,
                    rng_position,
                    frame,
                    policy,
                    choice.clone(),
                    selection,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let installed = match &selectable {
            Some(selectable) => {
                let opportunity = selectable.opportunity_id().map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!("live World-network opportunity is invalid: {error}"),
                    }
                })?;
                self.branch_network_choices
                    .iter()
                    .position(|decision| {
                        decision
                            .selection()
                            .is_ok_and(|selection| selection.opportunity() == opportunity)
                    })
                    .map(|index| self.branch_network_choices.remove(index))
            }
            None => None,
        };
        let record =
            match (installed, &selectable) {
                (Some(selection_decision), Some(selectable)) => {
                    let selection = selection_decision.selection().map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!("live World-network selection is invalid: {error}"),
                        }
                    })?;
                    let name = selectable
                        .selected_name(parent, &selection)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "live World-network branch selection was rejected: {error}"
                            ),
                        })?;
                    let draws = live_network_branch_draws(&faults, &preview.draws, name)
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "live World-network choice `{}` is impossible for point `{}`",
                                name, point.key
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
                        .insert(0, Decision::Selection(selection_decision));
                    record
                }
                (None, selectable) => {
                    let runtime =
                        self.world_network_links
                            .get_mut(&runtime_key)
                            .ok_or_else(|| SchedulerError::BoundaryViolation {
                                message: String::from(
                                    "World network link disappeared during live emission",
                                ),
                            })?;
                    let mut record = runtime
                    .emit_from_position(seed, rng_position, frame, policy)
                    .map_err(|source| SchedulerError::BoundaryViolation {
                        message: format!(
                            "World network link {:?} ({direction:?}) rejected a frame: {source}",
                            runtime.canonical_id.name
                        ),
                    })?;
                    if let Some(selectable) = selectable {
                        let selection = selectable.default_selection().map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "live World-network default selection could not be built: {error}"
                            ),
                        }
                    })?;
                        record
                            .decisions
                            .insert(0, Decision::Selection(SelectionDecision::new(&selection)));
                    }
                    record
                }
                (Some(_), None) => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "live World-network selection exists without an explorable opportunity",
                        ),
                    });
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
        Ok(LiveNetworkFrameResolution {
            record,
            branch_choices,
            discovery: selectable.map(|selectable| selectable.discovery()),
        })
    }

    fn preview_live_network_choice(
        &self,
        runtime_key: &(LinkId, NetworkLinkDirection),
        rng_position: u64,
        frame: &crucible_device::Frame,
        policy: crucible_device::PastDeliveryPolicy,
        choice: LiveNetworkBranchChoice,
        selection: crucible_campaign::Selection,
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
        decisions.push(Decision::Selection(SelectionDecision::new(&selection)));
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
