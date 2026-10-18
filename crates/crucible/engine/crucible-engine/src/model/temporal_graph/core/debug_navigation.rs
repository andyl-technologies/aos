//! Debugger attach and temporal-navigation operations.

use super::*;

impl TemporalGraph {
    /// Attaches a debug session by realizing the requested checkpoint configuration.
    ///
    /// Debug attach is intentionally just [`Self::resume`] plus metadata for the
    /// fourth out-of-band gdbstub channel. It records no scheduler decision,
    /// carries no per-quantum/frame data, and introduces no debug-specific
    /// realization path.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::resume`] when the checkpoint
    /// configuration cannot be instantiated. Returns
    /// [`EngineError::DebugAttachUnknownNode`] when the realized runtime does not
    /// contain the requested node.
    pub fn debug_attach(
        &mut self,
        request: &DebugAttachRequest,
    ) -> Result<DebugAttachReport, EngineError> {
        let runtime = self.resume(&request.configuration)?;
        let node = request.node.clone();
        if !runtime.runtime.node_blobs.contains_key(&node)
            || !runtime.runtime.node_icounts.contains_key(&node)
        {
            return Err(EngineError::DebugAttachUnknownNode {
                node,
                configuration: request.configuration.id(),
            });
        }
        let reduced = reduce(&request.configuration.def, &request.configuration.schedule)?;
        if runtime.runtime.id != reduced.id {
            return Err(EngineError::ReplayTargetMismatch {
                expected: reduced.id,
                actual: runtime.runtime.id,
            });
        }

        Ok(DebugAttachReport {
            configuration: request.configuration.id(),
            checkpoint: runtime.checkpoint,
            runtime,
            reduced_state: reduced.id,
            channel_set: DebugAttachChannelSet::four_channel_debug_session(),
            gdbstub: DebugGdbstubChannel {
                node: request.node.clone(),
                qemu_endpoint: request.qemu_gdbstub.clone(),
                operator_listen: request.gdb_listen.clone(),
                mediated_by_crucible: true,
                out_of_band: true,
                carries_per_quantum_timing: false,
                carries_frame_data: false,
            },
        })
    }

    /// Records read-only debugger observations without mutating the temporal graph.
    ///
    /// The immutable receiver is part of the contract: inspection cannot record
    /// graph state, append decisions, or advance virtual time through this API.
    /// The report captures graph/checkpoint/runtime footprints before and after
    /// building the debugger event-log view, then compares canonical causal
    /// projections of the supplied no-debug log and the debug-observed log.
    #[must_use]
    pub fn read_only_debug_inspection(
        &self,
        attach: &DebugAttachReport,
        request: &DebugReadOnlyInspectionRequest,
        event_log: &[SchedulerEventLogEntry],
    ) -> DebugReadOnlyInspectionReport {
        let footprint_before =
            DebugReadOnlyInspectionFootprint::capture(self, attach, request.virtual_time);
        let observation_time = footprint_before.virtual_time;
        let causal_event_log_before = event_log_causal_projection(event_log);
        let mut event_log_with_observations = event_log.to_vec();
        let mut observational_entries = Vec::with_capacity(request.inspections.len() + 2);
        let mut sequence = u64::try_from(event_log.len()).unwrap_or(u64::MAX);

        observational_entries.push(debug_read_only_observation_entry(
            sequence,
            observation_time,
            DebugReadOnlyInspectionEvent::Attach,
            attach,
        ));
        sequence = sequence.saturating_add(1);
        for inspection in &request.inspections {
            observational_entries.push(debug_read_only_observation_entry(
                sequence,
                observation_time,
                DebugReadOnlyInspectionEvent::Inspect(*inspection),
                attach,
            ));
            sequence = sequence.saturating_add(1);
        }
        observational_entries.push(debug_read_only_observation_entry(
            sequence,
            observation_time,
            DebugReadOnlyInspectionEvent::Detach,
            attach,
        ));

        event_log_with_observations.extend(observational_entries.iter().cloned());
        let causal_event_log_after = event_log_causal_projection(&event_log_with_observations);
        let footprint_after =
            DebugReadOnlyInspectionFootprint::capture(self, attach, request.virtual_time);

        DebugReadOnlyInspectionReport {
            footprint_before,
            footprint_after,
            requested_virtual_time: request.virtual_time,
            causal_event_log_before,
            causal_event_log_after,
            observational_entries,
            event_log_with_observations,
        }
    }

    /// Resolves a canonical debugger breakpoint without guest-memory mutation.
    ///
    /// Software breakpoint requests are translated to an out-of-band mechanism
    /// when one is available. If the request would require patching a trap into
    /// guest memory, the operation returns a typed `--allow-mutate` error rather
    /// than modifying the canonical run.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DebugAttachUnknownNode`] when the request names a
    /// node outside the attached runtime. Returns
    /// [`EngineError::DebugBreakpointRequiresAllowMutate`] when no canonical
    /// out-of-band mechanism can satisfy the request.
    pub fn canonical_debug_breakpoint(
        &self,
        attach: &DebugAttachReport,
        request: &DebugBreakpointRequest,
    ) -> Result<DebugBreakpointReport, EngineError> {
        if request.node != attach.gdbstub.node
            || !attach
                .runtime
                .runtime
                .node_blobs
                .contains_key(&request.node)
            || !attach
                .runtime
                .runtime
                .node_icounts
                .contains_key(&request.node)
        {
            return Err(EngineError::DebugAttachUnknownNode {
                node: request.node.clone(),
                configuration: attach.configuration,
            });
        }
        let mechanism = request.canonical_mechanism().ok_or_else(|| {
            EngineError::DebugBreakpointRequiresAllowMutate {
                node: request.node.clone(),
                target: request.target.clone(),
                requested_client_kind: request.client_kind,
            }
        })?;

        Ok(DebugBreakpointReport {
            configuration: attach.configuration,
            checkpoint: attach.checkpoint,
            node: request.node.clone(),
            requested_client_kind: request.client_kind,
            target: request.target.clone(),
            mechanism,
            canonical: true,
            mutates_guest_memory: false,
            memory_patch_used: false,
            requires_allow_mutate: false,
        })
    }

    /// Forks an attached debugger into a marked non-canonical debug branch.
    ///
    /// The branch is recorded as debug metadata rather than as a
    /// [`Configuration`]. Decision-expressible edits and control-log operations
    /// are retained separately from the debug-edit script for arbitrary
    /// guest-state changes. The canonical graph/checkpoint/runtime footprint and
    /// causal event-log projection are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DebugGotoAttachMismatch`] when `attach` does not
    /// realize `request.current`. Returns
    /// [`EngineError::DebugNonCanonicalBranchMissingTriggerEvidence`] when the
    /// request trigger is not backed by a corresponding operator action.
    pub fn debug_non_canonical_branch(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugNonCanonicalBranchRequest,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<DebugNonCanonicalBranchReport, EngineError> {
        if attach.configuration != request.current.id() {
            return Err(EngineError::DebugGotoAttachMismatch {
                attached: attach.configuration,
                requested_current: request.current.id(),
            });
        }
        if !request.trigger_has_evidence() {
            return Err(EngineError::DebugNonCanonicalBranchMissingTriggerEvidence {
                trigger: request.trigger,
                configuration: request.current.id(),
            });
        }

        let footprint_before = DebugReadOnlyInspectionFootprint::capture(self, attach, request.at);
        let causal_event_log_before =
            canonical_run_event_log_projection_without_debug_branches(event_log);
        let marker_sequence = next_event_log_sequence(event_log);
        let branch = DebugNonCanonicalBranch::from_request(attach, request, marker_sequence);
        let mut event_log_with_fork_marker = event_log.to_vec();
        event_log_with_fork_marker.push(branch.fork_marker.entry.clone());
        let causal_event_log_after =
            canonical_run_event_log_projection_without_debug_branches(&event_log_with_fork_marker);
        self.non_canonical_debug_branches
            .insert(branch.id, branch.clone());
        let footprint_after = DebugReadOnlyInspectionFootprint::capture(self, attach, request.at);

        Ok(DebugNonCanonicalBranchReport {
            branch,
            canonical_footprint_before: footprint_before,
            canonical_footprint_after: footprint_after,
            causal_event_log_before,
            causal_event_log_after,
            event_log_with_fork_marker,
            guest_introspection_features: None,
            guest_introspection_activation_failure: None,
        })
    }

    /// Returns a recorded non-canonical debug branch by id.
    #[must_use]
    pub fn debug_non_canonical_branch_view(
        &self,
        branch: ContentHash,
    ) -> Option<&DebugNonCanonicalBranch> {
        self.non_canonical_debug_branches.get(&branch)
    }

    /// Returns the number of non-canonical debug branches recorded as graph metadata.
    #[must_use]
    pub fn debug_non_canonical_branch_count(&self) -> usize {
        self.non_canonical_debug_branches.len()
    }

    /// Resolves an operator-facing debug target into a `goto` request.
    ///
    /// The resolver accepts the public coordinate forms used by the debug CLI:
    /// direct `--at` coordinates, event-log sequence coordinates, the first
    /// assertion failure in the event log, checkpoint content addresses, and
    /// divergence-bisection coordinates. The returned request delegates actual
    /// movement to [`Self::debug_goto`], keeping target resolution separate from
    /// restore-plus-replay execution.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the selector has no matching event-log or
    /// checkpoint coordinate, when `--at-failure` sees no assertion violation,
    /// or when the resolved target belongs to another scenario.
    pub fn debug_resolve_target(
        &self,
        request: &DebugTargetResolverRequest,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<DebugTargetResolverReport, EngineError> {
        let mut failure_event_sequence = None;
        let mut divergence = None;
        let mut exact_target = None;
        let resolved_coordinate = match &request.selector {
            DebugTargetSelector::At(coordinate) => coordinate.clone(),
            DebugTargetSelector::AtEvent(sequence) => {
                if !debug_event_log_contains_sequence(event_log, *sequence) {
                    return Err(EngineError::DebugTimeTravelMissingEventCoordinate {
                        sequence: *sequence,
                    });
                }
                DebugCoordinate::event_sequence(*sequence)
            }
            DebugTargetSelector::AtFailure => {
                let sequence = debug_first_assertion_violation_sequence(event_log).ok_or(
                    EngineError::DebugTargetResolverFailureNotFound {
                        configuration: request.current.id(),
                    },
                )?;
                failure_event_sequence = Some(sequence);
                DebugCoordinate::event_sequence(sequence)
            }
            DebugTargetSelector::AtCheckpoint(checkpoint) => {
                DebugCoordinate::checkpoint(*checkpoint)
            }
            DebugTargetSelector::Divergence(coordinate) => {
                divergence = Some(coordinate.clone());
                let target =
                    self.debug_resolve_exact_divergence_coordinate(&request.current, coordinate)?;
                exact_target = Some(target.clone());
                DebugCoordinate::configuration(target)
            }
        };
        let target = if let Some(target) = exact_target {
            target
        } else {
            self.debug_resolve_coordinate(
                &request.current,
                &resolved_coordinate,
                &request.event_coordinates,
            )?
        };
        debug_validate_same_scenario(&request.current, &target)?;
        let goto_request = DebugGotoRequest {
            current: request.current.clone(),
            target: resolved_coordinate.clone(),
            event_coordinates: request.event_coordinates.clone(),
        };
        Ok(DebugTargetResolverReport {
            selector: request.selector.clone(),
            resolved_coordinate,
            target_configuration: target.id(),
            goto_request,
            failure_event_sequence,
            divergence,
        })
    }

    pub(in crate::model) fn debug_resolve_exact_divergence_coordinate(
        &self,
        current: &Configuration,
        coordinate: &DebugDivergenceCoordinate,
    ) -> Result<Configuration, EngineError> {
        self.debug_resolve_scoped_node_icount(current, &coordinate.node, coordinate.icount)
            .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::node_icount(
                    coordinate.node.clone(),
                    coordinate.icount,
                ),
            })
    }

    /// Moves an attached debug session to `request.target` using restore-plus-replay.
    ///
    /// The selected restore point is the exact target snapshot when one exists,
    /// otherwise the nearest cached ancestor, otherwise baked genesis. The target
    /// runtime is then materialized through [`instantiate`] and checked against
    /// the replay oracle, so a corrupt exact snapshot or cached ancestor cannot
    /// be accepted as a debugger-only shortcut.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the attached configuration does not match
    /// `request.current`, when the target belongs to another scenario, when the
    /// target cannot be instantiated, or when the replay oracle rejects the
    /// restored path.
    pub fn debug_goto(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugGotoRequest,
    ) -> Result<DebugGotoReport, EngineError> {
        if attach.configuration != request.current.id() {
            return Err(EngineError::DebugGotoAttachMismatch {
                attached: attach.configuration,
                requested_current: request.current.id(),
            });
        }
        let target = self.debug_resolve_coordinate(
            &request.current,
            &request.target,
            &request.event_coordinates,
        )?;
        debug_validate_same_scenario(&request.current, &target)?;
        self.record_checkpoint_closure(&target)?;
        let restore = self.debug_restore_configuration(&target)?;
        let restore_checkpoint = self
            .checkpoint_node(restore.id())
            .or_else(|| self.cached_snapshot(&restore))
            .map(|checkpoint| checkpoint.id)
            .ok_or(EngineError::CheckpointNotRecorded {
                checkpoint: restore.id(),
            })?;
        let replay_suffix = target
            .schedule
            .suffix_from(restore.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;

        let runtime = self
            .resume(&target)
            .map_err(|error| self.debug_goto_error(&request.current, &target, &restore, error))?;
        let target_checkpoint =
            materialized_checkpoint_for_runtime(&target, runtime.runtime.clone()).map_err(
                |error| self.debug_goto_error(&request.current, &target, &restore, error),
            )?;
        let replay_oracle = self
            .replay_checkpoint(&target, &target_checkpoint)
            .map_err(|error| self.debug_goto_error(&request.current, &target, &restore, error))?;

        Ok(DebugGotoReport {
            current_configuration: request.current.id(),
            target_coordinate: request.target.clone(),
            target_configuration: target.id(),
            landed_virtual_time: configuration_virtual_time(&target),
            landed_schedule_prefix_len: target.schedule.len(),
            restore_configuration: restore.id(),
            restore_checkpoint,
            replay_suffix_decisions: replay_suffix.len(),
            runtime,
            target_checkpoint: target_checkpoint.id,
            replay_oracle,
            live_reposition: None,
        })
    }

    /// Resolves and executes one reverse-step operation.
    ///
    /// Reverse stepping only resolves an earlier coordinate and delegates the
    /// actual movement to [`Self::debug_goto`]. This keeps reverse motion in the
    /// same restore-plus-replay path as forward instantiation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when no earlier coordinate exists for the
    /// requested grain, when an event-log coordinate lacks a configuration
    /// mapping, or when the delegated `goto` fails.
    pub fn debug_reverse_step(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugReverseStepRequest,
    ) -> Result<DebugReverseStepReport, EngineError> {
        let target = debug_reverse_step_target(request)?;
        let goto_request = match target.event_sequence {
            Some(sequence) => DebugGotoRequest::new(
                request.current.clone(),
                DebugCoordinate::EventSequence(sequence),
            )
            .with_event_coordinate(sequence, target.configuration.clone()),
            None => DebugGotoRequest::at_configuration(
                request.current.clone(),
                target.configuration.clone(),
            ),
        };
        let goto = self.debug_goto(attach, &goto_request)?;
        Ok(DebugReverseStepReport {
            grain: request.grain,
            target_event_sequence: target.event_sequence,
            target_configuration: target.configuration.id(),
            goto,
        })
    }

    /// Scans backward to the latest event-log coordinate where `condition` holds.
    ///
    /// Named and guest-marker leaves are false by default; callers that need a
    /// host-side leaf resolver should use
    /// [`Self::debug_reverse_continue_with_leaf_oracle`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when a checked condition prefix cannot be built,
    /// a matching event-log coordinate lacks a configuration mapping, or the
    /// delegated `goto` fails.
    pub fn debug_reverse_continue(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugReverseContinueRequest,
    ) -> Result<DebugReverseContinueReport, EngineError> {
        self.debug_reverse_continue_with_leaf_oracle(attach, request, |_entry, _leaf| false)
    }

    /// Scans backward with a caller-supplied host-side leaf resolver.
    ///
    /// The scan evaluates each candidate through [`ConditionEvaluationPass`]
    /// over a checked event-log prefix, picks the latest matching coordinate at
    /// or before the current event limit, and realizes it through
    /// [`Self::debug_goto`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when a checked condition prefix cannot be built,
    /// a matching event-log coordinate lacks a configuration mapping, or the
    /// delegated `goto` fails.
    pub fn debug_reverse_continue_with_leaf_oracle<F>(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugReverseContinueRequest,
        mut leaf_oracle: F,
    ) -> Result<DebugReverseContinueReport, EngineError>
    where
        F: for<'leaf> FnMut(&SchedulerEventLogEntry, ConditionLeaf<'leaf>) -> bool,
    {
        for index in (0..request.event_log.len()).rev() {
            let entry = &request.event_log[index];
            if entry.sequence() > request.current_event_sequence_limit() {
                continue;
            }
            let prefix_entries = request.event_log[..=index].to_vec();
            let prefix = crate::trigger::ConditionEventLogPrefix::from_scheduler_event_log_entries(
                prefix_entries,
            )
            .map_err(|error| EngineError::DebugReverseContinueInvalidPrefix {
                sequence: entry.sequence(),
                reason: format!("{error:?}"),
            })?;
            let oracle = DebugReverseContinueLeafOracle {
                entry,
                leaf_oracle: &mut leaf_oracle,
            };
            let mut pass = ConditionEvaluationPass::from_log_prefix(prefix, oracle);
            if pass.evaluate_assertion_condition(&request.condition) {
                let target = request
                    .event_coordinates
                    .get(&entry.sequence())
                    .cloned()
                    .ok_or_else(|| EngineError::DebugTimeTravelMissingEventCoordinate {
                        sequence: entry.sequence(),
                    })?;
                let goto = self.debug_goto(
                    attach,
                    &DebugGotoRequest::new(
                        request.current.clone(),
                        DebugCoordinate::EventSequence(entry.sequence()),
                    )
                    .with_event_coordinate(entry.sequence(), target.clone()),
                )?;
                return Ok(DebugReverseContinueReport {
                    condition: request.condition.clone(),
                    searched_entries: request.searched_entries_before(index),
                    matched: Some(DebugReverseContinueMatch {
                        event_sequence: entry.sequence(),
                        target_configuration: target.id(),
                        goto,
                    }),
                });
            }
        }

        Ok(DebugReverseContinueReport {
            condition: request.condition.clone(),
            searched_entries: request.event_log.len(),
            matched: None,
        })
    }

    /// Moves one debugged node to an exact node-icount coordinate.
    ///
    /// The target is resolved from checkpoint metadata on the same linear
    /// schedule family as the attached configuration. Only the requested node's
    /// material is derived from the baked source-of-truth restore and target
    /// replay suffix; all other nodes keep the attached runtime material in the
    /// returned debugger projection.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the attached configuration does not match
    /// `request.current`, the node cannot be found in the attached runtime, the
    /// target coordinate cannot be resolved exactly, the target node material
    /// cannot be derived, or the graph lacks baked genesis for the scenario.
    pub fn debug_per_node_time_travel(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugPerNodeTimeTravelRequest,
    ) -> Result<DebugPerNodeTimeTravelReport, EngineError> {
        if attach.configuration != request.current.id() {
            return Err(EngineError::DebugGotoAttachMismatch {
                attached: attach.configuration,
                requested_current: request.current.id(),
            });
        }
        let (current_node_icount, current_node_blob) = debug_runtime_node_material(
            &attach.runtime.runtime,
            &request.node,
            request.current.id(),
        )?;
        let target = self
            .debug_resolve_scoped_node_icount(&request.current, &request.node, request.icount)
            .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::node_icount(request.node.clone(), request.icount),
            })?;
        let scoped = self.debug_scoped_node_material(
            &request.current,
            &target,
            request.node.clone(),
            request.icount,
        )?;
        let mut final_node_icounts = attach.runtime.runtime.node_icounts.clone();
        final_node_icounts.insert(request.node.clone(), scoped.node_icount);
        let mut final_node_blobs = attach.runtime.runtime.node_blobs.clone();
        final_node_blobs.insert(request.node.clone(), scoped.node_blob.clone());

        Ok(DebugPerNodeTimeTravelReport {
            current_configuration: request.current.id(),
            node: request.node.clone(),
            requested_icount: request.icount,
            target_configuration: scoped.target_configuration,
            current_node_icount,
            landed_node_icount: scoped.node_icount,
            current_node_blob,
            landed_node_blob: scoped.node_blob,
            current_node_icounts: attach.runtime.runtime.node_icounts.clone(),
            final_node_icounts,
            current_node_blobs: attach.runtime.runtime.node_blobs.clone(),
            final_node_blobs,
            node_goto: scoped.goto,
        })
    }

    /// Moves the whole debugged world to a prefix coordinate.
    ///
    /// Whole-world time travel is the same operation as a fork before it
    /// diverges: resolve a prefix configuration, instantiate it through
    /// [`Self::debug_goto`], and stop without appending any decisions.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the target coordinate cannot be resolved to
    /// an ancestor/prefix of `request.current`, when the delegated `goto` fails,
    /// or when the landed runtime lacks node material.
    pub fn debug_whole_world_time_travel(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugWholeWorldTimeTravelRequest,
    ) -> Result<DebugWholeWorldTimeTravelReport, EngineError> {
        let goto_request = request.goto_request(self)?;
        let target_configuration = match &goto_request.target {
            DebugCoordinate::Configuration(configuration) => configuration.clone(),
            coordinate => self.debug_resolve_coordinate(
                &goto_request.current,
                coordinate,
                &goto_request.event_coordinates,
            )?,
        };
        if !debug_configuration_is_ancestor_or_self(&target_configuration, &request.current) {
            return Err(EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::configuration(target_configuration),
            });
        }
        let goto = self.debug_goto(attach, &goto_request)?;

        Ok(DebugWholeWorldTimeTravelReport {
            current_configuration: request.current.id(),
            target: request.target.clone(),
            target_configuration: goto.target_configuration,
            landed_node_icounts: goto.runtime.runtime.node_icounts.clone(),
            landed_node_blobs: goto.runtime.runtime.node_blobs.clone(),
            goto,
        })
    }

    /// Applies an opportunistic debug checkpoint cadence along a schedule prefix.
    ///
    /// Cadence materialization uses the ordinary advisory cache policy. The
    /// denoted configuration identities do not change when a point remains thin.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when any cadence prefix cannot be constructed,
    /// recorded, materialized, or replay-oracle checked.
    pub fn debug_apply_checkpoint_cadence(
        &mut self,
        request: &DebugCheckpointCadenceRequest,
    ) -> Result<DebugCheckpointCadenceReport, EngineError> {
        let cached_snapshots_before = self.cached_snapshot_count();
        let mut candidate_configurations = Vec::new();
        let mut fat_checkpoints = Vec::new();
        let mut thin_checkpoints = Vec::new();

        for prefix_len in 1..=request.current.schedule.len() {
            if !request.stride.includes_prefix(prefix_len) {
                continue;
            }
            let candidate = debug_configuration_prefix(&request.current, prefix_len)?;
            let checkpoint = self.materialize_hot_checkpoint(
                &candidate,
                request.policy,
                MaterializationTrigger::InteractiveTarget,
            )?;
            candidate_configurations.push(candidate.id());
            match checkpoint.kind {
                CheckpointKind::Fat => fat_checkpoints.push(checkpoint.id),
                CheckpointKind::Thin => thin_checkpoints.push(checkpoint.id),
            }
        }

        Ok(DebugCheckpointCadenceReport {
            current_configuration: request.current.id(),
            stride: request.stride,
            policy: request.policy,
            candidate_configurations,
            fat_checkpoints,
            thin_checkpoints,
            cached_snapshots_before,
            cached_snapshots_after: self.cached_snapshot_count(),
        })
    }
}
