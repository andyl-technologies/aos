/// Host-side engine state machine owned by the session actor.
///
/// The engine owns the source-of-truth [`Configuration`], a rebuildable runtime
/// cache, the temporal graph used for instantiation and checkpoints, the
/// breakpoint registry, and the single [`QuantumLoop`] boundary that performs
/// virtual-time advancement.
///
/// `Engine` is a lower-level state-machine value. Once it is moved into a
/// [`SessionActor`], the actor's private field ownership prevents external
/// mutable access; live session interaction goes through the actor mailbox.
pub struct Engine<L> {
    configuration: Configuration,
    runtime: Option<RuntimeState>,
    runtime_instantiated: bool,
    state: EngineState,
    terminal_savepoint: Option<Checkpoint>,
    active_step: Option<ActiveStep>,
    graph: TemporalGraph,
    breakpoints: BreakpointSet,
    quantum_loop: L,
    frontier: VirtualTime,
    event_log_len: usize,
    quanta: u64,
    pending_control: Vec<ControlOperation>,
    pending_event_log_entries: Vec<SchedulerEventLogEntry>,
    debug_attach: Option<DebugAttachReport>,
    debug_branch_required: bool,
    next_control_sequence: u64,
    boundary_control_log: Vec<SessionControlLogEntry>,
    next_boundary_control_sequence: u64,
    next_boundary_control_batch: u64,
    scheduler_quiescence: Option<SchedulerQuiescence>,
    breakpoint_firings: Vec<BreakpointFiring>,
    next_breakpoint_firing_sequence: u64,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
}

impl<L> Engine<L> {
    /// Creates a loaded engine from a configuration, temporal graph, and quantum loop.
    #[must_use]
    pub fn new(configuration: Configuration, graph: TemporalGraph, quantum_loop: L) -> Self {
        Self {
            configuration,
            runtime: None,
            runtime_instantiated: false,
            state: EngineState::Loaded,
            terminal_savepoint: None,
            active_step: None,
            graph,
            breakpoints: BreakpointSet::new(),
            quantum_loop,
            frontier: VirtualTime::default(),
            event_log_len: 0,
            quanta: 0,
            pending_control: Vec::new(),
            pending_event_log_entries: Vec::new(),
            debug_attach: None,
            debug_branch_required: false,
            next_control_sequence: 0,
            boundary_control_log: Vec::new(),
            next_boundary_control_sequence: 0,
            next_boundary_control_batch: 0,
            scheduler_quiescence: None,
            breakpoint_firings: Vec::new(),
            next_breakpoint_firing_sequence: 0,
            white_box_policies: BTreeMap::new(),
        }
    }

    /// Adds authoritative white-box opt-in policies for guest-marker breakpoints.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .vm_nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    fn from_realized_checkpoint(
        configuration: Configuration,
        graph: TemporalGraph,
        quantum_loop: L,
        runtime: RuntimeState,
        checkpoint: &Checkpoint,
    ) -> Self {
        Self {
            configuration,
            runtime: Some(runtime.clone()),
            runtime_instantiated: true,
            state: EngineState::Paused {
                reason: PauseReason::Instantiated,
            },
            terminal_savepoint: None,
            active_step: None,
            graph,
            breakpoints: BreakpointSet::new(),
            quantum_loop,
            frontier: checkpoint.virtual_time,
            event_log_len: u64_to_usize(runtime.event_log.events),
            quanta: 0,
            pending_control: Vec::new(),
            pending_event_log_entries: Vec::new(),
            debug_attach: None,
            debug_branch_required: false,
            next_control_sequence: 0,
            boundary_control_log: Vec::new(),
            next_boundary_control_sequence: 0,
            next_boundary_control_batch: 0,
            scheduler_quiescence: None,
            breakpoint_firings: Vec::new(),
            next_breakpoint_firing_sequence: 0,
            white_box_policies: BTreeMap::new(),
        }
    }

    /// Returns the current engine state.
    #[must_use]
    pub fn state(&self) -> &EngineState {
        &self.state
    }

    /// Returns the source-of-truth configuration.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the cached runtime, if instantiated.
    #[must_use]
    pub fn runtime(&self) -> Option<&RuntimeState> {
        self.runtime.as_ref()
    }

    /// Returns the actor-owned breakpoint registry.
    #[must_use]
    pub fn breakpoints(&self) -> &BreakpointSet {
        &self.breakpoints
    }

    /// Returns the current scheduler frontier.
    #[must_use]
    pub fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns the canonical event-log length observed so far.
    #[must_use]
    pub fn event_log_len(&self) -> usize {
        self.event_log_len
    }

    /// Returns the deterministic boundary-control log.
    #[must_use]
    pub fn boundary_control_log(&self) -> &[SessionControlLogEntry] {
        &self.boundary_control_log
    }

    /// Captures a replay artifact for deterministic session control operations.
    ///
    /// The caller supplies the initial configuration because sessions may start
    /// from genesis, a resumed checkpoint, or a forked prefix. The captured
    /// artifact is sufficient to replay the recorded scheduler-control payloads
    /// at their original virtual-time/quanta boundaries with a fresh
    /// [`QuantumLoop`].
    #[must_use]
    pub fn control_replay_artifact(
        &self,
        initial_configuration: Configuration,
    ) -> SessionControlReplayArtifact {
        SessionControlReplayArtifact {
            initial_configuration,
            final_snapshot: self.snapshot(),
            control_log: self.boundary_control_log.clone(),
        }
    }

    /// Returns the deterministic breakpoint-firing log.
    #[must_use]
    pub fn breakpoint_firings(&self) -> &[BreakpointFiring] {
        &self.breakpoint_firings
    }

    /// Returns the active debug attach, if one is open.
    #[must_use]
    pub fn debug_attach(&self) -> Option<&DebugAttachReport> {
        self.debug_attach.as_ref()
    }

    /// Returns whether forward or mutating use must first mark a debug branch.
    #[must_use]
    pub const fn debug_branch_required(&self) -> bool {
        self.debug_branch_required
    }

    /// Returns the number of scheduler quanta driven by this engine.
    #[must_use]
    pub fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Creates an independent child session from `base` plus divergent decisions.
    ///
    /// The fork is recorded through [`TemporalGraph::fork`], which realizes
    /// `base` via `instantiate`, appends the supplied [`Decision`] values with
    /// the execution-model step operation, and records the branch as a thin
    /// checkpoint. The returned child is a normal paused [`SessionActor`] with
    /// its own mailbox and live snapshot; continuing it advances from the
    /// branch checkpoint through the same path as resume.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when called while the parent
    /// is loaded or running. A running parent must first pause at a quantum
    /// boundary. Returns [`SessionError::Engine`] when the temporal graph cannot
    /// realize `base` or record the fork branch.
    pub fn fork_child<C, I>(
        &mut self,
        base: &Configuration,
        decisions: I,
        child_quantum_loop: C,
    ) -> Result<SessionFork<C>, SessionError>
    where
        I: IntoIterator<Item = Decision>,
    {
        let parent_state = self.state.clone();
        if !matches!(
            parent_state,
            EngineState::Paused { .. } | EngineState::Stopped { .. }
        ) {
            return Err(SessionError::InvalidEngineState {
                state: parent_state,
                operation: "fork_child",
            });
        }

        let fork = self.graph.fork(base, decisions)?;
        let branch_configuration = fork.branch.clone();
        let branch_checkpoint = fork.branch_checkpoint.clone();
        let runtime = self.graph.resume_checkpoint(branch_checkpoint.id)?.runtime;
        let child_graph = self.graph.clone();
        let record = SessionForkRecord {
            from_checkpoint: fork.base.checkpoint,
            branch_checkpoint: branch_checkpoint.id,
            schedule_delta: branch_checkpoint.schedule_delta.clone(),
        };
        let child_engine = Engine::from_realized_checkpoint(
            branch_configuration.clone(),
            child_graph,
            child_quantum_loop,
            runtime,
            &branch_checkpoint,
        )
        .with_white_box_policies(self.white_box_policies.clone());
        let (child_sender, receiver) = mpsc::channel(SESSION_FORK_MAILBOX_CAPACITY);
        let child_actor = SessionActor::new(child_engine, receiver);

        Ok(SessionFork {
            parent_state,
            base_configuration: fork.base.configuration,
            branch_configuration,
            branch_checkpoint,
            record,
            child_sender,
            child_actor,
        })
    }

    /// Resumes an independent session actor from a recorded graph checkpoint.
    ///
    /// The checkpoint is resolved to its recorded [`Configuration`] and realized
    /// through [`TemporalGraph::resume_checkpoint`]. The returned actor is a
    /// normal paused session with its own mailbox and live mirror; continuing it
    /// advances from the resumed configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Engine`] when the checkpoint or its configuration
    /// is not recorded, or when temporal-graph resume cannot instantiate it.
    pub fn resume_session_from_checkpoint<C>(
        &mut self,
        checkpoint: ContentHash,
        session_quantum_loop: C,
    ) -> Result<SessionResume<C>, SessionError> {
        let checkpoint_record =
            self.graph
                .checkpoint_record(checkpoint)
                .cloned()
                .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                    checkpoint,
                }))?;
        let configuration = self
            .graph
            .checkpoint_configuration(checkpoint)
            .cloned()
            .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                checkpoint,
            }))?;
        let resumed = self.graph.resume_checkpoint(checkpoint)?;
        let runtime = resumed.runtime;
        let session_graph = self.graph.clone();
        let session_engine = Engine::from_realized_checkpoint(
            configuration.clone(),
            session_graph,
            session_quantum_loop,
            runtime.clone(),
            &checkpoint_record,
        )
        .with_white_box_policies(self.white_box_policies.clone());
        let (session_sender, receiver) = mpsc::channel(SESSION_FORK_MAILBOX_CAPACITY);
        let session_actor = SessionActor::new(session_engine, receiver);

        Ok(SessionResume {
            checkpoint: resumed.checkpoint,
            configuration,
            runtime,
            session_sender,
            session_actor,
        })
    }

    /// Forks an independent child actor from a recorded checkpoint prefix.
    ///
    /// The parent must already be at a forkable boundary. `from` is resolved to a
    /// checkpoint-backed prefix, then recorded through [`TemporalGraph::fork`]
    /// with an empty decision delta. The returned child actor is independently
    /// paused at [`PauseReason::Instantiated`] and can diverge through subsequent
    /// scheduler decisions without mutating the parent.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when called while the parent
    /// is loaded or running. A running parent must first pause at a quantum
    /// boundary. Returns [`SessionError::Engine`] when the checkpoint cannot be
    /// resolved or the graph cannot instantiate the prefix.
    pub fn fork_child_from_checkpoint<C>(
        &mut self,
        from: CheckpointRef,
        child_quantum_loop: C,
    ) -> Result<SessionFork<C>, SessionError> {
        let parent_state = self.state.clone();
        if !matches!(
            parent_state,
            EngineState::Paused { .. } | EngineState::Stopped { .. }
        ) {
            return Err(SessionError::InvalidEngineState {
                state: parent_state,
                operation: "fork_child_from_checkpoint",
            });
        }

        let checkpoint = self.resolve_fork_checkpoint(from)?;
        self.build_checkpoint_child(parent_state, checkpoint.id, child_quantum_loop)
    }

    fn build_checkpoint_child<C>(
        &mut self,
        parent_state: EngineState,
        checkpoint: ContentHash,
        child_quantum_loop: C,
    ) -> Result<SessionFork<C>, SessionError> {
        let base = self
            .graph
            .checkpoint_configuration(checkpoint)
            .cloned()
            .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                checkpoint,
            }))?;
        let fork = self.graph.fork(&base, std::iter::empty::<Decision>())?;
        let child_graph = self.graph.clone();
        let branch_configuration = fork.branch.clone();
        let branch_checkpoint = fork.branch_checkpoint.clone();
        let runtime = fork.base.runtime;
        let record = SessionForkRecord {
            from_checkpoint: fork.base.checkpoint,
            branch_checkpoint: branch_checkpoint.id,
            schedule_delta: Schedule::empty(),
        };
        let child_engine = Engine::from_realized_checkpoint(
            branch_configuration.clone(),
            child_graph,
            child_quantum_loop,
            runtime,
            &branch_checkpoint,
        )
        .with_white_box_policies(self.white_box_policies.clone());
        let (child_sender, receiver) = mpsc::channel(SESSION_FORK_MAILBOX_CAPACITY);
        let child_actor = SessionActor::new(child_engine, receiver);

        Ok(SessionFork {
            parent_state,
            base_configuration: fork.base.configuration,
            branch_configuration,
            branch_checkpoint,
            record,
            child_sender,
            child_actor,
        })
    }

    /// Returns a boundary snapshot of the engine state.
    #[must_use]
    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            state: self.state.clone(),
            configuration: self.configuration.clone(),
            terminal_savepoint: self.terminal_savepoint.clone(),
            frontier: self.frontier,
            event_log_len: self.event_log_len,
            quanta: self.quanta,
        }
    }

    /// Consumes the engine and returns the wrapped quantum loop.
    #[must_use]
    pub fn into_quantum_loop(self) -> L {
        self.quantum_loop
    }

    fn invalid_transition(&self, command: SessionCommand) -> SessionError {
        SessionError::InvalidTransition {
            state: Box::new(self.state.clone()),
            command: Box::new(command),
        }
    }

    fn invalid_engine_state(&self, operation: &'static str) -> SessionError {
        SessionError::InvalidEngineState {
            state: self.state.clone(),
            operation,
        }
    }

    fn current_debug_attach(
        &self,
        operation: &'static str,
    ) -> Result<DebugAttachReport, SessionError> {
        self.debug_attach
            .clone()
            .ok_or(SessionError::DebugAttachRequired { operation })
    }

    fn reject_debug_forward_without_branch(
        &self,
        command: &SessionCommand,
    ) -> Result<(), SessionError> {
        if self.debug_branch_required && command.requires_non_canonical_debug_branch() {
            return Err(SessionError::DebugNonCanonicalBranchRequired {
                operation: SessionCommandKind::from(command).operation_name(),
            });
        }
        Ok(())
    }

    fn update_debug_position(
        &mut self,
        previous_attach: &DebugAttachReport,
        goto: &DebugGotoReport,
    ) -> Result<DebugAttachReport, SessionError> {
        let configuration = self
            .graph
            .checkpoint_configuration(goto.target_configuration)
            .or_else(|| self.graph.checkpoint_configuration(goto.target_checkpoint))
            .cloned()
            .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                checkpoint: goto.target_configuration,
            }))?;
        let frontier = self
            .graph
            .checkpoint_record(goto.target_configuration)
            .or_else(|| self.graph.checkpoint_record(goto.target_checkpoint))
            .map_or_else(
                || {
                    let ticks = goto
                        .runtime
                        .runtime
                        .node_icounts
                        .values()
                        .map(|icount| icount.retired)
                        .min()
                        .unwrap_or_default();
                    VirtualTime { ticks }
                },
                |checkpoint| checkpoint.virtual_time,
            );
        self.configuration = configuration.clone();
        self.runtime = Some(goto.runtime.runtime.clone());
        self.runtime_instantiated = true;
        self.frontier = frontier;
        self.event_log_len = u64_to_usize(goto.runtime.runtime.event_log.events);
        self.active_step = None;
        if matches!(self.state, EngineState::Running) {
            self.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }
        self.debug_branch_required = true;
        let request = DebugAttachRequest {
            configuration,
            node: previous_attach.gdbstub.node.clone(),
            qemu_gdbstub: previous_attach.gdbstub.qemu_endpoint.clone(),
            gdb_listen: previous_attach.gdbstub.operator_listen.clone(),
        };
        let refreshed = self.graph.debug_attach(&request)?;
        self.debug_attach = Some(refreshed.clone());
        Ok(refreshed)
    }

    fn admit_control_operation(&mut self, kind: ControlOperationKind) {
        self.next_control_sequence = self.next_control_sequence.saturating_add(1);
        self.pending_control.push(ControlOperation {
            sequence: self.next_control_sequence,
            kind,
        });
    }

    fn apply_control_operation_at_boundary(
        &mut self,
        kind: ControlOperationKind,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        self.apply_control_operations_at_boundary(vec![kind])
    }

    fn apply_control_operations_at_boundary(
        &mut self,
        kinds: Vec<ControlOperationKind>,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if kinds.is_empty() {
            return Ok(());
        }
        let mut control = Vec::with_capacity(kinds.len());
        for kind in kinds {
            self.next_control_sequence = self.next_control_sequence.saturating_add(1);
            control.push(ControlOperation {
                sequence: self.next_control_sequence,
                kind,
            });
        }
        let entries = self.quantum_loop.apply_control_at_boundary(control)?;
        self.append_boundary_event_log_entries(entries)
    }

    fn append_boundary_event_log_entries(
        &mut self,
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<(), SessionError> {
        let current_event_log_len = usize_to_u64(self.event_log_len);
        let emitted_event_log_entries = usize_to_u64(entries.len());
        let expected_event_log_len = current_event_log_len
            .checked_add(emitted_event_log_entries)
            .ok_or(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: emitted_event_log_entries,
                next: current_event_log_len,
            })?;
        for (index, entry) in entries.iter().enumerate() {
            let expected_sequence = current_event_log_len.saturating_add(usize_to_u64(index));
            if entry.sequence() != expected_sequence {
                return Err(SessionError::EventLogOffsetMismatch {
                    current: current_event_log_len,
                    emitted: emitted_event_log_entries,
                    next: entry.sequence(),
                });
            }
        }
        self.event_log_len = u64_to_usize(expected_event_log_len);
        self.pending_event_log_entries.extend(entries);
        Ok(())
    }

    fn shutdown_quantum_loop(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        let entries = self.quantum_loop.shutdown()?;
        self.append_boundary_event_log_entries(entries)
    }

    fn validate_event_log_prefix(
        &self,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionError> {
        let current_event_log_len = usize_to_u64(self.event_log_len);
        if event_log.len() != self.event_log_len {
            return Err(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: 0,
                next: usize_to_u64(event_log.len()),
            });
        }
        for (index, entry) in event_log.iter().enumerate() {
            let expected_sequence = usize_to_u64(index);
            if entry.sequence() != expected_sequence {
                return Err(SessionError::EventLogOffsetMismatch {
                    current: current_event_log_len,
                    emitted: 0,
                    next: entry.sequence(),
                });
            }
        }
        Ok(())
    }

    fn record_boundary_control(
        &mut self,
        command: &SessionCommand,
        scheduler_control: Option<ControlOperationKind>,
    ) {
        let event_log_sequence_before = usize_to_u64(self.event_log_len());
        self.record_boundary_control_at(command, scheduler_control, event_log_sequence_before);
    }

    fn record_boundary_control_at(
        &mut self,
        command: &SessionCommand,
        scheduler_control: Option<ControlOperationKind>,
        event_log_sequence_before: u64,
    ) {
        let payload = SessionControlPayload::from(command);
        let scheduler_batch = if scheduler_control.is_some() {
            self.next_boundary_control_batch()
        } else {
            0
        };
        self.record_boundary_control_kind_payload_in_batch(
            SessionCommandKind::from(command),
            payload,
            scheduler_control,
            scheduler_batch,
            event_log_sequence_before,
        );
    }

    fn record_boundary_control_kind_in_batch(
        &mut self,
        command: SessionCommandKind,
        scheduler_control: Option<ControlOperationKind>,
        scheduler_batch: u64,
        event_log_sequence_before: u64,
    ) {
        let payload =
            SessionControlPayload::from_control_or_kind(command, scheduler_control.as_ref());
        self.record_boundary_control_kind_payload_in_batch(
            command,
            payload,
            scheduler_control,
            scheduler_batch,
            event_log_sequence_before,
        );
    }

    fn record_boundary_control_kind_payload_in_batch(
        &mut self,
        command: SessionCommandKind,
        payload: SessionControlPayload,
        scheduler_control: Option<ControlOperationKind>,
        scheduler_batch: u64,
        event_log_sequence_before: u64,
    ) {
        self.next_boundary_control_sequence = self.next_boundary_control_sequence.saturating_add(1);
        self.boundary_control_log.push(SessionControlLogEntry {
            sequence: self.next_boundary_control_sequence,
            command,
            payload,
            frontier: self.frontier,
            quanta: self.quanta,
            event_log_sequence_before,
            result: SessionControlResult::Accepted,
            scheduler_batch,
            scheduler_control,
        });
    }

    fn next_boundary_control_batch(&mut self) -> u64 {
        self.next_boundary_control_batch = self.next_boundary_control_batch.saturating_add(1);
        self.next_boundary_control_batch
    }

    fn evaluate_breakpoints(
        &mut self,
        event_log_entries: &[SchedulerEventLogEntry],
        emitted_event_log_entries: usize,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if self.breakpoints.is_empty() {
            return Ok(());
        }

        let Some(prefix) =
            self.breakpoint_condition_prefix(event_log_entries, emitted_event_log_entries)?
        else {
            return Ok(());
        };
        let evaluations = self
            .breakpoints
            .iter()
            .map(|(id, spec, was_true)| {
                let mut pass =
                    ConditionEvaluationPass::from_log_prefix(prefix.clone(), NoBreakpointLeaves)
                        .with_once_latches(self.breakpoints.once_latches(id))
                        .with_white_box_policies(self.white_box_policies.clone());
                if let Some(quiescence) = self.scheduler_quiescence.clone() {
                    pass = pass.with_scheduler_quiescence(quiescence);
                }
                let is_true = pass.evaluate_assertion_condition(&spec.predicate);
                (
                    id,
                    spec.clone(),
                    was_true,
                    is_true,
                    pass.once_latches().to_vec(),
                )
            })
            .collect::<Vec<_>>();

        for (id, spec, was_true, is_true, once_latches) in evaluations {
            if is_true && !was_true {
                self.fire_breakpoint(id, &spec)?;
                if matches!(spec.policy, BreakpointPolicy::OneShot) {
                    self.breakpoints.remove(id);
                } else {
                    self.breakpoints.set_once_latches(id, once_latches);
                    self.breakpoints.set_last_truth(id, true);
                }
            } else {
                self.breakpoints.set_once_latches(id, once_latches);
                self.breakpoints.set_last_truth(id, is_true);
            }
        }

        Ok(())
    }

    fn breakpoint_condition_prefix(
        &self,
        event_log_entries: &[SchedulerEventLogEntry],
        emitted_event_log_entries: usize,
    ) -> Result<Option<ConditionEventLogPrefix>, SessionError> {
        if emitted_event_log_entries == 0 {
            if self.scheduler_quiescence.is_some() {
                return ConditionEventLogPrefix::from_scheduler_event_log_entries_with_evaluation_boundary(
                    event_log_entries.to_vec(),
                    usize_to_u64(self.event_log_len),
                    self.frontier,
                    SchedulerEvaluationBoundaryKind::Quantum,
                )
                .map(Some)
                .map_err(|error| SessionError::BreakpointConditionPrefix {
                    reason: error.to_string(),
                });
            }
            return Ok(None);
        }

        ConditionEventLogPrefix::from_scheduler_event_log_entries(event_log_entries.to_vec())
            .map(Some)
            .map_err(|error| SessionError::BreakpointConditionPrefix {
                reason: error.to_string(),
            })
    }

    fn fire_breakpoint(
        &mut self,
        id: BreakpointId,
        spec: &BreakpointSpec,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        let mut scheduler_controls = Vec::new();
        match &spec.disposition {
            BreakpointDisposition::Suspend => {
                self.active_step = None;
                self.state = EngineState::Paused {
                    reason: PauseReason::Breakpoint { id },
                };
            }
            BreakpointDisposition::Trace => {}
            BreakpointDisposition::Action(action) => {
                self.apply_breakpoint_action(action, &mut scheduler_controls)?;
            }
        }

        self.next_breakpoint_firing_sequence =
            self.next_breakpoint_firing_sequence.saturating_add(1);
        self.breakpoint_firings.push(BreakpointFiring {
            sequence: self.next_breakpoint_firing_sequence,
            id,
            predicate: spec.predicate.clone(),
            disposition: spec.disposition.clone(),
            frontier: self.frontier,
            quanta: self.quanta,
            scheduler_controls,
        });
        Ok(())
    }

    fn apply_breakpoint_action(
        &mut self,
        action: &Action,
        scheduler_controls: &mut Vec<ControlOperationKind>,
    ) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        let planned_controls = Self::plan_breakpoint_action(action)?;
        let event_log_sequence_before = usize_to_u64(self.event_log_len());
        self.apply_control_operations_at_boundary(planned_controls.clone())?;
        let scheduler_batch = if planned_controls.is_empty() {
            0
        } else {
            self.next_boundary_control_batch()
        };
        for control in &planned_controls {
            if let Some(command) = control_operation_command_kind(control) {
                self.record_boundary_control_kind_in_batch(
                    command,
                    Some(control.clone()),
                    scheduler_batch,
                    event_log_sequence_before,
                );
            }
        }
        scheduler_controls.extend(planned_controls);
        Ok(())
    }

    fn plan_breakpoint_action(action: &Action) -> Result<Vec<ControlOperationKind>, SessionError> {
        let mut scheduler_controls = Vec::new();
        Self::plan_breakpoint_action_into(action, &mut scheduler_controls)?;
        Ok(scheduler_controls)
    }

    fn plan_breakpoint_action_into(
        action: &Action,
        scheduler_controls: &mut Vec<ControlOperationKind>,
    ) -> Result<(), SessionError> {
        match action {
            Action::InjectFault { tag, fault } => {
                let Some(fault) = fault.table_fault() else {
                    return Err(SessionError::UnsupportedBreakpointFault {
                        action: "inject-fault",
                        reason: "fault has no scheduler-control representation",
                    });
                };
                scheduler_controls.push(ControlOperationKind::InjectFault {
                    tag: tag.clone(),
                    fault,
                });
            }
            Action::HealFault { tag } => {
                scheduler_controls.push(ControlOperationKind::HealFault { tag: tag.clone() });
            }
            Action::Group(actions) => {
                for action in actions {
                    Self::plan_breakpoint_action_into(action, scheduler_controls)?;
                }
            }
            Action::ArmTimer { .. }
            | Action::CancelTimer { .. }
            | Action::StartNode { .. }
            | Action::StopNode { .. }
            | Action::CreateSavepoint { .. }
            | Action::Fork { .. }
            | Action::Pass
            | Action::Fail { .. }
            | Action::Log { .. } => {
                return Err(SessionError::UnsupportedBreakpointAction {
                    action: breakpoint_action_kind(action),
                });
            }
        }
        Ok(())
    }

    fn pending_control_len(&self) -> usize {
        self.pending_control.len()
    }

    fn enter_stopped(&mut self, outcome: Outcome) -> Result<(), SessionError> {
        let checkpoint = self.graph.save_checkpoint(&self.configuration)?;
        self.terminal_savepoint = Some(checkpoint);
        self.state = EngineState::Stopped { outcome };
        Ok(())
    }

    fn drain_event_log_entries(&mut self) -> Vec<SchedulerEventLogEntry> {
        std::mem::take(&mut self.pending_event_log_entries)
    }

    fn resolve_fork_checkpoint(&mut self, from: CheckpointRef) -> Result<Checkpoint, SessionError> {
        match from {
            CheckpointRef::Current => Ok(self.graph.save_checkpoint(&self.configuration)?),
            CheckpointRef::Checkpoint(checkpoint) => self
                .graph
                .checkpoint_node(checkpoint)
                .cloned()
                .ok_or(SessionError::Engine(EngineError::CheckpointNotRecorded {
                    checkpoint,
                })),
        }
    }
}

/// Error returned while constructing a live session engine from a logical World.
#[derive(Debug, Error)]
pub enum SessionWorldInstantiationError {
    /// The scheduler could not resolve or install the World runtime projection.
    #[error("cannot instantiate World-backed scheduler: {0}")]
    Scheduler(#[from] SchedulerWorldInstantiationError),
}

impl Engine<SingleScheduler> {
    /// Builds a live session engine over a production World-backed scheduler.
    ///
    /// The scheduler consumes the World's static VM/link/device projection,
    /// resolves concrete block/9p artifacts from `store`, and derives physical
    /// transport layout from `policy` only at this boundary. The engine adopts
    /// the scheduler's canonical configuration and the World's white-box policy
    /// map, so session fault commands operate on the same attached device nodes.
    ///
    /// `graph` must contain the baked genesis required by [`Engine::apply_command`]
    /// when the caller later starts the loaded engine.
    ///
    /// # Errors
    ///
    /// Returns [`SessionWorldInstantiationError`] when VM topology, artifact
    /// resolution, physical layout, or scheduler installation fails.
    pub fn from_world_scheduler(
        graph: TemporalGraph,
        scenario: SchedulerLivenessScenario,
        world: &World,
        store: &dyn DagStore,
        policy: WorldIoLayoutPolicy,
    ) -> Result<Self, SessionWorldInstantiationError> {
        let scheduler = SingleScheduler::from_world(scenario, world, store, policy)?;
        let configuration = scheduler.configuration().clone();
        Ok(Self::new(configuration, graph, scheduler).with_world_white_box_policies(world))
    }
}

impl<L: QuantumLoop> Engine<L> {
    /// Instantiates the engine runtime from its source-of-truth configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when the engine is not
    /// loaded. Returns [`SessionError::Engine`] when the execution model cannot
    /// instantiate the current configuration from the temporal graph.
    pub fn instantiate_runtime(&mut self) -> Result<EngineSnapshot, SessionError> {
        if !matches!(self.state, EngineState::Loaded) {
            return Err(self.invalid_engine_state("instantiate_runtime"));
        }

        let runtime = self.graph.resume(&self.configuration)?.runtime;
        self.runtime = Some(runtime);
        self.runtime_instantiated = true;
        self.state = EngineState::Paused {
            reason: PauseReason::Instantiated,
        };
        Ok(self.snapshot())
    }

    /// Drops the cached runtime while preserving the source-of-truth state.
    ///
    /// The runtime is a rebuildable cache. Evicting it must not change the
    /// engine's boundary snapshot, configuration, frontier, log length, or
    /// quantum count.
    pub fn evict_runtime_cache(&mut self) -> EngineSnapshot {
        self.runtime = None;
        self.snapshot()
    }

    /// Rebuilds the cached runtime from the source-of-truth configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when the runtime has not
    /// been initially instantiated. Returns [`SessionError::Engine`] when the
    /// execution model cannot instantiate the current configuration from the
    /// temporal graph.
    pub fn reinstantiate_runtime_cache(&mut self) -> Result<EngineSnapshot, SessionError> {
        if !self.runtime_instantiated {
            return Err(self.invalid_engine_state("reinstantiate_runtime_cache"));
        }

        let runtime = self.graph.resume(&self.configuration)?.runtime;
        self.runtime = Some(runtime);
        Ok(self.snapshot())
    }

    /// Drops and rebuilds the cached runtime at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] when the runtime has not
    /// been initially instantiated. Returns [`SessionError::Engine`] when the
    /// execution model cannot instantiate the current configuration from the
    /// temporal graph.
    pub fn refresh_runtime_cache(&mut self) -> Result<EngineSnapshot, SessionError> {
        if !self.runtime_instantiated {
            return Err(self.invalid_engine_state("refresh_runtime_cache"));
        }

        let runtime = self.graph.resume(&self.configuration)?.runtime;
        self.runtime = None;
        self.runtime = Some(runtime);
        Ok(self.snapshot())
    }

    /// Replays deterministic scheduler-control payloads from `artifact`.
    ///
    /// The supplied temporal graph and quantum loop must represent the same
    /// deterministic model used to produce the artifact. Replay starts from the
    /// artifact's initial configuration, applies every recorded scheduler-owned
    /// control payload at its recorded quanta/frontier boundary, and advances to
    /// the final recorded quantum boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the initial configuration
    /// cannot be started, [`SessionError::Scheduler`] or [`SessionError::Engine`]
    /// if the replay loop cannot advance, or a control-replay mismatch error if
    /// the artifact records a control entry for a boundary not reached by replay.
    pub fn replay_control_replay_artifact(
        artifact: &SessionControlReplayArtifact,
        graph: TemporalGraph,
        quantum_loop: L,
    ) -> Result<EngineSnapshot, SessionError> {
        let mut engine = Self::new(artifact.initial_configuration.clone(), graph, quantum_loop);
        engine.apply_command(SessionCommand::Start)?;
        engine.apply_command(SessionCommand::Continue)?;

        let mut log_index = 0;
        while engine.quanta < artifact.final_snapshot.quanta {
            engine.replay_controls_at_current_boundary(artifact, &mut log_index)?;
            let _ = engine.step_quantum()?;
        }
        engine.replay_controls_at_current_boundary(artifact, &mut log_index)?;
        if let Some(entry) = artifact.control_log.get(log_index) {
            return Err(SessionError::ControlReplayBoundaryMismatch {
                current_quanta: engine.quanta,
                recorded_quanta: entry.quanta,
            });
        }
        let replayed = engine.snapshot();
        if replayed != artifact.final_snapshot {
            return Err(SessionError::ControlReplayFinalSnapshotMismatch {
                expected: Box::new(artifact.final_snapshot.clone()),
                actual: Box::new(replayed),
            });
        }
        Ok(replayed)
    }

    fn replay_controls_at_current_boundary(
        &mut self,
        artifact: &SessionControlReplayArtifact,
        log_index: &mut usize,
    ) -> Result<(), SessionError> {
        while let Some(entry) = artifact.control_log.get(*log_index) {
            if entry.quanta < self.quanta {
                return Err(SessionError::ControlReplayBoundaryMismatch {
                    current_quanta: self.quanta,
                    recorded_quanta: entry.quanta,
                });
            }
            if entry.quanta != self.quanta {
                return Ok(());
            }
            if entry.frontier != self.frontier {
                return Err(SessionError::ControlReplayFrontierMismatch {
                    current: self.frontier,
                    recorded: entry.frontier,
                });
            }
            if entry.scheduler_control.is_none() {
                self.replay_non_scheduler_boundary_control(entry.command)?;
                *log_index += 1;
                continue;
            }

            let scheduler_batch = entry.scheduler_batch;
            if scheduler_batch == 0 {
                return Err(SessionError::ControlReplayBatchMismatch {
                    sequence: entry.sequence,
                    scheduler_batch,
                });
            }
            let mut controls = Vec::new();
            while let Some(batch_entry) = artifact.control_log.get(*log_index) {
                if batch_entry.quanta != self.quanta
                    || batch_entry.frontier != self.frontier
                    || batch_entry.scheduler_batch != scheduler_batch
                {
                    break;
                }
                let Some(control) = batch_entry.scheduler_control.clone() else {
                    return Err(SessionError::ControlReplayBatchMismatch {
                        sequence: batch_entry.sequence,
                        scheduler_batch,
                    });
                };
                controls.push(control);
                *log_index += 1;
            }
            self.apply_control_operations_at_boundary(controls)?;
        }
        Ok(())
    }

    fn replay_non_scheduler_boundary_control(
        &mut self,
        command: SessionCommandKind,
    ) -> Result<(), SessionError> {
        match command {
            SessionCommandKind::Pause | SessionCommandKind::Fork => {
                self.active_step = None;
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            SessionCommandKind::Stop => {
                self.shutdown_quantum_loop()?;
                self.pending_control.clear();
                self.active_step = None;
                self.enter_stopped(Outcome::Stopped)?;
            }
            SessionCommandKind::Start
            | SessionCommandKind::Continue
            | SessionCommandKind::StepQuantum
            | SessionCommandKind::StepEvent
            | SessionCommandKind::StepAssertion
            | SessionCommandKind::StepTimer
            | SessionCommandKind::StepDuration
            | SessionCommandKind::Inject
            | SessionCommandKind::InjectFault
            | SessionCommandKind::HealFault
            | SessionCommandKind::SetBreakpoint
            | SessionCommandKind::RemoveBreakpoint
            | SessionCommandKind::CreateSavepoint
            | SessionCommandKind::Query
            | SessionCommandKind::Snapshot
            | SessionCommandKind::AttachGdb
            | SessionCommandKind::DebugGoto
            | SessionCommandKind::DebugReverseStep
            | SessionCommandKind::DebugReverseContinue
            | SessionCommandKind::DebugForkNonCanonical => {}
        }
        Ok(())
    }

    /// Applies one actor-owned command at a state-machine boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the command is not valid
    /// in the current state. Returns [`SessionError::Engine`] or
    /// [`SessionError::Scheduler`] if the model or scheduler boundary fails.
    pub fn apply_command(&mut self, command: SessionCommand) -> Result<EngineSnapshot, SessionError>
    where
        L: QuantumLoop,
    {
        self.apply_command_with_event_log(command, &[])
    }

    /// Applies one actor-owned command with the current event-log prefix.
    ///
    /// `event_log` is used only by debugger branch-marking commands that must
    /// append visible non-canonical fork metadata to the actor-owned log.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] if the command is not valid
    /// in the current state. Returns [`SessionError::Engine`] or
    /// [`SessionError::Scheduler`] if the model or scheduler boundary fails.
    pub fn apply_command_with_event_log(
        &mut self,
        command: SessionCommand,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<EngineSnapshot, SessionError>
    where
        L: QuantumLoop,
    {
        match &command {
            SessionCommand::Acknowledge { command, reply } => {
                let result = self.apply_command_with_event_log((**command).clone(), event_log);
                match &result {
                    Ok(_) => reply.complete(Ok(())),
                    Err(error) => reply.complete(Err(error.clone())),
                }
                result
            }
            SessionCommand::Start => {
                if matches!(self.state, EngineState::Loaded) {
                    self.instantiate_runtime()
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Continue => {
                if matches!(self.state, EngineState::Paused { .. }) {
                    self.reject_debug_forward_without_branch(&command)?;
                    self.active_step = None;
                    self.state = EngineState::Running;
                    Ok(self.snapshot())
                } else {
                    Err(self.invalid_transition(command.clone()))
                }
            }
            SessionCommand::Pause => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    self.active_step = None;
                    self.state = EngineState::Paused {
                        reason: PauseReason::UserRequested,
                    };
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Step { mode } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    self.active_step = Some(ActiveStep::new(*mode, self.frontier));
                    self.state = EngineState::Running;
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Snapshot => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Snapshot);
                }
                Ok(self.snapshot())
            }
            SessionCommand::Fork { from, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } | EngineState::Stopped { .. } => {
                    let checkpoint = self.resolve_fork_checkpoint(*from)?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    let handle = SessionHandle::new(self.configuration.id(), &checkpoint);
                    reply.complete(Ok(handle));
                    Ok(self.snapshot())
                }
                EngineState::Loaded => Err(self.invalid_transition(command.clone())),
            },
            SessionCommand::Inject => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let control = ControlOperationKind::Inject;
                    let event_log_sequence_before = usize_to_u64(self.event_log_len());
                    self.apply_control_operation_at_boundary(control.clone())?;
                    self.record_boundary_control_at(
                        &command,
                        Some(control),
                        event_log_sequence_before,
                    );
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::InjectFault { spec, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let control = ControlOperationKind::InjectFault {
                        tag: spec.tag.clone(),
                        fault: spec.fault.clone(),
                    };
                    let event_log_sequence_before = usize_to_u64(self.event_log_len());
                    self.apply_control_operation_at_boundary(control.clone())?;
                    self.record_boundary_control_at(
                        &command,
                        Some(control),
                        event_log_sequence_before,
                    );
                    reply.complete(Ok(spec.tag.clone()));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::HealFault { tag, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let control = ControlOperationKind::HealFault { tag: tag.clone() };
                    let event_log_sequence_before = usize_to_u64(self.event_log_len());
                    self.apply_control_operation_at_boundary(control.clone())?;
                    self.record_boundary_control_at(
                        &command,
                        Some(control),
                        event_log_sequence_before,
                    );
                    reply.complete(Ok(()));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::SetBreakpoint { spec, reply } => match self.state {
                EngineState::Loaded | EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    let id = self.breakpoints.insert(spec.clone());
                    reply.complete(Ok(id));
                    Ok(self.snapshot())
                }
                EngineState::Stopped { .. } => Err(self.invalid_transition(command.clone())),
            },
            SessionCommand::RemoveBreakpoint { id, reply } => match self.state {
                EngineState::Loaded | EngineState::Running | EngineState::Paused { .. } => {
                    self.reject_debug_forward_without_branch(&command)?;
                    let removed = self.breakpoints.remove(*id);
                    if !removed {
                        let error = SessionError::BreakpointNotFound { id: *id };
                        reply.complete(Err(error.clone()));
                        return Err(error);
                    }
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    reply.complete(Ok(true));
                    Ok(self.snapshot())
                }
                EngineState::Stopped { .. } => Err(self.invalid_transition(command.clone())),
            },
            SessionCommand::CreateSavepoint { label, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let checkpoint = self.graph.save_checkpoint(&self.configuration)?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    reply.complete(Ok(SavepointInfo {
                        label: label.clone(),
                        configuration: self.configuration.id(),
                        checkpoint,
                    }));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::Stop => {
                if matches!(self.state, EngineState::Stopped { .. }) {
                    Err(self.invalid_transition(command.clone()))
                } else {
                    self.shutdown_quantum_loop()?;
                    if matches!(self.state, EngineState::Running) {
                        self.record_boundary_control(&command, None);
                    }
                    self.pending_control.clear();
                    self.active_step = None;
                    self.debug_branch_required = false;
                    self.enter_stopped(Outcome::Stopped)?;
                    Ok(self.snapshot())
                }
            }
            SessionCommand::Query { kind, reply } => {
                if matches!(self.state, EngineState::Running) {
                    self.admit_control_operation(ControlOperationKind::Query);
                }
                let snapshot = self.snapshot();
                let result = match kind {
                    QueryKind::Snapshot => QueryResult::Snapshot(Box::new(snapshot.clone())),
                    QueryKind::BreakpointFirings => {
                        QueryResult::BreakpointFirings(self.breakpoint_firings.clone())
                    }
                    QueryKind::State => {
                        QueryResult::State(LifecycleStateKind::from(&snapshot.state))
                    }
                    QueryKind::EventLogLength => {
                        QueryResult::EventLogLength(snapshot.event_log_len)
                    }
                    QueryKind::ExecutionFingerprint { node } => QueryResult::ExecutionFingerprint(
                        self.quantum_loop.sample_fingerprint(node.clone())?,
                    ),
                };
                reply.complete(Ok(result));
                Ok(snapshot)
            }
            SessionCommand::AttachGdb {
                node,
                listen,
                reply,
            } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let info = self
                        .quantum_loop
                        .open_gdbstub(node.clone(), listen.clone())?;
                    let qemu_endpoint = info.qemu_endpoint.clone();
                    let operator_listen = info.operator_listen.as_str().to_owned();
                    let request = DebugAttachRequest::new(
                        self.configuration.clone(),
                        info.node,
                        qemu_endpoint,
                        operator_listen,
                    )?;
                    let attach = self.graph.debug_attach(&request)?;
                    self.debug_attach = Some(attach.clone());
                    if matches!(self.state, EngineState::Running) {
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    reply.complete(Ok(attach));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugGoto { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let attach = self.current_debug_attach("debug-goto")?;
                    let report = self.graph.debug_goto(&attach, request)?;
                    let _refreshed = self.update_debug_position(&attach, &report)?;
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugReverseStep { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let attach = self.current_debug_attach("debug-reverse-step")?;
                    let report = self.graph.debug_reverse_step(&attach, request)?;
                    let _refreshed = self.update_debug_position(&attach, &report.goto)?;
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugReverseContinue { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    let attach = self.current_debug_attach("debug-reverse-continue")?;
                    let report = self.graph.debug_reverse_continue(&attach, request)?;
                    if let Some(matched) = report.matched.as_ref() {
                        let _refreshed = self.update_debug_position(&attach, &matched.goto)?;
                    } else if matches!(self.state, EngineState::Running) {
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
            SessionCommand::DebugForkNonCanonical { request, reply } => match self.state {
                EngineState::Running | EngineState::Paused { .. } => {
                    self.validate_event_log_prefix(event_log)?;
                    let attach = self.current_debug_attach("debug-fork-non-canonical")?;
                    let report = self
                        .graph
                        .debug_non_canonical_branch(&attach, request, event_log)?;
                    let entries = report
                        .event_log_with_fork_marker
                        .iter()
                        .skip(event_log.len())
                        .cloned()
                        .collect::<Vec<_>>();
                    self.append_boundary_event_log_entries(entries)?;
                    self.debug_branch_required = false;
                    if matches!(self.state, EngineState::Running) {
                        self.active_step = None;
                        self.state = EngineState::Paused {
                            reason: PauseReason::UserRequested,
                        };
                    }
                    reply.complete(Ok(report));
                    Ok(self.snapshot())
                }
                EngineState::Loaded | EngineState::Stopped { .. } => {
                    Err(self.invalid_transition(command.clone()))
                }
            },
        }
    }

    /// Advances exactly one bounded scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidEngineState`] if the engine is not
    /// running. Returns [`SessionError::Scheduler`] if the quantum loop rejects
    /// the boundary request. Returns [`SessionError::EventLogOffsetRegression`]
    /// or [`SessionError::EventLogOffsetMismatch`] if the scheduler's emitted
    /// entries do not match its returned event-log offset. Returns
    /// [`SessionError::Engine`] if the resulting configuration cannot be
    /// re-instantiated.
    pub fn step_quantum(&mut self) -> Result<QuantumOutcome, SessionError> {
        if !matches!(self.state, EngineState::Running) {
            return Err(self.invalid_engine_state("step_quantum"));
        }

        let outcome = self.quantum_loop.drive_quantum(QuantumRequest {
            configuration: self.configuration.clone(),
            control: std::mem::take(&mut self.pending_control),
        })?;
        let current_event_log_len = usize_to_u64(self.event_log_len);
        let emitted_event_log_entries = usize_to_u64(outcome.event_log_entries.len());
        let expected_event_log_len = current_event_log_len
            .checked_add(emitted_event_log_entries)
            .ok_or(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: emitted_event_log_entries,
                next: outcome.event_log_offset.events,
            })?;
        if outcome.event_log_offset.events < current_event_log_len {
            return Err(SessionError::EventLogOffsetRegression {
                current: current_event_log_len,
                next: outcome.event_log_offset.events,
            });
        }
        if outcome.event_log_offset.events != expected_event_log_len {
            return Err(SessionError::EventLogOffsetMismatch {
                current: current_event_log_len,
                emitted: emitted_event_log_entries,
                next: outcome.event_log_offset.events,
            });
        }
        let step_completion = if let Some(step) = self.active_step.as_ref() {
            Some((
                step.mode,
                step.is_complete(&outcome, current_event_log_len)
                    .map_err(|error| SessionError::BreakpointConditionPrefix {
                        reason: error.to_string(),
                    })?,
            ))
        } else {
            None
        };
        let runtime = self.graph.resume(&outcome.configuration)?.runtime;

        self.configuration = outcome.configuration.clone();
        self.runtime = Some(runtime);
        self.runtime_instantiated = true;
        self.frontier = outcome.frontier;
        self.event_log_len = u64_to_usize(outcome.event_log_offset.events);
        self.scheduler_quiescence = outcome.scheduler_quiescence.clone();
        self.quanta = self.quanta.saturating_add(1);
        self.pending_event_log_entries
            .extend(outcome.event_log_entries.iter().cloned());
        if let Some((mode, true)) = step_completion {
            self.state = EngineState::Paused {
                reason: PauseReason::StepComplete { mode },
            };
            self.active_step = None;
        }

        Ok(outcome)
    }

    fn stop_on_continuous_quiescence(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, EngineState::Running)
            && self.active_step.is_none()
            && self.breakpoints.is_empty()
            && self
                .scheduler_quiescence
                .as_ref()
                .is_some_and(SchedulerQuiescence::is_quiescent)
        {
            self.shutdown_quantum_loop()?;
            self.pending_control.clear();
            self.enter_stopped(Outcome::Passed)?;
        }
        Ok(())
    }
}
