//! Owns a distinct source-authenticated exact input collection route.
//!
//! Legacy no-input and quantized constructors retain their original guards.
//! This route binds the original host scheduler attachment and consumes the same
//! native Stage/ACK/Commit before admitting a full semantic position.

use crucible_node_format::{Id, Position};

use super::*;

impl ConformanceRuntime {
    /// Creates an exact input collection owner with its original host scheduling source.
    ///
    /// Every input-bearing node must select Exact. The independently installed
    /// source authority defaults to refusal, and the actual source-created host
    /// node must attach to this runtime's original uninitialized scheduler slot.
    ///
    /// # Errors
    /// Retains supplied originals on foreign source/plan, unsupported input mode,
    /// absent actual host node, unavailable custody or failed attachment.
    pub fn from_prepared_exact_inputs(
        graph: ConformanceGraph,
        mut prepared: PreparedRealization,
        source: Rc<super::super::HostSchedulingSource>,
    ) -> Result<Self, ConformanceRuntimeFailure> {
        let checked: Result<(), EvidenceError> = (|| {
            graph.authenticate_exact_input_scope(&source)?;
            if prepared.nodes.iter().any(|node| {
                !node
                    .collection_scope()
                    .is_some_and(|scope| scope.same_original(graph.plan()))
            }) {
                return Err(EvidenceError {
                    message: "exact input collection requires every original owner under one plan"
                        .into(),
                });
            }
            if graph.graph.node_ids().any(|node| {
                graph.graph.descriptor(node).is_some_and(|descriptor| {
                    descriptor.ports.iter().any(|port| {
                        port.lanes
                            .iter()
                            .any(|lane| lane.direction == Direction::Input)
                    }) && graph.graph.binding(node).is_none_or(|binding| {
                        binding.compatibility.operating_contract.mode != OperatingMode::Exact
                    })
                })
            }) {
                return Err(EvidenceError {
                    message: "exact input collection refuses incompatible ingress mode".into(),
                });
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(ConformanceRuntimeFailure::retained(error.message, prepared));
        }
        let Some(slot) = prepared.custody_slot.take() else {
            return Err(ConformanceRuntimeFailure::retained(
                "original exact collection custody is unavailable",
                prepared,
            ));
        };
        let nodes = std::mem::take(&mut prepared.nodes);
        let graph = Rc::new(graph);
        let mut runtime = NodeRuntime::new_for_purpose(
            &graph.graph,
            nodes,
            prepared.activation.clone(),
            prepared.limits,
            slot,
            Some(Rc::clone(&graph)),
        )
        .map_err(|failure| ConformanceRuntimeFailure {
            reason: crate::node_admission::original_runtime_construction_failure_reason(
                &failure.error,
            ),
            _retained: None,
            _preparation: Some(failure),
            _runtime: None,
        })?;
        if let Err(error) = runtime.attach_host_scheduling_owner(&source) {
            // Retain this same complete runtime in the refusal. Its original
            // custody can only transfer through the already retained supervisor.
            return Err(ConformanceRuntimeFailure {
                reason: crate::node_admission::original_runtime_construction_failure_reason(&error),
                _retained: None,
                _preparation: None,
                _runtime: Some(Box::new(runtime)),
            });
        }
        Ok(Self {
            graph,
            runtime,
            activation: None,
            quantized: false,
            exact_inputs: Some(source),
            origin: CollectionOrigin::Initial,
        })
    }

    /// Creates the inactive complete-restoration runtime under its bound source.
    ///
    /// The caller retains the same opaque fresh graph with its prebirth source
    /// capsule. Every actual node must carry that graph's original collecting
    /// plan; the actual Host node retains the source-issued archive ticket. Its
    /// original scheduler allocation attaches once before native preparation.
    /// This creates neither a completed restoration context nor Arm/activation.
    ///
    /// # Errors
    /// Retains supplied owners on foreign/expired source binding, unsupported
    /// input mode, another original Host/node, unavailable custody or attachment
    /// failure. Source12 and whole-preparation issuers remain independent.
    pub fn from_prepared_complete_original_restoration(
        graph: Rc<ConformanceGraph>,
        mut prepared: PreparedRealization,
        source: Rc<super::super::HostSchedulingSource>,
        archive: &CollectingCompleteRestorationSource,
    ) -> Result<Self, ConformanceRuntimeFailure> {
        let checked: Result<(), RuntimeError> = (|| {
            let original = archive.original_source_data(&graph)?;
            source
                .authenticate_complete_archive_source(&original.inner)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            graph
                .authenticate_exact_input_scope(&source)
                .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
            if prepared.nodes.iter().any(|node| {
                !node
                    .collection_scope()
                    .is_some_and(|scope| scope.same_original(graph.plan()))
            }) || graph.graph.node_ids().any(|node| {
                graph.graph.descriptor(node).is_some_and(|descriptor| {
                    descriptor.ports.iter().any(|port| {
                        port.lanes
                            .iter()
                            .any(|lane| lane.direction == Direction::Input)
                    }) && graph.graph.binding(node).is_none_or(|binding| {
                        binding.compatibility.operating_contract.mode != OperatingMode::Exact
                    })
                })
            }) {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(ConformanceRuntimeFailure::retained(
                error.to_string(),
                prepared,
            ));
        }
        let Some(slot) = prepared.custody_slot.take() else {
            return Err(ConformanceRuntimeFailure::retained(
                "original complete restoration custody is unavailable",
                prepared,
            ));
        };
        let nodes = std::mem::take(&mut prepared.nodes);
        let mut runtime = NodeRuntime::new_for_purpose(
            &graph.graph,
            nodes,
            prepared.activation.clone(),
            prepared.limits,
            slot,
            Some(Rc::clone(&graph)),
        )
        .map_err(|failure| ConformanceRuntimeFailure {
            reason: failure.error.to_string(),
            _retained: None,
            _preparation: Some(failure),
            _runtime: None,
        })?;
        let attached = archive
            .original_source_data(&graph)
            .and_then(|archive| runtime.attach_complete_original_host_source(&source, archive));
        if let Err(error) = attached {
            return Err(ConformanceRuntimeFailure {
                reason: error.to_string(),
                _retained: None,
                _preparation: None,
                _runtime: Some(Box::new(runtime)),
            });
        }
        Ok(Self {
            graph,
            runtime,
            activation: None,
            quantized: false,
            exact_inputs: Some(source),
            origin: CollectionOrigin::CompleteRestoration,
        })
    }

    /// Stages and source-commits the actual scheduler's complete exclusive input cut.
    ///
    /// Empty cuts still require original native Stage/ACK/Commit. A lost or
    /// uncertain reply retains the same original batch and never restages it.
    ///
    /// # Errors
    /// Refuses absent exact source authority, incomplete producer closure,
    /// changed cut/bytes, reused identities, missing native credit or uncertain effects.
    pub fn stage_exact_inputs(
        &mut self,
        node: &Id,
        stage_operation: Id,
        batch: Id,
        cutoff: Position,
    ) -> Result<(), RuntimePollFailure> {
        self.current().map_err(RuntimePollFailure::Admission)?;
        let source = Rc::clone(
            self.exact_inputs
                .as_ref()
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ))?,
        );
        self.graph
            .authenticate_exact_input_scope(&source)
            .map_err(policy_failure)?;
        source
            .authenticate_current()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ForeignAuthority))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let original = self
            .runtime
            .scheduler(&self.graph.graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .prepare_input_batch(node, stage_operation, batch, cutoff)
            .map_err(scheduler_failure)?;
        let authenticated = self
            .graph
            .authenticate_exact_inputs(&original, &source)
            .map_err(policy_failure)
            .and_then(|()| self.native_current().map_err(RuntimePollFailure::Admission));
        if let Err(error) = authenticated {
            // No native effect was submitted. Keep all used-identity history.
            self.runtime
                .scheduler(
                    &self.graph.graph,
                    self.activation
                        .as_ref()
                        .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?,
                )
                .map_err(RuntimePollFailure::Admission)?
                .reconcile_input_no_effect(&original)
                .map_err(scheduler_failure)?;
            return Err(error);
        }
        let acknowledgement = self
            .runtime
            .stage_exact_inputs_with_lineage(original, &source)?;
        self.current().map_err(RuntimePollFailure::Admission)?;
        let commit = self.runtime.commit_input_acknowledgement(acknowledgement)?;
        self.current().map_err(RuntimePollFailure::Admission)?;
        self.runtime.commit_input_staging(&commit)
    }

    /// Reserves one exact grant at a full exclusive phase and microstep coordinate.
    ///
    /// Same-instant advancement uses the original qualified BoundarySettle route.
    /// Later ticks use HorizonPark without flattening the semantic limit. Actual
    /// staged native input commitment remains a separate prerequisite.
    ///
    /// # Errors
    /// Refuses foreign/stale original source, missing activation/commit, unknown
    /// producer closure, pending uncaptured input or exhausted original credit.
    pub fn begin_exact_position(
        &mut self,
        node: &Id,
        operation: Id,
        limit: Position,
    ) -> Result<BeginResult, RuntimeError> {
        self.current()?;
        let source = Rc::clone(
            self.exact_inputs
                .as_ref()
                .ok_or(RuntimeError::ForeignAuthority)?,
        );
        self.graph
            .authenticate_exact_input_scope(&source)
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let activation = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        let original = self
            .runtime
            .scheduler(&self.graph.graph, activation)?
            .admit_exact_position(node, operation, limit)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        let authenticated = self
            .graph
            .authenticate_operation(node, original.operation(), &original.request())
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))
            .and_then(|()| self.native_current());
        if let Err(error) = authenticated {
            self.runtime
                .scheduler(
                    &self.graph.graph,
                    self.activation.as_ref().ok_or(RuntimeError::NotActivated)?,
                )?
                .reconcile_no_effect(&original)
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
            return Err(error);
        }
        self.runtime.begin_admitted(original)
    }
}

fn policy_failure(error: EvidenceError) -> RuntimePollFailure {
    RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.message))
}

fn scheduler_failure(error: crate::node_scheduling::SchedulingError) -> RuntimePollFailure {
    RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.to_string()))
}
