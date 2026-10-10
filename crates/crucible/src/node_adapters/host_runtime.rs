//! Common host runtime hooks retaining native model and original input custody.

use super::*;

impl SimulationNode for HostModelNode {
    fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }
    fn binding(&self) -> &NodeBinding {
        &self.binding
    }
    fn route(&self) -> &NodeRoute {
        &self.route
    }
    fn thread_affinity(&self) -> ThreadAffinity {
        ThreadAffinity::OwnerThread(self.thread)
    }
    fn facets(&self) -> &[FacetKind] {
        &self.facets
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        Ok(NodeStatus {
            lifecycle: if self.model.is_none() {
                Lifecycle::Released
            } else if self.quarantined {
                Lifecycle::Quarantined
            } else {
                Lifecycle::Stopped
            },
            physical: PhysicalState::Suspended,
            boundary: Some(self.boundary),
        })
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if self.quarantined
            || world.boundary != self.boundary
            || world.world_binding_hash != self.world_hash
            || !self
                .route
                .owners
                .iter()
                .all(|owner| world.owners.contains(owner))
            || self.capture()?.as_slice() != self.initial.as_slice()
        {
            return Err(failure(
                "host readiness has changed state, world or original boundary",
            ));
        }
        if let Some(ingress) = &mut self.recorded_ingress {
            ingress.arm(world)?;
        }
        let mut ready = ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: self.boundary,
            state_inventory: self.readiness_inventory.clone(),
            ready_receipt: self.receipt("host-model-owned-inactive-v1")?,
        };
        self.retain_public_clock_ready(world, &mut ready)?;
        if let Some((original, retained)) = &self.readiness
            && (original != world || retained != &ready)
        {
            return Err(failure("host already armed for another world"));
        }
        self.readiness = Some((world.clone(), ready.clone()));
        Ok(ready)
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<crucible_node_contract::PreparedOwner>>, OperationFailure> {
        self.public_clock_owners(world, ready)
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[crucible_node_contract::PreparedOwner],
    ) -> Result<(), OperationFailure> {
        let original = self
            .public_clock_owners(world, ready)?
            .ok_or_else(|| failure("public clock preparation was not selected"))?;
        if original != owners {
            return Err(failure(
                "public clock owners differ from original inactive model custody",
            ));
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.preparation_origin != HostPreparationOrigin::Original {
            return Err(failure(
                "restored public Clock cannot authenticate initial preparation",
            ));
        }
        self.public_clock_owners(world, ready)?
            .ok_or_else(|| failure("clock did not select genuine public initial preparation"))?;
        Ok(())
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.readiness.as_ref() != Some(&(world.clone(), ready.clone()))
            || self.model.is_none()
            || self.quarantined
            || self.capture()?.as_slice() != self.initial.as_slice()
        {
            return Err(failure(
                "host readiness lacks original owned inactive state custody",
            ));
        }
        Ok(())
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        if matches!(admission.request(), OperationRequest::DebugConditionV1(_)) {
            return self.begin_condition_control(admission);
        }
        if matches!(admission.request(), OperationRequest::FaultInjectionV1(_)) {
            return self.begin_fault_mutation(admission);
        }
        if matches!(
            admission.request(),
            OperationRequest::FinalizeAssertions { .. }
        ) {
            return self.begin_finalization(admission);
        }
        if matches!(
            admission.request(),
            OperationRequest::ExactRun { .. } | OperationRequest::BoundarySettle { .. }
        ) {
            return self.begin_exact(admission);
        }
        let run = || {
            if self.quarantined
                || self.model.is_none()
                || admission.token().route() != &self.route
                || self.readiness.as_ref().map(|r| &r.0) != Some(admission.activation().record())
                || self.activation_authority.as_ref().is_some_and(|authority| {
                    !Rc::ptr_eq(authority, &admission.activation.authority)
                })
                || self.completed.len() >= self.limits.maximum_operations
                || self.completed.contains_key(admission.token().operation())
            {
                return Err(failure(
                    "host operation lacks available original activated custody",
                ));
            }
            let (progress, capture) = match admission.request() {
                OperationRequest::Observe => (ProgressEvidence::Administrative, None),
                OperationRequest::Capture if self.facets.contains(&FacetKind::Preservation) => (
                    ProgressEvidence::Administrative,
                    Some(Rc::new(self.capture_continuation()?)),
                ),
                OperationRequest::Pause if self.facets.contains(&FacetKind::PhysicalPause) => (
                    ProgressEvidence::Paused {
                        reached: Some(self.boundary),
                        stop_receipt: self.receipt("host-model-no-autonomous-worker-v1")?,
                    },
                    None,
                ),
                OperationRequest::Shutdown => (ProgressEvidence::Administrative, None),
                _ => {
                    return Err(failure(
                        "host semantic execution requires qualified staged-input/publication adapter",
                    ));
                }
            };
            let evidence = match &progress {
                ProgressEvidence::Paused { stop_receipt, .. } => {
                    vec![crate::node_scheduling::InputPayload {
                        reference: stop_receipt.clone(),
                        bytes: self.receipt_bytes("host-model-no-autonomous-worker-v1"),
                    }]
                }
                _ => Vec::new(),
            };
            Ok((
                OperationOutcome {
                    operation: admission.token().operation().clone(),
                    node: self.route.node.clone(),
                    owners: self.route.owners.clone(),
                    progress,
                    retained_outputs: Vec::new(),
                    scheduling: None,
                },
                capture,
                evidence,
            ))
        };
        match run() {
            Err(error) => Submission::Refused(Refusal {
                reason: error.reason,
            }),
            Ok((outcome, capture, evidence)) => {
                self.activation_authority = Some(Rc::clone(&admission.activation.authority));
                if matches!(admission.request(), OperationRequest::Shutdown) {
                    self.model.take();
                }
                self.completed.insert(
                    outcome.operation.clone(),
                    Completed {
                        original: admission.clone(),
                        outcome,
                        capture,
                        acknowledged: false,
                        evidence,
                    },
                );
                Submission::Accepted
            }
        }
    }

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        _context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        if let Some((original, failure)) = self.failed.get(operation.operation()) {
            return Poll::Ready(
                if Rc::ptr_eq(&original.token.authority, &operation.authority)
                    && operation.route() == &self.route
                {
                    Err(failure.clone())
                } else {
                    Err(self::failure("foreign failed host operation authority"))
                },
            );
        }
        Poll::Ready(
            self.original(operation)
                .map(|completed| completed.outcome.clone()),
        )
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let completed = self.original(original.token())?;
        if completed.outcome != *outcome
            || completed.original.request() != original.request()
            || !Rc::ptr_eq(
                &completed.original.activation.authority,
                &original.activation.authority,
            )
        {
            return Err(failure(
                "host outcome lacks original retained operation custody",
            ));
        }
        Ok(())
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        let completed = self.original(original.token())?;
        self.validate_outcome(original, &completed.outcome)?;
        let evidence = self.original_condition_objects(original.token().operation(), completed)?;
        if references.len() > evidence.len() {
            return Err(failure(
                "host evidence request exceeds original retained inventory",
            ));
        }
        references
            .iter()
            .map(|reference| {
                evidence
                    .iter()
                    .find(|object| &object.reference == reference)
                    .map(|object| (**object).clone())
                    .ok_or_else(|| {
                        failure("host evidence is absent from original native receipt registry")
                    })
            })
            .collect()
    }

    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_operation_evidence(original, references)? != objects {
            return Err(failure("original host evidence bytes changed"));
        }
        Ok(())
    }

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.original(operation)?;
        Ok(CancelStatus::Terminal)
    }

    fn close_quantum(&mut self, _original: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "host model has no quantized execution facet".into(),
        })
    }

    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let completed = self.original(operation)?;
        if completed.outcome.retained_outputs != outputs {
            return Err(failure("host output inventory mismatch"));
        }
        let original = operation.operation().clone();
        if let Some(completed) = self.completed.get_mut(&original) {
            completed.acknowledged = true;
        }
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if !self.facets.contains(&kind) {
            return Err(Refusal {
                reason: "host facet unadvertised".into(),
            });
        }
        match kind {
            FacetKind::Preservation => Ok(NodeFacet::Preservation(&self.preservation)),
            // Both profiles use distinct fields of a retained descriptor. A
            // borrowed trait object must itself outlive the returned view.
            FacetKind::PhysicalPause => Ok(NodeFacet::PhysicalPause(&self.pause)),
            FacetKind::ExactExecution => Ok(NodeFacet::ExactExecution(&self.execution)),
            FacetKind::TerminalAssertions => Ok(NodeFacet::TerminalAssertions(&self.terminal)),
            FacetKind::Introspection => Ok(NodeFacet::Introspection(&self.terminal_inventory)),
            FacetKind::FaultInjection => Ok(NodeFacet::FaultInjection(&self.fault_injection)),
            FacetKind::Debugging => Ok(NodeFacet::Debugging(&self.condition_debug)),
            _ => Err(Refusal {
                reason: "host facet unsupported".into(),
            }),
        }
    }

    fn stage_inputs(
        &mut self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        if matches!(self.model, Some(HostModel::ConditionObserver(_))) {
            return Err(failure(
                "condition native staging requires authentic original producer proofs",
            ));
        }
        self.stage_exact_inputs(batch)
    }

    fn observe_condition_hit(
        &self,
        activation: &WorldActivation,
    ) -> Result<Option<crate::node_adapters::ConditionHitCandidate>, OperationFailure> {
        self.condition_hit(activation)
    }

    fn validate_condition_hit(
        &self,
        activation: &WorldActivation,
        hit: &crate::node_adapters::ConditionHitCandidate,
    ) -> Result<(), OperationFailure> {
        if self.condition_hit(activation)?.as_ref() != Some(hit) {
            return Err(failure("condition original native hit changed"));
        }
        Ok(())
    }

    fn observe_condition_stop(
        &self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<NativeConditionStopInventory, OperationFailure> {
        self.condition_inventory(activation, maximum_bytes)
    }

    fn validate_condition_stop(
        &self,
        activation: &WorldActivation,
        inventory: &NativeConditionStopInventory,
    ) -> Result<(), OperationFailure> {
        if self.condition_inventory(activation, self.limits.maximum_capture_bytes)? != *inventory {
            return Err(failure("condition complete stopped native custody changed"));
        }
        Ok(())
    }

    fn observe_condition_frontier(
        &self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<NativeConditionEventFrontier, OperationFailure> {
        self.condition_frontier(activation, maximum_bytes)
    }

    fn validate_condition_frontier(
        &self,
        activation: &WorldActivation,
        frontier: &NativeConditionEventFrontier,
    ) -> Result<(), OperationFailure> {
        if self.condition_frontier(activation, frontier.receipt.bytes.len())? != *frontier {
            return Err(failure("condition original native event frontier changed"));
        }
        Ok(())
    }

    fn observe_terminal(
        &mut self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<NativeTerminalInventory, OperationFailure> {
        self.terminal_inventory(activation, maximum_bytes)
    }

    fn validate_terminal(
        &self,
        activation: &WorldActivation,
        inventory: &NativeTerminalInventory,
    ) -> Result<(), OperationFailure> {
        let actual = self.terminal_inventory(activation, inventory.receipt.bytes.len())?;
        if actual != *inventory {
            return Err(failure(
                "host terminal inventory changed under original custody",
            ));
        }
        Ok(())
    }

    fn capture_host_continuation(
        &self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        maximum_bytes: usize,
    ) -> Result<HostNativeCapture, OperationFailure> {
        if self.recorded_ingress.is_some() {
            return Err(failure("recorded input cursor capture is not qualified"));
        }
        if self.public_preparation.is_some() {
            return Err(failure(
                "public clock preparation requires a distinct preparation-bearing capture codec",
            ));
        }
        state::capture_live(self, activation, source, maximum_bytes)
    }

    fn capture_native_continuation(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: crate::node_contract::NativeCaptureLimits,
    ) -> Result<crate::node_contract::InstalledNativeCapture, OperationFailure> {
        if self.recorded_ingress.is_some() {
            return Err(failure("recorded input cursor capture is not qualified"));
        }
        if self.public_continuation {
            return self.capture_public_clock(activation, source, limits);
        }
        let capture =
            self.capture_host_continuation(activation, source, limits.maximum_record_bytes)?;

        crate::node_contract::InstalledNativeCapture::from_host(
            capture,
            &self.descriptor,
            &self.binding,
            source.capture_cut,
            limits,
        )
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
        acknowledgement: &crate::node_scheduling::NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.validate_staged_inputs(batch, acknowledgement)
    }

    fn requires_input_provenance(
        &self,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> bool {
        self.recorded_ingress.is_some()
            || matches!(self.model.as_ref(), Some(HostModel::ConditionObserver(_)))
    }

    fn stage_inputs_with_provenance(
        &mut self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        if matches!(self.model.as_ref(), Some(HostModel::ConditionObserver(_))) {
            return self.condition_stage_provenance(batch, provenance);
        }
        self.validate_recorded_provenance(batch, provenance)?;
        self.stage_exact_inputs(batch)
    }

    fn read_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        if self.terminal_inventory.0.as_str() == HOST_CONDITION_INVENTORY_PROFILE {
            return self.condition_producer_objects(activation, references, maximum_bytes);
        }
        self.read_recorded_evidence(activation, references, maximum_bytes)
    }

    fn validate_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_boundary_evidence(activation, references, self.limits.maximum_capture_bytes)?
            != objects
        {
            return Err(failure("recorded input original boundary objects changed"));
        }
        Ok(())
    }

    fn input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        if self.terminal_inventory.0.as_str() == HOST_CONDITION_INVENTORY_PROFILE {
            return self.condition_producer_dependencies(activation, root, limits);
        }
        self.recorded_dependencies(activation, root, limits)
    }

    fn validate_input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        if self.input_provenance_dependencies(activation, root, InputProvenanceLimits::default())?
            != dependencies
        {
            return Err(failure(
                "recorded input complete source dependencies changed",
            ));
        }
        Ok(())
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<crate::node_scheduling::NativeSchedulingObservation, OperationFailure> {
        self.observe_exact(activation)
    }

    fn next_fault_mutation(
        &self,
        activation: &WorldActivation,
    ) -> Result<Option<crate::node_contract::FaultMutationRequest>, OperationFailure> {
        if self.quarantined
            || !self.same_world(activation)
            || !self.facets.contains(&FacetKind::FaultInjection)
        {
            return Err(failure(
                "native controller lacks its selected original activation",
            ));
        }
        match self.model.as_ref() {
            Some(HostModel::ControlledFaultLink(controller)) => Ok(controller.next_request()),
            _ => Err(failure(
                "selected native model has no admitted authored fault controller",
            )),
        }
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &crate::node_scheduling::NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.validate_exact_observation(activation, observation)
    }

    fn install_restored_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.install_native_custody(activation, source, operations, inputs)
    }

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        _context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if !self.quarantined || !self.route.owners.contains(owner) {
            return Poll::Ready(Err(failure("host owner not under original quarantine")));
        }
        self.model.take();
        let result =
            self.receipt("host-model-dropped-v1")
                .map(|receipt| NativeReclamationReceipt {
                    owner: owner.clone(),
                    receipt,
                });
        if let Ok(receipt) = &result {
            self.reclamations.insert(owner.clone(), receipt.clone());
        }
        Poll::Ready(result)
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.model.is_some() || self.reclamations.get(&receipt.owner) != Some(receipt) {
            return Err(failure(
                "host model not actually destroyed under retained owner custody",
            ));
        }
        Ok(())
    }
}
