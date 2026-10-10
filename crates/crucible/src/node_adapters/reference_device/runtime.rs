//! Common operations and native custody for the controlled reference child.

use super::*;

impl<C: ControlledReference> SimulationNode for ControlledReferenceNode<C> {
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
        &[FacetKind::QuantizedExecution]
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        Ok(NodeStatus {
            lifecycle: match self.child.status() {
                DeviceStatus::Reaped => Lifecycle::Released,
                DeviceStatus::Quarantined => Lifecycle::Quarantined,
                DeviceStatus::Active => Lifecycle::Executing,
                _ => Lifecycle::Stopped,
            },
            physical: PhysicalState::Unknown,
            boundary: Some(self.boundary),
        })
    }

    fn arm(&mut self, record: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if self.quarantined
            || self.child.status() != DeviceStatus::Parked
            || record.boundary != self.boundary
            || record.world_binding_hash != self.world_hash
            || !record.owners.contains(&self.route.owners[0])
        {
            return Err(no_effect(
                "device readiness lacks actual original inactive child",
            ));
        }
        let public_readiness = self.child.prepare_activation(record)?;
        let proof = json_bytes(
            &serde_json::json!({"schema_version":1,"child_pid":self.child.child_pid(),
            "supervision_id":self.child.supervision_id(),"owners":self.route.owners,"activation_id":record.activation_id,"world_generation":record.generation,"world_binding_hash":record.world_binding_hash,"activation_owners":record.owners,"activation_boundary":record.boundary,"state":self.descriptor.initialization_ref}),
        )?;
        let ready = public_readiness.unwrap_or(ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: self.boundary,
            state_inventory: self.descriptor.initialization_ref.clone(),
            ready_receipt: canonical::content_ref(&proof, "application/json")
                .map_err(|e| no_effect(&e.to_string()))?,
        });
        if ready.owners != self.route.owners
            || ready.boundary != self.boundary
            || ready.state_inventory != self.descriptor.initialization_ref
        {
            return Err(native_failure(
                "controlled readiness differs from original sealed scope",
            ));
        }
        if self
            .ready
            .as_ref()
            .is_some_and(|(original, old)| original != record || old != &ready)
        {
            return Err(no_effect("device already prepared for another world"));
        }
        self.ready = Some((record.clone(), ready.clone()));
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.ready.as_ref() != Some(&(record.clone(), ready.clone()))
            || self.child.status() != DeviceStatus::Parked
            || self.active.is_some()
            || self.staged.is_some()
            || self.quarantined
        {
            return Err(no_effect("device native initial readiness custody changed"));
        }
        self.child.validate_activation(record, ready)
    }

    fn prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<crucible_node_contract::PreparedOwner>>, OperationFailure> {
        self.validate_readiness(record, ready)?;
        self.child.prepared_owners(record, ready)
    }

    fn validate_prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[crucible_node_contract::PreparedOwner],
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(record, ready)?;
        self.child.validate_prepared_owners(record, ready, owners)
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(world, ready)?;
        if !self.windows.is_empty() || self.activation_authority.is_some() {
            return Err(no_effect("controlled node has retained continuation state"));
        }
        self.child.validate_initial_preparation(world, ready)
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.stage_inputs_inner(batch, None, None)
    }

    fn requires_input_provenance(&self, batch: &RuntimeInputBatch) -> bool {
        self.child.requires_input_provenance(batch)
    }

    fn stage_inputs_with_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &crate::node_contract::InputProvenanceClosure,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.stage_inputs_inner(batch, Some(provenance), None)
    }

    fn requires_original_input_lineage(&self, batch: &RuntimeInputBatch) -> bool {
        self.child.requires_original_input_lineage(batch)
    }

    fn original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        limits: crate::node_contract::OriginalInputLineageLimits,
    ) -> Result<crate::node_contract::OriginalPublicationClaim, OperationFailure> {
        let retained = self.original(original.token())?;
        if retained.outcome.as_ref() != Some(outcome)
            || outcome
                .scheduling
                .as_ref()
                .is_none_or(|observation| !observation.publications.contains(publication))
        {
            return Err(no_effect(
                "original publication changed retained completion",
            ));
        }
        self.child
            .original_publication_lineage(original, outcome, publication, limits)
    }

    fn validate_original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        claim: &crate::node_contract::OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        let retained = self.original(original.token())?;
        if retained.outcome.as_ref() != Some(outcome)
            || outcome
                .scheduling
                .as_ref()
                .is_none_or(|observation| !observation.publications.contains(publication))
        {
            return Err(no_effect("original lineage changed retained completion"));
        }
        self.child
            .validate_original_publication_lineage(original, outcome, publication, claim)
    }

    fn stage_inputs_with_original_lineage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &crate::node_contract::InputProvenanceClosure,
        lineage: &crate::node_contract::OriginalInputLineage,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.stage_inputs_inner(batch, Some(provenance), Some(lineage))
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        let staged = self
            .staged
            .as_ref()
            .ok_or_else(|| no_effect("reference staged input custody absent"))?;
        if !self.same_world(batch.activation())
            || staged.acknowledgement != *acknowledgement
            || staged.original.batch() != batch.batch()
            || staged.original.stage_operation() != batch.stage_operation()
            || staged.original.inventory() != batch.inventory()
            || staged.original.deliveries() != batch.deliveries()
            || staged.original.payloads() != batch.payloads()
            || self.quarantined
        {
            return Err(no_effect("reference actual retained input cut changed"));
        }
        Ok(())
    }

    fn begin_operation(&mut self, original: &OperationAdmission) -> Submission {
        let preflight = || -> Result<DeviceGrant, OperationFailure> {
            if !self.same_world(original.activation())
                || original.token().route() != &self.route
                || self.quarantined
                || self.active.is_some()
                || self.windows.len() >= self.maximum_operations
                || self.windows.contains_key(original.token().operation())
                || self
                    .windows
                    .values()
                    .flat_map(|window| &window.evidence)
                    .try_fold(0usize, |size, object| size.checked_add(object.bytes.len()))
                    .is_none_or(|size| size > 16 * 1024 * 1024 - 64 * 1024)
            {
                return Err(no_effect(
                    "reference device original execution custody unavailable",
                ));
            }
            let OperationRequest::QuantumBegin {
                window,
                start,
                end,
                input_batch,
                host_budget,
            } = original.request()
            else {
                return Err(no_effect(
                    "reference device supports only quantized execution",
                ));
            };
            let staged = self
                .staged
                .as_ref()
                .ok_or_else(|| no_effect("reference actual immutable input stage absent"))?;
            let inputs = original
                .inputs()
                .ok_or_else(|| no_effect("reference grant lacks opaque admitted input cut"))?;
            if staged.original.batch() != input_batch
                || inputs.batch() != input_batch
                || inputs.inventory() != staged.original.inventory()
                || inputs.deliveries() != staged.original.deliveries()
                || inputs.payloads() != staged.original.payloads()
                || *start != root(self.boundary.time_ps.get(), Phase::BoundaryControl)
                || start.time_ps.get().checked_add(self.quantum_ps) != Some(end.time_ps.get())
                || end.microstep.get() != 0
                || end.phase != Phase::Publication
                || start.time_ps.get() % self.quantum_ps != 0
                || u64::try_from(host_budget.as_nanos()).ok() != Some(self.host_budget_ns)
            {
                return Err(no_effect(
                    "reference grant grid or original frozen input scope mismatch",
                ));
            }
            Ok(DeviceGrant {
                owner_id: self.route.owners[0].owner.clone(),
                incarnation_id: self.route.owners[0].incarnation.clone(),
                generation: self.route.owners[0].generation,
                window_id: window.clone(),
                input_batch_id: input_batch.clone(),
                quantum: self.next_quantum,
                start: *start,
                publication: *end,
                host_budget_ns: self.host_budget_ns.into(),
            })
        };
        let grant = match preflight() {
            Ok(grant) => grant,
            Err(failure) => {
                return Submission::Refused(Refusal {
                    reason: failure.reason,
                });
            }
        };
        let Some(staged) = &self.staged else {
            return Submission::Refused(Refusal {
                reason: "original device input stage absent".into(),
            });
        };
        let input = Rc::clone(&staged.original);
        self.windows.insert(
            original.token().operation().clone(),
            Window {
                original: original.clone(),
                grant: grant.clone(),
                input,
                receipt: None,
                outcome: None,
                evidence: Vec::new(),
                acknowledged: false,
                failure: None,
            },
        );
        self.active = Some(original.token().operation().clone());
        if let Err(error) = self
            .child
            .retain_operation(original)
            .and_then(|()| self.child.stage(grant.clone(), &staged.bytes))
            .and_then(|()| self.child.activate(&grant))
        {
            self.quarantined = true;
            if let Some(window) = self.windows.get_mut(original.token().operation()) {
                window.failure = Some(native_failure(&error.to_string()));
            }
            return Submission::Uncertain(EffectKnowledge::Unknown);
        }
        Submission::Accepted
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        let grant = match self.original(original.token()) {
            Ok(window) if window.original.request() == original.request() => {
                if window.outcome.is_some() {
                    return Submission::Accepted;
                }
                window.grant.clone()
            }
            _ => {
                return Submission::Refused(Refusal {
                    reason: "foreign original device closure".into(),
                });
            }
        };
        let receipt = match self.child.close(&grant) {
            Ok(receipt) => receipt,
            Err(_) => {
                self.quarantined = true;
                return Submission::Uncertain(EffectKnowledge::Unknown);
            }
        };
        let result = self.original(original.token()).and_then(|window| {
            self.observation(&receipt, &window.input, original.token().operation())
        });
        let scheduling = match result {
            Ok(scheduling) => scheduling,
            Err(_) => {
                self.quarantined = true;
                return Submission::Uncertain(EffectKnowledge::Unknown);
            }
        };
        let proof = scheduling.proof_ref.clone();
        let outputs = scheduling
            .publications
            .iter()
            .map(|publication| publication.publication_id.clone())
            .collect();
        let commitments =
            (|| -> Result<(ContentRef, ContentRef, Vec<InputPayload>), OperationFailure> {
                let output_bytes = json_bytes(&scheduling.publications)?;
                let output_inventory = canonical::content_ref(&output_bytes, "application/json")
                    .map_err(|error| native_failure(&error.to_string()))?;
                let pending = json_bytes(
                    &serde_json::json!({"schema_version":1,"input_batch":grant.input_batch_id,
                "input_disposition":"consumed","original_buffer_retained":true,"outputs_retained":true,
                "application_parked":receipt.application_parked,"owner":self.route.owners[0]}),
                )?;
                let pending_inventory = canonical::content_ref(&pending, "application/json")
                    .map_err(|error| native_failure(&error.to_string()))?;
                let original_proof = self.completion_proof(&receipt)?;
                if original_proof.reference != proof {
                    return Err(native_failure(
                        "original completion proof changed during closure",
                    ));
                }
                let mut evidence = vec![
                    original_proof,
                    InputPayload {
                        reference: output_inventory.clone(),
                        bytes: output_bytes,
                    },
                    InputPayload {
                        reference: pending_inventory.clone(),
                        bytes: pending,
                    },
                ];
                evidence.extend(
                    scheduling
                        .publications
                        .iter()
                        .map(|publication| InputPayload {
                            reference: publication.payload.clone(),
                            bytes: publication.payload_bytes.clone(),
                        }),
                );
                if evidence
                    .iter()
                    .try_fold(0usize, |size, object| size.checked_add(object.bytes.len()))
                    .is_none_or(|size| size > 64 * 1024)
                {
                    return Err(native_failure(
                        "original device evidence exceeds native receipt ceiling",
                    ));
                }
                Ok((output_inventory, pending_inventory, evidence))
            })();
        let (output_inventory, pending_inventory, evidence) = match commitments {
            Ok(commitments) => commitments,
            Err(failure) => {
                if let Some(window) = self.windows.get_mut(original.token().operation()) {
                    window.receipt = Some(receipt);
                    window.failure = Some(failure);
                }
                self.quarantined = true;
                return Submission::Uncertain(EffectKnowledge::Unknown);
            }
        };
        let closure = QuantumClosureEvidence {
            input_batch: grant.input_batch_id.clone(),
            close_receipt: proof.clone(),
            output_inventory,
            pending_inventory,
            clock_evidence: proof,
        };
        let outcome = OperationOutcome {
            operation: original.token().operation().clone(),
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            progress: ProgressEvidence::Quantized {
                window: grant.window_id,
                publication: grant.publication,
                physical: PhysicalState::Unknown,
                closure: Box::new(closure),
            },
            retained_outputs: outputs,
            scheduling: Some(scheduling),
        };
        if let Some(window) = self.windows.get_mut(original.token().operation()) {
            window.receipt = Some(receipt);
            window.outcome = Some(outcome);
            window.evidence = evidence;
        }
        if let Some(waiter) = self.waiter.take() {
            waiter.wake();
        }
        Submission::Accepted
    }

    fn poll_operation(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        match self.original(token) {
            Err(error) => Poll::Ready(Err(error)),
            Ok(window) => {
                if let Some(failure) = &window.failure {
                    return Poll::Ready(Err(failure.clone()));
                }
                if let Some(outcome) = &window.outcome {
                    return Poll::Ready(Ok(outcome.clone()));
                }
                if self.quarantined {
                    return Poll::Ready(Err(OperationFailure {
                        effects: EffectKnowledge::Unknown,
                        reason: "original reference window contained".into(),
                    }));
                }
                self.waiter = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let window = self.original(original.token())?;
        let receipt = window
            .receipt
            .as_ref()
            .ok_or_else(|| no_effect("authentic original native receipt absent"))?;
        // The private acknowledged bit is set only after the real driver's
        // original-grant ACK succeeds. Later windows must not invalidate that
        // authentic immutable receipt or require re-sampling the current child.
        if !window.acknowledged {
            self.child
                .validate_receipt(receipt)
                .map_err(|e| no_effect(&e.to_string()))?;
        }
        let original_bytes = window
            .input
            .deliveries()
            .iter()
            .try_fold(0usize, |size, delivery| {
                let payload = window
                    .input
                    .payloads()
                    .iter()
                    .find(|payload| payload.reference == delivery.payload)?;
                size.checked_add(payload.bytes.len())
            })
            .ok_or_else(|| no_effect("original retained native input bytes unavailable"))?;
        if window.outcome.as_ref() != Some(outcome)
            || window.original.request() != original.request()
            || !Rc::ptr_eq(
                &window.original.activation.authority,
                &original.activation.authority,
            )
            || self.quarantined
            || receipt.output.bytes_processed.get() != original_bytes as u64
        {
            return Err(no_effect("original reference native closure scope differs"));
        }
        Ok(())
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        let window = self.original(original.token())?;
        let outcome = window
            .outcome
            .as_ref()
            .ok_or_else(|| no_effect("original native closure is not complete"))?;
        self.validate_outcome(original, outcome)?;
        if references.len() > window.evidence.len() {
            return Err(no_effect(
                "original native evidence request exceeds retained inventory",
            ));
        }
        references
            .iter()
            .map(|reference| {
                window
                    .evidence
                    .iter()
                    .find(|object| &object.reference == reference)
                    .cloned()
                    .ok_or_else(|| no_effect("evidence does not belong to original native closure"))
            })
            .collect()
    }

    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_operation_evidence(original, references)? != objects {
            return Err(no_effect("original native evidence bodies changed"));
        }
        Ok(())
    }

    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        self.original(token)?;
        self.quarantined = true;
        self.child
            .quarantine()
            .map_err(|e| native_failure(&e.to_string()))?;
        Ok(CancelStatus::Requested)
    }

    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let window = self.original(token)?;
        let outcome = window
            .outcome
            .as_ref()
            .ok_or_else(|| no_effect("reference original output not closed"))?;
        if outcome.retained_outputs != outputs {
            return Err(no_effect("reference output inventory differs"));
        }
        if window.acknowledged {
            return Ok(());
        }
        let grant = window.grant.clone();
        self.child
            .acknowledge_publication(&grant)
            .map_err(|e| native_failure(&e.to_string()))?;
        self.next_quantum = self
            .next_quantum
            .checked_add(1.into())
            .map_err(|e| native_failure(&e.to_string()))?;
        self.boundary = root(grant.publication.time_ps.get(), Phase::BoundaryControl);
        if let Some(window) = self.windows.get_mut(token.operation()) {
            window.acknowledged = true;
        }
        self.active = None;
        self.staged = None;
        Ok(())
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if !self.same_world(activation)
            || self.quarantined
            || self.active.is_some()
            || self.child.status() != DeviceStatus::Parked
        {
            return Err(no_effect(
                "reference initial producer observation unavailable",
            ));
        }
        let next = self
            .boundary
            .time_ps
            .get()
            .checked_add(self.quantum_ps)
            .ok_or_else(|| no_effect("reference future boundary overflow"))?;
        let proof_bytes = json_bytes(
            &serde_json::json!({"child":self.child.child_pid(),"owners":self.route.owners,
            "controller_boundary":self.boundary,"earliest_grant_output":root(next,Phase::Publication),"profile":self.profile.0}),
        )?;
        let proof_ref = canonical::content_ref(&proof_bytes, "application/json")
            .map_err(|e| no_effect(&e.to_string()))?;
        self.retain_boundary_evidence(
            activation,
            InputPayload {
                reference: proof_ref.clone(),
                bytes: proof_bytes,
            },
        )?;
        let observation = NativeSchedulingObservation {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            reached: self.boundary,
            closed_prefix: self.boundary,
            bounds: vec![NativeProducerBound {
                producer: self.route.node.clone(),
                bound: NativeOutputBound::At(root(next, Phase::Publication)),
                proof_ref: proof_ref.clone(),
            }],
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref,
        };
        self.observation = Some((activation.clone(), observation.clone()));
        Ok(observation)
    }

    fn read_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if self.thread != std::thread::current().id()
            || self.quarantined
            || !self.same_world(activation)
            || self
                .boundary_evidence_activation
                .as_ref()
                .is_some_and(|original| {
                    original.record() != activation.record()
                        || !Rc::ptr_eq(&original.authority, &activation.authority)
                })
        {
            return Err(no_effect(
                "reference boundary evidence has foreign or reclaimed custody",
            ));
        }
        let mut objects = Vec::new();
        let mut bytes = 0usize;
        for reference in references {
            let object = if let Some(original) = self.boundary_evidence.get(&reference.hash) {
                if original.reference != *reference {
                    return Err(no_effect("reference historical proof metadata changed"));
                }
                bytes = bytes
                    .checked_add(original.bytes.len())
                    .ok_or_else(|| no_effect("reference evidence byte extent overflow"))?;
                if bytes > maximum_bytes {
                    return Err(no_effect("reference evidence exceeds original read budget"));
                }
                original.clone()
            } else {
                let requested = std::slice::from_ref(reference);
                let mut delegated = self.child.read_boundary_evidence(
                    activation,
                    requested,
                    maximum_bytes.saturating_sub(bytes),
                )?;
                self.child
                    .validate_boundary_evidence(activation, requested, &delegated)?;
                if delegated.len() != 1 {
                    return Err(no_effect("controlled boundary evidence inventory changed"));
                }
                let object = delegated.remove(0);
                bytes = bytes
                    .checked_add(object.bytes.len())
                    .ok_or_else(|| no_effect("controlled evidence byte extent overflow"))?;
                object
            };
            if object.reference != *reference
                || reference.verify(&object.bytes).is_err()
                || bytes > maximum_bytes
            {
                return Err(no_effect(
                    "controlled original proof bytes changed or exceed budget",
                ));
            }
            objects.push(object);
        }
        Ok(objects)
    }

    fn validate_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_boundary_evidence(activation, references, 16 * 1024 * 1024)? != objects {
            return Err(no_effect(
                "reference original boundary proof bodies changed",
            ));
        }
        Ok(())
    }

    fn input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        if self.thread != std::thread::current().id()
            || !self.same_world(activation)
            || self.quarantined
        {
            return Err(no_effect(
                "reference producer proof has foreign or reclaimed custody",
            ));
        }
        if let Some(object) = self.boundary_evidence.get(&root.hash) {
            if object.reference != *root
                || limits.maximum_objects == 0
                || object.bytes.len() > limits.maximum_bytes
            {
                return Err(no_effect(
                    "reference boundary proof metadata or closure budget changed",
                ));
            }
            // This registry is populated only by the adapter's scalar observer
            // codec and literal buffer-custody codec; both are reference leaves.
            return Ok(Vec::new());
        }
        for window in self.windows.values() {
            if !Rc::ptr_eq(
                &window.original.activation().authority,
                &activation.authority,
            ) {
                continue;
            }
            let Some(receipt) = &window.receipt else {
                continue;
            };
            let Some(object) = window
                .evidence
                .iter()
                .find(|object| object.reference == *root)
            else {
                continue;
            };
            if json_bytes(receipt)? != object.bytes {
                continue;
            }
            if limits.maximum_objects == 0 || object.bytes.len() > limits.maximum_bytes {
                return Err(no_effect(
                    "reference producer proof closure budget exhausted",
                ));
            }
            self.child
                .validate_receipt(receipt)
                .map_err(|error| no_effect(&error.to_string()))?;
            // The installed checksum DeviceReceipt codec contains scalar grant,
            // measured output and native outcome data; it references no objects.
            return Ok(Vec::new());
        }
        self.child
            .input_provenance_dependencies(activation, root, limits)
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
            return Err(no_effect(
                "reference original producer dependency inventory changed",
            ));
        }
        Ok(())
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        if self
            .observation
            .as_ref()
            .is_none_or(|(original, retained)| {
                !Rc::ptr_eq(&original.authority, &activation.authority) || retained != observation
            })
            || !self.same_world(activation)
            || self.quarantined
            || self.child.status() != DeviceStatus::Parked
            || self.active.is_some()
            || observation.node != self.route.node
            || observation.owners != self.route.owners
            || observation.reached != self.boundary
            || observation.closed_prefix != self.boundary
            || !observation.publications.is_empty()
            || observation.input_progress.is_some()
            || observation.bounds.len() != 1
        {
            return Err(no_effect(
                "reference current producer closure lacks actual parked-child custody",
            ));
        }
        let next = self
            .boundary
            .time_ps
            .get()
            .checked_add(self.quantum_ps)
            .ok_or_else(|| no_effect("reference future boundary overflow"))?;
        if observation.bounds[0].producer != self.route.node
            || observation.bounds[0].bound != NativeOutputBound::At(root(next, Phase::Publication))
        {
            return Err(no_effect(
                "reference producer bound exceeds qualified controller-window semantics",
            ));
        }
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if kind == FacetKind::QuantizedExecution {
            Ok(NodeFacet::QuantizedExecution(&self.profile))
        } else {
            Err(Refusal {
                reason: "reference device optional facet unsupported".into(),
            })
        }
    }

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
        let _ = self.child.quarantine();
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if !self.quarantined || !self.route.owners.contains(owner) {
            return Poll::Ready(Err(no_effect(
                "reference owner not under original quarantine",
            )));
        }
        match self.child.quarantine() {
            Err(error) => Poll::Ready(Err(native_failure(&error.to_string()))),
            Ok(false) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(true) => {
                let result = json_bytes(&serde_json::json!({"schema_version":1,"owner":owner,"child_pid":self.child.child_pid(),
                    "supervision_id":self.child.supervision_id(),"reaped":true})).and_then(|bytes| canonical::content_ref(&bytes,"application/json")
                        .map_err(|e| no_effect(&e.to_string()))).map(|receipt| NativeReclamationReceipt {owner: owner.clone(),receipt});
                if let Ok(receipt) = &result {
                    self.reclaimed = Some(receipt.clone());
                }
                Poll::Ready(result)
            }
        }
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.child.status() != DeviceStatus::Reaped
            || self.reclaimed.as_ref() != Some(receipt)
            || !self.quarantined
        {
            return Err(no_effect(
                "reference original child has not been actually reaped",
            ));
        }
        // Reaping is not output-disposition authority. The driver's supervisor
        // retains original unpublished buffers when this wrapper is dropped.
        Ok(())
    }
}

impl<C: ControlledReference> ControlledReferenceNode<C> {
    fn stage_inputs_inner(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: Option<&crate::node_contract::InputProvenanceClosure>,
        lineage: Option<&crate::node_contract::OriginalInputLineage>,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        if !self.same_world(batch.activation())
            || batch.node() != &self.route.node
            || batch.owners() != self.route.owners
            || self.quarantined
            || self.active.is_some()
            || self.staged.is_some()
            || self.child.status() != DeviceStatus::Parked
            || (!self.descriptor.ports.iter().any(|port| {
                port.lanes
                    .iter()
                    .any(|lane| lane.direction == Direction::Input)
            }) && (!batch.deliveries().is_empty() || !batch.payloads().is_empty()))
        {
            return Err(no_effect(
                "reference device input staging custody unavailable",
            ));
        }
        let mut bytes = Vec::new();
        for delivery in batch.deliveries() {
            if delivery.consumer != self.route.node
                || delivery.consumer_endpoint.node_id != self.route.node
                || !self.descriptor.ports.iter().any(|port| {
                    port.id == delivery.consumer_endpoint.port_id
                        && port.lanes.iter().any(|lane| {
                            lane.id == delivery.consumer_endpoint.lane_id
                                && lane.direction == Direction::Input
                        })
                })
            {
                return Err(no_effect(
                    "reference input targets an unadmitted native port or lane",
                ));
            }
            let payload = batch
                .payloads()
                .iter()
                .find(|payload| payload.reference == delivery.payload)
                .ok_or_else(|| no_effect("original device payload absent"))?;
            let reference = canonical::content_ref(&payload.bytes, &payload.reference.media_type)
                .map_err(|e| no_effect(&e.to_string()))?;
            if reference != payload.reference
                || bytes
                    .len()
                    .checked_add(payload.bytes.len())
                    .is_none_or(|size| size > MAX_INPUT_BYTES)
            {
                return Err(no_effect(
                    "reference device immutable input bytes mismatch or exceed native ceiling",
                ));
            }
            bytes.extend_from_slice(&payload.bytes);
        }
        let proof_ref = canonical::content_ref(&bytes, "application/octet-stream")
            .map_err(|e| no_effect(&e.to_string()))?;
        // Empty byte batches still have real retained staging evidence.
        let proof_ref = if bytes.is_empty() {
            canonical::content_ref(
                b"reference-device-owned-empty-input-v1",
                "application/octet-stream",
            )
            .map_err(|e| no_effect(&e.to_string()))?
        } else {
            proof_ref
        };
        let acknowledgement = NativeInputAcknowledgement {
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            node: batch.node().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            proof_ref,
        };
        let fallback = InputPayload {
            reference: acknowledgement.proof_ref.clone(),
            bytes: if bytes.is_empty() {
                b"reference-device-owned-empty-input-v1".to_vec()
            } else {
                bytes.clone()
            },
        };
        self.reserve_boundary_evidence(&fallback)?;
        let public_acknowledgement = match (provenance, lineage) {
            (Some(provenance), Some(lineage)) => self
                .child
                .stage_runtime_inputs_with_original_lineage(batch, provenance, lineage)?,
            (None, Some(_)) => {
                return Err(no_effect("original input lineage omitted proof closure"));
            }
            (Some(provenance), None) => self
                .child
                .stage_runtime_inputs_with_provenance(batch, provenance)?,
            (None, None) => self.child.stage_runtime_inputs(batch)?,
        };
        if public_acknowledgement.is_none() {
            self.retain_boundary_evidence(batch.activation(), fallback)
                .map_err(|error| native_failure(&error.reason))?;
        }
        let acknowledgement = public_acknowledgement.unwrap_or(acknowledgement);
        if acknowledgement.stage_operation != *batch.stage_operation()
            || acknowledgement.batch != *batch.batch()
            || acknowledgement.node != *batch.node()
            || acknowledgement.owners != batch.owners()
            || acknowledgement.cutoff != batch.cutoff()
            || acknowledgement.inventory != *batch.inventory()
        {
            return Err(native_failure(
                "controlled input receipt differs from original retained cut",
            ));
        }
        self.activation_authority = Some(Rc::clone(&batch.activation.authority));
        self.staged = Some(Staged {
            original: Rc::new(batch.retained_copy()),
            bytes,
            acknowledgement: acknowledgement.clone(),
        });
        Ok(acknowledgement)
    }
}
