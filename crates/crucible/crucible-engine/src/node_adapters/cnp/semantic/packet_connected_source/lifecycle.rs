//! Lifecycle correlation beneath the same original connected native child.

use super::*;

impl CnpSemanticSource for PacketConnectedSemanticSource {
    fn requires_original_input_lineage(&self, _batch: &RuntimeInputBatch) -> bool {
        true
    }

    fn validate_original_input_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), OperationFailure> {
        self.authenticate_lineage(scope, batch, provenance, lineage)
    }

    fn read_original_input_evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalInputEvidence, OperationFailure> {
        self.input_evidence(scope, original, staged, limits)
    }

    fn validate_original_input_evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        evidence: &OriginalInputEvidence,
    ) -> Result<(), OperationFailure> {
        let expected = self.input_evidence(
            scope,
            original,
            staged,
            OriginalInputLineageLimits::default(),
        )?;
        if expected.root != evidence.root
            || expected.objects != evidence.objects
            || expected.rows != evidence.rows
        {
            return Err(refused("connected complete original input codec changed"));
        }
        Ok(())
    }

    fn original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        self.publication_claim(scope, original, outcome, publication, limits)
    }

    fn validate_original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        let expected = self.publication_claim(
            scope,
            original,
            outcome,
            publication,
            OriginalInputLineageLimits::default(),
        )?;
        if &expected != claim {
            return Err(refused(
                "connected complete original publication codec changed",
            ));
        }
        Ok(())
    }

    fn validate_exact_original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.validate_original_publication_lineage(scope, original, outcome, publication, claim)
    }

    fn validate_deferred_original_publication(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        prior: &OperationAdmission,
        prior_outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.deferred_publication(scope, original, outcome, publication, prior, prior_outcome)
    }

    fn installation(&self) -> &CnpSemanticInstallation {
        &self.installation
    }

    fn authenticate_provider(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        native.authenticate_process().map_err(unknown)?;
        if native.conformance.is_none() {
            return Err(refused("packet three-owner source is collecting-only"));
        }
        let controller = native
            .controller()
            .ok_or_else(|| refused("packet actual native transport absent"))?;
        if self
            .installation
            .provider
            .implementation
            .formats
            .iter()
            .any(|format| format.id.as_str() == "source-owned.packet-ingress/4")
            && !controller.has_connected_packet_transport_schema()
        {
            return Err(refused(
                "packet common ingress requires immutable original transport schema",
            ));
        }
        if self.complete_storage.is_some() {
            controller
                .authenticate_native5_source_codec()
                .map_err(crate::node_adapters::cnp::semantic::refused_display)?;
        }

        if !self
            .installation
            .provider
            .implementation
            .artifacts
            .iter()
            .any(|artifact| {
                artifact.role.as_str() == "executable"
                    && artifact.content == *controller.peer_executable()
            })
            || controller.peer_pid() != native.provider_pid()
        {
            return Err(refused(
                "packet actual native executable/peer is not the installed source",
            ));
        }
        if let Some(retained) = self
            .current_native
            .try_borrow()
            .map_err(|_| refused("connected source read busy"))?
            .as_ref()
        {
            let supplied = native.original_source_read().map_err(unknown)?;
            if !retained.same_original(&supplied) {
                return Err(refused(
                    "connected original native capsule cannot be replaced",
                ));
            }
            retained.ensure_current().map_err(unknown)?;
        }
        native.authenticate_process().map_err(unknown)
    }

    fn preflight_transition(
        &self,
        native: &CnpSemanticProcessCustody,
        transition: CnpSemanticTransition,
    ) -> Result<(), OperationFailure> {
        self.authenticate_provider(native)?;
        let prefix = match transition {
            CnpSemanticTransition::Preparation => credit::Prefix::Preparation,
            CnpSemanticTransition::Readiness => credit::Prefix::Stage,
            CnpSemanticTransition::Observation => credit::Prefix::Observation,
            CnpSemanticTransition::Admission | CnpSemanticTransition::Query => {
                credit::Prefix::Query
            }
            CnpSemanticTransition::Retirement => credit::Prefix::Retirement,
        };
        self.preflight_reply(
            prefix,
            native
                .controller()
                .ok_or_else(|| refused("packet source prefix has no original native controller"))?,
        )
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.authenticate_provider(scope.native)?;
            if scope.discovery.provider_manifest != self.installation.provider
                || scope.realization.realization_manifest.descriptors
                    != [self.installation.descriptor.clone()]
                || scope.realization.realization_manifest.bindings
                    != [self.installation.binding.clone()]
                || scope.realization.realization_manifest.owner_bindings
                    != [self.installation.owner.clone()]
                || scope.realization.realization_manifest.owners
                    != [self.installation.owner.owner.clone()]
                || scope.realization.realization_manifest.realization_id
                    != self.installation.realize.realization_id
            {
                return Err(refused(
                    "packet complete original realized source selection changed",
                ));
            }
            let native = self.initial(&scope, &scope.realization.closed_gate_receipt)?;
            let request =
                decode_request(native.original.method, &native.original.body).map_err(unknown)?;
            if !matches!(request, RequestBody::Realize(ref request) if request == &self.installation.realize)
            {
                return Err(refused(
                    "packet native gate belongs to a different original Realize",
                ));
            }
            self.world.authenticate_realization(scope.realization)?;
            self.retain_current_native(scope.native)
        })();
        self.guard(&scope)?;
        result
    }

    fn preflight_operation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.guard(&scope)?;
            self.preflight_reply(credit::Prefix::Operation, scope.controller)?;
            self.connected_authorization(&scope, original, None)?;
            let current = self.latest(&scope)?;
            let (start, _) = operation_interval(original)?;
            if current.inventory.reached != start {
                return Err(refused(
                    "connected original start differs from native cursor",
                ));
            }
            self.guard(&scope)
        })();
        self.guard(&scope)?;
        result
    }

    fn status(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<NodeStatus, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let native = self.latest(&scope)?;
            Ok(NodeStatus {
                lifecycle: if native.inventory.gate_closed {
                    Lifecycle::Prepared
                } else {
                    Lifecycle::Stopped
                },
                physical: PhysicalState::Unknown,
                boundary: Some(native.inventory.reached),
            })
        })();
        self.guard(&scope)?;
        result
    }

    fn prepared_owner(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<PreparedOwner, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.validate_readiness(scope, record, ready)?;
            Ok(PreparedOwner {
                owner_id: self.owner().owner,
                incarnation_id: self.owner().incarnation,
                owner_generation: self.owner().generation,
                binding_hashes: vec![self.installation.binding.identity().map_err(unknown)?],
                prepared_token: scope.realization.prepared_token.clone(),
                ready_receipt: ready.ready_receipt.clone(),
                extensions: Extensions::new(),
            })
        })();
        self.guard(&scope)?;
        result
    }

    fn validate_initial_preparation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.validate_readiness(scope, record, ready)?;
            let current = self.latest(&scope)?;
            if current.inventory != self.initial(&scope, &ready.ready_receipt)?.inventory {
                return Err(refused("packet native preparation has already changed"));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        response: &ActivateResult,
    ) -> Result<ReadyAttestation, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let native = self.initial(&scope, &response.activation_receipt)?;
            let request =
                decode_request(native.original.method, &native.original.body).map_err(unknown)?;
            let RequestBody::Activate(request) = request else {
                return Err(refused("packet readiness has no original Activate"));
            };
            self.authenticate_activation_record(record)?;
            if record.world_binding_hash != self.installation.world_binding_hash
                || record.boundary != native.inventory.reached
                || request.activation_id != record.activation_id
                || request.world_generation != record.generation
                || request.gate_id != self.installation.gate
                || response.staged_owner_ids != [self.owner().owner]
                || !response.staged
            {
                return Err(refused(
                    "packet actual original readiness differs from complete common preparation",
                ));
            }
            Ok(ReadyAttestation {
                owners: vec![self.owner()],
                boundary: native.inventory.reached,
                state_inventory: response.activation_receipt.clone(),
                ready_receipt: response.activation_receipt.clone(),
            })
        })();
        self.guard(&scope)?;
        result
    }

    fn validate_readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let native = self.initial(&scope, &ready.ready_receipt)?;
            self.authenticate_activation_record(record)?;
            if ready.owners != [self.owner()]
                || ready.boundary != record.boundary
                || ready.boundary != native.inventory.reached
                || ready.state_inventory != ready.ready_receipt
                || record.world_binding_hash != self.installation.world_binding_hash
            {
                return Err(refused(
                    "packet retained native readiness/common owner association changed",
                ));
            }
            let RequestBody::Activate(request) =
                decode_request(native.original.method, &native.original.body).map_err(unknown)?
            else {
                return Err(refused("packet readiness original method changed"));
            };
            if request.activation_id != record.activation_id
                || request.world_generation != record.generation
            {
                return Err(refused(
                    "packet readiness belongs to a different original activation",
                ));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn preflight_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.preflight_reply(credit::Prefix::WorldActivation, scope.controller)?;
            self.authenticate_provider(scope.native)?;
            let record = activation.record();
            let owners = activation
                .prepared_owners()
                .ok_or_else(|| refused("packet complete original prepared owners absent"))?;
            let coordinator = activation
                .coordinator_snapshot()
                .ok_or_else(|| refused("packet complete original coordinator bytes absent"))?;
            self.authenticate_activation_record(record)?;
            let local = self
                .world
                .authenticate_prepared(owners, scope.realization)?;
            let ready = self.initial(&scope, &local.ready_receipt)?;
            let current = self.latest(&scope)?;
            if current.inventory != ready.inventory {
                return Err(refused(
                    "packet source state changed before original global gate opening",
                ));
            }
            coordinator
                .reference
                .verify(&coordinator.bytes)
                .map_err(unknown)?;
            self.world.authenticate_coordinator(&coordinator.bytes)?;
            let data = canonical::parse_json(&coordinator.bytes, crucible_node_transport::reference_packet::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES).map_err(unknown)?;
            let saved: SavedRuntimeActivation =
                serde_json::from_value(data.get("activation").cloned().ok_or_else(|| {
                    refused("packet full original coordinator activation absent")
                })?)
                .map_err(unknown)?;
            if data.get("schema").and_then(serde_json::Value::as_str)
                != Some("crucible/coordinator-initial/1")
                || saved != SavedRuntimeActivation::from(record)
                || data.get("clock")
                    != Some(&serde_json::to_value(record.boundary).map_err(unknown)?)
                || data
                    .get("nodes")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(|nodes| nodes.len() != record.owners.len())
            {
                return Err(refused(
                    "packet common gate lacks authentic whole initial coordinator scope",
                ));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn validate_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &WorldActivateResult,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let native = self.native_record(&scope, &response.activation_receipt)?;
            let RequestBody::WorldActivate(request) =
                decode_request(native.original.method, &native.original.body).map_err(unknown)?
            else {
                return Err(refused("packet global gate lacks original WorldActivate"));
            };
            let coordinator = activation
                .coordinator_snapshot()
                .ok_or_else(|| refused("packet complete common coordinator absent"))?;
            let owners = activation
                .prepared_owners()
                .ok_or_else(|| refused("packet complete original common preparation absent"))?;
            let manifest: ActivationManifest = canonical::decode(
                scope
                    .controller
                    .content(&request.activation_manifest)
                    .map_err(unknown)?,
                65_536,
            )
            .map_err(unknown)?;
            coordinator
                .reference
                .verify(&coordinator.bytes)
                .map_err(unknown)?;
            self.world.authenticate_coordinator(&coordinator.bytes)?;
            let data = canonical::parse_json(&coordinator.bytes, crucible_node_transport::reference_packet::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES).map_err(unknown)?;
            let saved: SavedRuntimeActivation =
                serde_json::from_value(data.get("activation").cloned().ok_or_else(|| {
                    refused("packet original initial coordinator activation absent")
                })?)
                .map_err(unknown)?;
            self.authenticate_activation_record(activation.record())?;
            self.world
                .authenticate_prepared(owners, scope.realization)?;
            if data.get("schema").and_then(serde_json::Value::as_str)
                != Some("crucible/coordinator-initial/1")
                || saved != SavedRuntimeActivation::from(activation.record())
                || request.activation_id != activation.record().activation_id
                || request.world_generation != activation.record().generation
                || request.transaction_id != self.installation.transaction
                || manifest.owners != owners
                || manifest.coordinator_state_ref != coordinator.reference
                || scope
                    .controller
                    .content(&coordinator.reference)
                    .map_err(unknown)?
                    != coordinator.bytes
                || native.inventory.gate_closed
                || !native.inventory.retained_outputs.is_empty()
                || !native.inventory.reactions.is_empty()
            {
                return Err(refused(
                    "packet actual all-owner gate is not bound to original opaque common publication",
                ));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        response: &ResponseBody,
    ) -> Result<OperationOutcome, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) =
                &response.result
            else {
                return Err(refused(
                    "packet common outcome is not exact original completion",
                ));
            };
            self.guard(&scope)?;
            let outcome = self.mapped_outcome(&scope, original, &result.stop_receipt)?;
            budget::serialized_size(&outcome, self.installation.maximum_result_bytes)?;
            Ok(outcome)
        })();
        self.guard(&scope)?;
        result
    }

    fn validate_outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let root = self.operation_root(&scope, original)?;
            if self.mapped_outcome(&scope, original, &root)? != *outcome {
                return Err(refused("packet original native outcome changed"));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &ObserveResult,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            if !response.complete || response.observations.len() != 1 {
                return Err(refused(
                    "packet complete original native observation absent",
                ));
            }
            let root = &response.observations[0].measurement_ref;
            let native = self.native_record(&scope, root)?;
            self.observation(activation, root, &native)
        })();
        self.guard(&scope)?;
        result
    }

    fn validate_scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            let native = self.native_record(&scope, &observation.proof_ref)?;
            if self.observation(activation, &observation.proof_ref, &native)? != *observation {
                return Err(refused(
                    "packet actual original scheduling inventory changed",
                ));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        original: Option<&OperationAdmission>,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.authenticate_activation_record(activation.record())?;
            if references.len() > 32 {
                return Err(refused(
                    "packet evidence scope or association credit changed",
                ));
            }
            let current = if let Some(original) = original {
                let root = self.operation_root(&scope, original)?;
                self.native_record(&scope, &root)?
            } else {
                self.latest(&scope)?
            };
            let mut total = 0usize;
            let mut planned = Vec::with_capacity(references.len());
            for reference in references {
                let bytes = super::evidence::original_evidence_bytes(
                    &current.inventory,
                    reference,
                    scope.controller.content(reference).ok(),
                    || self.authenticate_record_evidence(&scope, reference),
                )?;
                total = total
                    .checked_add(bytes.len())
                    .filter(|size| *size <= maximum_bytes)
                    .ok_or_else(|| {
                        refused("packet full evidence credit exceeds original budget")
                    })?;
                planned.push((reference, bytes));
            }
            Ok(planned
                .into_iter()
                .map(|(reference, bytes)| InputPayload {
                    reference: reference.clone(),
                    bytes: bytes.to_vec(),
                })
                .collect())
        })();
        self.guard(&scope)?;
        result
    }

    fn consumption(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        outputs: &[Id],
    ) -> Result<InputPayload, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            self.validate_outcome(scope, original, outcome)?;
            if outputs != outcome.retained_outputs {
                return Err(refused(
                    "packet consumption omits or changes original outputs",
                ));
            }
            self.payload(
                &serde_json::json!({
                    "schema": "source-owned.packet-consumption.v4",
                    "operation": original.token().operation(),
                    "outputs": outputs,
                }),
                self.installation.maximum_authorization_bytes.min(8192),
            )
        })();
        self.guard(&scope)?;
        result
    }

    fn validate_retirement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        consumption: &InputPayload,
        response: &RetireResult,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.guard(&scope)?;
            consumption
                .reference
                .verify(&consumption.bytes)
                .map_err(unknown)?;
            let root = self.operation_root(&scope, original)?;
            let outcome = self.mapped_outcome(&scope, original, &root)?;
            let expected =
                self.consumption(scope, original, &outcome, &outcome.retained_outputs)?;
            if expected != *consumption
                || response.retired_operation_ids != [original.token().operation().clone()]
            {
                return Err(refused(
                    "packet original native consumption/retirement changed",
                ));
            }
            Ok(())
        })();
        self.guard(&scope)?;
        result
    }

    fn reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        owner: &OwnerIdentity,
    ) -> Result<NativeReclamationReceipt, OperationFailure> {
        self.local_owner()?;
        let retained = self
            .current_native
            .try_borrow()
            .map_err(|_| refused("connected original reclaimed owner read busy"))?;
        if !retained
            .as_ref()
            .is_some_and(|read| read.same_native_owner(native))
            || *owner != self.owner()
            || !native.kernel_resources_reclaimed().map_err(unknown)?
        {
            return Err(refused(
                "packet original native resources have not been authentically reclaimed",
            ));
        }
        // The installed source owns only process-local sockets/program state.
        // Kernel reaping and original empty-group proof release these handles;
        // output/receipt bodies remain in the common owning capsule separately.
        let proof = self.payload(
            &serde_json::json!({"schema":"source-owned.packet-reclaimed.v1",
            "original_pid":native.provider_pid(),"owner":owner,"actual_kernel_reaped":true,
            "implementation":self.installation.binding.compatibility.implementation}),
            self.installation.maximum_result_bytes,
        )?;
        Ok(NativeReclamationReceipt {
            owner: owner.clone(),
            receipt: proof.reference,
        })
    }

    fn validate_reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        if self.reclamation(native, &receipt.owner)? != *receipt {
            return Err(refused(
                "packet original source reclamation receipt changed",
            ));
        }
        Ok(())
    }

    fn input_batch(
        &self,
        batch: &RuntimeInputBatch,
        sequence: U64,
    ) -> Result<InputBatch, OperationFailure> {
        self.map_input_batch(batch, sequence)
    }
    fn input_acknowledgement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        response: &InputResult,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.guard(&scope)?;
        let result = self.staging_ack(scope, batch, response);
        self.guard(&scope)?;
        result
    }
    fn input_staging_context(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        request: &InputRequest,
    ) -> Result<(Extensions, Vec<InputPayload>), OperationFailure> {
        self.guard(&scope)?;
        let result = self.stage_context(scope, batch, request);
        self.guard(&scope)?;
        result
    }
    fn input_commit_context(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
        request: &InputRequest,
        staging: &InputResult,
    ) -> Result<(Extensions, Vec<InputPayload>), OperationFailure> {
        self.guard(&scope)?;
        let result = self.commit_context(scope, batch, commit, request, staging);
        self.guard(&scope)?;
        result
    }
    fn validate_input_commit(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
        request: &InputRequest,
        staging: &InputResult,
        response: &InputResult,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let result = self.check_input_commit(scope, batch, commit, request, staging, response);
        self.guard(&scope)?;
        result
    }
    fn boundary_policy(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<BoundaryPolicy, OperationFailure> {
        self.guard(&scope)?;
        let result = (|| {
            self.connected_authorization(&scope, original, None)?;
            Ok(BoundaryPolicy::OrdinaryStop)
        })();
        self.guard(&scope)?;
        result
    }
    fn input_authorization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        watermark: U64,
    ) -> Result<InputPayload, OperationFailure> {
        self.guard(&scope)?;
        let result = self.connected_authorization(&scope, original, Some(watermark));
        self.guard(&scope)?;
        result
    }
}
