//! Original common grants and actual delivered input beneath full exclusive cuts.

use super::*;
use crucible_node_transport::{
    envelope::Envelope,
    reference_packet::common::{
        PacketCommonActivation, PacketCommonBoundaryPolicy, PacketCommonOwner, PacketCommonRequest,
        PacketCommonRoute,
    },
};

pub(super) enum InstalledCommonGrant {
    Four(PacketConnectedCommonGrant),
    Complete(crucible_node_transport::reference_packet::common::PacketNative5CommonGrant),
}

pub(super) struct CommonGrantView<'a> {
    schema: &'a str,
    pub(super) operation: &'a Id,
    route: &'a PacketCommonRoute,
    activation: &'a PacketCommonActivation,
    pub(super) request: &'a PacketCommonRequest,
    pub(super) input_batch: &'a PacketConnectedCommonInput,
    input_watermark: U64,
}

impl InstalledCommonGrant {
    pub(super) fn view(&self) -> Result<CommonGrantView<'_>, OperationFailure> {
        let (schema, operation, route, activation, request, input_batch, input_watermark) =
            match self {
                Self::Four(grant) => (
                    &grant.schema,
                    &grant.operation,
                    &grant.route,
                    &grant.activation,
                    &grant.request,
                    &grant.input_batch,
                    grant.input_watermark,
                ),
                Self::Complete(grant) => (
                    &grant.schema,
                    &grant.operation,
                    &grant.route,
                    &grant.activation,
                    &grant.request,
                    grant.input.as_ref().ok_or_else(|| {
                        refused("complete reactive grant omitted actual consumed input")
                    })?,
                    grant.input_watermark,
                ),
            };
        Ok(CommonGrantView {
            schema,
            operation,
            route,
            activation,
            request,
            input_batch,
            input_watermark,
        })
    }
}

fn common_owner(owner: &OwnerIdentity) -> PacketCommonOwner {
    PacketCommonOwner {
        owner: owner.owner.clone(),
        incarnation: owner.incarnation.clone(),
        generation: owner.generation,
    }
}

// Baseline ExactRun parks before every position at its physical ceiling.
// Full same-time phases require their own BoundarySettle operation; translating
// one original full-phase interval into a shorter native interval is forbidden.
fn native_request(request: &OperationRequest) -> Result<PacketCommonRequest, OperationFailure> {
    match request {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        } if limit.microstep.get() == 0 && limit.phase == Phase::BoundaryControl => {
            Ok(PacketCommonRequest::ExactRun {
                start: *start,
                limit: *limit,
                boundary_policy: PacketCommonBoundaryPolicy::HorizonPark,
            })
        }
        OperationRequest::BoundarySettle { start, limit } if start.time_ps == limit.time_ps => {
            Ok(PacketCommonRequest::BoundarySettle {
                start: *start,
                limit: *limit,
            })
        }
        _ => Err(refused(
            "connected request is not representable by the native stop contract",
        )),
    }
}

impl PacketConnectedSemanticSource {
    pub(super) fn connected_authorization(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        watermark: Option<U64>,
    ) -> Result<InputPayload, OperationFailure> {
        self.guard(scope)?;
        // Refuse before original commit lookup or allocation of authorization.
        let request = native_request(original.request())?;
        self.world
            .authenticate_record(original.activation().record())?;
        let batch = original
            .inputs()
            .ok_or_else(|| refused("connected grant has no original coordinator input cut"))?;
        if original.token().route().node != self.installation.descriptor.id
            || original.token().route().owners != [self.owner()]
            || !batch.activation().same_authority(original.activation())
            || batch.activation().record() != original.activation().record()
        {
            return Err(refused("connected original input/grant owner changed"));
        }
        let (_, limit) = operation_interval(original)?;
        if limit > batch.cutoff() {
            return Err(refused(
                "connected original grant exceeds consumed producer-closed cut",
            ));
        }
        let (root, consumed) = self.original_commit(scope, batch, None)?;
        if watermark.is_some_and(|value| value != consumed.cut.batch_sequence) {
            return Err(refused("connected actual input watermark changed"));
        }
        let activation = original.activation().record();
        let operation = original.token().operation().clone();
        let route = PacketCommonRoute {
            node: original.token().route().node.clone(),
            owners: original
                .token()
                .route()
                .owners
                .iter()
                .map(common_owner)
                .collect(),
        };

        let activation = PacketCommonActivation {
            generation: activation.generation,
            activation_id: activation.activation_id.clone(),
            world_binding_hash: activation.world_binding_hash.clone(),
            owners: activation.owners.iter().map(common_owner).collect(),
            boundary: activation.boundary,
        };

        let input = PacketConnectedCommonInput {
            cut: consumed.cut.clone(),
            commit_request_id: consumed
                .original
                .request_id
                .0
                .clone()
                .ok_or_else(|| refused("connected commit original id absent"))?,
            commit_record: root,
        };

        let input_watermark = consumed.cut.batch_sequence;
        let maximum = self.installation.maximum_authorization_bytes.min(8192);
        let payload = if self.world.is_complete() {
            let body =
                crucible_node_transport::reference_packet::common::PacketNative5CommonGrant {
                    schema: "source-owned.packet-common-grant.v5".into(),
                    operation,
                    route,
                    activation,
                    request,
                    input: Some(input),
                    input_watermark,
                };
            self.payload(&body, maximum)?
        } else {
            let body = PacketConnectedCommonGrant {
                schema: "source-owned.packet-common-grant.v4".into(),
                operation,
                route,
                activation,
                request,
                input_batch: input,
                input_watermark,
            };
            self.payload(&body, maximum)?
        };
        self.guard(scope)?;
        Ok(payload)
    }

    pub(super) fn original_commit(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        through: Option<U64>,
    ) -> Result<(ContentRef, PacketCommitRecord), OperationFailure> {
        let mut found = None;
        for original in controller_originals(scope.controller) {
            if through.is_some_and(|sequence| original.request.sequence > sequence) {
                continue;
            }
            if original.request.method != Method::Input {
                continue;
            }
            let PacketInputContext::Commit { cut, .. } =
                PacketInputContext::decode(&original.request.extensions).map_err(unknown)?
            else {
                continue;
            };
            if &cut.batch_id != batch.batch() || &cut.stage_operation_id != batch.stage_operation()
            {
                continue;
            }
            let Some(response) = &original.response else {
                return Err(refused("connected original commitment is incomplete"));
            };
            let request =
                decode_request(original.request.method, &original.request.body).map_err(unknown)?;
            let Some(MethodResult::Input(response)) = decode_response(&request, &response.body)
                .map_err(unknown)?
                .result
            else {
                return Err(refused("connected original consumed answer absent"));
            };
            let root = self.input_root(scope, &response)?.0;
            let record = self.commit_record(scope, &root)?;
            let RequestBody::Input(request) = request else {
                return Err(refused("connected commitment original method"));
            };
            if record.cut != self.original_cut(batch, &request)? || found.is_some() {
                return Err(refused(
                    "connected opaque original input commitment changed/duplicated",
                ));
            }
            found = Some((root, record));
        }
        found.ok_or_else(|| refused("connected original input has no genuine consumed journal"))
    }

    pub(super) fn validate_original_grant(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        envelope: &Envelope,
        begin: &BeginRequest,
    ) -> Result<InstalledCommonGrant, OperationFailure> {
        let arguments: ExactRunArguments =
            serde_json::from_value(serde_json::Value::Object(begin.arguments.clone()))
                .map_err(unknown)?;
        arguments.validate().map_err(unknown)?;
        let common = if self.world.is_complete() {
            InstalledCommonGrant::Complete(self.object(scope, &arguments.input_authorization)?)
        } else {
            InstalledCommonGrant::Four(self.object(scope, &arguments.input_authorization)?)
        };
        let selected = common;
        let common = selected.view()?;
        let consumed = self.commit_record(scope, &common.input_batch.commit_record)?;
        let record = &common.activation;
        let activation: SavedRuntimeActivation =
            serde_json::from_value(self.world.coordinator().template["activation"].clone())
                .map_err(unknown)?;
        let (kind, start, limit) = match common.request {
            PacketCommonRequest::ExactRun {
                start,
                limit,
                boundary_policy: PacketCommonBoundaryPolicy::HorizonPark,
            } => (BeginKind::ExactRun, *start, *limit),
            PacketCommonRequest::BoundarySettle { start, limit }
                if start.time_ps == limit.time_ps =>
            {
                (BeginKind::BoundarySettle, *start, *limit)
            }
            _ => return Err(refused("connected original native stop convention")),
        };
        if common.schema
            != if self.world.is_complete() {
                "source-owned.packet-common-grant.v5"
            } else {
                "source-owned.packet-common-grant.v4"
            }
            || envelope.operation_id.0.as_ref() != Some(common.operation)
            || common.route.node != self.installation.descriptor.id
            || common.route.owners != [common_owner(&self.owner())]
            || record.generation != activation.generation
            || record.activation_id != activation.activation_id
            || record.world_binding_hash != activation.world_binding_hash
            || record.boundary != activation.boundary
            || record.owners
                != self
                    .world
                    .owners()
                    .iter()
                    .map(common_owner)
                    .collect::<Vec<_>>()
            || common.input_batch.cut != consumed.cut
            || common.input_batch.commit_request_id
                != consumed
                    .original
                    .request_id
                    .0
                    .clone()
                    .ok_or_else(|| refused("connected consumed request id absent"))?
            || common.input_watermark != consumed.cut.batch_sequence
            || common.input_watermark.get() == 0
            || arguments.input_watermark != common.input_watermark
            || &arguments.grant_id != common.operation
            || arguments.start != start
            || arguments.limit != limit
            || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
            || begin.kind != kind
            || begin.binding_hash != self.installation.owner.identity().map_err(unknown)?
            || begin.owner_generation != self.owner().generation
            || begin.activation_id.0.as_ref() != Some(&record.activation_id)
            || begin.world_generation != record.generation
            || arguments.participant_ids != [self.installation.descriptor.id.clone()]
            || arguments.realization_id != self.installation.realize.realization_id
            || arguments.activation_id != record.activation_id
            || arguments.world_generation != record.generation
            || arguments.owner_generation != self.owner().generation
            || arguments.input_epoch != self.installation.binding.authority.input_epoch
            || start > limit
            || limit > consumed.cut.cutoff
            || consumed.original.sequence >= envelope.sequence
        {
            return Err(refused(
                "connected native grant differs from complete actual original association",
            ));
        }
        Ok(selected)
    }

    pub(super) fn operation_root(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<ContentRef, OperationFailure> {
        for row in controller_originals(scope.controller) {
            if row.request.method == Method::Begin
                && row.request.operation_id.0.as_ref() == Some(original.token().operation())
            {
                return self
                    .completed_root(scope, &row.request)?
                    .ok_or_else(|| refused("connected original operation incomplete"));
            }
        }
        Err(refused("connected original Begin absent"))
    }

    pub(super) fn mapped_outcome(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        root: &ContentRef,
    ) -> Result<OperationOutcome, OperationFailure> {
        let record = self.native_record(scope, root)?;
        let grant = record
            .grant
            .as_ref()
            .ok_or_else(|| refused("connected original native grant absent"))?;
        let (start, limit) = operation_interval(original)?;
        if grant.operation != *original.token().operation()
            || grant.start != start
            || grant.limit != limit
            || !grant.complete
            || grant.inventory.reached != limit
        {
            return Err(refused("connected original whole interval outcome changed"));
        }
        let mut observation = self.observation(original.activation(), root, &record)?;
        let batch = original
            .inputs()
            .ok_or_else(|| refused("connected original outcome input absent"))?;
        let (_, consumed) = self.original_commit(scope, batch, Some(record.original.sequence))?;
        let commit_id = consumed
            .original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("connected original consumed id absent"))?;
        let mut consumed_inputs = Vec::new();
        let mut saw_pending = false;
        for delivery in batch.deliveries() {
            let found = record.inventory.delivered_inputs.iter().any(|actual| {
                actual.reaction.stage_operation == *batch.stage_operation()
                    && &actual.reaction.commit_request == commit_id
                    && actual.reaction.input_event == delivery.publication_id
                    && actual.reaction.input_producer == delivery.producer
                    && actual.reaction.input_sequence == delivery.source_sequence
                    && actual.reaction.parent == delivery.delivery
            });
            if found && saw_pending {
                return Err(refused(
                    "connected delivered input is not original canonical prefix",
                ));
            }
            if found {
                consumed_inputs.push(InputIdentity {
                    producer: delivery.producer.clone(),
                    source_sequence: delivery.source_sequence,
                });
            } else {
                saw_pending = true;
            }
        }
        observation.input_progress = Some(NativeInputProgress {
            batch: batch.batch().clone(),
            consumed: consumed_inputs,
            proof_ref: root.clone(),
        });
        self.guard(scope)?;
        Ok(OperationOutcome {
            operation: grant.operation.clone(),
            node: original.token().route().node.clone(),
            owners: original.token().route().owners.clone(),
            progress: ProgressEvidence::Exact {
                reached: limit,
                stop: crate::node_contract::StopReason::HorizonPark,
            },
            retained_outputs: grant
                .newborn
                .iter()
                .map(|row| row.output.event.clone())
                .collect(),
            scheduling: Some(observation),
        })
    }

    pub(in crate::node_adapters::cnp::semantic) fn observation(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        record: &PacketConnectedNativeRecord,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.world.authenticate_record(activation.record())?;
        Self::historical_scheduling17_data(
            &self.installation.descriptor,
            || self.owner(),
            &self.definition,
            root,
            record,
        )
    }

    /// Maps an already authenticated historical model without a live World.
    ///
    /// This is inert DATA construction shared with the live observation path.
    /// The caller independently authenticates native proof, installation and
    /// owner correspondence; this mapping grants no currentness or execution.
    ///
    /// # Errors
    /// Refuses a closed gate, an output unsupported by the exact model, or a
    /// model bound outside the unchanged finite superdense ordering profile.
    pub(in crate::node_adapters::cnp::semantic) fn historical_scheduling17_data(
        descriptor: &NodeDescriptor,
        owner: impl FnOnce() -> OwnerIdentity,
        definition: &PacketConnectedDefinition,
        root: &ContentRef,
        record: &PacketConnectedNativeRecord,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if record.inventory.gate_closed {
            return Err(refused("connected unopened original world"));
        }
        let mut publications = Vec::with_capacity(record.inventory.retained_outputs.len());
        for row in &record.inventory.retained_outputs {
            let endpoint = definition
                .output
                .as_ref()
                .ok_or_else(|| refused("connected sink invented public output"))?;
            let output = &row.output;
            publications.push(NativePublication {
                publication_id: output.event.clone(),
                endpoint: endpoint.clone(),
                native_sequence: output.sequence,
                publication: output.publication,
                evaluation: Some(output.evaluation),
                causal_parents: vec![row.pending.reaction.parent],
                payload: canonical::content_ref(
                    output.payload.as_slice(),
                    "application/octet-stream",
                )
                .map_err(unknown)?,
                payload_bytes: output.payload.as_slice().to_vec(),
            });
        }
        let bound = output_bound(&record.inventory, definition.output.is_some())?;
        Ok(NativeSchedulingObservation {
            node: descriptor.id.clone(),
            owners: vec![owner()],
            reached: record.inventory.reached,
            closed_prefix: record.inventory.reached,
            bounds: vec![NativeProducerBound {
                producer: descriptor.id.clone(),
                bound,
                proof_ref: root.clone(),
            }],
            publications,
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: root.clone(),
        })
    }
}

pub(super) fn output_bound(
    inventory: &PacketConnectedInventory,
    output: bool,
) -> Result<NativeOutputBound, OperationFailure> {
    if !output {
        return Ok(NativeOutputBound::AfterInstant(inventory.reached.time_ps));
    }
    // Future producer inputs remain possible. Empty local queues cannot issue EOF.
    // Scheduler At bounds must name Publication, preserving superdense order.
    let reached = inventory.reached;
    let microstep = if reached.phase <= Phase::Publication {
        reached.microstep
    } else {
        reached
            .microstep
            .checked_add(U64::new(1))
            .map_err(unknown)?
    };
    if microstep.get() >= 16 {
        return Err(refused("connected finite Publication bound exhausted"));
    }
    let mut bound = Position::new(reached.time_ps, microstep, Phase::Publication);
    for pending in &inventory.publications {
        bound = bound.min(pending.publication);
    }
    for reaction in &inventory.reactions {
        bound = bound.min(
            reaction
                .evaluation
                .reaction_publication(U64::new(16))
                .map_err(unknown)?,
        );
    }
    Ok(NativeOutputBound::At(bound))
}

#[cfg(test)]
mod native_stop_tests;
