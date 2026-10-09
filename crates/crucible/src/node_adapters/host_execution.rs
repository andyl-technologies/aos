//! Half-open native host-model reactions, publication and immutable input custody.

use std::collections::BTreeSet;

use crate::node_scheduling::{
    ExecutionPolicy, InputIdentity, InputPayload, NativeInputAcknowledgement, NativeInputProgress,
    NativeOutputBound, NativeProducerBound, NativePublication, NativeSchedulingObservation,
    RuntimeInputBatch,
};
use crucible_device::{
    BlockOp, BlockRequest,
    netlink::{Frame, FrameDraws, LinkFaults, PastDeliveryPolicy},
};
use crucible_node_contract::U64;

use super::*;

pub(super) struct Staged {
    pub(super) original: Rc<RuntimeInputBatch>,
    pub(super) acknowledgement: NativeInputAcknowledgement,
    pub(super) consumed: usize,
    pub(super) acknowledgement_body: InputPayload,
}

pub(super) fn validate_inventory(
    graph: &AdmittedGraph,
    node: &Id,
    model: &HostModel,
    facets: &[FacetKind],
) -> Result<(Option<Endpoint>, Option<Endpoint>), OperationFailure> {
    if !facets.contains(&FacetKind::ExactExecution) {
        return Ok((None, None));
    }
    if !matches!(
        graph.operating_policy(node),
        Some(ExecutionPolicy::Exact {
            boundary_settlement_ref: Some(_),
            ..
        })
    ) {
        return Err(failure(
            "host exact profile requires qualified boundary settlement",
        ));
    }
    if let HostModel::Link(link) = model {
        if link.snapshot().ticks_per_ns != 1_000 {
            return Err(failure(
                "host exact link requires the installed picosecond native clock",
            ));
        }
        if link.faults() != &LinkFaults::none() {
            return Err(failure(
                "host exact link requires an installed seeded fault executor",
            ));
        }
    }
    if let HostModel::SeededLink { link, definition } = model {
        let saved = definition.capture(link, 16 * 1024 * 1024)?;
        definition.restore(&saved, 16 * 1024 * 1024)?;
    }
    if let HostModel::Io(io) = model {
        let positive = if let Some(block) = io.block_device() {
            let latency = block.latency_model();
            latency.read_base_ns > 0
                && latency.write_base_ns > 0
                && latency.flush_ns > 0
                && latency.get_length_ns > 0
        } else if let Some(filesystem) = io.ninep_device() {
            let latency = filesystem.latency_model();
            latency.control_ns > 0 && latency.data_ns > 0
        } else {
            false
        };
        if !positive {
            return Err(failure(
                "host exact I/O profile requires positive native response latency floors",
            ));
        }
    }
    let descriptor = graph
        .descriptor(node)
        .ok_or_else(|| failure("host descriptor absent"))?;
    let mut input = None;
    let mut output = None;
    for port in &descriptor.ports {
        for lane in &port.lanes {
            let endpoint = Endpoint {
                node_id: node.clone(),
                port_id: port.id.clone(),
                lane_id: lane.id.clone(),
            };
            let slot = match lane.direction {
                Direction::Input => &mut input,
                Direction::Output => &mut output,
            };
            if slot.replace(endpoint).is_some() {
                return Err(failure(
                    "standalone host profile requires unique request and response lanes",
                ));
            }
        }
    }
    if matches!(model, HostModel::Clock(_)) {
        if input.is_some() || output.is_some() {
            return Err(failure(
                "integer host clock has no guest timer or external I/O lanes",
            ));
        }
    } else if matches!(model, HostModel::Semantics(model) if model.definition().inputs.is_empty()) {
        if input.is_some() || output.is_none() {
            return Err(failure(
                "closed semantic program requires one output and no ingress lane",
            ));
        }
    } else if matches!(model, HostModel::ScriptedSource(_)) {
        if input.is_some() || output.is_none() {
            return Err(failure(
                "scripted source requires one output and no ingress lane",
            ));
        }
    } else if input.is_none() || output.is_none() {
        return Err(failure(
            "host I/O profile lacks complete request/response inventory",
        ));
    }
    if let Some(endpoint) = &output {
        let lane = descriptor
            .ports
            .iter()
            .find(|port| port.id == endpoint.port_id)
            .and_then(|port| port.lanes.iter().find(|lane| lane.id == endpoint.lane_id))
            .ok_or_else(|| failure("host actual output lane absent"))?;
        let pending = match model {
            HostModel::Io(io) => io.pending_completion_keys().count(),
            HostModel::Link(link) | HostModel::SeededLink { link, .. } => link.inflight_len(),
            HostModel::Clock(_) => 0,
            HostModel::ScriptedSource(source) => source.requests().len() - source.cursor(),
            HostModel::Semantics(model) => model.pending_count(),
        };
        if pending as u64 > lane.maximum_pending_events.get() {
            return Err(failure(
                "host initial native pending queue exceeds its admitted lane ceiling",
            ));
        }
        if let HostModel::Link(link) | HostModel::SeededLink { link, .. } = model
            && link
                .snapshot()
                .inflight
                .iter()
                .any(|frame| frame.response.payload.len() as u64 > lane.maximum_payload_bytes.get())
        {
            return Err(failure(
                "host initial native frame exceeds its admitted lane ceiling",
            ));
        }
    }
    if let HostModel::ScriptedSource(source) = model {
        let endpoint = output
            .as_ref()
            .ok_or_else(|| failure("script output is absent"))?;
        let lane = descriptor
            .ports
            .iter()
            .find(|port| port.id == endpoint.port_id)
            .and_then(|port| port.lanes.iter().find(|lane| lane.id == endpoint.lane_id))
            .ok_or_else(|| failure("script output lane is absent"))?;
        let expected = match source.kind() {
            super::super::ScriptedRequestKind::Block => "crucible/block-request-v1",
            super::super::ScriptedRequestKind::Ninep => "crucible/filesystem-request-v1",
        };
        if lane.payload_schema.id.as_str() != expected
            || lane.payload_schema.version != 1
            || source
                .requests()
                .iter()
                .any(|request| request.payload.len() as u64 > lane.maximum_payload_bytes.get())
        {
            return Err(failure(
                "scripted source request codec or lane geometry differs",
            ));
        }
    }
    Ok((input, output))
}

impl HostModelNode {
    pub(super) fn same_world(&self, activation: &WorldActivation) -> bool {
        self.readiness.as_ref().map(|ready| &ready.0) == Some(activation.record())
            && self
                .activation_authority
                .as_ref()
                .is_none_or(|authority| Rc::ptr_eq(authority, &activation.authority))
    }

    pub(super) fn stage_exact_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        if !self.facets.contains(&FacetKind::ExactExecution)
            || self.quarantined
            || self.model.is_none()
            || !self.same_world(batch.activation())
            || batch.node() != &self.route.node
            || batch.owners() != self.route.owners
            || batch.deliveries().len() > self.limits.maximum_operations
        {
            return Err(failure(
                "host input cut lacks available original exact custody",
            ));
        }
        if let Some(staged) = &self.staged {
            if staged.original.batch() == batch.batch() {
                self.validate_staged_inputs(batch, &staged.acknowledgement)?;
                return Ok(staged.acknowledgement.clone());
            }
            if staged.consumed != staged.original.deliveries().len() {
                return Err(failure("host original input prefix remains unconsumed"));
            }
        }
        if self.input_history.contains_key(batch.stage_operation())
            || self.input_history.len() >= self.limits.maximum_operations
        {
            return Err(failure(
                "host original input staging identity or history ceiling exhausted",
            ));
        }
        let mut total = 0usize;
        for delivery in batch.deliveries() {
            if self.input_endpoint.as_ref() != Some(&delivery.consumer_endpoint)
                || delivery.delivery < self.boundary
            {
                return Err(failure(
                    "host staged input has foreign lane or past delivery",
                ));
            }
            let bytes = payload(batch, &delivery.payload)?;
            let input_lane = self.lane(self.input_endpoint.as_ref())?;
            let output_lane = self.lane(self.output_endpoint.as_ref())?;
            if bytes.len() as u64 > input_lane.maximum_payload_bytes.get()
                || batch.deliveries().len() as u64 > input_lane.maximum_pending_events.get()
                || canonical::content_ref(bytes, &delivery.payload.media_type)
                    .map_err(|error| failure(&error.to_string()))?
                    != delivery.payload
            {
                return Err(failure(
                    "host input cut violates the immutable lane payload/event contract",
                ));
            }
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| failure("host input byte count overflow"))?;
            if total > self.limits.maximum_capture_bytes {
                return Err(failure("host immutable input cut exceeds byte ceiling"));
            }
            match self.model.as_ref() {
                Some(HostModel::Io(io)) if io.block_device().is_some() => {
                    let request =
                        BlockRequest::decode(bytes).map_err(|error| failure(&error.to_string()))?;
                    let response_bytes = match request.op {
                        BlockOp::Read => u64::from(request.count),
                        BlockOp::GetLength => 8,
                        _ => 1,
                    }
                    .checked_add(crucible_device::block::RESPONSE_HEADER_LEN as u64)
                    .ok_or_else(|| failure("host block response geometry overflow"))?;
                    if response_bytes > output_lane.maximum_payload_bytes.get() {
                        return Err(failure(
                            "host block request exceeds the realized response lane geometry",
                        ));
                    }
                }
                Some(HostModel::Io(_)) => {
                    let message = crucible_device::ninep::codec::Message::decode(bytes)
                        .map_err(|error| failure(&error.to_string()))?;
                    if let crucible_device::ninep::codec::TMessage::Read { count, .. }
                    | crucible_device::ninep::codec::TMessage::Readdir { count, .. } =
                        message.body
                        && u64::from(count)
                            .checked_add(11)
                            .is_none_or(|size| size > output_lane.maximum_payload_bytes.get())
                    {
                        return Err(failure(
                            "host filesystem read exceeds the realized response lane geometry",
                        ));
                    }
                }
                Some(HostModel::Link(_) | HostModel::SeededLink { .. }) => {
                    u32::try_from(delivery.source_sequence.get())
                        .map_err(|_| failure("native link frame correlation exhausted"))?;
                    if bytes.len() as u64 > output_lane.maximum_payload_bytes.get() {
                        return Err(failure(
                            "native link frame exceeds its realized output lane geometry",
                        ));
                    }
                }
                Some(HostModel::Semantics(model)) => {
                    model.validate_input(delivery, bytes)?;
                }
                _ => return Err(failure("host clock cannot consume guest requests")),
            }
        }
        let retained_bytes = self
            .input_history
            .values()
            .chain(self.staged.iter())
            .try_fold(total, |total, input| {
                input
                    .original
                    .payloads()
                    .iter()
                    .try_fold(total, |total, payload| {
                        total
                            .checked_add(payload.bytes.len())
                            .ok_or_else(|| failure("host retained input byte count overflow"))
                    })
            })?;
        if retained_bytes > self.limits.maximum_capture_bytes {
            return Err(failure(
                "host retained native input history exceeds byte ceiling",
            ));
        }
        let proof_bytes = canonical::canonical_json(
            &serde_json::json!({"node":self.route.node,"owners":self.route.owners,"batch":batch.batch(),"inventory":batch.inventory(),"retained_bytes":retained_bytes.to_string()}),
        ).map_err(|error| failure(&error.to_string()))?;
        let proof_ref = canonical::content_ref(&proof_bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        let acknowledgement = NativeInputAcknowledgement {
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            node: batch.node().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            proof_ref,
        };
        self.activation_authority = Some(Rc::clone(&batch.activation().authority));
        if let Some(previous) = self.staged.take() {
            self.input_history
                .insert(previous.original.stage_operation().clone(), previous);
        }
        self.staged = Some(Staged {
            original: Rc::new(batch.retained_copy()),
            acknowledgement: acknowledgement.clone(),
            consumed: 0,
            acknowledgement_body: InputPayload {
                reference: acknowledgement.proof_ref.clone(),
                bytes: proof_bytes,
            },
        });
        Ok(acknowledgement)
    }

    pub(super) fn validate_staged_inputs(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        let staged = self
            .staged
            .as_ref()
            .filter(|input| input.original.stage_operation() == batch.stage_operation())
            .or_else(|| self.input_history.get(batch.stage_operation()))
            .ok_or_else(|| failure("host original input buffer unavailable"))?;
        if self.quarantined
            || self.model.is_none()
            || !self.same_world(batch.activation())
            || staged.acknowledgement != *acknowledgement
            || staged.original.batch() != batch.batch()
            || staged.original.stage_operation() != batch.stage_operation()
            || staged.original.inventory() != batch.inventory()
            || staged.original.deliveries() != batch.deliveries()
            || staged.original.payloads() != batch.payloads()
            || !Rc::ptr_eq(
                &staged.original.activation().authority,
                &batch.activation().authority,
            )
        {
            return Err(failure(
                "host acknowledgement does not authenticate retained original native buffers",
            ));
        }
        Ok(())
    }

    pub(super) fn begin_exact(&mut self, admission: &OperationAdmission) -> Submission {
        let checked = self.preflight_exact(admission);
        if let Err(error) = checked {
            return Submission::Refused(Refusal {
                reason: error.reason,
            });
        }
        self.activation_authority = Some(Rc::clone(&admission.activation.authority));
        match self.execute_exact(admission) {
            Ok((outcome, evidence)) => {
                self.completed.insert(
                    outcome.operation.clone(),
                    Completed {
                        original: admission.clone(),
                        outcome,
                        capture: None,
                        acknowledged: false,
                        evidence,
                    },
                );
                Submission::Accepted
            }
            Err(mut error) => {
                // Even a model validation error can occur after an earlier
                // request in this original prefix mutated persistent state.
                error.effects = EffectKnowledge::Unknown;
                self.failed.insert(
                    admission.token().operation().clone(),
                    (admission.clone(), error),
                );
                self.quarantined = true;
                Submission::Uncertain(EffectKnowledge::Unknown)
            }
        }
    }

    fn preflight_exact(&self, admission: &OperationAdmission) -> Result<(), OperationFailure> {
        if !self.facets.contains(&FacetKind::ExactExecution)
            || self.quarantined
            || self.model.is_none()
            || !self.same_world(admission.activation())
            || admission.token().route() != &self.route
            || self
                .completed
                .len()
                .checked_add(self.failed.len())
                .is_none_or(|count| count >= self.limits.maximum_operations)
            || self.completed.contains_key(admission.token().operation())
            || self.failed.contains_key(admission.token().operation())
            || self.completed.values().any(|completed| {
                !completed.acknowledged && !completed.outcome.retained_outputs.is_empty()
            })
        {
            return Err(failure(
                "host exact grant lacks available original activated custody",
            ));
        }
        let (start, limit) = interval(admission.request())?;
        if start != self.boundary || limit <= start {
            return Err(failure("host exact grant changed authentic boundary"));
        }
        if let Some(inputs) = admission.inputs() {
            let staged = self
                .staged
                .as_ref()
                .ok_or_else(|| failure("host execution input cut is not staged"))?;
            if staged.original.batch() != inputs.batch() {
                return Err(failure(
                    "host execution linked a historical consumed input batch",
                ));
            }
            self.validate_staged_inputs(inputs, &staged.acknowledgement)?;
            // A closed prefix cannot pass an unconsumed original delivery.
            // Check the complete original batch before any request can mutate
            // native state, including a phase-only cut excluding its Reaction.
            for delivery in staged
                .original
                .deliveries()
                .iter()
                .skip(staged.consumed)
                .take_while(|delivery| delivery.delivery < limit)
            {
                if self.input_reaction(delivery.delivery)? >= limit {
                    return Err(failure(
                        "host exclusive cut excludes the original input reaction",
                    ));
                }
            }
        } else if self
            .staged
            .as_ref()
            .is_some_and(|staged| staged.consumed < staged.original.deliveries().len())
        {
            return Err(failure(
                "host exact grant omitted retained unconsumed input",
            ));
        }
        Ok(())
    }

    fn execute_exact(
        &mut self,
        admission: &OperationAdmission,
    ) -> Result<(OperationOutcome, Vec<InputPayload>), OperationFailure> {
        let (start, limit) = interval(admission.request())?;
        let mut publications = Vec::new();
        loop {
            let input_position = admission
                .inputs()
                .and(self.staged.as_ref())
                .and_then(|staged| staged.original.deliveries().get(staged.consumed))
                .map(|delivery| self.input_reaction(delivery.delivery))
                .transpose()?;
            let local_position = match self.model.as_ref() {
                Some(HostModel::ScriptedSource(source)) => source.next_position(),
                Some(HostModel::Semantics(model)) => model.next_position(),
                _ => self.next_local_event().map(root_reaction),
            };
            let next = match (input_position, local_position) {
                (Some(input), Some(local)) => Some(input.min(local)),
                (input, local) => input.or(local),
            };
            let Some(next) = next else { break };
            if next >= limit {
                break;
            }
            if next < start {
                return Err(failure(
                    "host has unexecuted semantic work before its authenticated grant",
                ));
            }
            if input_position == Some(next) {
                self.consume_input()?;
            } else {
                if let Some(HostModel::ScriptedSource(source)) = self.model.as_mut()
                    && !source.evaluated()
                {
                    source.evaluate();
                }
                // Source evaluation births the immutable future publication in
                // this original grant. Transfer its bytes now even when the
                // phase-one visibility lies beyond the exclusive cut; common
                // coordinator custody schedules it later without reevaluation.
                let evaluation = if matches!(self.model, Some(HostModel::ScriptedSource(_))) {
                    root_reaction(next.time_ps.get())
                } else {
                    next
                };
                let mut due = self.publish_local(evaluation, admission.token().operation())?;
                publications.append(&mut due);
                if publications.len() > self.limits.maximum_operations {
                    return Err(failure("host publication count exceeds custody ceiling"));
                }
            }
        }
        // Native clock advancement is administrative horizon parking. All
        // actual request/alarm transitions at the exclusive ceiling remain in
        // the original buffers and queues for a later settlement grant.
        if let Some(HostModel::Clock(clock)) = self.model.as_mut() {
            clock
                .advance_to(limit.time_ps.get())
                .map_err(|error| failure(&error.to_string()))?;
        }
        if let Some(HostModel::ScriptedSource(source)) = self.model.as_mut() {
            source.park(limit.time_ps.get())?;
        }
        if let Some(HostModel::Semantics(model)) = self.model.as_mut() {
            model.park(limit)?;
        }
        self.boundary = limit;
        let original_objects = state::state_receipt_objects(self)?;
        let proof_ref = original_objects[0].reference.clone();
        let mut evidence = Vec::new();
        let mut references = BTreeSet::new();
        for object in original_objects {
            if references.insert(object.reference.clone()) {
                evidence.push(object);
            }
        }
        for publication in &publications {
            if references.insert(publication.payload.clone()) {
                evidence.push(InputPayload {
                    reference: publication.payload.clone(),
                    bytes: publication.payload_bytes.clone(),
                });
            }
        }
        let retained_bytes = self
            .completed
            .values()
            .flat_map(|completed| &completed.evidence)
            .chain(&evidence)
            .try_fold(0usize, |size, object| size.checked_add(object.bytes.len()));
        if retained_bytes.is_none_or(|bytes| bytes > self.limits.maximum_capture_bytes) {
            return Err(failure(
                "host original receipt registry exceeds native custody ceiling",
            ));
        }
        let input_progress = admission.inputs().map(|inputs| {
            let consumed = self.staged.as_ref().map_or(0, |staged| staged.consumed);
            NativeInputProgress {
                batch: inputs.batch().clone(),
                consumed: inputs
                    .deliveries()
                    .iter()
                    .take(consumed)
                    .map(|delivery| InputIdentity {
                        producer: delivery.producer.clone(),
                        source_sequence: delivery.source_sequence,
                    })
                    .collect(),
                proof_ref: proof_ref.clone(),
            }
        });
        let observation = NativeSchedulingObservation {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            reached: self.boundary,
            closed_prefix: self.boundary,
            bounds: vec![NativeProducerBound {
                producer: self.route.node.clone(),
                bound: self.output_bound(),
                proof_ref: proof_ref.clone(),
            }],
            publications,
            input_progress,
            external_inputs: Vec::new(),
            proof_ref,
        };
        Ok((
            OperationOutcome {
                operation: admission.token().operation().clone(),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                progress: ProgressEvidence::Exact {
                    reached: self.boundary,
                    stop: StopReason::HorizonPark,
                },
                retained_outputs: observation
                    .publications
                    .iter()
                    .map(|publication| publication.publication_id.clone())
                    .collect(),
                scheduling: Some(observation),
            },
            evidence,
        ))
    }

    pub(super) fn next_local_event(&self) -> Option<u64> {
        match self.model.as_ref() {
            Some(HostModel::Io(io)) => io.next_exact_local_event(),
            Some(HostModel::Link(link) | HostModel::SeededLink { link, .. }) => {
                link.next_exact_local_event()
            }
            Some(HostModel::ScriptedSource(source)) => source.next_time(),
            Some(HostModel::Semantics(model)) => model.next_position().map(|at| at.time_ps.get()),
            _ => None,
        }
    }

    fn input_reaction(&self, delivery: Position) -> Result<Position, OperationFailure> {
        if matches!(self.model.as_ref(), Some(HostModel::Semantics(_))) {
            // The unchanged semantic codec records a strict successor reaction.
            // Select it before the exclusive grant comparison and consumption.
            let microstep = delivery
                .microstep
                .checked_add(U64::new(1))
                .map_err(|_| failure("semantic input reaction microstep exhausted"))?;
            if microstep >= self.maximum_microsteps {
                return Err(failure(
                    "semantic input reaction exceeds selected microstep ceiling",
                ));
            }
            Ok(Position::new(delivery.time_ps, microstep, Phase::Reaction))
        } else {
            Ok(reaction(delivery))
        }
    }

    fn consume_input(&mut self) -> Result<(), OperationFailure> {
        let pending_limit = self
            .lane(self.output_endpoint.as_ref())?
            .maximum_pending_events
            .get();
        let pending = match self.model.as_ref() {
            Some(HostModel::Io(io)) => io.pending_completion_keys().count(),
            Some(HostModel::Link(link) | HostModel::SeededLink { link, .. }) => link.inflight_len(),
            Some(HostModel::Semantics(model)) => model.pending_count(),
            _ => 0,
        };
        if pending as u64 >= pending_limit {
            return Err(failure(
                "host native output queue reached its admitted event ceiling",
            ));
        }
        let staged = self
            .staged
            .as_ref()
            .ok_or_else(|| failure("original host input missing"))?;
        let delivery = staged
            .original
            .deliveries()
            .get(staged.consumed)
            .ok_or_else(|| failure("original host input prefix exhausted"))?;
        let bytes = payload(&staged.original, &delivery.payload)?;
        let cause = vec![delivery.delivery];
        let input_reaction = self.input_reaction(delivery.delivery)?;
        match self.model.as_mut() {
            Some(HostModel::Io(io)) => {
                let before: BTreeSet<_> = io.pending_completion_keys().collect();
                if io.block_device().is_some() {
                    let request =
                        BlockRequest::decode(bytes).map_err(|error| failure(&error.to_string()))?;
                    io.submit_fifo(delivery.delivery.time_ps.get(), &request)
                        .map_err(|error| failure(&error.to_string()))?;
                } else {
                    io.submit_ninep_frame(delivery.delivery.time_ps.get(), bytes)
                        .map_err(|error| failure(&error.to_string()))?;
                }
                for key in io
                    .pending_completion_keys()
                    .filter(|key| !before.contains(key))
                {
                    if key.0 <= delivery.delivery.time_ps.get() {
                        return Err(failure(
                            "installed I/O profile violated its positive response latency contract",
                        ));
                    }
                    self.pending_causes.insert(key, cause.clone());
                }
            }
            Some(HostModel::Link(link)) => {
                let frame_id = u32::try_from(delivery.source_sequence.get())
                    .map_err(|_| failure("link correlation overflow"))?;
                let output = link
                    .emit(
                        &Frame::new(delivery.delivery.time_ps.get(), frame_id, bytes.to_vec()),
                        &FrameDraws::default(),
                        PastDeliveryPolicy::FailLoud,
                    )
                    .map_err(|error| failure(&error.to_string()))?;
                for frame in output.deliveries {
                    self.pending_causes.insert(
                        (frame.key.delivery_icount, frame.key.src_node, frame.key.seq),
                        cause.clone(),
                    );
                }
            }
            Some(HostModel::SeededLink { link, definition }) => {
                let frame_id = u32::try_from(delivery.source_sequence.get())
                    .map_err(|_| failure("seeded link correlation overflow"))?;
                // The existing native snapshot owns the cursor; a fresh stream
                // resumes precisely that cursor rather than redrawing old faults.
                let mut rng = link.rng(
                    definition.seed.get(),
                    "crucible/seeded-link-v1",
                    definition.stream.as_str(),
                );
                let output = link
                    .emit_from_rng(
                        &Frame::new(delivery.delivery.time_ps.get(), frame_id, bytes.to_vec()),
                        &mut rng,
                        PastDeliveryPolicy::FailLoud,
                    )
                    .map_err(|error| failure(&error.to_string()))?;
                for frame in output.deliveries {
                    self.pending_causes.insert(
                        (frame.key.delivery_icount, frame.key.src_node, frame.key.seq),
                        cause.clone(),
                    );
                }
            }
            Some(HostModel::Semantics(model)) => {
                model.consume(delivery, bytes, input_reaction)?;
            }
            _ => return Err(failure("host clock has no input reaction")),
        }
        if self.pending_causes.len() > self.limits.maximum_operations {
            return Err(failure("host causal continuation exceeds event ceiling"));
        }
        if let Some(staged) = self.staged.as_mut() {
            staged.consumed += 1;
        }
        Ok(())
    }

    fn publish_local(
        &mut self,
        evaluation: Position,
        operation: &Id,
    ) -> Result<Vec<NativePublication>, OperationFailure> {
        if matches!(self.model.as_ref(), Some(HostModel::Semantics(_))) {
            return self.publish_semantic(evaluation, operation);
        }
        let maximum_payload_bytes = self
            .lane(self.output_endpoint.as_ref())?
            .maximum_payload_bytes
            .get();
        let mut outputs = Vec::new();
        match self.model.as_mut() {
            Some(HostModel::Io(io)) => {
                for due in io.deliver_due(evaluation.time_ps.get()) {
                    if let Some(completion) = due.completion {
                        outputs.push((
                            (due.delivery_icount, due.source_node, due.sequence),
                            completion.payload,
                        ));
                    } else {
                        self.pending_causes.remove(&(
                            due.delivery_icount,
                            due.source_node,
                            due.sequence,
                        ));
                    }
                }
            }
            Some(HostModel::Link(link) | HostModel::SeededLink { link, .. }) => {
                while let Some(due) = link.next_delivery(evaluation.time_ps.get()) {
                    outputs.push((
                        (due.key.delivery_icount, due.key.src_node, due.key.seq),
                        due.payload,
                    ));
                }
            }
            Some(HostModel::ScriptedSource(source)) => {
                outputs.extend(source.publish_due(evaluation.time_ps.get()));
            }
            _ => return Err(failure("clock has no armed native alarm")),
        }
        let endpoint = self
            .output_endpoint
            .clone()
            .ok_or_else(|| failure("native response output lane missing"))?;
        let mut publications = Vec::with_capacity(outputs.len());
        for (key, payload_bytes) in outputs {
            if payload_bytes.len() as u64 > maximum_payload_bytes {
                return Err(failure(
                    "host native response violated its admitted payload ceiling",
                ));
            }
            let causal_parents = self.pending_causes.remove(&key).unwrap_or_default();
            let publication = crate::node_scheduling::event::reaction_publication(
                &causal_parents,
                evaluation,
                evaluation.time_ps,
                self.maximum_microsteps,
            )
            .map_err(|error| failure(&error.to_string()))?;
            let native_sequence = self.native_sequence;
            self.native_sequence = self
                .native_sequence
                .checked_add(1)
                .ok_or_else(|| failure("host publication sequence exhausted"))?;
            let publication_id = Id::new(format!(
                "host-output/{}",
                canonical::hash(
                    "cnp.host-publication.v1",
                    format!("{operation}/{native_sequence}").as_bytes()
                )
                .map_err(|error| failure(&error.to_string()))?
                .digest
            ))
            .map_err(|error| failure(&error.to_string()))?;
            let payload = canonical::content_ref(&payload_bytes, "application/octet-stream")
                .map_err(|error| failure(&error.to_string()))?;
            publications.push(NativePublication {
                publication_id,
                endpoint: endpoint.clone(),
                native_sequence: native_sequence.into(),
                publication,
                evaluation: Some(evaluation),
                causal_parents,
                payload,
                payload_bytes,
            });
        }
        Ok(publications)
    }

    fn publish_semantic(
        &mut self,
        evaluation: Position,
        operation: &Id,
    ) -> Result<Vec<NativePublication>, OperationFailure> {
        let endpoint = self
            .output_endpoint
            .clone()
            .ok_or_else(|| failure("semantic original output endpoint absent"))?;
        let maximum_payload_bytes = self.lane(Some(&endpoint))?.maximum_payload_bytes.get();
        let Some(HostModel::Semantics(model)) = self.model.as_mut() else {
            return Err(failure("semantic native model absent"));
        };
        if model.pending_count() == 0 {
            model.settle(evaluation)?;
        }
        let outputs = model.take_publications_at(evaluation);
        let mut publications = Vec::with_capacity(outputs.len());
        for output in outputs {
            let payload_bytes = output.bytes.as_slice().to_vec();
            if payload_bytes.len() as u64 > maximum_payload_bytes {
                return Err(failure(
                    "semantic original output exceeds selected lane ceiling",
                ));
            }
            let publication = crate::node_scheduling::event::reaction_publication(
                &output.parents,
                output.evaluation,
                output.evaluation.time_ps,
                self.maximum_microsteps,
            )
            .map_err(|error| failure(&error.to_string()))?;
            let native_sequence = self.native_sequence;
            self.native_sequence = self
                .native_sequence
                .checked_add(1)
                .ok_or_else(|| failure("semantic original sequence exhausted"))?;
            let publication_id = Id::new(format!(
                "host-output/{}",
                canonical::hash(
                    "cnp.host-publication.v1",
                    format!("{operation}/{native_sequence}").as_bytes()
                )
                .map_err(|error| failure(&error.to_string()))?
                .digest
            ))
            .map_err(|error| failure(&error.to_string()))?;
            let payload = canonical::content_ref(&payload_bytes, "application/octet-stream")
                .map_err(|error| failure(&error.to_string()))?;
            publications.push(NativePublication {
                publication_id,
                endpoint: endpoint.clone(),
                native_sequence: native_sequence.into(),
                publication,
                evaluation: Some(output.evaluation),
                causal_parents: output.parents,
                payload,
                payload_bytes,
            });
        }
        Ok(publications)
    }

    fn output_bound(&self) -> NativeOutputBound {
        if self.output_endpoint.is_none() {
            // The qualified integer clock has no public outputs, armed guest
            // timers or autonomous worker, so this covers its entire inventory.
            NativeOutputBound::AfterInstant(U64::new(u64::MAX))
        } else if let Some(HostModel::Semantics(model)) = self.model.as_ref() {
            // Input closure is independently established by the terminal gate.
            // An empty evaluator queue does not imply an unconditional EOF.
            let at = model.next_position().unwrap_or(self.boundary);
            let microstep = if at.phase > Phase::Publication {
                at.microstep.checked_add(U64::new(1)).ok()
            } else {
                Some(at.microstep)
            };
            microstep
                .filter(|microstep| *microstep < self.maximum_microsteps)
                .map_or(NativeOutputBound::Unknown, |microstep| {
                    NativeOutputBound::At(Position::new(at.time_ps, microstep, Phase::Publication))
                })
        } else if let Some(HostModel::ScriptedSource(source)) = self.model.as_ref() {
            // This original cursor covers all immutable future publications.
            // At EOF, with no ingress or autonomy, the complete observation
            // closes every representable instant. The scheduler represents that
            // strict bound as mathematical top rather than computing MAX + 1.
            source.next_time().map_or(
                NativeOutputBound::AfterInstant(U64::new(u64::MAX)),
                |time| {
                    NativeOutputBound::At(Position::new(time.into(), 1.into(), Phase::Publication))
                },
            )
        } else if let Some(HostModel::Link(link) | HostModel::SeededLink { link, .. }) =
            self.model.as_ref()
        {
            // The installed fault-free model has no autonomous publications.
            // Every unseen request is at or beyond the authenticated half-open
            // cursor and requires the positive native latency floor. Already
            // scheduled native deliveries independently cap this bound.
            let unseen = self
                .boundary
                .time_ps
                .get()
                .saturating_add(link.floor_ticks());
            let earliest = self
                .next_local_event()
                .map_or(unseen, |pending| pending.min(unseen));
            NativeOutputBound::At(Position::new(
                U64::new(earliest),
                0.into(),
                Phase::Publication,
            ))
        } else {
            // Any unseen admitted request can cause a response at the current
            // physical instant. Pending queue absence proves no stronger bound.
            NativeOutputBound::At(Position::new(
                self.boundary.time_ps,
                0.into(),
                Phase::Publication,
            ))
        }
    }

    pub(super) fn observe_exact(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if !self.facets.contains(&FacetKind::ExactExecution)
            || !self.same_world(activation)
            || self.quarantined
            || self.model.is_none()
        {
            return Err(failure("host native producer observation unavailable"));
        }
        let proof_ref = self.native_state_ref()?;
        let observation = NativeSchedulingObservation {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            reached: self.boundary,
            closed_prefix: self.boundary,
            bounds: vec![NativeProducerBound {
                producer: self.route.node.clone(),
                bound: self.output_bound(),
                proof_ref: proof_ref.clone(),
            }],
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref,
        };
        self.activation_authority = Some(Rc::clone(&activation.authority));
        self.scheduling_observation = Some((activation.clone(), observation.clone()));
        Ok(observation)
    }

    pub(super) fn validate_exact_observation(
        &self,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        let Some((original, retained)) = &self.scheduling_observation else {
            return Err(failure("host original observation unavailable"));
        };
        if !self.same_world(activation)
            || !Rc::ptr_eq(&original.authority, &activation.authority)
            || self.quarantined
            || self.model.is_none()
            || retained != observation
            || observation.reached != self.boundary
            || observation.proof_ref != self.native_state_ref()?
        {
            return Err(failure(
                "host observation lost actual complete state custody",
            ));
        }
        Ok(())
    }

    fn native_state_ref(&self) -> Result<ContentRef, OperationFailure> {
        canonical::content_ref(&state::state_receipt(self)?, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))
    }

    pub(super) fn lane(
        &self,
        endpoint: Option<&Endpoint>,
    ) -> Result<&crucible_node_contract::LaneDescriptor, OperationFailure> {
        let endpoint = endpoint.ok_or_else(|| failure("host native lane inventory unavailable"))?;
        self.descriptor
            .ports
            .iter()
            .find(|port| port.id == endpoint.port_id)
            .and_then(|port| port.lanes.iter().find(|lane| lane.id == endpoint.lane_id))
            .ok_or_else(|| failure("host native lane absent from immutable descriptor"))
    }

    pub(super) fn capture_continuation(&self) -> Result<Vec<u8>, OperationFailure> {
        if !self.facets.contains(&FacetKind::ExactExecution) {
            return self.capture();
        }
        state::encode(self)
    }
}

fn payload<'a>(
    batch: &'a RuntimeInputBatch,
    reference: &ContentRef,
) -> Result<&'a [u8], OperationFailure> {
    batch
        .payloads()
        .iter()
        .find(|payload| &payload.reference == reference)
        .map(|payload| payload.bytes.as_slice())
        .ok_or_else(|| failure("host original immutable payload missing"))
}

fn reaction(delivery: Position) -> Position {
    Position::new(delivery.time_ps, delivery.microstep, Phase::Reaction)
}

fn root_reaction(time: u64) -> Position {
    Position::new(time.into(), 0.into(), Phase::Reaction)
}

fn interval(request: &OperationRequest) -> Result<(Position, Position), OperationFailure> {
    match request {
        OperationRequest::ExactRun { start, limit, .. }
        | OperationRequest::BoundarySettle { start, limit } => Ok((*start, *limit)),
        _ => Err(failure("host operation is not an exact semantic grant")),
    }
}
