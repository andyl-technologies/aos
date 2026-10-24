//! Derives complete common expectations from fixed programs and original input journals.

use super::*;
use crate::node_qualification::packet_collection::connected::{
    PacketConnectedCase, PacketConnectedCaseKind, PacketConnectedGrant as ScheduledGrant,
};
use crucible_engine::node_contract::{
    OperationOutcome, OperationRequest, OwnerIdentity, ProgressEvidence, StopReason,
};
use crucible_engine::node_scheduling::{
    InputIdentity, InputPayload, NativeInputProgress, NativeOutputBound, NativeProducerBound,
    NativePublication, NativeSchedulingObservation,
};
use crucible_node_format::{Endpoint, Phase, Position, U64};
use crucible_node_transport::reference_packet::{
    PacketPublication,
    connected::{
        PacketConnectedGrant, PacketConnectedPublication, PacketPendingPublication, PacketReaction,
    },
};
use serde::Serialize;

mod model;

impl PacketCompleteNativeOracle {
    /// Checks the immutable case reservation before original native execution.
    ///
    /// # Errors
    /// Refuses a changed plan/oracle/ceiling or a case lacking an exact operation.
    pub fn authenticate_case_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        self.template(case)?;
        if plan != &self.plan
            || maximum_bytes != MAXIMUM_SNAPSHOT
            || !plan
                .cases
                .iter()
                .any(|row| row.id == case && row.oracle == *oracle)
        {
            return Err(refused());
        }
        self.preflight()
    }

    /// Derives a whole expectation before reading the common runtime outcome.
    ///
    /// # Errors
    /// Refuses missing original receipts/effects, changed exclusive cuts, incomplete
    /// source-consumed input custody or a case without an independent native oracle.
    pub fn expected_completion(
        &self,
        case: &str,
    ) -> Result<ExactCompletionCase, QualificationError> {
        let (selected, scheduled, member) = self.template(case)?;
        self.roster.current_native().map_err(native_failure)?;
        let observed = self.observed.try_borrow().map_err(|_| refused())?;
        if observed.failed {
            return Err(refused());
        }
        let planned = self
            .plan
            .cases
            .iter()
            .find(|row| row.id == case)
            .ok_or_else(refused)?;
        let (start, limit) = interval(&scheduled.request)?;
        let seal = self.completion_seal(&observed, member, scheduled, start, limit)?;
        seal.reference.verify(&seal.bytes)?;
        let installation = self.roster.sources[member].installation();
        let owner = OwnerIdentity {
            owner: installation.owner.owner.id.clone(),
            incarnation: installation.binding.authority.incarnation_id.clone(),
            generation: installation.binding.authority.owner_generation,
        };
        let (bound, publications, retained, input_progress, input) =
            match (&seal.body, &self.programmes[member]) {
                (
                    NativeBody::Producer(record),
                    PacketConnectedSourceProgram::Producer { program },
                ) => {
                    let grant = record.grant.as_ref().ok_or_else(refused)?;
                    let completed: Vec<_> = program
                        .events
                        .iter()
                        .filter(|event| event.completion < limit)
                        .collect();
                    let private = completed
                        .iter()
                        .filter(|event| event.payload.is_none())
                        .count();
                    let packets = completed.len() - private;
                    if grant.inventory.reached != limit
                        || grant.inventory.gate_closed
                        || grant.inventory.private_mutations != U64::new(private as u64)
                        || grant.inventory.packet_effects != U64::new(packets as u64)
                        || grant.inventory.pending
                            != program
                                .events
                                .iter()
                                .filter(|event| event.completion >= limit)
                                .cloned()
                                .collect::<Vec<_>>()
                        || observed.effects[member].len() < completed.len()
                    {
                        return Err(refused());
                    }
                    let mut sequence = 0;
                    let mut outputs = Vec::new();
                    for event in &program.events {
                        if event.completion >= limit {
                            break;
                        }
                        if let Some(payload) = &event.payload {
                            sequence += 1;
                            if event.completion >= start {
                                outputs.push(PacketPublication {
                                    event: event.id.clone(),
                                    operation: scheduled.operation.clone(),
                                    sequence: U64::new(sequence),
                                    evaluation: event.evaluation,
                                    publication: event.completion,
                                    payload: payload.clone(),
                                });
                            }
                        }
                    }
                    if outputs != grant.newborn || outputs != grant.inventory.retained_outputs {
                        return Err(refused());
                    }
                    let port = installation.descriptor.ports.first().ok_or_else(refused)?;
                    let endpoint = Endpoint {
                        node_id: installation.descriptor.id.clone(),
                        port_id: port.id.clone(),
                        lane_id: port.lanes.first().ok_or_else(refused)?.id.clone(),
                    };
                    let publications = outputs
                        .iter()
                        .map(|output| public_output(output, &endpoint, Vec::new()))
                        .collect::<Result<Vec<_>, _>>()?;
                    let bound = program
                        .events
                        .iter()
                        .filter(|event| event.payload.is_some() && event.completion >= limit)
                        .map(|event| event.completion)
                        .min()
                        .map_or(
                            NativeOutputBound::AfterInstant(limit.time_ps),
                            NativeOutputBound::At,
                        );
                    (
                        bound,
                        publications,
                        outputs.iter().map(|row| row.event.clone()).collect(),
                        None,
                        None,
                    )
                }
                (
                    NativeBody::Reactive(record),
                    PacketConnectedSourceProgram::Reactive { program },
                ) => {
                    let grant = record.grant.as_ref().ok_or_else(refused)?;
                    model::authenticate(self, &observed, member, seal, grant, program)?;
                    let commit = latest_commit(&observed, member, record.original.sequence)?;
                    let stage = stage_for(&observed, member, &commit.staged_record)?;
                    if commit.cut.cutoff < limit
                        || grant.inventory.commits.last()
                            != Some(&commit_reference(&observed, member, commit)?)
                    {
                        return Err(refused());
                    }
                    let publications = grant
                        .newborn
                        .iter()
                        .map(|row| {
                            public_output(
                                &row.output,
                                program.output.as_ref().ok_or_else(refused)?,
                                vec![row.pending.reaction.parent],
                            )
                        })
                        .collect::<Result<Vec<_>, QualificationError>>()?;
                    let consumed = stage
                        .deliveries
                        .iter()
                        .filter(|delivery| {
                            grant.inventory.delivered_inputs.iter().any(|row| {
                                let reaction = &row.reaction;
                                reaction.stage_operation == stage.cut.stage_operation_id
                                    && reaction.input_event == delivery.publication_id
                                    && reaction.input_producer == delivery.producer
                                    && reaction.input_sequence == delivery.source_sequence
                                    && reaction.parent == delivery.delivery
                            })
                        })
                        .map(|delivery| InputIdentity {
                            producer: delivery.producer.clone(),
                            source_sequence: delivery.source_sequence,
                        })
                        .collect();
                    let input_progress = Some(NativeInputProgress {
                        batch: stage.cut.batch_id.clone(),
                        consumed,
                        proof_ref: seal.reference.clone(),
                    });
                    (
                        output_bound(&grant.inventory, program.output.is_some())?,
                        publications,
                        grant
                            .newborn
                            .iter()
                            .map(|row| row.output.event.clone())
                            .collect(),
                        input_progress,
                        Some(input_reference(stage, &owner)?),
                    )
                }
                _ => return Err(refused()),
            };
        let outcome = OperationOutcome {
            operation: scheduled.operation.clone(),
            node: installation.descriptor.id.clone(),
            owners: vec![owner.clone()],
            progress: ProgressEvidence::Exact {
                reached: limit,
                stop: StopReason::HorizonPark,
            },
            retained_outputs: retained,
            scheduling: Some(NativeSchedulingObservation {
                node: installation.descriptor.id.clone(),
                owners: vec![owner],
                reached: limit,
                closed_prefix: limit,
                bounds: vec![NativeProducerBound {
                    producer: installation.descriptor.id.clone(),
                    bound,
                    proof_ref: seal.reference.clone(),
                }],
                publications,
                input_progress,
                external_inputs: Vec::new(),
                proof_ref: seal.reference.clone(),
            }),
        };
        super::super::super::scope::encoded_size(&(&outcome, &outcome), MAXIMUM_SNAPSHOT as usize)?;
        self.roster.current_native().map_err(native_failure)?;
        Ok(ExactCompletionCase {
            case: case.into(),
            oracle: planned.oracle.clone(),
            request: scheduled.request.clone(),
            outcome,
            input,
            acknowledged: selected.kind == PacketConnectedCaseKind::AfterRetirement,
            maximum_bytes: MAXIMUM_SNAPSHOT,
        })
    }

    pub(super) fn template(
        &self,
        id: &str,
    ) -> Result<(&PacketConnectedCase, &ScheduledGrant, usize), QualificationError> {
        let case = self
            .schedule
            .cases
            .iter()
            .find(|case| case.id == id)
            .ok_or_else(refused)?;
        if !matches!(
            case.kind,
            PacketConnectedCaseKind::BeforeRetirement
                | PacketConnectedCaseKind::AfterRetirement
                | PacketConnectedCaseKind::Delivery
                | PacketConnectedCaseKind::Reaction
                | PacketConnectedCaseKind::Publication
                | PacketConnectedCaseKind::PositiveDelayCoordinate
                | PacketConnectedCaseKind::ZeroDelayClosure
        ) {
            return Err(refused());
        }
        let operation = case.operation.as_ref().ok_or_else(refused)?;
        let grant = self
            .schedule
            .grants
            .iter()
            .find(|grant| grant.node == case.node && grant.operation == *operation)
            .ok_or_else(refused)?;
        let member = self
            .schedule
            .nodes
            .iter()
            .position(|node| node == &case.node)
            .ok_or_else(refused)?;
        Ok((case, grant, member))
    }

    pub(super) fn completion_seal<'a>(
        &self,
        observed: &'a Observed,
        member: usize,
        scheduled: &ScheduledGrant,
        start: Position,
        limit: Position,
    ) -> Result<&'a Seal, QualificationError> {
        let mut candidates = observed
            .seals
            .iter()
            .filter(|seal| seal.member == member)
            .filter(|seal| match &seal.body {
                NativeBody::Producer(record) => record.grant.as_ref().is_some_and(|grant| {
                    grant.complete
                        && grant.operation == scheduled.operation
                        && grant.start == start
                        && grant.limit == limit
                }),
                NativeBody::Reactive(record) => record.grant.as_ref().is_some_and(|grant| {
                    grant.complete
                        && grant.operation == scheduled.operation
                        && grant.start == start
                        && grant.limit == limit
                }),
                _ => false,
            });
        let seal = candidates.next().ok_or_else(refused)?;
        // Poll/Observe bodies may refer to the same original completed grant.
        // Common outcomes use its original Begin/Poll proof, never a Retire read.
        if candidates.any(|other| match (&seal.body, &other.body) {
            (NativeBody::Producer(a), NativeBody::Producer(b)) => a.grant != b.grant,
            (NativeBody::Reactive(a), NativeBody::Reactive(b)) => a.grant != b.grant,
            _ => true,
        }) {
            return Err(refused());
        }
        Ok(seal)
    }
}

fn interval(request: &OperationRequest) -> Result<(Position, Position), QualificationError> {
    match request {
        OperationRequest::ExactRun { start, limit, .. }
        | OperationRequest::BoundarySettle { start, limit } => Ok((*start, *limit)),
        _ => Err(refused()),
    }
}

fn public_output(
    output: &PacketPublication,
    endpoint: &Endpoint,
    causal_parents: Vec<Position>,
) -> Result<NativePublication, QualificationError> {
    Ok(NativePublication {
        publication_id: output.event.clone(),
        endpoint: endpoint.clone(),
        native_sequence: output.sequence,
        publication: output.publication,
        evaluation: Some(output.evaluation),
        causal_parents,
        payload: canonical::content_ref(output.payload.as_slice(), "application/octet-stream")?,
        payload_bytes: output.payload.as_slice().to_vec(),
    })
}

fn latest_commit(
    observed: &Observed,
    member: usize,
    sequence: U64,
) -> Result<&PacketCommitRecord, QualificationError> {
    observed
        .seals
        .iter()
        .filter(|seal| seal.member == member)
        .filter_map(|seal| match &seal.body {
            NativeBody::Commit(record) if record.original.sequence < sequence => Some(record),
            _ => None,
        })
        .max_by_key(|record| record.original.sequence)
        .ok_or_else(refused)
}

fn stage_for<'a>(
    observed: &'a Observed,
    member: usize,
    reference: &ContentRef,
) -> Result<&'a PacketStageRecord, QualificationError> {
    observed
        .seals
        .iter()
        .find_map(|seal| match &seal.body {
            NativeBody::Stage(record) if seal.member == member && seal.reference == *reference => {
                Some(record)
            }
            _ => None,
        })
        .ok_or_else(refused)
}

fn commit_reference(
    observed: &Observed,
    member: usize,
    record: &PacketCommitRecord,
) -> Result<ContentRef, QualificationError> {
    observed
        .seals
        .iter()
        .find_map(|seal| match &seal.body {
            NativeBody::Commit(other)
                if seal.member == member && other.original == record.original =>
            {
                Some(seal.reference.clone())
            }
            _ => None,
        })
        .ok_or_else(refused)
}

fn output_bound(
    inventory: &crucible_node_transport::reference_packet::connected::PacketConnectedInventory,
    output: bool,
) -> Result<NativeOutputBound, QualificationError> {
    if !output {
        return Ok(NativeOutputBound::AfterInstant(inventory.reached.time_ps));
    }
    let reached = inventory.reached;
    let microstep = if reached.phase <= Phase::Publication {
        reached.microstep
    } else {
        reached.microstep.checked_add(U64::new(1))?
    };
    if microstep.get() >= 16 {
        return Err(refused());
    }
    let mut bound = Position::new(reached.time_ps, microstep, Phase::Publication);
    for row in &inventory.publications {
        bound = bound.min(row.publication);
    }
    for row in &inventory.reactions {
        bound = bound.min(row.evaluation.reaction_publication(U64::new(16))?);
    }
    Ok(NativeOutputBound::At(bound))
}

fn input_reference(
    stage: &PacketStageRecord,
    owner: &OwnerIdentity,
) -> Result<ContentRef, QualificationError> {
    #[derive(Serialize)]
    struct View<'a> {
        node: &'a Id,
        stage: &'a Id,
        batch: &'a Id,
        owners: &'a [OwnerIdentity],
        cutoff: Position,
        inventory: &'a ContentRef,
        deliveries: &'a [crucible_node_transport::input_commit::CommittedDeliveryV1],
        payloads: Vec<InputPayload>,
    }
    let mut payloads = std::collections::BTreeMap::new();
    for (delivery, payload) in stage.deliveries.iter().zip(&stage.payloads) {
        delivery.payload.verify(payload.as_slice())?;
        payloads.insert(delivery.payload.clone(), payload.as_slice().to_vec());
    }
    let view = View {
        node: &stage.cut.node_id,
        stage: &stage.cut.stage_operation_id,
        batch: &stage.cut.batch_id,
        owners: std::slice::from_ref(owner),
        cutoff: stage.cut.cutoff,
        inventory: &stage.cut.delivery_inventory,
        deliveries: &stage.deliveries,
        payloads: payloads
            .into_iter()
            .map(|(reference, bytes)| InputPayload { reference, bytes })
            .collect(),
    };
    super::super::super::scope::encoded_size(&view, 65_536)?;
    canonical::content_ref(
        &canonical::canonical_json(
            &serde_json::to_value(view).map_err(crucible_node_format::ContractError::from)?,
        )?,
        "application/json",
    )
    .map_err(Into::into)
}
