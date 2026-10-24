//! Derives quiet-window expectations from original native receipts and socket history.
//!
//! The first full programme window retains its existing source-derived oracle.
//! Later windows must have no newborn effects and unchanged cumulative counters.
//! Common outcomes are never read to establish expected native proof identities.

use super::*;

pub(in super::super) fn world_window(
    program: &PacketProgramDefinition,
    expected: &PacketNativeCase,
) -> Result<(Position, Position), QualificationError> {
    let OperationRequest::ExactRun {
        start,
        limit,
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    } = &expected.request
    else {
        return Err(refused());
    };
    let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    if *start == zero {
        return template_window(program, expected);
    }
    if program.events.len() != 2
        || program.events[0].payload.is_some()
        || program.events[1].payload.is_none()
        || start.phase != Phase::BoundaryControl
        || start.microstep != U64::new(0)
        || limit.phase != Phase::BoundaryControl
        || limit.microstep != U64::new(0)
        || *start >= *limit
        || program
            .events
            .iter()
            .any(|event| event.completion >= *start)
    {
        return Err(refused());
    }
    Ok((*start, *limit))
}

impl PacketNativeOracle {
    pub(super) fn expected_quiet_completion(
        &self,
        expected: &PacketNativeCase,
        start: Position,
        limit: Position,
    ) -> Result<ExactCompletionCase, QualificationError> {
        if self.store.world_owners.is_none() {
            return Err(refused());
        }
        self.store
            .source
            .authenticate_current_native()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        let observed = self.store.observed.try_borrow().map_err(|_| refused())?;
        if observed.failed || observed.trace_count != 2 {
            return Err(refused());
        }
        let mut candidates = observed.seals.iter().filter(|seal| {
            matches!(seal.record.original.method, Method::Begin | Method::Poll)
                && seal.record.grant.as_ref().is_some_and(|grant| {
                    grant.complete
                        && grant.operation == expected.operation
                        && grant.start == start
                        && grant.limit == limit
                })
        });
        let seal = candidates.next().ok_or_else(refused)?;
        if candidates.any(|other| other.reference != seal.reference) {
            return Err(refused());
        }
        seal.reference.verify(&seal.bytes)?;
        let grant = seal.record.grant.as_ref().ok_or_else(refused)?;
        if seal.record.inventory != grant.inventory
            || grant.inventory.reached != limit
            || grant.inventory.gate_closed
            || !grant.inventory.pending.is_empty()
            || grant.inventory.private_mutations != U64::new(1)
            || grant.inventory.packet_effects != U64::new(1)
            || !grant.newborn.is_empty()
            || !grant.inventory.retained_outputs.is_empty()
        {
            return Err(refused());
        }
        let selected = self.store.source.installation();
        // Two complete prospective case associations are counted before owner,
        // proof, operation or request copies. No output payload exists here.
        // The independently inspected complete native roster is empty above;
        // no later public callback exists in this fixed output-only program.
        let bounds = [BorrowedBound {
            producer: &selected.descriptor.id,
            bound: NativeOutputBound::AfterInstant(limit.time_ps),
            proof_ref: &seal.reference,
        }];
        let prospective = BorrowedCase {
            case: &expected.case,
            oracle: &expected.oracle,
            request: &expected.request,
            outcome: BorrowedOutcome {
                operation: &expected.operation,
                node: &selected.descriptor.id,
                owners: std::slice::from_ref(&self.store.expected_owner),
                progress: ProgressEvidence::Exact {
                    reached: limit,
                    stop: StopReason::HorizonPark,
                },
                retained_outputs: &[],
                scheduling: Some(BorrowedScheduling {
                    node: &selected.descriptor.id,
                    owners: std::slice::from_ref(&self.store.expected_owner),
                    reached: limit,
                    closed_prefix: limit,
                    bounds: &bounds,
                    publications: &[],
                    input_progress: None,
                    external_inputs: &[],
                    proof_ref: &seal.reference,
                }),
            },
            input: None,
            acknowledged: expected.acknowledged,
            maximum_bytes: MAXIMUM_SNAPSHOT,
        };
        super::super::super::scope::encoded_size(
            &(&prospective, &prospective),
            MAXIMUM_SNAPSHOT as usize,
        )?;
        let owners = vec![self.store.expected_owner.clone()];
        let proof = seal.reference.clone();
        Ok(ExactCompletionCase {
            case: expected.case.clone(),
            oracle: expected.oracle.clone(),
            request: expected.request.clone(),
            outcome: OperationOutcome {
                operation: expected.operation.clone(),
                node: selected.descriptor.id.clone(),
                owners: owners.clone(),
                progress: ProgressEvidence::Exact {
                    reached: limit,
                    stop: StopReason::HorizonPark,
                },
                retained_outputs: Vec::new(),
                scheduling: Some(NativeSchedulingObservation {
                    node: selected.descriptor.id.clone(),
                    owners,
                    reached: limit,
                    closed_prefix: limit,
                    bounds: vec![NativeProducerBound {
                        producer: selected.descriptor.id.clone(),
                        bound: NativeOutputBound::AfterInstant(limit.time_ps),
                        proof_ref: proof.clone(),
                    }],
                    publications: Vec::new(),
                    input_progress: None,
                    external_inputs: Vec::new(),
                    proof_ref: proof,
                }),
            },
            input: None,
            acknowledged: expected.acknowledged,
            maximum_bytes: MAXIMUM_SNAPSHOT,
        })
    }
}
