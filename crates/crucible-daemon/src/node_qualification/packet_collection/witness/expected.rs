//! Binds unpredictable proof identities after independent original native inspection.
//!
//! The complete programme, grant and pre/post-ACK case IDs are installed before
//! Child. Only an original source-validated complete receipt supplies its dynamic
//! proof identity. Expected common fields are derived from the fixed programme,
//! not copied from a common completion or portable report. The independently
//! owned UDP observations remain mandatory before any common outcome is read.

use crucible::node_contract::{
    ExactBoundaryPolicy, OperationOutcome, OwnerIdentity, ProgressEvidence, StopReason,
};
use crucible::node_scheduling::{
    NativeOutputBound, NativeProducerBound, NativePublication, NativeSchedulingObservation,
};
use crucible_node_contract::{Endpoint, Phase, Position, U64};
use crucible_node_provider::envelope::Method;

use super::*;
use crate::node_qualification::ExactCompletionCase;
use serde::Serialize;

const MAXIMUM_SNAPSHOT: u64 = 8 * 1024 * 1024;

impl PacketNativeOracle {
    /// Checks a predeclared exact case and its full original snapshot reservation.
    ///
    /// This check performs no native execution and grants no acceptance. The
    /// runner independently reserves its original attempted case before Begin.
    ///
    /// # Errors
    /// Refuses a foreign plan, unknown case/oracle, altered byte credit or a
    /// request outside this finite no-ingress whole-programme fixture.
    pub fn authenticate_case_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        let expected = self.template(case)?;
        if plan != &self.plan || oracle != &expected.oracle || maximum_bytes != MAXIMUM_SNAPSHOT {
            return Err(refused());
        }
        self.whole_programme(expected)?;
        Ok(())
    }

    /// Derives a full expectation from the fixed programme and original native proof.
    ///
    /// The original programme, request and case identity are never replaced.
    /// Native proof associations are inspected before the caller reads a common
    /// completion. This returns data only; the original runtime token, runner
    /// origin, report store and current installed source remain separate checks.
    ///
    /// # Errors
    /// Refuses unavailable, ambiguous, corrupt or unrelated original receipts,
    /// incomplete or extra socket effects, a changed programme/grant or exhausted
    /// complete-case credit. No observed common outcome is used as an oracle.
    pub fn expected_completion(
        &self,
        case: &str,
    ) -> Result<ExactCompletionCase, QualificationError> {
        let expected = self.template(case)?;
        let (start, limit) = self.whole_programme(expected)?;
        self.store
            .source
            .authenticate_current_native()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        let observed = self
            .store
            .observed
            .try_borrow()
            .map_err(|_| QualificationError::Refused("original packet expectations busy"))?;
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
            return Err(QualificationError::Refused(
                "ambiguous original packet completion proof",
            ));
        }
        seal.reference.verify(&seal.bytes)?;
        let grant = seal.record.grant.as_ref().ok_or_else(refused)?;
        let event = &self.store.program.events[1];
        let payload = event.payload.as_ref().ok_or_else(refused)?;
        if seal.record.inventory != grant.inventory
            || grant.inventory.reached != limit
            || grant.inventory.gate_closed
            || !grant.inventory.pending.is_empty()
            || grant.inventory.private_mutations != U64::new(1)
            || grant.inventory.packet_effects != U64::new(1)
            || grant.newborn.len() != 1
            || grant.inventory.retained_outputs != grant.newborn
        {
            return Err(refused());
        }
        let newborn = &grant.newborn[0];
        if newborn.operation != expected.operation
            || newborn.event != event.id
            || newborn.sequence != U64::new(1)
            || newborn.evaluation != event.evaluation
            || newborn.publication != event.completion
            || newborn.payload != *payload
        {
            return Err(refused());
        }
        let selected = self.store.source.installation();
        // Count the exact full prospective wire shape before copying any
        // source/receipt/owner/publication value. The original expectation and
        // its one submission are both charged; the template stays immutable.
        let endpoints = BorrowedEndpoint {
            node_id: &selected.descriptor.id,
            port_id: &selected.descriptor.ports[0].id,
            lane_id: &selected.descriptor.ports[0].lanes[0].id,
        };
        let bounds = [BorrowedBound {
            producer: &selected.descriptor.id,
            bound: NativeOutputBound::At(limit),
            proof_ref: &seal.reference,
        }];
        let publications = [BorrowedPublication {
            publication_id: &event.id,
            endpoint: endpoints,
            native_sequence: U64::new(1),
            publication: event.completion,
            evaluation: Some(event.evaluation),
            causal_parents: &[],
            payload: &self.store.payload_reference,
            payload_bytes: payload.as_slice(),
        }];
        let retained_outputs = [&event.id];
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
                retained_outputs: &retained_outputs,
                scheduling: Some(BorrowedScheduling {
                    node: &selected.descriptor.id,
                    owners: std::slice::from_ref(&self.store.expected_owner),
                    reached: limit,
                    closed_prefix: limit,
                    bounds: &bounds,
                    publications: &publications,
                    input_progress: None,
                    external_inputs: &[],
                    proof_ref: &seal.reference,
                }),
            },
            input: None,
            acknowledged: expected.acknowledged,
            maximum_bytes: MAXIMUM_SNAPSHOT,
        };
        super::scope::encoded_size(&(&prospective, &prospective), MAXIMUM_SNAPSHOT as usize)?;
        let owners = vec![self.store.expected_owner.clone()];
        let proof = seal.reference.clone();
        let outcome = OperationOutcome {
            operation: expected.operation.clone(),
            node: selected.descriptor.id.clone(),
            owners: owners.clone(),
            progress: ProgressEvidence::Exact {
                reached: limit,
                stop: StopReason::HorizonPark,
            },
            retained_outputs: vec![event.id.clone()],
            scheduling: Some(NativeSchedulingObservation {
                node: selected.descriptor.id.clone(),
                owners,
                reached: limit,
                closed_prefix: limit,
                bounds: vec![NativeProducerBound {
                    producer: selected.descriptor.id.clone(),
                    bound: NativeOutputBound::At(limit),
                    proof_ref: proof.clone(),
                }],
                publications: vec![NativePublication {
                    publication_id: event.id.clone(),
                    endpoint: Endpoint {
                        node_id: selected.descriptor.id.clone(),
                        port_id: selected.descriptor.ports[0].id.clone(),
                        lane_id: selected.descriptor.ports[0].lanes[0].id.clone(),
                    },
                    native_sequence: U64::new(1),
                    publication: event.completion,
                    evaluation: Some(event.evaluation),
                    causal_parents: Vec::new(),
                    payload: self.store.payload_reference.clone(),
                    payload_bytes: payload.as_slice().to_vec(),
                }],
                input_progress: None,
                external_inputs: Vec::new(),
                proof_ref: proof,
            }),
        };
        Ok(ExactCompletionCase {
            case: expected.case.clone(),
            oracle: expected.oracle.clone(),
            request: expected.request.clone(),
            outcome,
            input: None,
            acknowledged: expected.acknowledged,
            maximum_bytes: MAXIMUM_SNAPSHOT,
        })
    }

    pub(in super::super) fn authenticate_case_pair(
        &self,
        node: &Id,
        operation: &Id,
        horizon: U64,
        before: &str,
        after: &str,
    ) -> Result<(), QualificationError> {
        let before = self.template(before)?;
        let after = self.template(after)?;
        case_pair(
            &self.store.program,
            &self.store.source.installation().descriptor.id,
            node,
            operation,
            horizon,
            before,
            after,
        )
    }

    pub(in super::super) fn template_oracle(
        &self,
        case: &str,
    ) -> Result<&ContentRef, QualificationError> {
        Ok(&self.template(case)?.oracle)
    }

    fn template(&self, case: &str) -> Result<&PacketNativeCase, QualificationError> {
        self.cases
            .iter()
            .find(|expected| expected.case == case)
            .ok_or_else(refused)
    }

    fn whole_programme(
        &self,
        expected: &PacketNativeCase,
    ) -> Result<(Position, Position), QualificationError> {
        template_window(&self.store.program, expected)
    }
}

fn template_window(
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
    if *start != zero
        || program.events.len() != 2
        || program.events[0].payload.is_some()
        || program.events[1].payload.is_none()
        || program
            .events
            .iter()
            .any(|event| event.completion >= *limit)
    {
        return Err(refused());
    }
    Ok((*start, *limit))
}

// The complete fixed pair is checked before either case ticket can be reserved.
fn case_pair(
    program: &PacketProgramDefinition,
    selected_node: &Id,
    node: &Id,
    operation: &Id,
    horizon: U64,
    before: &PacketNativeCase,
    after: &PacketNativeCase,
) -> Result<(), QualificationError> {
    let (_, limit) = template_window(program, before)?;
    template_window(program, after)?;
    if before.case == after.case
        || before.acknowledged
        || !after.acknowledged
        || before.operation != *operation
        || after.operation != *operation
        || before.request != after.request
        || node != selected_node
        || limit != Position::new(horizon, U64::new(0), Phase::BoundaryControl)
    {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> QualificationError {
    QualificationError::Refused("source-owned whole packet expectation unavailable")
}

// These borrowed structs mirror the exact owned case/outcome fields. They have
// no decoder or authority constructor and count escaped bytes without retention.
#[derive(Serialize)]
struct BorrowedCase<'a> {
    case: &'a str,
    oracle: &'a ContentRef,
    request: &'a OperationRequest,
    outcome: BorrowedOutcome<'a>,
    input: Option<&'a ContentRef>,
    acknowledged: bool,
    maximum_bytes: u64,
}

#[derive(Serialize)]
struct BorrowedOutcome<'a> {
    operation: &'a Id,
    node: &'a Id,
    owners: &'a [OwnerIdentity],
    progress: ProgressEvidence,
    retained_outputs: &'a [&'a Id],
    scheduling: Option<BorrowedScheduling<'a>>,
}

#[derive(Serialize)]
struct BorrowedScheduling<'a> {
    node: &'a Id,
    owners: &'a [OwnerIdentity],
    reached: Position,
    closed_prefix: Position,
    bounds: &'a [BorrowedBound<'a>],
    publications: &'a [BorrowedPublication<'a>],
    input_progress: Option<()>,
    external_inputs: &'a [()],
    proof_ref: &'a ContentRef,
}

#[derive(Serialize)]
struct BorrowedBound<'a> {
    producer: &'a Id,
    bound: NativeOutputBound,
    proof_ref: &'a ContentRef,
}

#[derive(Serialize)]
struct BorrowedPublication<'a> {
    publication_id: &'a Id,
    endpoint: BorrowedEndpoint<'a>,
    native_sequence: U64,
    publication: Position,
    evaluation: Option<Position>,
    causal_parents: &'a [Position],
    payload: &'a ContentRef,
    payload_bytes: &'a [u8],
}

#[derive(Serialize)]
struct BorrowedEndpoint<'a> {
    node_id: &'a Id,
    port_id: &'a Id,
    lane_id: &'a Id,
}

#[cfg(test)]
mod tests;
