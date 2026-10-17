//! Retains synthetic native operations and input custody for common-runtime tests.
//!
//! This in-process model validates its own original receipts. It does not qualify
//! an installed backend, process image, or public multi-participant Host profile.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Model assertions intentionally fail on foreign custody or replayed effects.
#![allow(clippy::unwrap_used)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::*,
    node_scheduling::{event::Delivery, *},
};
use crucible_node_contract::{
    ContentRef, Endpoint, Id, NodeBinding, NodeDescriptor, Phase, Position, U64, canonical,
};

use super::{id, position};

/// Retains original callback identities and observable model input consumption.
#[derive(Default)]
pub(super) struct Journal {
    /// Records each original native begin exactly once.
    pub begins: Vec<Id>,
    /// Records original immutable staging before any semantic consumption.
    pub stages: Vec<Id>,
    /// Records genuine common publication acknowledgements.
    pub acknowledgements: Vec<Id>,
    /// Keeps an original native operation pending while another owner completes.
    pub pending: bool,
    /// Records actual payload bytes in semantic delivery order.
    pub semantic_inputs: Vec<Vec<u8>>,
    admissions: BTreeMap<Id, OperationAdmission>,
    outcomes: BTreeMap<Id, OperationOutcome>,
    input: Option<ModelInput>,
    ready: Option<ReadyAttestation>,
    quarantined: bool,
}

type NodeHandles = Vec<Box<dyn SimulationNode>>;
type Journals = Vec<Rc<RefCell<Journal>>>;

struct ModelInput {
    acknowledgement: NativeInputAcknowledgement,
    deliveries: Vec<Delivery>,
    payloads: Vec<InputPayload>,
}

struct OwnerState {
    cursor: Position,
    active: Option<Id>,
    staged: Option<Id>,
}

/// Implements exact callbacks over explicitly shared model-owner custody.
pub(super) struct ModelNode {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    profile: Id,
    participants: Vec<Id>,
    journal: Rc<RefCell<Journal>>,
    owner: Rc<RefCell<OwnerState>>,
}

/// Creates one model handle per public view with one state cell per execution owner.
pub(super) fn nodes(graph: &AdmittedGraph) -> (NodeHandles, Journals) {
    let mut handles: Vec<Box<dyn SimulationNode>> = Vec::new();
    let mut journals = Vec::new();
    let mut owner_states: BTreeMap<Id, Rc<RefCell<OwnerState>>> = BTreeMap::new();
    for node in graph.node_ids() {
        let binding = graph.binding(node).unwrap().clone();
        let owners = [
            binding.compatibility.execution_owner.id.clone(),
            binding.compatibility.capture_owner.id.clone(),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|owner| OwnerIdentity {
            owner,
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        })
        .collect();
        let owner = owner_states
            .entry(binding.compatibility.execution_owner.id.clone())
            .or_insert_with(|| {
                Rc::new(RefCell::new(OwnerState {
                    cursor: position(0),
                    active: None,
                    staged: None,
                }))
            })
            .clone();
        let journal = Rc::new(RefCell::new(Journal::default()));
        handles.push(Box::new(ModelNode {
            descriptor: graph.descriptor(node).unwrap().clone(),
            participants: binding
                .compatibility
                .execution_owner
                .participant_ids
                .clone(),
            binding,
            route: NodeRoute {
                node: node.clone(),
                owners,
            },
            profile: id("test-execution"),
            journal: journal.clone(),
            owner,
        }));
        journals.push(journal);
    }
    (handles, journals)
}

fn proof(bytes: &[u8]) -> ContentRef {
    canonical::content_ref(bytes, "application/json").unwrap()
}

fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

impl FacetDescription for ModelNode {
    fn profile(&self) -> &Id {
        &self.profile
    }
}

impl SimulationNode for ModelNode {
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
        ThreadAffinity::OwnerThread(std::thread::current().id())
    }

    fn facets(&self) -> &[FacetKind] {
        &[FacetKind::ExactExecution]
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        Ok(NodeStatus {
            lifecycle: Lifecycle::Stopped,
            physical: PhysicalState::Suspended,
            boundary: Some(self.owner.borrow().cursor),
        })
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        let ready = ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: world.boundary,
            state_inventory: proof(b"model-state"),
            ready_receipt: proof(b"model-ready"),
        };
        let mut journal = self.journal.borrow_mut();
        journal.ready = Some(ready.clone());
        self.owner.borrow_mut().cursor = world.boundary;
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.journal.borrow().ready.as_ref() == Some(ready) && ready.boundary == world.boundary {
            Ok(())
        } else {
            Err(refused("foreign model readiness"))
        }
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        let mut owner = self.owner.borrow_mut();
        assert!(owner.active.is_none());
        assert!(owner.staged.replace(self.route.node.clone()).is_none());
        assert_eq!(batch.node(), &self.route.node);
        assert_eq!(batch.owners(), self.route.owners);
        let acknowledgement = NativeInputAcknowledgement {
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            node: batch.node().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            proof_ref: proof(b"model-input-custody"),
        };
        let mut journal = self.journal.borrow_mut();
        journal.stages.push(batch.stage_operation().clone());
        journal.input = Some(ModelInput {
            acknowledgement: acknowledgement.clone(),
            deliveries: batch.deliveries().to_vec(),
            payloads: batch.payloads().to_vec(),
        });
        Ok(acknowledgement)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        if self
            .journal
            .borrow()
            .input
            .as_ref()
            .is_some_and(|input| &input.acknowledgement == acknowledgement)
            && acknowledgement.batch == *batch.batch()
        {
            Ok(())
        } else {
            Err(refused("foreign model input acknowledgement"))
        }
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        let mut owner = self.owner.borrow_mut();
        assert!(
            owner
                .active
                .replace(admission.token().operation().clone())
                .is_none()
        );
        if let OperationRequest::ExactRun { start, .. } = admission.request() {
            assert_eq!(*start, owner.cursor);
        }
        if let Some(staged) = &owner.staged {
            assert_eq!(staged, &self.route.node);
            assert!(admission.inputs().is_some());
        }
        let mut journal = self.journal.borrow_mut();
        assert!(
            journal
                .admissions
                .insert(admission.token().operation().clone(), admission.clone())
                .is_none()
        );
        journal.begins.push(admission.token().operation().clone());
        Submission::Accepted
    }

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        _: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        let mut journal = self.journal.borrow_mut();
        if journal.pending {
            return Poll::Pending;
        }
        if let Some(outcome) = journal.outcomes.get(operation.operation()) {
            return Poll::Ready(Ok(outcome.clone()));
        }
        let original = journal.admissions.get(operation.operation()).unwrap();
        let reached = match original.request() {
            OperationRequest::ExactRun { limit, .. } => *limit,
            _ => panic!("unsupported model request"),
        };
        let mut publications = Vec::new();
        if operation.operation() == &id("fill-credit") {
            for ordinal in 0..2 {
                let bytes = vec![ordinal as u8];
                publications.push(NativePublication {
                    publication_id: id(&format!("model-output/{ordinal}")),
                    endpoint: Endpoint {
                        node_id: id("a"),
                        port_id: id("data"),
                        lane_id: id("output"),
                    },
                    native_sequence: U64::new(ordinal),
                    publication: Position::new(
                        U64::new(4),
                        U64::new(ordinal * 2 + 1),
                        Phase::Publication,
                    ),
                    evaluation: Some(Position::new(
                        U64::new(4),
                        U64::new(ordinal * 2),
                        Phase::Reaction,
                    )),
                    causal_parents: vec![],
                    payload: canonical::content_ref(&bytes, "application/octet-stream").unwrap(),
                    payload_bytes: bytes,
                });
            }
        }
        let proof_ref = proof(operation.operation().as_str().as_bytes());
        let input_progress = journal.input.as_ref().map(|input| NativeInputProgress {
            batch: input.acknowledgement.batch.clone(),
            consumed: input
                .deliveries
                .iter()
                .map(|delivery| InputIdentity {
                    producer: delivery.producer.clone(),
                    source_sequence: delivery.source_sequence,
                })
                .collect(),
            proof_ref: input.acknowledgement.proof_ref.clone(),
        });
        let consumed_bytes = journal
            .input
            .as_ref()
            .map(|input| {
                input
                    .deliveries
                    .iter()
                    .map(|delivery| {
                        input
                            .payloads
                            .iter()
                            .find(|payload| payload.reference == delivery.payload)
                            .unwrap()
                            .bytes
                            .clone()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        journal.semantic_inputs.extend(consumed_bytes);
        let observation = NativeSchedulingObservation {
            node: operation.route().node.clone(),
            owners: operation.route().owners.clone(),
            reached,
            closed_prefix: reached,
            bounds: self
                .participants
                .iter()
                .map(|producer| NativeProducerBound {
                    producer: producer.clone(),
                    bound: NativeOutputBound::AfterInstant(reached.time_ps),
                    proof_ref: proof_ref.clone(),
                })
                .collect(),
            input_progress,
            publications,
            external_inputs: vec![],
            proof_ref,
        };
        let outcome = OperationOutcome {
            operation: operation.operation().clone(),
            node: operation.route().node.clone(),
            owners: operation.route().owners.clone(),
            progress: ProgressEvidence::Exact {
                reached,
                stop: StopReason::HorizonPark,
            },
            retained_outputs: observation
                .publications
                .iter()
                .map(|publication| publication.publication_id.clone())
                .collect(),
            scheduling: Some(observation),
        };
        self.owner.borrow_mut().cursor = reached;
        journal
            .outcomes
            .insert(operation.operation().clone(), outcome.clone());
        Poll::Ready(Ok(outcome))
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        if self
            .journal
            .borrow()
            .outcomes
            .get(original.token().operation())
            == Some(outcome)
        {
            Ok(())
        } else {
            Err(refused("foreign model outcome"))
        }
    }

    fn request_cancel(&mut self, _: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        Ok(CancelStatus::Requested)
    }

    fn close_quantum(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "exact model".into(),
        })
    }

    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let mut journal = self.journal.borrow_mut();
        assert_eq!(
            journal.outcomes[operation.operation()].retained_outputs,
            outputs
        );
        assert!(!journal.acknowledgements.contains(operation.operation()));
        journal.acknowledgements.push(operation.operation().clone());
        let mut owner = self.owner.borrow_mut();
        assert_eq!(owner.active.take().as_ref(), Some(operation.operation()));
        owner.staged = None;
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if kind == FacetKind::ExactExecution {
            Ok(NodeFacet::ExactExecution(self))
        } else {
            Err(Refusal {
                reason: "exact model only".into(),
            })
        }
    }

    fn quarantine_resources(&mut self) {
        self.journal.borrow_mut().quarantined = true;
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        _: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        assert!(self.journal.borrow().quarantined);
        Poll::Ready(Ok(NativeReclamationReceipt {
            owner: owner.clone(),
            receipt: proof(b"model-reclaimed"),
        }))
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.journal.borrow().quarantined
            && self.route.owners.contains(&receipt.owner)
            && receipt.receipt == proof(b"model-reclaimed")
        {
            Ok(())
        } else {
            Err(refused("foreign model reclamation"))
        }
    }
}
