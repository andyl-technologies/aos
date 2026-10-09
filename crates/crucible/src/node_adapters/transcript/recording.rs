//! Live common-node recording with reservations before physical execution.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{ContentRef, Id, Position, canonical};

use crate::{node_admission::AdmittedGraph, node_contract::*, node_scheduling::*};

use super::{
    capture::{CaptureSession, CapturedTranscript, Reservation},
    codec::{TranscriptError, encode, invalid},
    control::*,
    proof::RecordedProofClosure,
    types::*,
};

struct RecordingState {
    capture: Option<CaptureSession>,
    pending: usize,
}

/// Provides a one-shot complete-source export without borrowing native resources.
#[derive(Clone)]
pub struct RecordingHandle(Rc<RefCell<RecordingState>>);

impl RecordingHandle {
    /// Closes complete raw capture after all original publication custody settled.
    ///
    /// Once closed, new semantic source requests are refused. The source adapter
    /// retains its genuine native supervision and may still be quarantined.
    ///
    /// # Errors
    /// Refuses outstanding original operations, capture failure, incomplete
    /// records or repeated export. It never silently downgrades replayability.
    pub fn finish(&self) -> Result<CapturedTranscript, TranscriptError> {
        let mut state = self.0.borrow_mut();
        if state.pending != 0 {
            return Err(TranscriptError::Unqualified(
                "source publication custody remains outstanding".into(),
            ));
        }
        state
            .capture
            .take()
            .ok_or_else(|| TranscriptError::Unqualified("source capture is already closed".into()))?
            .finish()
    }
}

struct RecordedOperation {
    admission: OperationAdmission,
    completion: Option<Reservation>,
    terminal: Option<OperationOutcome>,
    acknowledged: bool,
    close_submission: Option<Submission>,
}

/// Retains the original native node after recording preparation is refused.
///
/// The owning world must transfer the recovered node into its pre-reserved
/// containment custody. Preparation failure never implies native reclamation.
pub struct RecordingPreparationFailure {
    error: TranscriptError,
    inner: Box<dyn SimulationNode>,
}

impl RecordingPreparationFailure {
    /// Borrows the original refusal without discarding native custody.
    pub fn error(&self) -> &TranscriptError {
        &self.error
    }

    /// Returns the original refusal and owning native handle for containment.
    pub fn into_parts(self) -> (TranscriptError, Box<dyn SimulationNode>) {
        (self.error, self.inner)
    }
}

impl std::fmt::Debug for RecordingPreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordingPreparationFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RecordingPreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for RecordingPreparationFailure {}

/// Records actual admitted boundary interactions around an authentic native node.
///
/// Recorded requests are the canonical common-node control boundary, not a claim
/// about an implementation's private internal transport. Pending polls are host
/// liveness observations; only the original terminal response enters the logical
/// transcript. Physical timing remains explicitly unqualified by this wrapper.
pub struct RecordingNode {
    inner: Box<dyn SimulationNode>,
    state: RecordingHandle,
    operations: BTreeMap<Id, RecordedOperation>,
    origin: TranscriptOrigin,
    boundary: Position,
    observation_sequence: u64,
}

impl RecordingNode {
    /// Predeclares complete capture before an actual source node is armed or run.
    ///
    /// The caller supplies complete materialized source context, including the
    /// raw admitted world and all relevant input, clock and fault preconditions.
    /// The actual sealed graph, source descriptor/binding and full owner roster
    /// are checked independently; they cannot be replaced by context labels.
    ///
    /// # Errors
    /// Refuses changed admitted native identity, missing complete context,
    /// unsupported preservation promises or insufficient capture reservations.
    pub fn new(
        graph: &AdmittedGraph,
        inner: Box<dyn SimulationNode>,
        attempt: Id,
        activation: &ActivationRecord,
        mut context: Vec<InputPayload>,
        limits: TranscriptLimits,
    ) -> Result<(Self, RecordingHandle), RecordingPreparationFailure> {
        let prepared: Result<_, TranscriptError> = (|| {
            if graph.descriptor(&inner.route().node) != Some(inner.descriptor())
                || graph.binding(&inner.route().node) != Some(inner.binding())
                || graph.world_binding_hash() != &activation.world_binding_hash
                || inner
                    .route()
                    .owners
                    .iter()
                    .any(|owner| !activation.owners.contains(owner))
                || inner.facets().contains(&FacetKind::Preservation)
            {
                return Err(TranscriptError::Unqualified("actual recording source differs from admitted graph or requires unsupported wrapper preservation".into()));
            }
            let source_bytes = encode(inner.binding())?;
            let source_binding =
                canonical::content_ref(&source_bytes, "application/json").map_err(invalid)?;
            context.push(InputPayload {
                reference: source_binding.clone(),
                bytes: source_bytes,
            });
            let descriptor_bytes = encode(inner.descriptor())?;
            context.push(InputPayload {
                reference: canonical::content_ref(&descriptor_bytes, "application/json")
                    .map_err(invalid)?,
                bytes: descriptor_bytes,
            });
            let world_bytes = encode(graph.world())?;
            let world_ref =
                canonical::content_ref(&world_bytes, "application/json").map_err(invalid)?;
            if !context
                .iter()
                .any(|object| object.reference == world_ref && object.bytes == world_bytes)
            {
                return Err(TranscriptError::Unqualified(
                    "complete raw admitted world context absent".into(),
                ));
            }
            let origin = TranscriptOrigin {
                attempt,
                activation: SavedRuntimeActivation::from(activation),
                route: inner.route().clone(),
                source_binding,
                context,
                repeatability: graph.world_repeatability(),
            };
            let capture = CaptureSession::new(origin.clone(), limits)?;
            Ok((origin, capture))
        })();
        let (origin, capture) = match prepared {
            Ok(value) => value,
            Err(error) => return Err(RecordingPreparationFailure { error, inner }),
        };
        let handle = RecordingHandle(Rc::new(RefCell::new(RecordingState {
            capture: Some(capture),
            pending: 0,
        })));
        Ok((
            Self {
                inner,
                state: handle.clone(),
                operations: BTreeMap::new(),
                origin,
                boundary: activation.boundary,
                observation_sequence: 0,
            },
            handle,
        ))
    }

    fn reserve(&self) -> Result<Reservation, OperationFailure> {
        self.state
            .0
            .borrow_mut()
            .capture
            .as_mut()
            .ok_or_else(|| failure("capture closed", EffectKnowledge::None))?
            .reserve()
            .map_err(|error| failure(error, EffectKnowledge::None))
    }

    fn capture_request(
        &self,
        action: TranscriptAction,
        id: Id,
        before: Position,
        body: &ControlRequest,
    ) -> Result<TranscriptRequest, OperationFailure> {
        let mut state = self.state.0.borrow_mut();
        let capture = state
            .capture
            .as_mut()
            .ok_or_else(|| failure("capture closed", EffectKnowledge::None))?;
        let context = capture
            .context()
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let request = request(action, id, before, context, body)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        if encode(&request)
            .map_err(|error| failure(error, EffectKnowledge::None))?
            .len() as u64
            > capture.maximum_record_bytes()
        {
            capture.invalidate();
            return Err(failure(
                "original request exceeds predeclared capture reservation",
                EffectKnowledge::None,
            ));
        }
        Ok(request)
    }

    fn retain(
        &self,
        reservation: Reservation,
        request: TranscriptRequest,
        response: ControlResponse,
        evidence: Vec<InputPayload>,
        positions: Vec<Position>,
    ) -> Result<(), OperationFailure> {
        let mut state = self.state.0.borrow_mut();
        let capture = state
            .capture
            .as_mut()
            .ok_or_else(|| failure("capture closed", EffectKnowledge::Unknown))?;
        let response =
            encode(&response).map_err(|error| failure(error, EffectKnowledge::Unknown))?;
        capture
            .retain(
                reservation,
                request,
                response,
                evidence,
                positions,
                PhysicalTimingUncertainty::Unbounded,
            )
            .map_err(|error| failure(error, EffectKnowledge::Unknown))
    }

    fn invalidate(&self) {
        if let Some(capture) = self.state.0.borrow_mut().capture.as_mut() {
            capture.invalidate();
        }
    }

    fn boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        let maximum = self
            .state
            .0
            .borrow()
            .capture
            .as_ref()
            .ok_or_else(|| failure("capture closed", EffectKnowledge::None))?
            .maximum_record_bytes();
        let maximum =
            usize::try_from(maximum).map_err(|error| failure(error, EffectKnowledge::None))?;
        let objects = self
            .inner
            .read_boundary_evidence(activation, references, maximum)?;
        self.inner
            .validate_boundary_evidence(activation, references, &objects)?;
        if objects.len() != references.len()
            || objects.iter().zip(references).any(|(object, reference)| {
                object.reference != *reference || reference.verify(&object.bytes).is_err()
            })
            || objects
                .iter()
                .try_fold(0usize, |size, object| size.checked_add(object.bytes.len()))
                .is_none_or(|size| size > maximum)
        {
            return Err(failure(
                "original boundary proof bytes are missing, changed or exceed reservation",
                EffectKnowledge::None,
            ));
        }
        Ok(objects)
    }

    fn retain_proof_closures(
        &self,
        activation: &WorldActivation,
        roots: &[ContentRef],
        evidence: &mut Vec<InputPayload>,
    ) -> Result<(), OperationFailure> {
        let limits = InputProvenanceLimits {
            maximum_objects: 4096,
            maximum_bytes: usize::try_from(
                self.state
                    .0
                    .borrow()
                    .capture
                    .as_ref()
                    .ok_or_else(|| failure("capture closed", EffectKnowledge::None))?
                    .maximum_record_bytes(),
            )
            .map_err(|error| failure(error, EffectKnowledge::None))?,
        };
        for root in roots {
            let dependencies = self
                .inner
                .input_provenance_dependencies(activation, root, limits)?;
            self.inner
                .validate_input_provenance_dependencies(activation, root, &dependencies)?;
            if dependencies
                .len()
                .checked_add(1)
                .is_none_or(|count| count > limits.maximum_objects)
                || dependencies.contains(root)
            {
                return Err(failure(
                    "source producer proof dependency inventory exceeds reservation",
                    EffectKnowledge::None,
                ));
            }
            let objects = self.boundary_evidence(activation, &dependencies)?;
            for object in objects {
                if !evidence.contains(&object) {
                    evidence.push(object);
                }
            }
            evidence.push(
                RecordedProofClosure::capture(&self.origin, root.clone(), dependencies)
                    .map_err(|error| failure(error, EffectKnowledge::None))?,
            );
            if evidence
                .iter()
                .try_fold(0usize, |bytes, object| {
                    bytes.checked_add(object.bytes.len())
                })
                .is_none_or(|bytes| bytes > limits.maximum_bytes)
            {
                return Err(failure(
                    "source producer proof bytes exceed original capture reservation",
                    EffectKnowledge::None,
                ));
            }
        }
        Ok(())
    }

    fn check_activation(&self, activation: &WorldActivation) -> Result<(), OperationFailure> {
        if SavedRuntimeActivation::from(activation.record()) != self.origin.activation {
            return Err(failure("source activation changed", EffectKnowledge::None));
        }
        Ok(())
    }

    fn refuse(error: OperationFailure) -> Submission {
        match error.effects {
            EffectKnowledge::None => Submission::Refused(Refusal {
                reason: error.reason,
            }),
            effects => Submission::Uncertain(effects),
        }
    }
}

impl RecordingNode {
    fn record_stage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: Option<&InputProvenanceClosure>,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.check_activation(batch.activation())?;
        let reservation = self.reserve()?;
        let body = ControlRequest::Stage {
            input: RecordedInput::with_provenance(batch, &self.origin.route.owners, provenance)?,
        };
        let request = self.capture_request(
            TranscriptAction::StageInput,
            batch.stage_operation().clone(),
            self.boundary,
            &body,
        )?;
        let ack = match provenance {
            Some(provenance) => self.inner.stage_inputs_with_provenance(batch, provenance)?,
            None => self.inner.stage_inputs(batch)?,
        };
        if let Err(error) = self.inner.validate_input_acknowledgement(batch, &ack) {
            self.invalidate();
            return Err(failure(error.reason, EffectKnowledge::MayHaveProgressed));
        }
        let mut evidence = match self
            .boundary_evidence(batch.activation(), std::slice::from_ref(&ack.proof_ref))
        {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Err(failure(error.reason, EffectKnowledge::MayHaveProgressed));
            }
        };
        if let Err(error) = self.retain_proof_closures(
            batch.activation(),
            std::slice::from_ref(&ack.proof_ref),
            &mut evidence,
        ) {
            self.invalidate();
            return Err(failure(error.reason, EffectKnowledge::MayHaveProgressed));
        }
        evidence.extend_from_slice(batch.payloads());
        if let Some(provenance) = provenance {
            for object in provenance.objects() {
                if !evidence.contains(object) {
                    evidence.push(object.clone());
                }
            }
        }
        self.retain(
            reservation,
            request,
            ControlResponse::Input(Box::new(ack.clone())),
            evidence,
            Vec::new(),
        )?;
        Ok(ack)
    }
}

impl SimulationNode for RecordingNode {
    fn descriptor(&self) -> &crucible_node_contract::NodeDescriptor {
        self.inner.descriptor()
    }
    fn binding(&self) -> &crucible_node_contract::NodeBinding {
        self.inner.binding()
    }
    fn route(&self) -> &NodeRoute {
        self.inner.route()
    }
    fn thread_affinity(&self) -> ThreadAffinity {
        self.inner.thread_affinity()
    }
    fn facets(&self) -> &[FacetKind] {
        self.inner.facets()
    }
    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.inner.status()
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if SavedRuntimeActivation::from(world) != self.origin.activation {
            return Err(failure(
                "source world differs from capture preconditions",
                EffectKnowledge::None,
            ));
        }
        let ready = self.inner.arm(world)?;
        self.inner.validate_readiness(world, &ready)?;
        Ok(ready)
    }
    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_readiness(world, ready)
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<crucible_node_contract::PreparedOwner>>, OperationFailure> {
        self.inner.prepared_owners(world, ready)
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[crucible_node_contract::PreparedOwner],
    ) -> Result<(), OperationFailure> {
        self.inner.validate_prepared_owners(world, ready, owners)
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if SavedRuntimeActivation::from(world) != self.origin.activation
            || !self.operations.is_empty()
            || self.observation_sequence != 0
        {
            return Err(failure(
                "recording source is not at its actual original preparation",
                EffectKnowledge::None,
            ));
        }
        self.inner.validate_initial_preparation(world, ready)
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.check_activation(activation)?;
        let reservation = self.reserve()?;
        let identity = Id::new(format!("transcript/observe-{}", self.observation_sequence))
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let request = self.capture_request(
            TranscriptAction::Observe,
            identity,
            self.boundary,
            &ControlRequest::Observe,
        )?;
        let observation = self.inner.observe_scheduling(activation)?;
        if let Err(error) = self
            .inner
            .validate_scheduling_observation(activation, &observation)
        {
            self.invalidate();
            return Err(error);
        }
        let mut evidence =
            self.boundary_evidence(activation, &observation_references(&observation))?;
        self.retain_proof_closures(
            activation,
            &observation_proof_references(&observation),
            &mut evidence,
        )?;
        self.observation_sequence = self
            .observation_sequence
            .checked_add(1)
            .ok_or_else(|| failure("observation sequence exhausted", EffectKnowledge::None))?;
        self.retain(
            reservation,
            request,
            ControlResponse::Observation(Box::new(observation.clone())),
            evidence,
            vec![observation.reached],
        )?;
        Ok(observation)
    }
    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.inner
            .validate_scheduling_observation(activation, observation)
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.record_stage(batch, None)
    }

    fn stage_inputs_with_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.record_stage(batch, Some(provenance))
    }

    fn requires_input_provenance(&self, batch: &RuntimeInputBatch) -> bool {
        self.inner.requires_input_provenance(batch)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        ack: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_input_acknowledgement(batch, ack)
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        if let Err(error) = self.check_activation(admission.activation()) {
            return Self::refuse(error);
        }
        if self.operations.contains_key(admission.token().operation()) {
            return Self::refuse(failure(
                "recorded source operation already exists",
                EffectKnowledge::None,
            ));
        }
        let begin = match self.reserve() {
            Ok(value) => value,
            Err(error) => return Self::refuse(error),
        };
        let completion = match self.reserve() {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Self::refuse(error);
            }
        };
        let body = ControlRequest::begin(admission, &self.origin.route.owners);
        let request = match self.capture_request(
            TranscriptAction::Begin,
            admission.token().operation().clone(),
            self.boundary,
            &body,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Self::refuse(error);
            }
        };
        let submission = self.inner.begin_operation(admission);
        if let Err(error) = self.retain(
            begin,
            request,
            ControlResponse::Submission(submission.clone()),
            Vec::new(),
            Vec::new(),
        ) {
            self.invalidate();
            return Self::refuse(error);
        }
        match &submission {
            Submission::Accepted => {
                self.operations.insert(
                    admission.token().operation().clone(),
                    RecordedOperation {
                        admission: admission.clone(),
                        completion: Some(completion),
                        terminal: None,
                        acknowledged: false,
                        close_submission: None,
                    },
                );
                self.state.0.borrow_mut().pending += 1;
            }
            Submission::Refused(_) => {
                if let Some(capture) = self.state.0.borrow_mut().capture.as_mut()
                    && capture.release_no_effect(completion).is_err()
                {
                    capture.invalidate();
                }
            }
            Submission::Uncertain(_) => self.invalidate(),
        }
        submission
    }

    fn poll_operation(
        &mut self,
        token: &OperationToken,
        cx: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        let Some(original) = self.operations.get(token.operation()) else {
            return Poll::Ready(Err(failure(
                "original recording operation absent",
                EffectKnowledge::None,
            )));
        };
        if original.admission.token().route() != token.route()
            || !Rc::ptr_eq(&original.admission.token().authority, &token.authority)
        {
            return Poll::Ready(Err(failure(
                "foreign original operation token",
                EffectKnowledge::None,
            )));
        }
        if let Some(outcome) = &original.terminal {
            return Poll::Ready(Ok(outcome.clone()));
        }
        let outcome = match self.inner.poll_operation(token, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.invalidate();
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(outcome)) => outcome,
        };
        let admission = original.admission.clone();
        let captured: Result<OperationOutcome, OperationFailure> = (|| {
            self.inner.validate_outcome(&admission, &outcome)?;
            let references = outcome_references(&outcome);
            let mut evidence = if references.is_empty() {
                Vec::new()
            } else {
                let evidence = self
                    .inner
                    .read_operation_evidence(&admission, &references)?;
                self.inner
                    .validate_operation_evidence(&admission, &references, &evidence)?;
                evidence
            };
            let roots: Vec<_> = outcome
                .scheduling
                .iter()
                .filter(|observation| !observation.publications.is_empty())
                .map(|observation| observation.proof_ref.clone())
                .collect();
            self.retain_proof_closures(admission.activation(), &roots, &mut evidence)?;
            let reservation = self
                .operations
                .get_mut(token.operation())
                .and_then(|operation| operation.completion.take())
                .ok_or_else(|| {
                    failure("completion reservation absent", EffectKnowledge::Unknown)
                })?;
            let body = ControlRequest::Complete {
                operation: token.operation().clone(),
            };
            let positions = outcome_positions(&outcome);
            let request = self.capture_request(
                TranscriptAction::Complete,
                token.operation().clone(),
                self.boundary,
                &body,
            )?;
            self.retain(
                reservation,
                request,
                ControlResponse::Outcome(Box::new(outcome.clone())),
                evidence,
                positions,
            )?;
            if let Some(operation) = self.operations.get_mut(token.operation()) {
                operation.terminal = Some(outcome.clone());
            }
            Ok(outcome)
        })();
        if captured.is_err() {
            self.invalidate();
        }
        Poll::Ready(
            captured.map_err(|error| failure(error.reason, EffectKnowledge::MayHaveProgressed)),
        )
    }

    fn validate_outcome(
        &self,
        admission: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_outcome(admission, outcome)
    }
    fn read_operation_evidence(
        &self,
        admission: &OperationAdmission,
        refs: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.inner.read_operation_evidence(admission, refs)
    }
    fn validate_operation_evidence(
        &self,
        admission: &OperationAdmission,
        refs: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        self.inner
            .validate_operation_evidence(admission, refs, objects)
    }

    fn read_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.inner
            .read_boundary_evidence(activation, references, maximum_bytes)
    }

    fn validate_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        self.inner
            .validate_boundary_evidence(activation, references, objects)
    }

    fn input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        self.inner
            .input_provenance_dependencies(activation, root, limits)
    }

    fn validate_input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        self.inner
            .validate_input_provenance_dependencies(activation, root, dependencies)
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        if let Some(operation) = self.operations.get(original.token().operation())
            && let Some(submission) = &operation.close_submission
        {
            if Rc::ptr_eq(
                &operation.admission.token().authority,
                &original.token().authority,
            ) && operation.admission.token().route() == original.token().route()
            {
                return submission.clone();
            }
            return Self::refuse(failure("foreign source close token", EffectKnowledge::None));
        }
        let reservation = match self.reserve() {
            Ok(value) => value,
            Err(error) => return Self::refuse(error),
        };
        let body = ControlRequest::Close {
            operation: original.token().operation().clone(),
            request: original.request().clone(),
        };
        let request = match self.capture_request(
            TranscriptAction::CloseWindow,
            original.token().operation().clone(),
            self.boundary,
            &body,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Self::refuse(error);
            }
        };
        let submission = self.inner.close_quantum(original);
        if let Err(error) = self.retain(
            reservation,
            request,
            ControlResponse::Submission(submission.clone()),
            Vec::new(),
            Vec::new(),
        ) {
            self.invalidate();
            return Self::refuse(error);
        }
        if let Some(operation) = self.operations.get_mut(original.token().operation()) {
            operation.close_submission = Some(submission.clone());
        }
        submission
    }

    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        let reservation = self.reserve()?;
        let body = ControlRequest::Cancel {
            operation: token.operation().clone(),
        };
        let request = self.capture_request(
            TranscriptAction::Cancel,
            token.operation().clone(),
            self.boundary,
            &body,
        )?;
        let result = self.inner.request_cancel(token)?;
        self.invalidate();
        // Cancellation can leave unknown physical effects. Retain the actual
        // source response, but this prefix cannot be exported as replayable.
        let _ = self.retain(
            reservation,
            request,
            ControlResponse::Cancel(format!("{result:?}")),
            Vec::new(),
            Vec::new(),
        );
        Ok(result)
    }

    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let original = self
            .operations
            .get(token.operation())
            .ok_or_else(|| failure("source original operation absent", EffectKnowledge::None))?;
        if original.acknowledged {
            return self.inner.acknowledge_publication(token, outputs);
        }
        if original
            .terminal
            .as_ref()
            .is_none_or(|outcome| outcome.retained_outputs != outputs)
        {
            return Err(failure(
                "source terminal response or original output inventory differs",
                EffectKnowledge::None,
            ));
        }
        let reservation = self.reserve()?;
        let body = ControlRequest::Acknowledge {
            operation: token.operation().clone(),
            outputs: outputs.to_vec(),
        };
        let request = self.capture_request(
            TranscriptAction::Acknowledge,
            token.operation().clone(),
            self.boundary,
            &body,
        )?;
        self.inner.acknowledge_publication(token, outputs)?;
        let retained = (|| {
            let after = self
                .inner
                .status()
                .map_err(|error| failure(error.reason, EffectKnowledge::Unknown))?
                .boundary
                .ok_or_else(|| {
                    failure(
                        "acknowledged source boundary is unknown",
                        EffectKnowledge::Unknown,
                    )
                })?;
            self.retain(
                reservation,
                request,
                ControlResponse::Acknowledged,
                Vec::new(),
                vec![after],
            )?;
            Ok::<_, OperationFailure>(after)
        })();
        let after = match retained {
            Ok(after) => after,
            Err(error) => {
                self.invalidate();
                return Err(failure(error.reason, EffectKnowledge::Unknown));
            }
        };
        self.boundary = after;
        if let Some(original) = self.operations.get_mut(token.operation()) {
            original.acknowledged = true;
        }
        let mut state = self.state.0.borrow_mut();
        state.pending = state.pending.checked_sub(1).ok_or_else(|| {
            failure(
                "source ACK pending inventory underflow",
                EffectKnowledge::Unknown,
            )
        })?;
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.inner.facet(kind)
    }
    fn quarantine_resources(&mut self) {
        self.inner.quarantine_resources();
    }
    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        cx: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        self.inner.poll_reclamation(owner, cx)
    }
    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_reclamation(receipt)
    }
}
