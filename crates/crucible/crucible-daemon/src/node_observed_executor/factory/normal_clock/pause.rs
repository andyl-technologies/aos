//! Executes the advertised actual physical-pause operation at a closed boundary.

use super::*;

pub(super) struct OriginalClockPause {
    operation: Id,
    expected: OperationOutcome,
    proof: InputPayload,
    token: Option<OperationToken>,
    actual: Option<Vec<InputPayload>>,
    attempted: bool,
    unexpected: Option<OperationToken>,
    busy_refused: bool,
    duplicate_refused: bool,
    wrong_ack_refused: bool,
    pub(super) acknowledged: bool,
}

impl OriginalClockPause {
    pub(super) fn new(node: &Id, owners: &[OwnerIdentity]) -> Result<Self, NodeObservedError> {
        let operation = Id::new("clock/physical-pause")?;
        let (_, at, _) = CASES
            .last()
            .ok_or_else(|| refused("Clock source population absent"))?;
        let reached = Position::new(U64::new(*at), 0.into(), Phase::BoundaryControl);
        // Independent source-side bytes bind the closed no-autonomous-worker
        // model and complete original owner roster before any original Arm.
        let mut bytes = b"host-model-no-autonomous-worker-v1".to_vec();
        bytes.extend_from_slice(&at.to_le_bytes());
        for owner in owners {
            bytes.extend_from_slice(owner.owner.as_str().as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(owner.incarnation.as_str().as_bytes());
            bytes.extend_from_slice(&owner.generation.get().to_le_bytes());
        }
        let proof = InputPayload {
            reference: canonical::content_ref(&bytes, "application/octet-stream")?,
            bytes,
        };
        let expected = OperationOutcome {
            operation: operation.clone(),
            node: node.clone(),
            owners: owners.to_vec(),
            progress: ProgressEvidence::Paused {
                reached: Some(reached),
                stop_receipt: proof.reference.clone(),
            },
            retained_outputs: Vec::new(),
            scheduling: None,
        };
        Ok(Self {
            operation,
            expected,
            proof,
            token: None,
            actual: None,
            attempted: false,
            unexpected: None,
            busy_refused: false,
            duplicate_refused: false,
            wrong_ack_refused: false,
            acknowledged: false,
        })
    }
    pub(super) fn complete(&self) -> bool {
        self.attempted
            && self.acknowledged
            && self.busy_refused
            && self.duplicate_refused
            && self.wrong_ack_refused
            && self.unexpected.is_none()
            && self.token.is_some()
            && self.actual.as_ref().is_some_and(|rows| {
                rows.len() == 1
                    && rows[0].reference == self.proof.reference
                    && rows[0].bytes == self.proof.bytes
            })
    }
}

impl OriginalClockQualificationRun {
    /// Exercises the selected physical-pause facet through production custody.
    ///
    /// The full stopped outcome and original native proof bytes were retained
    /// before Arm. This does not infer physical suspension from a logical exact
    /// horizon, fabricate a scheduler publication, or execute a test-only path.
    ///
    /// # Errors
    /// Refuses incomplete exact cases, duplicate/stale originals, submission,
    /// pending/mismatched native stop, changed proof, moved frontier or failed ACK.
    pub fn execute_original_pause(&mut self) -> Result<(), NodeObservedError> {
        self.current()?;
        if self.failed || self.next != self.cases.len() || self.pause.attempted {
            return Err(refused("original Clock physical pause unavailable"));
        }
        self.pause.attempted = true;
        self.failed = true;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("actual Clock activation absent"))?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| refused("actual Clock runtime retired"))?;
        let before = runtime
            .scheduler(&self.graph, activation)?
            .position(&self.node)?;
        match runtime.begin_exact_boundary_pause(
            &self.graph,
            activation,
            &self.node,
            self.pause.operation.clone(),
        )? {
            BeginResult::Accepted(token) => self.pause.token = Some(token),
            BeginResult::Uncertain { token, .. } => {
                self.pause.token = Some(token);
                return Err(refused("original Clock physical pause uncertain"));
            }
            BeginResult::Refused(_) => {
                return Err(refused("original Clock physical pause refused"));
            }
        }
        // A second operation on this same paused owner must refuse before its
        // native callback. Keep any unexpected accepted token in the owner.
        match runtime.begin_exact_boundary_pause(
            &self.graph,
            activation,
            &self.node,
            Id::new("clock/pause-busy")?,
        ) {
            Err(crucible_engine::node_contract::RuntimeError::OwnerBusy) => {
                self.pause.busy_refused = true
            }
            Ok(BeginResult::Accepted(token) | BeginResult::Uncertain { token, .. }) => {
                self.pause.unexpected = Some(token);
                return Err(refused("Clock pause owner exclusivity failed"));
            }
            _ => return Err(refused("Clock pause busy refusal differs")),
        }
        let token = self
            .pause
            .token
            .as_ref()
            .ok_or_else(|| refused("original Clock pause token absent"))?;
        let actual = match runtime.poll(token, &mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(outcome)) => outcome,
            Poll::Ready(Err(error)) => return Err(super::super::native(error)),
            Poll::Pending => return Err(refused("synchronous original Clock pause pending")),
        };
        if actual != self.pause.expected {
            return Err(refused(
                "actual Clock physical stop differs from independent source oracle",
            ));
        }
        self.pause.actual = Some(runtime.original_witness().operation_evidence(
            token,
            std::slice::from_ref(&self.pause.proof.reference),
            U64::new(MAXIMUM_CASE_BYTES as u64),
        )?);
        let expected = &self.pause.proof;
        let actual = self
            .pause
            .actual
            .as_ref()
            .ok_or_else(|| refused("actual Clock pause proof absent"))?;
        if actual.len() != 1
            || actual[0].reference != expected.reference
            || actual[0].bytes != expected.bytes
        {
            return Err(refused(
                "actual original Clock stopped receipt bytes differ",
            ));
        }
        runtime.acknowledge_exact_boundary_pause(&self.graph, activation, token)?;
        let original = runtime.original_completed_operation(token)?;
        if original.admission().request() != &OperationRequest::Pause
            || !original.acknowledged()
            || runtime
                .scheduler(&self.graph, activation)?
                .position(&self.node)?
                != before
        {
            return Err(refused(
                "original Clock physical pause ACK or coordinator position changed",
            ));
        }
        let exact = self
            .cases
            .first()
            .and_then(|case| case.token.as_ref())
            .ok_or_else(|| refused("original exact Clock token absent"))?;
        if !matches!(
            runtime.acknowledge_exact_boundary_pause(&self.graph, activation, exact),
            Err(
                crucible_engine::node_contract::RuntimePollFailure::Admission(
                    crucible_engine::node_contract::RuntimeError::ForeignAuthority
                )
            )
        ) {
            return Err(refused("Clock pause ACK accepted another operation kind"));
        }
        self.pause.wrong_ack_refused = true;
        match runtime.begin_exact_boundary_pause(
            &self.graph,
            activation,
            &self.node,
            self.pause.operation.clone(),
        ) {
            Err(crucible_engine::node_contract::RuntimeError::DuplicateOperation) => {
                self.pause.duplicate_refused = true
            }
            Ok(BeginResult::Accepted(token) | BeginResult::Uncertain { token, .. }) => {
                self.pause.unexpected = Some(token);
                return Err(refused("Clock pause duplicate created another operation"));
            }
            _ => return Err(refused("Clock pause duplicate refusal differs")),
        }
        // Lost caller ACK knowledge recovers this exact token and repeats only
        // the original acknowledgement; no second pause is dispatched.
        let recovered = runtime.recover(&self.pause.operation)?;
        if !recovered.same_authority(token) {
            return Err(refused("Clock pause recovery changed original authority"));
        }
        runtime.acknowledge_exact_boundary_pause(&self.graph, activation, &recovered)?;
        self.pause.acknowledged = true;
        self.admission_cases.inspect_closed_frontier(
            runtime,
            &self.graph,
            activation,
            &self.node,
            &self.cases,
        )?;
        self.current()?;
        self.failed = false;
        Ok(())
    }
}

#[cfg(test)]
#[path = "pause_tests.rs"]
mod tests;

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockPause {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            operation,
            expected,
            proof,
            token,
            actual,
            attempted: _,
            unexpected,
            busy_refused: _,
            duplicate_refused: _,
            wrong_ack_refused: _,
            acknowledged: _,
        } = self;
        counter.charge(operation)?;
        counter.charge(expected)?;
        counter.charge(proof)?;
        counter.charge(token)?;
        counter.charge(actual)?;
        counter.charge(unexpected)
    }
}
