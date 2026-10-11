//! Drives original finite quantized collection without exposing ordinary runtime.
//!
//! The actor supplies readiness/publication services and polls the same original
//! token. Each source completion is durably ACKed and independently collected
//! before its successor Stage can replace the latest retained input witness.

use super::{
    TypedReaderHostCollection, TypedReaderProgramme, TypedReaderWindowTicket,
    TypedReaderWitnessAuthority,
};
use crate::node_qualification::QualificationError;
use crucible::node_contract::{
    ActivationPublisher, BeginResult, ConformanceResultPublisher, ConformanceRuntime,
    OperationRequest, OperationToken, RuntimeError, RuntimePollFailure, Submission,
};
use crucible_node_contract::{Phase, Position, U64};
use crucible_node_provider::ProviderError;
use std::{
    rc::Rc,
    task::{Context, Poll},
};

/// Classifies source, runtime and independent collection refusal without replacement.
#[derive(Debug)]
pub enum TypedReaderDrivingError {
    /// Retains an original runtime admission/publication refusal.
    Runtime(RuntimeError),
    /// Retains the actual native poll or scheduling failure.
    Poll(Box<RuntimePollFailure>),
    /// Retains independent original-source oracle refusal.
    Source(ProviderError),
    /// Retains the independently installed host collector refusal.
    Collection(QualificationError),
    /// Refuses a changed or repeated finite transition.
    Transition(&'static str),
}

impl std::fmt::Display for TypedReaderDrivingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(formatter),
            Self::Poll(error) => error.fmt(formatter),
            Self::Source(error) => error.fmt(formatter),
            Self::Collection(error) => error.fmt(formatter),
            Self::Transition(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for TypedReaderDrivingError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaseState {
    Inactive,
    Idle,
    Open,
    Closed,
    Complete,
    Failed,
}

/// Owns the same collecting runtime through nine source-authenticated windows.
///
/// This owner has no ordinary graph/runtime getter or accepted-class output.
/// Failed/uncertain transitions remain sticky and keep their original opaque
/// operation token. Drop transfers runtime custody through its prior supervisor.
pub struct TypedReaderCollectingDriver {
    runtime: ConformanceRuntime,
    programme: Rc<TypedReaderProgramme>,
    authority: Rc<TypedReaderWitnessAuthority>,
    next: usize,
    phase: PhaseState,
    token: Option<OperationToken>,
    ticket: Option<TypedReaderWindowTicket>,
}

impl TypedReaderCollectingDriver {
    pub(super) fn retire_original(&mut self) -> Result<(), RuntimeError> {
        self.runtime.retire_original()
    }

    /// Retains an already owned collection-only runtime and independent source oracle.
    ///
    /// The runtime constructor must already have consumed the original graph,
    /// native handles and whole-world custody reservation. Every later operation
    /// repeats that runtime's exact original plan/source authorization.
    pub fn new(
        runtime: ConformanceRuntime,
        programme: Rc<TypedReaderProgramme>,
        authority: Rc<TypedReaderWitnessAuthority>,
    ) -> Self {
        Self {
            runtime,
            programme,
            authority,
            next: 0,
            phase: PhaseState::Inactive,
            token: None,
            ticket: None,
        }
    }

    /// Arms every actual owner and publishes its authentic complete initial coordinator.
    ///
    /// # Errors
    /// Refuses repeated activation, failed current custody/readiness or uncertain
    /// original publication. Failure never creates another activation or runtime.
    pub fn activate(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
        maximum_record_bytes: usize,
    ) -> Result<(), TypedReaderDrivingError> {
        if self.phase != PhaseState::Inactive {
            return Err(invalid());
        }
        self.phase = PhaseState::Failed;
        self.runtime
            .arm_all()
            .map_err(TypedReaderDrivingError::Runtime)?;
        self.runtime
            .activate_initial(publisher, maximum_record_bytes)
            .map_err(TypedReaderDrivingError::Runtime)?;
        self.phase = PhaseState::Idle;
        Ok(())
    }

    /// Records the host attempt, stages its complete batch and begins the planned window.
    ///
    /// # Errors
    /// Refuses changed programme/current native source, another outstanding token,
    /// failed Stage/ACK, refused Begin or uncertain effects. It never retries by
    /// replacing an operation, batch, window or owning native process.
    pub fn begin_next(
        &mut self,
        collection: &mut TypedReaderHostCollection<'_>,
    ) -> Result<(), TypedReaderDrivingError> {
        if self.phase != PhaseState::Idle || self.token.is_some() || self.ticket.is_some() {
            return Err(invalid());
        }
        let planned = self
            .programme
            .windows()
            .get(self.next)
            .ok_or_else(invalid)?;
        let OperationRequest::QuantumBegin { start, .. } = &planned.request else {
            return Err(invalid());
        };
        let cutoff = Position::new(start.time_ps, U64::new(1), Phase::BoundaryControl);
        self.phase = PhaseState::Failed;
        collection
            .authenticate_authority(self.authority.as_ref())
            .map_err(TypedReaderDrivingError::Collection)?;
        // Declaring the attempt precedes the first effect-capable Stage. A
        // later refusal retains this ticket and the host's sticky attempt.
        self.ticket = Some(
            collection
                .begin_window(&planned.case)
                .map_err(TypedReaderDrivingError::Collection)?,
        );
        self.runtime
            .stage_quantized_inputs(
                &planned.node,
                planned.stage.clone(),
                planned.batch.clone(),
                cutoff,
            )
            .map_err(|error| TypedReaderDrivingError::Poll(Box::new(error)))?;
        match self
            .runtime
            .begin_quantized(
                &planned.node,
                planned.operation.clone(),
                planned.window.clone(),
                planned.batch.clone(),
            )
            .map_err(TypedReaderDrivingError::Runtime)?
        {
            BeginResult::Accepted(token) => {
                self.token = Some(token);
                self.phase = PhaseState::Open;
                Ok(())
            }
            BeginResult::Uncertain { token, .. } => {
                self.token = Some(token);
                Err(TypedReaderDrivingError::Transition(
                    "original typed Begin remains uncertain",
                ))
            }
            BeginResult::Refused(_) => Err(TypedReaderDrivingError::Transition(
                "original typed Begin refused",
            )),
        }
    }

    /// Sends Close once to the same original native window and retains its token.
    ///
    /// # Errors
    /// Refuses another phase or uncertain/failed close; every original native
    /// obligation remains retained without a replacement Close or Begin.
    pub fn close_original(&mut self) -> Result<(), TypedReaderDrivingError> {
        if self.phase != PhaseState::Open {
            return Err(invalid());
        }
        let token = self.token.as_ref().ok_or_else(invalid)?;
        self.phase = PhaseState::Failed;
        match self
            .runtime
            .close_quantum(token)
            .map_err(TypedReaderDrivingError::Runtime)?
        {
            Submission::Accepted => {
                self.phase = PhaseState::Closed;
                Ok(())
            }
            Submission::Refused(_) => Err(TypedReaderDrivingError::Transition(
                "original typed Close refused",
            )),
            Submission::Uncertain(_) => Err(TypedReaderDrivingError::Transition(
                "original typed Close remains uncertain",
            )),
        }
    }

    /// Polls the same token and joins its outcome to a previously sealed native oracle.
    ///
    /// This method introduces no delay, new deadline or busy loop. Pending is
    /// returned to the owning actor with its original waker/context unchanged.
    ///
    /// # Errors
    /// Refuses another phase, original poll failure or a complete native outcome
    /// different from the independently enrolled source programme expectation.
    pub fn poll_original(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), TypedReaderDrivingError>> {
        if self.phase != PhaseState::Closed {
            return Poll::Ready(Err(invalid()));
        }
        let Some(token) = &self.token else {
            return Poll::Ready(Err(invalid()));
        };
        match self.runtime.poll(token, context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.phase = PhaseState::Failed;
                Poll::Ready(Err(TypedReaderDrivingError::Poll(Box::new(error))))
            }
            Poll::Ready(Ok(outcome)) => {
                self.phase = PhaseState::Failed;
                let checked = (|| {
                    let planned = self
                        .programme
                        .windows()
                        .get(self.next)
                        .ok_or_else(invalid)?;
                    let expected = self
                        .authority
                        .expected_outcome(&planned.case)
                        .map_err(TypedReaderDrivingError::Source)?;
                    if expected != outcome {
                        return Err(invalid());
                    }
                    Ok(())
                })();
                if checked.is_ok() {
                    self.phase = PhaseState::Complete;
                }
                Poll::Ready(checked)
            }
        }
    }

    /// Durably ACKs and collects the latest complete original before successor Stage.
    ///
    /// The expected case is derived from enrolled native/source originals before
    /// the collector borrows any common completion/report. The publisher retains
    /// every original proof and payload body before native publication ACK.
    ///
    /// # Errors
    /// Refuses incomplete/mismatched source oracles, uncertain durability/native
    /// ACK, missing original Stage closure or independent report authentication.
    /// A failed collection remains sticky with the same runtime and token.
    pub fn collect_original(
        &mut self,
        publisher: &mut dyn ConformanceResultPublisher,
        collection: &mut TypedReaderHostCollection<'_>,
    ) -> Result<(), TypedReaderDrivingError> {
        if self.phase != PhaseState::Complete {
            return Err(invalid());
        }
        let token = self.token.as_ref().ok_or_else(invalid)?;
        self.phase = PhaseState::Failed;
        collection
            .authenticate_authority(self.authority.as_ref())
            .map_err(TypedReaderDrivingError::Collection)?;
        self.runtime
            .publish_and_acknowledge(token, publisher)
            .map_err(|error| TypedReaderDrivingError::Poll(Box::new(error)))?;
        let mut witness = self
            .runtime
            .original_witness()
            .map_err(TypedReaderDrivingError::Runtime)?;
        let ticket = self.ticket.take().ok_or_else(invalid)?;
        collection
            .collect_window(ticket, &mut witness, token)
            .map_err(TypedReaderDrivingError::Collection)?;
        self.token = None;
        self.next += 1;
        self.phase = PhaseState::Idle;
        Ok(())
    }

    /// Reports complete nine-window collection without class or readiness authority.
    pub fn is_finished(&self) -> bool {
        self.phase == PhaseState::Idle && self.next == self.programme.windows().len()
    }
}

fn invalid() -> TypedReaderDrivingError {
    TypedReaderDrivingError::Transition("typed collection original transition differs")
}
