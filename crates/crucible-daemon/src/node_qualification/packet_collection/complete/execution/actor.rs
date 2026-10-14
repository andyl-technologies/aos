//! Drives the same collecting runtime through the fixed complete original grants.
//!
//! The prebirth reservation owns every identifier and token slot. Attachment
//! moves the actual runtime into that existing owner before any callback. Failed
//! or uncertain transitions retain the same capsule and never submit another Begin.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    task::{Context, Poll},
};

use crucible::node_contract::{
    ActivationPublisher, BeginResult, ConformanceResultPublisher, ConformanceRuntime,
    OperationToken,
};
use crucible::node_state::NativeArchiveRecord;
use crucible_node_contract::{Id, Position};

use super::super::{PacketCompleteCaptureFactory, PacketCompleteWorldCapture};
use super::{PacketCompleteExecutionScene, QualificationError, refused, schedule};

struct Grant {
    node: Id,
    operation: Id,
    limit: Position,
    input: Option<(Id, Id)>,
    token: Option<OperationToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Attached,
    Armed,
    Active,
    Running,
    Completed,
    Held,
    Retired,
}

/// Reports a refused transition while its original actor retains all custody.
#[derive(Debug)]
pub enum PacketCompleteExecutionError {
    /// Rejects a repeated or out-of-order transition before dispatch.
    Phase,
    /// Retains the same native/runtime state after a concrete refusal.
    Refused(String),
    /// Retains a native token whose original Begin did not settle certainly.
    Uncertain,
    /// Retains the same actor after a callback unwinds.
    Unwind,
}

/// Returns an unconsumed foreign runtime when attachment was already attempted.
pub struct PacketCompleteRuntimeAttachmentFailure {
    /// Reports the original attachment refusal.
    pub error: PacketCompleteExecutionError,
    /// Returns only an incoming runtime that was never installed in this actor.
    ///
    /// A failed first attachment remains inside the actor instead.
    pub incoming: Option<ConformanceRuntime>,
}

/// Owns the original four-owner runtime, scene and all thirteen grant tokens.
///
/// This exposes no mutable runtime, ordinary graph, native controller or token
/// constructor. Keep the actor outside callback unwind boundaries until genuine
/// native supervision has accepted its original resources.
#[must_use = "retain the original actor and all tokens through reclamation"]
pub struct PacketCompleteExecutionActor {
    scene: Rc<PacketCompleteExecutionScene>,
    runtime: Option<ConformanceRuntime>,
    grants: Vec<Grant>,
    next: usize,
    phase: Phase,
    attachment_attempted: bool,
    process: u32,
    thread: std::thread::ThreadId,
}

impl PacketCompleteExecutionScene {
    /// Reserves all fixed execution identifiers and token slots before Child.
    ///
    /// No native callback, grant, Arm or scheduling attachment is performed.
    /// The returned owner later receives the actual complete collecting runtime.
    ///
    /// # Errors
    /// Refuses stale original scene data or unavailable finite pointer storage.
    pub fn reserve_actor(
        self: &Rc<Self>,
    ) -> Result<Box<PacketCompleteExecutionActor>, QualificationError> {
        self.current()?;
        if self.actor_reserved.replace(true) {
            return Err(refused());
        }
        let mut grants = Vec::new();
        grants
            .try_reserve_exact(schedule::GRANTS)
            .map_err(|_| refused())?;
        for index in 0..schedule::GRANTS {
            let (member, operation, request) = schedule::row(index).ok_or_else(refused)?;
            let limit = match request {
                crucible::node_contract::OperationRequest::ExactRun { limit, .. }
                | crucible::node_contract::OperationRequest::BoundarySettle { limit, .. } => limit,
                _ => return Err(refused()),
            };
            grants.push(Grant {
                node: self.oracle.execution_schedule().nodes[member].clone(),
                operation: Id::new(operation)?,
                limit,
                input: if member == 0 {
                    None
                } else {
                    Some((
                        Id::new(format!("complete-stage-{index}"))?,
                        Id::new(format!("complete-batch-{index}"))?,
                    ))
                },
                token: None,
            });
        }
        self.current()?;
        Ok(Box::new(PacketCompleteExecutionActor {
            scene: Rc::clone(self),
            runtime: None,
            grants,
            next: 0,
            phase: Phase::Reserved,
            attachment_attempted: false,
            process: std::process::id(),
            thread: std::thread::current().id(),
        }))
    }
}

impl PacketCompleteExecutionActor {
    /// Moves the same actual inactive runtime into this original reservation once.
    ///
    /// # Errors
    /// Rejects foreign/active plans or repeated attachment. The first runtime is
    /// stored before validation or callback unwind and remains held on failure.
    pub fn attach(
        &mut self,
        incoming: ConformanceRuntime,
    ) -> Result<(), PacketCompleteRuntimeAttachmentFailure> {
        if self.attachment_attempted {
            return Err(PacketCompleteRuntimeAttachmentFailure {
                error: PacketCompleteExecutionError::Phase,
                incoming: Some(incoming),
            });
        }
        self.attachment_attempted = true;
        self.phase = Phase::Held;
        self.runtime = Some(incoming);
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.scene.preparation().map_err(failure)?;
            self.runtime
                .as_mut()
                .ok_or(PacketCompleteExecutionError::Phase)?
                .validate_inactive_collection_plan(&self.scene.plan)
                .map_err(failure)
        }));
        match result {
            Ok(Ok(())) => {
                self.scene.runtime_attached.set(true);
                self.phase = Phase::Attached;
                Ok(())
            }
            Ok(Err(error)) => Err(PacketCompleteRuntimeAttachmentFailure {
                error,
                incoming: None,
            }),
            Err(_) => Err(PacketCompleteRuntimeAttachmentFailure {
                error: PacketCompleteExecutionError::Unwind,
                incoming: None,
            }),
        }
    }

    /// Collects actual readiness from every same original native and Host2 node.
    ///
    /// # Errors
    /// Retains the original runtime on wrong phase, source refusal or unwind.
    pub fn arm(&mut self) -> Result<(), PacketCompleteExecutionError> {
        self.require(Phase::Attached)?;
        self.phase = Phase::Held;
        self.runtime_mut()?.arm_all().map_err(failure)?;
        self.phase = Phase::Armed;
        Ok(())
    }

    /// Durably publishes and activates the same actual initial four-owner world.
    ///
    /// # Errors
    /// Holds the same readiness, publisher state and runtime after any refusal.
    pub fn activate(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
        maximum_record_bytes: usize,
    ) -> Result<(), PacketCompleteExecutionError> {
        self.require(Phase::Armed)?;
        self.phase = Phase::Held;
        self.runtime_mut()?
            .activate_initial(publisher, maximum_record_bytes)
            .map_err(failure)?;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Stages the next actual exclusive cut and submits its original Begin once.
    ///
    /// Empty reactive cuts also perform genuine Stage/ACK/Commit. An uncertain
    /// Begin token is stored in its preexisting slot before returning refusal.
    ///
    /// # Errors
    /// Holds original input/operation state after a failed cut, refusal or unwind.
    pub fn begin_next(&mut self) -> Result<(), PacketCompleteExecutionError> {
        self.require(Phase::Active)?;
        self.scene.live().map_err(failure)?;
        self.scene.current_grant.set(Some(self.next));
        self.phase = Phase::Held;
        let original = self
            .grants
            .get(self.next)
            .ok_or(PacketCompleteExecutionError::Phase)?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(PacketCompleteExecutionError::Phase)?;
        if let Some((stage, batch)) = &original.input {
            runtime
                .stage_exact_inputs(&original.node, stage.clone(), batch.clone(), original.limit)
                .map_err(failure)?;
        }
        let result = runtime
            .begin_exact_position(&original.node, original.operation.clone(), original.limit)
            .map_err(failure)?;
        match result {
            BeginResult::Accepted(token) => {
                self.grants[self.next].token = Some(token);
                self.phase = Phase::Running;
                Ok(())
            }
            BeginResult::Uncertain { token, .. } => {
                self.grants[self.next].token = Some(token);
                Err(PacketCompleteExecutionError::Uncertain)
            }
            BeginResult::Refused(_) => Err(PacketCompleteExecutionError::Refused(
                "original complete Begin refused".into(),
            )),
        }
    }

    /// Polls only the retained token without submitting another operation.
    ///
    /// # Errors
    /// Holds the original token after failed native polling or wrong phase.
    pub fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), PacketCompleteExecutionError>> {
        if let Err(error) = self.require(Phase::Running) {
            return Poll::Ready(Err(error));
        }
        self.phase = Phase::Held;
        let Some(token) = self
            .grants
            .get(self.next)
            .and_then(|grant| grant.token.as_ref())
        else {
            return Poll::Ready(Err(PacketCompleteExecutionError::Phase));
        };
        let Some(runtime) = self.runtime.as_mut() else {
            return Poll::Ready(Err(PacketCompleteExecutionError::Phase));
        };
        match runtime.poll(token, context) {
            Poll::Pending => {
                self.phase = Phase::Running;
                Poll::Pending
            }
            Poll::Ready(Ok(_)) => {
                self.phase = Phase::Completed;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(failure(error))),
        }
    }

    /// Publishes the original completion durably before its scheduling/native ACK.
    ///
    /// # Errors
    /// Holds the same token and partial publication after refusal or uncertainty.
    pub fn acknowledge(
        &mut self,
        publisher: &mut dyn ConformanceResultPublisher,
    ) -> Result<(), PacketCompleteExecutionError> {
        self.require(Phase::Completed)?;
        self.phase = Phase::Held;
        let token = self
            .grants
            .get(self.next)
            .and_then(|grant| grant.token.as_ref())
            .ok_or(PacketCompleteExecutionError::Phase)?;
        self.runtime
            .as_mut()
            .ok_or(PacketCompleteExecutionError::Phase)?
            .publish_and_acknowledge(token, publisher)
            .map_err(failure)?;
        self.next += 1;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Captures between original grants through the same retained Core runtime.
    ///
    /// # Errors
    /// Holds this runtime and its original administrative attempt on any refusal.
    pub fn capture(
        &mut self,
        factory: &PacketCompleteCaptureFactory,
        request: PacketCompleteWorldCapture<'_>,
    ) -> Result<NativeArchiveRecord, PacketCompleteExecutionError> {
        self.require(Phase::Active)?;
        factory
            .authenticate_authority_object(self.scene.authority.as_ref())
            .map_err(failure)?;
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(PacketCompleteExecutionError::Phase);
        }
        // Count the existing Box and every independently owned grant/token
        // buffer before Core can prepare or dispatch a Capture. Core separately
        // charges the same runtime's internal banks; no runtime is moved out.
        let mut counter = super::super::retained::Counter::new(factory.daemon_storage_limit());
        counter.add(std::mem::size_of::<Self>()).map_err(failure)?;
        counter
            .add(
                self.grants
                    .capacity()
                    .checked_mul(std::mem::size_of::<Grant>())
                    .ok_or(PacketCompleteExecutionError::Phase)?,
            )
            .map_err(failure)?;
        for grant in &self.grants {
            counter.charge(&grant.node).map_err(failure)?;
            counter.charge(&grant.operation).map_err(failure)?;
            counter.charge(&grant.input).map_err(failure)?;
            if let Some(token) = &grant.token {
                counter.charge(token.operation()).map_err(failure)?;
                counter.charge(token.route()).map_err(failure)?;
            }
        }
        let identity = (self as *const Self).cast();
        self.phase = Phase::Held;
        let loan = factory
            .loan_actor_storage(&self.scene, identity, counter.bytes())
            .map_err(failure)?;
        // These borrows freeze all heap owners used to issue the private loan;
        // callbacks receive only the disjoint actual runtime below.
        let freeze = ActorMetadataBorrow {
            _grants: &self.grants,
            _scene: &self.scene,
        };
        let result = factory
            .capture_original_world(
                self.runtime
                    .as_mut()
                    .ok_or(PacketCompleteExecutionError::Phase)?,
                request,
            )
            .map_err(failure);
        drop(freeze);
        drop(loan);
        let result = result?;
        self.phase = Phase::Active;
        Ok(result)
    }

    /// Transfers the same actual runtime to its original pre-reserved supervisor.
    ///
    /// # Errors
    /// Holds the runtime if original resource containment is unresolved.
    pub fn retire_original(&mut self) -> Result<(), PacketCompleteExecutionError> {
        if self.phase == Phase::Retired {
            return Err(PacketCompleteExecutionError::Phase);
        }
        self.phase = Phase::Held;
        self.scene.current_grant.set(None);
        self.scene.runtime_attached.set(false);
        self.runtime_mut()?.retire_original().map_err(failure)?;
        self.phase = Phase::Retired;
        Ok(())
    }

    fn require(&self, expected: Phase) -> Result<(), PacketCompleteExecutionError> {
        if self.phase != expected {
            return Err(PacketCompleteExecutionError::Phase);
        }
        Ok(())
    }

    fn runtime_mut(&mut self) -> Result<&mut ConformanceRuntime, PacketCompleteExecutionError> {
        self.runtime
            .as_mut()
            .ok_or(PacketCompleteExecutionError::Phase)
    }
}

fn failure(error: impl std::fmt::Display) -> PacketCompleteExecutionError {
    PacketCompleteExecutionError::Refused(error.to_string())
}

struct ActorMetadataBorrow<'a> {
    _grants: &'a Vec<Grant>,
    _scene: &'a Rc<PacketCompleteExecutionScene>,
}

impl Drop for ActorMetadataBorrow<'_> {
    fn drop(&mut self) {}
}
