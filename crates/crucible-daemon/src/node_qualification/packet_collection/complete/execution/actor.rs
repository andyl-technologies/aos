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

use crucible::node_adapters::cnp::CnpSemanticSource;
use crucible::node_contract::{
    ActivationPublisher, BeginResult, ConformanceResultPublisher, ConformanceRuntime,
    OperationToken,
};
use crucible::node_state::NativeArchiveRecord;
use crucible_node_contract::{Id, Position};

use super::super::{PacketCompleteCaptureFactory, PacketCompleteWorldCapture};
use super::{PacketCompleteExecutionScene, QualificationError, refused, schedule};

mod construction;

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
    supervisor: Rc<crate::node_qualification::PacketWorldHostSupervisor>,
    supervision_proposal: Option<crucible::node_contract::ActivationRecord>,
    supervision_attempted: bool,
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
        let supervisor =
            Rc::new(crate::node_qualification::PacketWorldHostSupervisor::new_complete_original()?);
        let bootstrap = schedule::bootstrap_data(self.oracle.execution_schedule())?;
        let mut grants = Vec::new();
        grants
            .try_reserve_exact(schedule::GRANTS)
            .map_err(|_| refused())?;
        for index in 0..schedule::GRANTS {
            let (member, operation, request) = bootstrap.row(index).ok_or_else(refused)?;
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
            supervisor,
            supervision_proposal: None,
            supervision_attempted: false,
            process: std::process::id(),
            thread: std::thread::current().id(),
        }))
    }
}

impl PacketCompleteExecutionActor {
    /// Reserves the same three native slots and one four-owner runtime slot once.
    ///
    /// Call this before Child and pass these exact returned slots into the real
    /// selected Source/native construction. The proposal remains plain data;
    /// existing Source/plan/Arm/current-runtime gates independently issue rights.
    /// A failed first reservation stays spent and retains its original supervisor.
    ///
    /// # Errors
    /// Refuses foreign creator, changed source owner roster/world, incompatible
    /// finite limits, repeated reservation or exhausted original custody slots.
    pub fn reserve_original_supervision(
        &mut self,
        proposal: &crucible::node_contract::ActivationRecord,
        limits: crucible::node_contract::RuntimeLimits,
    ) -> Result<
        crate::node_qualification::PacketWorldOriginalReservations,
        PacketCompleteExecutionError,
    > {
        self.require(Phase::Reserved)?;
        self.original_creator()?;
        if self.supervision_attempted
            || proposal.owners.len() != 4
            || proposal.world_binding_hash != *self.scene.authority.host_source().world()
            || limits.maximum_nodes != 4
            || limits.maximum_owners != 4
            || limits.maximum_operations == 0
            || limits.maximum_operations > 64
        {
            return Err(PacketCompleteExecutionError::Phase);
        }
        self.scene.current().map_err(failure)?;
        for source in &self.scene.authority.roster().sources {
            let installation = source.installation();
            authenticate_proposed_owner(proposal, &installation.owner, &installation.binding)?;
        }
        let host = self.scene.authority.host_source().selection();
        authenticate_proposed_owner(proposal, &host.owner, &host.binding)?;
        self.supervision_attempted = true;
        self.supervision_proposal = Some(proposal.clone());
        self.supervisor
            .reserve_original(proposal, limits)
            .map_err(failure)
    }

    /// Borrows the same cleanup owner for retention outside actor unwind/drop.
    ///
    /// The caller retains an Rc alias through authentic reclamation. This owner
    /// exposes only custody reservation/cleanup, never native execution authority.
    pub fn original_supervisor(&self) -> &Rc<crate::node_qualification::PacketWorldHostSupervisor> {
        &self.supervisor
    }

    /// Drives selected cleanup with the same bounded original wake allocation.
    ///
    /// Source/Child liveness is deliberately not required to reclaim old custody.
    /// Cancellation, phase refusal and transport error leave this owner intact.
    ///
    /// # Errors
    /// Refuses foreign creator, unsupported selection or exhausted transport/pass
    /// bounds without dropping the original runtime or native capsules.
    pub fn drive_original_reclamation(
        &self,
        maximum_passes: usize,
    ) -> Result<
        Poll<
            Result<
                crate::node_qualification::PacketWorldSupervisionObservation,
                crate::node_qualification::PacketSupervisionFailure,
            >,
        >,
        PacketCompleteExecutionError,
    > {
        self.original_creator()?;
        self.supervisor
            .drive_complete_original_reclamation(maximum_passes)
            .map_err(failure)
    }

    fn original_creator(&self) -> Result<(), PacketCompleteExecutionError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(PacketCompleteExecutionError::Phase);
        }
        Ok(())
    }

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
            let proposal = self
                .supervision_proposal
                .as_ref()
                .ok_or(PacketCompleteExecutionError::Phase)?;
            self.runtime
                .as_mut()
                .ok_or(PacketCompleteExecutionError::Phase)?
                .validate_inactive_collection_proposal(&self.scene.plan, proposal)
                .map_err(failure)?;
            self.supervisor
                .authenticate_complete_original_runtime(
                    self.runtime
                        .as_mut()
                        .ok_or(PacketCompleteExecutionError::Phase)?,
                )
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

    /// Collects and durably publishes this scene's real completion before ACK.
    ///
    /// The concrete publisher enrolls the actual original runtime witness with
    /// the scene's independent native oracle. It retains every report and store
    /// partial; publication alone never supplies scheduling or native authority.
    ///
    /// # Errors
    /// Holds the same token and publisher after report, placement or ACK failure.
    pub fn acknowledge_stored(
        &mut self,
        publisher: &mut super::super::StoredPacketCompleteResultPublisher,
    ) -> Result<(), PacketCompleteExecutionError> {
        self.require(Phase::Completed)?;
        self.phase = Phase::Held;
        let token = self
            .grants
            .get(self.next)
            .and_then(|grant| grant.token.as_ref())
            .ok_or(PacketCompleteExecutionError::Phase)?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(PacketCompleteExecutionError::Phase)?;
        {
            let mut witness = runtime.original_witness().map_err(failure)?;
            publisher
                .collect_original(&mut witness, token)
                .map_err(failure)?;
        }
        runtime
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
        if counter.rc(&self.supervisor).map_err(failure)? {
            counter
                .add(
                    self.supervisor
                        .retained_requested_storage_data(counter.remaining())
                        .map_err(failure)?,
                )
                .map_err(failure)?;
        }
        counter
            .charge(&self.supervision_proposal)
            .map_err(failure)?;
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
            _supervisor: &self.supervisor,
            _proposal: &self.supervision_proposal,
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
    PacketCompleteExecutionError::Refused(super::super::construction_diagnostics::reason(error))
}

struct ActorMetadataBorrow<'a> {
    _grants: &'a Vec<Grant>,
    _scene: &'a Rc<PacketCompleteExecutionScene>,
    _supervisor: &'a Rc<crate::node_qualification::PacketWorldHostSupervisor>,
    _proposal: &'a Option<crucible::node_contract::ActivationRecord>,
}

impl Drop for ActorMetadataBorrow<'_> {
    fn drop(&mut self) {}
}

fn authenticate_proposed_owner(
    proposal: &crucible::node_contract::ActivationRecord,
    owner: &crucible_node_contract::OwnerBinding,
    binding: &crucible_node_contract::NodeBinding,
) -> Result<(), PacketCompleteExecutionError> {
    if binding
        .authority
        .activation_id
        .as_ref()
        .is_some_and(|actual| actual != &proposal.activation_id)
        || !proposal.owners.iter().any(|actual| {
            actual.owner == owner.owner.id
                && actual.incarnation == binding.authority.incarnation_id
                && actual.generation == binding.authority.owner_generation
        })
    {
        return Err(PacketCompleteExecutionError::Phase);
    }
    Ok(())
}

#[cfg(test)]
#[path = "actor/supervision_tests.rs"]
mod supervision_tests;

impl PacketCompleteExecutionActor {
    pub(in crate::node_qualification::packet_collection::complete) fn original_inactive_retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crucible::node_contract::RuntimeError> {
        self.inactive_storage_selected_precredit_data(maximum, None)
    }

    fn inactive_storage_selected_precredit_data(
        &self,
        maximum: usize,
        initial_sources: Option<
            &[Rc<crucible::node_adapters::cnp::PacketCompleteSemanticSource>; 3],
        >,
    ) -> Result<usize, crucible::node_contract::RuntimeError> {
        use crucible::node_contract::RuntimeError;
        self.original_creator()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if self.phase != Phase::Attached
            || !self.attachment_attempted
            || self.next != 0
            || self.grants.iter().any(|grant| grant.token.is_some())
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = super::super::retained::Counter::new(maximum);
        counter
            .add(std::mem::size_of::<Self>())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                self.grants
                    .capacity()
                    .checked_mul(std::mem::size_of::<Grant>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for grant in &self.grants {
            counter
                .charge(&grant.node)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&grant.operation)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&grant.input)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .charge(&self.supervision_proposal)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(match initial_sources {
                Some(sources) => self
                    .runtime
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .retained_original_initial_requested_storage_precredit_data(
                        sources,
                        counter.remaining(),
                    )?,
                None => self
                    .runtime
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_inactive_retained_storage_precredit_data(counter.remaining())?,
            })
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(counter.bytes())
    }
}

impl PacketCompleteExecutionActor {
    pub(in crate::node_qualification::packet_collection::complete) fn original_inactive_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, crucible::node_contract::RuntimeError> {
        use crucible::node_contract::RuntimeError;
        self.original_creator()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if self.next != 0 || self.grants.iter().any(|grant| grant.token.is_some()) {
            return Err(RuntimeError::UnsupportedFacet);
        }
        match (self.phase, &self.runtime) {
            (Phase::Reserved, None) => Ok(0),
            (Phase::Attached, Some(runtime)) => {
                runtime.original_inactive_descriptor_views_precredit_data()
            }
            _ => Err(RuntimeError::UnsupportedFacet),
        }
    }
}

impl PacketCompleteExecutionActor {
    pub(in crate::node_qualification::packet_collection::complete) fn retire_original_inactive_construction(
        &mut self,
    ) -> Result<(), crucible::node_contract::RuntimeError> {
        use crucible::node_contract::RuntimeError;
        self.original_creator()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if self.next != 0 || self.grants.iter().any(|grant| grant.token.is_some()) {
            return Err(RuntimeError::OutstandingObligations);
        }
        if self.phase == Phase::Retired || (!self.attachment_attempted && self.runtime.is_none()) {
            return Ok(());
        }
        self.retire_original()
            .map_err(|_| RuntimeError::OwnerUnavailable)
    }
}

#[cfg(test)]
impl PacketCompleteExecutionActor {
    /// Checks the actual attached actor and its same inactive Core runtime.
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_original_inactive_for_test(
        &mut self,
    ) -> Result<(), PacketCompleteExecutionError> {
        self.require(Phase::Attached)?;
        self.runtime
            .as_mut()
            .ok_or(PacketCompleteExecutionError::Phase)?
            .validate_inactive_complete_preservation_descriptions_for_test(&self.scene.plan)
            .map_err(failure)
    }
}

#[path = "actor/initial_preparation.rs"]
mod initial_preparation;
