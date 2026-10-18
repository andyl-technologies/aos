//! Retains a genuine host owner of the original common scheduling allocation.
//!
//! Host connection histories and coordinator queues stay host state. They never
//! become a native peer's captured bytes or an unrelated NetLink model. The
//! original source owner controls one revision; dropping it revokes every view.

use std::{
    cell::{Cell, RefCell},
    io::{self, Write},
    rc::{Rc, Weak},
    thread::{self, ThreadId},
};

use crucible_node_contract::{
    ContentRef, HashRef, Id, NodeBinding, NodeDescriptor, OwnerBinding, SchemaRef, Validate,
    canonical,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::node_admission::ConformanceGraph;

use super::runtime::scheduling_state::OriginalSchedulingSource;
use super::{ActivationRecord, NodeRoute, OperationFailure, OwnerIdentity, RuntimeError};

mod capture_dependencies;
pub use capture_dependencies::{HostCaptureDependencyLookupData, HostCaptureDependencyStorageData};

mod construction_storage;
pub use construction_storage::HostCollectionNodeConstructionStorageData;

mod continuation;
mod restored_continuation;
pub(crate) use restored_continuation::{
    HostSchedulingRestoredCaptureAttempt17, HostSchedulingRestoredContinuation17,
    RestoredHostCaptureAncestryBorrowed17,
};
pub use restored_continuation::{
    HostSchedulingRestoredContinuationRecord17, RestoredHostAdmissionPolicy17,
    RestoredHostAncestry17, RestoredHostSemanticAncestor,
    authenticate_host_scheduling_restored_continuation_schema17_data,
    host_scheduling_restored_continuation_definition17,
    host_scheduling_restored_continuation_schema17,
    host_scheduling_restored_continuation_schema17_counter_scratch_data,
};

mod prebirth_storage;
mod requested_storage;
pub use continuation::{
    HostSchedulingContinuationLimits, HostSchedulingContinuationRecord,
    HostSchedulingContinuationV2, HostSchedulingRuntimeRecord,
};

mod node;
pub use node::PreparedHostSchedulingNode;

mod ticket;
pub use ticket::HostSchedulingOriginalContinuationTicket;

mod complete;
pub use complete::{
    host_scheduling_complete_continuation_schema, host_scheduling_complete_owner_configuration,
    host_scheduling_complete_owner_definition, host_scheduling_complete_owner_preparation_schema,
    host_scheduling_complete_preservation_facet,
};

mod preservation;
pub use preservation::{
    host_scheduling_continuation_owner_configuration,
    host_scheduling_continuation_owner_definition,
    host_scheduling_continuation_owner_preparation_schema,
};

/// Borrows the source-owned initial host scheduling definition as data.
///
/// # Errors
/// Reports canonical serialization failure for the fixed unsupported-capture profile.
pub fn host_scheduling_owner_definition() -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-owner/1",
        "initial":"one original runtime-owned uninitialized scheduling slot before Arm; lazy initialization attaches the same actual CausalScheduler",
        "state":"host-owned transfer credits/staged deliveries, delivery heap, original input batches/commits/frontiers, source sequences, reservations/operations and durable placements; native buffers remain separate",
        "owner":"one original PID/thread/world/private runtime authority; no autonomous worker or queue-copy model",
        "access":"only original runtime mutates; same original source supplies bounded readonly witnesses from actual RuntimeSnapshot and SchedulingSnapshot",
        "limits":"source-selected complete world/connection policies and original RuntimeLimits remain authoritative; no budget renewal",
        "capture":"unsupported until complete unchanged-cut original closure and fresh restore are source-qualified; no checkpoint, restart, fork or replay permission"
    }))
    .map_err(failure)
}

/// Returns the distinct original host-owner preparation schema.
///
/// # Errors
/// Reports invalid fixed schema identities or canonical encoding failure.
pub fn host_scheduling_owner_preparation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-owner-preparation/1").map_err(failure)?,
        version: 1,
        definition: definition_ref()?,
        extensions: Default::default(),
    })
}

fn definition_ref() -> Result<ContentRef, OperationFailure> {
    canonical::content_ref(&host_scheduling_owner_definition()?, "application/json")
        .map_err(failure)
}

/// Names the host-owned state domain for one original world connection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSchedulingConnectionDomain {
    /// Names the exact connection selected by the complete world.
    pub connection: Id,
    /// Names its host-owned transfer, credit and delivery-history domain.
    pub domain: Id,
}

/// Binds semantic host state roles without interpreting caller-selected labels.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSchedulingDomains {
    /// Names the common scheduler's complete coordinator-state domain.
    pub coordinator: Id,
    /// Binds each original world connection to its own host state domain.
    pub connections: Vec<HostSchedulingConnectionDomain>,
}

/// Encodes the source-owned configuration for the explicit host domain map.
///
/// # Errors
/// Refuses invalid, duplicate or excessive domain/connection identifiers.
pub fn host_scheduling_owner_configuration(
    domains: &HostSchedulingDomains,
) -> Result<Vec<u8>, OperationFailure> {
    validate_domains(domains)?;
    canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-configuration/1",
        "definition":definition_ref()?,
        "domains":domains
    }))
    .map_err(failure)
}

fn validate_domains(domains: &HostSchedulingDomains) -> Result<(), OperationFailure> {
    domains.coordinator.validate().map_err(failure)?;
    if domains.connections.is_empty() || domains.connections.len() > 7 {
        return Err(failure(
            "host scheduling connection-domain roster is outside its bound",
        ));
    }
    let mut connections = std::collections::BTreeSet::new();
    let mut state_domains = std::collections::BTreeSet::from([domains.coordinator.clone()]);
    for connection in &domains.connections {
        connection.connection.validate().map_err(failure)?;
        connection.domain.validate().map_err(failure)?;
        if !connections.insert(connection.connection.clone())
            || !state_domains.insert(connection.domain.clone())
        {
            return Err(failure(
                "host scheduling connection/domain roles are duplicated",
            ));
        }
    }
    Ok(())
}

/// Retains the exact source-selected public host descriptor and ownership tuple.
///
/// These immutable records contain no private pointers or source authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSchedulingSelection {
    /// Names the actual source-selected host coordinator view, with no ports.
    pub descriptor: NodeDescriptor,
    /// Retains exact implementation, profile, configuration and live authority.
    pub binding: NodeBinding,
    /// Retains its own execution/capture owner and explicit host state domains.
    pub owner: OwnerBinding,
    /// Maps the original coordinator and connection state to this host owner.
    pub domains: HostSchedulingDomains,
    /// Retains the exact source-selected policy named by the binding.
    pub operating_policy: crate::node_scheduling::ExecutionPolicy,
    /// Retains the actual unsupported-capture guarantee named by the binding.
    pub guarantees: crucible_node_contract::GuaranteeProfile,
}

/// Owns the original source revision before construction of the host runtime node.
#[must_use = "retain the original host scheduling owner through collection and containment"]
pub struct HostSchedulingOwner {
    source: Rc<HostSchedulingSource>,
}

impl HostSchedulingOwner {
    /// Creates one concrete source revision without creating a scheduler or Ready.
    ///
    /// # Errors
    /// Refuses foreign or incomplete host metadata, unsupported profile/initializer,
    /// wrong owner roles or records exceeding the preallocation byte ceiling.
    pub fn new(
        selection: HostSchedulingSelection,
        world: HashRef,
    ) -> Result<Self, OperationFailure> {
        Self::create(selection, world, preservation::Edition::Unsupported, None)
    }

    fn create(
        selection: HostSchedulingSelection,
        world: HashRef,
        edition: preservation::Edition,
        ticket: Option<HostSchedulingOriginalContinuationTicket>,
    ) -> Result<Self, OperationFailure> {
        let process = std::process::id();
        let owner_thread = thread::current().id();
        credit(&(&selection, &world), 65_536)?;
        selection.descriptor.validate().map_err(failure)?;
        selection.binding.validate().map_err(failure)?;
        selection.owner.validate().map_err(failure)?;
        world.validate().map_err(failure)?;
        let definition = preservation::definition(edition)?;
        let configuration = canonical::content_ref(
            &preservation::configuration(edition, &selection.domains)?,
            "application/json",
        )
        .map_err(failure)?;
        let mut domains = vec![selection.domains.coordinator.clone()];
        domains.extend(
            selection
                .domains
                .connections
                .iter()
                .map(|connection| connection.domain.clone()),
        );
        domains.sort();
        let descriptor = &selection.descriptor;
        let binding = &selection.binding;
        let owner = &selection.owner;
        if descriptor.roles.len() != 1
            || descriptor.roles[0].as_str() != "coordinator-state"
            || !descriptor.ports.is_empty()
            || descriptor.model_ref != definition
            || descriptor.configuration_ref != configuration
            || descriptor.initialization_ref != configuration
            || binding.compatibility.node_id != descriptor.id
            || binding.compatibility.execution_owner != owner.owner
            || binding.compatibility.capture_owner != owner.owner
            || binding.compatibility.profile_ref != definition
            || binding.compatibility.configuration_ref != configuration
            || binding.compatibility.operating_contract.mode
                != crucible_node_contract::OperatingMode::Exact
            || binding.compatibility.operating_contract.scheduling_role
                != crucible_node_contract::SchedulingRole::EventDriven
            || !matches!(
                selection.operating_policy,
                crate::node_scheduling::ExecutionPolicy::Exact { .. }
            )
            || !complete::valid_facets(edition, &selection)
            || owner.owner.participant_ids != [descriptor.id.clone()]
            || owner.owner.state_domain_ids != domains
            || owner.owner_roles.iter().map(Id::as_str).collect::<Vec<_>>()
                != ["capture", "execution"]
            || owner.node_bindings.len() != 1
            || owner.node_bindings[0].node_id != descriptor.id
            || owner.node_bindings[0].binding_hash != binding.identity().map_err(failure)?
            || !binding
                .compatibility
                .implementation
                .formats
                .contains(&preservation::preparation(edition)?)
        {
            return Err(failure(
                "host scheduling source differs from its compiled original definition",
            ));
        }
        let policy_bytes = canonical::canonical_json(
            &serde_json::to_value(&selection.operating_policy).map_err(failure)?,
        )
        .map_err(failure)?;
        binding
            .compatibility
            .operating_contract
            .policy_ref
            .verify(&policy_bytes)
            .map_err(failure)?;
        let guarantee_bytes = canonical::canonical_json(
            &serde_json::to_value(&selection.guarantees).map_err(failure)?,
        )
        .map_err(failure)?;
        binding
            .compatibility
            .guarantees_ref
            .verify(&guarantee_bytes)
            .map_err(failure)?;
        let guarantee = &selection.guarantees;
        if !complete::valid_guarantees(edition, guarantee) {
            return Err(failure(
                "host scheduling source cannot claim unimplemented preservation",
            ));
        }
        let token = canonical::json_hash(
            "cnp.host-scheduling-preparation.v1",
            &(
                &world,
                binding.identity().map_err(failure)?,
                owner.identity().map_err(failure)?,
                process,
            ),
        )
        .map_err(failure)?;
        let prepared_token =
            Id::new(format!("host/scheduling-prepared/{}", token.digest)).map_err(failure)?;
        let preservation_facet = complete::selected_facet(edition, &selection);
        Ok(Self {
            source: Rc::new(HostSchedulingSource {
                selection,
                world,
                edition,
                original_ticket: ticket,
                archive_ticket: None,
                preservation_facet,
                process,
                owner_thread,
                prepared_token,
                revoked: Cell::new(false),
                node_created: Cell::new(false),
                attachment_attempted: Cell::new(false),
                node: RefCell::new(Weak::new()),
                attached: RefCell::new(None),
                capture_dependencies: RefCell::new(None),
            }),
        })
    }

    /// Borrows a view of the same original source revision without renewing it.
    pub fn source(&self) -> Rc<HostSchedulingSource> {
        // Installed callers may retain this owner beside an independently
        // counted view of the same source. New owned fields need a new census.
        let Self { source } = self;
        Rc::clone(source)
    }

    /// Permanently revokes all views while original runtime queues remain retained.
    pub fn revoke(&mut self) {
        self.source.revoke_attached();
    }
}

impl Drop for HostSchedulingOwner {
    fn drop(&mut self) {
        self.source.revoke_attached();
    }
}

/// Retains concrete source identity and read-only original scheduling attachment.
pub struct HostSchedulingSource {
    edition: preservation::Edition,
    original_ticket: Option<HostSchedulingOriginalContinuationTicket>,
    archive_ticket: Option<crate::node_state::CompleteOriginalHostTicket>,
    preservation_facet: Option<complete::SelectedPreservation>,
    selection: HostSchedulingSelection,
    world: HashRef,
    process: u32,
    owner_thread: ThreadId,
    prepared_token: Id,
    revoked: Cell<bool>,
    node_created: Cell<bool>,
    attachment_attempted: Cell<bool>,
    node: RefCell<Weak<()>>,
    attached: RefCell<Option<OriginalSchedulingSource>>,
    capture_dependencies: RefCell<Option<Rc<capture_dependencies::OriginalHostDependencyPlan>>>,
}

impl HostSchedulingSource {
    pub(super) fn begin_attachment(&self) -> Result<(), RuntimeError> {
        self.authenticate_preparation_source(&self.world)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if self.attachment_attempted.replace(true) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn attach(&self, original: OriginalSchedulingSource) -> Result<(), RuntimeError> {
        self.authenticate_preparation_source(&self.world)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        original.authenticate_initial(&self.world)?;
        let mut attached = self
            .attached
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if attached.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        *attached = Some(original);
        Ok(())
    }

    /// Borrows immutable source metadata without granting queue access or Ready.
    pub fn selection(&self) -> &HostSchedulingSelection {
        &self.selection
    }

    /// Borrows the source-owned coordinator and original connection domain roles.
    pub fn domains(&self) -> &HostSchedulingDomains {
        &self.selection.domains
    }

    /// Borrows the source-generated original pending preparation token as data.
    pub fn prepared_token(&self) -> &Id {
        &self.prepared_token
    }

    /// Borrows the complete world identity selected by the original installer.
    pub fn world(&self) -> &HashRef {
        &self.world
    }

    /// Authenticates original source creation before accessing cells or callbacks.
    ///
    /// This preparation check grants no current scheduler/Ready permission.
    ///
    /// # Errors
    /// Refuses revoked source or a foreign process, thread or complete world.
    pub fn authenticate_preparation_source(&self, world: &HashRef) -> Result<(), OperationFailure> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || &self.world != world
            || self.revoked.get()
        {
            return Err(failure(
                "original host scheduling source is no longer current",
            ));
        }
        Ok(())
    }

    /// Authenticates the original complete-preservation factory selection.
    ///
    /// This check binds the private source edition after original process,
    /// thread and world checks. It grants no live scheduler, capture or Ready
    /// permission and does not replace later dispatch/current authentication.
    ///
    /// # Errors
    /// Refuses foreign or revoked preparation, another world, or either older
    /// unsupported/original-lineage factory selection.
    pub fn authenticate_complete_preparation_source(
        &self,
        world: &HashRef,
    ) -> Result<(), OperationFailure> {
        self.authenticate_preparation_source(world)?;
        if self.edition != preservation::Edition::CompleteOriginalLineage {
            return Err(failure(
                "source was not created by the complete preservation factory",
            ));
        }
        Ok(())
    }

    /// Authenticates preparation dispatch without downgrading a prior attachment attempt.
    ///
    /// Initial native Admit may precede host attachment. Once the actual source
    /// node has attempted attachment, only the same live runtime slot suffices.
    /// This method never establishes Ready or authorizes an input/run effect.
    ///
    /// # Errors
    /// Refuses foreign/revoked source, reentrant access, failed attachment or a
    /// formerly attached slot that has lost its original live permission.
    pub fn authenticate_dispatch_source(&self) -> Result<(), OperationFailure> {
        self.authenticate_preparation_source(&self.world)?;
        let attached = self.attached.try_borrow().map_err(failure)?;
        if attached.is_none() && !self.attachment_attempted.get() {
            return Ok(());
        }
        drop(attached);
        self.authenticate_current()
    }

    /// Authenticates the actual live runtime attachment without copying its queues.
    ///
    /// # Errors
    /// Refuses absent/stale attachment, original node loss, revocation or foreign custody.
    pub fn authenticate_current(&self) -> Result<(), OperationFailure> {
        self.authenticate_preparation_source(&self.world)?;
        let node = self.node.try_borrow().map_err(failure)?;
        if node.upgrade().is_none() {
            return Err(failure("original host scheduling node is unavailable"));
        }
        let attached = self.attached.try_borrow().map_err(failure)?;
        attached
            .as_ref()
            .ok_or_else(|| failure("original host scheduling node is unattached"))?
            .authenticate_current(&self.world)
            .map_err(failure)
    }

    /// Authenticates one immutable batch retained by this same original scheduler.
    ///
    /// Equal portable world records cannot substitute another runtime's private
    /// activation. This check borrows actual retained storage without copying it.
    ///
    /// # Errors
    /// Refuses foreign/stale attachment, busy storage, another original runtime,
    /// absent batch or changed complete identity, inventory and payload bytes.
    pub fn authenticate_input_batch(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), OperationFailure> {
        self.authenticate_current()?;
        self.attached
            .try_borrow()
            .map_err(failure)?
            .as_ref()
            .ok_or_else(|| failure("original host scheduling attachment absent"))?
            .authenticate_input_batch(batch)
            .map_err(failure)?;
        self.authenticate_current()
    }

    pub(crate) fn authenticate_complete_archive_source(
        &self,
        archive: &Rc<crate::node_state::CompleteOriginalSource>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_preparation_source(&self.world)?;
        let ticket = self
            .archive_ticket
            .as_ref()
            .ok_or_else(|| failure("complete host archive ticket is absent"))?;
        ticket.authenticate_birth().map_err(failure)?;
        if self.edition != preservation::Edition::CompleteOriginalLineage
            || self.original_ticket.is_some()
            || !Rc::ptr_eq(&ticket.source, archive)
        {
            return Err(failure("complete host belongs to another original archive"));
        }
        self.authenticate_preparation_source(&self.world)
    }

    pub(super) fn original_restoration_record(
        &self,
    ) -> Result<&HostSchedulingContinuationRecord, OperationFailure> {
        self.authenticate_current()?;
        match (&self.original_ticket, &self.archive_ticket) {
            (Some(ticket), None) => {
                ticket.authenticate_birth().map_err(failure)?;
                Ok(ticket.record())
            }
            (None, Some(ticket)) => {
                ticket.authenticate_birth().map_err(failure)?;
                ticket.record().map_err(failure)
            }
            _ => Err(failure(
                "original host continuation ticket is absent or ambiguous",
            )),
        }
    }

    pub(super) fn restoration_runtime_fields_data(
        &self,
    ) -> Result<
        (
            &super::OriginalLineageRuntimeRecord,
            &crate::node_scheduling::SchedulingSnapshot,
            &[crate::node_scheduling::InputPayload],
            &HostSchedulingSelection,
        ),
        OperationFailure,
    > {
        self.authenticate_current()?;
        if let Some(ticket) = &self.archive_ticket
            && ticket.is_restored_settled_data().map_err(failure)?
        {
            if self.original_ticket.is_some() {
                return Err(failure("Host restoration has ambiguous actual tickets"));
            }
            let record = ticket.restored_record_data().map_err(failure)?;
            return Ok((
                &record.runtime,
                &record.scheduling,
                &record.objects,
                &record.source,
            ));
        }
        let original = self.original_restoration_record()?;
        let HostSchedulingRuntimeRecord::OriginalLineage(runtime) = &original.runtime else {
            return Err(failure("original Host legacy restoration is unsupported"));
        };
        Ok((
            runtime,
            &original.scheduling,
            &original.objects,
            &original.source,
        ))
    }

    pub(super) fn authenticate_original_lineage_context(
        &self,
        context: &super::OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_current()?;
        self.attached
            .try_borrow()
            .map_err(failure)?
            .as_ref()
            .ok_or_else(|| failure("original host scheduling attachment absent"))?
            .authenticate_runtime_authority(&self.world, context.original_runtime_authority())
            .map_err(failure)?;
        self.authenticate_current()
    }

    pub(super) fn authenticate_original_lineage_installation(
        &self,
        context: &super::OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_lineage_context(context)?;
        self.attached
            .try_borrow()
            .map_err(failure)?
            .as_ref()
            .ok_or_else(|| failure("original host scheduling attachment absent"))?
            .authenticate_original_lineage_installation(
                &self.world,
                context.source_record(),
                context.original_scheduler_identity(),
                context.target(),
            )
            .map_err(failure)?;
        self.authenticate_current()
    }

    /// Creates the actual collecting host node under the same original opaque plan.
    ///
    /// # Errors
    /// Refuses revoked/used source, foreign complete graph/activation/owner tuple,
    /// accepted capture demands or a reentrant original node reservation.
    pub fn prepare_collection_node(
        self: &Rc<Self>,
        graph: &ConformanceGraph,
        activation: &ActivationRecord,
    ) -> Result<PreparedHostSchedulingNode, OperationFailure> {
        self.authenticate_preparation_source(&self.world)?;
        graph.reauthenticate().map_err(failure)?;
        self.authenticate_preparation_source(&self.world)?;
        let selected = &self.selection;
        let inner = &graph.graph;
        let guarantee = inner
            .guarantees(&selected.descriptor.id)
            .ok_or_else(|| failure("host guarantee absent"))?;
        if graph.world().identity().map_err(failure)? != self.world
            || inner.descriptor(&selected.descriptor.id) != Some(&selected.descriptor)
            || inner.binding(&selected.descriptor.id) != Some(&selected.binding)
            || inner.owner(&selected.owner.owner.id) != Some(&selected.owner)
            || inner.operating_policy(&selected.descriptor.id) != Some(&selected.operating_policy)
            || inner.guarantees(&selected.descriptor.id) != Some(&selected.guarantees)
            || activation.world_binding_hash != self.world
            || self.node_created.get()
            || !complete::valid_guarantees(self.edition, guarantee)
        {
            return Err(failure(
                "host scheduling node differs from its original collecting graph",
            ));
        }
        let owner = OwnerIdentity {
            owner: selected.owner.owner.id.clone(),
            incarnation: selected.binding.authority.incarnation_id.clone(),
            generation: selected.binding.authority.owner_generation,
        };
        if !activation.owners.contains(&owner) {
            return Err(failure(
                "host scheduling owner absent from original activation",
            ));
        }
        let anchor = Rc::new(());
        *self.node.try_borrow_mut().map_err(failure)? = Rc::downgrade(&anchor);
        self.node_created.set(true);
        Ok(PreparedHostSchedulingNode::new(
            Rc::clone(self),
            anchor,
            graph.plan().retained(),
            activation.clone(),
            NodeRoute {
                node: selected.descriptor.id.clone(),
                owners: vec![owner],
            },
        ))
    }

    pub(super) fn authenticate_runtime(
        &self,
        state: &super::runtime::scheduling_state::OriginalSchedulingState,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let attached = self
            .attached
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if !attached
            .as_ref()
            .is_some_and(|original| original.same_original(state))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn authenticate_initial_attachment(&self) -> Result<(), OperationFailure> {
        self.authenticate_current()?;
        self.attached
            .try_borrow()
            .map_err(failure)?
            .as_ref()
            .ok_or_else(|| failure("original host scheduling attachment absent"))?
            .authenticate_initial(&self.world)
            .map_err(failure)
    }

    fn birth(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.owner_thread != thread::current().id() {
            return Err(failure(
                "host scheduling source has foreign process/thread origin",
            ));
        }
        Ok(())
    }

    pub(super) fn revoke_attached(&self) {
        if self.birth().is_err() {
            return;
        }
        self.revoked.set(true);
        if let Ok(attached) = self.attached.try_borrow()
            && let Some(original) = attached.as_ref()
        {
            let _ = original.revoke(&self.world);
        }
    }

    pub(super) fn authenticate_closed_attachment(&self) -> Result<(), OperationFailure> {
        self.birth()?;
        let attached = self.attached.try_borrow().map_err(failure)?;
        // An unattempted retired factory node never acquired scheduler storage.
        // Attempted-but-absent attachment stays unresolved; it cannot release
        // an unknown original slot or turn back into preparation authority.
        if self.revoked.get() && !self.attachment_attempted.get() && attached.is_none() {
            return Ok(());
        }
        attached
            .as_ref()
            .ok_or_else(|| failure("original closed host attachment absent"))?
            .authenticate_closed(&self.world)
            .map_err(failure)
    }

    /// Encodes the exact factory-selected initial node row without predicted Ready.
    ///
    /// # Errors
    /// Refuses foreign or revoked source and encoding limits. This static factory
    /// declaration precedes graph sealing and carries no predicted Ready state.
    pub fn initial_node_record(&self) -> Result<Value, OperationFailure> {
        self.authenticate_preparation_source(&self.world)?;
        let selected = &self.selection;
        let value = json!({
            "descriptor":selected.descriptor, "binding":selected.binding,
            "route":{"node":selected.descriptor.id,"owners":[{
                "owner":selected.owner.owner.id,"incarnation":selected.binding.authority.incarnation_id,
                "generation":selected.binding.authority.owner_generation}]},
            "facets":complete::selected_facets(self.edition).1, "native_thread_custody":"owner-thread",
            "operating_policy":selected.operating_policy,
            "guarantees":selected.guarantees,
            "effective_repeatability":selected.guarantees.repeatability,
            "ports":[]
        });
        credit(&value, 65_536)?;
        self.authenticate_preparation_source(&self.world)?;
        Ok(value)
    }
}

fn failure(error: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: super::EffectKnowledge::None,
        reason: crate::node_admission::original_runtime_construction_failure_reason(error),
    }
}

fn credit<T: Serialize>(value: &T, maximum: usize) -> Result<(), OperationFailure> {
    struct Remaining(usize);
    impl Write for Remaining {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("host source serialization credit exhausted"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Remaining(maximum), value).map_err(failure)
}

/// Borrows the actual source-created host node identity for original attachment.
///
/// This process-local witness has no decoder or public constructor. Its private
/// anchor belongs to the actual factory node, never to a portable source record.
pub struct HostSchedulingNodeWitness<'a> {
    source: &'a Rc<HostSchedulingSource>,
    anchor: &'a Rc<()>,
    original_node: Option<&'a PreparedHostSchedulingNode>,
}

impl<'a> HostSchedulingNodeWitness<'a> {
    pub(crate) fn new(source: &'a Rc<HostSchedulingSource>, anchor: &'a Rc<()>) -> Self {
        Self {
            source,
            anchor,
            original_node: None,
        }
    }

    pub(super) fn with_original_node(mut self, node: &'a PreparedHostSchedulingNode) -> Self {
        self.original_node = Some(node);
        self
    }

    pub(in crate::node_contract) fn original_node_requested_storage(
        &self,
    ) -> Result<usize, RuntimeError> {
        if !self.matches(self.source)? {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.original_node
            .ok_or(RuntimeError::UnsupportedFacet)?
            .retained_requested_storage_excluding_source()
            .map_err(|_| RuntimeError::UnsupportedFacet)
    }

    pub(in crate::node_contract) fn original_capture_source(
        &self,
    ) -> Result<Rc<HostSchedulingSource>, RuntimeError> {
        self.source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.matches(self.source)?
            || !matches!(
                self.source.edition,
                preservation::Edition::OriginalLineage
                    | preservation::Edition::CompleteOriginalLineage
            )
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(Rc::clone(self.source))
    }

    pub(crate) fn authenticate_archive_target(
        &self,
        archive: &Rc<crate::node_state::CompleteOriginalSource>,
        authority: &Rc<()>,
    ) -> Result<(), RuntimeError> {
        self.source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.matches(self.source)?
            || !self
                .source
                .archive_ticket
                .as_ref()
                .is_some_and(|ticket| Rc::ptr_eq(&ticket.source, archive))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.source
            .attached
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_runtime_authority(&self.source.world, authority)?;
        self.source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    pub(super) fn matches(&self, source: &Rc<HostSchedulingSource>) -> Result<bool, RuntimeError> {
        source
            .authenticate_preparation_source(&source.world)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let node = source
            .node
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        Ok(Rc::ptr_eq(self.source, source)
            && node
                .upgrade()
                .is_some_and(|original| Rc::ptr_eq(&original, self.anchor)))
    }
}

/// Borrows the actual runtime and scheduler ledgers under their original host owner.
///
/// This witness prevents mutable use of the same runtime while borrowed. Its
/// snapshots are facts only: they establish no native suspension, complete
/// capture, restore permission or Accepted class.
pub struct HostSchedulingObservation<'a> {
    runtime: &'a super::NodeRuntime,
    source: &'a HostSchedulingSource,
}

impl<'a> HostSchedulingObservation<'a> {
    pub(super) fn new(
        runtime: &'a super::NodeRuntime,
        source: &'a HostSchedulingSource,
    ) -> Result<Self, RuntimeError> {
        runtime.authenticate_host_scheduling_source(source)?;
        Ok(Self { runtime, source })
    }

    /// Reads the actual represented runtime and original scheduler at one bounded cut.
    ///
    /// Neither ledger is reconstructed from metadata or a separate queue model.
    /// Original native lineage that lacks a complete legacy codec remains refused.
    ///
    /// # Errors
    /// Refuses stale/foreign source, uninitialized or unpublished state, busy
    /// scheduling storage, unsupported original lineage or exceeded byte limits.
    pub fn snapshots(
        &self,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
        maximum_record_bytes: usize,
    ) -> Result<
        (
            super::RuntimeSnapshot,
            crate::node_scheduling::SchedulingSnapshot,
        ),
        RuntimeError,
    > {
        self.runtime
            .authenticate_host_scheduling_source(self.source)?;
        self.runtime
            .host_scheduler_preflight(maximum_record_bytes)?;
        let runtime = self
            .runtime
            .runtime_snapshot(cut, ordinal, maximum_record_bytes)?;
        let scheduler = self.runtime.host_scheduler_snapshot(cut, ordinal)?;
        credit(&scheduler, maximum_record_bytes).map_err(|_| RuntimeError::ResourceLimit)?;
        self.runtime
            .authenticate_host_scheduling_source(self.source)?;
        Ok((runtime, scheduler))
    }
}

#[cfg(test)]
mod tests {
    // Invalid source fixtures must fail the test instead of proceeding with metadata.
    #![allow(clippy::unwrap_used)]

    use super::*;

    pub(super) fn source_owner() -> HostSchedulingOwner {
        let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
        let node = graph.node_ids().next().unwrap();
        let mut descriptor = graph.descriptor(node).unwrap().clone();
        let mut binding = graph.binding(node).unwrap().clone();
        let mut owner = graph
            .owner(&binding.compatibility.execution_owner.id)
            .unwrap()
            .clone();
        let domains = HostSchedulingDomains {
            coordinator: Id::new("host/coordinator").unwrap(),
            connections: vec![HostSchedulingConnectionDomain {
                connection: Id::new("link/0").unwrap(),
                domain: Id::new("host/link/0").unwrap(),
            }],
        };
        owner.owner.state_domain_ids = vec![
            domains.coordinator.clone(),
            domains.connections[0].domain.clone(),
        ];
        owner.owner.state_domain_ids.sort();
        owner.owner_roles = vec![Id::new("capture").unwrap(), Id::new("execution").unwrap()];
        binding.compatibility.execution_owner = owner.owner.clone();
        binding.compatibility.capture_owner = owner.owner.clone();
        descriptor.roles = vec![Id::new("coordinator-state").unwrap()];
        descriptor.ports.clear();
        descriptor.model_ref = definition_ref().unwrap();
        let configuration = canonical::content_ref(
            &host_scheduling_owner_configuration(&domains).unwrap(),
            "application/json",
        )
        .unwrap();
        descriptor.configuration_ref = configuration.clone();
        descriptor.initialization_ref = configuration.clone();
        binding.compatibility.configuration_ref = configuration;
        binding.compatibility.profile_ref = definition_ref().unwrap();
        binding.compatibility.operating_contract.facets.clear();
        binding.compatibility.operating_contract.scheduling_role =
            crucible_node_contract::SchedulingRole::EventDriven;
        binding
            .compatibility
            .implementation
            .formats
            .push(host_scheduling_owner_preparation_schema().unwrap());
        binding
            .compatibility
            .implementation
            .formats
            .sort_by(|left, right| left.id.cmp(&right.id));
        let operating_policy = graph.operating_policy(node).unwrap().clone();
        binding.compatibility.operating_contract.policy_ref = canonical::content_ref(
            &canonical::canonical_json(&serde_json::to_value(&operating_policy).unwrap()).unwrap(),
            "application/json",
        )
        .unwrap();
        let mut guarantees = graph.guarantees(node).unwrap().clone();
        guarantees.repeatability = crucible_node_contract::Repeatability::Unqualified;
        guarantees.capture_scope = crucible_node_contract::CaptureScope::None;
        guarantees.continuation = crucible_node_contract::Continuation::Unsupported;
        guarantees.durable_restart = false;
        guarantees.isolated_fork = false;
        guarantees.conditional_replay = false;
        binding.compatibility.guarantees_ref = canonical::content_ref(
            &canonical::canonical_json(&serde_json::to_value(&guarantees).unwrap()).unwrap(),
            "application/json",
        )
        .unwrap();
        owner.node_bindings[0].binding_hash = binding.identity().unwrap();
        HostSchedulingOwner::new(
            HostSchedulingSelection {
                descriptor,
                binding,
                owner,
                domains,
                operating_policy,
                guarantees,
            },
            graph.world_binding_hash().clone(),
        )
        .unwrap()
    }

    #[test]
    fn host_source_bootstrap_never_downgrades_a_failed_original_attachment() {
        // The source factory is actual. No native peers, graph attachment or Ready are claimed.
        let mut owner = source_owner();
        let source = owner.source();
        assert!(source.authenticate_dispatch_source().is_ok());
        assert!(source.authenticate_current().is_err());
        source.begin_attachment().unwrap();
        assert!(source.authenticate_dispatch_source().is_err());
        assert!(source.begin_attachment().is_err());
        owner.revoke();
        assert!(
            source
                .authenticate_preparation_source(source.world())
                .is_err()
        );
    }

    #[test]
    fn host_unattached_retirement_does_not_release_an_unknown_attachment() {
        let mut owner = source_owner();
        let source = owner.source();
        assert!(source.authenticate_closed_attachment().is_err());
        owner.revoke();
        assert!(source.authenticate_closed_attachment().is_ok());
        assert!(source.authenticate_dispatch_source().is_err());

        let mut owner = source_owner();
        let source = owner.source();
        source.begin_attachment().unwrap();
        owner.revoke();
        assert!(source.authenticate_closed_attachment().is_err());
        assert!(source.authenticate_dispatch_source().is_err());
    }

    #[test]
    fn host_domain_configuration_rejects_duplicate_semantic_roles() {
        let owner = source_owner();
        let source = owner.source();
        let mut domains = source.domains().clone();
        assert!(host_scheduling_owner_configuration(&domains).is_ok());
        domains.connections.push(domains.connections[0].clone());
        assert!(host_scheduling_owner_configuration(&domains).is_err());
        domains.connections.pop();
        domains.connections[0].domain = domains.coordinator.clone();
        assert!(host_scheduling_owner_configuration(&domains).is_err());
    }
}
