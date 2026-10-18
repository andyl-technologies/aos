//! Keeps the original fixed complete scene behind collection-only lifecycle gates.
//!
//! The installed oracle owns the sole consuming receiver. Source callbacks retain
//! actual native capsules and Core issues operation/input admissions. This scene
//! cannot turn its schedule, a Refused audit or copied metadata into those tokens.

mod construction;
mod retained;

use std::{cell::Cell, rc::Rc};

use crucible::{
    node_adapters::cnp::{CnpSemanticRealizationScope, CnpSemanticSource},
    node_admission::{AdmissionRequest, InstalledConformancePlan},
    node_contract::{HostSchedulingSource, OperationRequest},
};
use crucible_node_contract::{Id, canonical};

use super::{
    InstalledPacketCompleteCollectionAuthority, PacketCompleteNativeOracle, QualificationError,
    refused,
};

mod actor;
pub use actor::{
    PacketCompleteExecutionActor, PacketCompleteExecutionError,
    PacketCompleteRuntimeAttachmentFailure,
};

mod inputs;
pub(in crate::node_qualification::packet_collection::complete) mod schedule;

/// Retains one source-selected complete scene without ordinary acceptance.
///
/// The caller installs this once before native birth and retains it with the
/// same factory, peers, oracle and supervisor through every failed transition.
/// Dormant preparation and active execution have separate original-source gates.
#[must_use = "retain the original scene and its oracle through native reclamation"]
pub struct PacketCompleteExecutionScene {
    authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    oracle: Rc<PacketCompleteNativeOracle>,
    actor_reserved: Cell<bool>,
    runtime_attached: Cell<bool>,
    current_grant: Cell<Option<usize>>,
}

impl PacketCompleteExecutionScene {
    /// Binds the actual oracle and its fixed finite schedule to this original plan.
    ///
    /// This performs no graph admission, native request, readiness or activation.
    /// Equal metadata cannot replace the retained source roster or oracle owner.
    ///
    /// # Errors
    /// Refuses a foreign plan, oracle, model, schedule or repeated scene binding.
    pub fn install(
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        oracle: Rc<PacketCompleteNativeOracle>,
    ) -> Result<Rc<Self>, QualificationError> {
        authority.current()?;
        plan.authenticate_authority(authority.as_ref())
            .map_err(evidence)?;
        oracle.authenticate_installation(
            authority.roster(),
            authority.coordinator(),
            oracle.execution_schedule(),
            authority.witness_plan(),
        )?;
        schedule::authenticate(&oracle, authority.world())?;
        let original = Rc::new(Self {
            authority,
            plan,
            oracle,
            actor_reserved: Cell::new(false),
            runtime_attached: Cell::new(false),
            current_grant: Cell::new(None),
        });
        original.current()?;
        original.authority.bind_execution_scene(&original)?;
        Ok(original)
    }

    // These loans preserve the exact scene/authority/plan association. They do
    // not expose a runtime, install a report or authorize native execution.
    pub(super) fn authenticate_publication_owner(
        &self,
        authority: &Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: &Rc<InstalledConformancePlan>,
    ) -> Result<(), crucible::node_contract::RuntimeError> {
        self.current()
            .map_err(|_| crucible::node_contract::RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(authority, &self.authority) || !Rc::ptr_eq(plan, &self.plan) {
            return Err(crucible::node_contract::RuntimeError::ForeignAuthority);
        }
        self.current()
            .map_err(|_| crucible::node_contract::RuntimeError::ForeignAuthority)
    }

    pub(super) fn publication_oracle(&self) -> &Rc<PacketCompleteNativeOracle> {
        &self.oracle
    }

    pub(super) fn has_authority(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
    ) -> bool {
        std::ptr::eq(authority, self.authority.as_ref())
    }

    pub(super) fn current(&self) -> Result<(), QualificationError> {
        self.authority.current()?;
        self.plan
            .authenticate_authority(self.authority.as_ref())
            .map_err(evidence)?;
        self.oracle.authenticate_installation(
            self.authority.roster(),
            self.authority.coordinator(),
            self.oracle.execution_schedule(),
            self.authority.witness_plan(),
        )?;
        schedule::authenticate(&self.oracle, self.authority.world())
    }

    pub(super) fn preparation(&self) -> Result<(), QualificationError> {
        self.current()?;
        if !self.actor_reserved.get() {
            return Err(refused());
        }
        self.authority
            .original_capture_factory()
            .map_err(evidence)?
            .authenticate_preparation()
            .map_err(|error| {
                QualificationError::Evidence(super::construction_diagnostics::reason(error))
            })?;
        self.authority.roster().current_native().map_err(native)?;
        self.authority
            .host_source()
            .authenticate_complete_preparation_source(self.authority.host_source().world())
            .map_err(native)?;
        self.current()
    }

    pub(super) fn live(&self) -> Result<(), QualificationError> {
        self.preparation()?;
        if !self.runtime_attached.get() {
            return Err(refused());
        }
        for source in &self.authority.roster().sources {
            source
                .authenticate_original_complete_capture_support()
                .map_err(native)?;
        }
        // Unlike the dormant preparation check, this requires the same source's
        // actual initialized host scheduling attachment before any grant/input.
        self.authority
            .host_source()
            .authenticate_current()
            .map_err(native)?;
        self.oracle.preflight()?;
        self.authority.roster().current_native().map_err(native)?;
        self.current()
    }

    pub(super) fn world_request(
        &self,
        request: AdmissionRequest<'_>,
    ) -> Result<(), QualificationError> {
        self.preparation()?;
        if request.world != self.authority.world()
            || request.descriptors.len() != 4
            || request.bindings.len() != 4
            || request.owners.len() != 4
            || canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?
                != *self.authority.requirements_identity()
        {
            return Err(refused());
        }
        for (member, source) in self.authority.roster().sources.iter().enumerate() {
            let installed = source.installation();
            if request.descriptors[member] != installed.descriptor
                || request.bindings[member] != installed.binding
                || request.owners[member] != installed.owner
            {
                return Err(refused());
            }
        }
        let host = self.authority.host_source().selection();
        if request.descriptors[3] != host.descriptor
            || request.bindings[3] != host.binding
            || request.owners[3] != host.owner
        {
            return Err(refused());
        }
        self.preparation()
    }

    pub(super) fn exact_source(
        &self,
        source: &HostSchedulingSource,
    ) -> Result<(), QualificationError> {
        if !std::ptr::eq(source, self.authority.host_source().as_ref()) {
            return Err(refused());
        }
        self.preparation()
    }

    pub(super) fn operation(
        &self,
        node: &Id,
        operation: &Id,
        request: &OperationRequest,
    ) -> Result<(), QualificationError> {
        self.live()?;
        let grant = self
            .current_grant
            .get()
            .and_then(|index| self.oracle.execution_schedule().grants.get(index))
            .ok_or_else(refused)?;
        if &grant.node != node || &grant.operation != operation || &grant.request != request {
            return Err(refused());
        }
        // Core's same-runtime reservation enforces order and once-only IDs;
        // matching the installed schedule never manufactures that reservation.
        self.live()
    }

    pub(super) fn inputs(
        &self,
        batch: &crucible::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), QualificationError> {
        self.live()?;
        let grant = self
            .current_grant
            .get()
            .and_then(|index| self.oracle.execution_schedule().grants.get(index))
            .ok_or_else(refused)?;
        let limit = match grant.request {
            OperationRequest::ExactRun { limit, .. }
            | OperationRequest::BoundarySettle { limit, .. } => limit,
            _ => return Err(refused()),
        };
        if &grant.node != batch.node() || limit != batch.cutoff() {
            return Err(refused());
        }
        self.authority
            .host_source()
            .authenticate_input_batch(batch)
            .map_err(native)?;
        inputs::authenticate(&self.authority, batch)?;
        self.live()
    }

    pub(super) fn observe_original(
        &self,
        member: usize,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), QualificationError> {
        self.preparation()?;
        let source = self
            .authority
            .roster()
            .sources
            .get(member)
            .ok_or_else(refused)?;
        if !std::ptr::eq(scope.installation, source.installation()) {
            return Err(refused());
        }
        source.authenticate_provider(scope.native).map_err(native)?;
        source.authenticate_realization(scope).map_err(native)?;
        source
            .authenticate_original_native_owner(scope.native)
            .map_err(native)?;
        if !self.runtime_attached.get()
            && self
                .authority
                .original_inactive_oracle_callback_data()
                .map_err(evidence)?
        {
            self.oracle.observe_original_construction(member, scope)?;
        } else {
            self.oracle.observe(member, scope)?;
        }
        self.authority.roster().current_native().map_err(native)?;
        self.current()
    }
}

fn evidence(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(super::construction_diagnostics::reason(error))
}

fn native(error: crucible::node_contract::OperationFailure) -> QualificationError {
    QualificationError::Evidence(error.reason)
}
