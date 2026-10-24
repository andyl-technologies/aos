//! Supplies the actual attached host scheduling owner to one collecting runtime.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_format::{Extensions, PreparedOwner};

use crate::node_admission::InstalledConformancePlan;
use crate::node_contract::{
    ActivationRecord, CancelStatus, FacetKind, Lifecycle, NativeReclamationReceipt, NodeFacet,
    NodeRoute, NodeStatus, OperationAdmission, OperationFailure, OperationOutcome, OperationToken,
    OwnerIdentity, PhysicalState, ReadyAttestation, Refusal, RuntimeError, SimulationNode,
    Submission, ThreadAffinity,
};

use super::{HostSchedulingSource, canonical, failure, json};

mod capture;
#[path = "node/capture17.rs"]
mod capture17;
mod preservation;
mod requested_storage;

/// Retains the source-created host owner without any unrelated model queue.
pub struct PreparedHostSchedulingNode {
    source: Rc<HostSchedulingSource>,
    anchor: Rc<()>,
    plan: Option<InstalledConformancePlan>,
    activation: ActivationRecord,
    route: NodeRoute,
    ready: Option<(ReadyAttestation, Vec<u8>)>,
    retired: bool,
    reclamation: Option<NativeReclamationReceipt>,
    restoration: Option<preservation::HostRestorationAdmission>,
    restoration_installed: bool,
    capture_preparation: Option<crate::node_contract::HostSchedulingContinuationV2>,
    capture_preparation17: Option<crate::node_contract::HostSchedulingRestoredContinuation17>,
}

impl PreparedHostSchedulingNode {
    pub(super) fn new(
        source: Rc<HostSchedulingSource>,
        anchor: Rc<()>,
        plan: InstalledConformancePlan,
        activation: ActivationRecord,
        route: NodeRoute,
    ) -> Self {
        Self {
            source,
            anchor,
            plan: Some(plan),
            activation,
            route,
            ready: None,
            retired: false,
            reclamation: None,
            restoration: None,
            restoration_installed: false,
            capture_preparation: None,
            capture_preparation17: None,
        }
    }

    pub(super) fn new_complete_restoration(
        source: Rc<HostSchedulingSource>,
        anchor: Rc<()>,
        plan: Option<InstalledConformancePlan>,
        activation: ActivationRecord,
        route: NodeRoute,
    ) -> Self {
        Self {
            source,
            anchor,
            plan,
            activation,
            route,
            ready: None,
            retired: false,
            reclamation: None,
            restoration: None,
            restoration_installed: false,
            capture_preparation: None,
            capture_preparation17: None,
        }
    }

    /// Authenticates this same factory-created inactive node before capsule transfer.
    ///
    /// The private source and node anchors must match; portable equal tuples do
    /// not authorize another host node or activation.
    pub(crate) fn authenticate_original_source(
        &self,
        source: &Rc<HostSchedulingSource>,
        activation: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        source.authenticate_dispatch_source()?;
        let witness = super::HostSchedulingNodeWitness::new(&self.source, &self.anchor);
        if !witness.matches(source).map_err(failure)?
            || &self.activation != activation
            || self.ready.is_some()
            || self.retired
            || self.reclamation.is_some()
        {
            return Err(failure(
                "original host node, activation or inactive custody differs",
            ));
        }
        source.authenticate_dispatch_source()
    }

    fn current(&self) -> Result<(), OperationFailure> {
        if self.retired {
            return Err(failure("original host scheduling node is retired"));
        }
        self.source.authenticate_current()
    }

    fn prepared(&self, readiness: &ReadyAttestation) -> Result<PreparedOwner, OperationFailure> {
        self.current()?;
        let owner = self
            .route
            .owners
            .first()
            .ok_or_else(|| failure("original host owner absent"))?;
        Ok(PreparedOwner {
            owner_id: owner.owner.clone(),
            incarnation_id: owner.incarnation.clone(),
            owner_generation: owner.generation,
            binding_hashes: vec![self.source.selection.binding.identity().map_err(failure)?],
            prepared_token: self.source.prepared_token.clone(),
            ready_receipt: readiness.ready_receipt.clone(),
            extensions: Extensions::new(),
        })
    }

    fn refuse() -> Refusal {
        Refusal {
            reason: "host scheduling state mutates only through its owning common runtime".into(),
        }
    }
}

impl SimulationNode for PreparedHostSchedulingNode {
    fn inspect_original_host_restoration_continuation(
        &self,
        inspection: &crate::node_admission::OriginalRestorationHostContinuationInspection<'_>,
    ) -> Result<(), RuntimeError> {
        inspection.authenticate_current()?;
        let ticket = self
            .source
            .archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if self.source.original_ticket.is_some()
            || !Rc::ptr_eq(&ticket.source, &inspection.archive_data().inner)
            || &self.route.node != inspection.node_data()?
            || &self.activation != inspection.target_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let record = inspection.record_data()?;
        self.validate_original_host_restoration_fields(
            inspection.source_record_data(),
            record,
            inspection.source_record_data(),
            &record.source_activation,
            inspection.target_data(),
            7,
            inspection.owner_mappings_data(),
            inspection.journals_data(),
            inspection.archive_data().content(),
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        inspection.authenticate_current()
    }

    fn retained_descriptor_views_precredit_data(&self) -> Result<Option<usize>, RuntimeError> {
        // The closed original Host owns only metadata/Rc scheduling state;
        // restoration, active readiness and unknown owners refuse below.
        if let Some(ticket) = self.source.archive_ticket.as_ref() {
            self.original_installed_restoration_node_precredit_data(usize::MAX)?;
            return ticket
                .source
                .retained_descriptor_views_precredit_data()
                .map(Some);
        }
        self.original_dormant_node_precredit_data(usize::MAX)?;
        Ok(Some(0))
    }

    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        if self.source.archive_ticket.is_some() {
            return self
                .original_installed_restoration_node_precredit_data(maximum)
                .map(Some);
        }
        self.original_dormant_node_precredit_data(maximum).map(Some)
    }

    fn retained_requested_storage_precredit_scratch_data(
        &self,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        if self.source.process != std::process::id()
            || self.source.owner_thread != std::thread::current().id()
        {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        // The source metadata walk excludes its shared runtime and follows
        // only fixed original selection/anchor/attachment views. Installed
        // authority counter banks remain independently admitted by the caller.
        if self.source.archive_ticket.is_some() {
            return Ok(Some(Self::restoration_inactive_node_counter_scratch_data()));
        }
        Ok(Some(Self::original_inactive_node_counter_scratch_data()))
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        self.original_retained_node_backing(maximum).map(Some)
    }

    fn collection_scope(&self) -> Option<&InstalledConformancePlan> {
        self.plan.as_ref()
    }

    fn validate_collection_scope(
        &self,
        plan: &InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        self.source
            .authenticate_preparation_source(&self.source.world)?;
        if !self
            .plan
            .as_ref()
            .is_some_and(|original| original.same_original(plan))
        {
            return Err(failure(
                "host scheduling node changed original collection plan",
            ));
        }
        if self.ready.is_some() {
            self.current()?;
        }
        Ok(())
    }

    fn descriptor(&self) -> &crucible_node_format::NodeDescriptor {
        &self.source.selection.descriptor
    }

    fn binding(&self) -> &crucible_node_format::NodeBinding {
        &self.source.selection.binding
    }

    fn route(&self) -> &NodeRoute {
        &self.route
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        ThreadAffinity::OwnerThread(self.source.owner_thread)
    }

    fn facets(&self) -> &[FacetKind] {
        super::complete::selected_facets(self.source.edition).0
    }

    fn original_host_scheduling_owner(
        &self,
    ) -> Option<crate::node_contract::HostSchedulingNodeWitness<'_>> {
        Some(
            crate::node_contract::HostSchedulingNodeWitness::new(&self.source, &self.anchor)
                .with_original_node(self),
        )
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.current()?;
        Ok(NodeStatus {
            lifecycle: if self.ready.is_some() {
                Lifecycle::Stopped
            } else {
                Lifecycle::Prepared
            },
            physical: PhysicalState::Unknown,
            boundary: None,
        })
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.current()?;
        if world != &self.activation || self.ready.is_some() {
            return Err(failure(
                "host scheduling Arm changed or repeated original preparation",
            ));
        }
        self.source.authenticate_initial_attachment()?;
        if (self.source.original_ticket.is_some() || self.source.archive_ticket.is_some())
            && self.restoration.is_none()
        {
            return Err(failure(
                "original host restore context was not admitted before Arm",
            ));
        }
        let body = if self.source.edition == super::preservation::Edition::Unsupported {
            json!({
                "schema":"source-owned.host-scheduling-owner-preparation/1",
                "process":self.source.process, "world_binding_hash":self.source.world,
                "node_binding_hash":self.source.selection.binding.identity().map_err(failure)?,
                "owner_binding_hash":self.source.selection.owner.identity().map_err(failure)?,
                "prepared_token":self.source.prepared_token,
                "scheduling_slot":"original-uninitialized", "boundary":world.boundary,
                "capture":"unsupported"
            })
        } else if self.source.edition == super::preservation::Edition::CompleteOriginalLineage {
            json!({
                "schema":"source-owned.host-scheduling-complete-preparation/2",
                "process":self.source.process, "world_binding_hash":self.source.world,
                "node_binding_hash":self.source.selection.binding.identity().map_err(failure)?,
                "owner_binding_hash":self.source.selection.owner.identity().map_err(failure)?,
                "prepared_token":self.source.prepared_token,
                "scheduling_slot":"original-uninitialized", "boundary":world.boundary,
                "original_restore":self.restoration.as_ref().map(|admission| &admission.source),
                "capture":"core-issued original unchanged-cut common snapshot with explicit administrative settlement"
            })
        } else {
            json!({
                "schema":"source-owned.host-scheduling-owner-preparation/2",
                "process":self.source.process, "world_binding_hash":self.source.world,
                "node_binding_hash":self.source.selection.binding.identity().map_err(failure)?,
                "owner_binding_hash":self.source.selection.owner.identity().map_err(failure)?,
                "prepared_token":self.source.prepared_token,
                "scheduling_slot":"original-uninitialized", "boundary":world.boundary,
                "original_restore":self.restoration.as_ref().map(|admission| &admission.source),
                "capture":"unsupported"
            })
        };
        let bytes = canonical::canonical_json(&body).map_err(failure)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(failure)?;
        let ready = ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: world.boundary,
            state_inventory: reference.clone(),
            ready_receipt: reference,
        };
        self.ready = Some((ready.clone(), bytes));
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let (original, bytes) = self
            .ready
            .as_ref()
            .ok_or_else(|| failure("original host Ready absent"))?;
        if world != &self.activation || readiness != original {
            return Err(failure(
                "host Ready differs from actual original attachment",
            ));
        }
        readiness.ready_receipt.verify(bytes).map_err(failure)
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        self.validate_readiness(world, readiness)?;
        Ok(Some(vec![self.prepared(readiness)?]))
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(world, readiness)?;
        if owners != [self.prepared(readiness)?] {
            return Err(failure(
                "host prepared owner differs from its original source token",
            ));
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(world, readiness)?;
        self.source.authenticate_initial_attachment()
    }

    fn validate_original_lineage_restoration(
        &self,
        source_record: &crucible_node_format::ContentRef,
        record: &crate::node_contract::OriginalLineageRuntimeRecord,
        scope: &crate::node_contract::OriginalLineageNativeScope,
        content: &crate::node_state::VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        self.validate_original_host_restoration(source_record, record, scope, content)
    }

    fn validate_exact_original_lineage_restoration(
        &self,
        source_record: &crucible_node_format::ContentRef,
        record: &crate::node_contract::OriginalLineageRuntimeRecord,
        scope: &crate::node_contract::OriginalLineageNativeScope,
        content: &crate::node_state::VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        self.validate_original_host_restoration(source_record, record, scope, content)
    }

    fn admit_original_lineage_restoration(
        &mut self,
        context: &crate::node_contract::OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.admit_original_host_restoration(context)
    }

    fn install_original_lineage_restored_custody(
        &mut self,
        context: &crate::node_contract::OriginalLineageRestoration<'_>,
        activation: &crate::node_contract::WorldActivation,
        operations: &[OperationAdmission],
        inputs: &[Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.install_original_host_restoration(context, activation, operations, inputs)
    }

    fn capture_original_lineage_continuation_with_ticket(
        &mut self,
        ticket: &crate::node_contract::OriginalLineageOwnerCaptureTicket<'_>,
        activation: &crate::node_contract::WorldActivation,
        source: &crate::node_contract::OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        limits: crate::node_contract::NativeCaptureLimits,
    ) -> Result<crate::node_contract::InstalledOriginalLineageCapture, OperationFailure> {
        self.capture_original_common_state(ticket, activation, source, runtime_object, limits)
    }

    fn capture_original_lineage_continuation_with_ticket_into(
        &mut self,
        ticket: &crate::node_contract::OriginalLineageOwnerCaptureTicket<'_>,
        activation: &crate::node_contract::WorldActivation,
        source: &crate::node_contract::OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        limits: crate::node_contract::NativeCaptureLimits,
        completed: &mut Option<crate::node_contract::InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        self.capture_original_common_state_into(
            ticket,
            activation,
            source,
            runtime_object,
            limits,
            completed,
        )
    }

    fn begin_operation(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Self::refuse())
    }

    fn poll_operation(
        &mut self,
        _: &OperationToken,
        _: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        Poll::Ready(Err(failure(
            "host coordinator has no independently submitted native operation",
        )))
    }

    fn validate_outcome(
        &self,
        _: &OperationAdmission,
        _: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        Err(failure("host coordinator cannot mint a native completion"))
    }

    fn request_cancel(&mut self, _: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        Ok(CancelStatus::Unsupported)
    }

    fn close_quantum(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Self::refuse())
    }

    fn acknowledge_publication(
        &mut self,
        _: &OperationToken,
        _: &[crucible_node_format::Id],
    ) -> Result<(), OperationFailure> {
        Err(failure(
            "host coordinator has no independent native output acknowledgement",
        ))
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.current().map_err(|_| Self::refuse())?;
        if kind == FacetKind::Preservation
            && let Some(facet) = self.source.preservation_facet.as_ref()
        {
            return Ok(NodeFacet::Preservation(facet));
        }
        Err(Self::refuse())
    }

    fn quarantine_resources(&mut self) {
        self.retired = true;
        self.source.revoke_attached();
    }

    fn graceful_retirement_available(&self) -> bool {
        true
    }

    fn shutdown_resources(&mut self) -> Result<(), OperationFailure> {
        self.source
            .authenticate_preparation_source(&self.source.world)?;
        self.retired = true;
        self.source.revoke_attached();
        Ok(())
    }

    fn transfer_retirement_resources(&mut self) -> Result<(), OperationFailure> {
        if !self.retired {
            return Err(failure("host scheduling mutation authority remains live"));
        }
        // The original whole-runtime slot owns operational queue bytes. This
        // source view cannot erase, advance, restore or free that allocation.
        self.source.authenticate_closed_attachment()
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        _: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if !self.retired || self.route.owners.as_slice() != [owner.clone()] {
            return Poll::Ready(Err(failure(
                "host scheduling owner remains live or foreign",
            )));
        }
        if let Err(error) = self.source.authenticate_closed_attachment() {
            return Poll::Ready(Err(error));
        }
        if self.reclamation.is_none() {
            let body = json!({"schema":"source-owned.host-scheduling-authority-revoked/1",
                "owner":owner,"world":self.source.world,"native_resources":[],
                "history":"original queues retained by whole-runtime custody; no capture or destruction permission"});
            let bytes = match canonical::canonical_json(&body).map_err(failure) {
                Ok(bytes) => bytes,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let receipt = match canonical::content_ref(&bytes, "application/json").map_err(failure)
            {
                Ok(reference) => reference,
                Err(error) => return Poll::Ready(Err(error)),
            };
            self.reclamation = Some(NativeReclamationReceipt {
                owner: owner.clone(),
                receipt,
            });
        }
        match self.reclamation.as_ref() {
            Some(receipt) => Poll::Ready(Ok(receipt.clone())),
            None => Poll::Ready(Err(failure("host authority revocation receipt absent"))),
        }
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.source.authenticate_closed_attachment()?;
        if !self.retired || self.reclamation.as_ref() != Some(receipt) {
            return Err(failure(
                "host revocation differs from original retained receipt",
            ));
        }
        Ok(())
    }
}

impl PreparedHostSchedulingNode {
    pub(crate) fn original_inactive_node_counter_scratch_data() -> usize {
        2 * std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>(
        ) + super::HostSchedulingSource::retained_original_metadata_counter_scratch_data()
            + std::mem::size_of::<std::cell::Ref<'_, std::rc::Weak<()>>>()
    }
}

impl PreparedHostSchedulingNode {
    pub(crate) fn restoration_inactive_node_counter_scratch_data() -> usize {
        2 * std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>(
        ) + super::HostSchedulingSource::retained_restoration_metadata_counter_scratch_data()
            + std::mem::size_of::<std::cell::Ref<'_, std::rc::Weak<()>>>()
            + std::mem::size_of::<
                Result<std::cell::Ref<'_, std::rc::Weak<()>>, std::cell::BorrowError>,
            >()
            + std::mem::size_of::<std::rc::Weak<()>>()
            + std::mem::size_of::<Result<Option<usize>, RuntimeError>>()
            + Self::original_installed_restoration_counter_scratch_data()
    }
}

#[path = "node/installed_storage.rs"]
mod installed_storage;
