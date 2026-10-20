//! Separates preparation correlation from actual native and host effect authority.

use crucible_engine::{
    node_adapters::cnp::{
        CnpSemanticConformanceAuthority, CnpSemanticRealizationScope, CnpSemanticRegistrationPolicy,
    },
    node_admission::{
        AdmissionEvidence, AdmissionRequest, ConformanceAdmissionAuthority,
        NodeCapabilityRequirement, QualificationClaim,
    },
    node_contract::{HostSchedulingSource, OperationFailure, OperationRequest},
};
use crucible_node_format::{ImplementationIdentity, NodeBinding, SchemaRef};

use super::*;

impl InstalledPacketConnectedCollectionAuthority {
    fn authenticate_world_request(
        &self,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        if request.world != &self.world
            || request.descriptors.len() != 4
            || request.bindings.len() != 4
            || request.owners.len() != 4
            || canonical::json_hash("cnp.admission-requirements.v1", request.requirements)
                .map_err(|error| evidence_error(error.into()))?
                != self.requirements
        {
            return Err(evidence_error(refused()));
        }
        for member in 0..3 {
            let selected = self.roster.sources[member].installation();
            if request.descriptors[member] != selected.descriptor
                || request.bindings[member] != selected.binding
                || request.owners[member] != selected.owner
            {
                return Err(evidence_error(refused()));
            }
        }
        let host = self.host.selection();
        if request.descriptors[3] != host.descriptor
            || request.bindings[3] != host.binding
            || request.owners[3] != host.owner
        {
            return Err(evidence_error(refused()));
        }
        self.current().map_err(evidence_error)
    }

    fn all_native_current(&self) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        self.roster.current_native()?;
        self.current().map_err(operation_error)
    }

    fn original_native(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        let selected = self
            .roster
            .sources
            .get(self.index(scope.installation).map_err(operation_error)?)
            .ok_or_else(|| operation_error(refused()))?;
        match selected {
            PacketConnectedParticipant::Producer(source) => {
                source.authenticate_provider(scope.native)?;
                source.authenticate_realization(scope)?;
            }
            PacketConnectedParticipant::Reactive(source) => {
                source.authenticate_provider(scope.native)?;
                source.authenticate_realization(scope)?;
            }
        }
        self.oracle
            .observe(
                self.index(scope.installation).map_err(operation_error)?,
                scope,
            )
            .map_err(operation_error)?;
        self.current().map_err(operation_error)
    }
}

impl AdmissionEvidence for InstalledPacketConnectedCollectionAuthority {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.current().map_err(evidence_error)?;
        let answer = if let Some(body) = self.population.bodies.get(reference) {
            if body.len() > maximum {
                return Err(evidence_error(refused()));
            }
            reference
                .verify(body)
                .map_err(|error| evidence_error(error.into()))?;
            body.clone()
        } else {
            self.graph_policy.content(reference, maximum)?
        };
        self.current().map_err(evidence_error)?;
        Ok(answer)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy
            .authenticate_implementation(implementation)?;
        self.current().map_err(evidence_error)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.authenticate_authority(binding)?;
        // Admission precedes host attachment. Actual effects separately require
        // live original native custody and that exact attached scheduler.
        self.current().map_err(evidence_error)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.authenticate_schema(schema)?;
        self.current().map_err(evidence_error)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy
            .qualify_capability(world, binding, requirement)?;
        self.current().map_err(evidence_error)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.qualify(claim)?;
        self.current().map_err(evidence_error)
    }
}

impl ConformanceAdmissionAuthority for InstalledPacketConnectedCollectionAuthority {
    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.authenticate_world_request(request)
    }

    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.authenticate_world_request(request)?;
        // This also runs before the host runtime is born. The preparation guard
        // cannot claim an attached scheduler; effect callbacks below require it.
        self.all_native_current().map_err(|error| EvidenceError {
            message: error.reason,
        })
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        let QualificationClaim::Node {
            binding,
            binding_hash,
            qualification_refs,
        } = claim
        else {
            return Err(evidence_error(refused()));
        };
        for node in self.world.node_bindings.iter().map(|row| &row.node_id) {
            let selected = self.binding(node).map_err(evidence_error)?;
            if binding == &selected.compatibility
                && binding_hash
                    == &selected
                        .compatibility
                        .identity()
                        .map_err(|error| evidence_error(error.into()))?
                && qualification_refs == selected.compatibility.qualification_refs
            {
                return self.current().map_err(evidence_error);
            }
        }
        Err(evidence_error(refused()))
    }

    fn authenticate_collection_exact_inputs(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
        source: &HostSchedulingSource,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.authenticate_world_request(request)?;
        if !std::ptr::eq(source, self.host.as_ref()) {
            return Err(evidence_error(refused()));
        }
        source
            .authenticate_preparation_source(
                &self
                    .world
                    .identity()
                    .map_err(|error| evidence_error(error.into()))?,
            )
            .map_err(|error| EvidenceError {
                message: error.reason,
            })?;
        self.all_native_current().map_err(|error| EvidenceError {
            message: error.reason,
        })
    }

    fn authenticate_collection_inputs(
        &self,
        plan: ConformancePlanEvidence<'_>,
        batch: &crucible_engine::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.authenticate_live_originals().map_err(evidence_error)?;
        self.host
            .authenticate_input_batch(batch)
            .map_err(|error| EvidenceError {
                message: error.reason,
            })?;
        super::input::authenticate(self, batch)?;
        self.authenticate_live_originals().map_err(evidence_error)
    }

    fn authenticate_collection_operation(
        &self,
        plan: ConformancePlanEvidence<'_>,
        node: &Id,
        operation: &Id,
        request: &OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.authenticate_live_originals().map_err(evidence_error)?;
        if !self.schedule.grants.iter().any(|grant| {
            &grant.node == node && &grant.operation == operation && &grant.request == request
        }) {
            return Err(evidence_error(refused()));
        }
        self.authenticate_live_originals().map_err(evidence_error)
    }
}

impl CnpSemanticRegistrationPolicy for InstalledPacketConnectedCollectionAuthority {
    fn authenticate(&self, selected: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        self.index(selected).map_err(operation_error)?;
        self.current().map_err(operation_error)
    }
}

impl CnpSemanticConformanceAuthority for InstalledPacketConnectedCollectionAuthority {
    fn authenticate_installation(
        &self,
        selected: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        self.index(selected).map_err(operation_error)?;
        self.current().map_err(operation_error)
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.original_native(scope)
    }

    fn authenticate_graph(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        graph: &crucible_engine::node_admission::ConformanceGraph,
    ) -> Result<(), OperationFailure> {
        self.original_native(scope)?;
        if graph.world() != &self.world {
            return Err(operation_error(refused()));
        }
        graph
            .plan()
            .authenticate_authority(self)
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))?;
        graph
            .reauthenticate()
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))?;
        self.all_native_current()
    }

    fn authenticate_native_dispatch(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        self.index(scope.installation).map_err(operation_error)?;
        plan.authenticate_authority(self)
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))?;
        self.authenticate_plan_view(plan.evidence())
            .map_err(|error| OperationFailure {
                effects: crucible_engine::node_contract::EffectKnowledge::None,
                reason: error.message,
            })?;
        self.all_native_current()?;
        self.host.authenticate_dispatch_source()?;
        self.current().map_err(operation_error)
    }
}
