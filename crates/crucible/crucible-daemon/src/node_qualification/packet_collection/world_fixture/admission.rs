//! Keeps complete three-owner collection admission distinct from ordinary claims.

use crucible_engine::{
    node_adapters::cnp::{
        CnpSemanticConformanceAuthority, CnpSemanticRealizationScope, CnpSemanticRegistrationPolicy,
    },
    node_admission::{
        AdmissionEvidence, AdmissionRequest, ConformanceAdmissionAuthority,
        NodeCapabilityRequirement, QualificationClaim,
    },
    node_contract::{EffectKnowledge, OperationFailure, OperationRequest},
};
use crucible_node_format::{ImplementationIdentity, NodeBinding, SchemaRef};

use super::*;

impl InstalledPacketWorldCollectionAuthority {
    fn authenticate_world_request(
        &self,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        if request.world != &self.world
            || request.descriptors.len() != 3
            || request.bindings.len() != 3
            || request.owners.len() != 3
            || canonical::json_hash("cnp.admission-requirements.v1", request.requirements)
                .map_err(|error| evidence(error.into()))?
                != self.requirements_hash
        {
            return Err(evidence(refused()));
        }
        for member in 0..3 {
            let selected = self.sources[member].installation();
            if request.descriptors[member] != selected.descriptor
                || request.bindings[member] != selected.binding
                || request.owners[member] != selected.owner
            {
                return Err(evidence(refused()));
            }
        }
        self.current().map_err(evidence)
    }

    fn original_native(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.current().map_err(operation)?;
        let member = self.index(scope.installation).map_err(operation)?;
        self.sources[member].authenticate_provider(scope.native)?;
        self.sources[member].authenticate_realization(scope)?;
        self.oracles[member].observe(scope).map_err(operation)?;
        self.current().map_err(operation)
    }
}

impl AdmissionEvidence for InstalledPacketWorldCollectionAuthority {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.current().map_err(evidence)?;
        if let Some(body) = self.bodies.get(reference) {
            if body.len() > maximum {
                return Err(evidence(refused()));
            }
            reference
                .verify(body)
                .map_err(|error| evidence(error.into()))?;
            let answer = body.clone();
            self.current().map_err(evidence)?;
            return Ok(answer);
        }
        let answer = self.graph_policy.content(reference, maximum)?;
        self.current().map_err(evidence)?;
        Ok(answer)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        self.graph_policy
            .authenticate_implementation(implementation)?;
        self.current().map_err(evidence)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        let selected = self
            .sources
            .iter()
            .find(|source| &source.installation().binding == binding)
            .ok_or_else(|| evidence(refused()))?;
        self.graph_policy.authenticate_authority(binding)?;
        selected
            .authenticate_current_native()
            .map_err(|error| EvidenceError {
                message: error.reason,
            })?;
        self.current().map_err(evidence)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        self.graph_policy.authenticate_schema(schema)?;
        self.current().map_err(evidence)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        self.graph_policy
            .qualify_capability(world, binding, requirement)?;
        self.current().map_err(evidence)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        // The source-installed structural policy refuses ordinary Node/classes.
        // Only its independently interpreted exact non-Node claims are delegated.
        self.graph_policy.qualify(claim)?;
        self.current().map_err(evidence)
    }
}

impl ConformanceAdmissionAuthority for InstalledPacketWorldCollectionAuthority {
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
        // Same original issuer/files/plan above; direct actual owner/gate reads
        // for ALL three enrolled native capsules are the terminal conjunction.
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
            return Err(evidence(refused()));
        };
        for source in &self.sources {
            let selected = source.installation();
            if binding == &selected.binding.compatibility
                && binding_hash
                    == &selected
                        .binding
                        .compatibility
                        .identity()
                        .map_err(|error| evidence(error.into()))?
                && qualification_refs == selected.binding.compatibility.qualification_refs
            {
                return self.current().map_err(evidence);
            }
        }
        Err(evidence(refused()))
    }

    fn authenticate_collection_operation(
        &self,
        plan: ConformancePlanEvidence<'_>,
        node: &Id,
        operation: &Id,
        request: &OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        let member = self.node(node).map_err(evidence)?;
        self.oracles[member].preflight().map_err(evidence)?;
        if !self
            .schedule
            .grants
            .iter()
            .enumerate()
            .any(|(index, grant)| {
                index % 3 == member && &grant.operation == operation && &grant.request == request
            })
        {
            return Err(evidence(refused()));
        }
        self.current().map_err(evidence)
    }
}

impl CnpSemanticRegistrationPolicy for InstalledPacketWorldCollectionAuthority {
    fn authenticate(&self, selection: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        self.current().map_err(operation)?;
        self.index(selection).map_err(operation)?;
        self.current().map_err(operation)
    }
}

impl CnpSemanticConformanceAuthority for InstalledPacketWorldCollectionAuthority {
    fn authenticate_installation(
        &self,
        selection: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        self.current().map_err(operation)?;
        self.index(selection).map_err(operation)?;
        self.current().map_err(operation)
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
            return Err(operation(refused()));
        }
        graph
            .plan()
            .authenticate_authority(self)
            .map_err(|error| operation(QualificationError::Evidence(error.to_string())))?;
        graph
            .reauthenticate()
            .map_err(|error| operation(QualificationError::Evidence(error.to_string())))?;
        self.all_native_current()
    }

    fn authenticate_native_dispatch(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        self.index(scope.installation).map_err(operation)?;
        plan.authenticate_authority(self)
            .map_err(|error| operation(QualificationError::Evidence(error.to_string())))?;
        self.authenticate_plan_view(plan.evidence())
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::None,
                reason: error.message,
            })?;
        self.all_native_current()
    }
}

fn operation(error: QualificationError) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: error.to_string(),
    }
}
