//! Authenticates original preparation without admitting runtime effects.

use super::*;
use crucible::{
    node_adapters::cnp::{
        CnpSemanticConformanceAuthority, CnpSemanticRealizationScope, CnpSemanticRegistrationPolicy,
    },
    node_admission::{
        AdmissionEvidence, ConformanceAdmissionAuthority, NodeCapabilityRequirement,
        QualificationClaim,
    },
};
use crucible_node_contract::{ImplementationIdentity, NodeBinding, SchemaRef};

impl AdmissionEvidence for InstalledPacketCompleteCollectionAuthority {
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
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for InstalledPacketCompleteCollectionAuthority {
    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)
    }
}

impl CnpSemanticRegistrationPolicy for InstalledPacketCompleteCollectionAuthority {
    fn authenticate(&self, selected: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        self.index(selected).map_err(operation_error)?;
        self.current().map_err(operation_error)
    }
}

impl CnpSemanticConformanceAuthority for InstalledPacketCompleteCollectionAuthority {
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
        self.current().map_err(operation_error)?;
        let index = self.index(scope.installation).map_err(operation_error)?;
        let source = &self.roster.sources[index];
        source.authenticate_provider(scope.native)?;
        source.authenticate_realization(scope)?;
        source.authenticate_original_native_owner(scope.native)?;
        source.authenticate_realized_preconstruction(&scope)?;
        if source.selected_ack_emitter_selection()?.is_some() {
            self.original_ack_callback_started.set(true);
            let slot = self
                .original_ack_hello
                .try_borrow()
                .map_err(|_| operation_error(refused()))?[index]
                .as_ref()
                .cloned()
                .ok_or_else(|| operation_error(refused()))?;
            let mut original = slot
                .try_borrow_mut()
                .map_err(|_| operation_error(refused()))?;
            source.retain_original_canonical_ack_peer_association(&scope, &mut original)?;
        }
        self.current().map_err(operation_error)
    }
}
