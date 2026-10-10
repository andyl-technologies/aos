//! Joins source-owned capability policy with authentic current native enrollment.

use super::{ResolvedCapabilityWorld, policy};
use crucible::node_admission::{
    AdmissionEvidence, EvidenceError, NodeCapabilityRequirement, QualificationClaim,
};
use crucible_node_contract::{
    ContentRef, ImplementationIdentity, NodeBinding, SchemaRef, WorldBinding, canonical,
};

pub(in crate::node_observed_executor::factory) struct CapabilityAdmission<'a> {
    pub original: &'a dyn AdmissionEvidence,
    pub resolved: &'a ResolvedCapabilityWorld,
}

impl AdmissionEvidence for CapabilityAdmission<'_> {
    fn extension_registry(&self) -> Option<&crucible::node_admission::InstalledExtensionRegistry> {
        self.original.extension_registry()
    }
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.original.content(reference, maximum_bytes)
    }
    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.original.authenticate_implementation(implementation)
    }
    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.original.authenticate_authority(binding)
    }
    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.original.authenticate_schema(schema)
    }
    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.original.qualify(claim)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        if world != &self.resolved.scenario.world {
            return Err(refused(
                "capability scope differs from complete installed scenario",
            ));
        }
        let demanded = self
            .resolved
            .requirements
            .nodes
            .iter()
            .find(|node| node.node == requirement.node)
            .ok_or_else(|| refused("capability scope names an unselected node"))?;
        let expected = self
            .resolved
            .scenario
            .compatibility
            .iter()
            .find(|node| node.node_id == requirement.node)
            .ok_or_else(|| refused("capability scope omitted source-selected contract"))?;
        let selected = self
            .resolved
            .candidate
            .selections
            .iter()
            .find(|node| node.node == requirement.node)
            .ok_or_else(|| refused("capability scope omitted installed recipe"))?;
        if &binding.compatibility != expected
            || canonical::json_hash("crucible.capability-demand.v1", requirement)
                .map_err(|error| refused(&error.to_string()))?
                != canonical::json_hash("crucible.capability-demand.v1", demanded)
                    .map_err(|error| refused(&error.to_string()))?
        {
            return Err(refused(
                "required contract differs from source-regenerated selection",
            ));
        }
        self.original.authenticate_authority(binding)?;
        policy::qualify_kind(
            &selected.kind,
            requirement,
            policy::standalone_clock(&self.resolved.candidate.selections),
            policy::condition_preservation(&self.resolved.candidate.selections),
            policy::gem5_ordinary(&self.resolved.candidate.selections),
        )
        .map_err(|error| refused(&error.to_string()))
    }
}

fn refused(message: &str) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}
