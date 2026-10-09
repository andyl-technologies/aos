//! Resolves mandatory authored capabilities against a complete selected contract.
//!
//! The distinct scenario-root wrapper binds the requirement document and every
//! selected compatibility hash. Structural matches remain data predicates;
//! admission separately requires installed semantic qualification for each node.

mod records;
mod selection;

#[cfg(test)]
mod tests;

pub use records::{
    CapabilityBinding, CapabilityRequirements, CapabilitySelection, ComputeRequirement,
    GuaranteeRequirement, NodeCapabilityRequirement, OperationRequirement, TimingRequirement,
};
pub(super) use selection::check_selection;

use super::error::refuse;
use super::{AdmissionCode, AdmissionError, AdmissionStage, AdmissionSubject};
use crucible_node_contract::{
    BindingCompatibility, CapabilityProfile, GuaranteeProfile, NodeDescriptor, Validate,
};

/// Names the closed authored capability document format.
pub const CAPABILITY_REQUIREMENTS_FORMAT: &str = "crucible.node-capability-requirements";
/// Names the distinct identity-bearing scenario-root format.
pub const CAPABILITY_SELECTION_FORMAT: &str = "crucible.node-capability-selection";
/// Selects the independently versioned authored requirements content type.
pub const CAPABILITY_REQUIREMENTS_MEDIA_TYPE: &str =
    "application/vnd.crucible.node-capability-requirements.v1+json";
/// Selects the independently versioned scenario-root interpretation.
pub const CAPABILITY_SELECTION_MEDIA_TYPE: &str =
    "application/vnd.crucible.node-capability-selection.v1+json";
/// Bounds each requirement dimension before matching or cloning.
pub const MAX_CAPABILITY_REQUIREMENTS: usize = 256;

impl CapabilityRequirements {
    /// Checks the closed edition, strict rosters and independently bounded axes.
    ///
    /// # Errors
    /// Refuses unsupported editions, empty/duplicate node or operation rosters,
    /// invalid references, and demands exceeding the fixed finite ceilings.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        super::evidence::bounded_core(self, 1024 * 1024)?;
        if self.format != CAPABILITY_REQUIREMENTS_FORMAT
            || self.schema_version != 1
            || self.nodes.is_empty()
            || self.nodes.len() > MAX_CAPABILITY_REQUIREMENTS
            || self
                .nodes
                .windows(2)
                .any(|pair| pair[0].node >= pair[1].node)
        {
            return Err(failure(
                "closed capability edition and sorted bounded node roster",
            ));
        }
        for node in &self.nodes {
            let dimensions = [
                node.roles.len(),
                node.operations.len(),
                node.extensions.len(),
            ];
            if dimensions
                .iter()
                .any(|count| *count > MAX_CAPABILITY_REQUIREMENTS)
                || node.roles.windows(2).any(|pair| pair[0] >= pair[1])
                || node.operations.is_empty()
                || node
                    .operations
                    .windows(2)
                    .any(|pair| pair[0].operation >= pair[1].operation)
                || node
                    .extensions
                    .windows(2)
                    .any(|pair| pair[0].identifier >= pair[1].identifier)
            {
                return Err(failure("sorted bounded conjunctive node demands"));
            }
            node.timing
                .policy_ref
                .validate()
                .map_err(super::nodes::schema_error)?;
            for operation in &node.operations {
                operation
                    .facet
                    .validate()
                    .map_err(super::nodes::schema_error)?;
            }
            for extension in &node.extensions {
                extension.validate().map_err(super::nodes::schema_error)?;
            }
            if let Some(compute) = &node.compute {
                compute
                    .machine_ref
                    .validate()
                    .map_err(super::nodes::schema_error)?;
                compute
                    .devices_ref
                    .validate()
                    .map_err(super::nodes::schema_error)?;
            }
        }
        Ok(())
    }
}

impl NodeCapabilityRequirement {
    /// Matches data predicates against one complete selected implementation.
    ///
    /// This method grants no installed support, native custody or execution
    /// authority. The host must independently qualify operation meanings and
    /// architecture/device interpretation for the exact matched scope.
    ///
    /// # Errors
    /// Refuses any unmatched role, timing/configuration/facet/version identity,
    /// independent guarantee axis, or actual machine/device-map identity.
    pub fn match_contract(
        &self,
        descriptor: &NodeDescriptor,
        binding: &BindingCompatibility,
        capabilities: &CapabilityProfile,
        guarantees: &GuaranteeProfile,
    ) -> Result<(), AdmissionError> {
        let operating = &binding.operating_contract;
        let demanded = &self.guarantees;
        let matched = self.node == descriptor.id
            && self.node == binding.node_id
            && self
                .roles
                .iter()
                .all(|role| descriptor.roles.contains(role))
            && self.timing.mode == operating.mode
            && self.timing.resolution_ps == operating.resolution_ps
            && self.timing.phase_ps == operating.phase_ps
            && self.timing.policy_ref == operating.policy_ref
            && self.operations.iter().all(|operation| {
                operating.facets.contains(&operation.facet)
                    && capabilities.facets.contains(&operation.facet)
            })
            && demanded.repeatability == guarantees.repeatability
            && demanded.capture_scope == guarantees.capture_scope
            && demanded.continuation == guarantees.continuation
            && (!demanded.durable_restart || guarantees.durable_restart)
            && (!demanded.isolated_fork || guarantees.isolated_fork)
            && (!demanded.conditional_replay || guarantees.conditional_replay);
        if !matched {
            return Err(node_failure(
                self,
                "one complete selected contract satisfying all mandatory demands",
            ));
        }
        if let Some(compute) = &self.compute
            && (!descriptor
                .roles
                .iter()
                .any(|role| role.as_str() == "compute")
                || compute.machine_ref != binding.configuration_ref
                || compute.devices_ref != capabilities.devices_ref)
        {
            return Err(node_failure(
                self,
                "explicit actual machine configuration and complete device map",
            ));
        }
        Ok(())
    }
}

pub(super) fn failure(required: &str) -> AdmissionError {
    refuse(
        AdmissionStage::Nodes,
        AdmissionSubject::World,
        AdmissionCode::FeatureMismatch,
        required,
        "authored capability requirement mismatch",
    )
}

pub(super) fn node_failure(node: &NodeCapabilityRequirement, required: &str) -> AdmissionError {
    refuse(
        AdmissionStage::Nodes,
        AdmissionSubject::Node(node.node.clone()),
        AdmissionCode::FeatureMismatch,
        required,
        "actual selected node does not satisfy demand",
    )
}

/// Retains the exact authenticated authored selection and its original root bytes.
///
/// The graph seal constructs this inventory after installed semantic admission.
/// It grants neither execution nor a preservation codec. Archive implementations
/// must preserve these original objects and authenticate their source scope.
#[derive(Debug)]
pub struct AdmittedCapabilitySelection {
    pub(super) selection: CapabilitySelection,
    pub(super) requirements: CapabilityRequirements,
    pub(super) objects: std::collections::BTreeMap<crucible_node_contract::ContentRef, Vec<u8>>,
}

impl AdmittedCapabilitySelection {
    /// Borrows the complete identity-bearing wrapper and compatibility resolution.
    pub fn selection(&self) -> &CapabilitySelection {
        &self.selection
    }

    /// Borrows the exact mandatory authored predicates qualified by admission.
    pub fn requirements(&self) -> &CapabilityRequirements {
        &self.requirements
    }

    /// Enumerates original verified root, requirements and baseline scenario bytes.
    pub fn objects(
        &self,
    ) -> impl ExactSizeIterator<Item = (&crucible_node_contract::ContentRef, &[u8])> {
        self.objects
            .iter()
            .map(|(reference, bytes)| (reference, bytes.as_slice()))
    }
}
