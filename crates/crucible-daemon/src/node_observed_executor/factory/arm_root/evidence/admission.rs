//! Authenticates claims only for the fixed independently enrolled Root world.

use crucible::node_adapters::arm_root::{
    ARM_ROOT_SERIAL_SCHEMA, ARM_ROOT_SERIAL_SPECIFICATION, arm_root_continuation_schema,
};
use crucible_node_contract::HashRef;

use super::*;

impl AdmissionEvidence for RootEvidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.immutable_content(reference, maximum)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if !self
            .bindings
            .values()
            .any(|binding| &binding.compatibility.implementation == implementation)
        {
            return Err(evidence(
                "Root implementation differs from the actual installed enrollment",
            ));
        }
        self.authenticate_scope()?;
        for artifact in &implementation.artifacts {
            let path = self.assets.get(&artifact.content).ok_or_else(|| {
                evidence("Root implementation lacks independently measured installed backing")
            })?;
            if measure_executable(path).map_err(observed_error)? != artifact.content {
                return Err(evidence(
                    "Root implementation asset changed after enrollment",
                ));
            }
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.authenticate_binding(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        let selected = self.bindings.values().any(|binding| {
            binding
                .compatibility
                .implementation
                .formats
                .contains(schema)
        });
        let root = arm_root_continuation_schema().map_err(|error| evidence(&error.reason))?;
        let clock = crucible::node_adapters::host_public_clock_continuation_schema()
            .map_err(|error| evidence(&error.reason))?;
        let clock_preparation = crucible::node_adapters::host_public_clock_preparation_schema()
            .map_err(|error| evidence(&error.reason))?;
        let serial = schema.id.as_str() == ARM_ROOT_SERIAL_SCHEMA
            && schema.version == 1
            && schema.extensions.is_empty()
            && schema.definition
                == canonical::content_ref(ARM_ROOT_SERIAL_SPECIFICATION.as_bytes(), "text/plain")
                    .map_err(contract_error)?
            && self
                .profile
                .scenario
                .descriptors
                .iter()
                .flat_map(|node| &node.ports)
                .flat_map(|port| &port.lanes)
                .any(|lane| &lane.payload_schema == schema);
        let legacy_clock = schema.id.as_str() == "host/native-continuation-v1"
            && schema.version == 1
            && schema.extensions.is_empty()
            && self
                .bindings
                .values()
                .filter(|binding| binding.compatibility.node_id.as_str() == "clock")
                .any(|binding| {
                    binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(schema)
                });
        if !serial
            && !legacy_clock
            && !(selected && (schema == &root || schema == &clock || schema == &clock_preparation))
        {
            return Err(evidence(
                "Root schema has no exact installed selected validator",
            ));
        }
        self.immutable_content(&schema.definition, 16 * 1024 * 1024)?;
        Ok(())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        match claim {
            QualificationClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } => {
                self.check_world(world_binding_hash)?;
                if scenario_ref != &self.profile.scenario.world.scenario_ref
                    || *requirements_hash
                        != canonical::json_hash(
                            "cnp.admission-requirements.v1",
                            &self.profile.scenario.requirements,
                        )
                        .map_err(contract_error)?
                {
                    return Err(evidence(
                        "Root scenario requirements differ from the fixed installed selection",
                    ));
                }
            }
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                let original = self
                    .bindings
                    .get(&binding.node_id)
                    .ok_or_else(|| evidence("Root node is not actually enrolled"))?;
                if binding != &original.compatibility
                    || qualification_refs != binding.qualification_refs
                    || *binding_hash != binding.identity().map_err(contract_error)?
                {
                    return Err(evidence(
                        "Root node claim differs from the complete installed compatibility",
                    ));
                }
                self.authenticate_binding(original)?;
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => {
                let original = self
                    .bindings
                    .get(node_id)
                    .ok_or_else(|| evidence("Root Serial owner is not enrolled"))?;
                let port = self
                    .profile
                    .scenario
                    .descriptors
                    .iter()
                    .find(|node| &node.id == node_id)
                    .and_then(|node| node.ports.iter().find(|port| &port.id == port_id))
                    .ok_or_else(|| evidence("Root selected Serial route is absent"))?;
                if node_id.as_str() != "root"
                    || port_id.as_str() != "serial"
                    || *binding_hash != original.compatibility.identity().map_err(contract_error)?
                    || policy_ref != &port.configuration_ref
                {
                    return Err(evidence(
                        "Root port claim differs from actual parent-zero typed Serial",
                    ));
                }
                self.authenticate_binding(original)?;
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if ownership_ref != &self.profile.scenario.world.ownership_ref
                    || proof_ref != &self.profile.qualification
                {
                    return Err(evidence(
                        "Root owner inventory differs from the fixed complete closure",
                    ));
                }
                let bytes = self.immutable_content(ownership_ref, 16 * 1024 * 1024)?;
                let policy: crucible::node_admission::OwnershipPolicy = serde_json::from_value(
                    canonical::parse_json(&bytes, 16 * 1024 * 1024).map_err(contract_error)?,
                )
                .map_err(|error| evidence(&error.to_string()))?;
                if policy.objects.len() != 2
                    || policy.domains.len() != 2
                    || policy.capture_owners.len() != 2
                    || !policy.internal_dependencies.is_empty()
                    || policy.inventory_proof_ref != self.profile.qualification
                {
                    return Err(evidence(
                        "Root inventory does not describe exactly the owned Clock and native Root",
                    ));
                }
                for binding in self.bindings.values() {
                    self.authenticate_binding(binding)?;
                }
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if procedure_ref != &self.profile.qualification
                    || !self
                        .bindings
                        .values()
                        .any(|binding| &binding.compatibility.capture_owner.id == capture_owner_id)
                {
                    return Err(evidence(
                        "Root capture claim names another complete owner or procedure",
                    ));
                }
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if policy_ref != &self.profile.scenario.world.coordinator_contract_ref {
                    return Err(evidence(
                        "Root coordinator differs from the installed unchanged-cut policy",
                    ));
                }
            }
            QualificationClaim::Connection { .. } | QualificationClaim::SameTimeClosure { .. } => {
                return Err(evidence(
                    "Fixed Root world declares no connections or same-time cycles",
                ));
            }
        }
        self.authenticate_scope()
    }
}

impl RootEvidence {
    fn check_world(&self, world: &HashRef) -> Result<(), EvidenceError> {
        if &self
            .profile
            .scenario
            .world
            .identity()
            .map_err(contract_error)?
            != world
        {
            return Err(evidence(
                "Root claim names another independently selected world",
            ));
        }
        Ok(())
    }
}
