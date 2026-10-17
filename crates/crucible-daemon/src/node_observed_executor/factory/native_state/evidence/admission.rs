//! Scope-specific graph claims for actual enrolled mixed resources.

use crucible::node_adapters::gem5::gem5_native_continuation_schema;
use crucible_node_provider::reference_service::profile::{
    NATIVE_OCTET_SCHEMA_ID, NATIVE_OCTET_SPECIFICATION,
};

use super::*;

impl AdmissionEvidence for MixedEvidence {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.immutable_content(reference, maximum_bytes)
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
                "mixed implementation is not the source-built regenerated selection",
            ));
        }
        self.authenticate_enrolled_scope()?;
        for artifact in &implementation.artifacts {
            let (original, path) =
                self.assets
                    .get(&artifact.content.hash.digest)
                    .ok_or_else(|| {
                        evidence("mixed artifact is outside independently installed scope")
                    })?;
            if original != &artifact.content
                || measure_executable(path).map_err(observed_evidence)? != *original
            {
                return Err(evidence("actual mixed installed artifact changed"));
            }
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        if self.bindings.get(&binding.compatibility.node_id) != Some(binding)
            || binding.authority.host_receipt != self.receipt.reference
        {
            return Err(evidence(
                "mixed authority is not the original locally enrolled live resource or owned lease",
            ));
        }
        self.receipt
            .reference
            .verify(&self.receipt.bytes)
            .map_err(contract_evidence)?;
        self.authenticate_enrolled_scope()
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        let native = gem5_native_continuation_schema().map_err(|error| evidence(&error.reason))?;
        let public_native = crucible::node_adapters::gem5::gem5_public_preparation_schema()
            .map_err(|error| evidence(&error.reason))?;
        let public_clock = crucible::node_adapters::host_public_clock_preparation_schema()
            .map_err(|error| evidence(&error.reason))?;
        let public_native_continuation =
            crucible::node_adapters::gem5::gem5_public_continuation_schema()
                .map_err(|error| evidence(&error.reason))?;
        let public_clock_continuation =
            crucible::node_adapters::host_public_clock_continuation_schema()
                .map_err(|error| evidence(&error.reason))?;
        let epoch_native = crucible::node_adapters::gem5::gem5_public_epoch_continuation_schema()
            .map_err(|error| evidence(&error.reason))?;
        let epoch_clock = crucible::node_adapters::host_public_clock_epoch_continuation_schema()
            .map_err(|error| evidence(&error.reason))?;
        let selected = self.bindings.values().any(|binding| {
            binding
                .compatibility
                .implementation
                .formats
                .contains(schema)
        });
        let supported = if schema == &native
            || (selected
                && (schema == &public_native
                    || schema == &public_clock
                    || schema == &public_native_continuation
                    || schema == &epoch_native
                    || schema == &epoch_clock
                    || schema == &public_clock_continuation))
        {
            true
        } else if schema.id.as_str() == NATIVE_OCTET_SCHEMA_ID
            && schema.version == 1
            && schema.extensions.is_empty()
        {
            schema.definition
                == canonical::content_ref(NATIVE_OCTET_SPECIFICATION.as_bytes(), "text/plain")
                    .map_err(contract_evidence)?
                && self
                    .scenario
                    .descriptors
                    .iter()
                    .flat_map(|node| &node.ports)
                    .flat_map(|port| &port.lanes)
                    .any(|lane| &lane.payload_schema == schema)
        } else {
            schema.id.as_str() == "host/native-continuation-v1"
                && schema.version == 1
                && self
                    .bindings
                    .values()
                    .filter(|binding| {
                        binding.compatibility.node_id.as_str() == "clock"
                            || self
                                .host_clocks
                                .contains_key(&binding.compatibility.node_id)
                    })
                    .any(|binding| {
                        binding
                            .compatibility
                            .implementation
                            .formats
                            .contains(schema)
                    })
        };
        if !supported {
            return Err(evidence(
                "mixed schema has no installed bounded native validator",
            ));
        }
        self.immutable_content(&schema.definition, MAXIMUM_CONTENT_BYTES)?;
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
                if scenario_ref != &self.scenario.world.scenario_ref
                    || canonical::json_hash(
                        "cnp.admission-requirements.v1",
                        &self.scenario.requirements,
                    )
                    .map_err(contract_evidence)?
                        != *requirements_hash
                {
                    return Err(evidence(
                        "mixed scenario differs from exact source-built requirements",
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
                    .ok_or_else(|| evidence("mixed node is not actually enrolled"))?;
                if binding != &original.compatibility
                    || qualification_refs != binding.qualification_refs
                    || binding.identity().map_err(contract_evidence)? != *binding_hash
                {
                    return Err(evidence(
                        "mixed node qualification differs from actual full installed selection",
                    ));
                }
                self.authenticate_authority(original)?;
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
                    .ok_or_else(|| evidence("mixed port owner is not enrolled"))?;
                let port = self
                    .scenario
                    .descriptors
                    .iter()
                    .find(|descriptor| &descriptor.id == node_id)
                    .and_then(|descriptor| descriptor.ports.iter().find(|port| &port.id == port_id))
                    .ok_or_else(|| {
                        evidence("mixed port is not the actual installed stdout route")
                    })?;
                if node_id.as_str() != "cpu"
                    || port_id.as_str() != "stdout"
                    || original
                        .compatibility
                        .identity()
                        .map_err(contract_evidence)?
                        != *binding_hash
                    || &port.configuration_ref != policy_ref
                {
                    return Err(evidence(
                        "mixed port policy differs from installed original syscall publication semantics",
                    ));
                }
                self.authenticate_authority(original)?;
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if ownership_ref != &self.scenario.world.ownership_ref
                    || proof_ref != &self.qualification
                {
                    return Err(evidence(
                        "mixed inventory differs from actual complete source-built owner closure",
                    ));
                }
                let bytes = self.immutable_content(ownership_ref, MAXIMUM_CONTENT_BYTES)?;
                let policy: crucible::node_admission::OwnershipPolicy = serde_json::from_value(
                    canonical::parse_json(&bytes, MAXIMUM_CONTENT_BYTES)
                        .map_err(contract_evidence)?,
                )
                .map_err(|error| evidence(&error.to_string()))?;
                if policy.objects.len() != self.bindings.len()
                    || policy.domains.len() != self.bindings.len()
                    || policy.capture_owners.len() != self.bindings.len()
                    || !policy.internal_dependencies.is_empty()
                    || policy.inventory_proof_ref != self.qualification
                {
                    return Err(evidence(
                        "mixed complete inventory is not the actual isolated clock/native closure",
                    ));
                }
                for binding in self.bindings.values() {
                    self.authenticate_authority(binding)?;
                }
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if procedure_ref != &self.qualification
                    || !self
                        .bindings
                        .values()
                        .any(|binding| &binding.compatibility.capture_owner.id == capture_owner_id)
                {
                    return Err(evidence(
                        "mixed capture procedure names another actual native owner or bridge",
                    ));
                }
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if policy_ref != &self.scenario.world.coordinator_contract_ref {
                    return Err(evidence(
                        "mixed coordinator policy differs from actual installed complete world closure",
                    ));
                }
            }
            QualificationClaim::Connection { .. } | QualificationClaim::SameTimeClosure { .. } => {
                return Err(evidence(
                    "fixed mixed native installation has no connections or declared same-time closure cycles",
                ));
            }
        }
        Ok(())
    }
}

fn observed_evidence(error: NodeObservedError) -> EvidenceError {
    evidence(&error.to_string())
}
