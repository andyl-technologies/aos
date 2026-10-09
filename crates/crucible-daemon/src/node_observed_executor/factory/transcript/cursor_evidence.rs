//! Admission against original-source-owning allocated replay cursors.
//!
//! This private installed adapter accepts the regenerated closed reference pair,
//! its original transfer semantics and the exact allocated fresh roster. Public
//! receipts cannot enroll additional cursors or change source applicability.

use crucible::node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim};
use crucible_node_contract::{ImplementationIdentity, NodeBinding, SchemaRef};

use super::*;

fn failure(message: impl ToString) -> EvidenceError {
    EvidenceError {
        message: message.to_string(),
    }
}

impl AdmissionEvidence for cursor_allocation::CursorAllocation {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.check_thread().map_err(failure)?;
        if reference.length.get() > maximum_bytes as u64 {
            return Err(failure(
                "replay immutable object exceeds admission reservation",
            ));
        }
        if let Some(path) = self.installed_asset(reference) {
            let mut file = File::open(path).map_err(failure)?;
            if file.metadata().map_err(failure)?.len() != reference.length.get() {
                return Err(failure("installed replay host extent changed"));
            }
            let length = usize::try_from(reference.length.get()).map_err(failure)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(failure)?;
            bytes.resize(length, 0);
            file.read_exact(&mut bytes).map_err(failure)?;
            let mut trailing = [0u8; 1];
            if file.read(&mut trailing).map_err(failure)? != 0 {
                return Err(failure("installed replay host exceeds its original extent"));
            }
            reference.verify(&bytes).map_err(failure)?;
            return Ok(bytes);
        }
        let object = self
            .profile()
            .scenario
            .content
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| failure("object is not in the original allocated replay context"))?;
        reference.verify(&object.bytes).map_err(failure)?;
        Ok(object.bytes.clone())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.check_scope().map_err(failure)?;
        if !self
            .profile()
            .bindings
            .iter()
            .any(|binding| &binding.compatibility.implementation == implementation)
            || implementation.implementation_id.as_str()
                != "crucible/transcript-reference-linked-v1"
            || implementation.artifacts.len() != 1
            || implementation.artifacts[0].content != *self.host_identity()
            || implementation.artifacts[0].role.as_str() != "replay-host"
        {
            return Err(failure(
                "implementation differs from installed original-source replay code",
            ));
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.check_thread().map_err(failure)?;
        let source = self
            .source_for(&binding.compatibility.node_id)
            .ok_or_else(|| failure("binding has no originally allocated source cursor"))?;
        if self
            .profile()
            .bindings
            .iter()
            .find(|original| original.compatibility.node_id == binding.compatibility.node_id)
            != Some(binding)
            || source.transcript().origin.route.node != binding.compatibility.node_id
            || !self
                .profile()
                .enrolled
                .get(&binding.compatibility.node_id)
                .is_some_and(|original| original.reference == binding.authority.host_receipt)
        {
            return Err(failure(
                "authority differs from original source-owning fresh cursor allocation",
            ));
        }
        self.content(&binding.authority.host_receipt, 1024 * 1024)?;
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.check_thread().map_err(failure)?;
        if schema
            == &crucible::node_adapters::transcript::transcript_replay_continuation_schema()
                .map_err(|error| failure(error.reason))?
            && self.profile().bindings.iter().all(|binding| {
                binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(schema)
            })
        {
            return Ok(());
        }
        if schema.version != 1
            || !matches!(
                schema.id.as_str(),
                "reference-device/input-v1"
                    | "reference-device/output-v1"
                    | "reference-device/content-possession-v1"
                    | "crucible/octet-stream-v1"
            )
            || !self.source().source_bindings.values().any(|binding| {
                binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(schema)
            })
        {
            return Err(failure(
                "replay schema has no installed original bounded codec",
            ));
        }
        Ok(())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.check_thread().map_err(failure)?;
        let scenario = &self.profile().scenario;
        let world = scenario.world.identity().map_err(failure)?;
        let ownership: crucible::node_admission::OwnershipPolicy =
            serde_json::from_slice(&self.content(&scenario.world.ownership_ref, 4 * 1024 * 1024)?)
                .map_err(failure)?;
        let accepted = match claim {
            QualificationClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } => {
                *world_binding_hash == world
                    && scenario_ref == &scenario.world.scenario_ref
                    && *requirements_hash
                        == canonical::json_hash(
                            "cnp.admission-requirements.v1",
                            &scenario.requirements,
                        )
                        .map_err(failure)?
            }
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                self.profile().bindings.iter().any(|original| {
                    &original.compatibility == binding
                        && qualification_refs == original.compatibility.qualification_refs
                }) && binding.identity().map_err(failure)? == *binding_hash
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => {
                let binding = self
                    .profile()
                    .bindings
                    .iter()
                    .find(|binding| &binding.compatibility.node_id == node_id);
                let port = scenario
                    .descriptors
                    .iter()
                    .find(|node| &node.id == node_id)
                    .and_then(|node| node.ports.iter().find(|port| &port.id == port_id));
                binding.is_some_and(|binding| {
                    binding.compatibility.identity().ok().as_ref() == Some(binding_hash)
                }) && port.is_some_and(|port| &port.configuration_ref == policy_ref)
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                *world_binding_hash == world
                    && ownership_ref == &scenario.world.ownership_ref
                    && proof_ref == &ownership.inventory_proof_ref
                    && ownership.internal_dependencies.is_empty()
                    && ownership.objects.len()
                        == self.source().sources.len() + scenario.world.connections.len()
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                *world_binding_hash == world
                    && ownership.capture_owners.iter().any(|owner| {
                        &owner.owner_id == capture_owner_id
                            && &owner.cut_procedure_ref == procedure_ref
                            && !owner.isolated_fork
                    })
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                *world_binding_hash == world
                    && policy_ref == &scenario.world.coordinator_contract_ref
            }
            QualificationClaim::Connection {
                world_binding_hash,
                connection_id,
                proof_ref,
            } => {
                if *world_binding_hash != world {
                    false
                } else {
                    let connection = scenario
                        .world
                        .connections
                        .iter()
                        .find(|connection| &connection.id == connection_id)
                        .ok_or_else(|| {
                            failure("replay transfer not in complete original topology")
                        })?;
                    let policy: crucible::node_admission::ConnectionPolicy =
                        serde_json::from_slice(&self.content(&connection.policy_ref, 1024 * 1024)?)
                            .map_err(failure)?;
                    &policy.causal_proof_ref == proof_ref
                }
            }
            QualificationClaim::SameTimeClosure { .. } => false,
        };
        if !accepted {
            return Err(failure(
                "claim differs from complete accepted source and allocated replay profile",
            ));
        }
        Ok(())
    }
}
