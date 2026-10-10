//! Admits the exact private conditional model installation before any replay.
//!
//! This fixture procedure authenticates the measured host and inspected original
//! triple. It is intentionally separate from ordinary catalog qualification and
//! accepts no native reader extension as target execution authority.

use super::conditional_source::InspectionError;

use crucible::node_admission::*;
use crucible_node_contract::*;

use super::conditional_profile::ConditionalProfile;

pub(super) fn admit(profile: &ConditionalProfile) -> Result<AdmittedGraph, InspectionError> {
    if profile.bindings.len() != 3
        || profile.bindings.iter().any(|binding| {
            binding.compatibility.implementation.artifacts.len() != 1
                || binding.compatibility.implementation.artifacts[0].content != profile.host
        })
    {
        return Err("conditional immutable fetch occurrence roster differs".into());
    }
    // Admission charges each node's artifact read, even when the complete
    // ContentRef is shared. Reserve all three actual measured ELF occurrences
    // before construction; the archive's unique-object credit stays separate.
    let host_bytes =
        usize::try_from(profile.host.length.get()).map_err(|error| error.to_string())?;
    let total_fetch_bytes = host_bytes
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
        .ok_or("conditional immutable fetch credit overflow")?;
    admit_graph(
        AdmissionRequest {
            world: &profile.world,
            descriptors: &profile.descriptors,
            bindings: &profile.bindings,
            owners: &profile.owners,
            requirements: &profile.requirements,
        },
        &Evidence { profile },
        AdmissionLimits {
            maximum_nodes: 3,
            maximum_owners: 3,
            maximum_connections: 2,
            // The source-built test host is independently measured before this
            // admission. Its ELF credit is separate from the 64 MiB tape/body
            // inventory and is never a native payload or transport allowance.
            maximum_content_bytes: 256 * 1024 * 1024,
            maximum_total_content_bytes: total_fetch_bytes,
            ..AdmissionLimits::default()
        },
    )
    .map_err(InspectionError::from_error)
}

struct Evidence<'a> {
    profile: &'a ConditionalProfile,
}

fn refused() -> EvidenceError {
    EvidenceError {
        message: "conditional fixture installation scope differs or is unsupported".into(),
    }
}

impl AdmissionEvidence for Evidence<'_> {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        if reference.length.get() > maximum as u64 {
            return Err(refused());
        }
        if reference == &self.profile.host {
            use std::io::Read;

            // This kernel-provided self executable is the installed fixture
            // identity, never a portable path accepted from tape metadata.
            let file = std::fs::File::open("/proc/self/exe").map_err(|_| refused())?;
            if file.metadata().map_err(|_| refused())?.len() != reference.length.get() {
                return Err(refused());
            }
            let length = usize::try_from(reference.length.get()).map_err(|_| refused())?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length.checked_add(1).ok_or_else(refused)?)
                .map_err(|_| refused())?;
            file.take(reference.length.get() + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refused())?;
            reference.verify(&bytes).map_err(|_| refused())?;
            return Ok(bytes);
        }
        let bytes = self.profile.content.get(reference).ok_or_else(refused)?;
        reference.verify(bytes).map_err(|_| refused())?;
        Ok(bytes.clone())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        let actual = crucible_node_provider::conformance::measure_executable(std::path::Path::new(
            "/proc/self/exe",
        ))
        .map_err(|_| refused())?;
        if actual != self.profile.host
            || !self
                .profile
                .bindings
                .iter()
                .any(|binding| &binding.compatibility.implementation == implementation)
            || implementation.artifacts.len() != 1
            || implementation.artifacts[0].content != actual
        {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        if !self.profile.bindings.contains(binding)
            || binding.compatibility.execution_owner != binding.compatibility.capture_owner
            || binding
                .compatibility
                .execution_owner
                .participant_ids
                .as_slice()
                != std::slice::from_ref(&binding.compatibility.node_id)
        {
            return Err(refused());
        }
        let receipt = self
            .profile
            .content
            .get(&binding.authority.host_receipt)
            .ok_or_else(refused)?;
        binding
            .authority
            .host_receipt
            .verify(receipt)
            .map_err(|_| refused())?;
        self.authenticate_implementation(&binding.compatibility.implementation)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if self.profile.bindings.iter().all(|binding| {
            !binding
                .compatibility
                .implementation
                .formats
                .contains(schema)
        }) || !self.profile.content.contains_key(&schema.definition)
        {
            return Err(refused());
        }
        Ok(())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        let world = self.profile.world.identity().map_err(|_| refused())?;
        let installation = &self.profile.installation;
        let accepted = match claim {
            QualificationClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } => {
                world_binding_hash == &world
                    && scenario_ref == &self.profile.world.scenario_ref
                    && requirements_hash
                        == &canonical::json_hash(
                            "cnp.admission-requirements.v1",
                            &self.profile.requirements,
                        )
                        .map_err(|_| refused())?
            }
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                self.profile
                    .bindings
                    .iter()
                    .any(|actual| &actual.compatibility == binding)
                    && binding.identity().as_ref().ok() == Some(binding_hash)
                    && qualification_refs == std::slice::from_ref(installation)
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => {
                self.profile.bindings.iter().any(|binding| {
                    &binding.compatibility.node_id == node_id
                        && binding.identity().as_ref().ok() == Some(binding_hash)
                }) && self
                    .profile
                    .descriptors
                    .iter()
                    .find(|descriptor| &descriptor.id == node_id)
                    .is_some_and(|descriptor| {
                        descriptor.ports.iter().any(|port| {
                            &port.id == port_id && &port.configuration_ref == policy_ref
                        })
                    })
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                world_binding_hash == &world
                    && ownership_ref == &self.profile.world.ownership_ref
                    && proof_ref == installation
            }
            QualificationClaim::Connection {
                world_binding_hash,
                connection_id,
                proof_ref,
            } => {
                world_binding_hash == &world
                    && self.profile.world.connections.iter().any(|connection| {
                        if &connection.id != connection_id {
                            return false;
                        }
                        let Some(bytes) = self.profile.content.get(&connection.policy_ref) else {
                            return false;
                        };
                        let Ok(policy) = serde_json::from_slice::<ConnectionPolicy>(bytes) else {
                            return false;
                        };
                        connection.policy_ref.verify(bytes).is_ok()
                            && &policy.causal_proof_ref == proof_ref
                            && self.profile.history.objects.get(proof_ref)
                                == self.profile.content.get(proof_ref)
                            && self.profile.history.objects.contains_key(proof_ref)
                    })
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                world_binding_hash == &world
                    && self
                        .profile
                        .owners
                        .iter()
                        .any(|owner| &owner.owner.id == capture_owner_id)
                    && procedure_ref == installation
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                world_binding_hash == &world
                    && policy_ref == &self.profile.world.coordinator_contract_ref
            }
            QualificationClaim::SameTimeClosure { .. } => false,
        };
        if accepted { Ok(()) } else { Err(refused()) }
    }
}
