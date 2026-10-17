//! Reauthenticates fixed source-world and each native collecting request.

use super::{InstalledTypedReaderSourceFixture, invalid, launch};
use crucible::{
    node_admission::{AdmissionRequest, QualificationClaim},
    node_contract::OperationRequest,
    node_scheduling::RuntimeInputBatch,
};
use crucible_node_contract::{
    ContentRef, Id, ImplementationIdentity, NodeBinding, SchemaRef, canonical,
};
use crucible_node_provider::ProviderError;

impl InstalledTypedReaderSourceFixture {
    /// Regenerates the complete fixed source/harness/programme prerequisite roster.
    ///
    /// The finite roster contains public identities only; private launch tokens
    /// and receipt capabilities have no projection. It grants no native authority.
    ///
    /// # Errors
    /// Refuses changed current unit, unsupported references or canonical source drift.
    pub fn collection_source_references(&self) -> Result<Vec<ContentRef>, ProviderError> {
        let unit = Self::qualification_unit(&self.package, &self.programme, &self.resources)?;
        if unit != self.plan.unit {
            return Err(invalid());
        }
        let mut sources = vec![
            self.package.identity().clone(),
            self.programme.reference().clone(),
            unit.implementation,
            unit.realization,
            unit.descriptors,
            unit.contracts,
            unit.port_profiles,
            unit.environment,
            unit.harness,
            unit.fixtures,
            unit.specification,
            self.package
                .definition()
                .declaration()
                .owner
                .publication_origin
                .clone(),
            self.package.definition().handler().clone(),
        ];
        sources.sort();
        sources.dedup();
        Ok(sources)
    }

    /// Checks the complete original durable Node scope solely for collection.
    ///
    /// # Errors
    /// Refuses changed original binding/qualification candidates or native custody.
    pub fn authenticate_collection_node(
        &self,
        claim: QualificationClaim<'_>,
    ) -> Result<(), ProviderError> {
        let QualificationClaim::Node {
            binding,
            binding_hash,
            qualification_refs,
        } = claim
        else {
            return Err(invalid());
        };
        let source = self.source(&binding.node_id)?;
        if binding != &source.binding
            || binding.identity()? != *binding_hash
            || qualification_refs != source.launch.qualification_refs
        {
            return Err(invalid());
        }
        self.current(&binding.node_id)
    }

    /// Authenticates all actual original bindings and owners of the fixed collecting world.
    ///
    /// This read-only callback supplies no Node behavioral qualification. Every
    /// group must still have its exact original enrolled kernel tuple.
    ///
    /// # Errors
    /// Refuses changed complete world, requirements, descriptor, original live
    /// authority/owner, omitted participant or dead/replaced native group.
    pub fn authenticate_collection_world(
        &self,
        request: AdmissionRequest<'_>,
    ) -> Result<(), ProviderError> {
        if request.world != &self.definition.world
            || request.descriptors != self.definition.descriptors
            || launch::encode(request.requirements, 1024 * 1024)?
                != launch::encode(&self.definition.requirements, 1024 * 1024)?
            || request.bindings.len() != 3
            || request.owners.len() != 3
        {
            return Err(invalid());
        }
        let mut expected_bindings = Vec::new();
        let mut expected_owners = Vec::new();
        expected_bindings
            .try_reserve_exact(3)
            .map_err(|_| invalid())?;
        expected_owners
            .try_reserve_exact(3)
            .map_err(|_| invalid())?;
        for source in &self.sources {
            self.current(&source.profile.descriptor.id)?;
            let (binding, owner) = source.profile.bind_qualified(
                source.launch.bootstrap.authority.clone(),
                &source.launch.qualification_refs,
            )?;
            expected_bindings.push(binding);
            expected_owners.push(owner);
        }
        expected_bindings.sort_by(|a, b| a.compatibility.node_id.cmp(&b.compatibility.node_id));
        expected_owners.sort_by(|a, b| a.owner.id.cmp(&b.owner.id));
        if request.bindings != expected_bindings || request.owners != expected_owners {
            return Err(invalid());
        }
        Ok(())
    }

    /// Authenticates an exact predeclared request before native collection Begin.
    ///
    /// # Errors
    /// Refuses substituted request/window, operation ID, node or current original group.
    pub fn authenticate_collection_operation(
        &self,
        node: &Id,
        operation: &Id,
        request: &OperationRequest,
    ) -> Result<(), ProviderError> {
        self.current(node)?;
        if !self.programme.windows().iter().any(|planned| {
            &planned.node == node && &planned.operation == operation && &planned.request == request
        }) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Checks the original scheduler batch against the fixed pre-Child programme.
    ///
    /// Full producer claims/provenance and actual native Stage ACK remain separate
    /// mandatory callbacks; this check cannot synthesize either source handle.
    ///
    /// # Errors
    /// Refuses changed stage/batch/input roster/cut/world/owner or missing current groups.
    pub fn authenticate_collection_inputs(
        &self,
        batch: &RuntimeInputBatch,
    ) -> Result<(), ProviderError> {
        for source in &self.sources {
            self.current(&source.profile.descriptor.id)?;
        }
        let planned = self
            .programme
            .windows()
            .iter()
            .find(|planned| &planned.stage == batch.stage_operation())
            .ok_or_else(invalid)?;
        if &planned.node != batch.node()
            || &planned.batch != batch.batch()
            || batch.activation().record().world_binding_hash != self.world
            || batch.activation().record().generation.get() != 1
            || batch
                .deliveries()
                .iter()
                .map(|delivery| &delivery.producer)
                .ne(planned.producers.iter())
            || batch
                .payloads()
                .iter()
                .any(|payload| payload.bytes.as_slice() != super::super::programme::PRODUCER_BYTES)
            || batch.cutoff()
                != crucible_node_contract::Position::new(
                    crucible_node_contract::U64::new(
                        planned
                            .quantum
                            .get()
                            .checked_mul(1000)
                            .and_then(|n| n.checked_add(1))
                            .ok_or_else(invalid)?,
                    ),
                    crucible_node_contract::U64::new(0),
                    crucible_node_contract::Phase::BoundaryControl,
                )
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Authenticates the exact original live binding beneath surviving kernel custody.
    ///
    /// # Errors
    /// Refuses foreign durable/live authority or a changed original native enrollment.
    pub fn authenticate_binding(&self, binding: &NodeBinding) -> Result<(), ProviderError> {
        let source = self.source(&binding.compatibility.node_id)?;
        self.current(&binding.compatibility.node_id)?;
        let (expected, _) = source.profile.bind_qualified(
            source.launch.bootstrap.authority.clone(),
            &source.launch.qualification_refs,
        )?;
        if binding != &expected {
            return Err(invalid());
        }
        Ok(())
    }

    /// Authenticates an independently measured installed source implementation.
    ///
    /// # Errors
    /// Refuses any uninstalled source/adapter/native implementation or changed kernel enrollment.
    pub fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), ProviderError> {
        let source = self
            .sources
            .iter()
            .find(|source| &source.profile.implementation == implementation)
            .ok_or_else(invalid)?;
        self.current(&source.profile.descriptor.id)
    }

    /// Authenticates schema support in the exact measured installed reader format roster.
    ///
    /// # Errors
    /// Refuses unknown or widened formats; content identity alone cannot add a schema.
    pub fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), ProviderError> {
        if !self
            .sources
            .iter()
            .any(|source| source.profile.implementation.formats.contains(schema))
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Reads only an original source-selected public body under pre-allocation credit.
    ///
    /// Private launch encodings and admission capabilities have no lookup path.
    ///
    /// # Errors
    /// Refuses unavailable objects, excessive extent or corrupt exact source bytes.
    pub fn public_content(
        &self,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        if usize::try_from(reference.length.get()).map_err(|_| invalid())? > maximum {
            return Err(invalid());
        }
        if let Some(bytes) = self.definition.content.get(reference) {
            reference.verify(bytes)?;
            return Ok(bytes.clone());
        }
        for source in &self.sources {
            if let Some(object) = source
                .launch
                .bootstrap
                .installed_content
                .iter()
                .find(|object| &object.reference == reference)
            {
                reference.verify(object.bytes.as_slice())?;
                return Ok(object.bytes.as_slice().to_vec());
            }
        }
        for role in ["provider", "device"] {
            if self.package.artifact_content(role).map_err(|_| invalid())? == reference {
                let path = self.package.executable(role).map_err(|_| invalid())?;
                let bytes =
                    super::super::package::read_bounded(path, maximum).map_err(|_| invalid())?;
                reference.verify(&bytes)?;
                return Ok(bytes);
            }
        }
        Err(invalid())
    }

    /// Verifies only fixed structural/semantic claims; ordinary Node always refuses.
    ///
    /// # Errors
    /// Refuses unsupported/native-class/preservation claims, changed original
    /// source-world scope or any attempt to use a collection audit as acceptance.
    pub fn authenticate_structural_claim(
        &self,
        claim: QualificationClaim<'_>,
    ) -> Result<(), ProviderError> {
        let world = &self.world;
        let proof = self.programme.reference();
        let valid =
            match claim {
                QualificationClaim::Scenario {
                    world_binding_hash,
                    scenario_ref,
                    requirements_hash,
                } => {
                    world_binding_hash == world
                        && scenario_ref == &self.definition.world.scenario_ref
                        && requirements_hash
                            == &canonical::json_hash(
                                "cnp.admission-requirements.v1",
                                &self.definition.requirements,
                            )?
                }
                QualificationClaim::Port {
                    node_id,
                    binding_hash,
                    port_id,
                    policy_ref,
                } => self.sources.iter().any(|source| {
                    &source.profile.descriptor.id == node_id
                        && source.binding.identity().as_ref().ok() == Some(binding_hash)
                        && source.profile.descriptor.ports.iter().any(|port| {
                            &port.id == port_id && &port.configuration_ref == policy_ref
                        })
                }),
                QualificationClaim::CompleteInventory {
                    world_binding_hash,
                    ownership_ref,
                    proof_ref,
                } => {
                    world_binding_hash == world
                        && ownership_ref == &self.definition.world.ownership_ref
                        && proof_ref == proof
                }
                QualificationClaim::Connection {
                    world_binding_hash,
                    connection_id,
                    proof_ref,
                } => {
                    world_binding_hash == world
                        && proof_ref == proof
                        && self
                            .definition
                            .world
                            .connections
                            .iter()
                            .any(|connection| &connection.id == connection_id)
                }
                QualificationClaim::Coordinator {
                    world_binding_hash,
                    policy_ref,
                } => world_binding_hash == world && policy_ref == proof,
                QualificationClaim::Capture {
                    world_binding_hash,
                    capture_owner_id,
                    procedure_ref,
                } => {
                    // This authenticates the exact no-preservation limitation;
                    // it cannot qualify any capture/reconstruction guarantee.
                    world_binding_hash == world
                        && procedure_ref == proof
                        && self
                            .definition
                            .ownership
                            .capture_owners
                            .iter()
                            .any(|policy| {
                                &policy.owner_id == capture_owner_id
                                    && &policy.cut_procedure_ref == procedure_ref
                                    && !policy.complete_model
                                    && !policy.unchanged_cut
                                    && !policy.exact_continuation
                                    && !policy.durable_restart
                                    && !policy.isolated_fork
                                    && policy.dependencies.is_empty()
                            })
                }
                // No same-time, ordinary Node or accepted class authority.
                _ => false,
            };
        if !valid {
            return Err(invalid());
        }
        for source in &self.sources {
            self.current(&source.profile.descriptor.id)?;
        }
        Ok(())
    }
}
