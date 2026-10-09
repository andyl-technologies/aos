//! Authenticates actual locally enrolled resources against installed closed profiles.

use super::{NodeObservedError, measure_executable, refused};
use crate::node_scenario::NodeScenario;
use crucible::{
    node_adapters::{HostModel, HostModelQualification, ReferenceDeviceQualification},
    node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim},
    node_contract::{EffectKnowledge, OperationFailure},
};
use crucible_node_contract::{
    ContentRef, HashRef, Id, ImplementationIdentity, NodeBinding, NodeDescriptor, SchemaRef,
    canonical,
};
use crucible_node_provider::reference_device::{DeviceStatus, ReferenceDevice};
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf};

struct Enrollment {
    binding: NodeBinding,
    child_pid: Option<u32>,
    model_bytes: Option<Vec<u8>>,
}

pub(super) struct InstalledEvidence {
    world: HashRef,
    scenario_ref: ContentRef,
    requirements: HashRef,
    ownership: ContentRef,
    coordinator: ContentRef,
    descriptors: BTreeMap<Id, NodeDescriptor>,
    connections: BTreeMap<Id, (ContentRef, ContentRef)>,
    enrollments: BTreeMap<Id, Enrollment>,
    content: BTreeMap<String, (ContentRef, Vec<u8>)>,
    installed: BTreeMap<String, (ContentRef, PathBuf)>,
}

impl InstalledEvidence {
    pub(super) fn new(
        scenario: &NodeScenario,
        bindings: &[NodeBinding],
        devices: &BTreeMap<Id, ReferenceDevice>,
        models: &BTreeMap<Id, HostModel>,
        content: BTreeMap<String, (ContentRef, Vec<u8>)>,
        installed: BTreeMap<String, (ContentRef, PathBuf)>,
    ) -> Result<Self, NodeObservedError> {
        let mut enrollments = BTreeMap::new();
        for binding in bindings {
            let node = &binding.compatibility.node_id;
            let enrollment = match (devices.get(node), models.get(node)) {
                (Some(child), None)
                    if child.status() == DeviceStatus::Parked
                        && child.owner_id() == &binding.compatibility.execution_owner.id
                        && child.incarnation_id() == &binding.authority.incarnation_id
                        && child.generation() == binding.authority.owner_generation =>
                {
                    let actual = measure_executable(&PathBuf::from(format!(
                        "/proc/{}/exe",
                        child.child_pid()
                    )))?;
                    let expected = binding
                        .compatibility
                        .implementation
                        .artifacts
                        .iter()
                        .find(|artifact| artifact.role.as_str() == "device-executable")
                        .ok_or_else(|| refused("child profile omitted actual executable"))?;
                    if actual != expected.content {
                        return Err(refused(
                            "parked child executable differs from installed qualification",
                        ));
                    }
                    Enrollment {
                        binding: binding.clone(),
                        child_pid: Some(child.child_pid()),
                        model_bytes: None,
                    }
                }
                (None, Some(model)) => Enrollment {
                    binding: binding.clone(),
                    child_pid: None,
                    model_bytes: Some(
                        model
                            .initialization_bytes(4 * 1024 * 1024)
                            .map_err(|error| refused(&error.reason))?,
                    ),
                },
                _ => {
                    return Err(refused(
                        "node has no unique actually owned supported native resource",
                    ));
                }
            };
            if enrollments.insert(node.clone(), enrollment).is_some() {
                return Err(refused("native enrollment reused a logical node"));
            }
        }
        if devices.len() + models.len() != bindings.len() {
            return Err(refused("native resource inventory is incomplete"));
        }
        Ok(Self {
            world: scenario.world.identity()?,
            scenario_ref: scenario.world.scenario_ref.clone(),
            requirements: canonical::json_hash(
                "cnp.admission-requirements.v1",
                &scenario.requirements,
            )?,
            ownership: scenario.world.ownership_ref.clone(),
            coordinator: scenario.world.coordinator_contract_ref.clone(),
            descriptors: scenario
                .descriptors
                .iter()
                .map(|descriptor| (descriptor.id.clone(), descriptor.clone()))
                .collect(),
            connections: scenario
                .world
                .connections
                .iter()
                .map(|connection| {
                    let policy: crucible::node_admission::ConnectionPolicy =
                        serde_json::from_slice(&content[&connection.policy_ref.hash.digest].1)?;
                    Ok((
                        connection.id.clone(),
                        (connection.policy_ref.clone(), policy.causal_proof_ref),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?,
            enrollments,
            content,
            installed,
        })
    }

    fn enrollment(&self, node: &Id) -> Result<&Enrollment, EvidenceError> {
        self.enrollments
            .get(node)
            .ok_or_else(|| evidence("native node was not enrolled"))
    }

    fn check_world(&self, world: &HashRef) -> Result<(), EvidenceError> {
        if world != &self.world {
            return Err(evidence(
                "qualification scope names a foreign complete world",
            ));
        }
        Ok(())
    }
}

impl AdmissionEvidence for InstalledEvidence {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        if reference.length.get() > maximum_bytes as u64 {
            return Err(evidence(
                "immutable object exceeds supplied allocation ceiling",
            ));
        }
        if let Some((original, bytes)) = self.content.get(&reference.hash.digest) {
            if original != reference {
                return Err(evidence("content reference differs from installed object"));
            }
            return Ok(bytes.clone());
        }
        let (original, path) = self
            .installed
            .get(&reference.hash.digest)
            .ok_or_else(|| evidence("immutable object has no installed content source"))?;
        if original != reference {
            return Err(evidence(
                "executable reference differs from installed identity",
            ));
        }
        let file = File::open(path).map_err(|error| evidence(&error.to_string()))?;
        if file
            .metadata()
            .map_err(|error| evidence(&error.to_string()))?
            .len()
            != reference.length.get()
        {
            return Err(evidence(
                "installed executable changed before content fetch",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(reference.length.get() as usize)
            .map_err(|_| evidence("bounded artifact allocation is unavailable"))?;
        file.take(reference.length.get().saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| evidence(&error.to_string()))?;
        reference
            .verify(&bytes)
            .map_err(|error| evidence(&error.to_string()))?;
        Ok(bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if !self
            .enrollments
            .values()
            .any(|enrollment| &enrollment.binding.compatibility.implementation == implementation)
        {
            return Err(evidence(
                "implementation was not regenerated by installed catalog",
            ));
        }
        for artifact in &implementation.artifacts {
            let (original, path) = self
                .installed
                .get(&artifact.content.hash.digest)
                .ok_or_else(|| evidence("artifact is not an installed executable"))?;
            if original != &artifact.content
                || measure_executable(path).map_err(|error| evidence(&error.to_string()))?
                    != *original
            {
                return Err(evidence(
                    "actual installed executable differs from selected implementation",
                ));
            }
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        let enrollment = self.enrollment(&binding.compatibility.node_id)?;
        if &enrollment.binding != binding {
            return Err(evidence(
                "live authority differs from originally enrolled native resource",
            ));
        }
        if let Some(pid) = enrollment.child_pid {
            let expected = binding
                .compatibility
                .implementation
                .artifacts
                .iter()
                .find(|artifact| artifact.role.as_str() == "device-executable")
                .ok_or_else(|| evidence("child executable artifact missing"))?;
            if measure_executable(&PathBuf::from(format!("/proc/{pid}/exe")))
                .map_err(|error| evidence(&error.to_string()))?
                != expected.content
            {
                return Err(evidence("live enrolled child identity changed"));
            }
        }
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if schema.version != 1
            || !matches!(
                schema.id.as_str(),
                "reference-device/input-v1"
                    | "reference-device/output-v1"
                    | "reference-device/content-possession-v1"
                    | "crucible/octet-stream-v1"
                    | "host/native-continuation-v1"
            )
            || !self.enrollments.values().any(|enrollment| {
                enrollment
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(schema)
            })
        {
            return Err(evidence(
                "selected schema has no installed bounded checksum validator",
            ));
        }
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
                if scenario_ref != &self.scenario_ref || requirements_hash != &self.requirements {
                    return Err(evidence(
                        "scenario qualification differs from explicit installed weaker-contract acceptance",
                    ));
                }
            }
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                let selected = &self.enrollment(&binding.node_id)?.binding.compatibility;
                if binding != selected
                    || qualification_refs != selected.qualification_refs
                    || binding
                        .identity()
                        .map_err(|error| evidence(&error.to_string()))?
                        != *binding_hash
                {
                    return Err(evidence(
                        "node qualification differs from complete regenerated installed profile",
                    ));
                }
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => {
                let selected = &self.enrollment(node_id)?.binding.compatibility;
                let port = self
                    .descriptors
                    .get(node_id)
                    .and_then(|descriptor| descriptor.ports.iter().find(|port| &port.id == port_id))
                    .ok_or_else(|| evidence("port is not implemented by enrolled native model"))?;
                if selected
                    .identity()
                    .map_err(|error| evidence(&error.to_string()))?
                    != *binding_hash
                    || &port.configuration_ref != policy_ref
                {
                    return Err(evidence(
                        "port qualification differs from exact installed checksum lane semantics",
                    ));
                }
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                self.check_world(world_binding_hash)?;
                let policy: crucible::node_admission::OwnershipPolicy =
                    serde_json::from_slice(&self.content(ownership_ref, 4 * 1024 * 1024)?)
                        .map_err(|error| evidence(&error.to_string()))?;
                if ownership_ref != &self.ownership
                    || proof_ref != &policy.inventory_proof_ref
                    || !policy.internal_dependencies.is_empty()
                    || policy.objects.len() != self.enrollments.len() + self.connections.len()
                {
                    return Err(evidence(
                        "actual isolated-owner inventory differs from installed native closure",
                    ));
                }
                for enrollment in self.enrollments.values() {
                    self.authenticate_authority(&enrollment.binding)?;
                }
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                self.check_world(world_binding_hash)?;
                let selected = self
                    .enrollments
                    .values()
                    .find(|enrollment| {
                        &enrollment.binding.compatibility.capture_owner.id == capture_owner_id
                    })
                    .ok_or_else(|| evidence("capture policy names no actual enrolled owner"))?;
                if !selected
                    .binding
                    .compatibility
                    .qualification_refs
                    .contains(procedure_ref)
                {
                    return Err(evidence(
                        "capture policy differs from installed clock codec or explicit unsupported child state",
                    ));
                }
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if policy_ref != &self.coordinator {
                    return Err(evidence(
                        "coordinator policy differs from installed bounded runtime",
                    ));
                }
            }
            QualificationClaim::Connection {
                world_binding_hash,
                connection_id,
                proof_ref,
            } => {
                self.check_world(world_binding_hash)?;
                let (policy, proof) = self
                    .connections
                    .get(connection_id)
                    .ok_or_else(|| evidence("connection is not an installed public transfer"))?;
                if proof != proof_ref {
                    return Err(evidence(
                        "connection proof differs from original source-built transfer",
                    ));
                }
                self.content(policy, 4 * 1024 * 1024)?;
            }
            QualificationClaim::SameTimeClosure { .. } => {
                return Err(evidence(
                    "selected installed catalog has no qualified coupled transfer or cycle closure",
                ));
            }
        }
        Ok(())
    }
}

impl ReferenceDeviceQualification for InstalledEvidence {
    fn authenticate_child(
        &self,
        child: &ReferenceDevice,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.authenticate_authority(binding).map_err(no_effect)?;
        let enrollment = self.enrollment(&descriptor.id).map_err(no_effect)?;
        if self.descriptors.get(&descriptor.id) != Some(descriptor)
            || enrollment.child_pid != Some(child.child_pid())
            || child.status() != DeviceStatus::Parked
            || child.owner_id() != &binding.compatibility.execution_owner.id
            || child.incarnation_id() != &binding.authority.incarnation_id
            || child.generation() != binding.authority.owner_generation
        {
            return Err(no_effect(evidence(
                "actual child differs from originally sealed inactive native custody",
            )));
        }
        Ok(())
    }
}

impl HostModelQualification for InstalledEvidence {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.authenticate_authority(binding).map_err(no_effect)?;
        let enrollment = self.enrollment(&descriptor.id).map_err(no_effect)?;
        if self.descriptors.get(&descriptor.id) != Some(descriptor)
            || enrollment.model_bytes.as_ref()
                != Some(&model.initialization_bytes(4 * 1024 * 1024)?)
        {
            return Err(no_effect(evidence(
                "actual clock differs from complete enrolled model state",
            )));
        }
        Ok(())
    }
}

fn evidence(reason: &str) -> EvidenceError {
    EvidenceError {
        message: reason.to_owned(),
    }
}
fn no_effect(error: EvidenceError) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: error.message,
    }
}
