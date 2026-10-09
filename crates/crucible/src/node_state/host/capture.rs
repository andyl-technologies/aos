//! Live unchanged-cut capture issuance and authenticated source admission.

use std::collections::BTreeMap;

use crucible_node_contract::{
    CaptureManifest, CaptureRepresentation, CapturedOwner, ContentRef, HashRef, Id, Position,
    Repeatability, U64, canonical,
};
use serde::{Deserialize, Serialize};

use crate::node_adapters::{HOST_EXACT_PROFILE, HostModelResources, validate_host_continuation};
use crate::node_admission::AdmittedGraph;
use crate::node_contract::{NodeRuntime, RuntimeSnapshot, WorldActivation};
use crate::node_scheduling::SchedulingSnapshot;

use super::super::closure::{bounded_record, core_references, limit, verify_closure};
use super::super::validation::required_immutable_refs;
use super::super::{
    CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateError,
    StateLimits, StateRequirements, StateRestoreMode, VerifiedCapture, VerifiedStateContent,
    admit_capture, schema,
};
use super::archive::{ArchiveBody, Object, refusal};
use super::{
    HostArchive, HostArchiveRecord, HostWorldFactory, native_failure, require_supported_extensions,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Coordinator {
    pub schema_version: u32,
    pub scheduler: SchedulingSnapshot,
    pub runtime: RuntimeSnapshot,
    pub world_repeatability: Repeatability,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct OwnerReceipt {
    schema_version: u32,
    node: Id,
    owner: Id,
    state: ContentRef,
    coordinator: ContentRef,
    cut: Position,
    ordinal: U64,
    domains: Vec<Id>,
}

impl HostArchive {
    /// Captures the authentic stopped live host world and persists its complete closure.
    ///
    /// Native capture is read-only. The actual runtime and scheduler inventories
    /// are checked again before issuance; the installed factory independently
    /// authenticates each complete native model and immutable inputs. The signed
    /// closure is sufficient after the original runtime has terminated.
    ///
    /// # Errors
    /// Refuses unsupported native profiles, moving cuts, pending/failed native
    /// operations, incomplete immutable content, unavailable installed model
    /// qualification, unsupported owners or any finite state bound violation.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_world(
        &self,
        graph: &AdmittedGraph,
        runtime: &mut NodeRuntime,
        activation: &WorldActivation,
        cut: Position,
        ordinal: U64,
        capture_id: Id,
        requirements: StateRequirements,
        immutable: &dyn CaptureEvidence,
        factory: &dyn HostWorldFactory,
    ) -> Result<HostArchiveRecord, StateError> {
        require_supported_extensions(graph)?;
        if requirements.restore_mode != StateRestoreMode::DurableRestart {
            return Err(refusal(
                "host signed archive selects durable reconstruction explicitly",
            ));
        }
        let scheduler = runtime
            .scheduler(graph, activation)
            .map_err(schema)?
            .snapshot(cut, ordinal)
            .map_err(schema)?;
        let source = runtime
            .runtime_snapshot(cut, ordinal, self.limits.maximum_record_bytes)
            .map_err(schema)?;
        let immutable_refs = required_immutable_refs(graph, self.limits)?;
        let mut immutable_content = verify_closure(immutable_refs.clone(), immutable, self.limits)?;
        let captures = runtime
            .capture_host_native(
                activation,
                &source,
                self.limits.maximum_record_bytes,
                self.limits.maximum_content_bytes,
                self.limits.maximum_total_content_bytes,
                self.limits.maximum_content_objects,
            )
            .map_err(schema)?;
        let mut objects = Objects::new(self.limits);
        for (reference, bytes) in immutable_content.entries() {
            let dependencies =
                immutable.dependencies(reference, bytes, self.limits.maximum_content_objects)?;
            objects.insert(reference.clone(), bytes.to_vec(), dependencies)?;
        }
        let coordinator = Coordinator {
            schema_version: 1,
            scheduler,
            runtime: source,
            world_repeatability: graph.world_repeatability(),
        };
        // Original scheduler custody retains dynamic request bytes separately
        // from immutable graph definitions. Verify their bounded identities
        // before native and coordinator validators authenticate their lineage.
        for payload in &coordinator.scheduler.payload_objects {
            immutable_content.include_payload(&payload.reference, &payload.bytes, self.limits)?;
            objects.insert(payload.reference.clone(), payload.bytes.clone(), vec![])?;
        }
        factory.authenticate_coordinator(
            graph,
            &coordinator.runtime,
            &coordinator.scheduler,
            &immutable_content,
        )?;
        let coordinator_ref = objects.record(
            &coordinator,
            core_references(&coordinator, self.limits.maximum_record_bytes)?,
        )?;
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(captures.len())
            .map_err(|_| limit("host capture owners"))?;
        for captured in captures {
            let node = captured.node();
            let binding = graph
                .binding(node)
                .ok_or_else(|| refusal("captured host binding absent"))?;
            let descriptor = graph
                .descriptor(node)
                .ok_or_else(|| refusal("captured host descriptor absent"))?;
            if captured.profile().as_str() != HOST_EXACT_PROFILE {
                return Err(refusal("unsupported native host capture profile"));
            }
            let inventory = validate_host_continuation(
                &captured.state().bytes,
                &coordinator.runtime,
                descriptor,
                binding,
                HostModelResources {
                    maximum_capture_bytes: self.limits.maximum_content_bytes,
                    ..HostModelResources::default()
                },
            )
            .map_err(native_failure)?;
            factory.authenticate_source(
                graph,
                node,
                &captured.state().bytes,
                &coordinator.runtime,
                &immutable_content,
            )?;
            let state_schema = factory.state_schema(graph, node)?;
            if !binding
                .compatibility
                .implementation
                .formats
                .contains(&state_schema)
            {
                return Err(refusal("installed native codec is not in actual binding"));
            }
            let mut dependencies = Vec::new();
            for object in captured.evidence() {
                dependencies.push(object.reference.clone());
                objects.insert(object.reference.clone(), object.bytes.clone(), vec![])?;
            }
            if inventory
                .evidence
                .iter()
                .any(|object| !dependencies.contains(&object.reference))
            {
                return Err(refusal("native capture evidence registry is incomplete"));
            }
            objects.insert(
                captured.state().reference.clone(),
                captured.state().bytes.clone(),
                dependencies,
            )?;
            let owner_id = &binding.compatibility.capture_owner.id;
            let policy = graph
                .ownership_policy()
                .capture_owners
                .iter()
                .find(|owner| &owner.owner_id == owner_id)
                .ok_or_else(|| refusal("host capture owner policy absent"))?;
            let domains: Vec<_> = graph
                .ownership_policy()
                .domains
                .iter()
                .filter(|domain| &domain.capture_owner_id == owner_id)
                .map(|domain| domain.id.clone())
                .collect();
            let receipt = OwnerReceipt {
                schema_version: 1,
                node: node.clone(),
                owner: owner_id.clone(),
                state: captured.state().reference.clone(),
                coordinator: coordinator_ref.clone(),
                cut,
                ordinal,
                domains: domains.clone(),
            };
            let receipt_ref = objects.record(
                &receipt,
                vec![receipt.state.clone(), coordinator_ref.clone()],
            )?;
            owners.push(CapturedOwner {
                capture_owner_id: owner_id.clone(),
                participant_ids: vec![node.clone()],
                state_domain_ids: domains,
                binding_hashes: vec![binding.identity().map_err(schema)?],
                state_schema,
                representation: CaptureRepresentation::Durable,
                state_ref: Some(captured.state().reference.clone()),
                retained_source_ref: None,
                dependencies: policy.dependencies.clone(),
                capture_receipt: receipt_ref,
                extensions: Default::default(),
            });
        }
        owners.sort_by(|left, right| left.capture_owner_id.cmp(&right.capture_owner_id));
        let guarantees_ref = objects.record(
            &serde_json::json!({
                "schema_version":1,"world_repeatability":graph.world_repeatability(),
                "exact_model_continuation":requirements.exact_model_continuation,
                "preservation_contract":requirements.preservation_contract,
            }),
            vec![],
        )?;
        let provenance_ref = objects.record(
            &serde_json::json!({
                "schema_version":1,"source_activation":coordinator.runtime.source_activation,
                "cut":cut,"ordinal":ordinal,
            }),
            vec![],
        )?;
        let manifest = CaptureManifest {
            schema_version: 1,
            capture_id,
            world_binding_hash: graph.world_binding_hash().clone(),
            scenario_ref: graph.world().scenario_ref.clone(),
            preservation_contract: requirements.preservation_contract.clone(),
            cut,
            event_ordinal: ordinal,
            ordering_profile: graph.world().ordering_profile.clone(),
            guarantees_ref,
            coordinator_state_ref: coordinator_ref,
            owners,
            immutable_refs,
            provenance_ref,
            extensions: Default::default(),
        };
        if runtime
            .runtime_snapshot(cut, ordinal, self.limits.maximum_record_bytes)
            .map_err(schema)?
            != coordinator.runtime
            || runtime
                .scheduler(graph, activation)
                .map_err(schema)?
                .snapshot(cut, ordinal)
                .map_err(schema)?
                != coordinator.scheduler
        {
            return Err(refusal(
                "original runtime or coordinator changed during native capture",
            ));
        }
        let artifact = objects.record(
            &manifest,
            core_references(&manifest, self.limits.maximum_record_bytes)?,
        )?;
        let body = ArchiveBody {
            schema_version: 1,
            artifact,
            objects: objects.finish(),
        };
        // Verify scope and native source closure before issuing any signature.
        let record = super::archive::validate_for_capture(body, self.limits)?;
        record.admit(graph, requirements, factory, self.limits)?;
        self.persist(super::archive::take_capture_body(record)?)
    }
}

impl HostArchiveRecord {
    /// Reads authenticated original generation data without granting live authority.
    ///
    /// Fresh realization derives higher generations from this data and then
    /// independently enrolls native owners. Saved incarnations are provenance,
    /// never reusable execution permissions.
    ///
    /// # Errors
    /// Refuses excessive coordinator bytes, malformed editions or an original
    /// activation/cut inconsistent with the authenticated complete manifest.
    pub fn source_activation(
        &self,
        maximum_record_bytes: usize,
    ) -> Result<crate::node_contract::SavedRuntimeActivation, StateError> {
        let object = self.object(&self.manifest.coordinator_state_ref)?;
        if object.bytes.len() > maximum_record_bytes {
            return Err(limit("authenticated source activation record"));
        }
        let coordinator: Coordinator = serde_json::from_slice(&object.bytes).map_err(schema)?;
        if coordinator.schema_version != 1
            || coordinator.runtime.source_activation.world_binding_hash
                != self.manifest.world_binding_hash
            || coordinator.runtime.capture_cut != self.manifest.cut
            || coordinator.runtime.capture_ordinal != self.manifest.event_ordinal
        {
            return Err(refusal(
                "authenticated source generation or complete cut differs",
            ));
        }
        Ok(coordinator.runtime.source_activation)
    }

    /// Admits the authenticated original capture against measured installed models.
    ///
    /// # Errors
    /// Refuses changed backend bindings, selected codecs, incomplete source
    /// closure, false native inventories or unavailable installed qualification.
    pub fn admit(
        &self,
        graph: &AdmittedGraph,
        requirements: StateRequirements,
        factory: &dyn HostWorldFactory,
        limits: StateLimits,
    ) -> Result<VerifiedCapture, StateError> {
        require_supported_extensions(graph)?;
        admit_capture(
            graph,
            self.artifact(),
            requirements,
            &ArchiveEvidence {
                record: self,
                factory,
            },
            limits,
        )
    }
}

pub(super) struct ArchiveEvidence<'a> {
    pub record: &'a HostArchiveRecord,
    pub factory: &'a dyn HostWorldFactory,
}

impl CaptureEvidence for ArchiveEvidence<'_> {
    fn content(&self, reference: &ContentRef, maximum_bytes: usize) -> Result<Vec<u8>, StateError> {
        let object = self.record.object(reference)?;
        if object.bytes.len() > maximum_bytes {
            return Err(limit("archive content allocation"));
        }
        Ok(object.bytes.clone())
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        verified_bytes: &[u8],
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let object = self.record.object(reference)?;
        if object.bytes != verified_bytes || object.dependencies.len() > maximum_dependencies {
            return Err(limit("archive selected dependency inventory"));
        }
        Ok(object.dependencies.clone())
    }

    fn verify_owner_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        owner: &CapturedOwner,
        requirements: &StateRequirements,
        content: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        if manifest != &self.record.manifest
            || requirements.restore_mode != StateRestoreMode::DurableRestart
            || owner.participant_ids.len() != 1
        {
            return Err(refusal(
                "host archive owner, durable scope or manifest differs",
            ));
        }
        let node = &owner.participant_ids[0];
        let reference = owner
            .state_ref
            .as_ref()
            .ok_or_else(|| refusal("durable host state absent"))?;
        let native = content
            .get(reference)
            .ok_or_else(|| refusal("host state unavailable"))?;
        let coordinator = self.coordinator(content)?;
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| refusal("host descriptor absent"))?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| refusal("host binding absent"))?;
        let inventory = validate_host_continuation(
            native,
            &coordinator.runtime,
            descriptor,
            binding,
            HostModelResources::default(),
        )
        .map_err(native_failure)?;
        if owner.state_schema != self.factory.state_schema(graph, node)?
            || inventory
                .evidence
                .iter()
                .any(|object| content.get(&object.reference) != Some(object.bytes.as_slice()))
        {
            return Err(refusal(
                "host codec or original native evidence unavailable",
            ));
        }
        let receipt: OwnerReceipt = serde_json::from_slice(
            content
                .get(&owner.capture_receipt)
                .ok_or_else(|| refusal("host capture receipt absent"))?,
        )
        .map_err(schema)?;
        let expected = OwnerReceipt {
            schema_version: 1,
            node: node.clone(),
            owner: owner.capture_owner_id.clone(),
            state: reference.clone(),
            coordinator: manifest.coordinator_state_ref.clone(),
            cut: manifest.cut,
            ordinal: manifest.event_ordinal,
            domains: owner.state_domain_ids.clone(),
        };
        if receipt != expected {
            return Err(refusal(
                "signed native owner cut or complete domains differ",
            ));
        }
        self.factory
            .authenticate_source(graph, node, native, &coordinator.runtime, content)?;
        Ok(NativeOwnerCaptureProof {
            owner_id: owner.capture_owner_id.clone(),
            state_domain_ids: owner.state_domain_ids.clone(),
            cut: manifest.cut,
            event_ordinal: manifest.event_ordinal,
        })
    }

    fn verify_coordinator_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        content: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        if manifest != &self.record.manifest {
            return Err(refusal("signed coordinator manifest differs"));
        }
        let coordinator = self.coordinator(content)?;
        if coordinator.schema_version != 1
            || coordinator.world_repeatability != graph.world_repeatability()
        {
            return Err(refusal("signed coordinator edition or guarantee differs"));
        }
        self.factory.authenticate_coordinator(
            graph,
            &coordinator.runtime,
            &coordinator.scheduler,
            content,
        )?;
        Ok(NativeCoordinatorCaptureProof {
            source_owners: coordinator.runtime.source_activation.owners.clone(),
            world_repeatability: coordinator.world_repeatability,
            pending_native_acknowledgements: coordinator.runtime.pending_acknowledgements(),
            scheduler: coordinator.scheduler,
            runtime: coordinator.runtime,
        })
    }
}

impl ArchiveEvidence<'_> {
    fn coordinator(&self, content: &VerifiedStateContent) -> Result<Coordinator, StateError> {
        let reference = &self.record.manifest.coordinator_state_ref;
        serde_json::from_slice(
            content
                .get(reference)
                .ok_or_else(|| refusal("signed coordinator bytes absent"))?,
        )
        .map_err(schema)
    }
}

struct Objects {
    objects: BTreeMap<HashRef, Object>,
    total: usize,
    limits: StateLimits,
}

impl Objects {
    fn new(limits: StateLimits) -> Self {
        Self {
            objects: BTreeMap::new(),
            total: 0,
            limits,
        }
    }

    fn insert(
        &mut self,
        reference: ContentRef,
        bytes: Vec<u8>,
        mut dependencies: Vec<ContentRef>,
    ) -> Result<(), StateError> {
        if bytes.len() > self.limits.maximum_content_bytes
            || dependencies.len() > self.limits.maximum_content_objects
        {
            return Err(limit("host archive source object"));
        }
        reference.verify(&bytes).map_err(schema)?;
        dependencies.sort();
        dependencies.dedup();
        if let Some(previous) = self.objects.get(&reference.hash) {
            if previous.reference != reference
                || previous.bytes != bytes
                || previous.dependencies != dependencies
            {
                return Err(refusal(format!(
                    "source hash metadata, bytes or selected dependency semantics differ: hash={}, metadata_match={}, bytes_match={}, dependency_match={}, existing_dependency_count={}, incoming_dependency_count={}",
                    reference.hash.digest,
                    previous.reference == reference,
                    previous.bytes == bytes,
                    previous.dependencies == dependencies,
                    previous.dependencies.len(),
                    dependencies.len(),
                )));
            }
            return Ok(());
        }
        self.total = self
            .total
            .checked_add(bytes.len())
            .ok_or_else(|| limit("host archive bytes"))?;
        if self.total > self.limits.maximum_total_content_bytes
            || self.objects.len() >= self.limits.maximum_content_objects
        {
            return Err(limit("host complete archive closure"));
        }
        self.objects.insert(
            reference.hash.clone(),
            Object {
                reference,
                dependencies,
                bytes,
            },
        );
        Ok(())
    }

    fn record(
        &mut self,
        value: &impl Serialize,
        dependencies: Vec<ContentRef>,
    ) -> Result<ContentRef, StateError> {
        bounded_record(value, self.limits.maximum_record_bytes)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(value).map_err(schema)?)
            .map_err(schema)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(schema)?;
        self.insert(reference.clone(), bytes, dependencies)?;
        Ok(reference)
    }

    fn finish(self) -> Vec<Object> {
        self.objects.into_values().collect()
    }
}
