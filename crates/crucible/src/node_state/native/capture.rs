//! Authentic unchanged-cut mixed-native capture and installed closure admission.

use std::collections::BTreeMap;

use crucible_node_contract::{
    CaptureManifest, CaptureRepresentation, CapturedOwner, ContentRef, HashRef, Id, Position,
    Repeatability, U64, canonical,
};
use serde::{Deserialize, Serialize};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRuntime, RuntimeSnapshot, WorldActivation},
    node_scheduling::SchedulingSnapshot,
};

use super::super::{
    CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateError,
    StateRequirements, StateRestoreMode, VerifiedCapture, VerifiedStateContent,
    closure::{
        ContentInventoryEdition, bounded_record, core_references, limit,
        verify_closure_with_edition,
    },
    schema,
    validation::{admit_capture_with_inventory, required_immutable_refs},
};
use super::storage::{Index, NativeArtifactState, Object};
use super::{
    AuthenticatedNativeSource, NativeArchive, NativeArchiveRecord, NativeOwnerState,
    NativeWorldFactory, decode_record, owner_state, refused, require_supported_extensions,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Coordinator {
    pub schema_version: u16,
    pub scheduler: SchedulingSnapshot,
    pub runtime: RuntimeSnapshot,
    pub world_repeatability: Repeatability,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct OwnerReceipt {
    schema_version: u16,
    owner: Id,
    inventory: HashRef,
    coordinator: ContentRef,
    cut: Position,
    ordinal: U64,
    domains: Vec<Id>,
}

impl NativeArchive {
    /// Captures and signs complete stopped installed native state without modeled execution.
    ///
    /// Each authoritative capture owner is read once, including shared public
    /// node views. Large images/resources stream directly to durable objects;
    /// the signed bounded index binds their complete reconstruction roster.
    /// Original runtime and scheduler snapshots must remain unchanged throughout
    /// mechanical checkpointing. Pending original prefixes retain their actual
    /// native positions and immutable birth/ACK custody in the installed codec.
    ///
    /// # Errors
    /// Refuses unsupported preservation/continuation profiles, moving cuts,
    /// incomplete native or immutable closure, failed installed authentication,
    /// corrupt streamed data, missing ownership or any finite limit excess.
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
        factory: &dyn NativeWorldFactory,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.capture_world_with_inventory(
            graph,
            runtime,
            activation,
            cut,
            ordinal,
            capture_id,
            requirements,
            immutable,
            factory,
            ContentInventoryEdition::Legacy,
        )
    }

    /// Captures exact typed content roles in an authenticated edition-two inventory.
    ///
    /// Each full reference retains its own installed dependency adjacency. Shared
    /// byte hashes deduplicate storage without changing media roles or native proof.
    /// This selection does not qualify selected extensions or native capture.
    ///
    /// # Errors
    /// Refuses moving cuts, unavailable native evidence, inconsistent typed roles,
    /// failed installed authentication, incomplete dependency closure or exceeded
    /// original object, edge, content and native resource credits.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_world_typed(
        &self,
        graph: &AdmittedGraph,
        runtime: &mut NodeRuntime,
        activation: &WorldActivation,
        cut: Position,
        ordinal: U64,
        capture_id: Id,
        requirements: StateRequirements,
        immutable: &dyn CaptureEvidence,
        factory: &dyn NativeWorldFactory,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.capture_world_with_inventory(
            graph,
            runtime,
            activation,
            cut,
            ordinal,
            capture_id,
            requirements,
            immutable,
            factory,
            ContentInventoryEdition::Typed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_world_with_inventory(
        &self,
        graph: &AdmittedGraph,
        runtime: &mut NodeRuntime,
        activation: &WorldActivation,
        cut: Position,
        ordinal: U64,
        capture_id: Id,
        requirements: StateRequirements,
        immutable: &dyn CaptureEvidence,
        factory: &dyn NativeWorldFactory,
        edition: ContentInventoryEdition,
    ) -> Result<NativeArchiveRecord, StateError> {
        require_supported_extensions(graph)?;
        if requirements.restore_mode != StateRestoreMode::DurableRestart {
            return Err(refused(
                "native archive selects durable reconstruction explicitly",
            ));
        }
        let scheduler = runtime
            .scheduler(graph, activation)
            .map_err(schema)?
            .snapshot(cut, ordinal)
            .map_err(schema)?;
        let source = runtime
            .runtime_snapshot(cut, ordinal, self.limits.state.maximum_record_bytes)
            .map_err(schema)?;
        let immutable_refs = required_immutable_refs(graph, self.limits.state)?;
        let content = verify_closure_with_edition(
            immutable_refs.clone(),
            immutable,
            self.limits.state,
            edition,
        )?;
        let captures = runtime
            .capture_installed_native(graph, activation, &source, self.limits.native)
            .map_err(schema)?;
        let mut objects = Objects::new(self, edition);
        for (reference, bytes) in content.entries() {
            let dependencies = immutable.dependencies(
                reference,
                bytes,
                self.limits.state.maximum_content_objects,
            )?;
            objects.insert(reference.clone(), bytes, dependencies)?;
        }
        let coordinator = Coordinator {
            schema_version: 1,
            scheduler,
            runtime: source,
            world_repeatability: graph.world_repeatability(),
        };
        let coordinator_ref = objects.record(
            &coordinator,
            core_references(&coordinator, self.limits.state.maximum_record_bytes)?,
        )?;
        for payload in &coordinator.scheduler.payload_objects {
            objects.insert(payload.reference.clone(), &payload.bytes, vec![])?;
        }
        let mut states = Vec::new();
        let mut owners = Vec::new();
        for captured in captures {
            let mut artifacts = Vec::new();
            for artifact in captured.artifacts() {
                self.store(artifact.reference(), &mut artifact.reader())?;
                artifacts.push(NativeArtifactState {
                    role: artifact.role().clone(),
                    name: artifact.name().to_owned(),
                    content: artifact.reference().clone(),
                });
            }
            artifacts
                .sort_by(|left, right| (&left.role, &left.name).cmp(&(&right.role, &right.name)));
            let mut evidence = Vec::new();
            for object in captured.evidence() {
                evidence.push(object.reference.clone());
                objects.insert(object.reference.clone(), &object.bytes, vec![])?;
            }
            evidence.sort();
            evidence.dedup();
            objects.insert(
                captured.state().reference.clone(),
                &captured.state().bytes,
                evidence.clone(),
            )?;
            let native = NativeOwnerState {
                owner: captured.owner().clone(),
                participants: captured.participants().to_vec(),
                key: captured.key().clone(),
                cut,
                state: captured.state().reference.clone(),
                evidence,
                artifacts,
            };
            let domains: Vec<_> = graph
                .ownership_policy()
                .domains
                .iter()
                .filter(|domain| domain.capture_owner_id == native.owner)
                .map(|domain| domain.id.clone())
                .collect();
            let policy = graph
                .ownership_policy()
                .capture_owners
                .iter()
                .find(|policy| policy.owner_id == native.owner)
                .ok_or_else(|| refused("captured native owner policy absent"))?;
            let receipt = OwnerReceipt {
                schema_version: 1,
                owner: native.owner.clone(),
                inventory: canonical::json_hash("crucible.native-owner-inventory.v1", &native)
                    .map_err(schema)?,
                coordinator: coordinator_ref.clone(),
                cut,
                ordinal,
                domains: domains.clone(),
            };
            let mut receipt_dependencies = native.evidence.clone();
            receipt_dependencies.extend([native.state.clone(), coordinator_ref.clone()]);
            let receipt_ref = objects.record(&receipt, receipt_dependencies)?;
            let binding_hashes = native
                .participants
                .iter()
                .map(|node| {
                    graph
                        .binding(node)
                        .ok_or_else(|| refused("native participant binding absent"))?
                        .identity()
                        .map_err(schema)
                })
                .collect::<Result<Vec<_>, _>>()?;
            owners.push(CapturedOwner {
                capture_owner_id: native.owner.clone(),
                participant_ids: native.participants.clone(),
                state_domain_ids: domains,
                binding_hashes,
                state_schema: native.key.schema.clone(),
                representation: CaptureRepresentation::Durable,
                state_ref: Some(native.state.clone()),
                retained_source_ref: None,
                dependencies: policy.dependencies.clone(),
                capture_receipt: receipt_ref,
                extensions: Default::default(),
            });
            states.push(native);
        }
        owners.sort_by(|left, right| left.capture_owner_id.cmp(&right.capture_owner_id));
        states.sort_by(|left, right| left.owner.cmp(&right.owner));
        let guarantees_ref = objects.record(
            &serde_json::json!({
                "schema_version":1,"world_repeatability":graph.world_repeatability(),
                "exact_model_continuation":requirements.exact_model_continuation,
                "preservation_contract":requirements.preservation_contract,
            }),
            vec![],
        )?;
        let mut provenance = serde_json::json!({
            "schema_version":1,"source_activation":coordinator.runtime.source_activation,"cut":cut,"ordinal":ordinal,
        });
        if edition == ContentInventoryEdition::Typed {
            provenance["native_archive"] = serde_json::json!({
                "schema_version":2,"content_inventory":2,"selected_extensions":null,
            });
        }
        let provenance_ref = objects.record(&provenance, vec![])?;
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
            .runtime_snapshot(cut, ordinal, self.limits.state.maximum_record_bytes)
            .map_err(schema)?
            != coordinator.runtime
            || runtime
                .scheduler(graph, activation)
                .map_err(schema)?
                .snapshot(cut, ordinal)
                .map_err(schema)?
                != coordinator.scheduler
        {
            return Err(refused(
                "native runtime or coordinator changed during capture",
            ));
        }
        let artifact = objects.record(
            &manifest,
            core_references(&manifest, self.limits.state.maximum_record_bytes)?,
        )?;
        let index = Index {
            schema_version: match edition {
                ContentInventoryEdition::Legacy => 1,
                ContentInventoryEdition::Typed => 2,
            },
            selected_extensions: None,
            artifact,
            objects: objects.finish(),
            owners: states,
        };
        // Installed authentication precedes signing. Only this crate-private
        // live-capture path can assemble and authenticate a new source index.
        let record = self.record(index.clone())?;
        let admitted = record.admit(graph, requirements, factory)?;
        if admitted.content().object_count() != index.objects.len() {
            return Err(refused(
                "native archive contains unowned core objects outside complete closure",
            ));
        }
        self.persist(index)
    }
}

impl NativeArchiveRecord {
    /// Admits this signed source against the unchanged graph and installed native factory.
    ///
    /// # Errors
    /// Refuses cross-backend schemas, changed graph bindings, missing streamed
    /// files, invalid original custody or unavailable native/coordinator proof.
    pub fn admit(
        &self,
        graph: &AdmittedGraph,
        requirements: StateRequirements,
        factory: &dyn NativeWorldFactory,
    ) -> Result<VerifiedCapture, StateError> {
        require_supported_extensions(graph)?;
        if self.index.owners.len() != self.manifest.owners.len()
            || self
                .index
                .owners
                .iter()
                .zip(&self.manifest.owners)
                .any(|(native, owner)| native.owner != owner.capture_owner_id)
        {
            return Err(refused(
                "native signed owner inventory differs from complete manifest",
            ));
        }
        admit_capture_with_inventory(
            graph,
            self.artifact(),
            requirements,
            &Evidence {
                record: self,
                factory,
            },
            self.limits.state,
            match self.index.schema_version {
                1 => ContentInventoryEdition::Legacy,
                2 => ContentInventoryEdition::Typed,
                _ => return Err(refused("unsupported native content inventory")),
            },
        )
    }

    /// Reads original activation data without reusing saved live permissions.
    ///
    /// # Errors
    /// Refuses unknown coordinator editions or inconsistent world/cut identity.
    pub fn source_activation(
        &self,
    ) -> Result<crate::node_contract::SavedRuntimeActivation, StateError> {
        let saved = self.coordinator()?;
        if saved.runtime.capture_cut != self.manifest.cut
            || saved.runtime.capture_ordinal != self.manifest.event_ordinal
            || saved.runtime.source_activation.world_binding_hash
                != self.manifest.world_binding_hash
        {
            return Err(refused("native archive original activation or cut differs"));
        }
        Ok(saved.runtime.source_activation)
    }

    pub(super) fn coordinator(&self) -> Result<Coordinator, StateError> {
        let bytes = self.object(
            &self.manifest.coordinator_state_ref,
            self.limits.state.maximum_record_bytes,
        )?;
        let saved: Coordinator = decode_record(&bytes, self.limits.state.maximum_record_bytes)?;
        if saved.schema_version != 1 {
            return Err(refused("unknown native coordinator edition"));
        }
        Ok(saved)
    }

    /// Seals this owner's original source against its exact saved runtime and core closure.
    ///
    /// This is preservation provenance only. It cannot qualify fresh native
    /// execution, mutate a source path or construct live operation authority.
    ///
    /// # Errors
    /// Refuses unknown owners, a changed original runtime ledger or absent
    /// authenticated native metadata/evidence in the supplied complete closure.
    pub fn authenticated_source<'a>(
        &'a self,
        owner: &Id,
        runtime: &'a RuntimeSnapshot,
        content: &'a VerifiedStateContent,
    ) -> Result<AuthenticatedNativeSource<'a>, StateError> {
        let state = owner_state(self, owner)?;
        if self.coordinator()?.runtime != *runtime
            || content.get(&state.state).is_none()
            || state
                .evidence
                .iter()
                .any(|reference| content.get(reference).is_none())
        {
            return Err(refused(
                "native source runtime or complete native evidence differs",
            ));
        }
        Ok(AuthenticatedNativeSource {
            record: self,
            owner: state,
            runtime,
            content,
        })
    }

    /// Reads the complete original runtime ledger without granting saved authority.
    ///
    /// # Errors
    /// Refuses missing coordinator content or an unsupported coordinator edition.
    pub fn runtime_snapshot(&self) -> Result<RuntimeSnapshot, StateError> {
        Ok(self.coordinator()?.runtime)
    }

    /// Reads the complete original scheduler and cross-owner transfer custody.
    ///
    /// # Errors
    /// Refuses missing coordinator content or an unsupported coordinator edition.
    pub fn scheduling_snapshot(&self) -> Result<SchedulingSnapshot, StateError> {
        Ok(self.coordinator()?.scheduler)
    }
}

struct Evidence<'a> {
    record: &'a NativeArchiveRecord,
    factory: &'a dyn NativeWorldFactory,
}

impl CaptureEvidence for Evidence<'_> {
    fn content(&self, reference: &ContentRef, maximum_bytes: usize) -> Result<Vec<u8>, StateError> {
        self.record.object(reference, maximum_bytes)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        _bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let object = self
            .record
            .index
            .objects
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| refused("native core dependency registry absent"))?;
        if object.dependencies.len() > maximum {
            return Err(limit("native dependency fanout"));
        }
        Ok(object.dependencies.clone())
    }

    fn verify_owner_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        owner: &CapturedOwner,
        _requirements: &StateRequirements,
        content: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        let native = owner_state(self.record, &owner.capture_owner_id)?;
        if manifest != self.record.manifest()
            || native.participants != owner.participant_ids
            || native.cut != manifest.cut
            || owner.state_ref.as_ref() != Some(&native.state)
            || owner.state_schema != native.key.schema
            || native
                .evidence
                .iter()
                .any(|reference| content.get(reference).is_none())
        {
            return Err(refused(
                "signed native owner roster, schema or original evidence differs",
            ));
        }
        for participant in &native.participants {
            let binding = graph
                .binding(participant)
                .ok_or_else(|| refused("native binding absent"))?;
            if native.key.implementation != binding.compatibility.implementation.implementation_id
                || !binding
                    .compatibility
                    .operating_contract
                    .facets
                    .iter()
                    .any(|facet| facet.id == native.key.profile)
                || !binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&native.key.schema)
                || binding.compatibility.capture_owner.participant_ids != native.participants
            {
                return Err(refused(
                    "native state cannot cross backend or participant bindings",
                ));
            }
        }
        let receipt: OwnerReceipt = decode_record(
            content
                .get(&owner.capture_receipt)
                .ok_or_else(|| refused("native owner receipt absent"))?,
            self.record.limits.state.maximum_record_bytes,
        )?;
        let expected = OwnerReceipt {
            schema_version: 1,
            owner: native.owner.clone(),
            inventory: canonical::json_hash("crucible.native-owner-inventory.v1", native)
                .map_err(schema)?,
            coordinator: manifest.coordinator_state_ref.clone(),
            cut: manifest.cut,
            ordinal: manifest.event_ordinal,
            domains: owner.state_domain_ids.clone(),
        };
        if receipt != expected {
            return Err(refused("native owner complete inventory receipt differs"));
        }
        let coordinator = self.record.coordinator()?;
        let source =
            self.record
                .authenticated_source(&native.owner, &coordinator.runtime, content)?;
        self.factory.authenticate_source(graph, owner, &source)?;
        Ok(NativeOwnerCaptureProof {
            owner_id: native.owner.clone(),
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
        let saved = self.record.coordinator()?;
        if manifest != self.record.manifest()
            || saved.world_repeatability != graph.world_repeatability()
        {
            return Err(refused("native coordinator world or repeatability differs"));
        }
        self.factory
            .authenticate_coordinator(graph, &saved.runtime, &saved.scheduler, content)?;
        Ok(NativeCoordinatorCaptureProof {
            source_owners: saved.runtime.source_activation.owners.clone(),
            world_repeatability: saved.world_repeatability,
            pending_native_acknowledgements: saved.runtime.pending_acknowledgements(),
            scheduler: saved.scheduler,
            runtime: saved.runtime,
        })
    }
}

struct Objects<'a> {
    archive: &'a NativeArchive,
    objects: BTreeMap<ContentRef, Object>,
    hashes: BTreeMap<HashRef, ContentRef>,
    edition: ContentInventoryEdition,
    total: usize,
}

impl<'a> Objects<'a> {
    fn new(archive: &'a NativeArchive, edition: ContentInventoryEdition) -> Self {
        Self {
            archive,
            objects: BTreeMap::new(),
            hashes: BTreeMap::new(),
            edition,
            total: 0,
        }
    }

    fn insert(
        &mut self,
        reference: ContentRef,
        mut bytes: &[u8],
        mut dependencies: Vec<ContentRef>,
    ) -> Result<(), StateError> {
        reference.verify(bytes).map_err(schema)?;
        dependencies.sort();
        dependencies.dedup();
        if let Some(old) = self.objects.get(&reference) {
            if old.dependencies != dependencies {
                return Err(refused("native typed role has conflicting dependencies"));
            }
            return Ok(());
        }
        let shared = self.hashes.get(&reference.hash);
        if let Some(original) = shared
            && ((self.edition == ContentInventoryEdition::Legacy && original != &reference)
                || original.length != reference.length)
        {
            return Err(refused("native core digest has conflicting typed metadata"));
        }
        let total = self
            .total
            .checked_add(if shared.is_some() { 0 } else { bytes.len() })
            .ok_or_else(|| limit("native core byte count"))?;
        if bytes.len() > self.archive.limits.state.maximum_content_bytes
            || total > self.archive.limits.state.maximum_total_content_bytes
            || self.objects.len() >= self.archive.limits.state.maximum_content_objects
            || dependencies.len() > self.archive.limits.state.maximum_content_objects
        {
            return Err(limit("native core inventory"));
        }
        self.archive.store(&reference, &mut bytes)?;
        self.total = total;
        self.hashes
            .entry(reference.hash.clone())
            .or_insert_with(|| reference.clone());
        self.objects.insert(
            reference.clone(),
            Object {
                reference,
                dependencies,
            },
        );
        Ok(())
    }

    fn record(
        &mut self,
        record: &impl Serialize,
        dependencies: Vec<ContentRef>,
    ) -> Result<ContentRef, StateError> {
        bounded_record(record, self.archive.limits.state.maximum_record_bytes)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(record).map_err(schema)?)
            .map_err(schema)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(schema)?;
        self.insert(reference.clone(), &bytes, dependencies)?;
        Ok(reference)
    }

    fn finish(self) -> Vec<Object> {
        self.objects.into_values().collect()
    }
}
