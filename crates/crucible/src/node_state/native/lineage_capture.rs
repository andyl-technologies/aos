//! Signs complete conditional Runtime7 state through a separately installed codec.
//!
//! The reference-only coordinator points to standalone runtime and scheduler
//! objects. This path never admits Runtime7 through legacy capture validation or
//! creates a physical backend preservation permit. Actual native model callbacks
//! and the installed original-source factory remain mandatory before signing.

use crucible_node_contract::{
    CaptureManifest, CaptureRepresentation, CapturedOwner, ContentRef, HashRef, Id, Position, U64,
    canonical,
};
use serde::Serialize;

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{
        NativeCaptureLimits, NodeRuntime, OriginalInputLineageLimits, WorldActivation,
    },
    node_scheduling::{InputPayload, SchedulingSnapshot},
};

use super::super::{
    CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateRequirements,
    StateRestoreMode,
    closure::{
        ContentInventoryEdition, bounded_record, core_references, verify_closure_with_edition,
    },
    schema,
    validation::required_immutable_refs,
};
use super::capture::Objects;
use super::lineage_source::OriginalLineageCoordinator;
use super::storage::Index;
use super::*;

/// Borrows actual stopped world custody and its independently installed capture policy.
///
/// These inputs do not themselves qualify capture. The runtime independently
/// compares its original ledgers and each owning native model before signing.
pub struct OriginalLineageCaptureRequest<'a> {
    /// Borrows the exact admitted complete conditional graph.
    pub graph: &'a AdmittedGraph,
    /// Retains the actual owning runtime throughout callbacks and refusals.
    pub runtime: &'a mut NodeRuntime,
    /// Borrows this runtime's genuinely published whole-world activation.
    pub activation: &'a WorldActivation,
    /// Names the unchanged complete-world capture cut.
    pub cut: Position,
    /// Preserves the actual coordinator event ordinal.
    pub ordinal: U64,
    /// Names this original capture without issuing execution permission.
    pub capture_id: Id,
    /// Selects explicit conditional-model exact-state preservation.
    pub requirements: StateRequirements,
    /// Supplies original immutable bytes and positively authenticated dependency rows.
    pub immutable: &'a dyn CaptureEvidence,
    /// Supplies independently installed source and model capture qualification.
    pub factory: &'a dyn NativeWorldFactory,
    /// Bounds every retained original lineage body occurrence independently.
    pub lineage_limits: OriginalInputLineageLimits,
}

#[derive(Serialize)]
struct OwnerReceipt<'a> {
    schema_version: u16,
    owner: &'a Id,
    inventory: HashRef,
    coordinator: &'a ContentRef,
    cut: Position,
    ordinal: U64,
    domains: &'a [Id],
}

impl NativeArchive {
    /// Captures and signs exact Runtime7 conditional model journals at an unchanged cut.
    ///
    /// Known immutable, original-body and portable obligations consume finite
    /// credits before any native capture callback. Unsupported source policies,
    /// physical artifacts and combined runtime/scheduler editions refuse.
    ///
    /// # Errors
    /// Refuses unsupported preservation, moving cuts, incomplete original native
    /// custody, unknown body dependencies, absent installed policy or finite excess.
    pub fn capture_original_lineage_world(
        &self,
        request: OriginalLineageCaptureRequest<'_>,
    ) -> Result<NativeArchiveRecord, StateError> {
        let OriginalLineageCaptureRequest {
            graph,
            runtime,
            activation,
            cut,
            ordinal,
            capture_id,
            requirements,
            immutable,
            factory,
            lineage_limits,
        } = request;
        if requirements.restore_mode != StateRestoreMode::DurableRestart
            || !requirements.exact_model_continuation
            || requirements.preservation_contract.as_str()
                != crate::node_adapters::transcript::TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE
            || requirements.deterministic
                && graph.world_repeatability()
                    != crucible_node_contract::Repeatability::Qualified
        {
            return Err(refused(
                "unsupported complete conditional lineage preservation requirements",
            ));
        }
        let selected = extensions::archive::prepare_capture(graph, factory, self.limits.state)?;
        let graph_refs = selected
            .as_ref()
            .map(|selected| {
                extensions::graph_refs::immutable_refs(graph, selected, self.limits.state)
            })
            .transpose()?;
        let immutable = extensions::evidence::SelectionEvidence {
            base: immutable,
            selected: selected.as_ref(),
        };
        let scheduler = runtime
            .scheduler(graph, activation)
            .map_err(schema)?
            .snapshot(cut, ordinal)
            .map_err(schema)?;
        if scheduler.schema_version != 1
            || scheduler.original_epochs.is_some()
            || !scheduler.external_closed_prefixes.is_empty()
        {
            return Err(refused(
                "complete Tape2 capture does not qualify combined scheduler editions or external ingress",
            ));
        }
        let source = runtime
            .original_lineage_runtime_snapshot(
                cut,
                ordinal,
                lineage_limits,
                self.limits.state.maximum_record_bytes,
            )
            .map_err(schema)?;
        factory.authenticate_original_lineage_capture(graph, &source, &scheduler)?;
        let immutable_refs = if let Some(refs) = &graph_refs {
            refs.verify(graph, self.limits.state)?;
            refs.roots().to_vec()
        } else {
            required_immutable_refs(graph, self.limits.state)?
        };
        let content = verify_closure_with_edition(
            immutable_refs.clone(),
            &immutable,
            self.limits.state,
            ContentInventoryEdition::Typed,
        )?;
        let runtime_object = self.lineage_record(&source, ORIGINAL_LINEAGE_RUNTIME_MEDIA)?;
        let scheduler_object = self.lineage_record(&scheduler, "application/json")?;
        let coordinator = OriginalLineageCoordinator {
            schema_version: 7,
            runtime: runtime_object.reference.clone(),
            scheduler: scheduler_object.reference.clone(),
            world_repeatability: graph.world_repeatability(),
        };
        let coordinator_object =
            self.lineage_record(&coordinator, ORIGINAL_LINEAGE_COORDINATOR_MEDIA)?;
        let body_geometry = runtime.original_lineage_capture_objects().try_fold(
            (0usize, 0usize),
            |(count, bytes), object| {
                Ok::<_, StateError>((
                    count
                        .checked_add(1)
                        .ok_or_else(|| refused("lineage body count overflow"))?,
                    bytes
                        .checked_add(object.bytes.len())
                        .ok_or_else(|| refused("lineage body byte count overflow"))?,
                ))
            },
        )?;
        let native_limits = remaining_native(
            graph,
            &content,
            [&runtime_object, &scheduler_object, &coordinator_object],
            &scheduler,
            body_geometry,
            self.limits,
        )?;
        let mut objects = Objects::new(self, ContentInventoryEdition::Typed);
        for (reference, bytes) in content.entries() {
            objects.insert(
                reference.clone(),
                bytes,
                immutable.dependencies(
                    reference,
                    bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
        }
        for object in runtime.original_lineage_capture_objects() {
            objects.insert(
                object.reference.clone(),
                &object.bytes,
                factory.original_lineage_capture_dependencies(
                    graph,
                    &object.reference,
                    &object.bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
        }
        for object in &scheduler.payload_objects {
            objects.insert(
                object.reference.clone(),
                &object.bytes,
                factory.original_lineage_capture_dependencies(
                    graph,
                    &object.reference,
                    &object.bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
        }
        objects.insert(
            runtime_object.reference.clone(),
            &runtime_object.bytes,
            core_references(&source, self.limits.state.maximum_record_bytes)?,
        )?;
        objects.insert(
            scheduler_object.reference.clone(),
            &scheduler_object.bytes,
            core_references(&scheduler, self.limits.state.maximum_record_bytes)?,
        )?;
        objects.insert(
            coordinator_object.reference.clone(),
            &coordinator_object.bytes,
            vec![
                runtime_object.reference.clone(),
                scheduler_object.reference.clone(),
            ],
        )?;

        let captures = runtime
            .capture_installed_original_lineage(
                graph,
                activation,
                &source,
                &runtime_object,
                lineage_limits,
                native_limits,
            )
            .map_err(schema)?;
        let mut states = Vec::new();
        let mut owners = Vec::new();
        states
            .try_reserve_exact(captures.len())
            .map_err(|_| refused("lineage owner reservation failed"))?;
        owners
            .try_reserve_exact(captures.len())
            .map_err(|_| refused("lineage owner receipt reservation failed"))?;
        for captured in captures {
            if !captured.artifacts().is_empty() {
                return Err(refused(
                    "physical image custody is unsupported by Tape2 capture",
                ));
            }
            let mut evidence = Vec::new();
            evidence
                .try_reserve_exact(captured.evidence().len())
                .map_err(|_| refused("lineage evidence reservation failed"))?;
            for object in captured.evidence() {
                evidence.push(object.reference.clone());
                if object.reference == runtime_object.reference {
                    continue;
                }
                objects.insert(
                    object.reference.clone(),
                    &object.bytes,
                    factory.original_lineage_capture_dependencies(
                        graph,
                        &object.reference,
                        &object.bytes,
                        self.limits.state.maximum_content_objects,
                    )?,
                )?;
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
                artifacts: Vec::new(),
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
                .find(|owner| owner.owner_id == native.owner)
                .ok_or_else(|| refused("lineage capture owner absent"))?;
            let receipt = OwnerReceipt {
                schema_version: 1,
                owner: &native.owner,
                inventory: canonical::json_hash("crucible.native-owner-inventory.v1", &native)
                    .map_err(schema)?,
                coordinator: &coordinator_object.reference,
                cut,
                ordinal,
                domains: &domains,
            };
            let mut dependencies = native.evidence.clone();
            dependencies.extend([native.state.clone(), coordinator_object.reference.clone()]);
            let receipt_ref = objects.record(&receipt, dependencies)?;
            let mut binding_hashes = native
                .participants
                .iter()
                .map(|node| {
                    graph
                        .binding(node)
                        .ok_or_else(|| refused("lineage participant binding absent"))?
                        .identity()
                        .map_err(schema)
                })
                .collect::<Result<Vec<_>, _>>()?;
            binding_hashes.sort();
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
        let guarantees_ref = objects.record(&serde_json::json!({
            "schema_version":1,"world_repeatability":graph.world_repeatability(),
            "exact_model_continuation":true,"preservation_contract":requirements.preservation_contract,
        }), vec![])?;
        let selected_ref = selected
            .as_ref()
            .map(|selected| selected.record.reference.clone());
        let provenance_ref = objects.record(&serde_json::json!({
            "schema_version":1,"source_activation":source.source_activation,"cut":cut,"ordinal":ordinal,
            "native_archive":{"schema_version":2,"content_inventory":2,"selected_extensions":selected_ref},
        }), selected_ref.iter().cloned().collect())?;
        let manifest = CaptureManifest {
            schema_version: 1,
            capture_id,
            world_binding_hash: graph.world_binding_hash().clone(),
            scenario_ref: graph.world().scenario_ref.clone(),
            preservation_contract: requirements.preservation_contract,
            cut,
            event_ordinal: ordinal,
            ordering_profile: graph.world().ordering_profile.clone(),
            guarantees_ref,
            coordinator_state_ref: coordinator_object.reference,
            owners,
            immutable_refs,
            provenance_ref,
            extensions: Default::default(),
        };
        if runtime
            .original_lineage_runtime_snapshot(
                cut,
                ordinal,
                lineage_limits,
                self.limits.state.maximum_record_bytes,
            )
            .map_err(schema)?
            != source
            || runtime
                .scheduler(graph, activation)
                .map_err(schema)?
                .snapshot(cut, ordinal)
                .map_err(schema)?
                != scheduler
        {
            return Err(refused(
                "conditional native/runtime state changed during capture",
            ));
        }
        let artifact = objects.record(
            &manifest,
            core_references(&manifest, self.limits.state.maximum_record_bytes)?,
        )?;
        let index = Index {
            schema_version: 2,
            selected_extensions: selected_ref,
            artifact,
            objects: objects.finish(),
            owners: states,
        };
        let record = self.record(index.clone())?;
        record.original_lineage_content(graph, factory, lineage_limits)?;
        self.persist(index)
    }

    fn lineage_record(
        &self,
        value: &impl Serialize,
        media: &str,
    ) -> Result<InputPayload, StateError> {
        bounded_record(value, self.limits.state.maximum_record_bytes)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(value).map_err(schema)?)
            .map_err(schema)?;
        let reference = canonical::content_ref(&bytes, media).map_err(schema)?;
        Ok(InputPayload { reference, bytes })
    }
}

impl NativeArchiveRecord {
    /// Authenticates the complete selected Runtime7 closure without legacy admission.
    ///
    /// The signed inventory and installed policy precede every source/native
    /// validation. The result is historical body custody, never a Ready permit.
    ///
    /// # Errors
    /// Refuses foreign graph, incomplete body/owner coverage, unknown selected
    /// codecs, failed original tape validation or finite content excess.
    pub fn original_lineage_content(
        &self,
        graph: &AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: OriginalInputLineageLimits,
    ) -> Result<VerifiedStateContent, StateError> {
        if self.index.schema_version != 2
            || self.manifest.world_binding_hash != *graph.world_binding_hash()
            || self.manifest.owners.len() != graph.ownership_policy().capture_owners.len()
            || self.owners().len() != self.manifest.owners.len()
            || self
                .owners()
                .iter()
                .any(|owner| !owner.artifacts.is_empty())
        {
            return Err(refused(
                "unsupported original-lineage signed world/owner roster",
            ));
        }
        super::super::validation::validate_manifest(
            graph,
            &self.manifest,
            &StateRequirements {
                preservation_contract: Id::new(
                    crate::node_adapters::transcript::TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE,
                )
                .map_err(schema)?,
                exact_model_continuation: true,
                deterministic: false,
                restore_mode: StateRestoreMode::DurableRestart,
            },
            self.limits.state,
        )?;
        let selected = extensions::archive::authenticate_archive(self, graph, factory)?;
        let immutable_refs = if let Some(selected) = &selected {
            let roots = extensions::graph_refs::immutable_refs(graph, selected, self.limits.state)?;
            roots.verify(graph, self.limits.state)?;
            roots.roots().to_vec()
        } else {
            required_immutable_refs(graph, self.limits.state)?
        };
        if immutable_refs
            .iter()
            .any(|reference| !self.manifest.immutable_refs.contains(reference))
        {
            return Err(refused("lineage manifest omitted admitted immutable roles"));
        }
        let content = verify_closure_with_edition(
            vec![self.artifact().clone()],
            &SignedRows(self),
            self.limits.state,
            ContentInventoryEdition::Typed,
        )?;
        if content.object_count() != self.index.objects.len() {
            return Err(refused("lineage index has unowned body roles"));
        }
        self.validate_lineage_owner_receipts(graph, &content)?;
        for owner in self.owners() {
            let source = if self.index.selected_extensions.is_some() {
                self.authenticated_selected_original_lineage_source(
                    &owner.owner,
                    &content,
                    limits,
                    graph,
                    factory,
                )?
            } else {
                let source =
                    self.authenticated_original_lineage_source(&owner.owner, &content, limits)?;
                factory.authenticate_original_lineage_source(graph, &source)?;
                source
            };
            crate::node_adapters::transcript::authenticate_tape2_continuation(
                &source,
                owner
                    .participants
                    .first()
                    .ok_or_else(|| refused("lineage owner has no participant"))?,
            )
            .map_err(|error| refused(error.reason))?;
        }
        Ok(content)
    }

    pub(super) fn validate_lineage_owner_receipts(
        &self,
        graph: &AdmittedGraph,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        for (native, captured) in self.owners().iter().zip(&self.manifest.owners) {
            if native.owner != captured.capture_owner_id
                || native.participants != captured.participant_ids
                || native.cut != self.manifest.cut
                || Some(&native.state) != captured.state_ref.as_ref()
                || native.key.schema != captured.state_schema
                || captured.retained_source_ref.is_some()
                || native
                    .evidence
                    .iter()
                    .any(|reference| content.get(reference).is_none())
            {
                return Err(refused("lineage native and manifest owner scopes differ"));
            }
            for participant in &native.participants {
                let binding = graph
                    .binding(participant)
                    .ok_or_else(|| refused("lineage binding absent"))?;
                if native.key.implementation
                    != binding.compatibility.implementation.implementation_id
                    || native.key.profile.as_str()
                        != crate::node_adapters::transcript::TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE
                    || !binding.compatibility.operating_contract.facets.iter().any(|facet| {
                        facet.id == native.key.profile
                            && facet.version == 2
                    })
                {
                    return Err(refused("lineage owner crossed selected implementation/profile"));
                }
            }
            let receipt = OwnerReceipt {
                schema_version: 1,
                owner: &native.owner,
                inventory: canonical::json_hash("crucible.native-owner-inventory.v1", native)
                    .map_err(schema)?,
                coordinator: &self.manifest.coordinator_state_ref,
                cut: self.manifest.cut,
                ordinal: self.manifest.event_ordinal,
                domains: &captured.state_domain_ids,
            };
            bounded_record(&receipt, self.limits.state.maximum_record_bytes)?;
            let expected =
                canonical::canonical_json(&serde_json::to_value(receipt).map_err(schema)?)
                    .map_err(schema)?;
            let bytes = content
                .get(&captured.capture_receipt)
                .ok_or_else(|| refused("lineage owner receipt absent"))?;
            let mut dependencies = native.evidence.clone();
            dependencies.extend([
                native.state.clone(),
                self.manifest.coordinator_state_ref.clone(),
            ]);
            dependencies.sort();
            dependencies.dedup();
            let row = self
                .index
                .objects
                .iter()
                .find(|row| row.reference == captured.capture_receipt)
                .ok_or_else(|| refused("lineage owner receipt row absent"))?;
            if bytes != expected || row.dependencies != dependencies {
                return Err(refused(
                    "lineage original owner receipt or adjacency differs",
                ));
            }
        }
        Ok(())
    }
}

struct SignedRows<'a>(&'a NativeArchiveRecord);

impl CaptureEvidence for SignedRows<'_> {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.0.object_bytes(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        reference.verify(bytes).map_err(schema)?;
        let row = self
            .0
            .index
            .objects
            .iter()
            .find(|row| &row.reference == reference)
            .ok_or_else(|| refused("signed lineage row absent"))?;
        if row.dependencies.len() > maximum {
            return Err(refused("signed lineage adjacency credit exhausted"));
        }
        Ok(row.dependencies.clone())
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(refused("Runtime7 cannot use legacy owner admission"))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(refused("Runtime7 cannot use legacy coordinator admission"))
    }
}

fn remaining_native(
    graph: &AdmittedGraph,
    content: &VerifiedStateContent,
    portable: [&InputPayload; 3],
    scheduler: &SchedulingSnapshot,
    original: (usize, usize),
    limits: NativeArchiveLimits,
) -> Result<NativeCaptureLimits, StateError> {
    let portable_count = graph
        .ownership_policy()
        .capture_owners
        .len()
        .checked_add(4)
        .ok_or_else(|| refused("lineage portable count overflow"))?;
    let portable_bytes = portable_count
        .checked_mul(limits.state.maximum_record_bytes)
        .ok_or_else(|| refused("lineage portable reservation overflow"))?;
    let payload_bytes = scheduler
        .payload_objects
        .iter()
        .try_fold(0usize, |total, object| {
            total.checked_add(object.bytes.len())
        })
        .ok_or_else(|| refused("lineage scheduler payload reservation overflow"))?;
    let known_bytes = portable
        .iter()
        .try_fold(content.total_bytes(), |total, object| {
            total.checked_add(object.bytes.len())
        })
        .and_then(|total| total.checked_add(original.1))
        .and_then(|total| total.checked_add(payload_bytes))
        .and_then(|total| total.checked_add(portable_bytes))
        .ok_or_else(|| refused("lineage known body reservation overflow"))?;
    let known_count = content
        .object_count()
        .checked_add(3)
        .and_then(|total| total.checked_add(original.0))
        .and_then(|total| total.checked_add(scheduler.payload_objects.len()))
        .and_then(|total| total.checked_add(portable_count))
        .ok_or_else(|| refused("lineage known role reservation overflow"))?;
    let mut native = limits.native;
    native.maximum_total_record_bytes = native
        .maximum_total_record_bytes
        .min(limits.state.maximum_total_content_bytes)
        .checked_sub(known_bytes)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| refused("lineage known custody exhausts byte credit"))?;
    native.maximum_objects = native
        .maximum_objects
        .min(limits.state.maximum_content_objects)
        .checked_sub(known_count)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| refused("lineage known custody exhausts role credit"))?;
    native.maximum_record_bytes = native
        .maximum_record_bytes
        .min(native.maximum_total_record_bytes)
        .min(limits.state.maximum_content_bytes);
    Ok(native)
}
