//! Builds a distinct complete conditional model from inspected original history.
//!
//! This private fixture selects the same continuation contract before the first
//! activation and on fresh restoration. Native reader extensions remain original
//! evidence; they never become the conditional model's installation authority.

use super::conditional_source::InspectionError;

use std::{collections::BTreeMap, rc::Rc};

use crucible::{
    node_adapters::transcript::{
        TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE, TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE,
        TRANSCRIPT_REPLAY_PROFILE, original_lineage_continuation_definition,
        original_lineage_continuation_schema,
    },
    node_admission::{ConnectionPolicy, CoordinatorPolicy, OwnershipPolicy, ScenarioRequirements},
    node_contract::{ActivationRecord, OwnerIdentity},
    node_state::PinnedOriginalLineageSource,
};
use crucible_node_contract::*;
use serde::{Serialize, de::DeserializeOwned};

use super::conditional_source::InspectedReaderHistory;

pub(super) struct ConditionalProfile {
    pub(super) world: WorldBinding,
    pub(super) descriptors: Vec<NodeDescriptor>,
    pub(super) bindings: Vec<NodeBinding>,
    pub(super) owners: Vec<OwnerBinding>,
    pub(super) requirements: ScenarioRequirements,
    pub(super) content: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) construction_rows: BTreeMap<ContentRef, Vec<ContentRef>>,
    pub(super) activation: ActivationRecord,
    pub(super) host: ContentRef,
    pub(super) installation: ContentRef,
    pub(super) history: Rc<InspectedReaderHistory>,
}

impl ConditionalProfile {
    /// Rebinds only live authority beneath the same authenticated capture world.
    pub(super) fn fresh_target(
        &self,
        source: &PinnedOriginalLineageSource,
        branch: &str,
    ) -> Result<Self, InspectionError> {
        if branch.is_empty()
            || source.runtime().source_activation
                != crucible::node_contract::SavedRuntimeActivation::from(&self.activation)
            || source.runtime().capture_cut
                != Position::new(U64::new(2000), U64::new(0), Phase::BoundaryControl)
            || source.runtime().source_activation.world_binding_hash
                != self.world.identity().map_err(text)?
        {
            return Err("fresh target does not retain the actual source capture".into());
        }
        if source.content().object_count() > 4096
            || source.content().total_bytes() > 384 * 1024 * 1024
            || source
                .original_objects()
                .any(|(_, body)| body.len() > 256 * 1024 * 1024)
        {
            return Err("complete owned source exceeds declared archive geometry".into());
        }
        let bytes = self.content.values().try_fold(0usize, |total, body| {
            total
                .checked_add(body.len())
                .filter(|n| *n <= 64 * 1024 * 1024)
        });
        let edges = self
            .construction_rows
            .values()
            .try_fold(0usize, |total, row| {
                total.checked_add(row.len()).filter(|n| *n <= 65_536)
            });
        if bytes.is_none()
            || edges.is_none_or(|n| n > 65_536 - 12)
            || self.content.len() > 4096 - 6
            || self.bindings.len() != 3
            || self.activation.owners.len() != 3
        {
            return Err("fresh target metadata copy exceeds declared credit".into());
        }
        let actual = crucible_node_provider::conformance::measure_executable(std::path::Path::new(
            "/proc/self/exe",
        ))
        .map_err(text)?;
        if actual != self.host {
            return Err("fresh target reconstruction executable changed".into());
        }

        // Derived live identities are validated before any retained-body clone.
        if branch.len() > 64
            || !branch
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("fresh target branch exceeds its finite identity grammar".into());
        }
        Id::new(format!("conditional/{branch}/activation")).map_err(text)?;
        Id::new(format!("conditional/{branch}/session")).map_err(text)?;
        for binding in &self.bindings {
            let node = &binding.compatibility.node_id;
            for role in ["incarnation", "realization", "input"] {
                Id::new(format!("conditional/{branch}/{node}/{role}")).map_err(text)?;
            }
        }

        let mut content = self.content.clone();
        let mut construction_rows = self.construction_rows.clone();
        let mut bindings = self.bindings.clone();
        let mut owners = Vec::new();
        owners.try_reserve_exact(3).map_err(text)?;
        for binding in &mut bindings {
            let node = &binding.compatibility.node_id;
            let prior = self
                .activation
                .owners
                .iter()
                .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .ok_or("fresh target original owner absent")?;
            let owner = OwnerIdentity {
                owner: prior.owner.clone(),
                incarnation: Id::new(format!("conditional/{branch}/{node}/incarnation"))
                    .map_err(text)?,
                generation: prior.generation.checked_add(U64::new(1)).map_err(text)?,
            };
            let enrollment = put_json(
                &mut content,
                &serde_json::json!({
                    "schema":"crucible.reader-conditional-model-enrollment.v1",
                    "host":self.host,"model":self.installation,"owner":owner,
                    "cursor":source.runtime().capture_cut,
                }),
            )?;
            record_edges(
                &mut construction_rows,
                &enrollment,
                vec![self.host.clone(), self.installation.clone()],
            )?;
            binding.authority = LiveAuthority {
                schema_version: 1,
                session_id: Id::new(format!("conditional/{branch}/session")).map_err(text)?,
                incarnation_id: owner.incarnation.clone(),
                realization_id: Id::new(format!("conditional/{branch}/{node}/realization"))
                    .map_err(text)?,
                activation_id: None,
                world_generation: U64::new(0),
                owner_generation: owner.generation,
                input_epoch: Id::new(format!("conditional/{branch}/{node}/input")).map_err(text)?,
                host_receipt: enrollment,
                extensions: Extensions::new(),
            };
            let complete = put_json(&mut content, binding)?;
            let compatibility = put_json(&mut content, &binding.compatibility)?;
            record_edges(
                &mut construction_rows,
                &complete,
                vec![compatibility, binding.authority.host_receipt.clone()],
            )?;
            owners.push(owner);
        }
        owners.sort();
        let activation = ActivationRecord {
            generation: self
                .activation
                .generation
                .checked_add(U64::new(1))
                .map_err(text)?,
            activation_id: Id::new(format!("conditional/{branch}/activation")).map_err(text)?,
            world_binding_hash: self.activation.world_binding_hash.clone(),
            owners,
            boundary: source.runtime().capture_cut,
        };
        Ok(Self {
            world: self.world.clone(),
            descriptors: self.descriptors.clone(),
            bindings,
            owners: self.owners.clone(),
            requirements: self.requirements.clone(),
            content,
            construction_rows,
            activation,
            host: self.host.clone(),
            installation: self.installation.clone(),
            history: Rc::clone(&self.history),
        })
    }

    /// Pins the original world and every owner body before the model substitution.
    ///
    /// Fresh branch identity is confined to live authority and activation fields.
    /// It cannot change the durable world shared by the capture and both targets.
    pub(super) fn build(
        history: Rc<InspectedReaderHistory>,
        original_world: &WorldBinding,
        original_descriptors: &[NodeDescriptor],
        original_owners: &[OwnerBinding],
        host: ContentRef,
        branch: &str,
        captured: Option<&PinnedOriginalLineageSource>,
    ) -> Result<Self, InspectionError> {
        let source = history
            .originals
            .values()
            .next()
            .ok_or("original roster absent")?;
        let source_activation = &source.transcript().origin.activation;
        let body_credit = history.objects.values().try_fold(0usize, |total, body| {
            total
                .checked_add(body.len())
                .ok_or("source content extent overflow")
        })?;
        history
            .originals
            .values()
            .try_fold(body_credit, |total, tape| {
                let total = total
                    .checked_add(tape.bytes().len())
                    .filter(|total| *total <= 384 * 1024 * 1024)
                    .ok_or("original tape and context closure exceeds unique archive credit")?;
                tape.transcript()
                    .origin
                    .context
                    .iter()
                    .try_fold(total, |total, object| {
                        total
                            .checked_add(object.bytes.len())
                            .filter(|total| *total <= 384 * 1024 * 1024)
                            .ok_or("raw original context exceeds archive copy credit")
                    })
            })?;
        let mut content = history.objects.clone();
        let mut construction_rows = BTreeMap::new();
        // Qualification proofs bind this exact canonical original origin. Its
        // standalone body is retained before any model callback; the original
        // authenticated tape remains the source of these historical bytes.
        for original in history.originals.values() {
            // Materialized context keeps the reconstructed semantic body; the
            // signed origin also owns the original fragment envelope and bytes.
            for object in &original.transcript().origin.context {
                retain(&mut content, &object.reference, &object.bytes)?;
            }
            let bytes = encode(&original.transcript().origin)?;
            let reference = crucible::node_adapters::transcript::context_commitment(
                &original.transcript().origin,
            )
            .map_err(text)?;
            retain(&mut content, &reference, &bytes)?;
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(original.transcript().origin.context.len() + 1)
                .map_err(text)?;
            dependencies.push(original.transcript().origin.source_binding.clone());
            dependencies.extend(
                original
                    .transcript()
                    .origin
                    .context
                    .iter()
                    .map(|object| object.reference.clone()),
            );
            record_edges(&mut construction_rows, &reference, dependencies)?;

            // The signed source byte wire embeds each control request/response.
            // Their hashes are original byte attestations, not external reads.
            // Installed proof/context validators do dereference these standalone
            // bodies, so the tape retains their explicit positive adjacency.
            retain(&mut content, original.reference(), original.bytes())?;
            let count =
                original
                    .transcript()
                    .records
                    .iter()
                    .try_fold(1usize, |count, record| {
                        count
                            .checked_add(record.evidence.len())
                            .filter(|count| *count <= 4096)
                            .ok_or("original tape evidence adjacency exceeds role credit")
                    })?;
            let mut dependencies = Vec::new();
            dependencies.try_reserve_exact(count).map_err(text)?;
            dependencies.push(reference);
            for record in &original.transcript().records {
                dependencies.extend(
                    record
                        .evidence
                        .iter()
                        .map(|object| object.reference.clone()),
                );
            }
            record_edges(&mut construction_rows, original.reference(), dependencies)?;
        }
        require_original_body(&content, original_world)?;
        if original_world.identity().map_err(text)? != source_activation.world_binding_hash
            || original_world.node_bindings.len() != 3
            || original_descriptors.len() != 3
            || original_owners.len() != 3
            || branch.is_empty()
        {
            return Err("conditional source world or branch scope differs".into());
        }

        let host_actual = crucible_node_provider::conformance::measure_executable(
            std::path::Path::new("/proc/self/exe"),
        )
        .map_err(text)?;
        if host != host_actual {
            return Err("conditional host is not the actual fixture executable".into());
        }
        for owner in original_owners {
            require_original_body(&content, owner)?;
        }
        let declaration = put_json(
            &mut content,
            &serde_json::json!({
                "schema":"crucible.installed-reader-conditional-model.v1",
                "source_world":original_world.identity().map_err(text)?,
                "source_tapes":history.originals.iter().map(|(node, tape)| (node,tape.reference())).collect::<Vec<_>>(),
                "host":host,
                "contracts":[TRANSCRIPT_REPLAY_PROFILE, TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE,
                    TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE],
                "scope":"exact original requests, native input/body/FIFO relations and time assignments; complete conditional Runtime7 and Scheduling1; original nondeterminism remains; no physical fallback",
            }),
        )?;
        record_edges(
            &mut construction_rows,
            &declaration,
            std::iter::once(host.clone())
                .chain(
                    history
                        .originals
                        .values()
                        .map(|tape| tape.reference().clone()),
                )
                .collect(),
        )?;
        let schema = original_lineage_continuation_schema().map_err(|error| error.reason)?;
        retain(
            &mut content,
            &schema.definition,
            original_lineage_continuation_definition(),
        )?;
        // This exact selected schema document is reconstruction code data. Its
        // format names are scalar declarations, not deferred object reads.
        record_edges(&mut construction_rows, &schema.definition, Vec::new())?;

        let mut bindings = Vec::new();
        let mut descriptors = Vec::new();
        let mut operational_owners = Vec::new();
        for (node, original) in &history.bindings {
            let expected = NodeBindingRef {
                node_id: node.clone(),
                binding_hash: original.compatibility.identity().map_err(text)?,
                extensions: Extensions::new(),
            };
            if !original_world.node_bindings.contains(&expected) {
                return Err("original world omits its authenticated binding".into());
            }
            let mut selected = original.compatibility.clone();
            let mut descriptor = original_descriptors
                .iter()
                .find(|descriptor| descriptor.id == *node)
                .ok_or("original descriptor node absent")?
                .clone();
            require_original_body(&content, &descriptor)?;
            if descriptor.identity().map_err(text)? != selected.descriptor_hash {
                return Err("original descriptor body differs".into());
            }
            let original_configuration = selected.configuration_ref.clone();
            let original_initialization = descriptor.initialization_ref.clone();
            let configuration = put_json(
                &mut content,
                &serde_json::json!({
                    "schema":"crucible.reader-conditional-model-configuration.v1",
                    "model":declaration,
                    "original_configuration":selected.configuration_ref,
                    "original_initialization":descriptor.initialization_ref,
                    "original_node":node,
                }),
            )?;
            record_edges(
                &mut construction_rows,
                &configuration,
                vec![
                    declaration.clone(),
                    original_configuration,
                    original_initialization,
                ],
            )?;
            descriptor.extensions = Extensions::new();
            descriptor.configuration_ref = configuration.clone();
            selected.configuration_ref = configuration;
            selected.descriptor_hash = descriptor.identity().map_err(text)?;
            put_json(&mut content, &descriptor)?;
            descriptors.push(descriptor);

            let mut guarantees: GuaranteeProfile = read_json(&content, &selected.guarantees_ref)?;
            if guarantees.repeatability != history.originals[node].transcript().origin.repeatability
            {
                return Err("source nondeterminism changed before model substitution".into());
            }
            guarantees.conditional_replay = true;
            guarantees.capture_scope = CaptureScope::CompleteModel;
            guarantees.continuation = Continuation::Exact;
            guarantees.durable_restart = true;
            guarantees.isolated_fork = false;
            guarantees.limitations_ref = declaration.clone();
            let guarantees_ref = put_json(&mut content, &guarantees)?;
            record_edges(
                &mut construction_rows,
                &guarantees_ref,
                vec![declaration.clone()],
            )?;
            let mut facets = [
                (TRANSCRIPT_REPLAY_PROFILE, 1),
                (TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE, 2),
                (TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE, 2),
            ]
            .into_iter()
            .map(|(name, version)| {
                Ok(FacetSelection {
                    id: Id::new(name).map_err(text)?,
                    version,
                    configuration_ref: declaration.clone(),
                    guarantees_ref: guarantees_ref.clone(),
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<Vec<_>, InspectionError>>()?;
            facets.sort_by(|a, b| (&a.id, a.version).cmp(&(&b.id, b.version)));
            let mut capabilities: CapabilityProfile =
                read_json(&content, &selected.capabilities_ref)?;
            capabilities.facets = facets.clone();
            capabilities.requirements_ref = declaration.clone();
            selected.capabilities_ref = put_json(&mut content, &capabilities)?;
            let mut capability_edges = vec![
                capabilities.devices_ref.clone(),
                capabilities.requirements_ref.clone(),
            ];
            for facet in &capabilities.facets {
                capability_edges.extend([
                    facet.configuration_ref.clone(),
                    facet.guarantees_ref.clone(),
                ]);
            }
            record_edges(
                &mut construction_rows,
                &selected.capabilities_ref,
                capability_edges,
            )?;
            selected.guarantees_ref = guarantees_ref;
            selected.profile_ref = declaration.clone();
            selected.operating_contract.facets = facets;
            selected.qualification_refs = vec![declaration.clone()];
            // The source-selected native extension is retained in the original
            // context. This host model does not select that native handler.
            selected.extensions = Extensions::new();
            selected.implementation.extensions = Extensions::new();
            selected.implementation.implementation_id =
                Id::new("crucible/reader-conditional-model-v1").map_err(text)?;
            selected.implementation.artifacts = vec![ArtifactIdentity {
                id: Id::new("conditional-host").map_err(text)?,
                role: Id::new("conditional-host").map_err(text)?,
                content: host.clone(),
                extensions: Extensions::new(),
            }];
            selected
                .implementation
                .model_definitions
                .push(declaration.clone());
            selected.implementation.model_definitions.sort();
            selected.implementation.model_definitions.dedup();
            if !selected.implementation.formats.contains(&schema) {
                selected.implementation.formats.push(schema.clone());
            }
            selected
                .implementation
                .formats
                .sort_by(|a, b| (&a.id, a.version).cmp(&(&b.id, b.version)));

            let prior_generation = match captured {
                Some(source) => {
                    source
                        .runtime()
                        .source_activation
                        .owners
                        .iter()
                        .find(|owner| owner.owner == selected.execution_owner.id)
                        .ok_or("authenticated source-capture owner absent")?
                        .generation
                }
                None => original.authority.owner_generation,
            };
            let generation = prior_generation.checked_add(U64::new(1)).map_err(text)?;
            let incarnation =
                Id::new(format!("conditional/{branch}/{node}/incarnation")).map_err(text)?;
            let owner = OwnerIdentity {
                owner: selected.execution_owner.id.clone(),
                incarnation: incarnation.clone(),
                generation,
            };
            let enrollment = put_json(
                &mut content,
                &serde_json::json!({
                    "schema":"crucible.reader-conditional-model-enrollment.v1",
                    "host":host,"model":declaration,"owner":owner,"cursor":"0",
                }),
            )?;
            record_edges(
                &mut construction_rows,
                &enrollment,
                vec![host.clone(), declaration.clone()],
            )?;
            bindings.push(NodeBinding {
                compatibility: selected,
                authority: LiveAuthority {
                    schema_version: 1,
                    session_id: Id::new(format!("conditional/{branch}/session")).map_err(text)?,
                    incarnation_id: incarnation,
                    realization_id: Id::new(format!("conditional/{branch}/{node}/realization"))
                        .map_err(text)?,
                    activation_id: None,
                    world_generation: U64::new(0),
                    owner_generation: generation,
                    input_epoch: Id::new(format!("conditional/{branch}/{node}/input"))
                        .map_err(text)?,
                    host_receipt: enrollment,
                    extensions: Extensions::new(),
                },
                extensions: Extensions::new(),
            });
            operational_owners.push(owner);
        }

        // Current qualification proofs name complete binding bytes, including
        // live authority. Keep those exact bodies beside the durable contracts.
        for binding in &bindings {
            let complete = put_json(&mut content, binding)?;
            let compatibility = put_json(&mut content, &binding.compatibility)?;
            record_edges(
                &mut construction_rows,
                &complete,
                vec![compatibility, binding.authority.host_receipt.clone()],
            )?;
        }

        let mut world = original_world.clone();
        world.node_bindings = bindings
            .iter()
            .map(|binding| {
                Ok(NodeBindingRef {
                    node_id: binding.compatibility.node_id.clone(),
                    binding_hash: binding.compatibility.identity().map_err(text)?,
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<_, InspectionError>>()?;
        let mut ownership: OwnershipPolicy = read_json(&content, &world.ownership_ref)?;
        ownership.inventory_proof_ref = declaration.clone();
        for owner in &mut ownership.capture_owners {
            owner.complete_model = true;
            owner.unchanged_cut = true;
            owner.exact_continuation = true;
            owner.durable_restart = true;
            owner.isolated_fork = false;
            owner.cut_procedure_ref = declaration.clone();
        }
        // Exact capture retains each transfer domain together with both of its
        // endpoint owners. This is an explicit whole-model cut obligation; the
        // installed capture policy must still authenticate the actual journals.
        for connection in &world.connections {
            let capture = ownership
                .capture_owners
                .iter_mut()
                .find(|owner| owner.owner_id == connection.capture_owner_id)
                .ok_or("conditional transfer capture owner absent")?;
            for endpoint in [&connection.producer, &connection.consumer] {
                let endpoint_owner = bindings
                    .iter()
                    .find(|binding| binding.compatibility.node_id == endpoint.node_id)
                    .ok_or("conditional transfer endpoint absent")?
                    .compatibility
                    .capture_owner
                    .id
                    .clone();
                if endpoint_owner != capture.owner_id {
                    capture.dependencies.push(endpoint_owner);
                }
            }
            capture.dependencies.sort();
            capture.dependencies.dedup();
        }
        world.ownership_ref = put_json(&mut content, &ownership)?;
        let mut coordinator: CoordinatorPolicy =
            read_json(&content, &world.coordinator_contract_ref)?;
        coordinator.state_closure_ref = declaration.clone();
        coordinator.operational_policy_ref = declaration.clone();
        world.coordinator_contract_ref = put_json(&mut content, &coordinator)?;
        // Exact Stage matching retains the original delivery policy and sampled
        // boundary. The installed host admission independently qualifies this
        // unchanged relation; the original native proof is provenance only.
        for connection in &world.connections {
            let _: ConnectionPolicy = read_json(&content, &connection.policy_ref)?;
        }
        let mut requirements: ScenarioRequirements = read_json(&content, &world.scenario_ref)?;
        requirements.exact_capture = true;
        requirements.exact_continuation = true;
        requirements.durable_restart = true;
        world.scenario_ref = put_json(&mut content, &requirements)?;
        // This exact builder-owned requirement record contains only scalar
        // guarantees and selected IDs; it names no external content roles.
        record_edges(&mut construction_rows, &world.scenario_ref, Vec::new())?;
        let mut owners = original_owners.to_vec();
        for owner in &mut owners {
            owner.node_bindings = world
                .node_bindings
                .iter()
                .filter(|binding| owner.owner.participant_ids.contains(&binding.node_id))
                .cloned()
                .collect();
            owner.ownership_ref = world.ownership_ref.clone();
        }
        // These exact builder-owned encodings precede graph admission. The
        // later projection must match their full references and bytes; it does
        // not supply authority to invent a different original policy encoding.
        put_json(&mut content, &world)?;
        for owner in &owners {
            put_json(&mut content, owner)?;
        }
        for binding in &bindings {
            put_json(&mut content, &binding.compatibility)?;
        }
        operational_owners.sort();
        let world_hash = world.identity().map_err(text)?;
        if captured.is_some_and(|source| {
            source.runtime().source_activation.world_binding_hash != world_hash
        }) {
            return Err(
                "fresh target compatibility differs from authenticated source capture".into(),
            );
        }
        let activation = ActivationRecord {
            generation: match captured {
                Some(source) => source
                    .runtime()
                    .source_activation
                    .generation
                    .checked_add(U64::new(1))
                    .map_err(text)?,
                None => U64::new(1),
            },
            activation_id: Id::new(format!("conditional/{branch}/activation")).map_err(text)?,
            world_binding_hash: world_hash,
            owners: operational_owners,
            boundary: captured.map_or(source_activation.boundary, |source| {
                source.runtime().capture_cut
            }),
        };
        let profile = Self {
            world,
            descriptors,
            bindings,
            owners,
            requirements,
            content,
            construction_rows,
            activation,
            host,
            installation: declaration,
            history,
        };
        super::conditional_capture_records::original_rows(&profile).map_err(text)?;
        Ok(profile)
    }
}

/// Retains explicit construction-time codec roles rather than scanning encoded JSON.
fn record_edges(
    rows: &mut BTreeMap<ContentRef, Vec<ContentRef>>,
    reference: &ContentRef,
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    super::conditional_capture_records::insert(rows, reference.clone(), dependencies).map_err(text)
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>, InspectionError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(text)?).map_err(text)
}

fn require_original_body(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<(), InspectionError> {
    let bytes = encode(value)?;
    let reference = canonical::content_ref(&bytes, "application/json").map_err(text)?;
    if content.get(&reference) != Some(&bytes) {
        return Err("explicit original typed role is absent from authenticated context".into());
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> Result<T, InspectionError> {
    let bytes = content.get(reference).ok_or("original typed body absent")?;
    reference.verify(bytes).map_err(text)?;
    serde_json::from_slice(bytes).map_err(text)
}

fn put_json(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<ContentRef, InspectionError> {
    let bytes = encode(value)?;
    let reference = canonical::content_ref(&bytes, "application/json").map_err(text)?;
    retain(content, &reference, &bytes)?;
    Ok(reference)
}

fn retain(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), InspectionError> {
    reference.verify(bytes).map_err(text)?;
    if content
        .get(reference)
        .is_some_and(|original| original != bytes)
    {
        return Err("conditional model conflicts with an original retained body".into());
    }
    content.insert(reference.clone(), bytes.to_vec());
    Ok(())
}

fn text(error: impl std::fmt::Display) -> InspectionError {
    InspectionError::from_error(error)
}
