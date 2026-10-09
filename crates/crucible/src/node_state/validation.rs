//! Whole-world capture admission against actual immutable realized bindings.

use std::collections::BTreeSet;

use crucible_node_contract::{
    CaptureManifest, CaptureRepresentation, CaptureScope, ContentRef, Continuation, Id,
    Repeatability, Validate, canonical,
};

use crate::node_admission::{AdmittedGraph, ObjectState};
use crate::node_contract::{OwnerIdentity, PreparedRuntimeRestore, RuntimeLimits};
use crate::node_scheduling::SchedulingSnapshot;

use super::closure::{bounded_record, core_references, limit};
use super::{
    CaptureEvidence, StateError, StateErrorCode, StateLimits, StateRequirements, StateRestoreMode,
    VerifiedStateContent, schema,
};

/// Seals authenticated complete world state without minting live restore authority.
///
/// Instances originate only from [`admit_capture`]. The source-incarnation roster
/// is retained for rejection of saved live authority; it is never an execution
/// token. Native resource custody is acquired separately during restoration.
#[derive(Debug)]
pub struct VerifiedCapture {
    pub(super) manifest: CaptureManifest,
    pub(super) artifact: ContentRef,
    pub(super) content: VerifiedStateContent,
    pub(super) source_owners: Vec<OwnerIdentity>,
    pub(super) scheduler: SchedulingSnapshot,
    pub(super) runtime: crate::node_contract::RuntimeSnapshot,
    pub(super) requirements: StateRequirements,
    pub(super) repeatability: Repeatability,
    pub(super) pending_native_acknowledgements: Vec<Id>,
}

impl VerifiedCapture {
    /// Returns the immutable complete capture record that passed native validation.
    pub fn manifest(&self) -> &CaptureManifest {
        &self.manifest
    }

    /// Returns the authenticated canonical manifest content identity.
    pub fn artifact(&self) -> &ContentRef {
        &self.artifact
    }

    /// Borrows authenticated closure content for the qualified native adapter.
    pub fn content(&self) -> &VerifiedStateContent {
        &self.content
    }

    /// Returns the required explicit reconstruction strategy.
    pub fn restore_mode(&self) -> StateRestoreMode {
        self.requirements.restore_mode
    }

    /// Reports authenticated graph-wide repeatability without upgrading exact state.
    pub fn world_repeatability(&self) -> Repeatability {
        self.repeatability
    }

    /// Borrows original operations requiring native acknowledgement ledger restoration.
    pub fn pending_native_acknowledgements(&self) -> &[Id] {
        &self.pending_native_acknowledgements
    }
}

/// Verifies a canonical artifact, complete ownership and actual native state proofs.
///
/// # Errors
/// Rejects malformed or noncanonical manifests, changed actual bindings/models,
/// missing owners/domains/dependencies, unsupported schema/fidelity, false
/// determinism claims, retained sources in durable mode, unavailable/corrupt
/// content, resource excess, or failed native/coordinator proof. Admission does
/// not stage resources, mutate a native owner, or grant execution.
pub fn admit_capture(
    graph: &AdmittedGraph,
    artifact: &ContentRef,
    requirements: StateRequirements,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
) -> Result<VerifiedCapture, StateError> {
    admit_capture_with_inventory(
        graph,
        artifact,
        requirements,
        evidence,
        limits,
        super::closure::ContentInventoryEdition::Legacy,
    )
}

pub(super) fn admit_capture_with_inventory(
    graph: &AdmittedGraph,
    artifact: &ContentRef,
    requirements: StateRequirements,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
    edition: super::closure::ContentInventoryEdition,
) -> Result<VerifiedCapture, StateError> {
    admit_capture_with_selected_graph(
        graph,
        artifact,
        requirements,
        evidence,
        limits,
        edition,
        None,
    )
}

pub(crate) fn admit_capture_with_selected_graph(
    graph: &AdmittedGraph,
    artifact: &ContentRef,
    requirements: StateRequirements,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
    edition: super::closure::ContentInventoryEdition,
    selected: Option<&super::native::extensions::SelectedGraphReferences>,
) -> Result<VerifiedCapture, StateError> {
    if selected.is_some() && edition != super::closure::ContentInventoryEdition::Typed {
        return Err(incompatible(
            "selected closure",
            "selected semantics require typed inventory two",
        ));
    }
    artifact.validate().map_err(schema)?;
    let length = usize::try_from(artifact.length.get()).map_err(|_| limit("manifest bytes"))?;
    if length > limits.maximum_record_bytes || length > limits.maximum_total_content_bytes {
        return Err(limit("manifest bytes"));
    }
    let bytes = evidence.content(artifact, length)?;
    artifact
        .verify(&bytes)
        .map_err(|error| StateError::new(StateErrorCode::Content, "manifest", error.to_string()))?;
    let value = canonical::parse_json(&bytes, limits.maximum_record_bytes).map_err(schema)?;
    if canonical::canonical_json(&value).map_err(schema)? != bytes {
        return Err(StateError::new(
            StateErrorCode::Schema,
            "manifest",
            "artifact must use canonical JSON",
        ));
    }
    let manifest: CaptureManifest =
        canonical::decode(&bytes, limits.maximum_record_bytes).map_err(schema)?;
    validate_manifest(graph, &manifest, &requirements, limits)?;

    let mut roots = core_references(&manifest, limits.maximum_record_bytes)?;
    roots.push(artifact.clone());
    let immutable = if let Some(selected) = selected {
        selected.verify(graph, limits)?;
        selected.roots().to_vec()
    } else {
        required_immutable_refs(graph, limits)?
    };
    if immutable
        .iter()
        .any(|reference| !manifest.immutable_refs.contains(reference))
    {
        return Err(incomplete(
            "immutable inputs",
            "capture omits a realized reconstruction dependency",
        ));
    }
    roots.extend(immutable);
    let content = super::closure::verify_closure_with_edition(roots, evidence, limits, edition)?;
    for owner in &manifest.owners {
        let proof =
            evidence.verify_owner_capture(graph, &manifest, owner, &requirements, &content)?;
        if proof.owner_id != owner.capture_owner_id
            || proof.state_domain_ids != owner.state_domain_ids
            || proof.cut != manifest.cut
            || proof.event_ordinal != manifest.event_ordinal
        {
            return Err(incomplete(
                owner.capture_owner_id.as_str(),
                "authenticated native proof does not cover the exact manifest cut and domains",
            ));
        }
    }
    let proof = evidence.verify_coordinator_capture(graph, &manifest, &content)?;
    bounded_record(&proof.runtime, limits.maximum_record_bytes)?;
    if proof.runtime.pending_acknowledgements() != proof.pending_native_acknowledgements
        || proof.runtime.capture_cut != manifest.cut
        || proof.runtime.capture_ordinal != manifest.event_ordinal
    {
        return Err(incomplete(
            "runtime ledger",
            "authenticated runtime cut or native custody inventory differs",
        ));
    }
    if proof.pending_native_acknowledgements.len() > limits.maximum_content_objects {
        return Err(limit("native acknowledgement ledger"));
    }
    for operation in &proof.pending_native_acknowledgements {
        operation.validate().map_err(schema)?;
    }
    if proof
        .pending_native_acknowledgements
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || proof
            .pending_native_acknowledgements
            .iter()
            .any(|operation| !proof.scheduler.used_operations.contains(operation))
    {
        return Err(incomplete(
            "native acknowledgement ledger",
            "pending original custody is unordered, duplicated or absent from used operations",
        ));
    }
    bounded_record(&proof.scheduler, limits.maximum_record_bytes)?;
    if proof.world_repeatability != graph.world_repeatability()
        || proof.scheduler.schema_version != 1
        || proof.scheduler.ordering_profile != manifest.ordering_profile
        || proof.scheduler.source_generation.get() == 0
        || proof.scheduler.world_binding_hash != manifest.world_binding_hash
        || proof.scheduler.capture_cut != manifest.cut
        || proof.scheduler.capture_ordinal != manifest.event_ordinal
    {
        return Err(incomplete(
            "coordinator",
            "native provenance, guarantees or scheduler cut differs",
        ));
    }
    let graph_owners: Vec<_> = graph.owners().map(|owner| owner.owner.id.clone()).collect();
    let proof_owners: Vec<_> = proof
        .source_owners
        .iter()
        .map(|owner| owner.owner.clone())
        .collect();
    let scheduler_owners: Vec<_> = proof
        .scheduler
        .source_owners
        .iter()
        .map(|owner| OwnerIdentity {
            owner: owner.owner.clone(),
            incarnation: owner.incarnation.clone(),
            generation: owner.generation,
        })
        .collect();
    if proof_owners != graph_owners
        || proof.source_owners != scheduler_owners
        || proof
            .source_owners
            .iter()
            .any(|owner| owner.generation.get() == 0)
    {
        return Err(incomplete(
            "source provenance",
            "complete authenticated source roster differs from scheduler continuation",
        ));
    }
    PreparedRuntimeRestore::validate_source(
        graph,
        &proof.scheduler,
        &proof.runtime,
        RuntimeLimits {
            maximum_nodes: graph.node_ids().count(),
            maximum_owners: limits.maximum_owners_or_domains,
            ..RuntimeLimits::default()
        },
        limits.maximum_record_bytes,
    )
    .map_err(|error| incomplete("runtime continuation", &error.to_string()))?;
    crate::node_scheduling::validate_saved_source(graph, &proof.scheduler)
        .map_err(|error| incomplete("coordinator continuation", &error.to_string()))?;

    Ok(VerifiedCapture {
        manifest,
        artifact: artifact.clone(),
        content,
        source_owners: proof.source_owners,
        scheduler: proof.scheduler,
        runtime: proof.runtime,
        requirements,
        repeatability: proof.world_repeatability,
        pending_native_acknowledgements: proof.pending_native_acknowledgements,
    })
}

pub(super) fn validate_manifest(
    graph: &AdmittedGraph,
    manifest: &CaptureManifest,
    requirements: &StateRequirements,
    limits: StateLimits,
) -> Result<(), StateError> {
    manifest.validate().map_err(schema)?;
    if manifest.world_binding_hash != *graph.world_binding_hash()
        || manifest.scenario_ref != graph.world().scenario_ref
        || manifest.ordering_profile != graph.world().ordering_profile
        || manifest.preservation_contract != requirements.preservation_contract
    {
        return Err(incompatible(
            "world",
            "scenario, actual binding, ordering or selected preservation contract differs",
        ));
    }
    let policy = graph.ownership_policy();
    if manifest.owners.len() > limits.maximum_owners_or_domains
        || policy.domains.len() > limits.maximum_owners_or_domains
    {
        return Err(limit("state owner/domain roster"));
    }
    if (graph.requirements().exact_capture || graph.requirements().exact_continuation)
        && !requirements.exact_model_continuation
    {
        return Err(incompatible(
            "fidelity",
            "capture cannot weaken the admitted scenario preservation requirement",
        ));
    }
    if requirements.deterministic && graph.world_repeatability() != Repeatability::Qualified {
        return Err(incompatible(
            "repeatability",
            "one nondeterministic or unqualified node taints the complete world",
        ));
    }
    if requirements.exact_model_continuation
        && policy.objects.iter().any(|object| {
            object.future_affecting && matches!(object.state, ObjectState::OutsideScope)
        })
    {
        return Err(incomplete(
            "model inventory",
            "future-affecting object lies outside exact capture scope",
        ));
    }

    let expected: Vec<_> = graph
        .owners()
        .filter(|owner| {
            owner
                .owner_roles
                .iter()
                .any(|role| role.as_str() == "capture")
        })
        .map(|owner| owner.owner.id.clone())
        .collect();
    let actual: Vec<_> = manifest
        .owners
        .iter()
        .map(|owner| owner.capture_owner_id.clone())
        .collect();
    if expected != actual {
        return Err(incomplete(
            "capture owners",
            "complete authoritative owner roster differs",
        ));
    }
    let mut seen_domains = BTreeSet::new();
    for owner in &manifest.owners {
        let expected = graph
            .owner(&owner.capture_owner_id)
            .ok_or_else(|| incomplete("capture owner", "owner not admitted"))?;
        let capture_policy = policy
            .capture_owners
            .iter()
            .find(|entry| entry.owner_id == owner.capture_owner_id)
            .ok_or_else(|| {
                incomplete(
                    owner.capture_owner_id.as_str(),
                    "no admitted capture procedure",
                )
            })?;
        let authoritative_domains: Vec<_> = policy
            .domains
            .iter()
            .filter(|domain| domain.capture_owner_id == owner.capture_owner_id)
            .map(|domain| domain.id.clone())
            .collect();
        if owner.participant_ids != expected.owner.participant_ids
            || owner.state_domain_ids != authoritative_domains
            || owner.dependencies != capture_policy.dependencies
        {
            return Err(incomplete(
                owner.capture_owner_id.as_str(),
                "participant, state-domain or dependency roster differs",
            ));
        }
        let mut hashes: Vec<_> = expected
            .node_bindings
            .iter()
            .map(|binding| binding.binding_hash.clone())
            .collect();
        hashes.sort();
        if owner.binding_hashes != hashes {
            return Err(incompatible(
                owner.capture_owner_id.as_str(),
                "actual implementation/model/profile binding differs",
            ));
        }
        for domain in &owner.state_domain_ids {
            if !seen_domains.insert(domain.clone())
                || !policy.domains.iter().any(|entry| {
                    entry.id == *domain && entry.capture_owner_id == owner.capture_owner_id
                })
            {
                return Err(incomplete(
                    domain.as_str(),
                    "mutable domain is duplicated, unknown or owned by another owner",
                ));
            }
        }
        if owner
            .dependencies
            .iter()
            .any(|dependency| !actual.contains(dependency))
        {
            return Err(incomplete(
                owner.capture_owner_id.as_str(),
                "capture dependency has no authoritative artifact",
            ));
        }
        if requirements.exact_model_continuation
            && !(capture_policy.complete_model
                && capture_policy.unchanged_cut
                && capture_policy.exact_continuation)
        {
            return Err(incompatible(
                owner.capture_owner_id.as_str(),
                "owner cannot preserve complete unchanged modeled continuation",
            ));
        }
        match requirements.restore_mode {
            StateRestoreMode::DurableRestart
                if owner.representation != CaptureRepresentation::Durable
                    || !capture_policy.durable_restart =>
            {
                return Err(incompatible(
                    owner.capture_owner_id.as_str(),
                    "durable restart refuses retained or source-dependent state",
                ));
            }
            StateRestoreMode::LiveFork if !capture_policy.isolated_fork => {
                return Err(incompatible(
                    owner.capture_owner_id.as_str(),
                    "isolated live branching is not qualified",
                ));
            }
            _ => {}
        }
        for participant in &owner.participant_ids {
            let binding = graph
                .binding(participant)
                .ok_or_else(|| incomplete(participant.as_str(), "actual binding absent"))?;
            let guarantees = graph
                .guarantees(participant)
                .ok_or_else(|| incomplete(participant.as_str(), "actual guarantees absent"))?;
            if !binding
                .compatibility
                .implementation
                .formats
                .contains(&owner.state_schema)
            {
                return Err(incompatible(
                    participant.as_str(),
                    "native state schema is not supported by the actual implementation",
                ));
            }
            if requirements.exact_model_continuation
                && (guarantees.capture_scope != CaptureScope::CompleteModel
                    || guarantees.continuation != Continuation::Exact)
            {
                return Err(incompatible(
                    participant.as_str(),
                    "selected node guarantee does not cover exact modeled continuation",
                ));
            }
            if (requirements.restore_mode == StateRestoreMode::DurableRestart
                && !guarantees.durable_restart)
                || (requirements.restore_mode == StateRestoreMode::LiveFork
                    && !guarantees.isolated_fork)
            {
                return Err(incompatible(
                    participant.as_str(),
                    "selected node lacks the requested reconstruction guarantee",
                ));
            }
        }
    }
    if seen_domains
        != policy
            .domains
            .iter()
            .map(|domain| domain.id.clone())
            .collect()
    {
        return Err(incomplete(
            "mutable domains",
            "world artifact does not preserve every authoritative domain exactly once",
        ));
    }
    Ok(())
}

pub(super) fn required_immutable_refs(
    graph: &AdmittedGraph,
    limits: StateLimits,
) -> Result<Vec<ContentRef>, StateError> {
    let mut references = core_references(graph.world(), limits.maximum_record_bytes)?;
    for owner in graph.owners() {
        references.extend(core_references(owner, limits.maximum_record_bytes)?);
        if references.len() > limits.maximum_content_objects {
            return Err(limit("immutable owner references"));
        }
    }
    for id in graph.node_ids() {
        let binding = graph
            .binding(id)
            .ok_or_else(|| incomplete(id.as_str(), "missing admitted binding"))?;
        references.extend(core_references(
            &binding.compatibility,
            limits.maximum_record_bytes,
        )?);
        let descriptor = graph
            .descriptor(id)
            .ok_or_else(|| incomplete(id.as_str(), "missing admitted descriptor"))?;
        references.extend(core_references(descriptor, limits.maximum_record_bytes)?);
        if references.len() > limits.maximum_content_objects {
            return Err(limit("immutable input references"));
        }
    }
    references.extend(core_references(
        graph.ownership_policy(),
        limits.maximum_record_bytes,
    )?);
    references.extend(core_references(
        graph.coordinator_policy(),
        limits.maximum_record_bytes,
    )?);
    references.sort();
    references.dedup();
    Ok(references)
}

pub(super) fn incompatible(component: &str, reason: &str) -> StateError {
    StateError::new(StateErrorCode::Incompatible, component, reason)
}

pub(super) fn incomplete(component: &str, reason: &str) -> StateError {
    StateError::new(StateErrorCode::IncompleteClosure, component, reason)
}
