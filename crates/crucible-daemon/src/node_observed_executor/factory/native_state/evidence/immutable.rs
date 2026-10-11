//! Supplies installed immutable closure without issuing native capture authority.

use std::collections::BTreeSet;

use crucible::{
    node_contract::{OwnerIdentity, ProgressEvidence, RuntimeSnapshot, SavedRuntimeResult},
    node_scheduling::{SchedulingSnapshot, validate_saved_source},
    node_state::{
        CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateError,
        StateErrorCode, StateRequirements, VerifiedStateContent,
    },
};
use crucible_node_contract::{CaptureManifest, CapturedOwner};

use super::*;

/// Supplies only installed immutable content to the separately authenticated signer.
pub(in crate::node_observed_executor::factory::native_state) struct MixedImmutableEvidence {
    evidence: Rc<MixedEvidence>,
}

impl MixedImmutableEvidence {
    /// Retains the original privately enrolled implementation registry.
    pub(in crate::node_observed_executor::factory::native_state) fn new(
        evidence: Rc<MixedEvidence>,
    ) -> Self {
        Self { evidence }
    }
}

impl CaptureEvidence for MixedImmutableEvidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.evidence
            .immutable_content(reference, maximum)
            .map_err(state_error)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        reference.verify(bytes).map_err(state_error)?;
        if self
            .evidence
            .assets
            .get(&reference.hash.digest)
            .is_some_and(|(expected, _)| expected == reference)
        {
            // Independently measured executable/image bytes are selected leaves;
            // their process and source closure is verified by the native bridge.
            return Ok(Vec::new());
        }
        let original = self
            .evidence
            .scenario
            .content
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| state_error("unsupported mixed immutable dependency format"))?;
        if original.bytes != bytes || bytes.len() > MAXIMUM_CONTENT_BYTES {
            return Err(state_error("original installed metadata differs"));
        }
        if reference.media_type != "application/json" {
            return Ok(Vec::new());
        }

        // This walker is confined to source-generated metadata, never opaque
        // native state or imported proof bodies. Depth and work are bounded
        // independently of the caller's emitted dependency allowance.
        let value = canonical::parse_json(bytes, MAXIMUM_CONTENT_BYTES).map_err(state_error)?;
        let mut stack = vec![(&value, 0usize)];
        let mut visited = 0usize;
        let mut references = Vec::new();
        while let Some((value, depth)) = stack.pop() {
            visited += 1;
            if depth > 64 || visited > 262_144 {
                return Err(state_error(
                    "installed dependency traversal exceeds finite bounds",
                ));
            }
            match value {
                serde_json::Value::Object(object)
                    if object.contains_key("hash")
                        && object.contains_key("length")
                        && object.contains_key("media_type") =>
                {
                    if references.len() >= maximum {
                        return Err(state_error(
                            "installed dependencies exceed original allowance",
                        ));
                    }
                    let dependency: ContentRef =
                        serde_json::from_value(value.clone()).map_err(state_error)?;
                    if !self.evidence.known_immutable_reference(&dependency) {
                        return Err(state_error("selected dependency has no installed source"));
                    }
                    references.try_reserve(1).map_err(state_error)?;
                    references.push(dependency);
                }
                serde_json::Value::Object(object) => {
                    reserve_work(&mut stack, object.len(), visited)?;
                    stack.extend(object.values().map(|value| (value, depth + 1)));
                }
                serde_json::Value::Array(array) => {
                    reserve_work(&mut stack, array.len(), visited)?;
                    stack.extend(array.iter().map(|value| (value, depth + 1)));
                }
                _ => {}
            }
        }
        references.sort();
        references.dedup();
        Ok(references)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(state_error(
            "installed immutable registry cannot issue native capture provenance",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(state_error(
            "installed immutable registry cannot issue coordinator capture provenance",
        ))
    }
}

impl MixedEvidence {
    pub(in crate::node_observed_executor::factory::native_state) fn known_immutable_reference(
        &self,
        reference: &ContentRef,
    ) -> bool {
        self.scenario
            .content
            .iter()
            .any(|object| &object.reference == reference)
            || self
                .assets
                .get(&reference.hash.digest)
                .is_some_and(|(expected, _)| expected == reference)
    }

    /// Authenticates the fixed coordinator scope independently of native owner proofs.
    ///
    /// # Errors
    /// Refuses incompatible worlds, unsupported inputs/transfers/faults, changed
    /// original owner/operation inventories or missing immutable payload closure.
    /// Complete native ledger authentication remains the generic archive's duty.
    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        let world = self.scenario.world.identity().map_err(state_error)?;
        if graph.world_binding_hash() != &world
            || graph.node_ids().count() != 2
            || !self.scenario.world.connections.is_empty()
            || !scheduler.pending_deliveries.is_empty()
            || !scheduler.external_closed_prefixes.is_empty()
            || runtime.schema_version != 1
            || !matches!(scheduler.schema_version, 1 | 2)
            || (scheduler.schema_version == 2
                && !self.scenario.compatibility.iter().all(|binding| {
                    binding.implementation.formats.iter().any(|schema| {
                        matches!(
                            schema.id.as_str(),
                            "crucible/host-public-clock-continuation-v2"
                                | "crucible/gem5-public-native-continuation-v2"
                        )
                    })
                }))
            || runtime.source_activation.world_binding_hash != world
            || scheduler.world_binding_hash != world
            || runtime.source_activation.activation_id != scheduler.source_activation_id
            || runtime.source_activation.generation != scheduler.source_generation
            || runtime.source_activation.boundary != scheduler.source_boundary
            || runtime.capture_cut != scheduler.capture_cut
            || runtime.capture_ordinal != scheduler.capture_ordinal
        {
            return Err(state_error(
                "mixed original coordinator scope or capture cut differs",
            ));
        }
        for original in self.bindings.values() {
            if graph
                .binding(&original.compatibility.node_id)
                .is_none_or(|binding| binding.compatibility != original.compatibility)
                || graph.descriptor(&original.compatibility.node_id)
                    != self
                        .scenario
                        .descriptors
                        .iter()
                        .find(|node| node.id == original.compatibility.node_id)
            {
                return Err(state_error("mixed installed complete graph differs"));
            }
        }
        let policy = graph.ownership_policy();
        if policy.objects.len() != 2
            || policy.domains.len() != 2
            || policy.capture_owners.len() != 2
            || !policy.internal_dependencies.is_empty()
            || policy.capture_owners.iter().any(|owner| {
                !owner.complete_model
                    || !owner.unchanged_cut
                    || !owner.exact_continuation
                    || !owner.dependencies.is_empty()
            })
        {
            return Err(state_error(
                "mixed coordinator has unqualified state domains",
            ));
        }
        validate_saved_source(graph, scheduler).map_err(state_error)?;
        let owners: Vec<_> = scheduler
            .source_owners
            .iter()
            .map(|owner| OwnerIdentity {
                owner: owner.owner.clone(),
                incarnation: owner.incarnation.clone(),
                generation: owner.generation,
            })
            .collect();
        if runtime.source_activation.owners != owners
            || runtime
                .owners
                .iter()
                .map(|owner| &owner.identity)
                .ne(owners.iter())
            || owners.len() != 2
        {
            return Err(state_error(
                "mixed complete original runtime owner roster differs",
            ));
        }
        for owner in &runtime.owners {
            if graph
                .owner(&owner.identity.owner)
                .is_none_or(|binding| binding.owner.state_domain_ids != owner.domains)
            {
                return Err(state_error("mixed runtime domain inventory differs"));
            }
        }
        for reference in [
            &self.scenario.world.scenario_ref,
            &self.scenario.world.initialization_ref,
            &self.scenario.world.ownership_ref,
            &self.scenario.world.coordinator_contract_ref,
        ] {
            verified(content, reference)?;
        }
        for payload in &scheduler.payload_objects {
            if verified(content, &payload.reference)? != payload.bytes {
                return Err(state_error("mixed original retained payload differs"));
            }
        }
        let mut operations = BTreeSet::new();
        for operation in &runtime.operations {
            let binding = graph
                .binding(&operation.route.node)
                .ok_or_else(|| state_error("mixed runtime operation has foreign node"))?;
            let owner = owners
                .iter()
                .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .ok_or_else(|| state_error("mixed original operation owner absent"))?;
            if !operations.insert(&operation.operation)
                || operation.route.owners.as_slice() != std::slice::from_ref(owner)
                || !scheduler.used_operations.contains(&operation.operation)
            {
                return Err(state_error(
                    "mixed original operation identity or owner differs",
                ));
            }
            if let SavedRuntimeResult::Complete(outcome)
            | SavedRuntimeResult::Acknowledged(outcome) = &operation.result
            {
                if outcome.operation != operation.operation
                    || outcome.node != operation.route.node
                    || outcome.owners != operation.route.owners
                    || matches!(outcome.progress, ProgressEvidence::Quantized { .. })
                {
                    return Err(state_error(
                        "mixed original outcome differs from retained operation",
                    ));
                }
                if let Some(observation) = &outcome.scheduling {
                    if observation.node != outcome.node
                        || observation.owners != outcome.owners
                        || !observation.external_inputs.is_empty()
                    {
                        return Err(state_error(
                            "mixed native observation introduced foreign input authority",
                        ));
                    }
                    verified(content, &observation.proof_ref)?;
                    for bound in &observation.bounds {
                        verified(content, &bound.proof_ref)?;
                    }
                    for publication in &observation.publications {
                        if publication.endpoint.node_id.as_str() != "cpu"
                            || publication.endpoint.port_id.as_str() != "stdout"
                            || publication.endpoint.lane_id.as_str() != "output"
                            || !publication.causal_parents.is_empty()
                            || verified(content, &publication.payload)? != publication.payload_bytes
                        {
                            return Err(state_error("mixed original publication payload differs"));
                        }
                    }
                    if let Some(input) = &observation.input_progress {
                        if !input.consumed.is_empty() {
                            return Err(state_error(
                                "closed mixed native claimed public input consumption",
                            ));
                        }
                        verified(content, &input.proof_ref)?;
                    }
                }
            }
        }
        for input in &runtime.inputs {
            if !input.deliveries.is_empty() || !input.payloads.is_empty() {
                return Err(state_error(
                    "closed mixed world contains an unqualified native input",
                ));
            }
            verified(content, &input.inventory)?;
            if let Some(acknowledgement) = &input.acknowledgement {
                verified(content, &acknowledgement.proof_ref)?;
            }
        }
        for batch in &scheduler.input_batches {
            let input = runtime
                .inputs
                .iter()
                .find(|input| input.stage_operation == batch.stage_operation)
                .ok_or_else(|| state_error("mixed original native input custody omitted"))?;
            if input.node != batch.node
                || input.batch != batch.batch
                || input.owners != batch.owners
                || input.cutoff != batch.cutoff
                || input.inventory != batch.inventory
                || input.deliveries != batch.deliveries
                || input.payloads != batch.payloads
                || input.acknowledgement != batch.acknowledgement
                || !batch.consumed.is_empty()
            {
                return Err(state_error("mixed original native input inventory changed"));
            }
        }
        Ok(())
    }
}

fn reserve_work<T>(stack: &mut Vec<T>, count: usize, visited: usize) -> Result<(), StateError> {
    if stack
        .len()
        .checked_add(count)
        .and_then(|count| count.checked_add(visited))
        .is_none_or(|count| count > 262_144)
    {
        return Err(state_error(
            "mixed dependency pending work exceeds finite allowance",
        ));
    }
    stack.try_reserve(count).map_err(state_error)
}

fn verified<'a>(
    content: &'a VerifiedStateContent,
    reference: &ContentRef,
) -> Result<&'a [u8], StateError> {
    let bytes = content
        .get(reference)
        .ok_or_else(|| state_error("mixed signed original content is absent"))?;
    reference.verify(bytes).map_err(state_error)?;
    Ok(bytes)
}

fn state_error(reason: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed mixed coordinator",
        reason.to_string(),
    )
}
