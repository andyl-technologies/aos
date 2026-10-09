//! Validates complete actual rosters, node selections, and bound guarantee content.

use std::collections::BTreeMap;

use crucible_node_contract::{
    CapabilityProfile, CaptureScope, Continuation, ContractError, GuaranteeProfile, Id,
    OperatingMode, Repeatability, Validate,
};

use super::error::refuse;
use super::evidence::{AdmissionLimits, VerifiedContent, bounded_core};
use super::{
    AdmissionCode, AdmissionError, AdmissionRequest, AdmissionStage, AdmissionSubject,
    QualificationClaim,
};
use crate::node_scheduling::ExecutionPolicy;

pub(super) struct NodeSelections {
    pub guarantees: BTreeMap<Id, GuaranteeProfile>,
    pub operating_policies: BTreeMap<Id, ExecutionPolicy>,
}

pub(super) fn schema_error(error: ContractError) -> AdmissionError {
    refuse(
        AdmissionStage::Parse,
        AdmissionSubject::World,
        AdmissionCode::InvalidSchema,
        "valid closed core schema",
        error.to_string(),
    )
}

pub(super) fn ordered_ids<'a>(
    ids: impl Iterator<Item = &'a Id>,
    maximum: usize,
) -> Result<(), AdmissionError> {
    let mut previous = None;
    let mut count = 0usize;
    for id in ids {
        if previous.is_some_and(|previous: &Id| previous >= id) {
            return Err(refuse(
                AdmissionStage::Parse,
                AdmissionSubject::World,
                AdmissionCode::InvalidSchema,
                "strictly sorted duplicate-free identity roster",
                "duplicate or unsorted identity",
            ));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| limit_error("identity count overflow"))?;
        if count > maximum {
            return Err(limit_error("identity roster exceeds admitted ceiling"));
        }
        previous = Some(id);
    }
    Ok(())
}

fn limit_error(observed: &str) -> AdmissionError {
    refuse(
        AdmissionStage::Parse,
        AdmissionSubject::World,
        AdmissionCode::BoundMismatch,
        "finite graph within admitted allocation ceilings",
        observed,
    )
}

pub(super) fn check_core(
    request: &AdmissionRequest<'_>,
    limits: AdmissionLimits,
) -> Result<(), AdmissionError> {
    if request.descriptors.is_empty() {
        return Err(limit_error(
            "empty world has no admitted public-node roster",
        ));
    }
    ordered_ids(
        request.descriptors.iter().map(|node| &node.id),
        limits.maximum_nodes,
    )?;
    ordered_ids(
        request
            .bindings
            .iter()
            .map(|binding| &binding.compatibility.node_id),
        limits.maximum_nodes,
    )?;
    ordered_ids(
        request.owners.iter().map(|owner| &owner.owner.id),
        limits.maximum_owners,
    )?;
    if request.world.node_bindings.len() != request.descriptors.len()
        || request.bindings.len() != request.descriptors.len()
        || request.world.connections.len() > limits.maximum_connections
    {
        return Err(limit_error(
            "world, descriptor, and binding rosters differ or connection ceiling exceeded",
        ));
    }

    let mut remaining = limits.maximum_total_core_bytes;
    let mut count = |value: &dyn erased_core::BoundedSerialize| -> Result<(), AdmissionError> {
        let used = value.bounded_size(limits.maximum_core_object_bytes.min(remaining))?;
        remaining = remaining
            .checked_sub(used)
            .ok_or_else(|| limit_error("total core byte ceiling exceeded"))?;
        Ok(())
    };
    count(request.world)?;
    request.world.validate().map_err(schema_error)?;
    for descriptor in request.descriptors {
        if descriptor.ports.len() > limits.maximum_ports_or_lanes
            || descriptor
                .ports
                .iter()
                .any(|port| port.lanes.len() > limits.maximum_ports_or_lanes)
        {
            return Err(limit_error("port or lane count exceeds admission ceiling"));
        }
        count(descriptor)?;
        descriptor.validate().map_err(schema_error)?;
    }
    for binding in request.bindings {
        count(binding)?;
        binding.validate().map_err(schema_error)?;
    }
    for owner in request.owners {
        if owner.owner.participant_ids.len() > limits.maximum_nodes
            || owner.owner.state_domain_ids.len() > limits.maximum_state_objects
        {
            return Err(limit_error(
                "owner participant or domain roster exceeds admission ceiling",
            ));
        }
        count(owner)?;
        owner.validate().map_err(schema_error)?;
    }

    for accepted in [
        &request.requirements.accepted_quantized_nodes,
        &request.requirements.accepted_nondeterministic_nodes,
        &request.requirements.accepted_limited_state_nodes,
    ] {
        ordered_ids(accepted.iter(), limits.maximum_nodes)?;
        if accepted.iter().any(|id| {
            request
                .descriptors
                .binary_search_by(|node| node.id.cmp(id))
                .is_err()
        }) {
            return Err(refuse(
                AdmissionStage::Nodes,
                AdmissionSubject::World,
                AdmissionCode::IdentityMismatch,
                "acceptance names actual admitted nodes",
                "acceptance names undeclared node",
            ));
        }
    }
    ordered_ids(
        request.requirements.accepted_visibility_conversions.iter(),
        limits.maximum_connections,
    )?;
    if request
        .requirements
        .accepted_visibility_conversions
        .iter()
        .any(|id| {
            request
                .world
                .connections
                .binary_search_by(|edge| edge.id.cmp(id))
                .is_err()
        })
    {
        return Err(refuse(
            AdmissionStage::Edges,
            AdmissionSubject::World,
            AdmissionCode::IdentityMismatch,
            "conversion acceptance names actual connections",
            "acceptance names undeclared connection",
        ));
    }
    Ok(())
}

// This tiny local abstraction keeps accounting generic without creating
// buffered JSON Values or introducing another serialization dependency.
mod erased_core {
    use super::{AdmissionError, bounded_core};
    use serde::Serialize;

    pub(super) trait BoundedSerialize {
        fn bounded_size(&self, maximum: usize) -> Result<usize, AdmissionError>;
    }

    impl<T: Serialize> BoundedSerialize for T {
        fn bounded_size(&self, maximum: usize) -> Result<usize, AdmissionError> {
            bounded_core(self, maximum)
        }
    }
}

pub(super) fn validate_nodes(
    request: &AdmissionRequest<'_>,
    content: &mut VerifiedContent<'_>,
) -> Result<NodeSelections, AdmissionError> {
    content.verify(&request.world.scenario_ref)?;
    content.verify(&request.world.initialization_ref)?;
    let mut guarantees = BTreeMap::new();
    let mut operating_policies = BTreeMap::new();
    for ((descriptor, binding), expected) in request
        .descriptors
        .iter()
        .zip(request.bindings)
        .zip(&request.world.node_bindings)
    {
        let compatibility = &binding.compatibility;
        let subject = AdmissionSubject::Node(descriptor.id.clone());
        let fail = |code, required, observed| {
            refuse(
                AdmissionStage::Nodes,
                subject.clone(),
                code,
                required,
                observed,
            )
        };
        if descriptor.id != compatibility.node_id
            || expected.node_id != descriptor.id
            || descriptor.identity().map_err(schema_error)? != compatibility.descriptor_hash
            || compatibility.identity().map_err(schema_error)? != expected.binding_hash
        {
            return Err(fail(
                AdmissionCode::IdentityMismatch,
                "actual descriptors and bindings match frozen world selections",
                "descriptor, node identity, or compatibility hash differs",
            ));
        }

        // Unknown identity-bearing extensions cannot be promoted to supported
        // semantics merely because their enclosing JSON object can be hashed.
        if !descriptor.extensions.is_empty()
            || !compatibility.extensions.is_empty()
            || !compatibility.implementation.extensions.is_empty()
            || !compatibility.operating_contract.extensions.is_empty()
            || !binding.extensions.is_empty()
            || !binding.authority.extensions.is_empty()
        {
            return Err(fail(
                AdmissionCode::UnknownInterface,
                "host-supported selected core extensions",
                "unregistered core extension",
            ));
        }
        for reference in [
            &descriptor.model_ref,
            &descriptor.configuration_ref,
            &descriptor.initialization_ref,
            &compatibility.profile_ref,
            &compatibility.configuration_ref,
            &binding.authority.host_receipt,
        ] {
            content.verify(reference)?;
        }
        let operating: ExecutionPolicy =
            content.policy(&compatibility.operating_contract.policy_ref)?;
        let valid = match &operating {
            ExecutionPolicy::Exact { schema_version, .. } => {
                *schema_version == 1
                    && compatibility.operating_contract.mode == OperatingMode::Exact
                    && compatibility.operating_contract.resolution_ps.is_some()
                    && compatibility.operating_contract.phase_ps.is_some()
            }
            ExecutionPolicy::Quantized {
                schema_version,
                quantum_ps,
                phase_ps,
                host_budget_ns,
                ..
            } => {
                *schema_version == 1
                    && compatibility.operating_contract.mode == OperatingMode::Quantized
                    && quantum_ps.get() > 0
                    && phase_ps.get() < quantum_ps.get()
                    && host_budget_ns.get() > 0
            }
        };
        if !valid {
            return Err(fail(
                AdmissionCode::VisibilityMismatch,
                "supported complete operating policy matching selected exact regular grid or quantized window",
                "operating mode, edition, grid, or hardware budget differs or is unsupported",
            ));
        }
        for proof in operating.proof_refs() {
            content.verify(proof)?;
        }
        for artifact in &compatibility.implementation.artifacts {
            if !artifact.extensions.is_empty() {
                return Err(fail(
                    AdmissionCode::UnknownInterface,
                    "registered artifact semantics",
                    "unknown artifact extension",
                ));
            }
            content.verify(&artifact.content)?;
        }
        for model in &compatibility.implementation.model_definitions {
            content.verify(model)?;
        }
        for format in &compatibility.implementation.formats {
            if !format.extensions.is_empty() {
                return Err(fail(
                    AdmissionCode::UnknownInterface,
                    "registered state/protocol format semantics",
                    "unknown schema extension",
                ));
            }
            content.verify(&format.definition)?;
            content
                .source
                .authenticate_schema(format)
                .map_err(|error| {
                    refuse(
                        AdmissionStage::Authenticate,
                        subject.clone(),
                        AdmissionCode::UnknownInterface,
                        "installed validator for exact complete format schema",
                        error.to_string(),
                    )
                })?;
        }
        for qualification in &compatibility.qualification_refs {
            content.verify(qualification)?;
        }
        if compatibility.implementation.artifacts.is_empty()
            || compatibility.qualification_refs.is_empty()
        {
            return Err(fail(
                AdmissionCode::QualificationUnavailable,
                "measured implementation artifacts and accepted scoped qualification",
                "empty artifact or qualification roster",
            ));
        }
        content
            .source
            .authenticate_implementation(&compatibility.implementation)
            .map_err(|error| {
                refuse(
                    AdmissionStage::Authenticate,
                    subject.clone(),
                    AdmissionCode::IdentityMismatch,
                    "trusted measured installed implementation",
                    error.to_string(),
                )
            })?;
        content
            .source
            .authenticate_authority(binding)
            .map_err(|error| {
                refuse(
                    AdmissionStage::Authenticate,
                    subject.clone(),
                    AdmissionCode::IdentityMismatch,
                    "authenticated actual live authority and host custody",
                    error.to_string(),
                )
            })?;

        let capability: CapabilityProfile = content.policy(&compatibility.capabilities_ref)?;
        capability.validate().map_err(schema_error)?;
        let guarantee: GuaranteeProfile = content.policy(&compatibility.guarantees_ref)?;
        guarantee.validate().map_err(schema_error)?;
        if !capability.extensions.is_empty() || !guarantee.extensions.is_empty() {
            return Err(fail(
                AdmissionCode::UnknownInterface,
                "host-supported capability and guarantee contracts",
                "unregistered extension",
            ));
        }
        content.verify(&capability.devices_ref)?;
        content.verify(&capability.requirements_ref)?;
        content.verify(&guarantee.limitations_ref)?;
        for facet in &capability.facets {
            if !facet.extensions.is_empty() {
                return Err(fail(
                    AdmissionCode::UnknownInterface,
                    "registered operation facet semantics",
                    "unknown facet extension",
                ));
            }
            content.verify(&facet.configuration_ref)?;
            content.verify(&facet.guarantees_ref)?;
        }
        for facet in &compatibility.operating_contract.facets {
            if !capability.facets.contains(facet) {
                return Err(fail(
                    AdmissionCode::FeatureMismatch,
                    "each selected facet exactly supported by actual capability profile",
                    "selected facet differs or is absent",
                ));
            }
        }
        content.qualify(
            subject.clone(),
            QualificationClaim::Node {
                binding: compatibility,
                binding_hash: &expected.binding_hash,
                qualification_refs: &compatibility.qualification_refs,
            },
        )?;

        let requirements = request.requirements;
        if compatibility.operating_contract.mode == OperatingMode::Quantized
            && requirements
                .accepted_quantized_nodes
                .binary_search(&descriptor.id)
                .is_err()
        {
            return Err(fail(
                AdmissionCode::NondeterminismUnaccepted,
                "explicit acceptance of complete selected quantized contract",
                "quantized node has no scenario acceptance",
            ));
        }
        if guarantee.repeatability != Repeatability::Qualified
            && (requirements.deterministic
                || requirements
                    .accepted_nondeterministic_nodes
                    .binary_search(&descriptor.id)
                    .is_err())
        {
            return Err(fail(
                AdmissionCode::NondeterminismUnaccepted,
                "explicit nondeterministic acceptance compatible with world requirements",
                "unaccepted nondeterministic or unqualified execution",
            ));
        }
        let limited = guarantee.capture_scope != CaptureScope::CompleteModel
            || guarantee.continuation != Continuation::Exact;
        if limited
            && requirements
                .accepted_limited_state_nodes
                .binary_search(&descriptor.id)
                .is_err()
        {
            return Err(fail(
                AdmissionCode::CaptureUnsupported,
                "explicit acceptance of actual capture and replay limitations",
                "limited state contract has no scenario acceptance",
            ));
        }
        if (requirements.exact_capture || requirements.exact_continuation)
            && guarantee.capture_scope != CaptureScope::CompleteModel
            || requirements.exact_continuation && guarantee.continuation != Continuation::Exact
            || requirements.durable_restart && !guarantee.durable_restart
            || requirements.isolated_fork && !guarantee.isolated_fork
        {
            return Err(fail(
                AdmissionCode::CaptureUnsupported,
                "selected independent preservation guarantees meet every required operation",
                "architectural, best-effort, or unsupported selected preservation axis",
            ));
        }
        guarantees.insert(descriptor.id.clone(), guarantee);
        operating_policies.insert(descriptor.id.clone(), operating);
    }
    Ok(NodeSelections {
        guarantees,
        operating_policies,
    })
}
