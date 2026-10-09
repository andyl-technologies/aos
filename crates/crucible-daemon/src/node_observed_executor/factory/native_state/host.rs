//! Exact host Clock restoration beneath an authenticated generic native source.
//!
//! The existing host envelope and native model codec remain unchanged. This
//! wrapper authenticates the generic archive's original source capability; it
//! never constructs or substitutes a HostArchive-specific source capability.

use crucible::{
    node_adapters::{
        HOST_EXACT_PROFILE, HostContinuationInventory, HostModel, HostModelNode,
        HostModelQualification, HostModelResources, validate_host_continuation,
    },
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, EffectKnowledge, NativeRuntimeContinuationEvidence, OperationFailure,
        RuntimeSnapshot,
    },
    node_state::{AuthenticatedNativeSource, StateError, StateErrorCode},
};
use crucible_device::clock::VirtualClock;
use crucible_node_contract::{Id, NodeBinding, NodeDescriptor};

/// Authenticates complete original Clock bytes under the selected native codec.
///
/// This function checks historical preservation only. Actual installed model
/// qualification and the global fresh activation barrier remain mandatory.
///
/// # Errors
/// Refuses another backend/schema/owner, incomplete original runtime/evidence,
/// altered raw receipt bodies, incompatible bindings or unsupported host state.
pub(super) fn authenticate_clock_source(
    graph: &AdmittedGraph,
    node: &Id,
    source: &AuthenticatedNativeSource<'_>,
    resources: HostModelResources,
) -> Result<HostContinuationInventory, StateError> {
    let descriptor = graph
        .descriptor(node)
        .ok_or_else(|| state_error("Clock descriptor absent"))?;
    let binding = graph
        .binding(node)
        .ok_or_else(|| state_error("Clock binding absent"))?;
    let owner = source.owner();
    let selected_schema = binding
        .compatibility
        .implementation
        .formats
        .iter()
        .find(|schema| schema.id.as_str() == "host/native-continuation-v1" && schema.version == 1)
        .ok_or_else(|| state_error("installed complete Clock codec absent"))?;
    if owner.key.implementation.as_str() != "crucible-host-clock"
        || binding
            .compatibility
            .implementation
            .implementation_id
            .as_str()
            != "crucible-host-clock"
        || owner.key.profile.as_str() != HOST_EXACT_PROFILE
        || &owner.key.schema != selected_schema
        || owner.owner != binding.compatibility.capture_owner.id
        || binding.compatibility.execution_owner != binding.compatibility.capture_owner
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || !owner.artifacts.is_empty()
        || source.archive().manifest().world_binding_hash != *graph.world_binding_hash()
    {
        return Err(state_error(
            "generic native source selects another Clock backend or complete scope",
        ));
    }
    let inventory = validate_host_continuation(
        source.native()?,
        source.runtime(),
        descriptor,
        binding,
        resources,
    )
    .map_err(|error| state_error(error.reason))?;
    if inventory.boundary != owner.cut
        || inventory.node != *node
        || source.content().get(&inventory.native_model.reference)
            != Some(inventory.native_model.bytes.as_slice())
        || !owner.evidence.contains(&inventory.native_model.reference)
        || inventory.evidence.iter().any(|object| {
            source.content().get(&object.reference) != Some(object.bytes.as_slice())
                || !owner.evidence.contains(&object.reference)
        })
    {
        return Err(state_error(
            "signed Clock source omits original native model or receipt bytes",
        ));
    }
    Ok(inventory)
}

/// Prepares unchanged original Clock state without staging or rerunning work.
///
/// # Errors
/// Refuses incompatible installed qualification, original lineage, fresh target
/// authority, bounded resource capacity or selected native continuation codec.
pub(super) fn prepare_clock(
    graph: &AdmittedGraph,
    node: &Id,
    source: &AuthenticatedNativeSource<'_>,
    target: &ActivationRecord,
    installed: &dyn HostModelQualification,
    resources: HostModelResources,
) -> Result<(HostModelNode, NativeRuntimeContinuationEvidence), StateError> {
    authenticate_clock_source(graph, node, source, resources)?;
    let qualifier = OriginalClockQualification {
        source,
        target,
        installed,
    };
    let mut actual = HostModelNode::new(
        graph,
        node,
        HostModel::Clock(VirtualClock::new()),
        &qualifier,
        resources,
    )
    .map_err(|error| state_error(error.reason))?;
    let proof = actual
        .prepare_continuation(source.native()?, source.runtime(), target, &qualifier)
        .map_err(|error| state_error(error.reason))?;
    Ok((actual, proof))
}

struct OriginalClockQualification<'a, 'b> {
    source: &'a AuthenticatedNativeSource<'b>,
    target: &'a ActivationRecord,
    installed: &'a dyn HostModelQualification,
}

impl HostModelQualification for OriginalClockQualification<'_, '_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if !matches!(model, HostModel::Clock(_)) {
            return Err(refusal(
                "mixed Clock source cannot qualify another host model",
            ));
        }
        self.installed
            .authenticate_model(model, descriptor, binding)
    }

    fn authenticate_continuation(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
        native: &[u8],
        runtime: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        self.authenticate_model(model, descriptor, binding)?;
        if self.source.owner().participants.as_slice() != std::slice::from_ref(&descriptor.id)
            || self
                .source
                .native()
                .map_err(|error| refusal(error.to_string()))?
                != native
            || self.source.runtime() != runtime
            || self.target != target
            || runtime.source_activation.world_binding_hash != target.world_binding_hash
            || runtime.capture_cut != target.boundary
            || runtime.source_activation.generation >= target.generation
        {
            return Err(refusal(
                "generic Clock continuation differs from authenticated original custody",
            ));
        }
        Ok(())
    }
}

fn refusal(reason: impl Into<String>) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

fn state_error(reason: impl Into<String>) -> StateError {
    StateError::new(StateErrorCode::NativeEvidence, "mixed Clock source", reason)
}
