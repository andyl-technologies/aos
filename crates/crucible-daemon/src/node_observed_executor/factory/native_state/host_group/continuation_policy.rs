//! Binds selected model restoration to the installed complete fresh-world factory.
//!
//! The original model predicate is necessary but cannot replace the explicit
//! continuation decision. This private policy borrows the authenticated signed
//! source and actual factory target; callers cannot construct it from data labels.

use crucible::{
    node_adapters::{HostModel, HostModelQualification},
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, EffectKnowledge, OperationFailure, RuntimeSnapshot},
    node_state::{AuthenticatedNativeSource, StateError},
};
use crucible_node_contract::{NodeBinding, NodeDescriptor, canonical};

use super::{evidence::IndependentGroupEvidence, source::error};

pub(in crate::node_observed_executor::factory::native_state) struct IndependentModelContinuation<
    'a,
    'b,
> {
    installed: &'a IndependentGroupEvidence,
    source: &'a AuthenticatedNativeSource<'b>,
    target: &'a ActivationRecord,
}

impl<'a, 'b> IndependentModelContinuation<'a, 'b> {
    pub(in crate::node_observed_executor::factory::native_state) fn new(
        installed: &'a IndependentGroupEvidence,
        graph: &AdmittedGraph,
        source: &'a AuthenticatedNativeSource<'b>,
        target: &'a ActivationRecord,
    ) -> Result<Self, StateError> {
        installed.authenticate_continuation_scope(graph, source, target)?;
        Ok(Self {
            installed,
            source,
            target,
        })
    }
}

impl HostModelQualification for IndependentModelContinuation<'_, '_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
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
        let reference =
            canonical::content_ref(native, "application/octet-stream").map_err(refused)?;
        if target != self.target
            || runtime != self.source.runtime()
            || self.source.owner().participants.as_slice() != std::slice::from_ref(&descriptor.id)
            || !self.source.owner().evidence.contains(&reference)
            || self.source.content().get(&reference) != Some(native)
            || binding.compatibility.execution_owner.id != self.source.owner().owner
        {
            return Err(refused(
                "installed group continuation lost its original native source or fresh target",
            ));
        }
        Ok(())
    }
}

fn refused(reason: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: error(reason).to_string(),
    }
}
