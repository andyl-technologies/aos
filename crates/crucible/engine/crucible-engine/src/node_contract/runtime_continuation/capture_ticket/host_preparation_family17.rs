//! Keeps genuine original15 and restored17 Host producers in separate families.
//!
//! Both variants retain actual private construction provenance. A historical
//! Host17 record, format label or optional Scope cannot create either variant.

use super::*;
use crate::node_contract::{HostSchedulingNodeWitness, PreparedRestoredHost17Capture};
use crate::node_state::{CompleteOriginalOwnerCapturePreflight, NativeArchiveLimits};

#[path = "host_cached_demand17.rs"]
mod demand17;

pub(crate) enum PreparedHostCaptureFamily {
    Initial15(Rc<OriginalHostCapturePreparation>),
    Settled17(Rc<PreparedRestoredHost17Capture>),
}

impl PreparedHostCaptureFamily {
    pub(crate) fn authenticate_family_data(&self, restored: bool) -> Result<(), RuntimeError> {
        if matches!(self, Self::Settled17(_)) != restored {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }

    pub(crate) fn retained(&self) -> Self {
        match self {
            Self::Initial15(owner) => Self::Initial15(Rc::clone(owner)),
            Self::Settled17(owner) => Self::Settled17(Rc::clone(owner)),
        }
    }

    pub(crate) fn authenticate_runtime(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Initial15(owner) => owner.authenticate_runtime(runtime),
            Self::Settled17(owner) => owner.authenticate_runtime_owner_data(runtime),
        }
    }

    pub(crate) fn owned_snapshot_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Initial15(owner) => owner.owned_snapshot_storage(),
            Self::Settled17(owner) => owner.retained_requested_storage_data(),
        }
    }

    pub(crate) fn cached_demand(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        witness: &HostSchedulingNodeWitness<'_>,
        activation: &WorldActivation,
        original: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalOwnerCapturePreflight, RuntimeError> {
        match self {
            Self::Initial15(owner) => owner.cached_demand(
                runtime,
                witness,
                activation,
                original,
                runtime_object,
                limits,
            ),
            Self::Settled17(owner) => demand17::cached_demand_data(
                owner,
                runtime,
                witness,
                activation,
                original,
                runtime_object,
                limits,
            ),
        }
    }

    pub(crate) fn with_original_scheduling_data<R>(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        runtime_object: &InputPayload,
        inspect: impl FnOnce(
            &HostSchedulingSource,
            &crate::node_scheduling::SchedulingSnapshot,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        match self {
            Self::Initial15(owner) => {
                owner.with_original_scheduling_data(runtime, activation, inspect)
            }
            Self::Settled17(owner) => {
                owner.with_scheduling_data(runtime, activation, runtime_object, inspect)
            }
        }
    }

    pub(crate) fn take(
        &self,
        source: &HostSchedulingSource,
        owner: &OwnerIdentity,
        world: &WorldActivation,
    ) -> Result<HostSchedulingContinuationV2, RuntimeError> {
        match self {
            Self::Initial15(prepared) => prepared.take(source, owner, world),
            Self::Settled17(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }

    pub(crate) fn take_restored17_data(
        &self,
        source: &HostSchedulingSource,
        owner: &OwnerIdentity,
        world: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
    ) -> Result<crate::node_contract::HostSchedulingRestoredContinuation17, RuntimeError> {
        match self {
            Self::Initial15(_) => Err(RuntimeError::UnsupportedFacet),
            Self::Settled17(prepared) => {
                prepared.take_data(source, owner, world, record, runtime_object)
            }
        }
    }
}

impl crate::node_contract::NodeRuntime {
    /// Borrows the unique actual Host source through defining Runtime custody.
    ///
    /// The pointer comparison identifies the retained source occurrence only;
    /// no private node map, decoded Source or manufactured witness escapes.
    ///
    /// # Errors
    /// Refuses absent or multiple Host owners, missing actual nodes or another
    /// source occurrence. The caller separately binds World and checkpoint data.
    pub(crate) fn retained_restored_host_source17_data(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        host: &HostSchedulingSource,
    ) -> Result<Rc<HostSchedulingSource>, RuntimeError> {
        self.authenticate_host_scheduling_source(host)?;
        let mut actual = None;
        for id in graph.node_ids() {
            let node = self.nodes.get(id).ok_or(RuntimeError::UnknownNode)?;
            if let Some(witness) = node.original_host_scheduling_owner() {
                let candidate = witness.original_capture_source()?;
                if actual.is_some() || !std::ptr::eq(candidate.as_ref(), host) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                actual = Some(candidate);
            }
        }
        actual.ok_or(RuntimeError::UnsupportedFacet)
    }
}

#[cfg(test)]
mod isolation_controls {
    use super::*;

    #[test]
    fn legacy_data_family_cannot_satisfy_current17_selection() {
        // This absent capsule tests only a closed family tag, never Current or
        // native capture authority. No historical DTO becomes a17 producer.
        let family =
            PreparedHostCaptureFamily::Initial15(Rc::new(OriginalHostCapturePreparation::absent()));
        assert_eq!(family.authenticate_family_data(false), Ok(()));
        assert_eq!(
            family.authenticate_family_data(true),
            Err(RuntimeError::UnsupportedFacet)
        );
        assert_eq!(
            family.retained().authenticate_family_data(true),
            Err(RuntimeError::UnsupportedFacet)
        );
    }
}
