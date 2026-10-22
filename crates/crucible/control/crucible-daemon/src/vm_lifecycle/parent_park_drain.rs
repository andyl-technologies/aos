//! Retains the complete prepared world through its later original park phase.
//!
//! The boxed launcher keeps the actual composed host owner and issued family
//! operation. No Node, pending ledger, launcher or generation lease is removed
//! from the lifecycle, and the parked facade exposes no mutable world loan.

use std::sync::Arc;

use crucible_engine::NodeId;
use crucible_engine::owned_decode::{DecodeAdmissionError, DecodeScratch};
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use crucible_qemu_host::{OriginalActorParkCaller, OriginalActorParkCallerLease, QmpParentParkResult};

use super::ProductionVmHotForkSourceWorld;

mod failure;
pub use failure::{
    ProductionVmParentParkDrainCause, ProductionVmParentParkDrainFailure,
    ProductionVmParentParkStageAdmissionCause, ProductionVmParentParkStageEarlyCause,
    ProductionVmParentParkStageEnteredCause, ProductionVmParentParkStageFailure,
    ProductionVmParentParkStageOwnerCause, ProductionVmParentParkStageReborrowCause,
};

/// Selects a fixed operation on the launcher's retained phase.
pub enum ProductionVmParentParkDrainRequest<'a> {
    /// Enters the fixed actor and factory-issued family phase exactly once.
    Begin {
        /// Already-retained authentic actor Preparation.
        original: &'a Arc<HostOperationGuard>,
        /// Same actor's independently retained decoder and original accounts.
        decoder: &'a OriginalActorParkCaller,
        /// Correlates the actual acquisition without issuing authority.
        correlation: u64,
    },
    /// Returns the same retained request through its actual Cleanup owner.
    Return,
}

/// Reports refusal while the complete source and typed first cause stay owned.
#[derive(Debug, thiserror::Error)]
pub enum ProductionVmParentParkDrainRefusal {
    /// The actual retained actor or decoder refused before phase entry.
    #[error(transparent)]
    Actor(#[from] crucible_qemu_host::OriginalActorAccountError),
    /// The installed source could not authenticate its retained loan.
    #[error(transparent)]
    Source(#[from] crucible_qemu_host::OriginalParkSourceError),
    /// The used launcher or source ownership route does not support this phase.
    #[error("parent park route unavailable: {0}")]
    Unavailable(&'static str),
    /// Existing actor credit refused before world handover or phase body birth.
    #[error(transparent)]
    Admission(#[from] DecodeAdmissionError),
    /// The actual actor original refused before handover.
    #[error(transparent)]
    Original(#[from] HostSupervisionError),
    /// The launcher's same prepaid phase retains its actual first cause.
    #[error("parent park refusal retained with the complete world")]
    Retained,
}

struct ParentParkWorldState {
    world: Option<ProductionVmHotForkSourceWorld>,
    node: NodeId,
    original: Arc<HostOperationGuard>,
    decoder: OriginalActorParkCallerLease,
    begin_attempted: bool,
    refused: bool,
}

/// Owns the entire world while a later original phase excludes other operations.
///
/// Explicit physical return and both original postcuts are required before the
/// world can be returned. Uncertainty or facade abandonment retains the whole
/// lifecycle, its NodeSet/pending ledger, boxed launcher and original credits.
#[must_use = "return explicitly or retain the whole world for containment"]
pub struct ProductionVmParentParkDrain {
    state: Option<Box<ParentParkWorldState>>,
    // State, including the physical world, closes before this external credit.
    credit: Option<DecodeScratch>,
}

impl ProductionVmParentParkDrain {
    /// Prepays the fixed owner before consuming the uniquely owned source slot.
    ///
    /// A daemon source-pool caller must first obtain its real exclusive source;
    /// this method cannot detach a source from a shared managed-world lease.
    /// Refusal leaves the supplied source slot installed and untouched.
    ///
    /// # Errors
    /// Refuses absent source ownership, actual original or actor credit.
    pub fn prepare(
        source: &mut Option<ProductionVmHotForkSourceWorld>,
        node: NodeId,
        original: Arc<HostOperationGuard>,
        decoder: OriginalActorParkCallerLease,
    ) -> Result<Self, ProductionVmParentParkDrainRefusal> {
        if source.is_none() {
            return Err(ProductionVmParentParkDrainRefusal::Unavailable(
                "source slot absent",
            ));
        }
        decoder.caller().verify_parent_park_preparation(&original)?;
        original.wait_slice()?;
        let budget = decoder.caller().budget()?;
        // Cover the owner, heap body and its by-value construction overlap
        // before any world or original alias moves into the new facade.
        let control_bytes = 2 * std::mem::size_of::<ParentParkWorldState>()
            + std::mem::size_of::<Self>()
            + std::mem::size_of::<DecodeScratch>();
        let credit = budget.reserve_scratch_array::<u8>(control_bytes)?;
        let mut state = Box::new(ParentParkWorldState {
            world: None,
            node,
            original,
            decoder,
            begin_attempted: false,
            refused: false,
        });
        // The world moves only after the body and its external credit exist.
        state.world = source.take();
        Ok(Self {
            state: Some(state),
            credit: Some(credit),
        })
    }

    /// Begins using the fixed factory and same retained actor exactly once.
    ///
    /// # Errors
    /// Refuses reuse, an absent used route or the actual retained first cause.
    pub fn begin(
        &mut self,
        correlation: u64,
    ) -> Result<QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
        let state = self
            .state
            .as_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "phase consumed",
            ))?;
        if state.begin_attempted || state.refused {
            return Err(ProductionVmParentParkDrainRefusal::Unavailable(
                "phase already entered",
            ));
        }
        if correlation == 0 || correlation == u64::MAX {
            return Err(ProductionVmParentParkDrainRefusal::Unavailable(
                "reset correlation is outside the park protocol domain",
            ));
        }
        // Mark the handover before the first possible native or Pause effect.
        state.begin_attempted = true;
        let request = ProductionVmParentParkDrainRequest::Begin {
            original: &state.original,
            decoder: state.decoder.caller(),
            correlation,
        };
        let result = state
            .world
            .as_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "world consumed",
            ))?
            .parent_park_drain_step(&state.node, request);
        if result.is_err() {
            state.refused = true;
        }
        result
    }

    /// Returns the actual complete world only after physical and semantic settlement.
    ///
    /// On refusal this facade still owns everything; callers retain it for
    /// containment. No successful scalar or Drop path restores a mutable world.
    ///
    /// # Errors
    /// Refuses absent acquisition, native uncertainty or either actual original.
    pub fn return_world(
        &mut self,
    ) -> Result<ProductionVmHotForkSourceWorld, ProductionVmParentParkDrainRefusal> {
        let state = self
            .state
            .as_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "phase consumed",
            ))?;
        if !state.begin_attempted {
            return Err(ProductionVmParentParkDrainRefusal::Unavailable(
                "phase is not held",
            ));
        }
        let result = state
            .world
            .as_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "world consumed",
            ))?
            .parent_park_drain_step(&state.node, ProductionVmParentParkDrainRequest::Return);
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(first) => {
                state.refused = true;
                return Err(first);
            }
        };
        if receipt.closed_request.is_none()
            || !receipt.host_memberships_returned
            || receipt.has_operation_failure()
            || state.refused
        {
            state.refused = true;
            return Err(ProductionVmParentParkDrainRefusal::Retained);
        }
        let world = state
            .world
            .take()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "world consumed",
            ))?;
        self.state = None;
        self.credit = None;
        Ok(world)
    }

    /// Starts the existing actual-owner quarantine while retaining all custody.
    ///
    /// No mutable world is returned, neither original completes, and no native
    /// or Source credit is released. Actual reap and later complete retirement
    /// remain independent obligations of the containing attempt.
    ///
    /// # Errors
    /// Refuses an absent lifecycle or unsupported containing launcher.
    pub fn contain(&mut self) -> Result<(), ProductionVmParentParkDrainRefusal> {
        let state = self
            .state
            .as_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "phase consumed",
            ))?;
        state.refused = true;
        state
            .world
            .as_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "world consumed",
            ))?
            .contain_parent_park_drain()
    }

    /// Borrows the actual typed first cause from the same retained launcher.
    pub fn first_failure(&self) -> Option<ProductionVmParentParkDrainFailure<'_>> {
        self.state
            .as_ref()?
            .world
            .as_ref()?
            .parent_park_drain_failure()
    }
}

impl Drop for ProductionVmParentParkDrain {
    fn drop(&mut self) {
        // Start the genuine containing guard's quarantine before preserving
        // the full owner. Failure cannot authorize ordinary rollback or refund.
        let _containment = self.contain();
        if let Some(state) = self.state.take() {
            // No disposition attestation exists. Preserve the actual complete
            // world, originals and source credit, rather than refund on Drop.
            std::mem::forget(state);
            if let Some(credit) = self.credit.take() {
                std::mem::forget(credit);
            }
        }
    }
}

impl ProductionVmHotForkSourceWorld {
    /// Begins the fixed original phase while the managed pool retains this world.
    ///
    /// The daemon's pool-issued session owns exclusion against other checkouts;
    /// this method neither moves the world nor authenticates a pool lease.
    ///
    /// # Errors
    /// Refuses changed installed source, actual original or used factory custody.
    pub fn begin_parent_park_retained(
        &mut self,
        node: &NodeId,
        original: &Arc<HostOperationGuard>,
        decoder: &OriginalActorParkCaller,
        correlation: u64,
    ) -> Result<QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
        decoder.verify_parent_park_preparation(original)?;
        if correlation == 0 || correlation == u64::MAX {
            return Err(ProductionVmParentParkDrainRefusal::Unavailable(
                "invalid park correlation",
            ));
        }
        self.parent_park_drain_step(
            node,
            ProductionVmParentParkDrainRequest::Begin {
                original,
                decoder,
                correlation,
            },
        )
    }

    /// Requests explicit disposition from the same installed native phase.
    ///
    /// # Errors
    /// Refuses uncertain disposal or either original's actual independent postcut.
    pub fn return_parent_park_retained(
        &mut self,
        node: &NodeId,
    ) -> Result<QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
        self.parent_park_drain_step(node, ProductionVmParentParkDrainRequest::Return)
    }

    /// Transfers the actual containing owner to quarantine without attesting reap.
    ///
    /// # Errors
    /// Refuses an absent original containment route; the caller retains this world.
    pub fn contain_parent_park_retained(
        &mut self,
    ) -> Result<(), ProductionVmParentParkDrainRefusal> {
        self.contain_parent_park_drain()
    }

    fn parent_park_drain_step(
        &mut self,
        node: &NodeId,
        request: ProductionVmParentParkDrainRequest<'_>,
    ) -> Result<QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
        let prepared = self
            .prepared
            .iter()
            .find(|prepared| prepared.node() == node)
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "node is not prepared",
            ))?;
        let lifecycle = self.lifecycle.as_deref_mut().ok_or(
            ProductionVmParentParkDrainRefusal::Unavailable("source lifecycle absent"),
        )?;
        let mut source = lifecycle
            .inner
            .backend_mut()
            .prepared_parent_park_source(prepared)
            .map_err(ProductionVmParentParkDrainRefusal::Source)?;
        lifecycle
            .node_launcher
            .parent_park_drain(&mut source, request)
    }

    fn contain_parent_park_drain(&mut self) -> Result<(), ProductionVmParentParkDrainRefusal> {
        self.lifecycle
            .as_deref_mut()
            .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
                "source lifecycle absent",
            ))?
            .node_launcher
            .contain_parent_park_drain()
    }

    fn parent_park_drain_failure(&self) -> Option<ProductionVmParentParkDrainFailure<'_>> {
        self.lifecycle
            .as_deref()?
            .node_launcher
            .parent_park_drain_failure()
    }
}
