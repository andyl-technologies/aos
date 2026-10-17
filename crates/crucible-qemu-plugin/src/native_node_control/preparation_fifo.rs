//! Initialization-ACK-bound custody of the actual mapped transport queues.
//!
//! This owner retains the accepted original initialization token and the real
//! callback, worker and mapping holds before taking an immutable byte image.
//! Preparation never invents an execution command. The image does not fence
//! administrative peer writes, unread kernel data or native device producers;
//! those obligations remain separate prerequisites for a source-owned epoch.

use std::sync::Arc;

use crucible_protocol::node_control::NativeCommandError;
use crucible_shmem::{
    HotForkRingImage, HotForkRingImageError, MappedSetupRegion, SetupRegionBackingIdentity,
};
use thiserror::Error;

use super::initialization_custody::{AcknowledgedInitialization, InitializationCustody};
use crate::runtime::callback_quiescence::LiveCallbackQuiescence;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, NativeWorkerOwnershipError};

const MAXIMUM_IMAGE_BYTES: usize = 64 * 1024 * 1024;

/// Keeps the same original owners alive across incomplete acquisition retries.
///
/// The mapping borrow prevents this ledger from outliving its genuine mapped
/// owner. Dropping this ledger does not reopen any admission gate.
#[cfg(test)]
pub(crate) struct NativePreparationFifoCustody<'mapping> {
    region: &'mapping MappedSetupRegion,
    state: NativePreparationFifoState,
}

/// Retains acquisition beside the runtime that owns the original mapping.
///
/// Each synchronous call borrows that runtime's mapping and checks its original
/// process-private address and backing. This avoids a self-referential runtime
/// allocation without transferring mapping ownership to callback metadata.
pub(crate) struct NativePreparationFifoState {
    initialization: Arc<InitializationCustody>,
    callbacks: Arc<LiveCallbackQuiescence>,
    workers: Arc<LiveWorkerQuiescence>,
    mapping_start: usize,
    mapping_identity: SetupRegionBackingIdentity,
    maximum_bytes: usize,
    original: Option<AcknowledgedInitialization>,
    image: Option<HotForkRingImage>,
    failed: bool,
}

/// Refuses acquisition while preserving the actual retained owners and holds.
#[derive(Debug, Error)]
pub(crate) enum NativePreparationFifoError {
    #[error("original initialization custody is foreign, failed or unavailable")]
    Initialization(#[from] NativeCommandError),
    #[error("preparation FIFO credit is invalid")]
    Credit,
    #[error("preparation FIFO requires one genuinely private machine mapping")]
    SharedRegion,
    #[error("preparation FIFO ownership changed or became invalid")]
    Ownership,
    #[error(transparent)]
    Workers(#[from] NativeWorkerOwnershipError),
    #[error("preparation FIFO bytes cannot be retained")]
    Image(#[from] HotForkRingImageError),
}

impl NativePreparationFifoState {
    /// Preflights storage policy while retaining the actual resource owners.
    ///
    /// # Errors
    /// Refuses invalid byte credit or a shared/malformed mapping before holding
    /// callback, worker or mapped-ring admission.
    pub(crate) fn new(
        initialization: Arc<InitializationCustody>,
        callbacks: Arc<LiveCallbackQuiescence>,
        workers: Arc<LiveWorkerQuiescence>,
        region: &MappedSetupRegion,
        maximum_bytes: usize,
    ) -> Result<Self, NativePreparationFifoError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_IMAGE_BYTES {
            return Err(NativePreparationFifoError::Credit);
        }
        let layout = region
            .layout()
            .map_err(|source| HotForkRingImageError::RegionAccess {
                source: crucible_shmem::MappedSetupRegionAccessError::Header { source },
            })?;
        if layout.vm_node_count != 1 {
            return Err(NativePreparationFifoError::SharedRegion);
        }

        Ok(Self {
            initialization,
            callbacks,
            workers,
            mapping_start: region.mapping_start(),
            mapping_identity: region.backing_identity(),
            maximum_bytes,
            original: None,
            image: None,
            failed: false,
        })
    }

    /// Retains the first ACK-bound image or returns that same historical image.
    ///
    /// None means a busy original journal, an ACK that has not yet arrived or
    /// admission that has not yet drained.
    /// Once an ACK is accepted here, it stays owned even when a later step is
    /// incomplete. Every hold survives retry, failure and ledger drop. Neither
    /// success nor None supplies source-root, input-epoch or execution authority.
    ///
    /// # Errors
    /// Refuses failed ACK custody, teardown, exhausted byte credit or
    /// changed admission. A failure after original retention is sticky.
    pub(crate) fn try_retain(
        &mut self,
        region: &MappedSetupRegion,
    ) -> Result<Option<&HotForkRingImage>, NativePreparationFifoError> {
        if self.failed {
            return Err(NativePreparationFifoError::Ownership);
        }

        let result = self.try_retain_inner(region);
        if result.is_err() && self.original.is_some() {
            self.failed = true;
        }
        if result? {
            Ok(self.image.as_ref())
        } else {
            Ok(None)
        }
    }

    fn try_retain_inner(
        &mut self,
        region: &MappedSetupRegion,
    ) -> Result<bool, NativePreparationFifoError> {
        if region.mapping_start() != self.mapping_start
            || region.backing_identity() != self.mapping_identity
        {
            return Err(NativePreparationFifoError::Ownership);
        }
        if self.original.is_none() {
            let Some(original) = self.initialization.try_pending_acknowledged_original()? else {
                return Ok(false);
            };
            // Install original authority before any hold or fallible image copy.
            self.original = Some(original);
        }
        let original = self
            .original
            .as_ref()
            .ok_or(NativePreparationFifoError::Ownership)?;
        if !original.try_validate_original(&self.initialization)? {
            return Ok(false);
        }
        if self.image.is_some() {
            // Recovery reads no mapping, queue cursor or live admission state.
            return Ok(true);
        }

        let callbacks = self.callbacks.hold_hot_fork();
        let Some(workers) = self.workers.try_hold()? else {
            return Ok(false);
        };
        region
            .hold_hot_fork_ring_io()
            .map_err(|source| HotForkRingImageError::RegionAccess { source })?;
        if callbacks.teardown_closed {
            return Err(NativePreparationFifoError::Ownership);
        }
        if callbacks.in_flight != 0
            || workers.parked_mask != workers.worker_mask
            || workers.pending_mask != 0
            || workers.operations_in_flight != 0
        {
            return Ok(false);
        }

        let image = region.capture_hot_fork_ring_image(self.maximum_bytes)?;
        let Some(workers_after) = self.workers.try_snapshot()? else {
            return Ok(false);
        };
        if self.callbacks.snapshot() != callbacks || workers_after != workers {
            return Err(NativePreparationFifoError::Ownership);
        }
        if !original.try_validate_original(&self.initialization)? {
            // Keep the exact first image while the original journal is busy;
            // acquisition may recover it only after authentic ACK revalidation.
            self.image = Some(image);
            return Ok(false);
        }
        self.image = Some(image);
        Ok(true)
    }
}

#[cfg(test)]
impl<'mapping> NativePreparationFifoCustody<'mapping> {
    /// Keeps a mapping borrow for standalone acquisition harnesses.
    ///
    /// # Errors
    /// Refuses the same credit and actual one-machine mapping conditions as the
    /// runtime-owned acquisition state, before installing any holds.
    pub(crate) fn new(
        initialization: Arc<InitializationCustody>,
        callbacks: Arc<LiveCallbackQuiescence>,
        workers: Arc<LiveWorkerQuiescence>,
        region: &'mapping MappedSetupRegion,
        maximum_bytes: usize,
    ) -> Result<Self, NativePreparationFifoError> {
        Ok(Self {
            region,
            state: NativePreparationFifoState::new(
                initialization,
                callbacks,
                workers,
                region,
                maximum_bytes,
            )?,
        })
    }

    /// Retains the original image while the borrowed mapping owner remains live.
    ///
    /// # Errors
    /// Refuses invalid original ACK, owner changes and image/credit failures.
    pub(crate) fn try_retain(
        &mut self,
    ) -> Result<Option<&HotForkRingImage>, NativePreparationFifoError> {
        self.state.try_retain(self.region)
    }
}

#[cfg(test)]
impl std::ops::Deref for NativePreparationFifoCustody<'_> {
    type Target = NativePreparationFifoState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

#[cfg(test)]
#[path = "preparation_fifo_tests.rs"]
pub(crate) mod tests;
