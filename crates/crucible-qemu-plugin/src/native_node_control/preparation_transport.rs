//! Original preparatory transport custody retained beside the source root join.
//!
//! The owner holds actual callback/worker/FIFO admission and retains the same
//! initializer ACK, sole administrative inbox and RUN socket. Its historical
//! image covers consumed raw packets, reply credit, every partial RUN prefix
//! and full mapped FIFO backing. It cannot represent unread kernel backlog or
//! stop peer writes; no source RootSeal or executable epoch is issued here.

use std::sync::Arc;

use crucible_protocol::ControlLifecycleState;
#[cfg(test)]
use crucible_shmem::HotForkRingImage;
use crucible_shmem::MappedSetupRegion;
use thiserror::Error;

use super::administrative_inbox::{NativeAdministrativeInbox, NativeAdministrativeInboxError};
use super::initialization_custody::InitializationCustody;
use super::preparation_fifo::{NativePreparationFifoError, NativePreparationFifoState};
use crate::runtime::callback_quiescence::LiveCallbackQuiescence;
use crate::runtime::native_run_control::{
    NativeRunControlCustody, NativeRunControlError, NativeRunControlSnapshot,
};
use crate::runtime::worker_quiescence::LiveWorkerQuiescence;

const MAXIMUM_INBOX_BYTES: usize = 16 * 1024 * 1024;

/// Bounds the two independently retained original transport images.
pub(crate) struct NativePreparationTransportCredit {
    pub(crate) fifo_bytes: usize,
    pub(crate) inbox_bytes: usize,
}

/// Retains all actual plugin transport owners while original acquisition is pending.
#[cfg(test)]
pub(crate) struct NativePreparationTransportCustody<'mapping> {
    region: &'mapping MappedSetupRegion,
    state: NativePreparationTransportState,
}

/// Keeps retained transport state beside the owning pinned callback runtime.
///
/// Each acquisition borrows that runtime's original mapping synchronously; the
/// FIFO ledger checks actual mapping address and backing before any hold.
pub(crate) struct NativePreparationTransportState {
    fifo: NativePreparationFifoState,
    inbox: Arc<NativeAdministrativeInbox>,
    run: Arc<NativeRunControlCustody>,
    maximum_inbox_bytes: usize,
    original_run: Option<NativeRunControlSnapshot>,
    original_inbox: Option<Vec<u8>>,
    failed: bool,
}

/// Borrows immutable material without creating source or native effect authority.
#[cfg(test)]
pub(crate) struct NativePreparationTransportView<'owner> {
    pub(crate) fifo: &'owner HotForkRingImage,
    pub(crate) run: &'owner NativeRunControlSnapshot,
    pub(crate) inbox: &'owner [u8],
}

/// Retains incomplete or tainted original owners without reopening admission.
#[derive(Debug, Error)]
pub(crate) enum NativePreparationTransportError {
    #[error("preparation transport does not belong to the same original native owners")]
    Ownership,
    #[error("preparation inbox image credit is invalid")]
    Credit,
    #[error(transparent)]
    Fifo(#[from] NativePreparationFifoError),
    #[error(transparent)]
    Inbox(#[from] NativeAdministrativeInboxError),
    #[error(transparent)]
    Run(#[from] NativeRunControlError),
}

impl NativePreparationTransportState {
    /// Joins the exact native inbox worker owner with real mapping and RUN custody.
    ///
    /// # Errors
    /// Refuses foreign worker identity, scope mismatch, invalid credit or mapping
    /// policy before holding admission. Equal worker masks are insufficient.
    pub(crate) fn new(
        initialization: Arc<InitializationCustody>,
        callbacks: Arc<LiveCallbackQuiescence>,
        workers: Arc<LiveWorkerQuiescence>,
        region: &MappedSetupRegion,
        inbox: Arc<NativeAdministrativeInbox>,
        run: Arc<NativeRunControlCustody>,
        credit: NativePreparationTransportCredit,
    ) -> Result<Self, NativePreparationTransportError> {
        if initialization.scope != *inbox.scope() || !Arc::ptr_eq(&workers, inbox.modeled_workers())
        {
            return Err(NativePreparationTransportError::Ownership);
        }
        if credit.inbox_bytes == 0 || credit.inbox_bytes > MAXIMUM_INBOX_BYTES {
            return Err(NativePreparationTransportError::Credit);
        }
        let fifo = NativePreparationFifoState::new(
            initialization,
            callbacks,
            workers,
            region,
            credit.fifo_bytes,
        )?;
        Ok(Self {
            fifo,
            inbox,
            run,
            maximum_inbox_bytes: credit.inbox_bytes,
            original_run: None,
            original_inbox: None,
            failed: false,
        })
    }

    /// Retains original transport bytes without another receive or broad release.
    ///
    /// Each completed part stays installed before taking the next fallible cut.
    /// False means a busy owner or previously admitted work is still draining.
    /// The administrative owner remains live with finite journal/reply credit;
    /// this does not exempt its socket from later source-root input closure.
    ///
    /// # Errors
    /// Refuses original faults, invalid RUN lifecycle or image failures. Errors
    /// are sticky, and the original sockets, ACK and holds remain retained.
    pub(crate) fn try_retain(
        &mut self,
        region: &MappedSetupRegion,
    ) -> Result<bool, NativePreparationTransportError> {
        if self.failed {
            return Err(NativePreparationTransportError::Ownership);
        }
        let result = self.try_retain_inner(region);
        if result.is_err() {
            self.failed = true;
        }
        if !result? {
            return Ok(false);
        }
        match self.fifo.try_retain(region) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(error) => {
                self.failed = true;
                Err(error.into())
            }
        }
    }

    fn try_retain_inner(
        &mut self,
        region: &MappedSetupRegion,
    ) -> Result<bool, NativePreparationTransportError> {
        if self.fifo.try_retain(region)?.is_none() {
            return Ok(false);
        }
        if self.original_run.is_none() {
            let Some(original) = self.run.try_snapshot()? else {
                return Ok(false);
            };
            // Retain a terminal prefix even when it prevents a fresh epoch.
            self.original_run = Some(original);
        }
        if self.original_run.as_ref().is_none_or(|original| {
            original.terminal || original.lifecycle != ControlLifecycleState::RunningViaSharedMemory
        }) {
            return Err(NativePreparationTransportError::Ownership);
        }
        if self.original_inbox.is_none() {
            let Some(original) = self.inbox.try_snapshot(self.maximum_inbox_bytes)? else {
                return Ok(false);
            };
            self.original_inbox = Some(original);
        }
        Ok(true)
    }
}

#[cfg(test)]
impl<'mapping> NativePreparationTransportCustody<'mapping> {
    /// Keeps a mapping borrow when acquisition runs outside the callback runtime.
    ///
    /// # Errors
    /// Refuses foreign actual worker identity, scope mismatch and invalid credit.
    pub(crate) fn new(
        initialization: Arc<InitializationCustody>,
        callbacks: Arc<LiveCallbackQuiescence>,
        workers: Arc<LiveWorkerQuiescence>,
        region: &'mapping MappedSetupRegion,
        inbox: Arc<NativeAdministrativeInbox>,
        run: Arc<NativeRunControlCustody>,
        credit: NativePreparationTransportCredit,
    ) -> Result<Self, NativePreparationTransportError> {
        Ok(Self {
            region,
            state: NativePreparationTransportState::new(
                initialization,
                callbacks,
                workers,
                region,
                inbox,
                run,
                credit,
            )?,
        })
    }

    /// Retains actual original bytes without receiving or reopening admission.
    ///
    /// # Errors
    /// Refuses original faults, invalid RUN lifecycle and image failures.
    pub(crate) fn try_retain(
        &mut self,
    ) -> Result<Option<NativePreparationTransportView<'_>>, NativePreparationTransportError> {
        if !self.state.try_retain(self.region)? {
            return Ok(None);
        }
        let Some(fifo) = self.state.fifo.try_retain(self.region)? else {
            return Ok(None);
        };
        Ok(Some(NativePreparationTransportView {
            fifo,
            run: self
                .state
                .original_run
                .as_ref()
                .ok_or(NativePreparationTransportError::Ownership)?,
            inbox: self
                .state
                .original_inbox
                .as_deref()
                .ok_or(NativePreparationTransportError::Ownership)?,
        }))
    }
}

#[cfg(test)]
impl std::ops::Deref for NativePreparationTransportCustody<'_> {
    type Target = NativePreparationTransportState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

#[cfg(test)]
#[path = "preparation_transport_tests.rs"]
mod tests;
