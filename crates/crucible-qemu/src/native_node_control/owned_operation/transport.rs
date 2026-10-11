//! Drives one original prefix operation through its retained transport and archive.
//!
//! Every command is durably reserved before socket exposure. One immutable pending
//! frame remains owned across backpressure; consumed ACKs precede continuation.
//! This driver provides no PreparedOwner, native retirement or capture authority.

// SPDX-License-Identifier: Apache-2.0

use crate::native_node_control::NativeAdministrationTransport;
use crucible_protocol::node_control::{NativeEffectCompute, NativeFrame, NativePrefixPreparation};

use super::{Archive, ArchiveError, OriginalPrefixJournal, TurnoverState};

/// Provides original nonblocking frames from one retained prepared endpoint.
///
/// The native implementation preserves its actual reader and process correlation.
/// Implementations used in tests supply modeled replies, never native authority.
pub trait OriginalOperationEndpoint {
    /// Borrows the endpoint's immutable complete prefix preparation.
    fn prefix_preparation(&self) -> Option<&NativePrefixPreparation>;

    /// Sends the same owned frame or reports backpressure without consuming it.
    ///
    /// # Errors
    /// Reports failed endpoint custody or an incompatible original frame.
    fn send_original(&self, frame: &NativeFrame) -> Result<bool, ArchiveError>;

    /// Receives at most one original response without blocking.
    ///
    /// # Errors
    /// Reports failed endpoint custody or invalid framing.
    fn receive_original(&self) -> Result<Option<NativeFrame>, ArchiveError>;
}

impl OriginalOperationEndpoint for NativeAdministrationTransport {
    fn prefix_preparation(&self) -> Option<&NativePrefixPreparation> {
        self.prefix_preparation()
    }

    fn send_original(&self, frame: &NativeFrame) -> Result<bool, ArchiveError> {
        self.send_construction(frame)
            .map_err(ArchiveError::Transport)
    }

    fn receive_original(&self) -> Result<Option<NativeFrame>, ArchiveError> {
        self.receive_construction().map_err(ArchiveError::Transport)
    }
}

/// Reports host custody progress without asserting a completed native grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalOperationProgress {
    /// Retains the same pending frame and original reply obligation.
    Pending,
    /// Retains a newly authenticated original prefix and an offered ACK.
    ResultRetained,
    /// Retains the native consumed ACK; a continuation remains explicit.
    AcknowledgementConsumed,
    /// Retains an equal historical body without changing the current obligation.
    HistoricalRecovered,
}

/// Owns one original endpoint, command journal and durably reserved archive.
///
/// A refused initialization or later failure keeps these owners in this value.
/// The caller must quarantine the associated child before disposing of uncertain
/// custody. This type neither spawns a child nor substitutes for its supervisor.
pub struct OriginalOperationDriver<T: OriginalOperationEndpoint> {
    endpoint: T,
    archive: Archive,
    journal: Option<OriginalPrefixJournal>,
    pending: Option<NativeFrame>,
    sent: bool,
    original: NativeEffectCompute,
    failure: Option<ArchiveError>,
}

impl<T: OriginalOperationEndpoint> OriginalOperationDriver<T> {
    /// Reserves the complete original command durably before permitting any send.
    ///
    /// Failure leaves an inert driver retaining the endpoint and archive. The
    /// first poll reports that refusal; it cannot accidentally expose a command.
    /// Only a vacant archive admits a new operation. Restored or committed
    /// history needs a separate native recovery or retirement confirmation join.
    pub fn retain(endpoint: T, mut archive: Archive, original: NativeEffectCompute) -> Self {
        let journal = endpoint
            .prefix_preparation()
            .ok_or(ArchiveError::Conflict)
            .and_then(|preparation| {
                if preparation.maximum_prefixes != archive.maximum_prefixes() {
                    return Err(ArchiveError::Budget);
                }
                OriginalPrefixJournal::new(preparation, original.clone())
            })
            .and_then(|journal| {
                // Historical storage equality cannot authenticate a live epoch
                // or release the previous native command's retirement fence.
                if archive.state() != TurnoverState::Vacant {
                    return Err(ArchiveError::Conflict);
                }
                archive.reserve(&original)?;
                Ok(journal)
            });
        match journal {
            Ok(journal) => Self {
                endpoint,
                archive,
                journal: Some(journal),
                pending: Some(NativeFrame::EffectCompute(Box::new(original.clone()))),
                sent: false,
                original,
                failure: None,
            },
            Err(error) => Self {
                endpoint,
                archive,
                journal: None,
                pending: None,
                sent: false,
                original,
                failure: Some(error),
            },
        }
    }

    /// Borrows the complete original even when preparation or storage was refused.
    pub fn original(&self) -> &NativeEffectCompute {
        &self.original
    }

    /// Borrows the first permanent refusal without forgetting its original owners.
    pub fn failure(&self) -> Option<&ArchiveError> {
        self.failure.as_ref()
    }

    /// Borrows the original archive transition while all owners remain retained.
    pub fn archive_state(&self) -> TurnoverState {
        self.archive.state()
    }

    /// Borrows immutable correlated history without exposing native handles.
    pub fn journal(&self) -> Option<&OriginalPrefixJournal> {
        self.journal.as_ref()
    }

    /// Advances nonblocking host transport custody for this same original operation.
    ///
    /// A sent frame is not automatically resent on every poll. A separate explicit
    /// historical request can re-expose its exact bytes without renewing budgets.
    ///
    /// # Errors
    /// Retains permanent refusal after invalid replies, uncertain transport custody
    /// or journal failure. No later poll may dispatch another frame after refusal.
    pub fn poll(&mut self) -> Result<OriginalOperationProgress, ArchiveError> {
        if self.failure.is_some() {
            return Err(ArchiveError::Failed);
        }
        let outcome = self.poll_original();
        match outcome {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.failure = Some(error);
                Err(ArchiveError::Failed)
            }
        }
    }

    fn poll_original(&mut self) -> Result<OriginalOperationProgress, ArchiveError> {
        if !self.sent
            && let Some(frame) = &self.pending
        {
            if !self.endpoint.send_original(frame)? {
                return Ok(OriginalOperationProgress::Pending);
            }
            self.sent = true;
        }
        let Some(frame) = self.endpoint.receive_original()? else {
            return Ok(OriginalOperationProgress::Pending);
        };
        let journal = self.journal.as_mut().ok_or(ArchiveError::Failed)?;
        match &frame {
            NativeFrame::EffectProgress(_) | NativeFrame::PrefixProgress(_) => {
                let before = journal.retained_prefixes();
                journal.observe_result(&frame)?;
                if before == journal.retained_prefixes() {
                    return Ok(OriginalOperationProgress::HistoricalRecovered);
                }
                self.pending = Some(journal.offer_acknowledgement()?);
                self.sent = false;
                Ok(OriginalOperationProgress::ResultRetained)
            }
            NativeFrame::PrefixAcknowledged(ack) => {
                journal.observe_acknowledgement(&frame)?;
                if self.pending.as_ref() != Some(&NativeFrame::AcknowledgePrefix(ack.clone())) {
                    return Ok(OriginalOperationProgress::HistoricalRecovered);
                }
                self.pending = None;
                self.sent = false;
                Ok(OriginalOperationProgress::AcknowledgementConsumed)
            }
            _ => Err(ArchiveError::Conflict),
        }
    }

    /// Requests a separately source-selected cut after the actual current consumed ACK.
    ///
    /// # Errors
    /// Refuses failed custody, an outstanding frame, missing consumed ACK,
    /// completed/unknown history or unchanged original prefix-budget exhaustion.
    pub fn request_continuation(&mut self) -> Result<(), ArchiveError> {
        if self.failure.is_some() || self.pending.is_some() {
            return Err(ArchiveError::Conflict);
        }
        let journal = self.journal.as_mut().ok_or(ArchiveError::Failed)?;
        self.pending = Some(journal.continuation()?);
        self.sent = false;
        Ok(())
    }

    /// Re-exposes the exact pending frame for explicit historical reconciliation.
    ///
    /// # Errors
    /// Refuses failed custody or an absent original pending request. This does not
    /// clear any ACK obligation, replace a command or supply another allowance.
    pub fn request_original_again(&mut self) -> Result<(), ArchiveError> {
        if self.failure.is_some() || self.pending.is_none() {
            return Err(ArchiveError::Conflict);
        }
        self.sent = false;
        Ok(())
    }
}
