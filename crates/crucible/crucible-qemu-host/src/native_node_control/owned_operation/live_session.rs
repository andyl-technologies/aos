//! Same-Child live retirement and bounded source-proved quiet operations.
//!
//! Every original request remains pending through backpressure. Actual native
//! receipt/commit joins and existing archive durability precede another command.
//! No constructor here issues Ready or adopts a Child from portable data.

// SPDX-License-Identifier: Apache-2.0

use super::{
    Archive, ArchiveError, NativeOwnedPrefixOperation, NativeOwnedPrefixRefusal,
    OriginalInitialEvidence, OriginalOperationEndpoint, OriginalPrefixJournal,
    QuietTerminalEvidence, TurnoverState,
};
use crate::native_node_control::NativeAdministrationTransport;
use crate::{QemuNodeChild, QemuShutdownTargetError};
use crucible_qemu_protocol::node_control::{
    NativeCurrentCensus, NativeFrame, NativeLiveAccept, NativeQuietCommand, NativeQuietProgress,
    NativeQuietStatus, NativeRetireOriginal, NativeRetirementCommitted, NativeRetirementProposal,
    NativeRetirementReceipt,
};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Proposal,
    Receipt,
    Commit,
    Stopped,
    Quiet,
    QuietTerminal,
}

/// Reports retained source/host custody without common readiness authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLiveProgress {
    /// Keeps the exact original request and reply obligation pending.
    Pending,
    /// Retains a genuine quiet result; retirement remains a separate operation.
    QuietRetained(NativeQuietStatus),
    /// Retains actual native commit and matching durable host archive state.
    Stopped,
}

/// Retains the complete original operation when live conversion refuses.
pub struct NativeLiveStartFailure {
    original: Option<NativeOwnedPrefixOperation>,
    error: ArchiveError,
}

impl NativeLiveStartFailure {
    /// Borrows the complete owner retained on failed conversion.
    pub fn original(&self) -> Option<&NativeOwnedPrefixOperation> {
        self.original.as_ref()
    }
    /// Borrows the conversion refusal without discarding custody.
    pub fn error(&self) -> &ArchiveError {
        &self.error
    }
    /// Reaps the same actual child while retaining the original failed owner.
    ///
    /// # Errors
    /// Preserves unique wait authority after timeout or kernel failure.
    pub fn dispose(&mut self, timeout: Duration) -> Result<(), QemuShutdownTargetError> {
        match &mut self.original {
            Some(original) => original.dispose(timeout),
            None => Err(QemuShutdownTargetError::new(
                "live conversion",
                "missing retained original",
            )),
        }
    }
}

/// Owns the original Child, source endpoint, input history and bounded live bank.
///
/// This live-only stage retains original effect cuts and supports subsequent
/// source-proved quiet intervals. Due CPU/timer work returns NeedsEvaluation;
/// it never invokes an unqualified evaluating-turnover path.
pub struct NativeLiveSession {
    child: QemuNodeChild,
    endpoint: NativeAdministrationTransport,
    archive: Archive,
    initial: OriginalInitialEvidence,
    first: OriginalPrefixJournal,
    quiet: Option<NativeQuietCommand>,
    quiet_result: Option<NativeQuietProgress>,
    proposal: Option<NativeRetirementProposal>,
    receipt: Option<NativeRetirementReceipt>,
    committed: Option<NativeRetirementCommitted>,
    pending: Option<NativeFrame>,
    sent: bool,
    phase: Phase,
    failure: Option<ArchiveError>,
    refusal: Option<NativeOwnedPrefixRefusal>,
}

impl NativeLiveSession {
    /// Consumes the genuine completed first operation into its retirement join.
    ///
    /// # Errors
    /// Returns the complete same operation on absent consumed ACK/initial source
    /// history, wrong endpoint, pending work or failed Child supervision.
    pub fn from_prefix(
        original: NativeOwnedPrefixOperation,
    ) -> Result<Self, Box<NativeLiveStartFailure>> {
        let mut failure = Box::new(NativeLiveStartFailure {
            original: Some(original),
            error: ArchiveError::Conflict,
        });
        let request = (|| {
            let original = failure.original.as_mut().ok_or(ArchiveError::Conflict)?;
            original.check_child()?;
            if !original.operation.endpoint().live_quiet_selected()
                || original
                    .initial
                    .as_ref()
                    .and_then(|initial| initial.stopped_cut())
                    .is_none()
                || original.operation.failure().is_some()
            {
                return Err(ArchiveError::Conflict);
            }
            original
                .operation
                .journal()
                .ok_or(ArchiveError::Conflict)?
                .retirement_request()
        })();
        let request = match request {
            Ok(request) => request,
            Err(error) => {
                failure.error = error;
                return Err(failure);
            }
        };
        let Some(mut original) = failure.original.take() else {
            return Err(failure);
        };
        let Some(initial) = original.initial.take() else {
            failure.original = Some(original);
            return Err(failure);
        };
        let (endpoint, archive, first) = match original.operation.into_live_parts() {
            Ok(parts) => parts,
            Err(operation) => {
                failure.original = Some(NativeOwnedPrefixOperation {
                    child: original.child,
                    operation,
                    refusal: original.refusal,
                    initial: Some(initial),
                });
                return Err(failure);
            }
        };
        Ok(Self {
            child: original.child,
            endpoint,
            archive,
            initial,
            first,
            quiet: None,
            quiet_result: None,
            proposal: None,
            receipt: None,
            committed: None,
            pending: Some(NativeFrame::RetireOriginal(Box::new(request))),
            sent: false,
            phase: Phase::Proposal,
            failure: None,
            refusal: original.refusal,
        })
    }

    /// Returns the unchanged actual process identifier.
    pub fn process_id(&self) -> u32 {
        self.child.process_id()
    }
    /// Reports only an actual observed Child reap.
    pub fn reaped(&self) -> bool {
        self.child.reaped()
    }
    /// Borrows retained permanent custody failure.
    pub fn failure(&self) -> Option<&ArchiveError> {
        self.failure.as_ref()
    }
    /// Borrows the actual current source committed predecessor.
    pub fn committed(&self) -> Option<&NativeRetirementCommitted> {
        self.committed.as_ref()
    }
    /// Borrows the genuine quiet result, including a due-source refusal.
    pub fn quiet_result(&self) -> Option<&NativeQuietProgress> {
        self.quiet_result.as_ref()
    }
    /// Borrows the same original command archive, without releasing its lock.
    pub fn archive(&self) -> &Archive {
        &self.archive
    }

    /// Reserves the complete next quiet command before any native exposure.
    ///
    /// # Errors
    /// Refuses noncommitted custody, foreign/changed source position, unsupported
    /// shape or exhausted/damaged original archive. Accepted failed inputs stay owned.
    pub fn begin_quiet(&mut self, original: NativeQuietCommand) -> Result<(), ArchiveError> {
        self.check_child()?;
        if self.phase != Phase::Stopped || self.failure.is_some() {
            return Err(ArchiveError::Conflict);
        }
        original.validate()?;
        let committed = self.committed.as_ref().ok_or(ArchiveError::Conflict)?;
        let current = self
            .proposal
            .as_ref()
            .ok_or(ArchiveError::Conflict)?
            .current()?;
        let preparation = self
            .endpoint
            .prefix_preparation()
            .ok_or(ArchiveError::Conflict)?;
        if original.command.kind.start().microstep
            >= preparation.original_effect.original_root.maximum_microstep
            || original.command.kind.limit().microstep
                >= preparation.original_effect.original_root.maximum_microstep
            || original.predecessor_commit != committed.digest()
            || original.command.kind.start() != current.position()?
            || original.preparation != preparation.identity_digest()?
        {
            return Err(ArchiveError::Conflict);
        }
        self.quiet = Some(original);
        self.quiet_result = None;
        self.proposal = None;
        self.receipt = None;
        let Some(original) = self.quiet.as_ref() else {
            return Err(ArchiveError::Failed);
        };
        if let Err(error) = self.archive.reserve_quiet(original) {
            self.failure = Some(error);
            return Err(ArchiveError::Failed);
        }
        self.pending = Some(NativeFrame::QuietAdvance(Box::new(original.clone())));
        self.sent = false;
        self.phase = Phase::Quiet;
        Ok(())
    }

    /// Begins retirement of the exact retained quiet result without re-executing it.
    ///
    /// # Errors
    /// Refuses absent terminal result, failed custody or an outstanding request.
    pub fn retire_quiet(&mut self) -> Result<(), ArchiveError> {
        self.check_child()?;
        if self.failure.is_some() || self.phase != Phase::QuietTerminal || self.pending.is_some() {
            return Err(ArchiveError::Conflict);
        }
        let result = self.quiet_result.as_ref().ok_or(ArchiveError::Conflict)?;
        self.pending = Some(NativeFrame::RetireOriginal(Box::new(
            NativeRetireOriginal {
                identity: result.identity()?,
                final_acknowledgement: [0; 192],
            },
        )));
        self.sent = false;
        self.phase = Phase::Proposal;
        Ok(())
    }

    /// Re-exposes exactly the same pending original for explicit recovery.
    ///
    /// # Errors
    /// Refuses failed/terminal custody or an absent original request. This never
    /// substitutes another operation ID, clears an ACK or renews an allowance.
    pub fn request_original_again(&mut self) -> Result<(), ArchiveError> {
        self.check_child()?;
        if self.failure.is_some() || self.pending.is_none() {
            return Err(ArchiveError::Conflict);
        }
        self.sent = false;
        Ok(())
    }

    /// Polls only the original pending request; backpressure never resends it.
    ///
    /// # Errors
    /// Retains sticky failure and original Child/epoch/archive after ambiguous
    /// source, framing, supervision or durability errors.
    pub fn poll(&mut self) -> Result<NativeLiveProgress, ArchiveError> {
        if self.failure.is_some() {
            return Err(ArchiveError::Failed);
        }
        let outcome = self.poll_once().and_then(|progress| {
            self.check_child()?;
            Ok(progress)
        });
        match outcome {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.failure = Some(error);
                Err(ArchiveError::Failed)
            }
        }
    }

    fn poll_once(&mut self) -> Result<NativeLiveProgress, ArchiveError> {
        self.check_child()?;
        if !self.endpoint.original_process_matches(self.process_id()) {
            return Err(ArchiveError::Conflict);
        }
        if self.phase == Phase::Stopped {
            return Ok(NativeLiveProgress::Stopped);
        }
        if self.phase == Phase::QuietTerminal {
            let status = self
                .quiet_result
                .as_ref()
                .ok_or(ArchiveError::Conflict)?
                .validate_original(
                    self.quiet.as_ref().ok_or(ArchiveError::Conflict)?,
                    self.process_id(),
                )?;
            return Ok(NativeLiveProgress::QuietRetained(status));
        }

        if !self.sent
            && let Some(frame) = &self.pending
        {
            if !self.endpoint.send_original(frame)? {
                return Ok(NativeLiveProgress::Pending);
            }
            self.sent = true;
        }
        let Some(frame) = self.endpoint.receive_original()? else {
            self.check_child()?;
            return Ok(NativeLiveProgress::Pending);
        };
        self.check_child()?;
        if self.is_historical_reply(&frame)? {
            return Ok(NativeLiveProgress::Pending);
        }
        match frame {
            NativeFrame::QuietProgress(result) if self.phase == Phase::Quiet => {
                let original = self.quiet.as_ref().ok_or(ArchiveError::Conflict)?;
                let status = result.validate_original(original, self.process_id())?;
                self.validate_lineage(&result.before()?)?;
                self.validate_lineage(&result.after()?)?;
                self.quiet_result = Some(*result);
                self.pending = None;
                self.sent = false;
                self.phase = Phase::QuietTerminal;
                Ok(NativeLiveProgress::QuietRetained(status))
            }
            NativeFrame::RetirementProposed(proposal) if self.phase == Phase::Proposal => {
                self.validate_lineage(&proposal.current()?)?;
                let terminal_digest = if let Some(result) = &self.quiet_result {
                    let evidence = QuietTerminalEvidence {
                        progress: result.clone(),
                        proposal: (*proposal).clone(),
                    };
                    self.archive.archive_quiet_terminal(&evidence)?
                } else {
                    self.first.validate_retirement_proposal(&proposal)?;
                    let evidence = self.first.terminal_evidence(proposal.bytes().to_vec())?;
                    self.archive.archive_terminal(&evidence)?
                };
                let identity = proposal.identity()?;
                self.pending = Some(NativeFrame::AcceptTerminal(NativeLiveAccept {
                    identity,
                    native_digest: proposal.digest(),
                    archive_digest: terminal_digest,
                }));
                self.proposal = Some(*proposal);
                self.sent = false;
                self.phase = Phase::Receipt;
                Ok(NativeLiveProgress::Pending)
            }
            NativeFrame::RetirementReceipt(receipt) if self.phase == Phase::Receipt => {
                let TurnoverState::TerminalArchived {
                    terminal_digest, ..
                } = self.archive.state()
                else {
                    return Err(ArchiveError::Conflict);
                };
                let proposal = self.proposal.as_ref().ok_or(ArchiveError::Conflict)?;
                receipt.validate_original(proposal, terminal_digest)?;
                self.archive
                    .record_native_receipt(terminal_digest, receipt.bytes())?;
                let TurnoverState::ReceiptStored { receipt_digest, .. } = self.archive.state()
                else {
                    return Err(ArchiveError::Conflict);
                };
                self.pending = Some(NativeFrame::AcknowledgeRetirement(NativeLiveAccept {
                    identity: proposal.identity()?,
                    native_digest: receipt.digest(),
                    archive_digest: receipt_digest,
                }));
                self.receipt = Some(*receipt);
                self.sent = false;
                self.phase = Phase::Commit;
                Ok(NativeLiveProgress::Pending)
            }
            NativeFrame::RetirementCommitted(committed) if self.phase == Phase::Commit => {
                let TurnoverState::ReceiptStored { receipt_digest, .. } = self.archive.state()
                else {
                    return Err(ArchiveError::Conflict);
                };
                committed.validate_original(
                    self.receipt.as_ref().ok_or(ArchiveError::Conflict)?,
                    receipt_digest,
                )?;
                self.archive
                    .record_native_commit(receipt_digest, committed.bytes())?;
                self.committed = Some(*committed);
                self.pending = None;
                self.sent = false;
                self.phase = Phase::Stopped;
                Ok(NativeLiveProgress::Stopped)
            }
            _ => Err(ArchiveError::Conflict),
        }
    }

    fn is_historical_reply(&mut self, frame: &NativeFrame) -> Result<bool, ArchiveError> {
        if matches!(frame, NativeFrame::QuietProgress(result) if self.quiet_result.as_ref() == Some(result.as_ref()))
            || matches!(frame, NativeFrame::RetirementProposed(result) if self.proposal.as_ref() == Some(result.as_ref()))
            || matches!(frame, NativeFrame::RetirementReceipt(result) if self.receipt.as_ref() == Some(result.as_ref()))
            || matches!(frame, NativeFrame::RetirementCommitted(result) if self.committed.as_ref() == Some(result.as_ref()))
        {
            return Ok(true);
        }
        let sequence = match frame {
            NativeFrame::QuietProgress(result) => result.identity()?.sequence.get(),
            NativeFrame::RetirementProposed(result) => result.identity()?.sequence.get(),
            NativeFrame::RetirementReceipt(result) => u64::from_be_bytes(
                result.bytes()[80..88]
                    .try_into()
                    .map_err(|_| ArchiveError::Corrupt)?,
            ),
            NativeFrame::RetirementCommitted(result) => u64::from_be_bytes(
                result.bytes()[96..104]
                    .try_into()
                    .map_err(|_| ArchiveError::Corrupt)?,
            ),
            _ => return Ok(false),
        };
        if sequence > self.archive.last_committed_sequence() {
            return Ok(false);
        }
        let stored = self.archive.historical(sequence)?;
        let same = match frame {
            NativeFrame::QuietProgress(result) => stored
                .quiet_terminal
                .as_ref()
                .is_some_and(|stored| stored.progress == **result),
            NativeFrame::RetirementProposed(result) => {
                stored
                    .terminal
                    .as_ref()
                    .is_some_and(|stored| stored.native_proposal == result.bytes().as_slice())
                    || stored
                        .quiet_terminal
                        .as_ref()
                        .is_some_and(|stored| stored.proposal == **result)
            }
            NativeFrame::RetirementReceipt(result) => {
                stored.native_receipt.as_deref() == Some(result.bytes().as_slice())
            }
            NativeFrame::RetirementCommitted(result) => {
                stored.native_commit.as_deref() == Some(result.bytes().as_slice())
            }
            _ => false,
        };
        if !same {
            return Err(ArchiveError::Conflict);
        }
        Ok(true)
    }

    fn validate_lineage(&self, current: &NativeCurrentCensus) -> Result<(), ArchiveError> {
        self.first.validate_lifetime_provenance(current)?;
        let maximum = self
            .endpoint
            .prefix_preparation()
            .ok_or(ArchiveError::Conflict)?
            .original_effect
            .original_root
            .maximum_microstep;
        if current.position()?.microstep >= maximum {
            return Err(ArchiveError::Conflict);
        }
        let initial = self
            .initial
            .stopped_cut()
            .ok_or(ArchiveError::Conflict)?
            .source_record();
        let actual = current.bytes();
        if actual[8..16] != u64::from(self.process_id()).to_be_bytes()
            || actual[16..24] != initial[16..24]
            || actual[56..80] != initial[56..80]
            || actual[184..344] != initial[184..344]
        {
            return Err(ArchiveError::Conflict);
        }
        Ok(())
    }

    fn check_child(&mut self) -> Result<(), ArchiveError> {
        if self.refusal.is_some() {
            return Err(ArchiveError::Failed);
        }
        match self.child.try_wait_natural_exit() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
                self.refusal = Some(NativeOwnedPrefixRefusal::ChildExited(status));
                Err(ArchiveError::Failed)
            }
            Err(error) => {
                self.refusal = Some(NativeOwnedPrefixRefusal::Supervision(error));
                Err(ArchiveError::Failed)
            }
        }
    }

    /// Contains and reaps the same Child while preserving every original body.
    ///
    /// # Errors
    /// Retains unique wait authority on timeout or kernel failure; sends stay fenced.
    pub fn dispose(&mut self, timeout: Duration) -> Result<(), QemuShutdownTargetError> {
        if self.refusal.is_none() {
            self.refusal = Some(NativeOwnedPrefixRefusal::DisposalStarted);
        }
        self.child.force_kill_and_reap_failed_helper(timeout)
    }
}
