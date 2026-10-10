//! Retains one original quantum's immutable prefix and consumed-ACK obligations.
//!
//! This journal owns correlation and historical replies only. The installed
//! native source still owns every root, cut, CPU/timer allowance and evaluation.
//! An outgoing continuation names the original consumed ACK; it never creates a
//! replacement grant or reserves output by counting records.

// SPDX-License-Identifier: Apache-2.0

use crucible_protocol::node_control::{
    NativeEffectCompute, NativeEffectProgress, NativeEffectProgressStatus, NativeFrame,
    NativePrefixAcknowledgement, NativePrefixContinuation, NativePrefixPreparation,
    NativePrefixProgress,
};

use super::{ArchiveError, PrefixEvidence, TerminalEvidence};

enum ResultBody {
    Initial(NativeEffectProgress),
    Typed(NativePrefixProgress),
}

impl ResultBody {
    fn acknowledgement(&self) -> Result<NativePrefixAcknowledgement, ArchiveError> {
        Ok(match self {
            Self::Initial(result) => NativePrefixAcknowledgement::from_initial(result)?,
            Self::Typed(result) => NativePrefixAcknowledgement::from_progress(result)?,
        })
    }

    fn status(&self) -> NativeEffectProgressStatus {
        match self {
            Self::Initial(result) => result.status,
            Self::Typed(result) => result.status,
        }
    }

    fn canonical(&self) -> Result<Vec<u8>, ArchiveError> {
        Ok(match self {
            Self::Initial(result) => result.encode()?,
            Self::Typed(result) => result.encode()?,
        })
    }
}

struct RetainedPrefix {
    result: ResultBody,
    offered: Option<NativePrefixAcknowledgement>,
    consumed: Option<NativePrefixAcknowledgement>,
}

/// Retains one original command and a finite immutable chain until native retirement.
pub struct OriginalPrefixJournal {
    original: NativeEffectCompute,
    prefixes: Vec<RetainedPrefix>,
    maximum_prefixes: u32,
    pending_continuation: Option<NativePrefixContinuation>,
}

impl OriginalPrefixJournal {
    /// Binds the original command to its complete prepared ancestor and finite quota.
    ///
    /// This is host correlation, not common readiness or native effect admission.
    ///
    /// # Errors
    /// Rejects foreign preparation/scope, widened original budgets, invalid empty
    /// input identity or allocation failure before any command is exposed.
    pub fn new(
        preparation: &NativePrefixPreparation,
        original: NativeEffectCompute,
    ) -> Result<Self, ArchiveError> {
        preparation.validate()?;
        original.validate()?;
        let ancestor = &preparation.original_effect;
        if original.effect_preparation != preparation.identity_digest()?
            || original.command.scope
                != ancestor
                    .original_root
                    .administration
                    .phase
                    .initialization
                    .preparation
                    .scope
            || original.maximum_callbacks > ancestor.maximum_callbacks
            || original.maximum_service_span > ancestor.maximum_service_span
        {
            return Err(ArchiveError::Conflict);
        }
        let mut prefixes = Vec::new();
        prefixes
            .try_reserve_exact(preparation.maximum_prefixes as usize)
            .map_err(|_| ArchiveError::Budget)?;
        Ok(Self {
            original,
            prefixes,
            maximum_prefixes: preparation.maximum_prefixes,
            pending_continuation: None,
        })
    }

    /// Copies one already retained historical result without issuing another cut.
    pub fn retained_frame(&self, ordinal: usize) -> Option<NativeFrame> {
        self.prefixes
            .get(ordinal)
            .map(|prefix| match &prefix.result {
                ResultBody::Initial(result) => {
                    NativeFrame::EffectProgress(Box::new(result.clone()))
                }
                ResultBody::Typed(result) => NativeFrame::PrefixProgress(Box::new(result.clone())),
            })
    }

    /// Counts retained original frontier rows without granting another budget.
    pub fn retained_prefixes(&self) -> usize {
        self.prefixes.len()
    }

    /// Borrows the unchanged command for exact initial dispatch or historical recovery.
    pub fn original(&self) -> &NativeEffectCompute {
        &self.original
    }

    /// Retains a source result only after full original and preceding-history correlation.
    ///
    /// Equal historical replies leave state unchanged. A foreign packet cannot
    /// consume another slot or renew the original allowance.
    ///
    /// # Errors
    /// Rejects wrong frame classes, foreign/corrupt result identities, unsolicited
    /// continuation results, changed historical bodies or finite-prefix exhaustion.
    pub fn observe_result(&mut self, frame: &NativeFrame) -> Result<(), ArchiveError> {
        let (cut_id, body) = match frame {
            NativeFrame::EffectProgress(result) => {
                (result.cut_id, ResultBody::Initial((**result).clone()))
            }
            NativeFrame::PrefixProgress(result) => {
                (result.cut_id, ResultBody::Typed((**result).clone()))
            }
            _ => return Err(ArchiveError::Conflict),
        };
        let canonical = body.canonical()?;
        for prefix in &self.prefixes {
            if prefix.result.acknowledgement()?.cut_id == cut_id {
                return if prefix.result.canonical()? == canonical {
                    Ok(())
                } else {
                    Err(ArchiveError::Conflict)
                };
            }
        }
        if self.prefixes.len() == self.maximum_prefixes as usize {
            return Err(ArchiveError::Budget);
        }
        match (&body, self.prefixes.last()) {
            (ResultBody::Initial(result), None) => result.validate_against(&self.original)?,
            (ResultBody::Typed(result), Some(previous)) => {
                let continuation = self
                    .pending_continuation
                    .as_ref()
                    .ok_or(ArchiveError::Conflict)?;
                if previous.consumed.as_ref() != Some(&continuation.acknowledgement) {
                    return Err(ArchiveError::Conflict);
                }
                match &previous.result {
                    ResultBody::Initial(previous) => {
                        result.validate_after_initial(&self.original, previous)?
                    }
                    ResultBody::Typed(previous) => {
                        result.validate_after_progress(&self.original, previous)?
                    }
                }
            }
            _ => return Err(ArchiveError::Conflict),
        }
        self.prefixes.push(RetainedPrefix {
            result: body,
            offered: None,
            consumed: None,
        });
        self.pending_continuation = None;
        Ok(())
    }

    /// Retains an offered ACK for the exact current result without claiming consumption.
    ///
    /// # Errors
    /// Rejects absent original history or malformed canonical source result identity.
    pub fn offer_acknowledgement(&mut self) -> Result<NativeFrame, ArchiveError> {
        let prefix = self.prefixes.last_mut().ok_or(ArchiveError::Conflict)?;
        let acknowledgement = prefix.result.acknowledgement()?;
        prefix.offered = Some(acknowledgement.clone());
        Ok(NativeFrame::AcknowledgePrefix(acknowledgement))
    }

    /// Retains only the native consumed-ACK reply to the exact original offer.
    ///
    /// # Errors
    /// Rejects ACK echo/request frames, unsolicited replies or any changed original
    /// result/version/digest/sequence/cut field. Equal historical replies are inert.
    pub fn observe_acknowledgement(&mut self, frame: &NativeFrame) -> Result<(), ArchiveError> {
        let NativeFrame::PrefixAcknowledged(acknowledgement) = frame else {
            return Err(ArchiveError::Conflict);
        };
        for prefix in &mut self.prefixes {
            if prefix.offered.as_ref() == Some(acknowledgement) {
                prefix.consumed = Some(acknowledgement.clone());
                return Ok(());
            }
        }
        Err(ArchiveError::Conflict)
    }

    /// Retains a continuation of the same command after the actual preceding ACK.
    ///
    /// Source selects the next CPU/timer cut independently. This request supplies
    /// no new budget and cannot authorize the original pending I/O instruction.
    ///
    /// # Errors
    /// Rejects missing consumed ACK, completed/unknown history or an exhausted
    /// original prefix quota. Repeated requests retain the same bytes.
    pub fn continuation(&mut self) -> Result<NativeFrame, ArchiveError> {
        if let Some(original) = &self.pending_continuation {
            return Ok(NativeFrame::ContinuePrefix(Box::new(original.clone())));
        }
        if self.prefixes.len() == self.maximum_prefixes as usize {
            return Err(ArchiveError::Budget);
        }
        let prefix = self.prefixes.last().ok_or(ArchiveError::Conflict)?;
        let acknowledgement = prefix.consumed.clone().ok_or(ArchiveError::Conflict)?;
        let expected_cursor = match &prefix.result {
            ResultBody::Initial(result) => result.resulting,
            ResultBody::Typed(result) => result.resulting,
        };
        let continuation = NativePrefixContinuation {
            acknowledgement,
            expected_cursor,
        };
        match &prefix.result {
            ResultBody::Initial(result) => continuation.validate_initial(result)?,
            ResultBody::Typed(result) => continuation.validate_progress(result)?,
        }
        self.pending_continuation = Some(continuation.clone());
        Ok(NativeFrame::ContinuePrefix(Box::new(continuation)))
    }

    /// Copies complete terminal history for durable archival before native retirement.
    ///
    /// Native proposal bytes must come from the authentic source retirement
    /// operation. Their retention here grants no slot-release authority.
    ///
    /// # Errors
    /// Rejects unfinished continuation, nonterminal/unknown results, missing exact
    /// consumed ACKs or invalid bounded proposal/history.
    pub fn terminal_evidence(
        &self,
        native_proposal: Vec<u8>,
    ) -> Result<TerminalEvidence, ArchiveError> {
        if self.pending_continuation.is_some()
            || self.prefixes.last().is_none_or(|prefix| {
                prefix.result.status() != NativeEffectProgressStatus::Completed
            })
        {
            return Err(ArchiveError::Conflict);
        }
        let mut prefixes = Vec::new();
        prefixes
            .try_reserve_exact(self.prefixes.len())
            .map_err(|_| ArchiveError::Budget)?;
        for prefix in &self.prefixes {
            let offered = prefix.offered.as_ref().ok_or(ArchiveError::Conflict)?;
            let consumed = prefix.consumed.as_ref().ok_or(ArchiveError::Conflict)?;
            prefixes.push(PrefixEvidence {
                result: prefix.result.canonical()?,
                offered_acknowledgement: offered.encode()?,
                consumed_acknowledgement: consumed.encode()?,
            });
        }
        let evidence = TerminalEvidence {
            prefixes,
            native_proposal,
        };
        evidence.validate(&self.original, self.maximum_prefixes)?;
        Ok(evidence)
    }
}
