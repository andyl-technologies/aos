//! Durable source-only maintenance fences for exact paused executions.
//!
//! A declaration identifies an operation; it never proves destination
//! readiness. Preparation, cancellation and release all retain the selected
//! checkpoint. No ordinary ledger transition may remove an installed fence.

use super::*;

/// Declared destination intent for one offline maintenance operation.
///
/// These identities do not authenticate a destination or grant execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceTransferIntent {
    /// Digest of the complete versioned transfer operation declaration.
    pub operation: CampaignHash,
    /// Destination daemon incarnation named by that declaration.
    pub destination: DaemonEpoch,
    /// Digest of the authorized storage namespace declaration.
    pub namespace: CampaignHash,
    /// Nonzero immutable offer generation.
    pub offer_generation: u64,
    /// Required durable placement count; zero is not a maintenance intent.
    pub durable_placements: u64,
}

impl SourceTransferIntent {
    pub(super) fn valid(self) -> bool {
        self.operation.as_bytes() != [0; 32]
            && self.namespace.as_bytes() != [0; 32]
            && self.offer_generation != 0
            && self.durable_placements != 0
    }
}

/// Persistent disposition of a fenced source execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceTransferPhase {
    /// The source is retained and unavailable to ordinary execution admission.
    Prepared,
    /// Cancellation retained the fence; it did not restore resume permission.
    Canceled,
    /// Execution authority was durably released to the bound destination.
    ///
    /// This tombstone is not a destination execution grant or a Ready receipt.
    Released {
        /// Digest of the separately authenticated destination readiness.
        readiness: CampaignHash,
        /// Nonzero execution-ownership generation committed by its issuer.
        ownership_generation: u64,
    },
}

/// Bound source transfer state retained inside an exact paused record.
///
/// Private fields prevent an external caller from turning a declaration into
/// release authority. The operational supervisor owns all live transitions;
/// strict record decoding reconstructs persistent state after restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceTransferState {
    pub(in crate::assignment_ledger) intent: SourceTransferIntent,
    pub(in crate::assignment_ledger) phase: SourceTransferPhase,
}

impl SourceTransferState {
    /// Returns the operation declaration without issuing any authority.
    #[must_use]
    pub const fn intent(self) -> SourceTransferIntent {
        self.intent
    }

    /// Returns the retained source disposition.
    #[must_use]
    pub const fn phase(self) -> SourceTransferPhase {
        self.phase
    }

    pub(crate) fn prepared(intent: SourceTransferIntent) -> Option<Self> {
        intent.valid().then_some(Self {
            intent,
            phase: SourceTransferPhase::Prepared,
        })
    }

    pub(crate) fn canceled(self) -> Option<Self> {
        match self.phase {
            SourceTransferPhase::Prepared | SourceTransferPhase::Canceled => Some(Self {
                phase: SourceTransferPhase::Canceled,
                ..self
            }),
            SourceTransferPhase::Released { .. } => None,
        }
    }

    pub(crate) fn released(
        self,
        readiness: CampaignHash,
        ownership_generation: u64,
    ) -> Option<Self> {
        if self.phase != SourceTransferPhase::Prepared
            || readiness.as_bytes() == [0; 32]
            || ownership_generation == 0
        {
            return None;
        }
        Some(Self {
            phase: SourceTransferPhase::Released {
                readiness,
                ownership_generation,
            },
            ..self
        })
    }

    pub(in crate::assignment_ledger) fn valid(self) -> bool {
        self.intent.valid()
            && match self.phase {
                SourceTransferPhase::Prepared | SourceTransferPhase::Canceled => true,
                SourceTransferPhase::Released {
                    readiness,
                    ownership_generation,
                } => readiness.as_bytes() != [0; 32] && ownership_generation != 0,
            }
    }
}

impl AttemptRuntimeState {
    /// Returns the source fence without granting destination execution.
    #[must_use]
    pub const fn source_transfer(self) -> Option<SourceTransferState> {
        match self {
            Self::Paused {
                source_transfer, ..
            } => source_transfer,
            _ => None,
        }
    }

    pub(crate) fn with_source_transfer(self, transfer: SourceTransferState) -> Option<Self> {
        match self {
            Self::Paused {
                promotion_basis: None,
                ..
            } => {
                let mut next = self;
                if let Self::Paused {
                    source_transfer, ..
                } = &mut next
                {
                    *source_transfer = Some(transfer);
                }
                Some(next)
            }
            _ => None,
        }
    }
}

/// Rejects any attempt to discard or move an already installed source fence.
pub(super) fn preserves_source_transfer(
    current: Option<AttemptRuntimeState>,
    next: Option<AttemptRuntimeState>,
) -> bool {
    let Some(current) = current else { return true };
    let Some(before) = current.source_transfer() else {
        return true;
    };
    let Some(next) = next else { return false };
    let Some(after) = next.source_transfer() else {
        return false;
    };
    if before.intent != after.intent || current.with_source_transfer(after) != Some(next) {
        return false;
    }
    match before.phase {
        SourceTransferPhase::Prepared => true,
        SourceTransferPhase::Canceled | SourceTransferPhase::Released { .. } => before == after,
    }
}
