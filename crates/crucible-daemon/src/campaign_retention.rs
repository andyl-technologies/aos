//! Snapshot-bound local campaign retention-root discovery.
//!
//! This module composes the campaign repository's authenticated semantic pin
//! projection with the executor assignment ledger's operational observation
//! and exact-checkpoint roots. It deliberately produces an inventory rather
//! than a deletion plan: a destructive garbage collector must additionally
//! bind the physical object inventory to a store generation and revalidate the
//! campaign snapshot before applying any deletion.

use crucible_campaign::{
    CampaignName, CampaignPinRetentionRecord, CampaignPinRetentionSummary, CampaignRepository,
    CampaignRepositoryError, ObservationId,
};
use thiserror::Error;

use crate::{AssignmentLedger, ExactCheckpointId};

/// One authenticated retention root discovered for the local campaign subsystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalCampaignRetentionRoot {
    /// One current semantic pin and its thin replay artifacts.
    SemanticPin(Box<CampaignPinRetentionRecord>),
    /// One in-progress or completed executor observation publication.
    Observation(ObservationId),
    /// One in-progress or paused exact-checkpoint publication.
    ExactCheckpoint(ExactCheckpointId),
}

/// Terminal evidence that one local retention inventory completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCampaignRetentionSummary {
    semantic_pins: CampaignPinRetentionSummary,
    observation_roots: u64,
    checkpoint_roots: u64,
}

impl LocalCampaignRetentionSummary {
    /// Returns the terminal summary for the authenticated semantic pin scan.
    #[must_use]
    pub const fn semantic_pins(self) -> CampaignPinRetentionSummary {
        self.semantic_pins
    }

    /// Returns the number of operational observation-root records visited.
    #[must_use]
    pub const fn observation_roots(self) -> u64 {
        self.observation_roots
    }

    /// Returns the number of operational exact-checkpoint-root records visited.
    #[must_use]
    pub const fn checkpoint_roots(self) -> u64 {
        self.checkpoint_roots
    }
}

/// Failure to complete one local campaign retention inventory.
#[derive(Debug, Error)]
pub enum LocalCampaignRetentionError<E> {
    /// The semantic campaign root set was unavailable, corrupt, or inconsistent.
    #[error(transparent)]
    Campaign(#[from] CampaignRepositoryError),
    /// The operational assignment ledger could not be enumerated completely.
    #[error("assignment-ledger retention-root discovery failed")]
    Ledger(#[source] E),
    /// A root count exceeded the representable inventory summary.
    #[error("local campaign retention {category} count overflow")]
    CountOverflow {
        /// Stable root category whose count overflowed.
        category: &'static str,
    },
}

/// Streams one campaign's semantic roots and the supplied local ledger's roots.
///
/// Semantic pins are emitted first, followed by observation and exact
/// checkpoint roots from the operational ledger. Assignment-ledger records are
/// lineage-qualified rather than campaign-name-qualified, so they are a
/// host-local root set and are not attributed to the named campaign. A caller
/// aggregating several campaign refs should enumerate that ledger only once.
/// The ledger may name the same immutable root from more than one runtime
/// record; visitors that construct a physical retain set should deduplicate by
/// content identity.
///
/// Visited roots are tentative until this function returns a terminal
/// [`LocalCampaignRetentionSummary`]. Even a successful summary is only an
/// inventory input. A destructive collector must bind the physical inventory
/// to a store generation and prove that the campaign snapshot named by
/// [`CampaignPinRetentionSummary::snapshot`] is still authoritative before it
/// deletes anything.
///
/// # Errors
///
/// Returns [`LocalCampaignRetentionError::Campaign`] if the campaign's current
/// semantic pin projection cannot be authenticated,
/// [`LocalCampaignRetentionError::Ledger`] if operational enumeration fails,
/// or [`LocalCampaignRetentionError::CountOverflow`] if a terminal count cannot
/// be represented. The visitor may already have observed a prefix on error.
pub fn visit_local_campaign_retention_roots<L: AssignmentLedger>(
    repository: &CampaignRepository,
    campaign: &CampaignName,
    ledger: &L,
    visitor: &mut dyn FnMut(LocalCampaignRetentionRoot),
) -> Result<LocalCampaignRetentionSummary, LocalCampaignRetentionError<L::Error>> {
    let semantic_pins = repository.visit_pin_retention_roots(campaign.as_str(), &mut |record| {
        visitor(LocalCampaignRetentionRoot::SemanticPin(Box::new(record)))
    })?;

    let mut observation_roots = 0_u64;
    let mut observation_overflow = false;
    ledger
        .visit_observation_roots(&mut |observation| {
            let Some(next) = observation_roots.checked_add(1) else {
                observation_overflow = true;
                return;
            };
            observation_roots = next;
            visitor(LocalCampaignRetentionRoot::Observation(observation));
        })
        .map_err(LocalCampaignRetentionError::Ledger)?;
    if observation_overflow {
        return Err(LocalCampaignRetentionError::CountOverflow {
            category: "observation-root",
        });
    }

    let mut checkpoint_roots = 0_u64;
    let mut checkpoint_overflow = false;
    ledger
        .visit_checkpoint_roots(&mut |checkpoint| {
            let Some(next) = checkpoint_roots.checked_add(1) else {
                checkpoint_overflow = true;
                return;
            };
            checkpoint_roots = next;
            visitor(LocalCampaignRetentionRoot::ExactCheckpoint(checkpoint));
        })
        .map_err(LocalCampaignRetentionError::Ledger)?;
    if checkpoint_overflow {
        return Err(LocalCampaignRetentionError::CountOverflow {
            category: "checkpoint-root",
        });
    }

    Ok(LocalCampaignRetentionSummary {
        semantic_pins,
        observation_roots,
        checkpoint_roots,
    })
}

#[cfg(test)]
mod tests;
