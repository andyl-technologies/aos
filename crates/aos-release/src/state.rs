//! Legal release states and append-only journal transitions.
//!
//! Journal entries use this shape:
//!
//! ```json
//! {"schema_version":"aos.release.journal-entry/v1","sequence":1,
//!  "previous_entry_digest":null,"plan_digest":"sha256:...",
//!  "manifest_digest":null,"prior_state":null,"new_state":"planned",
//!  "operation_ids":[],"evidence":[],"recorded_at":"..."}
//! ```

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::RELEASE_JOURNAL_ENTRY_V1;
use crate::digest::Sha256Digest;

/// Monotonic states of one immutable release identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseState {
    /// The frozen plan exists and no build effect is accepted yet.
    Planned,
    /// Planned artifacts were realized and build evidence was recorded.
    Built,
    /// External signing and final-byte assembly completed.
    Finalized,
    /// The exact bundle was committed to staging.
    Staged,
    /// Staged public bytes passed every selected qualification gate.
    Qualified,
    /// The same immutable objects were admitted to production.
    Promoted,
    /// At least one public channel partition names the release.
    Rolling,
    /// The planned channel rollout and retention handoff completed.
    Complete,
    /// A terminal failure was recorded; the version cannot be reused.
    Failed,
}

impl ReleaseState {
    /// Returns whether `next` is a legal direct transition from this state.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Built)
                | (Self::Built, Self::Finalized)
                | (Self::Finalized, Self::Staged)
                | (Self::Staged, Self::Qualified)
                | (Self::Qualified, Self::Promoted)
                | (Self::Promoted, Self::Rolling)
                | (Self::Rolling, Self::Complete)
        ) || (!matches!(self, Self::Complete | Self::Failed) && matches!(next, Self::Failed))
    }
}

/// One signed append-only release journal payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntryV1 {
    /// Exact schema identifier.
    pub schema_version: String,
    /// One-based sequence number.
    pub sequence: u64,
    /// Digest of the prior canonical journal entry, absent only at sequence 1.
    pub previous_entry_digest: Option<Sha256Digest>,
    /// Frozen plan identity shared by every entry.
    pub plan_digest: Sha256Digest,
    /// Final manifest identity once finalization has completed.
    pub manifest_digest: Option<Sha256Digest>,
    /// State expected before this operation, absent only at sequence 1.
    pub prior_state: Option<ReleaseState>,
    /// State committed by this operation.
    pub new_state: ReleaseState,
    /// Stable external or local operation identifiers.
    pub operation_ids: Vec<String>,
    /// Public evidence identities accepted by this transition.
    pub evidence: Vec<Sha256Digest>,
    /// RFC 3339 UTC timestamp supplied by the effectful coordinator.
    pub recorded_at: String,
}

impl JournalEntryV1 {
    /// Validates the entry independently of its predecessor.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong schema, invalid first-entry shape, empty
    /// timestamp, duplicate operation id, or duplicate evidence identity.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RELEASE_JOURNAL_ENTRY_V1 {
            bail!("unsupported journal schema: {}", self.schema_version);
        }
        if self.sequence == 0 {
            bail!("journal sequence must be one-based");
        }
        if self.recorded_at.trim().is_empty() {
            bail!("journal timestamp cannot be empty");
        }
        require_unique(&self.operation_ids, "journal operation id")?;
        require_unique(&self.evidence, "journal evidence digest")?;

        if self.sequence == 1 {
            if self.previous_entry_digest.is_some()
                || self.prior_state.is_some()
                || self.new_state != ReleaseState::Planned
            {
                bail!("first journal entry must enter planned without a predecessor");
            }
        } else if self.previous_entry_digest.is_none() || self.prior_state.is_none() {
            bail!("non-initial journal entry requires prior state and digest");
        }
        if self.new_state >= ReleaseState::Finalized
            && self.new_state != ReleaseState::Failed
            && self.manifest_digest.is_none()
        {
            bail!("finalized and later journal states require a manifest digest");
        }
        Ok(())
    }
}

fn require_unique<T>(values: &[T], label: &str) -> Result<()>
where
    T: Ord + Clone,
{
    let mut sorted = values.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("duplicate {label}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_are_strictly_monotonic() {
        assert!(ReleaseState::Planned.can_transition_to(ReleaseState::Built));
        assert!(ReleaseState::Built.can_transition_to(ReleaseState::Failed));
        assert!(!ReleaseState::Built.can_transition_to(ReleaseState::Staged));
        assert!(!ReleaseState::Failed.can_transition_to(ReleaseState::Planned));
        assert!(!ReleaseState::Complete.can_transition_to(ReleaseState::Failed));
    }
}
