//! Release states, append-only journal entries, and per-destination replay.
//!
//! A journal records one global build lifecycle and then one lifecycle per
//! planned destination:
//!
//! ```text
//! global:          planned -> built -> finalized
//! destination d:   finalized -> published(d) -> rolling(d) -> rolling(d) -> complete(d)
//! failure:         any non-failed global state -> failed (terminal for the release)
//! ```
//!
//! Destinations interleave freely once the bundle is finalized; a production
//! destination may be published only after a staging destination holds a
//! publication. Entries use this shape:
//!
//! ```json
//! {"schema_version":"aos.release.journal-entry/v1","sequence":5,
//!  "previous_entry_digest":"sha256:...","plan_digest":"sha256:...",
//!  "manifest_digest":"sha256:...","prior_state":"finalized",
//!  "new_state":"published","destination":"staging/edge",
//!  "operation_ids":["publish-1"],"evidence":[],"recorded_at":"..."}
//! ```

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::RELEASE_JOURNAL_ENTRY;
use crate::digest::Sha256Digest;
use crate::plan::{ReleasePlan, SurfaceRole, parse_destination_name};
use crate::registry::registry_policy;

/// States of one immutable release identity or one of its destinations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseState {
    /// The frozen plan exists and no build effect is accepted yet.
    Planned,
    /// Planned artifacts were realized and build evidence was recorded.
    Built,
    /// External signing and final-byte assembly completed.
    Finalized,
    /// The exact bundle was published to one destination's surface.
    Published,
    /// At least one channel partition of the destination names the release.
    Rolling,
    /// The destination's planned rollout and handoff completed.
    Complete,
    /// A terminal failure was recorded; the version cannot be reused.
    Failed,
}

impl ReleaseState {
    /// Returns whether an entry in this state names a destination.
    #[must_use]
    pub const fn is_destination_state(self) -> bool {
        matches!(self, Self::Published | Self::Rolling | Self::Complete)
    }
}

impl std::fmt::Display for ReleaseState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Planned => "planned",
            Self::Built => "built",
            Self::Finalized => "finalized",
            Self::Published => "published",
            Self::Rolling => "rolling",
            Self::Complete => "complete",
            Self::Failed => "failed",
        };
        formatter.write_str(name)
    }
}

/// One hash-chained append-only release journal payload.
///
/// Destination states carry the destination they change; global states carry
/// none.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
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
    ///
    /// For a destination entry this is the destination's current state, or
    /// the global state when the destination has none yet.
    pub prior_state: Option<ReleaseState>,
    /// State committed by this operation.
    pub new_state: ReleaseState,
    /// Destination name for published, rolling, and complete entries; `None`
    /// otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Stable external or local operation identifiers.
    pub operation_ids: Vec<String>,
    /// Public evidence identities accepted by this transition.
    pub evidence: Vec<Sha256Digest>,
    /// RFC 3339 UTC timestamp supplied by the effectful coordinator.
    pub recorded_at: String,
}

impl JournalEntry {
    /// Computes the digest the next entry's `previous_entry_digest` must name.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical(&self.schema_version, self)
    }

    /// Validates the entry independently of its predecessor.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong schema, invalid first-entry shape, empty
    /// timestamp, duplicate operation id, duplicate evidence identity, or a
    /// destination that is missing, unexpected, or malformed.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RELEASE_JOURNAL_ENTRY {
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

        match (&self.destination, self.new_state.is_destination_state()) {
            (Some(destination), true) => {
                parse_destination_name(destination)?;
            }
            (None, false) => {}
            (Some(_), false) => bail!("only destination states may name a destination"),
            (None, true) => bail!("{} entries must name a destination", self.new_state),
        }
        Ok(())
    }
}

/// Replayed state of a verified journal.
///
/// `global` is the build lifecycle state (`planned`, `built`, `finalized`, or
/// `failed`) and `destinations` holds every destination that has been
/// published.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalSummary {
    /// Global build lifecycle state.
    pub global: ReleaseState,
    /// Current state of every published destination, keyed by name.
    pub destinations: BTreeMap<String, ReleaseState>,
}

impl JournalSummary {
    /// Starts replay from a validated first entry.
    pub(crate) fn start(first: &JournalEntry) -> Self {
        Self {
            global: first.new_state,
            destinations: BTreeMap::new(),
        }
    }

    /// Returns the state `entry.prior_state` must name for continuity.
    pub(crate) fn expected_prior(&self, entry: &JournalEntry) -> ReleaseState {
        entry
            .destination
            .as_ref()
            .and_then(|destination| self.destinations.get(destination))
            .copied()
            .unwrap_or(self.global)
    }

    /// Applies one validated, continuous entry.
    ///
    /// # Errors
    /// Returns an error for an illegal transition.
    pub(crate) fn apply(&mut self, entry: &JournalEntry) -> Result<()> {
        let Some(destination) = &entry.destination else {
            return self.apply_global(entry);
        };
        if self.global != ReleaseState::Finalized {
            bail!(
                "destination {destination} changes before finalization or after failure at sequence {}",
                entry.sequence
            );
        }
        let current = self.destinations.get(destination).copied();
        let legal = match (current, entry.new_state) {
            (None, ReleaseState::Published) => {
                self.require_after_satisfied(destination, entry.sequence)?;
                true
            }
            (Some(ReleaseState::Published | ReleaseState::Rolling), ReleaseState::Rolling)
            | (Some(ReleaseState::Rolling), ReleaseState::Complete) => true,
            _ => false,
        };
        if !legal {
            bail!(
                "illegal transition of destination {destination} to {} at sequence {}",
                entry.new_state,
                entry.sequence
            );
        }
        self.destinations
            .insert(destination.clone(), entry.new_state);
        Ok(())
    }

    fn apply_global(&mut self, entry: &JournalEntry) -> Result<()> {
        let legal = match (self.global, entry.new_state) {
            (ReleaseState::Planned, ReleaseState::Built)
            | (ReleaseState::Built, ReleaseState::Finalized) => true,
            (current, ReleaseState::Failed) => current != ReleaseState::Failed,
            _ => false,
        };
        if !legal {
            bail!(
                "illegal release state transition at sequence {}",
                entry.sequence
            );
        }
        self.global = entry.new_state;
        Ok(())
    }

    /// Enforces the contract floor that production follows staging.
    ///
    /// Every contract requires production destinations to list exactly
    /// `after = [staging]`, so this holds without the plan. The plan-aware
    /// check is [`JournalSummary::can_publish`].
    fn require_after_satisfied(&self, destination: &str, sequence: u64) -> Result<()> {
        let (role, _) = parse_destination_name(destination)?;
        if role == SurfaceRole::Production && !self.surface_holds_publication(SurfaceRole::Staging)
        {
            bail!(
                "production destination {destination} was published before any staging destination at sequence {sequence}"
            );
        }
        Ok(())
    }

    /// Returns whether any destination on `role` is published, rolling, or complete.
    #[must_use]
    pub fn surface_holds_publication(&self, role: SurfaceRole) -> bool {
        self.destinations.iter().any(|(name, state)| {
            state.is_destination_state()
                && parse_destination_name(name).is_ok_and(|(surface, _)| surface == role)
        })
    }

    /// Returns the current state of one destination, if it has been published.
    #[must_use]
    pub fn state_of(&self, destination: &str) -> Option<ReleaseState> {
        self.destinations.get(destination).copied()
    }

    /// Returns whether a terminal failure was recorded.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.global == ReleaseState::Failed
    }

    /// Returns whether every destination of `plan` is complete.
    ///
    /// Plans without destinations (qualification snapshots) are never complete.
    #[must_use]
    pub fn is_complete(&self, plan: &ReleasePlan) -> bool {
        !self.is_failed()
            && !plan.destinations.is_empty()
            && plan
                .destinations
                .iter()
                .all(|destination| self.state_of(&destination.name) == Some(ReleaseState::Complete))
    }

    /// Requires that `destination` may be published next.
    ///
    /// # Errors
    /// Returns an error for a journal that is not finalized or has failed, an
    /// unplanned or already published destination, or an `after` surface role
    /// of the destination's contract cell that holds no publication yet.
    pub fn can_publish(&self, plan: &ReleasePlan, destination: &str) -> Result<()> {
        match self.global {
            ReleaseState::Finalized => {}
            ReleaseState::Failed => bail!("release has failed; no destination may be published"),
            state => bail!("release must be finalized before publication; it is {state}"),
        }
        let planned = plan.destination(destination)?;
        if let Some(state) = self.state_of(destination) {
            bail!("destination {destination} is already {state}");
        }

        let tier = registry_policy(&plan.registry)?.tier();
        let cell =
            plan.qualification
                .destination(tier, planned.surface, planned.channel_kind()?)?;
        for role in &cell.after {
            if !self.surface_holds_publication(*role) {
                bail!("destination {destination} must follow a {role} publication");
            }
        }
        Ok(())
    }

    /// Requires that `destination` is published or rolling, so a channel
    /// range may advance or the rollout may complete.
    ///
    /// # Errors
    /// Returns an error for a failed journal, or a destination that is
    /// unpublished or already complete.
    pub fn require_rolling_allowed(&self, destination: &str) -> Result<()> {
        if self.is_failed() {
            bail!("failed journals cannot advance a channel");
        }
        match self.state_of(destination) {
            Some(ReleaseState::Published | ReleaseState::Rolling) => Ok(()),
            Some(state) => bail!("destination {destination} is {state}"),
            None => bail!("destination {destination} has not been published"),
        }
    }
}

/// Parses a canonical, newline-terminated release journal.
///
/// # Errors
///
/// Returns an error for non-UTF-8 input, an empty line, non-canonical JSON, an
/// invalid closed entry schema, or a missing final newline.
pub fn parse_journal(bytes: &[u8]) -> Result<Vec<JournalEntry>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("release journal is not UTF-8"))?;
    if !text.ends_with('\n') {
        bail!("release journal must end with a newline");
    }
    text.strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .enumerate()
        .map(|(index, line)| {
            if line.is_empty() {
                bail!("release journal contains an empty line at {}", index + 1);
            }
            crate::canonical::require_canonical(line.as_bytes(), "release journal entry")?;
            crate::canonical::from_slice(line.as_bytes(), "release journal entry")
        })
        .collect()
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
#[path = "state_tests.rs"]
mod tests;
