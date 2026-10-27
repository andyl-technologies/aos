//! Compact proofs that a replay reached an exact modeled boundary.
//!
//! A savepoint or checkpoint boundary is identified by its configuration,
//! scheduler coordinates, a digest over the complete event prefix, and the
//! identity of the prefix's causal projection. Replays prove they reached the
//! same boundary by recomputing these over their own retained log.

use super::*;

/// Compact proof of the modeled boundary and causal log reached by replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuSavepointReplayProof {
    pub(super) configuration: ContentHash,
    pub(super) completed_quanta: u64,
    pub(super) frontier: VirtualTime,
    pub(super) event_count: u64,
    event_digest: [u8; 32],
    causal_digest: ContentHash,
    causal_bytes: usize,
    causal_events: usize,
    event_log_offset: Option<EventLogOffset>,
    attempt_event_count: Option<u64>,
}

/// Authenticated event prefix reconstructed at an ordinary attempt's start.
///
/// The proof is sealed before lifecycle shutdown, so it covers inherited
/// genesis-to-start evidence and excludes later same-attempt and final-drain
/// events. Exact resume uses that boundary to derive attempt-local progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuAttemptStartReplayProof {
    configuration: ContentHash,
    event_count: u64,
    event_digest: [u8; 32],
}

impl QemuAttemptStartReplayProof {
    #[cfg(test)]
    pub(crate) fn from_reached_boundary(
        configuration: &Configuration,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(entries.len())
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        Ok(Self {
            configuration: configuration.id(),
            event_count,
            event_digest: savepoint_event_prefix_digest(entries),
        })
    }

    /// Binds a reached configuration to a retained log's complete prefix.
    pub(crate) fn from_retained_boundary(
        configuration: &Configuration,
        log: &RetainedAttemptLog,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        Ok(Self {
            configuration: configuration.id(),
            event_count: u64::try_from(log.len())
                .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?,
            event_digest: log.event_prefix_digest()?,
        })
    }

    pub(crate) fn attempt_event_count(
        self,
        start: &Configuration,
        entries: &[SchedulerEventLogEntry],
    ) -> Option<usize> {
        let event_count = usize::try_from(self.event_count).ok()?;
        let prefix = entries.get(..event_count)?;
        (self.configuration == start.id()
            && self.event_digest == savepoint_event_prefix_digest(prefix))
        .then_some(entries.len() - event_count)
    }
}

impl QemuSavepointReplayProof {
    /// Binds a reached configuration to its scheduler coordinate, complete
    /// event prefix, and canonical causal subsequence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::SavepointReplayProof`] when the
    /// event count cannot be represented by the portable proof.
    pub fn from_reached_boundary(
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(entries.len())
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        let causal = crucible_engine::event_log_causal_projection(entries);
        Ok(Self {
            configuration: configuration.id(),
            completed_quanta,
            frontier,
            event_count,
            event_digest: savepoint_event_prefix_digest(entries),
            causal_digest: causal.content_hash(),
            causal_bytes: causal.canonical_bytes().len(),
            causal_events: causal.len(),
            event_log_offset: None,
            attempt_event_count: None,
        })
    }

    /// Binds a reached configuration to a retained log, streaming its segments.
    ///
    /// # Errors
    ///
    /// Returns a proof error when the log cannot be read back or its folded
    /// causal count disagrees with its entries.
    pub(crate) fn from_retained_boundary(
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        log: &RetainedAttemptLog,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let identity = log.identity()?;
        Ok(Self {
            configuration: configuration.id(),
            completed_quanta,
            frontier,
            event_count: identity.event_count,
            event_digest: identity.event_digest,
            causal_digest: identity.causal.content_hash,
            causal_bytes: identity.causal.canonical_bytes,
            causal_events: identity.causal.entries,
            event_log_offset: None,
            attempt_event_count: None,
        })
    }

    /// Seals the private replay boundary before teardown changes its log.
    ///
    /// # Errors
    ///
    /// Returns a mismatch unless modeled driving stopped at the requested
    /// checkpoint boundary.
    pub(crate) fn from_checkpoint_replay_boundary(
        pending: QemuFreshPendingObservation,
        event_log_offset: EventLogOffset,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        if !matches!(pending.stop, ModeledStop::ReplayBoundary) {
            return Err(QemuFreshModeledDriverError::SelectedResumeBoundaryMismatch);
        }
        Self::from_retained_boundary(
            &pending.configuration,
            pending.completed_quanta,
            pending.terminal_at,
            &pending.event_log,
        )?
        .with_event_log_offset(event_log_offset)
    }

    /// Binds the independently produced segment-chain offset to this proof.
    ///
    /// # Errors
    ///
    /// Returns a proof error when the offset's event count differs from the
    /// independently retained entries.
    pub(crate) fn with_event_log_offset(
        mut self,
        event_log_offset: EventLogOffset,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        if event_log_offset.events != self.event_count {
            return Err(QemuFreshModeledDriverError::SavepointReplayProof);
        }
        self.event_log_offset = Some(event_log_offset);
        Ok(self)
    }

    pub(crate) fn with_attempt_event_count(
        mut self,
        event_count: usize,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(event_count)
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        if event_count > self.event_count {
            return Err(QemuFreshModeledDriverError::SavepointReplayProof);
        }
        self.attempt_event_count = Some(event_count);
        Ok(self)
    }

    pub(crate) const fn attempt_event_count(self) -> Option<u64> {
        self.attempt_event_count
    }

    pub(crate) fn same_boundary(self, other: Self) -> bool {
        self.configuration == other.configuration
            && self.completed_quanta == other.completed_quanta
            && self.frontier == other.frontier
            && self.event_count == other.event_count
            && self.event_digest == other.event_digest
            && self.causal_digest == other.causal_digest
            && self.causal_bytes == other.causal_bytes
            && self.causal_events == other.causal_events
            && self.event_log_offset == other.event_log_offset
    }

    /// Binds a restored checkpoint's boundary, streaming its referenced log.
    ///
    /// Sealed segments are read from `segments` and authenticated one at a
    /// time. Like [`Self::from_reached_boundary`], the proof leaves the
    /// segment-chain offset unbound.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::SavepointReplayProof`] when the
    /// checkpoint covers only a log suffix, or a referenced segment cannot be
    /// read or authenticated.
    pub fn from_checkpoint(
        configuration: &Configuration,
        scheduler: &crucible_engine::SingleSchedulerCheckpoint,
        segments: &(impl crucible_engine::EventLogSegmentReader + ?Sized),
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let identity = checkpoint_log_identity(scheduler, segments)?;
        Ok(Self {
            configuration: configuration.id(),
            completed_quanta: scheduler.quanta(),
            frontier: scheduler.frontier(),
            event_count: identity.event_count,
            event_digest: identity.event_digest,
            causal_digest: identity.causal.content_hash,
            causal_bytes: identity.causal.canonical_bytes,
            causal_events: identity.causal.entries,
            event_log_offset: None,
            attempt_event_count: None,
        })
    }

    /// Returns whether one restored checkpoint has this exact modeled boundary.
    ///
    /// The checkpoint's log is streamed from `segments` only after its scalar
    /// coordinates match. A segment that cannot be read or authenticated is a
    /// mismatch.
    #[must_use]
    pub fn matches_checkpoint(
        self,
        configuration: &Configuration,
        scheduler: &crucible_engine::SingleSchedulerCheckpoint,
        segments: &(impl crucible_engine::EventLogSegmentReader + ?Sized),
    ) -> bool {
        // The live replay offset authenticates the ordered segment chain,
        // encoded byte count, and event count. Entries alone cannot
        // reconstruct segment boundaries or their prefix hash.
        let offset = scheduler.event_log_offset();
        if !self.matches_coordinates(
            configuration,
            scheduler.quanta(),
            scheduler.frontier(),
            offset.events,
        ) || self
            .event_log_offset
            .is_some_and(|expected| expected != offset)
        {
            return false;
        }
        checkpoint_log_identity(scheduler, segments).is_ok_and(|identity| {
            self.event_digest == identity.event_digest && self.matches_causal(identity.causal)
        })
    }

    /// Returns the cumulative scheduler work required to reconstruct the boundary.
    #[must_use]
    pub const fn completed_quanta(self) -> u64 {
        self.completed_quanta
    }

    pub(crate) fn matches_boundary(
        self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        event_base: u64,
        entries: &[SchedulerEventLogEntry],
    ) -> bool {
        let Ok(event_count) = u64::try_from(entries.len()) else {
            return false;
        };
        if !self.matches_coordinates(configuration, completed_quanta, frontier, event_count)
            || event_base != 0
            || self.event_digest != savepoint_event_prefix_digest(entries)
        {
            return false;
        }
        self.matches_causal(crucible_engine::event_log_causal_projection(entries).summary())
    }

    /// Returns whether a retained log reached this exact boundary.
    ///
    /// Scalar coordinates are compared first, so the per-quantum check reads
    /// the log only at the one quantum whose event count matches.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when the log must be
    /// read and a sealed segment cannot be read back.
    pub(crate) fn matches_retained_boundary(
        self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        log: &RetainedAttemptLog,
    ) -> Result<bool, QemuFreshModeledDriverError> {
        let Ok(event_count) = u64::try_from(log.len()) else {
            return Ok(false);
        };
        if !self.matches_coordinates(configuration, completed_quanta, frontier, event_count) {
            return Ok(false);
        }
        let identity = log.identity()?;
        Ok(self.event_digest == identity.event_digest && self.matches_causal(identity.causal))
    }

    fn matches_coordinates(
        self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        event_count: u64,
    ) -> bool {
        self.configuration == configuration.id()
            && self.completed_quanta == completed_quanta
            && self.frontier == frontier
            && self.event_count == event_count
    }

    fn matches_causal(self, causal: crucible_engine::EventLogCausalSummary) -> bool {
        self.causal_digest == causal.content_hash
            && self.causal_bytes == causal.canonical_bytes
            && self.causal_events == causal.entries
    }
}

/// Authenticated private target used only to verify a later own checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuSelectedResumeBoundary {
    configuration: Configuration,
    proof: QemuSavepointReplayProof,
}

impl QemuSelectedResumeBoundary {
    /// Binds the complete decoded configuration to its scheduler/evidence proof.
    #[must_use]
    pub const fn new(configuration: Configuration, proof: QemuSavepointReplayProof) -> Self {
        Self {
            configuration,
            proof,
        }
    }

    /// Returns the authenticated full configuration at the checkpoint boundary.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the compact scheduler and event-prefix proof for the boundary.
    #[must_use]
    pub const fn proof(&self) -> QemuSavepointReplayProof {
        self.proof
    }

    pub(super) fn matches(
        &self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        log: &RetainedAttemptLog,
    ) -> Result<bool, QemuFreshModeledDriverError> {
        if self.configuration != *configuration {
            return Ok(false);
        }
        self.proof
            .matches_retained_boundary(configuration, completed_quanta, frontier, log)
    }

    pub(super) fn was_passed(&self, completed_quanta: u64, frontier: VirtualTime) -> bool {
        completed_quanta > self.proof.completed_quanta || frontier > self.proof.frontier
    }

    pub(super) fn matches_pre_choice_quantum(
        &self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        prior: &RetainedAttemptLog,
        quantum_entries: &[SchedulerEventLogEntry],
    ) -> Result<bool, QemuFreshModeledDriverError> {
        let Some(event_count) = prior.len().checked_add(quantum_entries.len()) else {
            return Ok(false);
        };
        let Ok(portable_event_count) = u64::try_from(event_count) else {
            return Ok(false);
        };
        if self.configuration != *configuration
            || !self.proof.matches_coordinates(
                configuration,
                completed_quanta,
                frontier,
                portable_event_count,
            )
        {
            return Ok(false);
        }
        Ok(self.proof.event_digest == prior.event_prefix_digest_with(quantum_entries)?)
    }
}

/// Streams a checkpoint's complete event log into its boundary identity.
///
/// The causal projection's header names its entry count, so a first pass
/// counts causal entries and a second digests both projections. Each pass
/// holds at most one sealed segment.
fn checkpoint_log_identity(
    scheduler: &crucible_engine::SingleSchedulerCheckpoint,
    segments: &(impl crucible_engine::EventLogSegmentReader + ?Sized),
) -> Result<super::attempt_log::RetainedLogIdentity, QemuFreshModeledDriverError> {
    let invalid = |_| QemuFreshModeledDriverError::SavepointReplayProof;
    if scheduler.event_log_base_events() != 0 {
        return Err(QemuFreshModeledDriverError::SavepointReplayProof);
    }
    let event_count = scheduler.event_log_offset().events;

    let mut causal_entries = 0_u64;
    scheduler
        .try_for_each_event_log_entry(segments, |entry| {
            if crucible_engine::is_causal_event_log_entry(entry) {
                causal_entries += 1;
            }
            Ok::<_, crucible_engine::SingleSchedulerCheckpointError>(())
        })
        .map_err(invalid)?;

    let mut prefix = SavepointEventPrefixDigest::new(event_count);
    let mut causal = crucible_engine::EventLogCausalDigest::new(causal_entries);
    scheduler
        .try_for_each_event_log_entry(segments, |entry| {
            prefix.update(entry);
            causal.observe(entry);
            Ok::<_, crucible_engine::SingleSchedulerCheckpointError>(())
        })
        .map_err(invalid)?;
    Ok(super::attempt_log::RetainedLogIdentity {
        event_count,
        event_digest: prefix.finish(),
        causal: causal
            .finish()
            .ok_or(QemuFreshModeledDriverError::SavepointReplayProof)?,
    })
}

fn savepoint_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> [u8; 32] {
    let mut digest = SavepointEventPrefixDigest::new(entries.len() as u64);
    entries.iter().for_each(|entry| digest.update(entry));
    digest.finish()
}

/// Incremental savepoint event-prefix digest over a known entry count.
///
/// The count is hashed before the entries, so it must be known up front.
pub(crate) struct SavepointEventPrefixDigest {
    hasher: blake3::Hasher,
}

impl SavepointEventPrefixDigest {
    pub(crate) fn new(count: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
        hasher.update(&count.to_be_bytes());
        Self { hasher }
    }

    pub(crate) fn update(&mut self, entry: &SchedulerEventLogEntry) {
        self.hasher.update(&entry.sequence().to_be_bytes());
        self.hasher.update(&entry.content_hash().bytes);
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}
