//! Streaming checks of observation prefixes and assertion-failure boundaries.
//!
//! A savepoint or finding boundary commits to a digest over an event-log
//! prefix and, for assertion failures, to the single violation transition
//! inside the final quantum. These checks consume entries one at a time, so a
//! segmented log is verified while holding one segment.

use super::*;

/// Savepoint event-prefix digest computed one entry at a time.
///
/// The digest commits to the entry count before any entry, so the count is
/// fixed up front and [`Self::finish`] fails when a different number of
/// entries was supplied.
pub(crate) struct ObservationPrefixDigest {
    hasher: blake3::Hasher,
    expected: u64,
    supplied: u64,
}

impl ObservationPrefixDigest {
    pub(crate) fn new(entry_count: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
        hasher.update(&entry_count.to_be_bytes());
        Self {
            hasher,
            expected: entry_count,
            supplied: 0,
        }
    }

    pub(crate) fn update(&mut self, entry: &SchedulerEventLogEntry) {
        self.hasher.update(&entry.sequence().to_be_bytes());
        self.hasher.update(&entry.content_hash().bytes);
        self.supplied = self.supplied.saturating_add(1);
    }

    /// Returns the digest, or `None` when the supplied count differs.
    pub(crate) fn finish(self) -> Option<CampaignHash> {
        (self.supplied == self.expected).then(|| self.digest())
    }

    fn digest(self) -> CampaignHash {
        CampaignHash::from_bytes(*self.hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
pub(crate) fn observation_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> CampaignHash {
    let mut digest = ObservationPrefixDigest::new(entries.len() as u64);
    for entry in entries {
        digest.update(entry);
    }
    digest.digest()
}

/// Streaming search for the single violation transition of one property.
///
/// The scan requires a dense log from sequence zero with valid entry hashes,
/// and exactly one engine-sourced `Violated` transition for `property` at or
/// after `quantum_start_events`.
pub(crate) struct AssertionTransitionScan<'property> {
    property: &'property str,
    quantum_start_events: u64,
    next_sequence: u64,
    authenticated: bool,
    transition: Option<SchedulerEventLogEntry>,
    repeated: bool,
}

impl<'property> AssertionTransitionScan<'property> {
    pub(crate) const fn new(property: &'property str, quantum_start_events: u64) -> Self {
        Self {
            property,
            quantum_start_events,
            next_sequence: 0,
            authenticated: true,
            transition: None,
            repeated: false,
        }
    }

    pub(crate) fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        if entry.sequence() != self.next_sequence || !entry.has_valid_content_hash() {
            self.authenticated = false;
        }
        self.next_sequence = self.next_sequence.saturating_add(1);

        let is_transition = entry.sequence() >= self.quantum_start_events
            && matches!(entry.source(), EventSource::Engine)
            && matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(
                    ObservableEventPayload::AssertionStateChanged { name, state }
                ) if name.name == self.property && *state == AssertionPhase::Violated
            );
        if is_transition {
            if self.transition.is_some() {
                self.repeated = true;
            } else {
                self.transition = Some(entry.clone());
            }
        }
    }

    /// Returns the transition when the scanned log satisfied every rule.
    pub(crate) fn finish(self) -> Option<SchedulerEventLogEntry> {
        if !self.authenticated || self.repeated || self.next_sequence < self.quantum_start_events {
            return None;
        }
        self.transition
    }
}

#[cfg(test)]
pub(crate) fn verified_assertion_transition<'a>(
    entries: &'a [SchedulerEventLogEntry],
    quantum_start_events: u64,
    property: &str,
) -> Option<&'a SchedulerEventLogEntry> {
    let mut scan = AssertionTransitionScan::new(property, quantum_start_events);
    for entry in entries {
        scan.observe(entry);
    }
    let transition = scan.finish()?;
    entries.get(usize::try_from(transition.sequence()).ok()?)
}

/// Checks a retained finding's failure boundary against its replay leaf.
///
/// The leaf's complete log is streamed once from `source`. A missing or
/// unauthenticated segment fails the check.
pub(crate) fn verify_assertion_failure_boundary(
    leaf: &CrucibleMeasurementReplayEvidence,
    source: &dyn AttemptLogSegmentSource,
    boundary: &FindingAssertionFailureBoundary,
) -> bool {
    let mut digest = ObservationPrefixDigest::new(leaf.entry_count());
    let mut scan =
        AssertionTransitionScan::new(boundary.property(), boundary.quantum_start_events());
    let streamed = leaf.try_for_each_entry(source, |entry| {
        digest.update(entry);
        scan.observe(entry);
        Ok::<_, CrucibleMeasurementError>(())
    });
    let Some(transition) = streamed.ok().and_then(|()| scan.finish()) else {
        return false;
    };
    leaf.id().ok() == Some(boundary.trace())
        && leaf.stop() == CrucibleMeasurementStopEvidence::Campaign
        && leaf.entry_count() == boundary.terminal_events()
        && digest.finish() == Some(boundary.prefix_digest())
        && transition.sequence() == boundary.transition_sequence()
        && CampaignHash::from_bytes(transition.content_hash().bytes) == boundary.transition_hash()
}
