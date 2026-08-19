//! Bounded rebuildable input pages for the local attempt queue.
//!
//! Queue pages are operational projections over one authenticated campaign
//! snapshot. They contain admitted semantic attempts that do not yet have a
//! canonical observation. The cursor is deliberately snapshot-bound: a head
//! advance makes it stale, forcing the supervisor to rebuild against the new
//! observation and accounting roots.

use super::*;

/// Process-local daemon incarnation attached only to volatile reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DaemonEpoch([u8; 16]);

impl DaemonEpoch {
    /// Builds a nonzero caller-generated daemon epoch.
    ///
    /// # Errors
    ///
    /// Returns an error for the all-zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, AttemptQueueError> {
        if bytes == [0; 16] {
            return Err(AttemptQueueError::ZeroDaemonEpoch);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact operational epoch bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Process-local worker slot identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerSlotId(u32);

impl WorkerSlotId {
    /// Builds one zero-based worker slot identity.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the zero-based slot number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Volatile lease of one immutable semantic attempt to one local worker slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptReservation {
    attempt: AttemptId,
    daemon_epoch: DaemonEpoch,
    worker_slot: WorkerSlotId,
    generation: u64,
}

impl AttemptReservation {
    /// Returns the immutable semantic attempt being leased.
    #[must_use]
    pub const fn attempt(self) -> AttemptId {
        self.attempt
    }

    /// Returns the daemon incarnation that owns this volatile lease.
    #[must_use]
    pub const fn daemon_epoch(self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the local worker slot receiving the attempt.
    #[must_use]
    pub const fn worker_slot(self) -> WorkerSlotId {
        self.worker_slot
    }

    /// Returns the monotonically assigned epoch-local lease generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Bounded process-local reservations over rebuildable claimable pages.
pub struct AttemptQueue {
    daemon_epoch: DaemonEpoch,
    maximum_reservations: usize,
    next_generation: u64,
    by_attempt: BTreeMap<AttemptId, AttemptReservation>,
    by_slot: BTreeMap<WorkerSlotId, AttemptId>,
}

impl AttemptQueue {
    /// Builds an empty reservation table for one daemon incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptQueueError::ZeroCapacity`] when no worker reservation
    /// can ever be admitted.
    pub fn new(
        daemon_epoch: DaemonEpoch,
        maximum_reservations: usize,
    ) -> Result<Self, AttemptQueueError> {
        if maximum_reservations == 0 {
            return Err(AttemptQueueError::ZeroCapacity);
        }
        Ok(Self {
            daemon_epoch,
            maximum_reservations,
            next_generation: 1,
            by_attempt: BTreeMap::new(),
            by_slot: BTreeMap::new(),
        })
    }

    /// Returns this queue's process-local daemon incarnation.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the number of currently held worker reservations.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.by_attempt.len()
    }

    /// Reserves the first unleased attempt in one canonical projection page.
    ///
    /// Repeating a claim for a slot that already owns a reservation returns the
    /// exact lease. An empty or fully reserved page returns `None`; callers then
    /// continue with [`ClaimableAttemptPage::next`].
    ///
    /// # Errors
    ///
    /// Returns an error when the configured reservation bound is full or the
    /// epoch-local generation counter is exhausted.
    pub fn reserve_from_page(
        &mut self,
        page: &ClaimableAttemptPage,
        worker_slot: WorkerSlotId,
    ) -> Result<Option<AttemptReservation>, AttemptQueueError> {
        if let Some(attempt) = self.by_slot.get(&worker_slot) {
            return Ok(self.by_attempt.get(attempt).copied());
        }
        let Some(attempt) = page
            .attempts()
            .iter()
            .copied()
            .find(|attempt| !self.by_attempt.contains_key(attempt))
        else {
            return Ok(None);
        };
        if self.by_attempt.len() >= self.maximum_reservations {
            return Err(AttemptQueueError::CapacityExhausted);
        }
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(AttemptQueueError::GenerationExhausted)?;
        let reservation = AttemptReservation {
            attempt,
            daemon_epoch: self.daemon_epoch,
            worker_slot,
            generation,
        };
        self.by_attempt.insert(attempt, reservation);
        self.by_slot.insert(worker_slot, attempt);
        Ok(Some(reservation))
    }

    /// Releases one exact reservation after completion or retry handoff.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptQueueError::ReservationMismatch`] when the lease is
    /// stale, belongs to another daemon epoch, or is not currently held.
    pub fn release(&mut self, reservation: AttemptReservation) -> Result<(), AttemptQueueError> {
        if reservation.daemon_epoch != self.daemon_epoch
            || self.by_attempt.get(&reservation.attempt) != Some(&reservation)
            || self.by_slot.get(&reservation.worker_slot) != Some(&reservation.attempt)
        {
            return Err(AttemptQueueError::ReservationMismatch);
        }
        self.by_attempt.remove(&reservation.attempt);
        self.by_slot.remove(&reservation.worker_slot);
        Ok(())
    }
}

/// Failure while managing bounded local attempt reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AttemptQueueError {
    /// The all-zero daemon epoch sentinel was supplied.
    #[error("daemon epoch must be nonzero")]
    ZeroDaemonEpoch,
    /// A queue was configured without any reservation capacity.
    #[error("attempt queue reservation capacity must be nonzero")]
    ZeroCapacity,
    /// Every configured worker reservation is currently occupied.
    #[error("attempt queue reservation capacity is exhausted")]
    CapacityExhausted,
    /// The epoch-local reservation generation counter overflowed.
    #[error("attempt queue reservation generation is exhausted")]
    GenerationExhausted,
    /// A release did not name the exact currently held lease.
    #[error("attempt reservation is stale or does not match the held lease")]
    ReservationMismatch,
}

/// Opaque continuation for one claimable-attempt projection scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptQueueCursor {
    snapshot: CampaignSnapshotId,
    accounting_after: CampaignHash,
}

impl AttemptQueueCursor {
    /// Returns the immutable campaign snapshot that owns this cursor.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }
}

/// One bounded page of admitted attempts without canonical observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimableAttemptPage {
    snapshot: CampaignSnapshotId,
    attempts: Vec<AttemptId>,
    scanned_entries: usize,
    next: Option<AttemptQueueCursor>,
}

impl ClaimableAttemptPage {
    /// Returns the authoritative snapshot used for this projection page.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns claimable attempts in canonical accounting-key order.
    #[must_use]
    pub fn attempts(&self) -> &[AttemptId] {
        &self.attempts
    }

    /// Returns the number of accounting entries consumed to build this page.
    #[must_use]
    pub const fn scanned_entries(&self) -> usize {
        self.scanned_entries
    }

    /// Returns the exclusive cursor for the next bounded scan, if any.
    #[must_use]
    pub const fn next(&self) -> Option<AttemptQueueCursor> {
        self.next
    }
}

impl CampaignRepository {
    /// Projects one bounded page of admitted attempts lacking observations.
    ///
    /// The scan limit bounds accounting entries examined, rather than results,
    /// because the accounting root also contains admissions, ordinals, and
    /// replay indexes. Empty pages with a continuation are therefore expected.
    /// Concatenating pages to EOF yields the same attempt sequence for every
    /// valid scan limit.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or invalid campaign, a cursor from an
    /// older snapshot, an invalid page size, malformed accounting membership,
    /// or an unreadable attempt/observation closure.
    pub fn project_claimable_attempts(
        &self,
        name: &str,
        cursor: Option<AttemptQueueCursor>,
        scan_limit: usize,
    ) -> Result<ClaimableAttemptPage, CampaignRepositoryError> {
        let head = self.head(name)?;
        let snapshot = head.snapshot_id();
        let after = match cursor {
            Some(cursor) if cursor.snapshot != snapshot => {
                return Err(CampaignRepositoryError::Stale {
                    expected: cursor.snapshot,
                    current: snapshot,
                });
            }
            Some(cursor) => Some(cursor.accounting_after),
            None => None,
        };

        let roots = head.snapshot().roots();
        let page = self.merkle.scan(roots.accounting, after, scan_limit)?;
        let mut attempts = Vec::new();
        for (key, value) in page.entries() {
            let envelope = self.read_envelope(*value)?;
            if envelope.record_kind() != crate::CampaignRecordKind::Attempt {
                continue;
            }
            let attempt = self.read_attempt(*value)?;
            let attempt_id = attempt.id()?;
            if *key != map_key_content("accounting.attempt", attempt_id.content_id()) {
                continue;
            }
            if self
                .merkle
                .get(
                    roots.observations,
                    map_key_content("observations.attempt", attempt_id.content_id()),
                )?
                .is_none()
            {
                attempts.push(attempt_id);
            }
        }

        Ok(ClaimableAttemptPage {
            snapshot,
            attempts,
            scanned_entries: page.entries().len(),
            next: page
                .next_after()
                .map(|accounting_after| AttemptQueueCursor {
                    snapshot,
                    accounting_after,
                }),
        })
    }
}
