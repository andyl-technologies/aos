//! Bounded operational measurements over authentic campaign queue pages.
//!
//! The ordered digest retains the complete attempt sequence without collecting
//! it in memory. Neither the digest nor the work counters enter campaign state.

use std::error::Error;

use crucible_campaign::{
    AttemptId, AttemptQueue, CampaignRepository, CampaignSnapshotId, DaemonEpoch, WorkerSlotId,
};

/// Work and ordered identities retained from one complete snapshot-bound scan.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QueueScanMeasurement {
    pub(crate) attempts: usize,
    pub(crate) pages: usize,
    pub(crate) scanned_entries: usize,
    pub(crate) empty_pages: usize,
    pub(crate) maximum_page_attempts: usize,
    pub(crate) ordered_attempts_digest: blake3::Hash,
}

/// Walks the actual mixed accounting root and exercises one-slot reservations.
///
/// Page size and total page count are independent bounds. Empty pages retain
/// their continuation; reaching the page bound never accepts a partial scan.
///
/// # Errors
///
/// Returns an error for zero or exhausted page bounds, repository/proof or
/// reservation failures, and snapshot, cursor, or accounting violations.
pub(crate) fn scan_queue(
    repository: &CampaignRepository,
    name: &str,
    snapshot: CampaignSnapshotId,
    page_size: usize,
    maximum_pages: usize,
) -> Result<QueueScanMeasurement, Box<dyn Error>> {
    if maximum_pages == 0 {
        return Err("queue scan page bound must be positive".into());
    }
    let mut cursor = None;
    let mut measured = QueueScanMeasurement {
        attempts: 0,
        pages: 0,
        scanned_entries: 0,
        empty_pages: 0,
        maximum_page_attempts: 0,
        ordered_attempts_digest: blake3::hash(&[]),
    };
    let mut identities = OrderedAttemptDigest::new();
    let mut queue = AttemptQueue::new(DaemonEpoch::from_bytes([0x94; 16])?, 1)?;

    loop {
        if measured.pages == maximum_pages {
            return Err("paged queue exceeded its complete-scan bound".into());
        }
        let page = repository.project_claimable_attempts(name, cursor, page_size)?;
        if page.snapshot() != snapshot
            || page.scanned_entries() > page_size
            || page.attempts().len() > page.scanned_entries()
        {
            return Err("queue page violated its snapshot or accounting bound".into());
        }
        measured.pages += 1;
        measured.scanned_entries = measured
            .scanned_entries
            .checked_add(page.scanned_entries())
            .ok_or("queue accounting count overflow")?;
        measured.attempts = measured
            .attempts
            .checked_add(page.attempts().len())
            .ok_or("queue attempt count overflow")?;
        measured.empty_pages += usize::from(page.attempts().is_empty());
        measured.maximum_page_attempts = measured.maximum_page_attempts.max(page.attempts().len());
        for attempt in page.attempts() {
            identities.push(*attempt);
        }

        if let Some(first) = page.attempts().first() {
            let reservation = queue
                .reserve_from_page(&page, WorkerSlotId::new(0))?
                .ok_or("nonempty page did not yield a reservation")?;
            if reservation.attempt() != *first {
                return Err("queue reservation changed the first page attempt".into());
            }
            queue.release(reservation)?;
        }
        let next = page.next();
        if next.is_some() && next == cursor {
            return Err("queue cursor did not advance".into());
        }
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    if queue.reservation_count() != 0 {
        return Err("queue scan retained a worker reservation".into());
    }
    measured.ordered_attempts_digest = identities.finish();
    Ok(measured)
}

struct OrderedAttemptDigest(blake3::Hasher);

impl OrderedAttemptDigest {
    fn new() -> Self {
        Self(blake3::Hasher::new_derive_key(
            "crucible.campaign-queue.ordered-attempts.v1",
        ))
    }

    fn push(&mut self, attempt: AttemptId) {
        // Retain the complete typed content identity, including its schema.
        let identity = attempt.to_text();
        self.0.update(&(identity.len() as u64).to_be_bytes());
        self.0.update(identity.as_bytes());
    }

    fn finish(self) -> blake3::Hash {
        self.0.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_digest_distinguishes_reordering_replacement_and_duplication()
    -> Result<(), Box<dyn Error>> {
        fn digest(bytes: &[u8]) -> Result<blake3::Hash, Box<dyn Error>> {
            let mut digest = OrderedAttemptDigest::new();
            for byte in bytes {
                let identity = format!(
                    "crucible.campaign.attempt@campaign-fact.9.{}",
                    format!("{byte:02x}").repeat(32)
                );
                digest.push(AttemptId::parse(&identity)?);
            }
            Ok(digest.finish())
        }

        let original = digest(&[1, 2, 3])?;
        assert_ne!(original, digest(&[2, 1, 3])?);
        assert_ne!(original, digest(&[1, 2, 4])?);
        assert_ne!(original, digest(&[1, 2, 3, 3])?);
        assert_ne!(original, digest(&[])?);
        Ok(())
    }
}
