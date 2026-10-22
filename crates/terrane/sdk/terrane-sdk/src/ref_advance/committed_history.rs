//! Checks ordered reflog suffixes against an exact committed whole-record horizon.
//!
//! Append-first candidates beyond that horizon remain uncommitted. This pure
//! representation check grants no token authority or protection from later changes;
//! callers authorize the observation before I/O and recheck it before delivery.

use terrane_format::refs::{RefLogRecord, RefRecord};

use crate::store::{CorruptSubject, StoreErrorKind, StoreFailure};

/// Retains only a complete ordered suffix ending at the exact observed head.
///
/// # Errors
/// Refuses missing, duplicated or reordered committed sequences, malformed
/// records, inconsistent whole predecessors or a mismatching terminal record.
pub(crate) fn checked_suffix(
    reference: &str,
    from_sequence: u64,
    head: &RefRecord,
    mut records: Vec<RefLogRecord>,
) -> Result<Vec<RefLogRecord>, StoreFailure> {
    let corrupt = || {
        StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::RefName(
            reference.to_owned(),
        )))
    };

    // Append-first candidates are not committed merely because a backend can
    // return them. Only the exact authorized horizon may be reported.
    records.retain(|entry| entry.record.seq <= head.seq);
    let mut expected = from_sequence;
    let mut previous = None;
    for entry in &records {
        if entry.record.seq != expected || entry.encode().is_err() {
            return Err(corrupt());
        }
        if expected == 1 && entry.previous_commit.is_some() {
            return Err(corrupt());
        }
        if let Some(previous) = previous {
            if entry.record.candidate_id.is_some() {
                if entry.selected_previous().map_err(|_| corrupt())? != Some(previous) {
                    return Err(corrupt());
                }
            } else if entry.previous_commit != Some(previous.commit)
                || RefRecord::validate_successor(Some(previous), &entry.record).is_err()
            {
                return Err(corrupt());
            }
        }
        previous = Some(&entry.record);
        if entry.record.seq < head.seq {
            expected = expected.checked_add(1).ok_or_else(corrupt)?;
        }
    }
    if previous != Some(head) {
        return Err(corrupt());
    }

    Ok(records)
}
