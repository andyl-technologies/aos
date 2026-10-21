//! Reads committed reflog history through current repository authorization.
//!
//! A history result describes one unchanged, authorized whole ref. It is an
//! observation, not a capability or proof for a later operation. Candidate logs
//! beyond that head cannot enter the result, even if a backend returns them.

use terrane_format::{
    auth::Verb,
    refs::{RefClass, RefLogRecord, RefName, RefRecord},
};

use super::{Error, Repository};
use crate::{
    ref_advance::AdvanceError,
    store::{Clock, CorruptSubject, LocalFs, Store, StoreErrorKind, StoreFailure},
};

#[cfg(test)]
mod tests;

/// Describes a currently authorized ref and its requested committed suffix.
///
/// The head remains the complete value observed by this read, including its
/// writer epoch, home and candidate selector. Entries retain recorded principals,
/// timestamps, reasons and whole predecessors. Reading history grants no right
/// to read the content named by an entry; that operation needs fresh policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefHistory {
    head: Option<RefRecord>,
    entries: Vec<RefLogRecord>,
}

impl RefHistory {
    /// Returns the exact current value checked before and after the log read.
    pub fn head(&self) -> Option<&RefRecord> {
        self.head.as_ref()
    }

    /// Borrows committed entries in increasing sequence order.
    pub fn entries(&self) -> &[RefLogRecord] {
        &self.entries
    }
}

impl<S: Store, C: Clock, F: LocalFs> Repository<S, C, F> {
    /// Reads a branch's committed reflog under fresh current read authority.
    ///
    /// Sequence zero selects the beginning. An absent branch or a sequence past
    /// the head returns no entries after authorization. Tags and other ref
    /// classes without branch logs are rejected. The backend's existing reflog
    /// operation materializes the requested suffix; this API is not a bounded
    /// streaming reader. Callers must apply their own service resource policy.
    ///
    /// Authorization runs again after storage I/O. A concurrently changed whole
    /// head refuses this attempt, so a caller can retry without mixing histories.
    /// No signing authority or raw store handle is exposed.
    ///
    /// # Errors
    /// Rejects invalid ref classes, denied or expired credentials, malformed or
    /// incomplete committed history and backend failures. Returns `Unavailable`
    /// when the complete ref changes during the read, including disappearance.
    pub async fn ref_history(
        &self,
        reference: &str,
        from_sequence: u64,
        token: &[u8],
        surface: &str,
    ) -> Result<RefHistory, Error> {
        let name = RefName::parse(reference).map_err(|_| AdvanceError::InvalidRefClass)?;
        if !matches!(
            name.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            return Err(AdvanceError::InvalidRefClass.into());
        }

        let guard = self.coordinator.guard();
        let authorized = guard
            .authorize(reference, token, Verb::Read, &[], surface)
            .await?;
        let head = authorized.record().cloned();
        let from_sequence = from_sequence.max(1);
        let entries = match &head {
            Some(head) if from_sequence <= head.seq => {
                let records = self
                    .coordinator
                    .store()
                    .ref_log_read(reference, from_sequence)
                    .await?;
                checked_suffix(reference, from_sequence, head, records)?
            }
            _ => Vec::new(),
        };

        // No result escapes on revocation, expiry or a changed selection while
        // storage was awaited. Equal commit hashes alone cannot bind a history.
        let current = guard
            .authorize(reference, token, Verb::Read, &[], surface)
            .await?;
        if current.record() != head.as_ref() {
            return Err(
                StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }).into(),
            );
        }

        Ok(RefHistory { head, entries })
    }
}

fn checked_suffix(
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
