//! Retains fresh main-writer intervals around the four finite helper requests.
//!
//! Each before observes the original replayed file, never a rebased current
//! file. Its independent after remains owed even when send, receive or Source
//! currentness fails. The same actual writer and exclusive locks stay resident.

use aos_sandbox_journal::protected_storage::FileIdentity;

use super::*;

const EXCHANGES: usize = 4;

pub(super) struct InitialNvMainCurrentnessOriginalV1 {
    quote: Option<Result<ResourceVector, JournalError>>,
    pub(super) intervals: [approval_currentness::ApprovalCurrentnessOriginalV1; EXCHANGES],
    next: usize,
    active: bool,
    closed: Option<JournalError>,
}

impl InitialNvMainCurrentnessOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            quote: None,
            intervals: std::array::from_fn(|_| {
                approval_currentness::ApprovalCurrentnessOriginalV1::new()
            }),
            next: 0,
            active: false,
            closed: None,
        }
    }

    pub(super) fn quote_once(
        &mut self,
        journal: &Journal,
        replayed: FileIdentity,
    ) -> Option<ResourceVector> {
        if self.quote.is_some() || self.next != 0 || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.quote = Some((|| {
            let mut demand = ResourceVector::ZERO;
            for interval in &mut self.intervals {
                let next = interval
                    .quote_once(journal, replayed)
                    .ok_or(JournalError::ProtectedBoundary)?;
                demand = demand
                    .checked_add(next)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            }
            Ok(demand)
        })());
        self.quote.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn begin_once(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.active
            || self.failure().is_some()
            || !matches!(self.quote, Some(Ok(_)))
            || self.next >= EXCHANGES
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let index = self.next;
        self.next += 1;
        self.active = true;
        self.intervals[index].before_once(journal)
    }

    pub(super) fn finish_after_owed(&mut self, journal: &Journal) -> Result<(), JournalError> {
        // A failed before or earlier transport/Source refusal cannot suppress
        // this actual after. Completed intervals retain their original result.
        for interval in &mut self.intervals[..self.next] {
            let _after = interval.finish_after_owed(journal);
        }
        if self.failure().is_some() {
            Err(JournalError::ProtectedBoundary)
        } else {
            self.active = false;
            Ok(())
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.quote
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.intervals
                    .iter()
                    .find_map(|interval| interval.failure())
            })
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn quote_initial_nv_main_once(&mut self) -> Option<ResourceVector> {
        if self.failure().is_some() || self.post.is_some() || !self.tpm_locks.ready() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        let replayed = self
            .inner
            .original
            .captured_replay_file_identity_data_v1()?;
        self.nv_currentness
            .quote_once(self.inner.original.journal_data_v1()?, replayed)
    }

    pub(crate) fn begin_initial_nv_main_once(&mut self) -> Result<(), JournalError> {
        if self.failure().is_some() || self.post.is_some() || !self.tpm_locks.ready() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let journal = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.nv_currentness.begin_once(journal)
    }

    pub(crate) fn finish_initial_nv_main_after_owed(&mut self) -> Result<(), JournalError> {
        // The original journal is used even when the Source has already failed.
        let journal = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.nv_currentness.finish_after_owed(journal)
    }
}
