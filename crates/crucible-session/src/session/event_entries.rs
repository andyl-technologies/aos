//! Independent event bodies and replaceable table-capacity loans for session logs.

use super::*;
use crucible::owned_decode::{self, DecodeBudget, DecodeCustody, DecodeScratch};

/// Owns a current vector capacity rather than an allocation history.
pub(super) struct LoanedVec<T> {
    values: Vec<T>,
    capacity: Option<DecodeScratch>,
    budget: Option<DecodeBudget>,
}

impl<T: fmt::Debug> fmt::Debug for LoanedVec<T> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("LoanedVec")
            .field("values", &self.values)
            .finish_non_exhaustive()
    }
}

impl<T> Default for LoanedVec<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            capacity: None,
            budget: None,
        }
    }
}

impl<T> std::ops::Deref for LoanedVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> LoanedVec<T> {
    pub(super) fn reserve(&mut self, additional: usize) -> Result<(), EngineError> {
        let required = self
            .values
            .len()
            .checked_add(additional)
            .ok_or_else(overflow)?;
        if required <= self.values.capacity() {
            return Ok(());
        }
        let capacity = required.checked_next_power_of_two().ok_or_else(overflow)?;
        let budget = match &self.budget {
            Some(budget) => budget.clone(),
            None => owned_decode::require_current_child_budget().map_err(admission)?,
        };
        let bytes = capacity
            .checked_mul(std::mem::size_of::<T>())
            .ok_or_else(overflow)?;
        let loan = budget
            .reserve_scratch_bytes(bytes as u64)
            .map_err(admission)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|source| admission(owned_decode::DecodeAdmissionError::new(source)))?;
        replacement.append(&mut self.values);
        let previous = std::mem::replace(&mut self.values, replacement);
        drop(previous);
        self.capacity = Some(loan);
        self.budget = Some(budget);
        Ok(())
    }

    /// Requires a prior successful capacity admission.
    pub(super) fn push_reserved(&mut self, value: T) {
        self.values.push(value);
    }

    pub(super) fn truncate(&mut self, length: usize) {
        self.values.truncate(length);
    }
}

/// Keeps individual body credits paired with the corresponding entry.
#[derive(Debug, Default)]
pub(super) struct AdmittedEventEntries {
    entries: LoanedVec<SchedulerEventLogEntry>,
    credits: LoanedVec<DecodeCustody>,
}

impl std::ops::Deref for AdmittedEventEntries {
    type Target = [SchedulerEventLogEntry];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

/// Retains transferred body and table loans until the request's final use.
pub(super) struct EventEntriesCredit {
    _credits: LoanedVec<DecodeCustody>,
    _capacity: Option<DecodeScratch>,
    _budget: Option<DecodeBudget>,
}

impl AdmittedEventEntries {
    pub(super) fn enter_original_scope(&self) -> Option<owned_decode::DecodeScope> {
        self.entries.budget.as_ref().map(DecodeBudget::enter)
    }

    pub(super) fn into_parts(self) -> (Vec<SchedulerEventLogEntry>, EventEntriesCredit) {
        let LoanedVec {
            values,
            capacity,
            budget,
        } = self.entries;
        (
            values,
            EventEntriesCredit {
                _credits: self.credits,
                _capacity: capacity,
                _budget: budget,
            },
        )
    }

    pub(super) fn copied(source: &[SchedulerEventLogEntry]) -> Result<Self, EngineError> {
        let mut entries = Self::default();
        entries.append_copies(source)?;
        Ok(entries)
    }

    pub(super) fn append_copies(
        &mut self,
        source: &[SchedulerEventLogEntry],
    ) -> Result<(), EngineError> {
        if source.is_empty() {
            return Ok(());
        }
        // Stage every independently owning body before changing the logical log.
        let mut staged = LoanedVec::default();
        staged.reserve(source.len())?;
        for entry in source {
            staged.push_reserved(entry.try_clone_admitted()?);
        }
        self.entries.reserve(source.len())?;
        self.credits.reserve(source.len())?;
        for entry in staged.values.drain(..) {
            let (entry, credit) = entry.into_parts();
            self.entries.push_reserved(entry);
            self.credits.push_reserved(credit);
        }
        Ok(())
    }

    pub(super) fn retain_before(&mut self, sequence: u64) {
        let length = self
            .entries
            .partition_point(|entry| entry.sequence() < sequence);
        // Removed bodies close before their matching original credits.
        self.entries.truncate(length);
        self.credits.truncate(length);
    }
}

fn admission(source: owned_decode::DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

fn overflow() -> EngineError {
    admission(owned_decode::DecodeAdmissionError::new(std::fmt::Error))
}

#[cfg(test)]
#[path = "event_entries/tests.rs"]
mod tests;
