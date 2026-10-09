//! Incremental native replay coordinates, counts, and transaction identities.
//!
//! The bookkeeping owner retains one transaction-ID set throughout replay.
//! Callers keep frame reads, closed namespace decoding, semantic joins, and
//! record application at their existing positions between these operations.
//! Coordinates describe caller-recorded progress, not durable receipts or
//! permission to repair, publish, or apply a transaction.

use std::collections::BTreeSet;

use crate::framing::Frame;

/// Reports mechanical replay failures without interpreting domain records.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeReplayError {
    /// A frame does not have the next exact sequence at the current offset.
    #[error("journal sequence discontinuity at byte offset {0}")]
    SequenceDiscontinuity(u64),
    /// Sequence space cannot advance without wrapping.
    #[error("journal sequence space is exhausted")]
    SequenceExhausted,
    /// The next frame offset cannot be represented.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A transaction identity is already in the resident set.
    #[error("transaction identity was already committed")]
    DuplicateTransaction,
    /// A replay count overflows or exceeds its supplied bound.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

/// Copies replay progress DATA without certifying semantic or physical validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeReplayCoordinates {
    /// Measures bytes observed through the most recently reached frame.
    pub offset: u64,
    /// Records the end chosen by the caller's latest successful commit step.
    pub durable_end: u64,
    /// Names the next expected frame sequence.
    pub expected_sequence: u64,
    /// Records the next sequence at the caller's latest commit boundary.
    pub durable_next_sequence: u64,
    /// Counts the caller's reached commit-accounting steps.
    pub committed_transactions: usize,
    /// Counts rows at successful caller-recorded commit boundaries.
    pub committed_records: usize,
}

/// Owns incremental native replay accounting and its original transaction-ID set.
///
/// Methods do not decode records, observe files, or authorize transactions.
/// Failures retain the same partially advanced coordinates as the ordered
/// operations they replace; the owner is deliberately not cloneable.
pub struct NativeReplayBookkeeping {
    coordinates: NativeReplayCoordinates,
    transaction_ids: BTreeSet<[u8; 16]>,
}

impl NativeReplayBookkeeping {
    /// Starts empty bookkeeping at byte zero and frame sequence one.
    pub fn new() -> Self {
        Self {
            coordinates: NativeReplayCoordinates {
                offset: 0,
                durable_end: 0,
                expected_sequence: 1,
                durable_next_sequence: 1,
                committed_transactions: 0,
                committed_records: 0,
            },
            transaction_ids: BTreeSet::new(),
        }
    }

    /// Copies current coordinates without transferring the resident ID set.
    pub fn coordinates(&self) -> NativeReplayCoordinates {
        self.coordinates
    }

    /// Checks a reached frame sequence, then advances sequence and byte offset.
    ///
    /// # Errors
    ///
    /// Rejects discontinuity before sequence exhaustion or offset overflow.
    /// Offset overflow retains the already advanced expected sequence.
    pub fn observe_frame(
        &mut self,
        frame: &Frame,
        bytes_read: u64,
    ) -> Result<(), NativeReplayError> {
        if frame.sequence != self.coordinates.expected_sequence {
            return Err(NativeReplayError::SequenceDiscontinuity(
                self.coordinates.offset,
            ));
        }
        self.coordinates.expected_sequence = self
            .coordinates
            .expected_sequence
            .checked_add(1)
            .ok_or(NativeReplayError::SequenceExhausted)?;
        self.coordinates.offset = self
            .coordinates
            .offset
            .checked_add(bytes_read)
            .ok_or(NativeReplayError::JournalTooLarge)?;
        Ok(())
    }

    /// Inserts an identity into the same resident set at the caller's chosen step.
    ///
    /// Membership is bookkeeping DATA, not evidence that a transaction was
    /// validated, applied, or committed.
    ///
    /// # Errors
    ///
    /// Rejects an identity already present without replacing the resident set.
    pub fn register_transaction(
        &mut self,
        transaction_id: [u8; 16],
    ) -> Result<(), NativeReplayError> {
        if !self.transaction_ids.insert(transaction_id) {
            return Err(NativeReplayError::DuplicateTransaction);
        }
        Ok(())
    }

    /// Advances commit counts and records the caller's current frame boundary.
    ///
    /// Callers perform semantic joins and apply their actual records first.
    /// This operation does not establish those preconditions or issue a receipt.
    ///
    /// # Errors
    ///
    /// Rejects transaction-count overflow, then its bound, then record-count
    /// overflow. A bound or record-count failure retains the advanced
    /// transaction count without advancing either boundary coordinate.
    pub fn finish_commit(
        &mut self,
        record_count: usize,
        maximum_transactions: usize,
    ) -> Result<(), NativeReplayError> {
        self.coordinates.committed_transactions = self
            .coordinates
            .committed_transactions
            .checked_add(1)
            .ok_or(NativeReplayError::LimitExceeded(
                "committed transaction count",
            ))?;
        if self.coordinates.committed_transactions > maximum_transactions {
            return Err(NativeReplayError::LimitExceeded(
                "committed transaction count",
            ));
        }
        self.coordinates.committed_records = self
            .coordinates
            .committed_records
            .checked_add(record_count)
            .ok_or(NativeReplayError::LimitExceeded("committed record count"))?;
        self.coordinates.durable_end = self.coordinates.offset;
        self.coordinates.durable_next_sequence = self.coordinates.expected_sequence;
        Ok(())
    }

    /// Moves the original ID set out, leaving an empty set in its place.
    ///
    /// This handoff does not reconstruct or clone identities and conveys no
    /// authority beyond ownership of the retained bookkeeping DATA.
    pub fn take_transaction_ids(&mut self) -> BTreeSet<[u8; 16]> {
        std::mem::take(&mut self.transaction_ids)
    }
}

#[cfg(test)]
mod tests;
