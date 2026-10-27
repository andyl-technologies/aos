//! Reuses successful pure record checks after byte-for-byte fresh reads.
//!
//! Entries contain no read receipts or backend permission. Each memo belongs to
//! one held observation and bounds both its entry count and encoded input size.
//!
//! Test diagnostics count the existing lookup's hit or miss after successful lock
//! acquisition. Decoder spans exclude binding checks, raw digest computation and
//! result cloning; the inclusive whole-memo spans retain those costs.

use super::{corrupt, digest};
use crate::store::StoreFailure;
use std::sync::Mutex;
use terrane_format::gc::publication::{
    PortableSnapshot, PublicationCommit, PublicationTransaction, RawDigest,
};

const MAX_ENTRIES: usize = 64;
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

struct Entry<T> {
    inputs: Vec<Vec<u8>>,
    value: T,
}

struct Records<T> {
    entries: Vec<Entry<T>>,
    input_bytes: usize,
}

impl<T: Clone> Records<T> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            input_bytes: 0,
        }
    }

    fn get(&self, inputs: &[&[u8]]) -> Option<T> {
        self.entries
            .iter()
            .find(|entry| {
                entry.inputs.len() == inputs.len()
                    && entry
                        .inputs
                        .iter()
                        .zip(inputs)
                        .all(|(old, new)| old.as_slice() == *new)
            })
            .map(|entry| entry.value.clone())
    }

    fn insert(&mut self, inputs: &[&[u8]], value: T) {
        let Some(size) = inputs
            .iter()
            .try_fold(0usize, |size, bytes| size.checked_add(bytes.len()))
        else {
            return;
        };
        if size > MAX_INPUT_BYTES {
            return;
        }

        // Keep the bounded prefix useful even when a longer chain is walked
        // repeatedly. Evicting it on every later slot would thrash the memo.
        if self.entries.len() >= MAX_ENTRIES || self.input_bytes > MAX_INPUT_BYTES - size {
            return;
        }
        self.input_bytes += size;
        self.entries.push(Entry {
            inputs: inputs.iter().map(|bytes| bytes.to_vec()).collect(),
            value,
        });
    }
}

/// Retains bounded pure results, never the evidence needed to use them.
pub(in crate::bucket::publication) struct DecodeMemo {
    commits: Mutex<Records<(PublicationCommit, RawDigest)>>,
    transactions: Mutex<Records<PublicationTransaction>>,
    snapshots: Mutex<Records<PortableSnapshot>>,
}

impl DecodeMemo {
    /// Creates an empty operation-local memo with fixed retention limits.
    pub(in crate::bucket::publication) fn new() -> Self {
        Self {
            commits: Mutex::new(Records::new()),
            transactions: Mutex::new(Records::new()),
            snapshots: Mutex::new(Records::new()),
        }
    }

    /// Decodes exact commit bytes and computes their raw digest.
    ///
    /// # Errors
    /// Rejects malformed commit bytes or a poisoned memo mutex as corrupt.
    pub(super) fn commit(
        &self,
        bytes: &[u8],
    ) -> Result<(PublicationCommit, RawDigest), StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::MemoCommit);
        let inputs = [bytes];
        let records = self.commits.lock().map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if records.is_err() {
            diagnostic.finish_result(&records);
        }
        let mut records = records?;

        if let Some(value) = records.get(&inputs) {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(crate::diagnostic_clock::Group::MemoCommitHit, 1);
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            diagnostic.complete();
            return Ok(value);
        }
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        crate::diagnostic_clock::count(crate::diagnostic_clock::Group::MemoCommitMiss, 1);

        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut decode =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DecodeCommit);
        let decoded = PublicationCommit::decode(bytes).map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        decode.finish_result(&decoded);
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        drop(decode);
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if decoded.is_err() {
            diagnostic.finish_result(&decoded);
        }
        let value = (decoded?, digest(bytes));

        records.insert(&inputs, value.clone());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(value)
    }

    /// Checks and decodes exact transaction bytes against their commit and slot.
    ///
    /// The commit value must be decoded from `commit_bytes` by this resolver.
    ///
    /// # Errors
    /// Rejects malformed transactions, contradictory slot or commit inputs, and
    /// a poisoned memo mutex as corrupt.
    pub(super) fn transaction(
        &self,
        commit: &PublicationCommit,
        commit_bytes: &[u8],
        key: &str,
        bytes: &[u8],
    ) -> Result<PublicationTransaction, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::MemoTransaction);
        // The exact slot spelling is an input to check_transaction, too.
        let inputs = [commit_bytes, key.as_bytes(), bytes];
        let records = self.transactions.lock().map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if records.is_err() {
            diagnostic.finish_result(&records);
        }
        let mut records = records?;

        if let Some(value) = records.get(&inputs) {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(crate::diagnostic_clock::Group::MemoTransactionHit, 1);
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            diagnostic.complete();
            return Ok(value);
        }
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        crate::diagnostic_clock::count(crate::diagnostic_clock::Group::MemoTransactionMiss, 1);

        let checked = commit.check_transaction(key, bytes).map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if checked.is_err() {
            diagnostic.finish_result(&checked);
        }
        checked?;

        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut decode =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DecodeTransaction);
        let value = PublicationTransaction::decode(bytes).map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        decode.finish_result(&value);
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if value.is_err() {
            diagnostic.finish_result(&value);
        }
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        drop(decode);
        let value = value?;

        records.insert(&inputs, value.clone());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(value)
    }

    /// Checks and decodes exact snapshot bytes against their transaction.
    ///
    /// The transaction value must be decoded from `transaction_bytes` by this
    /// resolver. Whole predecessor and projection checks remain separate.
    ///
    /// # Errors
    /// Rejects malformed snapshots, contradictory transaction selectors or
    /// snapshot contents, and a poisoned memo mutex as corrupt.
    pub(super) fn snapshot(
        &self,
        transaction: &PublicationTransaction,
        transaction_bytes: &[u8],
        bytes: &[u8],
    ) -> Result<PortableSnapshot, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::MemoSnapshot);
        let inputs = [transaction_bytes, bytes];
        let records = self.snapshots.lock().map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if records.is_err() {
            diagnostic.finish_result(&records);
        }
        let mut records = records?;

        if let Some(value) = records.get(&inputs) {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(crate::diagnostic_clock::Group::MemoSnapshotHit, 1);
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            diagnostic.complete();
            return Ok(value);
        }
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        crate::diagnostic_clock::count(crate::diagnostic_clock::Group::MemoSnapshotMiss, 1);

        let checked = transaction
            .snapshot
            .check_snapshot(bytes)
            .map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if checked.is_err() {
            diagnostic.finish_result(&checked);
        }
        checked?;
        let checked = transaction.check_snapshot(bytes).map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if checked.is_err() {
            diagnostic.finish_result(&checked);
        }
        checked?;

        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut decode =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DecodeSnapshot);
        let value = PortableSnapshot::decode(bytes).map_err(|_| corrupt());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        decode.finish_result(&value);
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if value.is_err() {
            diagnostic.finish_result(&value);
        }
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        drop(decode);
        let value = value?;

        records.insert(&inputs, value.clone());
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ENTRIES, MAX_INPUT_BYTES, Records};

    #[test]
    fn later_chain_records_do_not_evict_bounded_prefix_or_match_other_context() {
        let mut records = Records::new();
        for index in 0..MAX_ENTRIES {
            records.insert(&[&index.to_be_bytes(), b"slot"], index);
        }
        records.insert(&[b"later", b"slot"], MAX_ENTRIES);

        assert_eq!(records.get(&[&0usize.to_be_bytes(), b"slot"]), Some(0));
        assert_eq!(records.get(&[&0usize.to_be_bytes(), b"other"]), None);
        assert_eq!(records.get(&[b"later", b"slot"]), None);
        assert_eq!(records.entries.len(), MAX_ENTRIES);
    }

    #[test]
    fn oversized_fresh_record_remains_uncached_without_disturbing_prefix() {
        let mut records = Records::new();
        records.insert(&[b"prefix"], 1);
        let oversized = vec![0; MAX_INPUT_BYTES + 1];
        records.insert(&[&oversized], 2);

        assert_eq!(records.get(&[b"prefix"]), Some(1));
        assert_eq!(records.get(&[&oversized]), None);
        assert_eq!(records.input_bytes, b"prefix".len());
    }
}
