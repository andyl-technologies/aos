//! Compares exact validated native transaction suffixes as passive DATA.
//!
//! The actual role retains and pays its rooted file, complete semantic replay,
//! native errors and independent posts. These borrowed recipes/progress cannot
//! open a file, authenticate an owner, grant capacity or authorize a transition.

use aos_sandbox_core::RecordNamespace;
use sha2::{Digest as _, Sha256};
use crate::domain_ledger::transaction::JournalTransaction;
use super::{KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordEnvelopeV1};

/// Derives the established native pair identity from its owner and checksum.
///
/// This deterministic format DATA does not validate or admit a native append.
pub fn history_pair_transaction_id_v1(owner: OwnerV1, checksum: [u8; 32]) -> [u8; 16] {
    let domain: &[u8] = match owner {
        OwnerV1::Root => b"aos.sandbox.create-storage.root-open.transaction.v1\0",
        OwnerV1::Controller => b"aos.sandbox.create-storage.controller.transaction.v1\0",
        OwnerV1::Source => b"aos.sandbox.create-storage.source.transaction.v1\0",
        OwnerV1::Cache => b"aos.sandbox.create-storage.cache.transaction.v1\0",
    };
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(checksum);
    let digest: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);

    id
}

/// Classifies an exact native suffix comparison, without retaining native IO.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryPairSuffixErrorV1 {
    #[error("Create Storage suffix recipe differs")]
    Recipe,
    #[error("Create Storage suffix crosses its original prefix")]
    Prefix,
    #[error("Create Storage suffix has a different transaction")]
    Transaction,
    #[error("Create Storage suffix native coordinates differ")]
    Coordinates,
    #[error("Create Storage suffix is incomplete")]
    Incomplete,
}

/// Retains the entire once-only suffix comparison independently of its recipe.
///
/// A receiving owner keeps this value and the actual expected transaction in
/// disjoint resident fields. Native replay borrows both temporarily, so no
/// self-reference, recipe clone or failure-only lossy snapshot is required.
/// These coordinates and comparison results remain passive DATA.
pub struct HistoryPairNativeSuffixProgressV1 {
    before_next: u64,
    before_end: u64,
    after_next: u64,
    after_end: u64,
    attempted: bool,
    seen: bool,
    finished: bool,
    first: Option<HistoryPairSuffixErrorV1>,
}

impl HistoryPairNativeSuffixProgressV1 {
    /// Prearms an empty destination without parsing, allocating or granting IO.
    pub const fn new() -> Self {
        Self { before_next: 0, before_end: 0, after_next: 0, after_end: 0,
            attempted: false, seen: false, finished: false, first: None }
    }

    /// Borrows the first actual recipe/parser-comparison cause.
    pub fn failure(&self) -> Option<&HistoryPairSuffixErrorV1> {
        self.first.as_ref()
    }

    /// Reports complete successful comparison DATA, never receiving authority.
    pub fn is_complete(&self) -> bool {
        self.attempted && self.seen && self.finished && self.first.is_none()
    }
}

/// Borrows one exact expected pair and its caller-owned complete progression.
///
/// The receiving owner separately authenticates and pays the SAME replay. The
/// Native parser supplies validated COMMIT transactions and exact coordinates.
/// Dropping this temporary wrapper cannot drop or reset the retained progress.
pub struct HistoryPairNativeSuffixV1<'expected, 'progress> {
    expected: &'expected JournalTransaction,
    progress: &'progress mut HistoryPairNativeSuffixProgressV1,
}

impl<'expected, 'progress> HistoryPairNativeSuffixV1<'expected, 'progress> {
    /// Borrows an exact two-member recipe with four-frame before/after DATA.
    ///
    /// # Errors
    /// Retains malformed pair keys/values/envelope/head, a substituted native
    /// identity, zero NEXT or differing exact encoded append geometry in the
    /// same caller-owned progress. Reentry permanently closes that progress.
    pub fn new(
        expected: &'expected JournalTransaction,
        progress: &'progress mut HistoryPairNativeSuffixProgressV1,
        before_next: u64,
        before_end: u64,
        after_next: u64,
        after_end: u64,
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;

        if progress.attempted {
            let first = *progress.first.get_or_insert(E::Incomplete);
            return Err(first);
        }
        progress.attempted = true;
        progress.before_next = before_next;
        progress.before_end = before_end;
        progress.after_next = after_next;
        progress.after_end = after_end;
        let validation = (|| {
            let [record, head] = expected.records() else { return Err(E::Recipe); };
            if record.namespace() != RecordNamespace::CreateStorageHistory
                || head.namespace() != RecordNamespace::CreateStorageHistory
            {
                return Err(E::Recipe);
            }
            let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
            let latest = KeyV1::new(key.lane(), key.owner(), 0).map_err(|_| E::Recipe)?;
            if head.key() != latest.encode() { return Err(E::Recipe); }
            let bytes = record.value().ok_or(E::Recipe)?;
            let phase = PhaseV1::new(key.owner(), *bytes.get(11).ok_or(E::Recipe)?)
                .map_err(|_| E::Recipe)?;
            let envelope = RecordEnvelopeV1::decode(bytes, key, phase).map_err(|_| E::Recipe)?;
            LatestHeadV1::decode(head.value().ok_or(E::Recipe)?, latest)
                .and_then(|head| head.check_record(latest, envelope)).map_err(|_| E::Recipe)?;
            if expected.id() != &history_pair_transaction_id_v1(key.owner(), envelope.checksum()) {
                return Err(E::Recipe);
            }
            let append = super::super::transaction::encoded_transaction_append_bytes(expected).map_err(|_| E::Recipe)?;
            if before_next == 0 || before_next.checked_add(4) != Some(after_next)
                || before_end.checked_add(append) != Some(after_end)
            {
                return Err(E::Coordinates);
            }
            Ok(())
        })();
        if let Err(first) = validation {
            progress.first = Some(first);
            return Err(first);
        }
        Ok(Self { expected, progress })
    }

    // The three-member bank transaction uses the same comparison/progress
    // engine as a history pair. Its exact members come from the sole canonical
    // AccountMutation encoder, and the independent PhysicalHistory observer
    // still validates the actual financial predecessor and complete history.
    /// Borrows the exact three-member U reservation recipe as comparison DATA.
    ///
    /// # Errors
    /// Rejects differing immutable binding, member roster or native positions.
    pub fn new_use_reserve(
        expected: &'expected JournalTransaction,
        progress: &'progress mut HistoryPairNativeSuffixProgressV1,
        before: (u64, u64),
        after: (u64, u64),
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if progress.attempted {
            return Err(*progress.first.get_or_insert(E::Incomplete));
        }
        progress.attempted = true;
        progress.before_next = before.0;
        progress.before_end = before.1;
        progress.after_next = after.0;
        progress.after_end = after.1;
        let result = (|| {
            let [_, _, binding] = expected.records() else { return Err(E::Recipe); };
            if expected.records().iter().any(|record|
                record.namespace() != RecordNamespace::ControllerResourceReservation)
            { return Err(E::Recipe); }
            let binding = crate::domain_ledger::resource_bank::
                CreateStorageUseBindingV1::decode(binding.value().ok_or(E::Recipe)?)
                .map_err(|_| E::Recipe)?;
            if binding.reserve_transaction_id().map_err(|_| E::Recipe)? != *expected.id() {
                return Err(E::Recipe);
            }
            let append = super::super::transaction::encoded_transaction_append_bytes(expected).map_err(|_| E::Recipe)?;
            if before.0 == 0 || before.0.checked_add(5) != Some(after.0)
                || before.1.checked_add(append) != Some(after.1)
            { return Err(E::Coordinates); }
            Ok(())
        })();
        if let Err(first) = result { progress.first = Some(first); return Err(first); }
        Ok(Self { expected, progress })
    }

    /// Borrows the exact two-member positive U commit as comparison DATA.
    ///
    /// # Errors
    /// Rejects another bank roster, original binding identity or native extent.
    pub fn new_use_commit(
        expected: &'expected JournalTransaction,
        progress: &'progress mut HistoryPairNativeSuffixProgressV1,
        binding: crate::domain_ledger::resource_bank::CreateStorageUseBindingV1,
        before: (u64, u64), after: (u64, u64),
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if progress.attempted { return Err(*progress.first.get_or_insert(E::Incomplete)); }
        progress.attempted = true;
        progress.before_next = before.0; progress.before_end = before.1;
        progress.after_next = after.0; progress.after_end = after.1;
        let result = (|| {
            if expected.records().len() != 2 || expected.records().iter().any(|record|
                record.namespace() != RecordNamespace::ControllerResourceReservation)
                || binding.commit_transaction_id().map_err(|_| E::Recipe)? != *expected.id()
            { return Err(E::Recipe); }
            let append = super::super::transaction::encoded_transaction_append_bytes(expected).map_err(|_| E::Recipe)?;
            if before.0 == 0 || before.0.checked_add(4) != Some(after.0)
                || before.1.checked_add(append) != Some(after.1) { return Err(E::Coordinates); }
            Ok(())
        })();
        if let Err(first) = result { progress.first = Some(first); return Err(first); }
        Ok(Self { expected, progress })
    }

    /// Compares a transaction supplied by the same validated COMMIT parser.
    ///
    /// # Errors
    /// Retains the first straddling prefix, foreign/extra transaction, or exact
    /// BEGIN/COMMIT/byte-position mismatch; subsequent calls cannot heal it.
    pub fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;

        if let Some(first) = self.progress.first { return Err(first); }
        let result = (|| {
            if self.progress.finished { return Err(E::Incomplete); }
            if begin_sequence < self.progress.before_next {
                if self.progress.seen || commit_sequence >= self.progress.before_next || end_offset > self.progress.before_end {
                    return Err(E::Prefix);
                }
                return Ok(());
            }
            if self.progress.seen || transaction != self.expected { return Err(E::Transaction); }
            if begin_sequence != self.progress.before_next || begin_offset != self.progress.before_end
                || commit_sequence.checked_add(1) != Some(self.progress.after_next)
                || end_offset != self.progress.after_end
            {
                return Err(E::Coordinates);
            }
            self.progress.seen = true;
            Ok(())
        })();
        if let Err(first) = result { self.progress.first = Some(first); }
        result
    }

    /// Joins the same replay's final durable NEXT/end to its captured file end.
    ///
    /// # Errors
    /// Rejects absent/extra suffix, a partial tail or a second completion. The
    /// original receiving owner retains the actual replay and native IO errors.
    pub fn finish(
        &mut self,
        durable_next: u64,
        durable_end: u64,
        captured_file_end: u64,
    ) -> Result<(), HistoryPairSuffixErrorV1> {
        self.finish_inner(durable_next, durable_end, Some(captured_file_end))
    }

    // The same validated COMMIT parser supplies an intermediate segment end.
    // A later segment must still join the actual whole captured file end.
    /// Finishes an intermediate exact segment before a separately owned suffix.
    ///
    /// # Errors
    /// Rejects absent, repeated or differing native completion coordinates.
    pub fn finish_segment(
        &mut self,
        durable_next: u64,
        durable_end: u64,
    ) -> Result<(), HistoryPairSuffixErrorV1> {
        self.finish_inner(durable_next, durable_end, None)
    }

    fn finish_inner(
        &mut self,
        durable_next: u64,
        durable_end: u64,
        captured_file_end: Option<u64>,
    ) -> Result<(), HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;

        if let Some(first) = self.progress.first { return Err(first); }
        let result = if self.progress.finished || !self.progress.seen {
            Err(E::Incomplete)
        } else if durable_next != self.progress.after_next || durable_end != self.progress.after_end
            || captured_file_end.is_some_and(|end| end != self.progress.after_end)
        {
            Err(E::Coordinates)
        } else {
            Ok(())
        };
        self.progress.finished = true;
        if let Err(first) = result { self.progress.first = Some(first); }
        result
    }

    /// Reports whether the actual COMMIT matching this recipe has been seen.
    pub const fn has_seen_v1(&self) -> bool { self.progress.seen }

    /// Reports this segment's completed comparison DATA without lending IO.
    pub fn is_complete_v1(&self) -> bool { self.progress.is_complete() }

    /// Borrows the first exact comparison cause after failure.
    pub fn failure(&self) -> Option<&HistoryPairSuffixErrorV1> {
        self.progress.first.as_ref()
    }
}
