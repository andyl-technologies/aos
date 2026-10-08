//! Resident native journal state and ordered mechanical mutation.
//!
//! The owner retains the actual data and lock files, native coordinates, and
//! materialized DATA map. Namespace and configuration types are supplied by
//! the domain without moving their interpretation here. Immutable views are
//! diagnostic DATA, including after an uncertain append.
//!
//! Domain wrappers retain admission, semantic replay, final authority crossings,
//! idempotency, and protected receipts. Opening and compaction eligibility are
//! still upper responsibilities; this owner is a concrete migration pilot.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::PathBuf;

use crate::framing::FrameError;
use crate::geometry::NativeGeometryBounds;
use crate::materialized::{self, RecordMutationRef};
use crate::storage::NativeJournalStorage;
use crate::transaction::{self, NativeRecordRef};

/// Owns supplied native progress and materialized DATA without certifying replay.
///
/// Field order preserves the original identity set, namespace provenance, and
/// materialized map disposal order. Deleted namespaces remain DATA provenance
/// until the domain permits replacement with a replayed compaction prefix.
pub struct NativeJournalState<N> {
    next_sequence: u64,
    committed_transactions: usize,
    transaction_ids: BTreeSet<[u8; 16]>,
    committed_namespaces: BTreeSet<N>,
    state: BTreeMap<(N, Vec<u8>), Vec<u8>>,
    materialized_bytes: usize,
}

impl<N> NativeJournalState<N> {
    /// Adopts the original supplied sets and map without cloning or validating them.
    pub fn from_owned_parts(
        next_sequence: u64,
        committed_transactions: usize,
        transaction_ids: BTreeSet<[u8; 16]>,
        committed_namespaces: BTreeSet<N>,
        state: BTreeMap<(N, Vec<u8>), Vec<u8>>,
        materialized_bytes: usize,
    ) -> Self {
        Self {
            next_sequence,
            committed_transactions,
            transaction_ids,
            committed_namespaces,
            state,
            materialized_bytes,
        }
    }
}

/// Owns one supplied native journal prefix and permanent append uncertainty.
///
/// Neither adoption nor a native operation establishes protected admission or
/// semantic currentness. The configuration remains its original supplied DATA
/// type. Destruction releases the path, data file, lock file, then state owners
/// in the same order as the original contiguous journal fields.
pub struct NativeJournal<N, L = NativeGeometryBounds> {
    path: PathBuf,
    storage: NativeJournalStorage,
    limits: L,
    prefix: NativeJournalState<N>,
}

impl<N, L> NativeJournal<N, L> {
    /// Adopts actual files and state without opening, locking, or issuing authority.
    pub fn from_owned_parts(
        path: PathBuf,
        file: File,
        lock: File,
        limits: L,
        prefix: NativeJournalState<N>,
    ) -> Self {
        Self {
            path,
            storage: NativeJournalStorage::from_owned_files(file, lock),
            limits,
            prefix,
        }
    }

    /// Borrows the supplied path DATA without resolving or admitting it.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Borrows the actual data file as an ordinary native capability.
    ///
    /// A shared file borrow does not establish read-only access or currentness.
    pub fn file(&self) -> &File {
        self.storage.file()
    }

    /// Borrows the actual data file and copies its original configuration together.
    ///
    /// This native capability does not admit replay or certify its outcome.
    pub fn file_with_limits_mut(&mut self) -> (&mut File, L)
    where
        L: Copy,
    {
        (self.storage.file_mut(), self.limits)
    }

    /// Borrows the retained original lock file without certifying lock admission.
    pub fn lock_file(&self) -> &File {
        self.storage.lock_file()
    }

    /// Copies the recorded next native sequence without issuing a current cut.
    pub const fn next_sequence(&self) -> u64 {
        self.prefix.next_sequence
    }

    /// Returns the recorded committed transaction count as DATA.
    pub const fn committed_transactions(&self) -> usize {
        self.prefix.committed_transactions
    }

    /// Borrows the resident native identity set without certifying membership.
    pub fn transaction_ids(&self) -> &BTreeSet<[u8; 16]> {
        &self.prefix.transaction_ids
    }

    /// Borrows namespace provenance without interpreting or admitting a namespace.
    pub fn committed_namespaces(&self) -> &BTreeSet<N> {
        &self.prefix.committed_namespaces
    }

    /// Borrows materialized DATA without granting protected read authority.
    pub fn state(&self) -> &BTreeMap<(N, Vec<u8>), Vec<u8>> {
        &self.prefix.state
    }

    /// Returns the supplied materialized byte accounting as DATA.
    pub const fn materialized_bytes(&self) -> usize {
        self.prefix.materialized_bytes
    }

    /// Reports permanent uncertainty without establishing positive health authority.
    pub fn is_poisoned(&self) -> bool {
        self.storage.is_poisoned()
    }

    /// Permanently denies reuse after an ambiguous native or upper postcheck failure.
    pub fn poison(&mut self) {
        self.storage.poison();
    }

    /// Replaces only the actual data file, preserving the original lock and poison.
    ///
    /// This raw native capability does not replay or admit its replacement.
    pub fn replace_file(&mut self, file: File) {
        self.storage.replace_file(file);
    }

    /// Replaces a data file and then its supplied replay prefix in original order.
    ///
    /// Domain replay, histories, and authority-instance rotation remain upper.
    /// The path, configuration, retained lock, and permanent poison are unchanged.
    pub fn replace_replayed_file(&mut self, file: File, prefix: NativeJournalState<N>) {
        self.storage.replace_file(file);
        self.prefix.next_sequence = prefix.next_sequence;
        self.prefix.committed_transactions = prefix.committed_transactions;
        self.prefix.transaction_ids = prefix.transaction_ids;
        self.prefix.committed_namespaces = prefix.committed_namespaces;
        self.prefix.state = prefix.state;
        self.prefix.materialized_bytes = prefix.materialized_bytes;
    }

    /// Appends the actual prepared bytes without adding an observation before I/O.
    ///
    /// The expected length is preparation DATA. Domain wrappers perform their
    /// final checks immediately before entry and retain subsequent publication.
    ///
    /// # Errors
    ///
    /// Preserves native append, flush, sync, metadata, and length errors. Every
    /// such failure permanently poisons the same retained storage owner.
    pub fn append_exact(
        &mut self,
        frames: &[Vec<u8>],
        expected_length: u64,
    ) -> Result<u64, FrameError> {
        self.storage.append_exact(frames, expected_length)
    }
}

impl<N, L: Copy> NativeJournal<N, L> {
    /// Copies the exact supplied configuration without admitting its ceilings.
    pub const fn limits(&self) -> L {
        self.limits
    }

    /// Replaces only raw configuration DATA for an explicitly selected test fixture.
    ///
    /// This fixture operation establishes no admission, currentness, or durability.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn replace_limits_for_fixture(&mut self, limits: L) {
        self.limits = limits;
    }

    /// Replaces only recorded head DATA for an explicitly selected test fixture.
    ///
    /// This fixture operation establishes no admission, currentness, or durability.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn replace_next_sequence_for_fixture(&mut self, sequence: u64) {
        self.prefix.next_sequence = sequence;
    }
}

impl<N: Ord + Copy, L> NativeJournal<N, L> {
    /// Applies one raw map mutation at the domain's existing application step.
    ///
    /// This neither publishes coordinates nor updates domain-specific indexes.
    pub fn apply_mutation(&mut self, record: RecordMutationRef<'_, N>) {
        materialized::apply_mutation(&mut self.prefix.state, record);
    }

    /// Publishes supplied append bookkeeping after the domain applies its rows.
    ///
    /// The domain retains actual append outcomes and semantic indexes. This
    /// operation preserves byte, sequence, count, identity, then namespace order;
    /// it does not fabricate a durable receipt or validate supplied DATA.
    ///
    /// # Panics
    ///
    /// Panics on transaction-count overflow when overflow checks are enabled,
    /// preserving the original increment after the domain's count admission.
    pub fn publish_append(
        &mut self,
        materialized_bytes: usize,
        following_sequence: u64,
        transaction_id: [u8; 16],
        namespaces: impl IntoIterator<Item = N>,
    ) {
        self.prefix.materialized_bytes = materialized_bytes;
        self.prefix.next_sequence = following_sequence;
        self.prefix.committed_transactions += 1;
        self.prefix.transaction_ids.insert(transaction_id);
        self.prefix.committed_namespaces.extend(namespaces);
    }
}

impl<N: Ord + Copy, L: Copy + Into<NativeGeometryBounds>> NativeJournal<N, L> {
    /// Projects bounded materialized accounting without changing the resident map.
    ///
    /// # Errors
    ///
    /// Preserves the existing checked count, byte, and configured-limit refusals.
    ///
    /// # Panics
    ///
    /// Repeating existing-key deletions may overflow record accounting when
    /// overflow checks are enabled; domain admission rejects duplicate keys.
    pub fn projected_change<'a>(
        &self,
        records: impl IntoIterator<Item = RecordMutationRef<'a, N>>,
    ) -> Result<usize, FrameError> {
        let limits = self.limits.into();
        materialized::validate_change(
            &self.prefix.state,
            self.prefix.materialized_bytes,
            records,
            limits.maximum_materialized_bytes,
            limits.maximum_materialized_records,
        )
    }

    /// Encodes supplied record DATA at the recorded native head without admission.
    ///
    /// # Errors
    ///
    /// Preserves native representation, frame-count, and sequence-space errors.
    ///
    /// # Panics
    ///
    /// Preserves the encoder's count and allocation-capacity panic conditions.
    pub fn encode_at_head<'a>(
        &self,
        transaction_id: [u8; 16],
        records: impl ExactSizeIterator<Item = NativeRecordRef<'a>>,
    ) -> Result<Vec<Vec<u8>>, FrameError> {
        transaction::encode_transaction(transaction_id, self.prefix.next_sequence, records)
    }

    /// Computes resulting length from the actual file without reserving capacity.
    ///
    /// # Errors
    ///
    /// Preserves metadata errors before overflowing or excessive native length.
    pub fn expected_append_length(&self, frames: &[Vec<u8>]) -> Result<u64, FrameError> {
        self.storage
            .expected_append_length(frames, self.limits.into().maximum_journal_bytes)
    }
}

#[cfg(all(test, unix))]
mod tests;
