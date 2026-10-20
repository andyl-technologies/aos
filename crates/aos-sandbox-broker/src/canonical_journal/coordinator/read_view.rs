//! Lends immutable native/index/location DATA without descriptor projections.
//!
//! Construction stays inside Broker's genuine closed writers or ordinary DATA
//! adapter. Every read delegates to the original owner and sampler. These views
//! carry no role health, payment, replay, semantic or disposition certificate.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::Metadata;
use std::io;

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::owner::NativeJournal;
use aos_sandbox_journal::protected_storage::{
    FileIdentity, ProtectedFailure, ProtectedJournalLocation, ProtectedWriterNameWitness,
    WriterWitnessOriginalsV1,
};
use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;
use aos_sandbox_protocol::domain_ledger::readonly::{
    HistoricalLedgerReadViewV1, IdempotencyDecisionV1,
};
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read::
    HistoricalRuntimeLedgerReadV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use crate::writer_currentness::WriterCurrentnessOriginalsV1;
use crate::receiving::root_invocation::RootInvocationOriginalV1;
use super::invocation_cursor::{CanonicalCoordinatorReadCursorV1, enter_root_read};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Borrows the same physical owner and models with only named readonly operations.
///
/// It exposes no native journal, file, descriptor, mutable prefix or location.
/// Supplied historical DATA can never replace its captured owners. Actual
/// protected and healthy checks remain at the caller's established frontiers.
///
/// No raw file projection is available:
///
/// ```compile_fail
/// use std::fs::File;
/// use aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1;
/// fn escape<'a>(view: CanonicalWriterReadViewV1<'a, ()>) -> &'a File {
///     view.file()
/// }
/// ```
pub struct CanonicalWriterReadViewV1<'owner, P> {
    native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
    index: &'owner Index,
    location: Option<&'owner ProtectedJournalLocation<P>>,
    invocation: Option<&'owner RootInvocationOriginalV1>,
}

/// Keeps an independently opened comparison directory through its old scope.
///
/// This mechanical DATA loan exposes no File/descriptor, role permission or
/// positive constructor. Its private actual file closes at the caller's old
/// comparison-local disposal frontier.
pub struct CanonicalDirectoryComparisonDataV1 {
    _file: std::fs::File,
}

impl<P> Copy for CanonicalWriterReadViewV1<'_, P> {}

impl<P> Clone for CanonicalWriterReadViewV1<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'owner, P> CanonicalWriterReadViewV1<'owner, P> {
    /// Bounds fixed inline construction/return carriers without funding them.
    ///
    /// The actual native/index/location and their dynamic allocations remain
    /// borrowed and separately priced. Returns `None` on arithmetic overflow.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(super::CanonicalWriterNativeOperationsV1::<P>::receiving_construction_bytes_v1()?)?
            .checked_add(std::mem::size_of::<CanonicalProtectedReadViewV1<'_, P>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<CanonicalDirectoryComparisonDataV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<CanonicalCoordinatorReadCursorV1<'_>>().checked_mul(3)?)
    }

    /// Returns zero namespace metadata entries for this borrowed DATA view.
    ///
    /// The enclosing ordinary or closed role wrapper and all native results
    /// remain separately named by its actual before-entry supplier.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        0
    }

    pub(crate) const fn from_parts(
        native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
        index: &'owner Index,
        location: Option<&'owner ProtectedJournalLocation<P>>,
    ) -> Self {
        Self { native, index, location, invocation: None }
    }

    pub(crate) const fn from_root_parts(
        native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
        index: &'owner Index,
        location: &'owner ProtectedJournalLocation<P>,
        invocation: &'owner RootInvocationOriginalV1,
    ) -> Self {
        Self { native, index, location: Some(location), invocation: Some(invocation) }
    }

    pub(super) fn ordinary_native_operations(self)
        -> super::CanonicalWriterNativeOperationsV1<'owner, P>
    {
        super::CanonicalWriterNativeOperationsV1::from_parts(
            self.native, self.location, self.invocation,
        )
    }

    /// Borrows the actual complete materialized map as immutable DATA.
    #[must_use]
    pub fn state(self) -> &'owner State {
        self.native.state()
    }

    /// Borrows the actual resident index without certifying its validity.
    #[must_use]
    pub fn idempotency_index(self) -> &'owner Index {
        self.index
    }

    /// Borrows actual committed transaction identities without a currentness claim.
    #[must_use]
    pub fn transaction_ids(self) -> &'owner BTreeSet<[u8; 16]> {
        self.native.transaction_ids()
    }

    /// Borrows actual committed namespace provenance, including deleted rows.
    #[must_use]
    pub fn committed_namespaces(self) -> &'owner BTreeSet<RecordNamespace> {
        self.native.committed_namespaces()
    }

    /// Returns the actual complete native transaction count as DATA.
    #[must_use]
    pub fn committed_transactions(self) -> usize {
        self.native.committed_transactions()
    }

    /// Returns the actual next native sequence as DATA.
    #[must_use]
    pub fn next_sequence(self) -> u64 {
        self.native.next_sequence()
    }

    /// Returns the actual materialized byte accounting as DATA.
    #[must_use]
    pub fn materialized_bytes(self) -> usize {
        self.native.materialized_bytes()
    }

    /// Returns the actual native configuration without issuing authority.
    #[must_use]
    pub fn limits(self) -> JournalLimits {
        self.native.limits()
    }

    /// Reports recorded native poison without asserting positive health.
    #[must_use]
    pub fn is_poisoned(self) -> bool {
        self.native.is_poisoned()
    }

    /// Borrows historical DATA from this same actual native owner and index.
    #[must_use]
    pub fn historical_view(self) -> HistoricalLedgerReadViewV1<'owner> {
        HistoricalLedgerReadViewV1::new(self.native, self.index)
    }

    /// Borrows Runtime history with the same optional actual protected location.
    #[must_use]
    pub fn runtime_history(self) -> HistoricalRuntimeLedgerReadV1<'owner, ProtectedJournalLocation<P>> {
        HistoricalRuntimeLedgerReadV1::new(self.historical_view(), self.location)
    }

    /// Samples the held data file at the caller's original metadata frontier.
    ///
    /// # Errors
    /// Returns the original metadata IO error without adding a health check.
    pub fn metadata(self) -> io::Result<Metadata> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = self.native.file().metadata();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Samples one ordinary data-file identity at the original frontier.
    ///
    /// Selected callers needing partial retention use their actual retained
    /// sampler; this top Result alone supplies no whole-prefix custody.
    ///
    /// # Errors
    /// Moves the original native metadata failure through `E` unchanged.
    pub fn file_identity<E: From<io::Error>>(self) -> Result<FileIdentity, E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = FileIdentity::of(self.native.file());
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Retains the same held-file metadata and identity projection in a sink.
    ///
    /// The destination grants no role or read authority. The actual caller
    /// retains its same original and pays this one metadata observation before
    /// entry. Root views still enter their original invocation read guard.
    ///
    /// # Errors
    /// Retains the actual metadata/identity cause or refuses an inactive Root
    /// invocation without opening or projecting any File or descriptor.
    pub fn observe_file_identity_into_v1<E: ProtectedFailure>(
        self,
        originals: &mut aos_sandbox_journal::protected_storage::FileIdentityOriginalsV1<E>,
    ) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = FileIdentity::of_retaining_v1(self.native.file(), originals);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Samples the actual lock identity at its original native frontier.
    ///
    /// # Errors
    /// Preserves the original native metadata error without cloning the file.
    pub fn lock_identity<E: From<io::Error>>(self) -> Result<FileIdentity, E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = FileIdentity::of(self.native.lock_file());
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Retains the same actual Lock/Journal name observations in supplied slots.
    ///
    /// # Errors
    /// Retains each native partial and rejects absent protected custody.
    pub fn observe_named_files_into<E: ProtectedFailure>(
        self,
        originals: &mut aos_sandbox_journal::protected_storage::ProtectedFileNamesCurrentOriginalsV1<E>,
    ) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let location = self.location.ok_or(E::BOUNDARY)?;
        location.observe_names_once(self.native.lock_file(), self.native.file(), originals);
        if originals.is_complete() { Ok(()) }
        else {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
            Err(E::BOUNDARY)
        }
    }

    /// Lends the original bounded positional cursor without opening another file.
    #[must_use]
    pub fn captured_reader(self, length: u64) -> CanonicalCoordinatorReadCursorV1<'owner> {
        CanonicalCoordinatorReadCursorV1::from_parts(
            ReadOnlyCapturedFileCursorV1::new(self.native.file(), length), self.invocation,
        )
    }

    /// Lends the same sequential file position through only Read/Seek/identity.
    ///
    /// Unlike a bounded captured cursor this preserves the original shared
    /// offset effects. It exports no File, descriptor, write or role grant.
    #[must_use]
    pub fn original_reader(self) -> CanonicalCoordinatorReadCursorV1<'owner> {
        CanonicalCoordinatorReadCursorV1::from_original(self.native.file(), self.invocation)
    }

    /// Borrows the actual retained pathname solely as comparison DATA.
    #[must_use]
    pub fn path(self) -> &'owner std::path::PathBuf {
        self.native.path()
    }

    /// Borrows an opaque protected comparison view only when actually present.
    #[must_use]
    pub fn protected_view(self) -> Option<CanonicalProtectedReadViewV1<'owner, P>> {
        Some(CanonicalProtectedReadViewV1 { view: self, location: self.location? })
    }

    /// Reports whether the actual owner retains a protected location.
    #[must_use]
    pub fn is_protected(self) -> bool {
        self.location.is_some()
    }

    /// Borrows the actual retained basename as comparison DATA.
    #[must_use]
    pub fn protected_name(self) -> Option<&'owner str> {
        self.location.map(ProtectedJournalLocation::name)
    }

    /// Copies the actual retained owner UID as comparison DATA.
    #[must_use]
    pub fn protected_uid(self) -> Option<u32> {
        self.location.map(ProtectedJournalLocation::expected_uid)
    }

    /// Borrows the same opaque negative compaction selection without interpreting it.
    #[must_use]
    pub fn compaction_selection(self) -> Option<&'owner P> {
        self.location.map(ProtectedJournalLocation::original_compaction_selection)
    }

    /// Samples actual names through the caller's original retained destination.
    ///
    /// The genuine owner supplies one-shot entry, health and prior funding.
    /// Already-entered owed observations may still inspect these same held files
    /// after native poison without granting fresh role entry or disposition.
    ///
    /// # Errors
    /// Preserves original sampled native partials; refuses absent protection.
    pub fn observe_names_into<E>(
        self,
        originals: &mut WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where
        E: ProtectedFailure + From<FrameError> + Error + 'static,
    {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let location = self.location.ok_or(E::BOUNDARY)?;
        let result = originals.observe_names(
            location, location.name(), location.expected_uid(),
            self.native.lock_file(), self.native.file(),
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Samples a witness while retaining each actual reached native result.
    ///
    /// # Errors
    /// Preserves native Metadata, projected identities and the whole top result
    /// in the actual prepaid owner; refuses absent protection or owner reentry.
    pub fn writer_witness_retaining_v1<E: ProtectedFailure>(
        self,
        originals: &mut WriterWitnessOriginalsV1<E>,
    ) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let location = self.location.ok_or(E::BOUNDARY)?;
        let result = location.writer_witness_retaining_v1(
            self.native.file(), self.native.lock_file(), originals,
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Compares the witness lazily while retaining each actual reached result.
    ///
    /// # Errors
    /// Keeps original Metadata/identity/mismatch data and whole top result in
    /// the separate prepaid comparison owner. No positive retirement occurs.
    pub fn require_writer_witness_retaining_v1<E: ProtectedFailure>(
        self,
        witness: &ProtectedWriterNameWitness,
        originals: &mut WriterWitnessOriginalsV1<E>,
    ) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let location = self.location.ok_or(E::BOUNDARY)?;
        let result = location.require_writer_witness_retaining_v1(
            self.native.file(), self.native.lock_file(), witness, originals,
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }
    /// Samples the SAME held protected directory as nonauthorizing DATA.
    ///
    /// # Errors
    /// Preserves native metadata failure or absent protected custody.
    pub fn directory_metadata<E: ProtectedFailure>(self)
        -> Result<aos_sandbox_journal::protected_storage::OriginalFileMetadataV1, E>
    {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.directory_metadata().map_err(E::from);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Resolves the original comparison path while keeping its real file opaque.
    ///
    /// # Errors
    /// Preserves existing rooted traversal and identity/owner failures.
    pub fn require_directory<E: ProtectedFailure>(self, path: &std::path::Path, uid: u32)
        -> Result<CanonicalDirectoryComparisonDataV1, E>
    {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.require_directory(path, uid)
            .map(|file| CanonicalDirectoryComparisonDataV1 { _file: file });
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Compares the existing fixture path under its explicit original UID.
    ///
    /// # Errors
    /// Preserves existing fixture traversal and identity failures.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub fn require_directory_at_uid_for_test<E: ProtectedFailure>(
        self, path: &std::path::Path, uid: u32,
    ) -> Result<CanonicalDirectoryComparisonDataV1, E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.require_directory_at_uid_for_test(path, uid)
            .map(|file| CanonicalDirectoryComparisonDataV1 { _file: file });
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Compares a supplied observation with the actual held directory.
    ///
    /// The supplied file is only a comparison input; it cannot replace custody.
    ///
    /// # Errors
    /// Preserves the existing physical identity mismatch or native failure.
    pub fn require_opened_directory<E: ProtectedFailure>(self, observed: &std::fs::File)
        -> Result<(), E>
    {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.require_opened_directory(observed);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Retains rooted traversal and binds it to this SAME held location.
    ///
    /// The ordinary adapter preserves observe-directory then bind order. Root's
    /// closed writer keeps its actual invocation lock across both native steps.
    ///
    /// # Errors
    /// Keeps each reached native/typed result in the caller's paid originals.
    pub fn observe_directory_binding_into<E>(
        self, path: &std::path::Path, uid: u32,
        originals: &mut WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where E: ProtectedFailure + From<FrameError> + Error + 'static,
    {
        self.observe_directory_binding_engine_v6(path, uid, originals, None)
    }

    /// Binds this actual held location to one retained same-interval ancestry.
    ///
    /// Every writer keeps its own native binding and name checks. This shared
    /// observation cannot replace custody or bypass the invocation bookend.
    ///
    /// # Errors
    /// Retains absent, mismatched, failed shared or native identity outcomes.
    pub fn observe_shared_directory_binding_into_v6<E>(self, path: &std::path::Path, uid: u32,
        originals: &mut WriterCurrentnessOriginalsV1<E>, shared: &WriterCurrentnessOriginalsV1<E>) -> Result<(), E>
    where E: ProtectedFailure + From<FrameError> + Error + 'static,
    {
        self.observe_directory_binding_engine_v6(path, uid, originals, Some(shared))
    }

    fn observe_directory_binding_engine_v6<E>(self, path: &std::path::Path, uid: u32,
        originals: &mut WriterCurrentnessOriginalsV1<E>, shared: Option<&WriterCurrentnessOriginalsV1<E>>) -> Result<(), E>
    where E: ProtectedFailure + From<FrameError> + Error + 'static,
    {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = (|| {
            let location = self.location.ok_or(E::BOUNDARY)?;
            if let Some(shared) = shared {
                originals.bind_shared_location_v6(shared, path, uid, location)
            } else {
                originals.observe_directory(path, uid)?;
                originals.bind_location(location)
            }
        })();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Checks the actual same-file Lock/Journal names in their original order.
    ///
    /// Selected callers requiring partial custody use observe_names_into with
    /// their already-paid owner. This ordinary frontend retains its old scope.
    ///
    /// # Errors
    /// Preserves the original name, native and stale-custody failures.
    pub fn require_names<E: ProtectedFailure>(self) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.require_names(
            self.native.lock_file(), self.native.file(),
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Samples the ordinary witness through its existing native frontend.
    ///
    /// This top Result is not a claim of selected partial-metadata custody;
    /// selected callers retain writer_witness_retaining_v1 in their actual owner.
    ///
    /// # Errors
    /// Preserves the original Directory/Journal/Lock native first failure.
    pub fn writer_witness<E: ProtectedFailure>(self) -> Result<ProtectedWriterNameWitness, E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.writer_witness(
            self.native.file(), self.native.lock_file(),
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Runs the ordinary lazy witness comparison over the actual same files.
    ///
    /// Selected whole-prefix custody requires its separate retained counterpart.
    ///
    /// # Errors
    /// Preserves the original native error or first lazy comparison refusal.
    pub fn require_writer_witness<E: ProtectedFailure>(
        self, witness: &ProtectedWriterNameWitness,
    ) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(E::from)?;
        let result = self.location.ok_or(E::BOUNDARY)?.require_writer_witness(
            self.native.file(), self.native.lock_file(), witness,
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

}

/// Borrows actual protected path/selection DATA and named comparison operations.
///
/// This has no public constructor or raw location/File/descriptor getter. It
/// grants no original, budget, semantic success or independently owned writer.
pub struct CanonicalProtectedReadViewV1<'owner, P> {
    view: CanonicalWriterReadViewV1<'owner, P>,
    location: &'owner ProtectedJournalLocation<P>,
}

impl<P> Copy for CanonicalProtectedReadViewV1<'_, P> {}

impl<P> Clone for CanonicalProtectedReadViewV1<'_, P> {
    fn clone(&self) -> Self { *self }
}

impl<'owner, P> CanonicalProtectedReadViewV1<'owner, P> {
    /// Borrows the actual fixed basename as comparison DATA.
    #[must_use]
    pub fn name(self) -> &'owner str { self.location.name() }

    /// Returns the actual retained owner UID as comparison DATA.
    #[must_use]
    pub fn expected_uid(self) -> u32 { self.location.expected_uid() }

    /// Borrows the actual uninterpreted negative compaction selection.
    #[must_use]
    pub fn original_compaction_selection(self) -> &'owner P {
        self.location.original_compaction_selection()
    }

    /// Observes the actual directory at its existing native frontier.
    ///
    /// # Errors
    /// Preserves the original metadata IO error.
    pub fn directory_metadata<E: ProtectedFailure>(self)
        -> Result<aos_sandbox_journal::protected_storage::OriginalFileMetadataV1, E>
    { self.view.directory_metadata() }

    /// Resolves the caller's existing comparison path without exporting its file.
    ///
    /// # Errors
    /// Preserves the existing rooted path, UID and physical identity failures.
    pub fn require_directory<E: ProtectedFailure>(self, path: &std::path::Path, uid: u32)
        -> Result<CanonicalDirectoryComparisonDataV1, E>
    { self.view.require_directory(path, uid) }

    /// Compares the original fixture directory under its explicit UID.
    ///
    /// # Errors
    /// Preserves the existing fixture rooted traversal/identity failure.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub fn require_directory_at_uid_for_test<E: ProtectedFailure>(
        self, path: &std::path::Path, uid: u32,
    ) -> Result<CanonicalDirectoryComparisonDataV1, E> {
        self.view.require_directory_at_uid_for_test(path, uid)
    }

    /// Compares a supplied observation without adopting its file or identity.
    ///
    /// # Errors
    /// Preserves the actual identity refusal or native IO error.
    pub fn require_opened_directory<E: ProtectedFailure>(self, observed: &std::fs::File)
        -> Result<(), E>
    { self.view.require_opened_directory(observed) }

    /// Rechecks the actual same-owner protected names in their old order.
    ///
    /// # Errors
    /// Preserves native and stale-name failures.
    pub fn require_names<E: ProtectedFailure>(self) -> Result<(), E> {
        self.view.require_names()
    }

    /// Samples the ordinary witness with its original temporary disposition.
    ///
    /// # Errors
    /// Preserves the original Directory/Journal/Lock first native failure.
    pub fn writer_witness<E: ProtectedFailure>(self) -> Result<ProtectedWriterNameWitness, E> {
        self.view.writer_witness()
    }

    /// Compares the ordinary witness lazily at its original native frontier.
    ///
    /// # Errors
    /// Preserves the original native or first lazy comparison refusal.
    pub fn require_writer_witness<E: ProtectedFailure>(self, witness: &ProtectedWriterNameWitness)
        -> Result<(), E>
    { self.view.require_writer_witness(witness) }
}
