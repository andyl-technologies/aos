//! Observes the same ordinary held originals without exposing their files.
//!
//! These named operations retain the existing native and readonly observation
//! engines. They create no role, source cut, financial original or mutable map.
//! Selected Controller, Root and Source owners keep their separate invocation
//! and admission paths; this implementation is only on the actual ordinary owner.

use aos_sandbox_journal::protected_storage::{
    ProtectedFailure, ReadOnlyJournalNameWitness, ReadOnlyJournalNamesOriginalsV1,
    ReadonlyNameArchiveV1,
};

use super::CanonicalOrdinaryHeldJournalV1;
use crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1;

impl<P, I> CanonicalOrdinaryHeldJournalV1<P, I> {
    /// Reports the actual acquisition's readonly mode as mechanical DATA.
    ///
    /// Only internal real acquisition sets this mode. There is no public setter
    /// or supplied-parts constructor that can upgrade a readonly descriptor.
    #[must_use]
    pub fn is_read_only_v1(&self) -> bool {
        self.access == super::AcquisitionAccess::ReadOnly
    }

    /// Lends the existing named native operations of these same held originals.
    ///
    /// The caller retains its actual financial and confined-recipient gates.
    /// This method implements no selected NativeOwner interface and exposes no
    /// file, mutable native prefix, resident index or supplied-parts constructor.
    #[must_use]
    pub fn native_operations_v1(&self) -> CanonicalWriterNativeOperationsV1<'_, P> {
        CanonicalWriterNativeOperationsV1::from_parts(
            self.native.native(),
            self.location.as_ref(),
            None,
        )
    }

    /// Compares the actual held file with an existing readonly name witness.
    ///
    /// # Errors
    /// Preserves the original identity inspection or witness mismatch.
    pub fn require_readonly_identity_v1<E: ProtectedFailure>(
        &self,
        witness: &ReadOnlyJournalNameWitness,
    ) -> Result<(), E> {
        witness.require_file_identity(self.native.native().file())
    }

    /// Runs the next actual readonly archive observation on this same file.
    ///
    /// This is also available on a poisoned ordinary owner for independently
    /// owed native posts. Its archive retains every actual native cause.
    ///
    /// # Errors
    /// Preserves the archive's exact failed slot or overlap/exhaustion index.
    pub fn observe_readonly_archive_v1<E: ProtectedFailure>(
        &self,
        archive: &ReadonlyNameArchiveV1<E>,
        witness: &ReadOnlyJournalNameWitness,
    ) -> Result<(), u8> {
        archive.observe(witness, self.native.native().file())
    }

    /// Captures the existing readonly-name post on this same actual held file.
    ///
    /// No healthy gate, fresh sample or debit replaces this already-owed native
    /// observation. The supplied original retains its own exact once result.
    pub fn capture_readonly_names_once_v1<E: ProtectedFailure>(
        &self,
        original: &ReadOnlyJournalNamesOriginalsV1<E>,
        witness: &ReadOnlyJournalNameWitness,
    ) {
        original.capture_once(witness, self.native.native().file());
    }
}

// These are the existing mechanical fixture mutations, with their actual
// private native destination retained here. Dependent tests cannot obtain a
// general mutable-native or File projection from a production API.
#[cfg(any(test, feature = "test-fixtures"))]
impl<P, I> CanonicalOrdinaryHeldJournalV1<P, I> {
    /// Changes the actual data-file length for a native corruption fixture.
    ///
    /// # Errors
    /// Preserves the original truncate error.
    pub fn set_length_for_fixture_v1(&self, length: u64) -> std::io::Result<()> {
        self.native.native().file().set_len(length)
    }

    /// Duplicates the actual protected directory for an existing fixture.
    ///
    /// # Errors
    /// Refuses an unprotected owner or preserves the original duplicate error.
    pub fn clone_protected_directory_for_fixture_v1<E: ProtectedFailure>(
        &self,
    ) -> Result<std::fs::File, E> {
        self.location
            .as_ref()
            .ok_or(E::BOUNDARY)?
            .clone_directory_for_test()
            .map_err(E::from)
    }

    /// Changes the existing native limits in a bounded fixture.
    pub fn replace_limits_for_fixture_v1(
        &mut self,
        limits: crate::canonical_journal::JournalLimits,
    ) {
        self.native.native_mut().replace_limits_for_fixture(limits);
    }

    /// Changes the existing native sequence in a bounded fixture.
    pub fn replace_next_sequence_for_fixture_v1(&mut self, sequence: u64) {
        self.native
            .native_mut()
            .replace_next_sequence_for_fixture(sequence);
    }

    /// Replaces the existing native path for a bounded fixture.
    pub fn replace_path_for_fixture_v1(&mut self, path: std::path::PathBuf) {
        self.native.native_mut().replace_path_for_fixture(path);
    }

    /// Replaces the existing data file for a native fault fixture.
    pub fn replace_file_for_fixture_v1(&mut self, file: std::fs::File) {
        self.native.native_mut().replace_file(file);
    }

    /// Applies the existing mechanical record mutation for a bounded fixture.
    pub fn apply_mutation_for_fixture_v1(
        &mut self,
        record: aos_sandbox_journal::materialized::RecordMutationRef<
            '_,
            aos_sandbox_model::RecordNamespace,
        >,
    ) {
        self.native.native_mut().apply_mutation(record);
    }

    /// Measures the actual fixture append's expected data-file length.
    ///
    /// # Errors
    /// Preserves the original metadata, frame or checked-length error.
    pub fn expected_append_length_for_fixture_v1(
        &self,
        frames: &[Vec<u8>],
    ) -> Result<u64, aos_sandbox_journal::framing::FrameError> {
        self.native.native().expected_append_length(frames)
    }

    /// Appends fixture frames through the existing exact native append engine.
    ///
    /// # Errors
    /// Preserves the original native append uncertainty and frame errors.
    pub fn append_exact_for_fixture_v1(
        &mut self,
        frames: &[Vec<u8>],
        expected: u64,
    ) -> Result<u64, aos_sandbox_journal::framing::FrameError> {
        self.native.native_mut().append_exact(frames, expected)
    }
}
