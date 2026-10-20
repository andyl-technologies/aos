//! Acquires readonly files and owns their one canonical indexed replay.
//!
//! The actual rooted opener retains every partial physical result. Only its
//! same completed file/parser/index can form an ordinary readonly holder.
//! Fixed role selection, financial admission, mount/name posts and full role
//! semantics stay with the caller; no input File, prefix, map or Arc is accepted.

use std::error::Error;
use std::fs::Metadata;
use std::io;
use std::io::{Seek as _, SeekFrom};
use std::path::Path;

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1;
use aos_sandbox_journal::owner::NativeJournalState;
use aos_sandbox_journal::protected_storage::{
    CompletedReadOnlyAcquisitionV1, FileIdentity, ProtectedFailure, ReadOnlyAcquisitionOriginalsV1,
    ReadOnlyJournalNameWitness, ReadOnlyJournalNamesOriginalsV1, ReadonlyNameArchiveV1,
    CapturedReplayPrefixPostV1,
};
use aos_sandbox_journal::recovery::{RecoveryTailError, finish_readonly_replayed_tail_v1};

use super::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1, Index, OpenedIndexBundle,
};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::opening::{AcquisitionAccess, CompletedNativeOpening, Configuration};
use crate::canonical_journal::{
    CanonicalReplayCursorV1, CanonicalReplayOriginalV1, JournalLimits, NativeJournalDataErrorV1,
    RecoveryReport,
};

/// Owns actual readonly acquisition, canonical parser and private index.
///
/// This mechanical original performs no flock, truncation, repair, semantic
/// admission or identity allocation during acquisition and replay. The caller
/// prepays each actual fixed and captured-extent frontier before entering it.
pub struct CanonicalOrdinaryReadonlyOpeningV1<E> {
    physical: ReadOnlyAcquisitionOriginalsV1<E>,
    configuration: Option<Configuration>,
    acquisition: Option<Result<(), E>>,
    bound_directory: Option<Result<(), E>>,
    metadata: Option<io::Result<Metadata>>,
    parser_seek: Option<io::Result<u64>>,
    parser_identity: Option<Result<FileIdentity, E>>,
    captured_post: Option<CapturedReplayPrefixPostV1<E>>,
    tail_seek: Option<io::Result<u64>>,
    tail: Option<Result<u64, RecoveryTailError>>,
    replay: CanonicalReplayOriginalV1,
    index: Index,
    indexed: CanonicalReplayIndexOriginalsV1,
    prefix: Option<NativeJournalState<RecordNamespace>>,
    pending: Option<OpenedIndexBundle>,
    replay_started: bool,
    ordinary_replay: bool,
    ordinary_disposition: u8,
    ordinary_native_taken: bool,
    taken: bool,
    closed: bool,
}

/// Retains completed canonical readonly DATA after actual file-prefix disposal.
///
/// Its sole constructor consumes this same opening. No native descriptor,
/// admitted purpose or live-currentness claim is present in this result.
pub struct CanonicalOrdinaryReadonlyReplayDataV1 {
    replay: CanonicalReplayOriginalV1,
    index: Index,
    _indexed: CanonicalReplayIndexOriginalsV1,
}

impl<E> CanonicalOrdinaryReadonlyOpeningV1<E> {
    /// Creates inert destinations without allocation or IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            physical: ReadOnlyAcquisitionOriginalsV1::new(),
            configuration: None,
            acquisition: None,
            bound_directory: None,
            metadata: None,
            parser_seek: None,
            parser_identity: None,
            captured_post: None,
            tail_seek: None,
            tail: None,
            replay: CanonicalReplayOriginalV1::new(),
            index: Index::new(),
            indexed: CanonicalReplayIndexOriginalsV1::new(),
            prefix: None,
            pending: None,
            replay_started: false,
            ordinary_replay: false,
            ordinary_disposition: 0,
            ordinary_native_taken: false,
            taken: false,
            closed: false,
        }
    }

    /// Bounds fixed constructor, transfer and held-result representation.
    ///
    /// The enclosing role also pays actual path/name backing, descriptors,
    /// ancestors and every dynamic native/index/semantic extent. The optional
    /// late identity allocation is priced separately before conversion.
    #[must_use]
    pub fn receiving_construction_bytes_v1<P, I>() -> Option<usize>
    where
        E: ProtectedFailure,
    {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(ReadOnlyAcquisitionOriginalsV1::<E>::receiving_construction_bytes_v1()?)?
            // Lower construction, returned outgoing owner and common local.
            .checked_add(std::mem::size_of::<CompletedReadOnlyAcquisitionV1>().checked_mul(3)?)?
            .checked_add(
                std::mem::size_of::<(std::fs::File, std::fs::File, std::fs::File)>()
                    .checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<CompletedNativeOpening>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<OpenedIndexBundle>().checked_mul(2)?)?
            .checked_add(
                std::mem::size_of::<CanonicalOrdinaryHeldJournalV1<P, I>>().checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<
                Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)>,
            >())?
            .checked_add(
                std::mem::size_of::<CanonicalOrdinaryReadonlyReplayDataV1>().checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<CanonicalReplayCursorV1<'_, '_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<CanonicalIndexedReplayV1<'_, '_>>().checked_mul(2)?)?
            // Initial Metadata remains resident while its parser input moves.
            .checked_add(std::mem::size_of::<Metadata>().checked_mul(2)?)?
            .checked_add(CapturedReplayPrefixPostV1::<E>::receiving_memory_bytes_v1()?)?
            .checked_add(aos_sandbox_journal::recovery::readonly_tail_receiving_bytes_v1()?)?
            .checked_add(std::mem::size_of::<P>().checked_mul(2)?)
    }

    /// Bounds the ordinary entry and error-move planes beside the common owner.
    ///
    /// This complete fixed supplier includes the common construction supplier.
    /// Dynamic canonical/index/semantic and path backing remain separately
    /// governed by the caller's actual ordinary offline policy.
    #[must_use]
    pub fn receiving_ordinary_construction_bytes_v1<P, I>() -> Option<usize>
    where
        E: ProtectedFailure,
    {
        type NativePair<'file, 'original> =
            (FileIdentity, CanonicalIndexedReplayV1<'file, 'original>);
        Self::receiving_construction_bytes_v1::<P, I>()?
            .checked_add(std::mem::size_of::<Result<NativePair<'_, '_>, NativeJournalDataErrorV1>>()
                .checked_mul(2)?)?
            .checked_add(std::mem::size_of::<CanonicalReplayOriginalV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<CanonicalReplayIndexOriginalsV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<(
                Option<IdempotencyRecordDataErrorV1>, Option<NativeJournalDataErrorV1>,
            ), NativeJournalDataErrorV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Option<E>>().checked_mul(2)?)
    }

    /// Copies the actual directory, journal and lock identity observations.
    #[must_use]
    pub fn identities_data_v1(&self) -> Option<(FileIdentity, FileIdentity, FileIdentity)> {
        self.physical.identities()
    }

    /// Borrows the original canonical replay reservoir as comparison DATA.
    #[must_use]
    pub const fn replay_data_v1(&self) -> &CanonicalReplayOriginalV1 {
        &self.replay
    }

    /// Borrows this same replay's immutable private idempotency index.
    #[must_use]
    pub fn index_data_v1(&self) -> &Index {
        &self.index
    }

    /// Reports actual indexed EOF without certifying any role semantics.
    #[must_use]
    pub fn indexed_replay_complete_data_v1(&self) -> bool {
        self.indexed.is_complete()
    }

    /// Borrows the actual original native parser stopping cause.
    #[must_use]
    pub fn replay_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.replay.failure()
    }

    /// Borrows the actual original index stopping cause.
    #[must_use]
    pub fn index_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.indexed.failure()
    }

    /// Borrows an entry-order refusal after the actual native/index causes.
    #[must_use]
    pub fn order_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.closed
            .then_some(&READONLY_CLOSED as &(dyn Error + 'static))
    }

    /// Reports the original captured length without another observation.
    #[must_use]
    pub fn captured_length_data_v1(&self) -> Option<u64> {
        Some(self.metadata.as_ref()?.as_ref().ok()?.len())
    }

    /// Reports only whether an actual file remains in this acquisition.
    ///
    /// This passive result permits an owed observer to preserve its original
    /// absent-file branch; it creates no native or semantic completion.
    #[must_use]
    pub fn has_native_file_data_v1(&self) -> bool {
        self.physical.file().is_some()
    }

    /// Performs the owed actual file metadata observation without a health gate.
    ///
    /// The caller retains the entire result at its original independent post.
    ///
    /// # Errors
    /// Preserves the original metadata failure or absent-file refusal.
    pub fn observe_metadata_v1(&self) -> io::Result<Metadata> {
        self.physical
            .file()
            .ok_or_else(|| io::Error::from_raw_os_error(rustix::io::Errno::BADF.raw_os_error()))?
            .metadata()
    }

    /// Captures an independently prepaid name post on this same actual file.
    ///
    /// No healthy-entry check suppresses an owed post after an earlier failure.
    pub fn capture_readonly_names_once_v1<F: ProtectedFailure>(
        &self,
        original: &ReadOnlyJournalNamesOriginalsV1<F>,
        witness: &ReadOnlyJournalNameWitness,
    ) {
        if let Some(file) = self.physical.file() {
            original.capture_once(witness, file);
        }
    }

    /// Runs the existing finite archive on this same reached readonly file.
    ///
    /// No health gate suppresses an independently owed post after failure.
    ///
    /// # Errors
    /// Returns the actual archive failure index or absent-file refusal.
    pub fn observe_archived_names_v1<F: ProtectedFailure>(
        &self,
        archive: &ReadonlyNameArchiveV1<F>,
        witness: &ReadOnlyJournalNameWitness,
    ) -> Result<(), u8> {
        let file = self.physical.file().ok_or(u8::MAX)?;
        archive.observe(witness, file)
    }

    /// Rechecks the existing temporary witness and same reached readonly file.
    ///
    /// # Errors
    /// Preserves the original rooted/name or held-file identity refusal.
    pub fn require_temporary_names_current_v1<F: ProtectedFailure>(
        &self,
        witness: &ReadOnlyJournalNameWitness,
    ) -> Result<(), F> {
        let file = self.physical.file().ok_or(F::BOUNDARY)?;
        witness.check_named_currentness::<F>()?;
        witness.require_file_identity::<F>(file)
    }
}

impl<E: ProtectedFailure> CanonicalOrdinaryReadonlyOpeningV1<E> {
    /// Acquires the exact debug fixture directory before upper limits/files.
    ///
    /// The actual no-follow open and UID/type/mode validation match the old
    /// provided-directory fixture. No supplied File or native prefix is accepted.
    ///
    /// # Errors
    /// Retains the original native/typed cause and refuses repeated entry.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub fn prepare_fixture_directory_once_v1(
        &mut self, root: &Path, name: &str, limits: JournalLimits, uid: u32,
    ) -> Result<(), E> {
        if self.closed || self.configuration.is_some() || self.taken {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.configuration = Some(Configuration {
            path: name.into(), name: name.to_owned(), limits, uid,
        });
        self.bound_directory = Some(self.physical.prepare_fixture_directory_once_v1(root, uid));
        if matches!(self.bound_directory, Some(Ok(()))) { Ok(()) } else { Err(E::BOUNDARY) }
    }

    /// Opens the actual rooted readonly directory, lock and journal once.
    ///
    /// This uses the existing rooted acquisition and readonly FD flags. Initial
    /// mount binding, witness construction and before-name posts remain upper.
    ///
    /// # Errors
    /// Retains the first physical refusal and every reached native original;
    /// repeated entry refuses before another open.
    pub fn prepare_rooted_once_v1(
        &mut self,
        root: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<(), E> {
        if self.closed || self.configuration.is_some() || self.acquisition.is_some() || self.taken {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.configuration = Some(Configuration {
            path: root.join(name),
            name: name.to_owned(),
            limits,
            uid,
        });
        self.acquisition = Some((|| {
            self.physical.prepare_rooted_directory_once(root, uid)?;
            self.physical.prepare_files_once(name, uid)
        })());
        if matches!(self.acquisition, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Resolves and binds the original retained directory before limit checks.
    ///
    /// The existing legacy path DATA is the basename. The independently held
    /// fixed directory still governs all native opens and name witnesses.
    /// Existing RootFixed rooted acquisition keeps its joined-path DATA.
    ///
    /// # Errors
    /// Retains the first actual directory/binding refusal and prevents reentry.
    pub fn prepare_bound_directory_once_v1(
        &mut self,
        root: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: (u64, u64),
    ) -> Result<(), E> {
        self.prepare_original_directory_once_v1(root, name, limits, uid, Some(expected_directory))
    }

    /// Resolves the original directory before upper replay-limit validation.
    ///
    /// A supplied binding is compared by the existing bound-directory engine.
    /// With no binding, the existing rooted engine retains its actual first
    /// observation; no expected identity is synthesized. Both routes keep the
    /// original generic opener's basename path DATA.
    ///
    /// # Errors
    /// Retains the first rooted or binding refusal and prevents repeated entry.
    pub fn prepare_original_directory_once_v1(
        &mut self,
        root: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: Option<(u64, u64)>,
    ) -> Result<(), E> {
        if self.closed || self.configuration.is_some() || self.taken {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.configuration = Some(Configuration {
            path: name.into(), name: name.to_owned(), limits, uid,
        });
        self.bound_directory = Some(match expected_directory {
            Some(expected) => self.physical.prepare_directory_once(root, uid, expected),
            None => self.physical.prepare_rooted_directory_once(root, uid),
        });
        if matches!(self.bound_directory, Some(Ok(()))) { Ok(()) } else { Err(E::BOUNDARY) }
    }

    /// Opens the bound directory's original files after upper limit validation.
    ///
    /// # Errors
    /// Retains actual files/causes and refuses missing or repeated preparation.
    pub fn prepare_bound_files_once_v1(
        &mut self,
        retained_lock_name: Option<&mut Option<String>>,
    ) -> Result<(), E> {
        if self.closed || self.acquisition.is_some()
            || !matches!(self.bound_directory, Some(Ok(())))
        {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        let configuration = self.configuration.as_ref().ok_or(E::BOUNDARY)?;
        self.acquisition = Some(self.physical.prepare_files_with_original_lock_name_once_v1(
            &configuration.name, configuration.uid, retained_lock_name,
        ));
        if matches!(self.acquisition, Some(Ok(()))) { Ok(()) } else { Err(E::BOUNDARY) }
    }

    /// Captures the original parser extent after the role's before-name post.
    ///
    /// # Errors
    /// Retains the actual metadata refusal and refuses reentry or failed entry.
    pub fn capture_metadata_once_v1(&mut self) -> Result<u64, E> {
        if self.closed || self.metadata.is_some() || !self.physical.is_complete() {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.metadata = Some(self.observe_metadata_v1());
        self.captured_length_data_v1().ok_or(E::BOUNDARY)
    }

    /// Lends the existing canonical cursor for an independent native geometry pass.
    ///
    /// The real audit original retains its own parser and all actual IO. The
    /// later full semantic/indexed traversal is a separate unchanged pass.
    ///
    /// # Errors
    /// Preserves the supplied canonical original's actual parser-entry refusal.
    pub fn begin_geometry_cursor_v1<'file, 'original>(
        &'file self,
        original: &'original mut CanonicalReplayOriginalV1,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        let file = self
            .physical
            .file()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let configuration = self
            .configuration
            .as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let bytes = self
            .captured_length_data_v1()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        original.begin_semantic_cursor_once(file, configuration.limits, bytes)
    }

    /// Begins this same readonly file's canonical indexed traversal once.
    ///
    /// # Errors
    /// Retains native parser/index refusal and rejects absent or repeated entry.
    pub fn begin_indexed_replay_once_v1(
        &mut self,
    ) -> Result<CanonicalIndexedReplayV1<'_, '_>, NativeJournalDataErrorV1> {
        if self.closed || self.replay_started || !self.physical.is_complete() {
            self.closed = true;
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.replay_started = true;
        let file = self
            .physical
            .file()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let configuration = self
            .configuration
            .as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let bytes = self
            .captured_length_data_v1()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let cursor = self
            .replay
            .begin_semantic_cursor_once(file, configuration.limits, bytes)?;
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut self.index,
            &mut self.indexed,
        ))
    }

    /// Begins the original captured readonly parser without an early race check.
    ///
    /// Initial metadata fixes the positional bound. The distinct original
    /// parser identity remains its one later observation; the actual upper
    /// prefix post decides size/timestamp drift after the parser outcome.
    ///
    /// # Errors
    /// Retains actual identity/parser/index refusal without replacing originals.
    pub fn begin_retained_captured_replay_once_v1(
        &mut self,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'_, '_>), NativeJournalDataErrorV1> {
        self.begin_original_replay_inner(false, true)
    }

    /// Begins the original readonly description's actual seek/read route.
    ///
    /// This preserves its real OFD movement, retained native validation and
    /// independent parser identity; no positional substitute is introduced.
    ///
    /// # Errors
    /// Retains the original seek, identity or parser failure and rejects reentry.
    pub fn begin_retained_original_replay_once_v1(
        &mut self,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'_, '_>), NativeJournalDataErrorV1> {
        self.begin_original_replay_inner(true, true)
    }

    /// Begins the immediate ordinary parser on this actual original description.
    ///
    /// The same seek, identity and initial metadata schedule is used. Native
    /// scratch uses its original ordinary disposition, independently of the
    /// upper semantic adapter's false Source-family policy.
    ///
    /// # Errors
    /// Retains the actual first seek, identity or parser refusal until the
    /// ordinary caller moves it after the ordered temporary-disposal windows.
    pub fn begin_original_replay_once_v1(
        &mut self,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'_, '_>), NativeJournalDataErrorV1> {
        self.begin_original_replay_inner(true, false)
    }

    fn begin_original_replay_inner(
        &mut self,
        original_description: bool,
        retaining_validation: bool,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'_, '_>), NativeJournalDataErrorV1> {
        if self.closed || self.replay_started || !self.physical.is_complete() {
            self.closed = true;
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.replay_started = true;
        self.ordinary_replay = !retaining_validation;
        let file = self.physical.file().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        if original_description {
            let mut description = file;
            self.parser_seek = Some(description.seek(SeekFrom::Start(0)));
            if !matches!(self.parser_seek, Some(Ok(_))) {
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
        }
        self.parser_identity = Some(FileIdentity::of::<E>(file));
        let identity = self.parser_identity.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .cloned().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let limits = self.configuration.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.limits;
        let cursor = if original_description {
            self.replay.begin_shared_original_cursor_once(file, limits, metadata, retaining_validation)?
        } else {
            self.replay.begin_semantic_cursor_with_metadata_once(file, limits, metadata.len(), metadata)?
        };
        Ok((identity, CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut self.index, &mut self.indexed,
        )))
    }

    /// Disposes ordinary current frame/COMMIT DATA before upper semantic locals.
    ///
    /// # Errors
    /// Refuses retained mode, actual transferred custody or repeated disposition.
    pub fn dispose_ordinary_current_once_v1(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        if !self.ordinary_replay || self.taken || self.ordinary_disposition != 0 {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.ordinary_disposition = 1;
        Ok(self.replay.dispose_ordinary_current_once())
    }

    /// Disposes ordinary pending DATA after the actual upper semantic locals.
    ///
    /// # Errors
    /// Refuses retained mode, transferred custody or a missing first window.
    pub fn dispose_ordinary_pending_once_v1(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        if !self.ordinary_replay || self.taken || self.ordinary_disposition != 1 {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.ordinary_disposition = 2;
        Ok(self.replay.dispose_ordinary_pending_once())
    }

    /// Moves actual ordinary index/native causes after ordered DATA disposal.
    ///
    /// Actual directory, lock and main descriptors remain in this owner. Their
    /// ordinary error-return boundary follows the caller's semantic/index
    /// temporary disposal; successful held transfer is closed by this method.
    ///
    /// # Errors
    /// Refuses retained mode, actual transferred custody or missing disposal.
    pub fn take_ordinary_replay_errors_once_v1(
        &mut self,
    ) -> Result<(Option<IdempotencyRecordDataErrorV1>, Option<NativeJournalDataErrorV1>), NativeJournalDataErrorV1> {
        if !self.ordinary_replay || self.taken || self.ordinary_disposition != 2 {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.ordinary_disposition = 3;
        self.closed = true;
        let index = std::mem::replace(&mut self.indexed, CanonicalReplayIndexOriginalsV1::new())
            .into_ordinary_error();
        drop(std::mem::take(&mut self.index));
        let native = std::mem::replace(&mut self.replay, CanonicalReplayOriginalV1::new())
            .into_ordinary_error();
        Ok((index, native))
    }

    /// Moves the ordinary physical/entry/seek cause without projecting a File.
    ///
    /// Parser and index causes move through their separate ordered error seam.
    /// Calling this closes successful transfer while keeping actual descriptors
    /// until the original ordinary return boundary.
    #[must_use]
    pub fn take_ordinary_native_error_once_v1(&mut self) -> Option<E> {
        if self.taken || self.ordinary_native_taken || (self.replay_started && !self.ordinary_replay) {
            return None;
        }
        self.ordinary_native_taken = true;
        self.closed = true;
        macro_rules! take_error {
            ($field:ident) => {
                match self.$field.take() {
                    Some(Err(cause)) => Some(cause),
                    original => {
                        self.$field = original;
                        None
                    }
                }
            };
        }
        self.physical.take_ordinary_error_once_v1()
            .or_else(|| take_error!(metadata).map(E::from))
            .or_else(|| take_error!(parser_seek).map(E::from))
            .or_else(|| take_error!(parser_identity))
            .or_else(|| take_error!(tail_seek).map(E::from))
    }

    /// Captures the independently owed prefix post before consulting replay.
    ///
    /// No parser-success check suppresses the actual metadata observation.
    pub fn observe_retained_prefix_post_once_v1(&mut self) {
        if self.captured_post.is_some() {
            self.closed = true;
            return;
        }
        if let (Some(file), Some(Ok(before))) = (self.physical.file(), self.metadata.as_ref()) {
            self.captured_post = Some(CapturedReplayPrefixPostV1::observe(file, before));
        } else {
            self.closed = true;
        }
    }

    /// Finishes the same readonly tail only after the actual upper post passed.
    ///
    /// # Errors
    /// Preserves uncommitted-tail refusal and retains the actual final seek I/O.
    pub fn finish_retained_tail_once_v1(&mut self) -> Result<u64, RecoveryTailError> {
        if self.closed || self.tail.is_some() || !self.indexed.is_complete()
            || self.captured_post.as_ref().is_some_and(|post|
                post.metadata_result().is_err() || post.comparison_result().is_err())
        {
            self.closed = true;
            return Err(RecoveryTailError::RetainedNativeFailure);
        }
        let (end, _) = self.replay.report().ok_or(RecoveryTailError::RetainedNativeFailure)?;
        let length = self.captured_length_data_v1().ok_or(RecoveryTailError::RetainedNativeFailure)?;
        let file = self.physical.file().ok_or(RecoveryTailError::RetainedNativeFailure)?;
        self.tail = Some(finish_readonly_replayed_tail_v1(file, length, end, &mut self.tail_seek));
        match self.tail.as_ref() {
            Some(Ok(bytes)) => Ok(*bytes),
            Some(Err(RecoveryTailError::UncommittedTail)) => Err(RecoveryTailError::UncommittedTail),
            _ => Err(RecoveryTailError::RetainedNativeFailure),
        }
    }

    /// Validates the actual native EOF/index without performing tail repair.
    ///
    /// # Errors
    /// Refuses an incomplete parser/index, failed acquisition or nonexact EOF.
    pub fn require_completed_replay_v1(&self) -> Result<RecoveryReport, NativeJournalDataErrorV1> {
        if self.closed || self.taken || !self.physical.is_complete() || !self.indexed.is_complete()
            || self.captured_post.as_ref().is_some_and(|post|
                post.metadata_result().is_err() || post.comparison_result().is_err())
            || matches!(self.tail, Some(Err(_)))
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let (end, report) = self
            .replay
            .report()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        if end
            != self
                .captured_length_data_v1()
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        Ok(report)
    }

    /// Moves this same completed native graph and allocates its one late marker.
    ///
    /// The caller first completes full semantic conversion and all owed posts,
    /// and prepays the marker's actual payload supplier before this entry.
    /// No caller-supplied native state, index, descriptor or Arc is accepted.
    #[must_use]
    pub fn take_held_with_late_payload_once_v1<P, I>(
        &mut self,
        selection: P,
        payload: I,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)> {
        if self.pending.is_none() {
            let report = self.require_completed_replay_v1().ok()?;
            if self.prefix.is_none() {
                self.prefix = self.replay.take_prefix();
            }
            self.prefix.as_ref()?;
            let pair = (self.configuration.take(), self.prefix.take());
            let (configuration, prefix) = match pair {
                (Some(configuration), Some(prefix)) => (configuration, prefix),
                (configuration, prefix) => {
                    self.configuration = configuration;
                    self.prefix = prefix;
                    return None;
                }
            };
            let originals = match self.physical.take_completed_files_once_v1() {
                Some(originals) => originals,
                None => {
                    self.configuration = Some(configuration);
                    self.prefix = Some(prefix);
                    return None;
                }
            };
            let (directory, file, lock) = originals.into_original_files();
            self.pending = Some(OpenedIndexBundle {
                opened: CompletedNativeOpening {
                    configuration,
                    directory: Some(directory),
                    file,
                    lock,
                    prefix,
                    report,
                    access: AcquisitionAccess::ReadOnly,
                },
                index: std::mem::take(&mut self.index),
            });
        }
        if self.closed || self.taken {
            return None;
        }
        let bundle = self.pending.take()?;
        self.taken = true;
        let instance = CanonicalJournalInstanceDataV1::from_payload(payload);
        Some(CanonicalOrdinaryHeldJournalV1::from_bundle(
            bundle,
            selection,
            Some(instance),
        ))
    }

    /// Consumes completed replay DATA while physically dropping native prefixes.
    ///
    /// The actual upper role first requires every semantic/native/financial
    /// post. Failure returns this whole unchanged owner for retained diagnostics.
    ///
    /// # Errors
    /// Returns this owner after incomplete replay or any previous transfer.
    pub fn into_completed_data_v1(self) -> Result<CanonicalOrdinaryReadonlyReplayDataV1, Self> {
        if self.require_completed_replay_v1().is_err() {
            return Err(self);
        }
        let Self {
            replay,
            index,
            indexed,
            ..
        } = self;
        Ok(CanonicalOrdinaryReadonlyReplayDataV1 {
            replay,
            index,
            _indexed: indexed,
        })
    }
}

impl<E: Error + 'static> CanonicalOrdinaryReadonlyOpeningV1<E> {
    /// Borrows the original description/identity stopping cause before parsing.
    #[must_use]
    pub fn retained_parser_preparation_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.parser_seek.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.parser_identity.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Borrows the independently reached prefix post without another probe.
    #[must_use]
    pub fn retained_prefix_post_v1(&self) -> Option<&CapturedReplayPrefixPostV1<E>> {
        self.captured_post.as_ref()
    }

    /// Borrows the actual final-seek error before its upper boundary projection.
    #[must_use]
    pub fn retained_tail_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.tail_seek.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
    }

    /// Borrows the first physical or metadata cause without another observation.
    #[must_use]
    pub fn acquisition_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.physical
            .failure()
            .or_else(|| {
                self.acquisition
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

impl<E> Default for CanonicalOrdinaryReadonlyOpeningV1<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalOrdinaryReadonlyReplayDataV1 {
    /// Borrows the same completed parser DATA after native-prefix disposal.
    #[must_use]
    pub const fn replay_data_v1(&self) -> &CanonicalReplayOriginalV1 {
        &self.replay
    }

    /// Borrows the same completed private index as immutable historical DATA.
    #[must_use]
    pub fn index_data_v1(&self) -> &Index {
        &self.index
    }
}

static READONLY_CLOSED: NativeJournalDataErrorV1 = NativeJournalDataErrorV1::ProtectedBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    use aos_sandbox_protocol::domain_ledger::transaction::{
        JournalRecord, JournalTransaction, encode_transaction,
    };

    fn history() -> tempfile::TempDir {
        let directory = super::super::tests::protected_directory();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("history"))
            .unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("history.lock"))
            .unwrap();
        let transaction = JournalTransaction::new(
            [7; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"actual-row".to_vec(),
                b"actual-value".to_vec(),
            )],
        )
        .unwrap();
        for frame in encode_transaction(&transaction, 1).unwrap() {
            file.write_all(&frame).unwrap();
        }
        directory
    }

    fn acquire(directory: &Path) -> CanonicalOrdinaryReadonlyOpeningV1<NativeJournalDataErrorV1> {
        let mut opened = CanonicalOrdinaryReadonlyOpeningV1::new();
        opened
            .prepare_rooted_once_v1(
                directory,
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
            )
            .unwrap();
        opened.capture_metadata_once_v1().unwrap();
        opened
    }

    fn replay(opened: &mut CanonicalOrdinaryReadonlyOpeningV1<NativeJournalDataErrorV1>) {
        let mut cursor = opened.begin_indexed_replay_once_v1().unwrap();
        while cursor.advance_once().unwrap() {
            cursor.validate_compaction_once().unwrap();
            cursor.register_and_compare_index_once().unwrap();
            cursor.prepare_change_once().unwrap();
            while cursor.apply_next_record_once().unwrap() {}
            cursor.finish_commit_accounting_once().unwrap();
            cursor.finish_commit_once().unwrap();
        }
    }

    struct Marker;

    fn acquire_bound(directory: &Path) -> CanonicalOrdinaryReadonlyOpeningV1<NativeJournalDataErrorV1> {
        let directory_file = std::fs::File::open(directory).unwrap();
        let expected = FileIdentity::of::<NativeJournalDataErrorV1>(&directory_file).unwrap().physical_pair();
        let mut opening = CanonicalOrdinaryReadonlyOpeningV1::new();
        opening.prepare_bound_directory_once_v1(directory, "history", JournalLimits::default(),
            rustix::process::geteuid().as_raw(), expected).unwrap();
        assert!(!opening.has_native_file_data_v1());
        opening.prepare_bound_files_once_v1(None).unwrap();
        opening.capture_metadata_once_v1().unwrap();
        opening
    }

    fn finish_indexed(cursor: &mut CanonicalIndexedReplayV1<'_, '_>) {
        while cursor.advance_once().unwrap() {
            cursor.validate_compaction_once().unwrap();
            cursor.register_and_compare_index_once().unwrap();
            cursor.prepare_change_once().unwrap();
            while cursor.apply_next_record_once().unwrap() {}
            cursor.finish_commit_accounting_once().unwrap();
            cursor.finish_commit_once().unwrap();
        }
    }

    #[test]
    fn retained_capture_keeps_initial_bound_then_observes_later_drift_without_moving_ofd() {
        use std::io::{Seek as _, SeekFrom};

        let directory = history();
        let mut opened = acquire_bound(directory.path());
        let original_length = opened.captured_length_data_v1().unwrap();
        let mut writer = std::fs::OpenOptions::new().append(true)
            .open(directory.path().join("history")).unwrap();
        writer.write_all(b"x").unwrap();
        let mut description = opened.physical.file().unwrap();
        description.seek(SeekFrom::Start(1)).unwrap();

        {
            let (identity, mut cursor) = opened.begin_retained_captured_replay_once_v1().unwrap();
            assert_eq!(identity.byte_len(), original_length + 1);
            finish_indexed(&mut cursor);
        }
        assert_eq!(opened.replay_data_v1().report().unwrap().0, original_length);
        assert_eq!(opened.physical.file().unwrap().stream_position().unwrap(), 1);
        opened.observe_retained_prefix_post_once_v1();

        assert!(opened.retained_prefix_post_v1().unwrap().metadata_result().is_ok());
        assert!(opened.retained_prefix_post_v1().unwrap().comparison_result().is_err());
        assert!(opened.finish_retained_tail_once_v1().is_err());
        assert!(opened.take_held_with_late_payload_once_v1((), Marker).is_none());
        assert!(opened.has_native_file_data_v1());
    }

    #[test]
    fn fixture_entry_acquires_exact_directory_without_inventing_root_ancestry() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["history", "history.lock"] {
            OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(directory.path().join(name)).unwrap();
        }
        let mut opened = CanonicalOrdinaryReadonlyOpeningV1::<NativeJournalDataErrorV1>::new();

        opened.prepare_fixture_directory_once_v1(
            directory.path(), "history", JournalLimits::default(),
            rustix::process::geteuid().as_raw(),
        ).unwrap();
        assert!(!opened.has_native_file_data_v1());
        opened.prepare_bound_files_once_v1(None).unwrap();
        opened.capture_metadata_once_v1().unwrap();
        {
            let (_, mut cursor) = opened.begin_original_replay_once_v1().unwrap();
            finish_indexed(&mut cursor);
        }
        opened.finish_retained_tail_once_v1().unwrap();
        let (held, report) = opened.take_held_with_late_payload_once_v1((), Marker).unwrap();

        assert_eq!(report.committed_transactions, 0);
        assert!(held.is_read_only_v1());
        assert_eq!(held.read_view_v1().path(), &std::path::PathBuf::from("history"));
    }

    #[test]
    fn ordinary_original_replay_moves_actual_error_after_disposal_and_keeps_files() {
        let directory = history();
        std::fs::write(directory.path().join("history"),
            [0; aos_sandbox_journal::framing::HEADER_BYTES]).unwrap();
        let mut opened = acquire_bound(directory.path());
        let fd = opened.physical.file().unwrap().as_raw_fd();

        {
            let (_, mut cursor) = opened.begin_original_replay_once_v1().unwrap();
            assert!(cursor.advance_once().is_err());
        }
        assert!(opened.take_ordinary_replay_errors_once_v1().is_err());
        opened.dispose_ordinary_current_once_v1().unwrap();
        // The caller drops its actual upper semantic locals in this window.
        opened.dispose_ordinary_pending_once_v1().unwrap();
        let (index, native) = opened.take_ordinary_replay_errors_once_v1().unwrap();

        assert!(index.is_none());
        assert!(matches!(native, Some(NativeJournalDataErrorV1::Frame(
            aos_sandbox_journal::framing::FrameError::MalformedTransaction("invalid frame magic")
        ))));
        assert_eq!(opened.physical.file().unwrap().as_raw_fd(), fd);
        assert!(opened.take_held_with_late_payload_once_v1((), Marker).is_none());
        assert!(opened.take_ordinary_replay_errors_once_v1().is_err());
    }

    #[test]
    fn retained_original_replay_refuses_ordinary_error_extraction() {
        let directory = history();
        let mut opened = acquire_bound(directory.path());
        {
            let (_, mut cursor) = opened.begin_retained_original_replay_once_v1().unwrap();
            finish_indexed(&mut cursor);
        }

        assert!(opened.dispose_ordinary_current_once_v1().is_err());
        assert!(opened.take_ordinary_replay_errors_once_v1().is_err());
        assert!(opened.take_ordinary_native_error_once_v1().is_none());
        opened.finish_retained_tail_once_v1().unwrap();
        assert!(opened.take_held_with_late_payload_once_v1((), Marker).is_some());
    }

    #[test]
    fn original_directory_without_binding_uses_actual_rooted_acquisition() {
        let directory = history();
        let mut opened = CanonicalOrdinaryReadonlyOpeningV1::<NativeJournalDataErrorV1>::new();

        opened.prepare_original_directory_once_v1(
            directory.path(), "history", JournalLimits::default(),
            rustix::process::geteuid().as_raw(), None,
        ).unwrap();
        assert!(!opened.has_native_file_data_v1());
        opened.prepare_bound_files_once_v1(None).unwrap();
        opened.capture_metadata_once_v1().unwrap();
        {
            let (_, mut cursor) = opened.begin_retained_original_replay_once_v1().unwrap();
            finish_indexed(&mut cursor);
        }
        opened.finish_retained_tail_once_v1().unwrap();
        let (held, report) = opened.take_held_with_late_payload_once_v1((), Marker).unwrap();

        assert_eq!(report.committed_transactions, 1);
        assert!(held.is_read_only_v1());
        assert_eq!(held.read_view_v1().path(), &std::path::PathBuf::from("history"));
    }

    #[test]
    fn retained_original_description_uses_actual_ofd_and_keeps_basename_path_data() {
        use std::io::{Seek as _, SeekFrom};

        let directory = history();
        let mut opened = acquire_bound(directory.path());
        let length = opened.captured_length_data_v1().unwrap();
        let mut description = opened.physical.file().unwrap();
        description.seek(SeekFrom::Start(1)).unwrap();

        {
            let (_, mut cursor) = opened.begin_retained_original_replay_once_v1().unwrap();
            finish_indexed(&mut cursor);
        }
        assert_eq!(opened.physical.file().unwrap().stream_position().unwrap(), length);
        opened.finish_retained_tail_once_v1().unwrap();
        let (held, _) = opened.take_held_with_late_payload_once_v1((), Marker).unwrap();

        assert!(held.is_read_only_v1());
        assert_eq!(held.read_view_v1().path(), &std::path::PathBuf::from("history"));
    }

    #[test]
    fn actual_readonly_flags_no_flock_and_same_file_index_move_precede_late_identity() {
        let directory = history();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join("history.lock"))
            .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let mut opened = acquire(directory.path());
        let original_fd = opened.physical.file().unwrap().as_raw_fd();
        let flags = rustix::fs::fcntl_getfl(opened.physical.file().unwrap()).unwrap();
        assert!(!flags.intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR));
        assert!(
            opened
                .take_held_with_late_payload_once_v1((), Marker)
                .is_none()
        );
        replay(&mut opened);
        let (held, report) = opened
            .take_held_with_late_payload_once_v1((), Marker)
            .unwrap();

        assert_eq!(held.native.native().file().as_raw_fd(), original_fd);
        assert!(held.is_read_only_v1());
        assert_eq!(report.committed_transactions, 1);
        assert_eq!(
            held.read_view_v1()
                .state()
                .get(&(RecordNamespace::DesiredState, b"actual-row".to_vec())),
            Some(&b"actual-value".to_vec())
        );
        assert_eq!(
            std::sync::Arc::strong_count(held.instance_data_v1().unwrap().comparison_arc_v1()),
            1
        );
        assert!(
            opened
                .take_held_with_late_payload_once_v1((), Marker)
                .is_none()
        );
    }

    #[test]
    fn audit_and_full_indexed_pass_keep_two_actual_independent_canonical_reservoirs() {
        let directory = history();
        let mut opened = acquire(directory.path());
        let mut audit = CanonicalReplayOriginalV1::new();
        {
            let mut cursor = opened.begin_geometry_cursor_v1(&mut audit).unwrap();
            while cursor.advance_once().unwrap() {
                cursor.validate_compaction_once().unwrap();
                cursor.register_transaction_once().unwrap();
                cursor.prepare_change_once().unwrap();
                cursor.apply_commit_once().unwrap();
            }
        }
        assert!(opened.replay_data_v1().report().is_none());

        replay(&mut opened);

        assert_eq!(audit.report(), opened.replay_data_v1().report());
        assert_eq!(audit.state(), opened.replay_data_v1().state());
        assert!(!std::ptr::eq(
            audit.state().unwrap(),
            opened.replay_data_v1().state().unwrap()
        ));
    }

    #[test]
    fn readonly_torn_tail_never_repairs_or_allocates_a_late_marker() {
        let directory = history();
        let mut file = OpenOptions::new()
            .append(true)
            .open(directory.path().join("history"))
            .unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        let length = file.metadata().unwrap().len();
        let mut opened = acquire(directory.path());
        replay(&mut opened);

        assert!(
            opened
                .take_held_with_late_payload_once_v1((), Marker)
                .is_none()
        );
        assert!(opened.pending.is_none());
        assert!(opened.physical.file().is_some());
        assert_eq!(file.metadata().unwrap().len(), length);
        assert!(opened.require_completed_replay_v1().is_err());
    }

    #[test]
    fn malformed_frame_retains_same_cause_and_native_file_after_reentry() {
        let directory = history();
        let mut file = OpenOptions::new()
            .append(true)
            .open(directory.path().join("history"))
            .unwrap();
        file.write_all(&[0; aos_sandbox_journal::framing::HEADER_BYTES])
            .unwrap();
        let mut opened = acquire(directory.path());
        let fd = opened.physical.file().unwrap().as_raw_fd();
        {
            let mut cursor = opened.begin_indexed_replay_once_v1().unwrap();
            assert!(cursor.advance_once().unwrap());
            cursor.validate_compaction_once().unwrap();
            cursor.register_and_compare_index_once().unwrap();
            cursor.prepare_change_once().unwrap();
            while cursor.apply_next_record_once().unwrap() {}
            cursor.finish_commit_accounting_once().unwrap();
            cursor.finish_commit_once().unwrap();
            assert!(cursor.advance_once().is_err());
        }
        let first = opened.replay_failure_v1().unwrap() as *const dyn Error;

        assert!(opened.begin_indexed_replay_once_v1().is_err());
        assert!(std::ptr::eq(
            first,
            opened.replay_failure_v1().unwrap() as *const dyn Error
        ));
        assert_eq!(opened.physical.file().unwrap().as_raw_fd(), fd);
        assert!(
            opened
                .take_held_with_late_payload_once_v1((), Marker)
                .is_none()
        );
    }

    #[test]
    fn owed_name_post_observes_same_unhealthy_file_and_retains_real_name_replacement() {
        let directory = history();
        let mut opened = acquire(directory.path());
        let (root, file, lock) = opened.identities_data_v1().unwrap();
        let witness = ReadOnlyJournalNameWitness::from_original_parts((
            directory.path().to_path_buf(),
            "history".to_owned(),
            rustix::process::geteuid().as_raw(),
            root,
            file,
            lock,
        ));
        assert!(opened.begin_indexed_replay_once_v1().is_ok());
        assert!(opened.begin_indexed_replay_once_v1().is_err());
        std::fs::rename(
            directory.path().join("history"),
            directory.path().join("old"),
        )
        .unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("history"))
            .unwrap();
        let after = ReadOnlyJournalNamesOriginalsV1::<NativeJournalDataErrorV1>::new();

        opened.capture_readonly_names_once_v1(&after, &witness);

        assert!(!after.is_complete());
        assert!(after.failure().is_some());
        assert!(opened.observe_metadata_v1().is_ok());
    }

    #[test]
    fn actual_readonly_holder_keeps_prepare_order_and_refuses_both_write_dispositions() {
        use crate::canonical_journal::coordinator::retained_data::RetainedAppendDataCustodyV1;
        use crate::canonical_journal::coordinator::{
            CanonicalCoordinatorAppendDataV1 as _, CanonicalCoordinatorAppendV1 as _,
        };

        let directory = history();
        let mut opened = acquire(directory.path());
        replay(&mut opened);
        let (mut held, _) = opened
            .take_held_with_late_payload_once_v1((), Marker)
            .unwrap();
        let before = held.read_view_v1().state().clone();
        let transaction = JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"another-row".to_vec(),
                b"new-value".to_vec(),
            )],
        )
        .unwrap();
        let mut ordinary = held.prepare_append_once(&transaction).unwrap();
        held.append_coordinates_once(&mut ordinary).unwrap();
        let length = held.expected_append_length_once(&mut ordinary).unwrap();

        assert!(held.append_prepared_once(&mut ordinary).is_err());
        assert!(ordinary.failure().is_some());
        assert!(ordinary.take_ordinary_error_v1().unwrap().is_some());
        assert_eq!(held.read_view_v1().state(), &before);

        let custody = RetainedAppendDataCustodyV1::new();
        let mut captured = held
            .prepare_captured_append_v1(&custody, &transaction)
            .unwrap();
        held.append_coordinates_once(&mut captured).unwrap();
        assert_eq!(
            held.expected_append_length_once(&mut captured).unwrap(),
            length
        );
        assert!(held.append_prepared_once(&mut captured).is_err());
        let diagnostic = captured.take_captured_failure_v1().unwrap();
        drop(diagnostic);

        assert!(custody.failure().is_some());
        assert!(custody.is_closed());
        assert_eq!(held.read_view_v1().state(), &before);
    }
}
