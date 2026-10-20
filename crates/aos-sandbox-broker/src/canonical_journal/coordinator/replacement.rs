//! Shares physical replacement without exporting its actual data descriptor.
//!
//! Ordinary and selected adapters run the same write/sync/size/dispose/install
//! schedule. Semantic replay stays in its sole upper engine. A selected body
//! owns its real replacement, reopened File, cleanup debt and native/index
//! originals, so a failure can park without releasing physical uncertainty.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_journal::owner::{NativeJournal, NativeJournalState};
use aos_sandbox_journal::protected_storage::{
    FileIdentity, FileIdentityOriginalsV1, OwnedProtectedTemporaryV1,
    ProtectedJournalLocation, ProtectedTemporary,
};
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use crate::canonical_journal::{
    CanonicalReplayExtentDataV1, CanonicalReplayOriginalV1,
    NativeJournalDataErrorV1, write_compacted_data,
};
use super::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1};
use super::selected_append::{SelectedAppendCustodyV1, SelectedAppendGuardV1};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Preserves the actual physical or canonical replacement stopping cause.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalReplacementErrorV1 {
    /// Preserves actual open, sync, size and final seek failures.
    #[error(transparent)]
    Native(#[from] NativeJournalDataErrorV1),
    /// Preserves the original canonical snapshot writer failure.
    #[error(transparent)]
    Encode(#[from] crate::canonical_journal::CanonicalCompactionErrorV1),
    /// Rejects an absent, repeated or incomplete mechanical stage.
    #[error("journal replacement stage is closed")]
    Closed,
}

impl From<io::Error> for CanonicalReplacementErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Native(NativeJournalDataErrorV1::Io(error))
    }
}

enum TemporaryName {
    Protected(String),
    Unprotected(PathBuf),
}

trait Cleanup {
    fn install(
        &mut self,
        temporary: &TemporaryName,
        file: &mut Option<File>,
        native_error: &mut Option<rustix::io::Errno>,
    ) -> Result<(), NativeJournalDataErrorV1>;
}

struct OwnedCleanup<P> {
    location: Arc<ProtectedJournalLocation<P>>,
    debt: OwnedProtectedTemporaryV1<P>,
}

impl<P> Cleanup for OwnedCleanup<P> {
    fn install(&mut self, temporary: &TemporaryName, file: &mut Option<File>, native: &mut Option<rustix::io::Errno>)
        -> Result<(), NativeJournalDataErrorV1>
    {
        let TemporaryName::Protected(temporary) = temporary else {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        };
        self.location.install_owned_replacement_retaining_v1::<NativeJournalDataErrorV1>(
            temporary, &mut self.debt, file, native,
        )
    }
}

enum OrdinaryCleanup<'owner, P> {
    Protected {
        location: &'owner ProtectedJournalLocation<P>,
        debt: ProtectedTemporary<'owner>,
    },
    Unprotected { path: &'owner Path },
}

impl<P> Cleanup for OrdinaryCleanup<'_, P> {
    fn install(&mut self, temporary: &TemporaryName, file: &mut Option<File>, _: &mut Option<rustix::io::Errno>)
        -> Result<(), NativeJournalDataErrorV1>
    {
        *file = Some(match self {
            Self::Protected { location, debt } => {
                let TemporaryName::Protected(temporary) = temporary else {
                    return Err(NativeJournalDataErrorV1::ProtectedBoundary);
                };
                location.install_replacement::<NativeJournalDataErrorV1>(temporary, debt)?
            },
            Self::Unprotected { path } => {
                let TemporaryName::Unprotected(temporary) = temporary else {
                    return Err(NativeJournalDataErrorV1::ProtectedBoundary);
                };
                std::fs::rename(temporary, *path)?;
                let parent = path.parent().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidInput, "journal path has no parent directory",
                ))?;
                File::open(parent)?.sync_all()?;
                OpenOptions::new().read(true).write(true).open(*path)?
            }
        });
        Ok(())
    }
}

struct ReplacementIo<C> {
    // As in the original protected function, cleanup retires before open files.
    cleanup: Option<C>,
    replacement: Option<File>,
    temporary: Option<TemporaryName>,
    installed: Option<File>,
    native_open: Option<rustix::io::Errno>,
    preparation: Option<Result<(), CanonicalReplacementErrorV1>>,
    completion: Option<Result<(), CanonicalReplacementErrorV1>>,
    limits: JournalLimits,
    retaining: bool,
    size_metadata: Option<std::fs::Metadata>,
    tail_metadata: Option<std::fs::Metadata>,
}

impl<C> Drop for ReplacementIo<C> {
    fn drop(&mut self) {
        // After installation the old reopened File local was newer than its
        // disarmed cleanup loan. Before installation cleanup precedes the still
        // open replacement. Preserve both destruction boundaries.
        drop(self.installed.take());
    }
}

impl<C: Cleanup> ReplacementIo<C> {
    fn empty(limits: JournalLimits, retaining: bool) -> Self {
        Self {
            cleanup: None, replacement: None, temporary: None, installed: None,
            native_open: None, preparation: None, completion: None, limits,
            retaining, size_metadata: None, tail_metadata: None,
        }
    }

    // This is the single physical write/install schedule for both adapters.
    fn write_and_install(&mut self, state: &State) -> Result<(), CanonicalReplacementErrorV1> {
        let replacement = self.replacement.as_mut().ok_or(CanonicalReplacementErrorV1::Closed)?;
        write_compacted_data(replacement, state, self.limits)?;
        replacement.sync_all()?;
        let metadata = replacement.metadata()?;
        let length = metadata.len();
        if self.retaining {
            self.size_metadata = Some(metadata);
        } else {
            // Preserve the ordinary condition temporary's disposal before its
            // oversized branch or subsequent replacement File close.
            drop(metadata);
        }
        if length > self.limits.maximum_journal_bytes {
            return Err(NativeJournalDataErrorV1::JournalTooLarge.into());
        }
        drop(self.replacement.take());
        let cleanup = self.cleanup.as_mut().ok_or(CanonicalReplacementErrorV1::Closed)?;
        let temporary = self.temporary.as_ref().ok_or(CanonicalReplacementErrorV1::Closed)?;
        cleanup.install(temporary, &mut self.installed, &mut self.native_open)?;
        Ok(())
    }

    fn finish(&mut self, durable_end: u64) -> Result<(), CanonicalReplacementErrorV1> {
        if self.completion.is_some() || !matches!(self.preparation, Some(Ok(()))) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        self.completion = Some((|| {
            let file = self.installed.as_mut().ok_or(CanonicalReplacementErrorV1::Closed)?;
            let metadata = file.metadata()?;
            let length = metadata.len();
            if self.retaining {
                self.tail_metadata = Some(metadata);
            } else {
                drop(metadata);
            }
            if durable_end != length {
                return Err(NativeJournalDataErrorV1::MalformedTransaction(
                    "compacted journal has an uncommitted tail",
                ).into());
            }
            file.seek(SeekFrom::End(0))?;
            Ok(())
        })());
        if matches!(self.completion, Some(Ok(()))) { Ok(()) }
        else { Err(CanonicalReplacementErrorV1::Closed) }
    }

    fn failure(&self) -> Option<&CanonicalReplacementErrorV1> {
        self.preparation.as_ref().and_then(|value| value.as_ref().err())
            .or_else(|| self.completion.as_ref().and_then(|value| value.as_ref().err()))
    }
}

/// Adapts actual ordinary storage to the shared replacement schedule.
///
/// Supplied ordinary DATA cannot construct or adopt a selected role writer.
/// The original upper parser and its semantic gates remain the caller's engine.
pub(in crate::canonical_journal) struct OrdinaryCoordinatorReplacementV1<'owner, P> {
    io: ReplacementIo<OrdinaryCleanup<'owner, P>>,
}

impl<'owner, P> OrdinaryCoordinatorReplacementV1<'owner, P> {
    /// Prepares replacement at the original ordinary physical frontier.
    ///
    /// # Errors
    /// Preserves exact native/encoder failure after ordinary local disposal.
    pub fn prepare_once(
        native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
        location: Option<&'owner ProtectedJournalLocation<P>>,
    ) -> Result<Self, CanonicalReplacementErrorV1> {
        let mut owner = Self { io: ReplacementIo::empty(native.limits(), false) };
        let result = (|| {
            let (temporary, replacement, cleanup) = match location {
                Some(location) => {
                    let (temporary, replacement, debt) = location.begin_replacement::<NativeJournalDataErrorV1>()?;
                    (TemporaryName::Protected(temporary), replacement, OrdinaryCleanup::Protected { location, debt })
                }
                None => {
                    let mut temporary = native.path().as_os_str().to_os_string();
                    temporary.push(".compact.tmp");
                    let temporary = PathBuf::from(temporary);
                    let replacement = OpenOptions::new().read(true).write(true)
                        .create(true).truncate(true).open(&temporary)?;
                    let cleanup = OrdinaryCleanup::Unprotected { path: native.path() };
                    (TemporaryName::Unprotected(temporary), replacement, cleanup)
                }
            };
            owner.io.temporary = Some(temporary);
            owner.io.replacement = Some(replacement);
            owner.io.cleanup = Some(cleanup);
            owner.io.write_and_install(native.state())
        })();
        if let Err(error) = result {
            drop(owner);
            return Err(error);
        }
        owner.io.preparation = Some(Ok(()));
        Ok(owner)
    }

    // Only the same-bundle ordinary composition uses these two delegates.
    // Seek and metadata Results stay on that original; no File is projected.
    pub(in crate::canonical_journal) fn prepare_indexed_parser_once_v1(
        &mut self,
        seek: &mut Option<io::Result<u64>>,
        metadata: &mut Option<io::Result<std::fs::Metadata>>,
    ) -> Result<FileIdentity, CanonicalReplacementErrorV1> {
        if !matches!(self.io.preparation, Some(Ok(())))
            || self.io.completion.is_some()
            || seek.is_some()
            || metadata.is_some()
        {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let file = self.io.installed.as_mut()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        *seek = Some(file.seek(SeekFrom::Start(0)));
        if !matches!(seek, Some(Ok(_))) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        *metadata = Some(file.metadata());
        let metadata = metadata.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        Ok(FileIdentity::from_metadata_data_v1(metadata))
    }

    pub(in crate::canonical_journal) fn begin_indexed_replay_once_v1<'file, 'original>(
        &'file mut self,
        replay: &'original mut CanonicalReplayOriginalV1,
        index: &'original mut Index,
        indexed: &'original mut CanonicalReplayIndexOriginalsV1,
        metadata_original: &mut Option<io::Result<std::fs::Metadata>>,
    ) -> Result<CanonicalIndexedReplayV1<'file, 'original>, CanonicalReplacementErrorV1> {
        if !matches!(self.io.preparation, Some(Ok(()))) || self.io.completion.is_some() {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let metadata = match metadata_original.take() {
            Some(Ok(metadata)) => metadata,
            other => {
                *metadata_original = other;
                return Err(CanonicalReplacementErrorV1::Closed);
            }
        };
        let file = self.io.installed.as_mut()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        let cursor = replay.begin_ordinary_semantic_cursor_on_original_once(
            file, self.io.limits, metadata,
        )?;
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, index, indexed,
        ))
    }

    /// Finishes the original tail check and final seek after actual replay.
    ///
    /// # Errors
    /// Preserves exact metadata/tail/seek error after ordinary local disposal.
    pub fn finish_once(mut self, durable_end: u64)
        -> Result<OrdinaryReplacementFileDataV1, CanonicalReplacementErrorV1>
    {
        if self.io.finish(durable_end).is_err() {
            let failure = self.io.completion.take().and_then(Result::err)
                .unwrap_or(CanonicalReplacementErrorV1::Closed);
            drop(self);
            return Err(failure);
        }
        let file = self.io.installed.take().ok_or(CanonicalReplacementErrorV1::Closed)?;
        let temporary = if matches!(self.io.cleanup, Some(OrdinaryCleanup::Unprotected { .. })) {
            match self.io.temporary.take() {
                Some(TemporaryName::Unprotected(path)) => Some(path),
                _ => None,
            }
        } else { None };
        Ok(OrdinaryReplacementFileDataV1 { file: Some(file), _temporary: temporary })
    }
}

/// Moves only an actual ordinary replacement into its original native storage.
///
/// Its constructor is private to the ordinary adapter. Selected role writers
/// cannot receive this DATA or use it to adopt caller-projected replay state.
pub(in crate::canonical_journal) struct OrdinaryReplacementFileDataV1 {
    file: Option<File>,
    // Unprotected temporary path retains its original caller-scope disposal;
    // protected cleanup/name locals already retired at their old inner return.
    _temporary: Option<PathBuf>,
}

impl OrdinaryReplacementFileDataV1 {
    /// Installs the same private composition's completed canonical prefix.
    ///
    /// # Errors
    /// Refuses repeated installation without replacing the actual native owner.
    pub(in crate::canonical_journal) fn install_once(
        &mut self,
        native: &mut NativeJournal<RecordNamespace, JournalLimits>,
        state: NativeJournalState<RecordNamespace>,
    ) -> Result<(), CanonicalReplacementErrorV1> {
        let file = self.file.take().ok_or(CanonicalReplacementErrorV1::Closed)?;
        native.replace_replayed_file(file, state);
        Ok(())
    }
}

pub(crate) struct SelectedReplacementBodyV1<P> {
    io: ReplacementIo<OwnedCleanup<P>>,
    replay: CanonicalReplayOriginalV1,
    index: Index,
    indexed: CanonicalReplayIndexOriginalsV1,
    identity: FileIdentityOriginalsV1<NativeJournalDataErrorV1>,
    identity_result: Option<Result<(), NativeJournalDataErrorV1>>,
    extent: Option<Result<CanonicalReplayExtentDataV1, NativeJournalDataErrorV1>>,
    taken: bool,
    installed_durable_end: Option<u64>,
    closed: Option<CanonicalReplacementErrorV1>,
}

impl<P> SelectedReplacementBodyV1<P> {
    pub(crate) fn new(limits: JournalLimits) -> Self {
        Self {
            io: ReplacementIo::empty(limits, true), replay: CanonicalReplayOriginalV1::new(),
            index: Index::new(), indexed: CanonicalReplayIndexOriginalsV1::new(),
            identity: FileIdentityOriginalsV1::new(), identity_result: None,
            extent: None, taken: false, installed_durable_end: None, closed: None,
        }
    }

    pub(crate) fn prepare_once(&mut self, location: &Arc<ProtectedJournalLocation<P>>, state: &State)
        -> Result<(), CanonicalReplacementErrorV1>
    {
        if self.io.preparation.is_some() { return Err(CanonicalReplacementErrorV1::Closed); }
        self.io.preparation = Some((|| {
            let mut temporary = None;
            let mut cleanup = None;
            let opened = location.begin_owned_replacement_retaining_v1::<NativeJournalDataErrorV1>(
                &mut temporary, &mut cleanup, &mut self.io.replacement, &mut self.io.native_open,
            );
            self.io.temporary = temporary.map(TemporaryName::Protected);
            self.io.cleanup = cleanup.map(|debt| OwnedCleanup { location: Arc::clone(location), debt });
            opened?;
            self.io.write_and_install(state)
        })());
        if matches!(self.io.preparation, Some(Ok(()))) { Ok(()) }
        else { Err(CanonicalReplacementErrorV1::Closed) }
    }

    pub(crate) fn prepare_identity_once(&mut self) -> Result<FileIdentity, CanonicalReplacementErrorV1> {
        if self.identity_result.is_some() || !matches!(self.io.preparation, Some(Ok(()))) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let file = self.io.installed.as_ref().ok_or(CanonicalReplacementErrorV1::Closed)?;
        self.identity_result = Some(FileIdentity::of_retaining_v1(file, &mut self.identity));
        if !matches!(self.identity_result, Some(Ok(()))) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let identity = self.identity.completed_identity().copied()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        self.extent = Some(CanonicalReplayExtentDataV1::new(self.io.limits, identity.byte_len()));
        if !matches!(self.extent, Some(Ok(_))) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        Ok(identity)
    }

    pub(crate) fn begin_replay_once(&mut self)
        -> Result<CanonicalIndexedReplayV1<'_, '_>, CanonicalReplacementErrorV1>
    {
        let extent = self.extent.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        let file = self.io.installed.as_ref().ok_or(CanonicalReplacementErrorV1::Closed)?;
        let cursor = self.replay.begin_semantic_cursor_once(file, self.io.limits, extent.native_bytes())?;
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut self.index, &mut self.indexed))
    }

    pub(crate) fn install_once(&mut self, native: &mut NativeJournal<RecordNamespace, JournalLimits>, index: &mut Index)
        -> Result<(), CanonicalReplacementErrorV1>
    {
        if self.taken || !self.indexed.is_complete() { return Err(CanonicalReplacementErrorV1::Closed); }
        let (durable_end, _) = self.replay.report().ok_or(CanonicalReplacementErrorV1::Closed)?;
        self.io.finish(durable_end)?;
        let prefix = self.replay.take_prefix().ok_or(CanonicalReplacementErrorV1::Closed)?;
        let file = self.io.installed.take().ok_or(CanonicalReplacementErrorV1::Closed)?;
        native.replace_replayed_file(file, prefix);
        *index = std::mem::take(&mut self.index);
        self.installed_durable_end = Some(durable_end);
        self.taken = true;
        Ok(())
    }

    pub(crate) fn is_installed(&self) -> bool { self.taken }

    pub(crate) fn retain_boundary_refusal(&mut self) {
        if self.failure().is_none() { self.closed = Some(CanonicalReplacementErrorV1::Closed); }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.io.failure().map(|cause| cause as _)
            .or_else(|| self.identity.failure())
            .or_else(|| self.identity_result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.extent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.replay.failure()).or_else(|| self.indexed.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

/// Keeps the selected replacement in its original once-only permanent sink.
///
/// Only Broker's genuine fixed role owners construct this carrier. It provides
/// no raw File, positive role constructor or caller-supplied replay import.
pub struct CanonicalSelectedReplacementV1<P> {
    storage: SelectedAppendGuardV1<SelectedReplacementBodyV1<P>>,
}

impl<P> CanonicalSelectedReplacementV1<P> {
    pub(crate) fn new(
        sink: Arc<SelectedAppendCustodyV1<SelectedReplacementBodyV1<P>>>,
        limits: JournalLimits,
    ) -> Option<Self> {
        if !sink.enter() { return None; }
        Some(Self { storage: SelectedAppendGuardV1::new(sink, SelectedReplacementBodyV1::new(limits)) })
    }

    pub(crate) fn body_mut(&mut self) -> Option<&mut SelectedReplacementBodyV1<P>> {
        self.storage.body_mut()
    }

    pub(crate) fn has_resident_body(&self) -> bool { self.storage.body().is_some() }

    pub(crate) fn has_custody(
        &self,
        sink: &Arc<SelectedAppendCustodyV1<SelectedReplacementBodyV1<P>>>,
    ) -> bool {
        Arc::ptr_eq(self.storage.custody(), sink)
    }

    /// Copies actual installed durable-end DATA without performing native IO.
    ///
    /// Returns `None` before this same stage installs its replayed prefix. This
    /// comparison value is neither semantic completion nor a role receipt.
    #[must_use]
    pub fn installed_durable_end_v1(&self) -> Option<u64> {
        let body = self.storage.body()?;
        if !body.taken { return None; }
        body.installed_durable_end
    }

    /// Borrows the original physical/parser/index stopping cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.storage.body().and_then(SelectedReplacementBodyV1::failure)
    }

    /// Samples the SAME actual installed replacement before semantic parsing.
    ///
    /// # Errors
    /// Keeps the actual native identity and its partials in this selected body.
    pub fn prepare_identity_once(&mut self) -> Result<FileIdentity, CanonicalReplacementErrorV1> {
        self.body_mut().ok_or(CanonicalReplacementErrorV1::Closed)?.prepare_identity_once()
    }

    /// Borrows the SAME shared canonical/index cursor for the upper semantic loop.
    ///
    /// # Errors
    /// Retains native refusal or rejects incomplete/failed/repeated preparation.
    pub fn begin_replay_once(&mut self)
        -> Result<CanonicalIndexedReplayV1<'_, '_>, CanonicalReplacementErrorV1>
    {
        self.body_mut().ok_or(CanonicalReplacementErrorV1::Closed)?.begin_replay_once()
    }

    pub(crate) fn release_positive(&mut self) -> Result<(), CanonicalReplacementErrorV1> {
        let body = self.storage.body().ok_or(CanonicalReplacementErrorV1::Closed)?;
        if !body.is_installed() || body.failure().is_some() {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let body = self.storage.take_body().ok_or(CanonicalReplacementErrorV1::Closed)?;
        drop(body);
        self.storage.custody().release_active();
        Ok(())
    }

    pub(crate) fn into_failure_original(mut self) -> CanonicalReplacementFailureOriginalV1<P> {
        if let Some(body) = self.storage.body_mut() { body.retain_boundary_refusal(); }
        let original = CanonicalReplacementFailureOriginalV1 { sink: Arc::clone(self.storage.custody()) };
        self.storage.park_unfinished();
        original
    }
}

/// Retains the permanent original of a failed selected replacement.
///
/// The same sink keeps every reached File and cleanup obligation after the
/// returned error drops. Its source borrows the actual parked error in place.
pub struct CanonicalReplacementFailureOriginalV1<P> {
    sink: Arc<SelectedAppendCustodyV1<SelectedReplacementBodyV1<P>>>,
}

impl<P> CanonicalReplacementFailureOriginalV1<P> {
    /// Borrows the actual permanently parked first physical/native cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.sink.parked_body().and_then(SelectedReplacementBodyV1::failure)
    }
}

impl<P> std::fmt::Debug for CanonicalReplacementFailureOriginalV1<P> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("CanonicalReplacementFailureOriginalV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl<P> std::fmt::Display for CanonicalReplacementFailureOriginalV1<P> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("selected replacement original was refused"),
        }
    }
}

impl<P: 'static> std::error::Error for CanonicalReplacementFailureOriginalV1<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}

pub(crate) fn selected_replacement_demand_v1<P>(
    state: &State,
    limits: JournalLimits,
    name: &str,
) -> Result<aos_sandbox_core::ResourceVector, CanonicalReplacementErrorV1> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    let invalid = || CanonicalReplacementErrorV1::Closed;
    let (encoded, extent) = replacement_geometry_v1(state, limits)?;
    // The encoder's actual cloned records, chunk/lookahead and frame backing
    // coexist only with this same held input. Four complete encoded lanes plus
    // actual row/borrowed-row carriers conservatively cover those byte peaks.
    let memory = encoded.checked_mul(4)
        .and_then(|bytes| bytes.checked_add(name.len().checked_add(12)?.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<aos_sandbox_journal::materialized::RecordMutationRef<'_, RecordNamespace>>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<Vec<u8>>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(state.len().checked_mul(
            std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>()
                .checked_add(std::mem::size_of::<aos_sandbox_journal::materialized::RecordMutationRef<'_, RecordNamespace>>())?
                .checked_mul(3)?,
        )?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SelectedReplacementBodyV1<P>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CanonicalSelectedReplacementV1<P>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CanonicalReplacementFailureOriginalV1<P>>().checked_mul(3)?))
        .ok_or_else(invalid)?;
    let fixed = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        // The old file stays held; replacement is closed before reopening.
        .with(D::OpenFiles, 1);
    let index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
        .map_err(|_| CanonicalReplacementErrorV1::Closed)?;
    let native = extent.dominant_native_receiving_demand_v1()?;
    let semantic = extent.dominant_semantic_receiving_demand_v1()?;
    fixed.checked_add(native)
        .and_then(|demand| demand.checked_add(semantic))
        .and_then(|demand| demand.checked_add(index))
        .map_err(|_| CanonicalReplacementErrorV1::Closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::{Read as _, Seek as _};
    use std::os::unix::fs::MetadataExt as _;

    fn state() -> State {
        BTreeMap::from([((RecordNamespace::DesiredState, vec![1]), vec![2, 3])])
    }

    fn native(directory: &Path, limits: JournalLimits) -> NativeJournal<RecordNamespace, JournalLimits> {
        let file = OpenOptions::new().read(true).write(true).create_new(true)
            .open(directory.join("history")).unwrap();
        let lock = OpenOptions::new().read(true).write(true).create_new(true)
            .open(directory.join("history.lock")).unwrap();
        NativeJournal::from_owned_parts(
            directory.join("history"), file, lock, limits,
            NativeJournalState::from_owned_parts(
                1, 0, BTreeSet::new(), BTreeSet::new(), state(), 3,
            ),
        )
    }

    #[test]
    fn ordinary_replacement_uses_the_same_encoder_bytes_and_actual_reopened_file() {
        let directory = tempfile::tempdir().unwrap();
        let mut native = native(directory.path(), JournalLimits::default());
        let mut expected = tempfile::tempfile().unwrap();
        write_compacted_data(&mut expected, native.state(), native.limits()).unwrap();
        expected.rewind().unwrap();
        let mut expected_bytes = Vec::new();
        expected.read_to_end(&mut expected_bytes).unwrap();

        let mut replacement = OrdinaryCoordinatorReplacementV1::<()>::prepare_once(&native, None).unwrap();
        let mut actual = Vec::new();
        replacement.io.installed.as_mut().unwrap().read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected_bytes);
        let mut replay = CanonicalReplayOriginalV1::new();
        let mut index = Index::new();
        let mut indexed = CanonicalReplayIndexOriginalsV1::new();
        let mut seek = None;
        let mut metadata = None;
        replacement.prepare_indexed_parser_once_v1(&mut seek, &mut metadata).unwrap();
        {
            let mut cursor = replacement.begin_indexed_replay_once_v1(
                &mut replay, &mut index, &mut indexed, &mut metadata).unwrap();
            while cursor.advance_once().unwrap() {
                cursor.validate_compaction_once().unwrap();
                cursor.register_and_compare_index_once().unwrap();
                cursor.prepare_change_once().unwrap();
                while cursor.apply_next_record_once().unwrap() {}
                cursor.finish_commit_accounting_once().unwrap();
                cursor.finish_commit_once().unwrap();
            }
        }
        let durable_end = replay.report().unwrap().0;
        assert!(indexed.is_complete());
        assert!(replay.dispose_ordinary_current_once());
        assert!(replay.dispose_ordinary_pending_once());
        let mut installed = replacement.finish_once(durable_end).unwrap();
        let prefix = replay.take_prefix().unwrap();
        installed.install_once(&mut native, prefix).unwrap();

        assert_eq!(native.state(), &state());
        assert_eq!(native.file().metadata().unwrap().ino(),
            std::fs::metadata(directory.path().join("history")).unwrap().ino());
        assert!(!directory.path().join("history.compact.tmp").exists());
        assert!(installed.file.is_none());
    }

    #[test]
    fn selected_size_refusal_keeps_actual_metadata_and_replacement_file() {
        let directory = tempfile::tempdir().unwrap();
        let uid = File::open(directory.path()).unwrap().metadata().unwrap().uid();
        let location = Arc::new(ProtectedJournalLocation::from_original_parts((
            File::open(directory.path()).unwrap(), "history".to_owned(), uid, (),
        )));
        let limits = JournalLimits { maximum_journal_bytes: 1, ..JournalLimits::default() };
        let sink = Arc::new(SelectedAppendCustodyV1::new());
        let mut stage = CanonicalSelectedReplacementV1::new(Arc::clone(&sink), limits).unwrap();
        assert!(stage.body_mut().unwrap().prepare_once(&location, &state()).is_err());
        let body = stage.storage.body().unwrap();
        let metadata = body.io.size_metadata.as_ref().unwrap();
        assert!(metadata.len() > limits.maximum_journal_bytes);
        assert_eq!(metadata.ino(), body.io.replacement.as_ref().unwrap().metadata().unwrap().ino());
        assert!(matches!(body.io.failure(), Some(CanonicalReplacementErrorV1::Native(
            NativeJournalDataErrorV1::JournalTooLarge,
        ))));
        assert!(body.io.installed.is_none());
        let original = stage.into_failure_original();
        assert!(original.failure().is_some());
    }

    #[test]
    fn selected_encoder_refusal_parks_the_actual_file_and_cleanup_with_stable_cause() {
        let directory = tempfile::tempdir().unwrap();
        let uid = File::open(directory.path()).unwrap().metadata().unwrap().uid();
        let location = Arc::new(ProtectedJournalLocation::from_original_parts((
            File::open(directory.path()).unwrap(), "history".to_owned(), uid, (),
        )));
        let limits = JournalLimits { maximum_transactions: 0, ..JournalLimits::default() };
        let sink = Arc::new(SelectedAppendCustodyV1::new());
        let mut stage = CanonicalSelectedReplacementV1::new(Arc::clone(&sink), limits).unwrap();
        assert!(stage.body_mut().unwrap().prepare_once(&location, &state()).is_err());
        let body = stage.storage.body().unwrap();
        let inode = body.io.replacement.as_ref().unwrap().metadata().unwrap().ino();
        let temporary = match body.io.temporary.as_ref().unwrap() {
            TemporaryName::Protected(name) => directory.path().join(name),
            TemporaryName::Unprotected(_) => panic!("selected replacement used ordinary path"),
        };
        let cause = stage.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(stage.prepare_identity_once().is_err());
        assert_eq!(stage.failure().unwrap() as *const dyn std::error::Error as *const (), cause);

        // Parking moves the inline body into its permanent Arc allocation.
        // Its enum address can change; the actual error and file must survive.
        let original = stage.into_failure_original();
        assert!(matches!(original.failure().unwrap()
            .downcast_ref::<CanonicalReplacementErrorV1>(),
            Some(CanonicalReplacementErrorV1::Encode(
                crate::canonical_journal::CanonicalCompactionErrorV1::LimitExceeded(
                    "committed transaction count",
                ),
            ))));
        let parked_cause = original.failure().unwrap()
            as *const dyn std::error::Error as *const ();
        drop(original);
        let parked = sink.parked_body().unwrap();
        assert_eq!(parked.failure().unwrap()
            as *const dyn std::error::Error as *const (), parked_cause);
        assert_eq!(parked.io.replacement.as_ref().unwrap().metadata().unwrap().ino(), inode);
        assert_eq!(std::fs::metadata(&temporary).unwrap().ino(), inode);
        assert!(CanonicalSelectedReplacementV1::new(Arc::clone(&sink), limits).is_none());

        // This tests mechanical DATA custody, without fabricating a role owner.
        // Actual closed role prefixes abort rather than release unresolved debt.
        drop(sink);
        assert!(!temporary.exists());
    }
}

/// Bounds replacement replay from the actual resident rows without encoding.
///
/// This passive geometry shares the exact physical supplier's row/header/batch
/// calculation. It creates no paid extent, writer, replacement or semantic grant.
///
/// # Errors
/// Refuses the same checked row/byte or configured-bound geometry overflow.
pub fn replacement_replay_extent_data_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<CanonicalReplayExtentDataV1, CanonicalReplacementErrorV1> {
    replacement_geometry_v1(state, limits).map(|(_, extent)| extent)
}

fn replacement_geometry_v1(
    state: &State,
    limits: JournalLimits,
) -> Result<(usize, CanonicalReplayExtentDataV1), CanonicalReplacementErrorV1> {
    use aos_sandbox_journal::framing::{HEADER_BYTES, COMMIT_PAYLOAD_BYTES};
    use aos_sandbox_journal::geometry::EncodedRecordLayout;

    let invalid = || CanonicalReplacementErrorV1::Closed;
    // Every completed compaction transaction contains at least one actual row.
    // Charging one BEGIN+COMMIT per actual row bounds every legal batching,
    // without multiplying unrelated configured cardinality and byte maxima.
    let envelope = HEADER_BYTES.checked_mul(2).and_then(|bytes| bytes.checked_add(4))
        .and_then(|bytes| bytes.checked_add(COMMIT_PAYLOAD_BYTES)).ok_or_else(invalid)?;
    let encoded = state.iter().try_fold(0usize, |bytes, ((_, key), value)| {
        let row = EncodedRecordLayout::new(key.len(), Some(value.len()))
            .map_err(NativeJournalDataErrorV1::from)?.payload_bytes;
        bytes.checked_add(HEADER_BYTES).and_then(|bytes| bytes.checked_add(row))
            .and_then(|bytes| bytes.checked_add(envelope)).ok_or_else(invalid)
    })?;
    let replay_bytes = u64::try_from(encoded).map_err(|_| invalid())?
        .min(limits.maximum_journal_bytes);
    let extent = CanonicalReplayExtentDataV1::new(limits, replay_bytes)?;
    Ok((encoded, extent))

}
