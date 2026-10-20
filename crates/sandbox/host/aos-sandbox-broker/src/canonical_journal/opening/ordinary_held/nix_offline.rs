//! Stages the actual ordinary Nix directory, lock and main acquisition.
//!
//! The upper offline job retains its original hardware/approval/label gates.
//! Named operation borrows keep that first actual directory private across the
//! lock-label-before-main frontier. Only this owner's canonical parser/index
//! may produce its completed held bundle; no native parts or Arc enter here.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use aos_sandbox_journal::protected_storage::{
    FileIdentity, OriginalFileMetadataV1, ProtectedFailure, inspect_original_file_metadata,
    open_protected_file_into, validate_protected_fd,
};
use aos_sandbox_journal::recovery::{RecoveryTailError, RecoveryTailMode};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, open_nofollow_child, read_exact_positioned_retaining_cause,
};
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, ResolveFlags, flock};

use super::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1,
    CanonicalOrdinaryOpeningOriginalsV1, OpeningMode,
};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::opening::Configuration;
use crate::canonical_journal::{
    CanonicalReplayOriginalV1, JournalLimits, NativeJournalDataErrorV1, RecoveryReport,
};

/// Preserves the original ordinary Nix native/protected error channels.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalNixOfflineAcquisitionErrorV1<E> {
    /// Owns the original direct openat2, flock or directory-fsync error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Owns the caller's exact existing protected opening/validation error.
    #[error(transparent)]
    Protected(E),
    /// Refuses a missing, repeated or otherwise closed mechanical frontier.
    #[error("ordinary Nix acquisition is closed")]
    Closed,
}

/// Borrows named observations on one actual opening-owned file.
///
/// Its constructor and descriptor stay private. These mechanical operations
/// establish no label, role, currentness, financial allowance or TPM result.
#[derive(Clone, Copy)]
pub struct CanonicalNixOfflineFileOperationsV1<'owner> {
    file: &'owner File,
}

impl CanonicalNixOfflineFileOperationsV1<'_> {
    /// Observes the same metadata length at the upper lock-label frontier.
    ///
    /// # Errors
    /// Preserves the actual metadata I/O error without adding another probe.
    pub fn byte_len(self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Samples the original parser/file identity through its sole projection.
    ///
    /// # Errors
    /// Preserves the caller's existing protected identity error channel.
    pub fn physical_identity<E: ProtectedFailure>(self) -> Result<FileIdentity, E> {
        FileIdentity::of::<E>(self.file)
    }

    /// Observes the actual original file's complete metadata DATA.
    ///
    /// # Errors
    /// Preserves the original metadata error without changing custody.
    pub fn identity(self) -> io::Result<OriginalFileMetadataV1> {
        inspect_original_file_metadata(self.file)
    }

    /// Observes the actual original Linux mount identity.
    ///
    /// # Errors
    /// Preserves the original kernel mount inspection failure.
    pub fn mount_id(self) -> Result<MountId, aos_sandbox_linux::Error> {
        MountId::from_fd(self.file.as_fd())
    }

    /// Reads the original file's attribute for the unchanged upper predicate.
    ///
    /// # Errors
    /// Preserves the original xattr errno and returned extent.
    pub fn xattr(self, name: &str, bytes: &mut [u8]) -> Result<usize, rustix::io::Errno> {
        rustix::fs::fgetxattr(self.file, name, bytes)
    }

    /// Reads exact bytes from this same retained original without moving its offset.
    ///
    /// # Errors
    /// Preserves the existing positioned-reader failure and reached extent.
    pub fn read_exact_positioned(self, bytes: &mut [u8]) -> Result<(), ExactReadFailure> {
        read_exact_positioned_retaining_cause(self.file, bytes)
    }
}

/// Borrows only named primitives on the same first actual Nix directory.
#[derive(Clone, Copy)]
pub struct CanonicalNixOfflineDirectoryOperationsV1<'owner> {
    file: &'owner File,
}

impl<'owner> CanonicalNixOfflineDirectoryOperationsV1<'owner> {
    /// Borrows the same directory's observation primitives without a descriptor.
    #[must_use]
    pub fn observations(self) -> CanonicalNixOfflineFileOperationsV1<'owner> {
        CanonicalNixOfflineFileOperationsV1 { file: self.file }
    }

    /// Opens the original sidefile through the existing nofollow primitive.
    ///
    /// # Errors
    /// Preserves the original openat2 errno and creates no semantic admission.
    pub fn open_child(self, name: &str) -> Result<OwnedFd, rustix::io::Errno> {
        open_nofollow_child(self.file, name)
    }

    /// Opens an existing UID-zero protected sidefile into its actual output slot.
    ///
    /// # Errors
    /// Preserves the existing native open/validation error and reached file.
    pub fn open_original<E: ProtectedFailure>(
        self,
        name: &str,
        output: &mut Option<File>,
    ) -> Result<(), E> {
        open_protected_file_into::<E>(self.file, name, 0, false, false, false, output)
    }
}

/// Owns the ordinary Nix opener's actual staged directory, lock and main.
///
/// Its early captured identity replaces the old Job allocation. The actual
/// offline allocation policy and every upper origin/approval gate stay upper.
pub struct CanonicalOrdinaryNixOfflineOpeningV1<I> {
    original: CanonicalOrdinaryOpeningOriginalsV1<I>,
    directory_entered: bool,
    lock_entered: bool,
    main_entered: bool,
    initialize: Option<bool>,
    initial_identity: Option<FileIdentity>,
    parser_identity: Option<FileIdentity>,
    replay_disposed: bool,
}

impl<I> CanonicalOrdinaryNixOfflineOpeningV1<I> {
    /// Allocates the one original comparison identity before native acquisition.
    ///
    /// The returned alias shares that allocation and preserves the upper Job's
    /// original authority field/drop position. No Arc or successful owner is
    /// supplied to this constructor; all native destinations remain inert.
    #[must_use]
    pub fn new_with_captured_payload_v1(payload: I) -> (Self, CanonicalJournalInstanceDataV1<I>) {
        let instance = CanonicalJournalInstanceDataV1::from_payload(payload);
        let alias = instance.clone();
        let mut original = CanonicalOrdinaryOpeningOriginalsV1::new_for_capture_payload_v1();
        original.instance = Some(instance);
        (
            Self {
                original,
                directory_entered: false,
                lock_entered: false,
                main_entered: false,
                initialize: None,
                initial_identity: None,
                parser_identity: None,
                replay_disposed: false,
            },
            alias,
        )
    }

    /// Borrows the same first actual directory across upper label/approval checks.
    #[must_use]
    pub fn directory_operations_v1(&self) -> Option<CanonicalNixOfflineDirectoryOperationsV1<'_>> {
        Some(CanonicalNixOfflineDirectoryOperationsV1 {
            file: self.original.native.directory.as_ref()?,
        })
    }

    /// Borrows actual lock observations before the main file can be opened.
    #[must_use]
    pub fn lock_operations_v1(&self) -> Option<CanonicalNixOfflineFileOperationsV1<'_>> {
        Some(CanonicalNixOfflineFileOperationsV1 {
            file: self.original.native.lock.as_ref()?,
        })
    }

    /// Borrows the actual main file's named observation and positioned-read primitives.
    #[must_use]
    pub fn file_operations_v1(&self) -> Option<CanonicalNixOfflineFileOperationsV1<'_>> {
        Some(CanonicalNixOfflineFileOperationsV1 {
            file: self.original.native.file.as_ref()?,
        })
    }

    fn refuse<E: ProtectedFailure, T>(&mut self) -> Result<T, E> {
        self.original
            .closed
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        Err(E::BOUNDARY)
    }

    fn refuse_acquisition<E, T>(&mut self) -> Result<T, CanonicalNixOfflineAcquisitionErrorV1<E>> {
        self.original
            .closed
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        Err(CanonicalNixOfflineAcquisitionErrorV1::Closed)
    }

    /// Opens and retains the first actual directory before upper label checks.
    ///
    /// Limit validation remains at its original later upper frontier. This
    /// performs the old CWD/openat2/FD validation schedule, not rooted reopening.
    ///
    /// # Errors
    /// Returns the exact original native or protected validation error. The
    /// upper Job owns that typed first cause; this owner keeps reached files.
    pub fn prepare_directory_once_v1<E: ProtectedFailure>(
        &mut self,
        root: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<(), CanonicalNixOfflineAcquisitionErrorV1<E>> {
        if self.directory_entered || self.original.mode.is_some() || self.original.closed.is_some()
        {
            return self.refuse_acquisition();
        }
        self.directory_entered = true;
        self.original.mode = Some(OpeningMode::Ordinary);
        let native = &mut self.original.native;
        native.attempted = true;
        native.ordinary = true;
        native.configuration = Some(Configuration {
            // Preserve the original Nix Journal's relative pathname DATA.
            path: name.into(),
            name: name.to_owned(),
            limits,
            uid,
        });
        let result = (|| {
            native.directory = Some(File::from(
                rustix::fs::openat2(
                    rustix::fs::CWD,
                    root,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|error| {
                    CanonicalNixOfflineAcquisitionErrorV1::Io(io::Error::from(error))
                })?,
            ));
            validate_protected_fd::<E>(
                native
                    .directory
                    .as_ref()
                    .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?,
                uid,
                FileType::Directory,
                Mode::RWXU,
            )
            .map_err(CanonicalNixOfflineAcquisitionErrorV1::Protected)
        })();
        if result.is_err() {
            self.original
                .closed
                .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        result
    }

    /// Opens and claims the actual lock before the upper lock-label gap.
    ///
    /// Initialization preserves exclusive-new creation. Recovery opens only an
    /// existing file. The mode cannot change before later main acquisition.
    ///
    /// # Errors
    /// Returns original protected-open or flock errno through the caller's E;
    /// all reached originals stay resident and repeat entry is fenced.
    pub fn prepare_lock_once_v1<E: ProtectedFailure>(
        &mut self,
        lock_name: &str,
        initialize: bool,
    ) -> Result<(), CanonicalNixOfflineAcquisitionErrorV1<E>> {
        if !self.directory_entered || self.lock_entered || self.original.closed.is_some() {
            return self.refuse_acquisition();
        }
        self.lock_entered = true;
        self.initialize = Some(initialize);
        let native = &mut self.original.native;
        let result = (|| {
            let configuration = native
                .configuration
                .as_ref()
                .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?;
            if lock_name.strip_suffix(".lock") != Some(configuration.name.as_str()) {
                return Err(CanonicalNixOfflineAcquisitionErrorV1::Closed);
            }
            let directory = native
                .directory
                .as_ref()
                .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?;
            open_protected_file_into::<E>(
                directory,
                lock_name,
                configuration.uid,
                initialize,
                initialize,
                false,
                &mut native.lock,
            )
            .map_err(CanonicalNixOfflineAcquisitionErrorV1::Protected)?;
            flock(
                native
                    .lock
                    .as_ref()
                    .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?,
                FlockOperation::NonBlockingLockExclusive,
            )
            .map_err(|error| CanonicalNixOfflineAcquisitionErrorV1::Io(io::Error::from(error)))
        })();
        if result.is_err() {
            self.original
                .closed
                .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        result
    }

    /// Opens the main only after the caller's original lock metadata/label checks.
    ///
    /// The actual initialization mode selected for the lock governs the main
    /// as well. The original initialization directory fsync remains here.
    ///
    /// # Errors
    /// Preserves original protected-open/fsync failure and every reached file.
    pub fn prepare_main_once_v1<E: ProtectedFailure>(
        &mut self,
    ) -> Result<(), CanonicalNixOfflineAcquisitionErrorV1<E>> {
        if !self.lock_entered || self.main_entered || self.original.closed.is_some() {
            return self.refuse_acquisition();
        }
        self.main_entered = true;
        let initialize = self
            .initialize
            .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?;
        let native = &mut self.original.native;
        let result = (|| {
            let configuration = native
                .configuration
                .as_ref()
                .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?;
            let directory = native
                .directory
                .as_ref()
                .ok_or(CanonicalNixOfflineAcquisitionErrorV1::Closed)?;
            open_protected_file_into::<E>(
                directory,
                &configuration.name,
                configuration.uid,
                initialize,
                initialize,
                false,
                &mut native.file,
            )
            .map_err(CanonicalNixOfflineAcquisitionErrorV1::Protected)?;
            if initialize {
                rustix::fs::fsync(directory).map_err(|error| {
                    CanonicalNixOfflineAcquisitionErrorV1::Io(io::Error::from(error))
                })?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.original
                .closed
                .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        result
    }

    /// Samples the old initial physical identity and retains that actual metadata.
    ///
    /// The canonical positional parser reuses this Metadata comparison value;
    /// its distinct old parser-identity sample remains a separate later call.
    ///
    /// # Errors
    /// Preserves the original metadata error and refuses absent/repeated entry.
    pub fn capture_initial_identity_once_v1<E: ProtectedFailure>(
        &mut self,
    ) -> Result<FileIdentity, E> {
        if !self.main_entered || self.initial_identity.is_some() || self.original.closed.is_some() {
            return self.refuse();
        }
        let native = &mut self.original.native;
        let metadata = match native.file.as_ref().ok_or(E::BOUNDARY)?.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                self.original
                    .closed
                    .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
                return Err(E::from(error));
            }
        };
        let identity = FileIdentity::from_metadata_data_v1(&metadata);
        native.metadata = Some(Ok(metadata));
        native.preparation = Some(Ok(()));
        native.recovery_started = true;
        self.initial_identity = Some(identity);
        Ok(identity)
    }

    /// Samples the one old parser identity at its original post-byte-read frontier.
    ///
    /// # Errors
    /// Preserves the actual metadata failure and refuses repeated entry.
    pub fn sample_parser_identity_once_v1<E: ProtectedFailure>(
        &mut self,
    ) -> Result<FileIdentity, E> {
        if self.initial_identity.is_none()
            || self.parser_identity.is_some()
            || self.original.closed.is_some()
        {
            return self.refuse();
        }
        let result = FileIdentity::of::<E>(self.original.native.file.as_ref().ok_or(E::BOUNDARY)?);
        match result {
            Ok(identity) => {
                self.parser_identity = Some(identity);
                Ok(identity)
            }
            Err(error) => {
                self.original
                    .closed
                    .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
                Err(error)
            }
        }
    }

    /// Lends the positional ordinary canonical parser with its private index once.
    ///
    /// No seek or native metadata observation is added. The upper uses its
    /// original finite Nix history observer beside this same staged parser.
    ///
    /// # Errors
    /// Preserves original canonical preparation/index failure and rejects reentry.
    pub fn begin_indexed_replay_once_v1(
        &mut self,
    ) -> Result<CanonicalIndexedReplayV1<'_, '_>, NativeJournalDataErrorV1> {
        if self.parser_identity.is_none()
            || self.original.replay_started
            || self.original.closed.is_some()
        {
            return self.refuse();
        }
        self.original.replay_started = true;
        let native = &mut self.original.native;
        let limits = native
            .configuration
            .as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .limits;
        let metadata = match native.metadata.take() {
            Some(Ok(metadata)) => metadata,
            other => {
                native.metadata = other;
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
        };
        let file = native
            .file
            .as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let cursor = native
            .replay
            .begin_ordinary_semantic_cursor_with_metadata_once(file, limits, metadata)?;
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut self.original.index,
            &mut self.original.index_originals,
        ))
    }

    /// Borrows only the same canonical replay reservoir's immutable DATA.
    #[must_use]
    pub fn replay_data_v1(&self) -> &CanonicalReplayOriginalV1 {
        &self.original.native.replay
    }

    /// Reports an actual parser/index refusal for upper ordinary error selection.
    #[must_use]
    pub fn replay_failed_v1(&self) -> bool {
        self.original.native.replay.failure().is_some()
            || self.original.index_originals.failure().is_some()
    }

    /// Copies completed coordinates from this same indexed canonical prefix.
    ///
    /// # Errors
    /// Refuses incomplete canonical EOF/index or an earlier order refusal.
    pub fn completed_coordinates_v1(
        &self,
    ) -> Result<aos_sandbox_journal::replay::NativeReplayCoordinates, NativeJournalDataErrorV1>
    {
        if self.original.closed.is_some()
            || !self.original.index_originals.is_complete()
            || self.original.native.replay.report().is_none()
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        Ok(self
            .original
            .native
            .replay
            .work
            .as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .native
            .coordinates())
    }

    /// Retires ordinary current parser locals before the upper semantic scratch.
    ///
    /// # Errors
    /// Refuses an out-of-order or repeated disposition.
    pub fn dispose_ordinary_current_once_v1(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        self.original.dispose_ordinary_current_once_v1()
    }

    /// Retires ordinary pending parser locals after the upper semantic scratch.
    ///
    /// # Errors
    /// Refuses an out-of-order or repeated disposition.
    pub fn dispose_ordinary_pending_once_v1(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        self.original.dispose_ordinary_pending_once_v1()
    }

    /// Moves ordinary replay causes while retaining actual directory/lock/file custody.
    ///
    /// Only temporary parser/index/model DATA is disposed. The actual Job's
    /// first-error cell takes the returned cause and retains this whole owner.
    ///
    /// # Errors
    /// Refuses extraction before current/upper/pending disposal or on reentry.
    pub fn take_ordinary_replay_errors_once_v1(
        &mut self,
    ) -> Result<
        (
            Option<IdempotencyRecordDataErrorV1>,
            Option<NativeJournalDataErrorV1>,
        ),
        NativeJournalDataErrorV1,
    > {
        if self.replay_disposed || self.original.ordinary_disposition != 2 {
            return self.refuse();
        }
        self.replay_disposed = true;
        let indexed = std::mem::replace(
            &mut self.original.index_originals,
            CanonicalReplayIndexOriginalsV1::new(),
        )
        .into_ordinary_error();
        drop(std::mem::take(&mut self.original.index));
        let native = std::mem::replace(
            &mut self.original.native.replay,
            CanonicalReplayOriginalV1::new(),
        )
        .into_ordinary_error();
        self.original
            .closed
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        Ok((indexed, native))
    }

    /// Performs the original final rejecting tail/seek frontier after upper checks.
    ///
    /// No new metadata observation or tail repair is inserted. The ordinary
    /// tail engine returns its actual seek failure to the original Job cell.
    ///
    /// # Errors
    /// Preserves the whole original tail/seek error or incomplete-stage refusal.
    pub fn finish_tail_once_v1(&mut self) -> Result<(), RecoveryTailError> {
        if self
            .original
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .is_ok()
        {
            return Ok(());
        }
        let cause = self
            .original
            .native
            .tail
            .take()
            .and_then(Result::err)
            .unwrap_or(RecoveryTailError::RetainedNativeFailure);
        self.original
            .closed
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        Err(cause)
    }

    /// Moves this actual completed native/index bundle with its SAME early marker.
    ///
    /// The actual upper Job first completes its labels, full semantic/history,
    /// EOF/hash and independent physical postchecks. No late marker is allocated.
    #[must_use]
    pub fn take_held_once_v1<P>(
        &mut self,
        selection: P,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)> {
        self.original
            .take_held_with_captured_instance_once_v1(selection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;

    fn directory(path: &Path) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn prepare_directory(opening: &mut CanonicalOrdinaryNixOfflineOpeningV1<()>, path: &Path) {
        opening
            .prepare_directory_once_v1::<NativeJournalDataErrorV1>(
                path,
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
            )
            .unwrap();
    }

    #[test]
    fn original_directory_survives_upper_gap_and_same_early_marker_moves_to_held() {
        let scratch = tempfile::tempdir().unwrap();
        let first = scratch.path().join("first");
        let parked = scratch.path().join("parked");
        directory(&first);
        let (mut opening, marker) =
            CanonicalOrdinaryNixOfflineOpeningV1::new_with_captured_payload_v1(());
        assert_eq!(Arc::strong_count(marker.comparison_arc_v1()), 2);
        assert!(opening.directory_operations_v1().is_none());
        prepare_directory(&mut opening, &first);
        let original_directory = opening
            .directory_operations_v1()
            .unwrap()
            .observations()
            .identity()
            .unwrap();
        opening
            .prepare_lock_once_v1::<NativeJournalDataErrorV1>("history.lock", true)
            .unwrap();
        assert_eq!(opening.lock_operations_v1().unwrap().byte_len().unwrap(), 0);
        assert!(opening.file_operations_v1().is_none());

        // The real upper label/approval gap must not permit rooted reopening.
        std::fs::rename(&first, &parked).unwrap();
        directory(&first);
        opening
            .prepare_main_once_v1::<NativeJournalDataErrorV1>()
            .unwrap();
        assert!(!first.join("history").exists());
        assert!(parked.join("history").exists());
        assert_eq!(
            opening
                .directory_operations_v1()
                .unwrap()
                .observations()
                .identity()
                .unwrap(),
            original_directory
        );

        let physical = opening
            .capture_initial_identity_once_v1::<NativeJournalDataErrorV1>()
            .unwrap();
        assert!(
            opening
                .sample_parser_identity_once_v1::<NativeJournalDataErrorV1>()
                .unwrap()
                == physical
        );
        {
            let mut cursor = opening.begin_indexed_replay_once_v1().unwrap();
            assert!(!cursor.advance_once().unwrap());
        }
        assert_eq!(opening.completed_coordinates_v1().unwrap().durable_end, 0);
        opening.dispose_ordinary_current_once_v1().unwrap();
        opening.dispose_ordinary_pending_once_v1().unwrap();
        opening.finish_tail_once_v1().unwrap();
        let (held, report) = opening.take_held_once_v1(()).unwrap();
        assert_eq!(report.committed_transactions, 0);
        assert!(held.instance_data_v1().unwrap().same_original_v1(&marker));
        assert!(!held.is_read_only_v1());
        assert!(opening.take_held_once_v1(()).is_none());
    }

    #[test]
    fn exclusive_initial_lock_collision_keeps_directory_and_never_opens_main() {
        let scratch = tempfile::tempdir().unwrap();
        let first = scratch.path().join("first");
        directory(&first);
        File::create(first.join("history.lock")).unwrap();
        let (mut opening, _) =
            CanonicalOrdinaryNixOfflineOpeningV1::new_with_captured_payload_v1(());
        prepare_directory(&mut opening, &first);

        assert!(matches!(
            opening.prepare_lock_once_v1::<NativeJournalDataErrorV1>("history.lock", true),
            Err(CanonicalNixOfflineAcquisitionErrorV1::Protected(_))
        ));
        assert!(opening.directory_operations_v1().is_some());
        assert!(opening.file_operations_v1().is_none());
        assert!(
            opening
                .prepare_main_once_v1::<NativeJournalDataErrorV1>()
                .is_err()
        );
        assert!(!first.join("history").exists());
    }

    #[test]
    fn premature_main_refusal_cannot_later_enter_native_directory_acquisition() {
        let scratch = tempfile::tempdir().unwrap();
        let first = scratch.path().join("first");
        directory(&first);
        let (mut opening, _) =
            CanonicalOrdinaryNixOfflineOpeningV1::new_with_captured_payload_v1(());

        assert!(
            opening
                .prepare_main_once_v1::<NativeJournalDataErrorV1>()
                .is_err()
        );
        assert!(
            opening
                .prepare_directory_once_v1::<NativeJournalDataErrorV1>(
                    &first,
                    "history",
                    JournalLimits::default(),
                    rustix::process::geteuid().as_raw(),
                )
                .is_err()
        );
        assert!(opening.directory_operations_v1().is_none());
        assert!(opening.take_held_once_v1(()).is_none());
    }

    #[test]
    fn completed_models_can_retire_after_later_upper_refusal_without_closing_originals() {
        use std::io::Write as _;
        use aos_sandbox_protocol::domain_ledger::transaction::{
            JournalRecord, JournalTransaction, encode_transaction,
        };

        let scratch = tempfile::tempdir().unwrap();
        let first = scratch.path().join("first");
        directory(&first);
        let (mut opening, _) =
            CanonicalOrdinaryNixOfflineOpeningV1::new_with_captured_payload_v1(());
        prepare_directory(&mut opening, &first);
        opening.prepare_lock_once_v1::<NativeJournalDataErrorV1>("history.lock", true).unwrap();
        opening.prepare_main_once_v1::<NativeJournalDataErrorV1>().unwrap();
        let transaction = JournalTransaction::new([3; 16], vec![JournalRecord::put(
            aos_sandbox_model::RecordNamespace::DesiredState, b"key".to_vec(), b"value".to_vec(),
        )]).unwrap();
        for frame in encode_transaction(&transaction, 1).unwrap() {
            opening.original.native.file.as_mut().unwrap().write_all(&frame).unwrap();
        }
        let physical = opening.capture_initial_identity_once_v1::<NativeJournalDataErrorV1>().unwrap();
        opening.sample_parser_identity_once_v1::<NativeJournalDataErrorV1>().unwrap();
        {
            let mut cursor = opening.begin_indexed_replay_once_v1().unwrap();
            while cursor.advance_once().unwrap() {
                cursor.validate_compaction_once().unwrap();
                cursor.register_and_compare_index_once().unwrap();
                cursor.prepare_change_once().unwrap();
                while cursor.apply_next_record_once().unwrap() {}
                cursor.finish_commit_accounting_once().unwrap();
                cursor.finish_commit_once().unwrap();
            }
        }
        assert_eq!(opening.replay_data_v1().state().unwrap().len(), 1);
        opening.dispose_ordinary_current_once_v1().unwrap();
        opening.dispose_ordinary_pending_once_v1().unwrap();

        // A real later upper denial drops only the old local replay models.
        let (index, native) = opening.take_ordinary_replay_errors_once_v1().unwrap();
        assert!(index.is_none() && native.is_none());
        assert!(opening.replay_data_v1().state().is_none());
        assert!(opening.directory_operations_v1().is_some());
        assert!(opening.lock_operations_v1().is_some());
        assert!(opening.file_operations_v1().unwrap()
            .physical_identity::<NativeJournalDataErrorV1>().unwrap() == physical);
        assert!(opening.take_held_once_v1(()).is_none());
    }

    #[test]
    fn incomplete_original_tail_refuses_without_repair_or_native_loss() {
        let scratch = tempfile::tempdir().unwrap();
        let first = scratch.path().join("first");
        directory(&first);
        std::fs::write(first.join("history"), b"bad").unwrap();
        std::fs::write(first.join("history.lock"), b"").unwrap();
        for name in ["history", "history.lock"] {
            std::fs::set_permissions(first.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let (mut opening, _) =
            CanonicalOrdinaryNixOfflineOpeningV1::new_with_captured_payload_v1(());
        prepare_directory(&mut opening, &first);
        opening
            .prepare_lock_once_v1::<NativeJournalDataErrorV1>("history.lock", false)
            .unwrap();
        opening
            .prepare_main_once_v1::<NativeJournalDataErrorV1>()
            .unwrap();
        let physical = opening
            .capture_initial_identity_once_v1::<NativeJournalDataErrorV1>()
            .unwrap();
        opening
            .sample_parser_identity_once_v1::<NativeJournalDataErrorV1>()
            .unwrap();
        {
            let mut cursor = opening.begin_indexed_replay_once_v1().unwrap();
            assert!(!cursor.advance_once().unwrap());
        }
        assert_eq!(physical.byte_len(), 3);
        assert_eq!(opening.completed_coordinates_v1().unwrap().durable_end, 0);
        opening.dispose_ordinary_current_once_v1().unwrap();
        opening.dispose_ordinary_pending_once_v1().unwrap();

        assert!(matches!(
            opening.finish_tail_once_v1(),
            Err(RecoveryTailError::UncommittedTail)
        ));
        assert_eq!(opening.file_operations_v1().unwrap().byte_len().unwrap(), 3);
        assert!(opening.take_held_once_v1(()).is_none());
        assert_eq!(std::fs::read(first.join("history")).unwrap(), b"bad");
    }
}
