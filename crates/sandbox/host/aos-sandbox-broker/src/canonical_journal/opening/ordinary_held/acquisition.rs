//! Acquires supported ordinary storage into the same private parser originals.
//!
//! No method accepts a File, native state, resident map, Arc or successful replay.
//! Ordinary unprotected policy remains the caller's existing allocation policy;
//! protected role admission and all selected native financial owners stay upper.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

use super::{CanonicalOrdinaryOpeningOriginalsV1, OpeningMode};
use crate::canonical_journal::opening::Configuration;
use crate::canonical_journal::{JournalLimits, NativeJournalDataErrorV1};

impl<C> CanonicalOrdinaryOpeningOriginalsV1<C> {
    /// Acquires an explicit test fixture through the original no-follow recipe.
    ///
    /// This retains the existing fixture-only omission of root ancestry. Its
    /// final directory, owner/mode, lock and data checks remain the same body
    /// as production, and no supplied native or successful DATA enters here.
    ///
    /// # Errors
    /// Retains the actual acquisition/metadata failure; reentry performs no IO.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn prepare_fixture_ordinary_once_v1(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.prepare_fixture_once_v1(
            path, name, limits, uid, allow_create, OpeningMode::Ordinary,
        )
    }

    /// Acquires a real fixture with retained parser and native error custody.
    ///
    /// Only the existing fixture gate omits root ancestry. Final ownership,
    /// mode, no-follow resolution, locks and file checks remain unchanged.
    ///
    /// # Errors
    /// Retains actual acquisition causes; reentry performs no additional IO.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn prepare_fixture_retaining_once_v1(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.prepare_fixture_once_v1(
            path, name, limits, uid, allow_create, OpeningMode::Retained,
        )
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn prepare_fixture_once_v1(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
        mode: OpeningMode,
    ) -> Result<(), NativeJournalDataErrorV1> {
        use aos_sandbox_journal::protected_storage::{
            WriterAcquisitionRetentionV1, WriterAcquisitionSlotsV1,
            acquire_writer_fixture_originals_ordinary_v1,
            acquire_writer_fixture_originals_retaining_v1,
        };

        self.begin_mode(mode)?;
        let native = &mut self.native;
        if native.attempted {
            return Err(native.refuse_order());
        }
        native.attempted = true;
        native.ordinary = mode == OpeningMode::Ordinary;
        native.preparation = Some((|| {
            let slots = WriterAcquisitionSlotsV1 {
                ancestors: &mut native.ancestors,
                directory: &mut native.directory,
                lock: &mut native.lock,
                file: &mut native.file,
                lock_open: &mut native.lock_open,
                lock_claim: &mut native.lock_claim,
                compaction: &mut native.compaction,
                file_open: &mut native.file_open,
                directory_sync: &mut native.directory_sync,
            };
            match mode {
                OpeningMode::Ordinary => acquire_writer_fixture_originals_ordinary_v1(
                    slots, path, name, limits.into(), uid, allow_create,
                    NativeJournalDataErrorV1::AlreadyLocked, &mut native.ordinary_lock_name,
                )?,
                OpeningMode::Retained => acquire_writer_fixture_originals_retaining_v1(
                    slots, path, name, limits.into(), uid, allow_create,
                    NativeJournalDataErrorV1::AlreadyLocked,
                    Some(WriterAcquisitionRetentionV1 {
                        directory_error: &mut native.directory_error,
                        directory_native_error: &mut native.directory_native_error,
                        lock_native_error: &mut native.lock_native_error,
                        lock_claim_native_error: &mut native.lock_claim_native_error,
                        file_native_error: &mut native.file_native_error,
                    }),
                )?,
            }
            native.record_prepared_configuration(path, name, limits, uid)
        })());
        if matches!(native.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    /// Opens the actual ordinary path and its original sibling lock once.
    ///
    /// This preserves the supported unprotected allocation/opening policy. It
    /// does not resolve a protected directory, create a role or supply funding.
    /// The same canonical indexed cursor, tail engine and private completed
    /// bundle subsequently own replay and transfer. No external parts enter.
    ///
    /// # Errors
    /// Retains original bounds, lock/open/flock/parent-sync or metadata failure;
    /// reentry refuses before additional IO. Ordinary extraction preserves the
    /// actual cause after the caller's original semantic/local disposal order.
    pub fn prepare_unprotected_ordinary_once_v1(
        &mut self,
        path: &Path,
        limits: JournalLimits,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.begin_mode(OpeningMode::Ordinary)?;
        let native = &mut self.native;
        if native.attempted {
            return Err(native.refuse_order());
        }
        native.attempted = true;
        native.ordinary = true;
        native.preparation = Some((|| {
            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())?;
            let path = path.to_path_buf();
            let mut lock_name = path.as_os_str().to_os_string();
            lock_name.push(".lock");
            native.configuration = Some(Configuration {
                path,
                name: String::new(),
                limits,
                uid: 0,
            });
            native.lock_open = Some((|| {
                let lock = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(PathBuf::from(lock_name))?;
                native.lock = Some(lock);
                Ok(())
            })());
            if !matches!(native.lock_open, Some(Ok(()))) {
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
            native.lock_claim = Some(
                flock(
                    native
                        .lock
                        .as_ref()
                        .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?,
                    FlockOperation::NonBlockingLockExclusive,
                )
                .map_err(|error| {
                    if error == rustix::io::Errno::WOULDBLOCK {
                        NativeJournalDataErrorV1::AlreadyLocked
                    } else {
                        NativeJournalDataErrorV1::Io(io::Error::from_raw_os_error(
                            error.raw_os_error(),
                        ))
                    }
                }),
            );
            if !matches!(native.lock_claim, Some(Ok(()))) {
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
            let path = &native
                .configuration
                .as_ref()
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
                .path;
            let existed = path.exists();
            native.file_open = Some((|| {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)?;
                native.file = Some(file);
                Ok(())
            })());
            if !matches!(native.file_open, Some(Ok(()))) {
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
            if !existed {
                native.directory_sync = Some((|| {
                    let parent = path.parent().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "journal path has no parent directory",
                        )
                    })?;
                    File::open(parent)?.sync_all()?;
                    Ok(())
                })());
                if !matches!(native.directory_sync, Some(Ok(()))) {
                    return Err(NativeJournalDataErrorV1::ProtectedBoundary);
                }
            }
            native.recovery_started = true;
            native.metadata = Some(
                native
                    .file
                    .as_ref()
                    .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
                    .metadata(),
            );
            let length = native
                .metadata
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
                .len();
            if length > limits.maximum_journal_bytes {
                return Err(NativeJournalDataErrorV1::JournalTooLarge);
            }
            Ok(())
        })());
        if matches!(native.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::finish_replay;
    use super::*;
    use aos_sandbox_journal::recovery::RecoveryTailMode;

    #[test]
    fn fixture_reuses_actual_protected_files_and_keeps_existing_only_refusal() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_fixture_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                uid,
                true,
            )
            .unwrap();
        finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, _) = opening.take_held_without_instance_once_v1(()).unwrap();

        assert!(held.read_view_v1().is_protected());
        assert!(held.instance_data_v1().is_none());
        assert_eq!(
            std::fs::metadata(directory.path().join("history"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let mut competing = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            competing
                .prepare_fixture_ordinary_once_v1(
                    directory.path(),
                    "history",
                    JournalLimits::default(),
                    uid,
                    false,
                )
                .is_err()
        );
        assert!(matches!(
            competing.native.lock_claim,
            Some(Err(NativeJournalDataErrorV1::AlreadyLocked))
        ));
        drop(competing);
        drop(held);

        std::fs::remove_file(directory.path().join("history.lock")).unwrap();
        let mut missing = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            missing
                .prepare_fixture_ordinary_once_v1(
                    directory.path(),
                    "history",
                    JournalLimits::default(),
                    uid,
                    false,
                )
                .is_err()
        );
        assert!(std::fs::metadata(directory.path().join("history.lock")).is_err());
        assert!(missing.native.file.is_none());
    }

    #[test]
    fn retained_fixture_keeps_parser_cause_and_owed_post_without_ordinary_disposal() {
        use std::error::Error;
        use std::os::unix::fs::PermissionsExt as _;
        use aos_sandbox_journal::framing::{FrameError, HEADER_BYTES};
        use aos_sandbox_journal::protected_storage::CapturedReplayPrefixPostV1;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = [0; HEADER_BYTES];
        for (name, contents) in [("history", bytes.as_slice()), ("history.lock", &[][..])] {
            let path = directory.path().join(name);
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening.prepare_fixture_retaining_once_v1(
            directory.path(), "history", JournalLimits::default(),
            rustix::process::geteuid().as_raw(), false,
        ).unwrap();
        opening.prepare_parser_identity_once_v1().unwrap();

        {
            let mut cursor = opening.begin_captured_replay_with_parser_metadata_once_v1().unwrap();
            assert!(cursor.advance_once().is_err());
        }

        assert!(matches!(
            opening.native_failure_v1().unwrap().downcast_ref::<NativeJournalDataErrorV1>(),
            Some(NativeJournalDataErrorV1::Frame(FrameError::MalformedTransaction(
                "invalid frame magic",
            )))
        ));
        let first = opening.native_failure_v1().unwrap() as *const dyn Error;
        let mut post: Option<CapturedReplayPrefixPostV1<NativeJournalDataErrorV1>> = None;
        opening.observe_captured_prefix_post_once_v1(&mut post).unwrap();
        assert!(post.as_ref().unwrap().metadata_result().is_ok());
        assert!(post.as_ref().unwrap().comparison_result().is_ok());
        assert!(opening.dispose_ordinary_current_once_v1().is_err());
        assert!(std::ptr::eq(first, opening.native_failure_v1().unwrap() as *const _));
        assert_eq!(std::fs::read(directory.path().join("history")).unwrap(), bytes);
    }

    #[test]
    fn fixture_refuses_a_nonprivate_directory_and_a_symlink() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mut unsafe_mode = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            unsafe_mode
                .prepare_fixture_ordinary_once_v1(
                    directory.path(),
                    "history",
                    JournalLimits::default(),
                    uid,
                    true,
                )
                .is_err()
        );
        assert!(unsafe_mode.native.lock.is_none());

        let parent = tempfile::tempdir().unwrap();
        let link = parent.path().join("linked");
        symlink(directory.path(), &link).unwrap();
        let mut linked = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            linked
                .prepare_fixture_ordinary_once_v1(
                    &link,
                    "history",
                    JournalLimits::default(),
                    uid,
                    true,
                )
                .is_err()
        );
        assert!(linked.native.directory.is_none());
    }

    #[test]
    fn real_unprotected_open_retains_its_lock_and_allocates_no_instance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
            .unwrap();
        finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RepairIncomplete)
            .unwrap();
        let (held, report) = opening.take_held_without_instance_once_v1(()).unwrap();

        assert!(!held.read_view_v1().is_protected());
        assert!(!held.is_read_only_v1());
        assert!(held.instance_data_v1().is_none());
        assert_eq!(held.read_view_v1().next_sequence(), 1);
        assert_eq!(report.committed_transactions, 0);

        let mut competing = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            competing
                .prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
                .is_err()
        );
        assert!(matches!(
            competing.native.lock_claim,
            Some(Err(NativeJournalDataErrorV1::AlreadyLocked))
        ));
        drop(held);

        let mut reopened = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            reopened
                .prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
                .is_ok()
        );
    }

    #[test]
    fn actual_competing_flock_keeps_its_primary_through_reentry_and_disposal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let mut held = CanonicalOrdinaryOpeningOriginalsV1::new();
        held.prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
            .unwrap();
        let mut refused = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(
            refused
                .prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
                .is_err()
        );
        let first = refused.native_failure_v1().unwrap() as *const dyn std::error::Error;

        assert!(
            refused
                .prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
                .is_err()
        );
        assert!(std::ptr::eq(refused.native_failure_v1().unwrap(), first));
        refused.dispose_ordinary_current_once_v1().unwrap();
        refused.dispose_ordinary_pending_once_v1().unwrap();
        let (index, native) = refused.into_ordinary_errors_v1().ok().unwrap();

        assert!(index.is_none());
        assert!(matches!(
            native,
            Some(NativeJournalDataErrorV1::AlreadyLocked)
        ));
        assert!(held.native.lock.is_some());
    }
}
