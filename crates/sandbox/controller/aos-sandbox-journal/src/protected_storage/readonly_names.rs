//! Preserves the existing readonly snapshot check and every reached owner.
//!
//! Result slots are immutable after observation, so an enclosing selected
//! reader can borrow its original native cause without copying the error.
//! Ordinary adapters consume the same engine and dispose its temporary files.

use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use super::{
    FileIdentity, ProtectedFailure, ReadOnlyJournalNameWitness,
    open_read_only_protected_file_original, resolve_protected_directory_from_root_original,
};

/// Retains one complete or partial physical readonly snapshot observation.
///
/// This DATA reservoir supplies no authority, funding or retry. Its caller
/// retains the actual owner through all independent operation posts.
pub struct ReadOnlyJournalNamesOriginalsV1<E> {
    entered: AtomicBool,
    ancestors: Mutex<Vec<File>>,
    root_error: Mutex<Option<rustix::io::Errno>>,
    directory: OnceLock<Result<File, E>>,
    directory_identity: OnceLock<Result<FileIdentity, E>>,
    directory_comparison: OnceLock<Result<(), E>>,
    named_lock: Mutex<Option<Result<File, rustix::io::Errno>>>,
    lock_validation: OnceLock<Result<(), E>>,
    named_file: Mutex<Option<Result<File, rustix::io::Errno>>>,
    file_validation: OnceLock<Result<(), E>>,
    lock_identity: OnceLock<Result<FileIdentity, E>>,
    file_identity: OnceLock<Result<FileIdentity, E>>,
    names_comparison: OnceLock<Result<(), E>>,
    held_file_identity: OnceLock<Result<FileIdentity, E>>,
    held_file_comparison: OnceLock<Result<(), E>>,
    result: OnceLock<Result<(), E>>,
}

impl<E> Default for ReadOnlyJournalNamesOriginalsV1<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> ReadOnlyJournalNamesOriginalsV1<E> {
    /// Constructs empty destinations without allocation or observation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            ancestors: Mutex::new(Vec::new()),
            root_error: Mutex::new(None),
            directory: OnceLock::new(),
            directory_identity: OnceLock::new(),
            directory_comparison: OnceLock::new(),
            named_lock: Mutex::new(None),
            lock_validation: OnceLock::new(),
            named_file: Mutex::new(None),
            file_validation: OnceLock::new(),
            lock_identity: OnceLock::new(),
            file_identity: OnceLock::new(),
            names_comparison: OnceLock::new(),
            held_file_identity: OnceLock::new(),
            held_file_comparison: OnceLock::new(),
            result: OnceLock::new(),
        }
    }
}

impl<E: ProtectedFailure> ReadOnlyJournalNamesOriginalsV1<E> {
    /// Observes the same rooted snapshot and actual held file exactly once.
    ///
    /// Reentry performs no IO and cannot replace an incomplete or failed
    /// prefix. The original path, UID and identities come from the witness.
    pub fn capture_once(&self, witness: &ReadOnlyJournalNameWitness, held_file: &File) {
        self.capture_rooted(witness, true, Some(held_file));
    }

    pub(super) fn capture_rooted(
        &self,
        witness: &ReadOnlyJournalNameWitness,
        retain_ancestors: bool,
        held_file: Option<&File>,
    ) {
        if self.entered.swap(true, Ordering::AcqRel) {
            return;
        }
        self.result.get_or_init(|| {
            let mut ancestors = self.ancestors.try_lock().map_err(|_| E::BOUNDARY)?;
            let mut root_error = self.root_error.try_lock().map_err(|_| E::BOUNDARY)?;
            self.directory.get_or_init(|| resolve_protected_directory_from_root_original::<E>(
                &witness.directory_path, witness.expected_uid,
                retain_ancestors.then_some(&mut *ancestors),
                retain_ancestors.then_some(&mut *root_error)));
            let directory = stage(&self.directory)?;
            self.capture_in_directory_inner(witness, directory)?;
            if let Some(held_file) = held_file {
                self.held_file_identity.get_or_init(|| FileIdentity::of::<E>(held_file));
                let observed = stage(&self.held_file_identity)?;
                self.held_file_comparison.get_or_init(|| {
                    if *observed == witness.file_identity { Ok(()) } else { Err(E::BOUNDARY) }
                });
                stage(&self.held_file_comparison)?;
            }
            Ok(())
        });
    }

    pub(super) fn capture_in_directory(
        &self,
        witness: &ReadOnlyJournalNameWitness,
        directory: &File,
    ) {
        if self.entered.swap(true, Ordering::AcqRel) {
            return;
        }
        self.result.get_or_init(|| self.capture_in_directory_inner(witness, directory));
    }

    fn capture_in_directory_inner(
        &self,
        witness: &ReadOnlyJournalNameWitness,
        directory: &File,
    ) -> Result<(), E> {
        self.directory_identity.get_or_init(|| FileIdentity::of::<E>(directory));
        let directory_identity = stage(&self.directory_identity)?;
        self.directory_comparison.get_or_init(|| {
            if *directory_identity == witness.directory_identity { Ok(()) } else { Err(E::BOUNDARY) }
        });
        stage(&self.directory_comparison)?;

        let mut lock = self.named_lock.try_lock().map_err(|_| E::BOUNDARY)?;
        self.lock_validation.get_or_init(|| open_read_only_protected_file_original::<E>(
            directory, &format!("{}.lock", witness.name), witness.expected_uid, &mut lock));
        stage(&self.lock_validation)?;
        let lock_file = match lock.as_ref() { Some(Ok(file)) => file, _ => return Err(E::BOUNDARY) };

        let mut file = self.named_file.try_lock().map_err(|_| E::BOUNDARY)?;
        self.file_validation.get_or_init(|| open_read_only_protected_file_original::<E>(
            directory, &witness.name, witness.expected_uid, &mut file));
        stage(&self.file_validation)?;
        let named_file = match file.as_ref() { Some(Ok(file)) => file, _ => return Err(E::BOUNDARY) };

        self.lock_identity.get_or_init(|| FileIdentity::of::<E>(lock_file));
        let lock_identity = stage(&self.lock_identity)?;
        // Preserve short-circuiting: the old engine never sampled Journal
        // identity when the newly opened Lock already differed.
        if *lock_identity != witness.lock_identity {
            self.names_comparison.get_or_init(|| Err(E::STALE_NAME));
            return Err(E::BOUNDARY);
        }
        self.file_identity.get_or_init(|| FileIdentity::of::<E>(named_file));
        let file_identity = stage(&self.file_identity)?;
        self.names_comparison.get_or_init(|| {
            if *file_identity == witness.file_identity { Ok(()) } else { Err(E::STALE_NAME) }
        });
        stage(&self.names_comparison)?;
        Ok(())
    }

    /// Borrows the actual first native or snapshot comparison failure.
    #[must_use]
    pub fn failure(&self) -> Option<&E> {
        error(&self.directory).or_else(|| error(&self.directory_identity))
            .or_else(|| error(&self.directory_comparison))
            .or_else(|| error(&self.lock_validation)).or_else(|| error(&self.file_validation))
            .or_else(|| error(&self.lock_identity)).or_else(|| error(&self.file_identity))
            .or_else(|| error(&self.names_comparison)).or_else(|| error(&self.held_file_identity))
            .or_else(|| error(&self.held_file_comparison)).or_else(|| error(&self.result))
    }

    /// Reports completion of every reached original snapshot comparison.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.result.get(), Some(Ok(())))
    }

    /// Consumes the temporary ordinary disposition in its original close order.
    ///
    /// # Errors
    /// Returns the actual first stored error, or the boundary if unentered.
    pub fn into_result(mut self) -> Result<(), E> {
        let failure = take_error(&mut self.directory)
            .or_else(|| take_error(&mut self.directory_identity))
            .or_else(|| take_error(&mut self.directory_comparison))
            .or_else(|| take_error(&mut self.lock_validation))
            .or_else(|| take_error(&mut self.file_validation))
            .or_else(|| take_error(&mut self.lock_identity))
            .or_else(|| take_error(&mut self.file_identity))
            .or_else(|| take_error(&mut self.names_comparison))
            .or_else(|| take_error(&mut self.held_file_identity))
            .or_else(|| take_error(&mut self.held_file_comparison))
            .or_else(|| take_error(&mut self.result));
        let result = failure.map_or_else(|| {
            if self.is_complete() { Ok(()) } else { Err(E::BOUNDARY) }
        }, Err);
        drop(self.named_file);
        drop(self.named_lock);
        drop(self.directory);
        result
    }
}

fn stage<T, E: ProtectedFailure>(slot: &OnceLock<Result<T, E>>) -> Result<&T, E> {
    match slot.get() { Some(Ok(value)) => Ok(value), _ => Err(E::BOUNDARY) }
}

fn error<T, E>(slot: &OnceLock<Result<T, E>>) -> Option<&E> {
    slot.get().and_then(|result| result.as_ref().err())
}

fn take_error<T, E>(slot: &mut OnceLock<Result<T, E>>) -> Option<E> {
    if matches!(slot.get(), Some(Err(_))) {
        match slot.take() { Some(Err(error)) => Some(error), _ => None }
    } else { None }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    enum Failure {
        #[error(transparent)]
        Io(#[from] io::Error),
        #[error("boundary")]
        Boundary,
        #[error("unsupported open")]
        Unsupported,
        #[error("stale snapshot")]
        Stale,
    }

    impl ProtectedFailure for Failure {
        const BOUNDARY: Self = Self::Boundary;
        const UNSUPPORTED_OPEN: Self = Self::Unsupported;
        const STALE_NAME: Self = Self::Stale;
    }

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "aos-readonly-names-{}-{}", std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn file(&self, name: &str) -> File {
            std::fs::OpenOptions::new().read(true).write(true).create_new(true)
                .mode(0o600).open(self.0.join(name)).unwrap()
        }

        fn witness(&self, directory: &File, file: &File, lock: &File)
            -> ReadOnlyJournalNameWitness
        {
            ReadOnlyJournalNameWitness::from_original_parts((
                self.0.clone(), "state.journal".to_owned(), directory.metadata().unwrap().uid(),
                FileIdentity::of::<Failure>(directory).unwrap(),
                FileIdentity::of::<Failure>(file).unwrap(),
                FileIdentity::of::<Failure>(lock).unwrap(),
            ))
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn missing_journal_keeps_fresh_lock_and_exact_native_cause_without_retry() {
        let fixture = Directory::new();
        let directory = File::open(&fixture.0).unwrap();
        let lock = fixture.file("state.journal.lock");
        let file = fixture.file("state.journal");
        std::fs::remove_file(fixture.0.join("state.journal")).unwrap();
        // Negative mechanics only: this snapshot DATA is sampled after unlink
        // so the test reaches the native Journal open, without forging a payer.
        let witness = fixture.witness(&directory, &file, &lock);
        let observation = ReadOnlyJournalNamesOriginalsV1::<Failure>::new();

        observation.capture_in_directory(&witness, &directory);

        let first = observation.failure().unwrap() as *const Failure;
        assert!(matches!(observation.failure(), Some(Failure::Io(error))
            if error.kind() == io::ErrorKind::NotFound));
        assert!(matches!(*observation.named_lock.lock().unwrap(), Some(Ok(_))));
        assert!(matches!(*observation.named_file.lock().unwrap(), Some(Err(_))));
        assert!(!observation.is_complete());

        let _replacement = fixture.file("state.journal");
        observation.capture_in_directory(&witness, &directory);

        assert!(std::ptr::eq(observation.failure().unwrap(), first));
        assert!(matches!(*observation.named_lock.lock().unwrap(), Some(Ok(_))));
        assert!(matches!(witness.check_in_directory::<Failure>(&directory), Err(Failure::Boundary) | Err(Failure::Stale)));
    }

    #[test]
    fn changed_lock_keeps_both_fresh_files_and_preserves_identity_short_circuit() {
        let fixture = Directory::new();
        let directory = File::open(&fixture.0).unwrap();
        let lock = fixture.file("state.journal.lock");
        let file = fixture.file("state.journal");
        let old_lock = FileIdentity::of::<Failure>(&lock).unwrap();
        std::fs::remove_file(fixture.0.join("state.journal.lock")).unwrap();
        let _replacement = fixture.file("state.journal.lock");
        let mut witness = fixture.witness(&directory, &file, &lock);
        witness.lock_identity = old_lock;
        let observation = ReadOnlyJournalNamesOriginalsV1::<Failure>::new();

        observation.capture_in_directory(&witness, &directory);

        assert!(matches!(observation.failure(), Some(Failure::Stale)));
        assert!(matches!(*observation.named_lock.lock().unwrap(), Some(Ok(_))));
        assert!(matches!(*observation.named_file.lock().unwrap(), Some(Ok(_))));
        assert!(observation.file_identity.get().is_none());
        assert!(matches!(witness.check_in_directory::<Failure>(&directory), Err(Failure::Stale)));
    }

    #[test]
    fn retained_result_slots_preserve_send_and_sync() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<ReadOnlyJournalNamesOriginalsV1<Failure>>();
    }

    #[test]
    fn ordinary_adapter_accepts_the_complete_unchanged_snapshot() {
        let fixture = Directory::new();
        let directory = File::open(&fixture.0).unwrap();
        let lock = fixture.file("state.journal.lock");
        let file = fixture.file("state.journal");
        let witness = fixture.witness(&directory, &file, &lock);

        witness.check_in_directory::<Failure>(&directory).unwrap();

        assert_eq!(FileIdentity::of::<Failure>(&file).unwrap().physical_pair(),
            witness.file_identity.physical_pair());
    }
}
