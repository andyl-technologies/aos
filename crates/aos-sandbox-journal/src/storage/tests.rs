//! Genuine-file regressions for native custody, append uncertainty, and read cuts.

#![allow(clippy::unwrap_used)]

#[cfg(unix)]
use std::borrow::Borrow;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::Read as _;
use std::io::{self, Seek as _, SeekFrom, Write as _};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use super::CapturedFileCursor;
use super::NativeJournalStorage;
use crate::framing::FrameError;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TemporaryFile {
    file: Option<File>,
    path: PathBuf,
}

impl TemporaryFile {
    fn new(contents: &[u8]) -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "aos-journal-native-storage-{}-{}",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed),
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path);
            let mut file = match file {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("temporary file creation failed: {error}"),
            };
            file.write_all(contents).unwrap();
            return Self {
                file: Some(file),
                path,
            };
        }
    }

    fn take_file(&mut self) -> File {
        self.file.take().unwrap()
    }

    fn read_only(&self) -> File {
        OpenOptions::new().read(true).open(&self.path).unwrap()
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
#[test]
fn adoption_retains_both_original_descriptors_and_file_identities() {
    let mut data = TemporaryFile::new(b"original");
    let mut lock = TemporaryFile::new(b"lock");
    let file = data.take_file();
    let lock_file = lock.take_file();
    let data_descriptor = file.as_raw_fd();
    let lock_descriptor = lock_file.as_raw_fd();
    let data_metadata = file.metadata().unwrap();
    let lock_metadata = lock_file.metadata().unwrap();

    let owner = NativeJournalStorage::from_owned_files(file, lock_file);

    assert_eq!(owner.file().as_raw_fd(), data_descriptor);
    assert_eq!(owner.lock_file().as_raw_fd(), lock_descriptor);
    let actual_data = owner.file().metadata().unwrap();
    let actual_lock = owner.lock_file().metadata().unwrap();
    assert_eq!(
        (actual_data.dev(), actual_data.ino()),
        (data_metadata.dev(), data_metadata.ino())
    );
    assert_eq!(
        (actual_lock.dev(), actual_lock.ino()),
        (lock_metadata.dev(), lock_metadata.ino())
    );
    assert!(!owner.is_poisoned());
}

#[test]
fn exact_append_uses_actual_file_length_and_returns_only_native_durability() {
    let mut data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let mut owner = NativeJournalStorage::from_owned_files(data.take_file(), lock.take_file());
    let frames = vec![b"one".to_vec(), b"two".to_vec()];

    let expected = owner.expected_append_length(&frames, 12).unwrap();
    let durable = owner.append_exact(&frames, expected).unwrap();

    assert_eq!(expected, 12);
    assert_eq!(durable, 12);
    assert_eq!(owner.file().metadata().unwrap().len(), 12);
    assert_eq!(fs::read(&data.path).unwrap(), b"prefixonetwo");
    assert!(!owner.is_poisoned());
}

#[test]
fn preflight_limit_refusal_does_not_write_or_poison_the_owner() {
    let mut data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let owner = NativeJournalStorage::from_owned_files(data.take_file(), lock.take_file());

    let outcome = owner.expected_append_length(&[b"more".to_vec()], 9);

    assert!(matches!(outcome, Err(FrameError::JournalTooLarge)));
    assert_eq!(owner.file().metadata().unwrap().len(), 6);
    assert_eq!(fs::read(&data.path).unwrap(), b"prefix");
    assert!(!owner.is_poisoned());
}

#[test]
fn failed_native_append_returns_owning_io_cause_and_poisons() {
    let data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let mut original = data.read_only();
    original.seek(SeekFrom::Start(2)).unwrap();
    let mut owner = NativeJournalStorage::from_owned_files(original, lock.take_file());

    let outcome = owner.append_exact(&[b"more".to_vec()], 10);

    let FrameError::Io(actual) = outcome.unwrap_err() else {
        panic!("native append failure must retain its actual I/O cause");
    };
    assert!(actual.raw_os_error().is_some());
    assert!(owner.is_poisoned());
    assert_eq!(owner.file_mut().stream_position().unwrap(), 2);
    assert_eq!(owner.file().metadata().unwrap().len(), 6);
    assert_eq!(fs::read(&data.path).unwrap(), b"prefix");
}

#[test]
fn durable_length_mismatch_poisons_after_the_original_write() {
    let mut data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let mut owner = NativeJournalStorage::from_owned_files(data.take_file(), lock.take_file());

    let outcome = owner.append_exact(&[b"more".to_vec()], 11);

    let FrameError::Io(actual) = outcome.unwrap_err() else {
        panic!("length mismatch must retain the existing I/O classification");
    };
    assert_eq!(
        actual.to_string(),
        "journal length changed outside the exclusive writer"
    );
    assert!(owner.is_poisoned());
    assert_eq!(owner.file().metadata().unwrap().len(), 10);
    assert_eq!(fs::read(&data.path).unwrap(), b"prefixmore");
}

#[cfg(unix)]
#[test]
fn replacement_retains_the_same_lock_and_never_resets_poison() {
    let mut data = TemporaryFile::new(b"old");
    let mut lock = TemporaryFile::new(b"lock");
    let mut replacement = TemporaryFile::new(b"replacement");
    let file = replacement.take_file();
    let replacement_descriptor = file.as_raw_fd();
    let mut owner = NativeJournalStorage::from_owned_files(data.take_file(), lock.take_file());
    let lock_descriptor = owner.lock_file().as_raw_fd();
    let original_lock = owner.lock_file().metadata().unwrap();
    owner.poison();

    owner.replace_file(file);

    assert_eq!(owner.file().as_raw_fd(), replacement_descriptor);
    assert_eq!(owner.lock_file().as_raw_fd(), lock_descriptor);
    let retained_lock = owner.lock_file().metadata().unwrap();
    assert_eq!(
        (retained_lock.dev(), retained_lock.ino()),
        (original_lock.dev(), original_lock.ino())
    );
    assert_eq!(owner.file().metadata().unwrap().len(), 11);
    assert!(owner.is_poisoned());
}

#[cfg(unix)]
#[test]
fn captured_reader_bounds_its_cut_and_borrows_the_same_file_without_seeking_it() {
    let mut data = TemporaryFile::new(b"prefix");
    let mut original = data.take_file();
    original.seek(SeekFrom::Start(3)).unwrap();
    let mut reader = CapturedFileCursor::new(&original, 4);
    let mut bytes = [0; 8];

    assert_eq!(reader.read(&mut bytes).unwrap(), 4);
    assert_eq!(&bytes[..4], b"pref");
    assert_eq!(reader.read(&mut bytes).unwrap(), 0);
    assert!(std::ptr::eq(Borrow::<File>::borrow(&reader), &original));
    assert_eq!((&original).stream_position().unwrap(), 3);
    assert!(reader.seek(SeekFrom::End(1)).is_err());
    assert_eq!(reader.seek(SeekFrom::Current(0)).unwrap(), 4);
    assert_eq!(reader.seek(SeekFrom::Start(0)).unwrap(), 0);
    assert!(reader.seek(SeekFrom::Current(-1)).is_err());
    assert_eq!((&original).stream_position().unwrap(), 3);
}

#[cfg(unix)]
#[test]
fn captured_reader_native_failure_keeps_logical_and_shared_cursors() {
    let data = TemporaryFile::new(b"prefix");
    let mut original = OpenOptions::new().write(true).open(&data.path).unwrap();
    original.seek(SeekFrom::Start(2)).unwrap();
    let mut reader = CapturedFileCursor::new(&original, 6);

    let cause = reader.read(&mut [0; 1]).unwrap_err();

    assert!(cause.raw_os_error().is_some());
    assert_eq!(reader.seek(SeekFrom::Current(0)).unwrap(), 0);
    assert!(std::ptr::eq(Borrow::<File>::borrow(&reader), &original));
    assert_eq!((&original).stream_position().unwrap(), 2);
}
