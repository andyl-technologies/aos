//! Native finalization of an already replayed journal's incomplete tail.
//!
//! The domain owner first observes metadata, enforces bounds, and completes its
//! actual semantic replay. This module then performs the existing truncate,
//! data-sync, and end-seek sequence on that same borrowed file. It does not open
//! files, own locks, validate replay, authorize repair, or publish committed state.
//! Selected callers loan their actual native-result slots so each owning error
//! remains resident before classification or another operation.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};

/// Selects existing incomplete-tail handling without granting repair authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTailMode {
    /// Performs the existing truncation and data sync for an incomplete tail.
    RepairIncomplete,
    /// Refuses an incomplete tail without truncation, sync, or seek.
    RejectIncomplete,
}

/// Borrows the owner's existing native-result slots without adopting custody.
///
/// All three slots belong to the same selected upper recovery owner. Native
/// results are parked in these actual slots before classification or another
/// syscall; no file, replay result, or authority is constructed here.
pub struct TailResultSlots<'a> {
    truncate: &'a mut Option<io::Result<()>>,
    sync: &'a mut Option<io::Result<()>>,
    seek: &'a mut Option<io::Result<u64>>,
}

impl<'a> TailResultSlots<'a> {
    /// Loans the same three native-result slots for one selected finalization.
    pub const fn new(
        truncate: &'a mut Option<io::Result<()>>,
        sync: &'a mut Option<io::Result<()>>,
        seek: &'a mut Option<io::Result<u64>>,
    ) -> Self {
        Self {
            truncate,
            sync,
            seek,
        }
    }
}

/// Reports finalization failure while preserving ordinary or selected custody.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryTailError {
    /// Owns the ordinary caller's actual truncate, sync, or seek error.
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Reports the existing refusal to repair an incomplete read-only tail.
    #[error("malformed journal transaction: read-only journal has an uncommitted tail")]
    UncommittedTail,
    /// Leaves the genuine error in the selected owner's original native slot.
    #[error("protected journal storage boundary is invalid")]
    RetainedNativeFailure,
}

/// Finalizes an already replayed prefix on the same borrowed native file.
///
/// The lengths and mode are DATA, not evidence of semantic replay or authority
/// to repair protected storage. The upper owner supplies its actual observed
/// length and replayed prefix only after all existing replay checks succeed.
/// The returned removed-byte count is neither a commit receipt nor currentness.
///
/// With selected slots, every native result remains in its original upper field;
/// ordinary errors instead move directly into [`RecoveryTailError::Io`]. A file
/// with no incomplete tail still seeks to its end without truncation or sync.
///
/// # Errors
///
/// Refuses an incomplete tail in rejecting mode before any native operation.
/// Otherwise stops on the first failed truncate, data sync, or final end seek.
pub fn finish_replayed_tail(
    file: &mut File,
    observed_length: u64,
    replayed_prefix_end: u64,
    mode: RecoveryTailMode,
    slots: Option<TailResultSlots<'_>>,
) -> Result<u64, RecoveryTailError> {
    let truncated_bytes = observed_length.saturating_sub(replayed_prefix_end);
    let (truncate_slot, sync_slot, seek_slot) = match slots {
        None => (None, None, None),
        Some(slots) => (Some(slots.truncate), Some(slots.sync), Some(slots.seek)),
    };

    // Successes are Copy; the actual owning Err stays in the selected slot.
    macro_rules! native {
        ($slot:expr, $operation:expr) => {
            match $slot {
                None => $operation?,
                Some(slot) => {
                    *slot = Some($operation);
                    match slot.as_ref() {
                        Some(Ok(value)) => *value,
                        _ => return Err(RecoveryTailError::RetainedNativeFailure),
                    }
                }
            }
        };
    }
    if truncated_bytes > 0 {
        if mode == RecoveryTailMode::RejectIncomplete {
            return Err(RecoveryTailError::UncommittedTail);
        }
        native!(truncate_slot, file.set_len(replayed_prefix_end));
        native!(sync_slot, file.sync_data());
    }
    native!(seek_slot, file.seek(SeekFrom::End(0)));
    Ok(truncated_bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::{self, OpenOptions};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TemporaryJournalFile {
        file: Option<File>,
        path: PathBuf,
    }

    impl TemporaryJournalFile {
        fn new(contents: &[u8]) -> Self {
            loop {
                let path = std::env::temp_dir().join(format!(
                    "aos-journal-recovery-tail-{}-{}",
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
                    Err(error) => panic!("temporary journal creation failed: {error}"),
                };
                file.write_all(contents).unwrap();
                return Self {
                    file: Some(file),
                    path,
                };
            }
        }

        fn file_mut(&mut self) -> &mut File {
            self.file.as_mut().unwrap()
        }

        fn read_only(&self) -> File {
            OpenOptions::new().read(true).open(&self.path).unwrap()
        }
    }

    impl Drop for TemporaryJournalFile {
        fn drop(&mut self) {
            drop(self.file.take());
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn rejected_tail_leaves_file_and_all_native_slots_untouched() {
        let mut journal = TemporaryJournalFile::new(b"prefix-tail");
        let file = journal.file_mut();
        file.seek(SeekFrom::Start(2)).unwrap();
        let mut truncate = None;
        let mut sync = None;
        let mut seek = None;

        let outcome = finish_replayed_tail(
            file,
            11,
            6,
            RecoveryTailMode::RejectIncomplete,
            Some(TailResultSlots::new(&mut truncate, &mut sync, &mut seek)),
        );

        assert!(matches!(outcome, Err(RecoveryTailError::UncommittedTail)));
        assert_eq!(file.metadata().unwrap().len(), 11);
        assert_eq!(file.stream_position().unwrap(), 2);
        assert!(truncate.is_none());
        assert!(sync.is_none());
        assert!(seek.is_none());
    }

    #[test]
    fn permitted_repair_parks_truncate_sync_and_end_seek_on_same_file() {
        let mut journal = TemporaryJournalFile::new(b"prefix-tail");
        let file = journal.file_mut();
        let original_file = std::ptr::from_ref(&*file);
        #[cfg(unix)]
        let original_identity = {
            let metadata = file.metadata().unwrap();
            (metadata.dev(), metadata.ino())
        };
        let mut truncate = None;
        let mut sync = None;
        let mut seek = None;

        let removed = finish_replayed_tail(
            file,
            11,
            6,
            RecoveryTailMode::RepairIncomplete,
            Some(TailResultSlots::new(&mut truncate, &mut sync, &mut seek)),
        )
        .unwrap();

        assert_eq!(removed, 5);
        assert_eq!(std::ptr::from_ref(&*file), original_file);
        #[cfg(unix)]
        {
            let metadata = file.metadata().unwrap();
            assert_eq!((metadata.dev(), metadata.ino()), original_identity);
        }
        assert_eq!(file.metadata().unwrap().len(), 6);
        assert_eq!(file.stream_position().unwrap(), 6);
        assert!(matches!(truncate, Some(Ok(()))));
        assert!(matches!(sync, Some(Ok(()))));
        assert!(matches!(seek, Some(Ok(6))));
    }

    #[test]
    fn complete_prefix_seeks_to_end_without_truncating_or_syncing() {
        let mut journal = TemporaryJournalFile::new(b"prefix");
        let file = journal.file_mut();
        file.seek(SeekFrom::Start(1)).unwrap();
        let mut truncate = None;
        let mut sync = None;
        let mut seek = None;

        let removed = finish_replayed_tail(
            file,
            6,
            6,
            RecoveryTailMode::RejectIncomplete,
            Some(TailResultSlots::new(&mut truncate, &mut sync, &mut seek)),
        )
        .unwrap();

        assert_eq!(removed, 0);
        assert_eq!(file.metadata().unwrap().len(), 6);
        assert_eq!(file.stream_position().unwrap(), 6);
        assert!(truncate.is_none());
        assert!(sync.is_none());
        assert!(matches!(seek, Some(Ok(6))));
    }

    #[test]
    fn selected_truncate_failure_retains_owning_cause_before_sync_or_seek() {
        let journal = TemporaryJournalFile::new(b"prefix-tail");
        let mut file = journal.read_only();
        file.seek(SeekFrom::Start(2)).unwrap();
        let mut truncate = None;
        let mut sync = None;
        let mut seek = None;

        let outcome = finish_replayed_tail(
            &mut file,
            11,
            6,
            RecoveryTailMode::RepairIncomplete,
            Some(TailResultSlots::new(&mut truncate, &mut sync, &mut seek)),
        );

        assert!(matches!(
            outcome,
            Err(RecoveryTailError::RetainedNativeFailure)
        ));
        let actual = truncate.as_ref().unwrap().as_ref().unwrap_err();
        assert!(actual.raw_os_error().is_some());
        let original_cause = std::ptr::from_ref(actual);
        assert_eq!(file.metadata().unwrap().len(), 11);
        assert_eq!(file.stream_position().unwrap(), 2);
        assert!(sync.is_none());
        assert!(seek.is_none());
        assert_eq!(
            std::ptr::from_ref(truncate.as_ref().unwrap().as_ref().unwrap_err()),
            original_cause,
        );
    }

    #[test]
    fn ordinary_truncate_failure_returns_native_cause_without_later_seek() {
        let journal = TemporaryJournalFile::new(b"prefix-tail");
        let mut file = journal.read_only();
        file.seek(SeekFrom::Start(2)).unwrap();

        let outcome =
            finish_replayed_tail(&mut file, 11, 6, RecoveryTailMode::RepairIncomplete, None);

        let RecoveryTailError::Io(actual) = outcome.unwrap_err() else {
            panic!("ordinary failure must own the native error");
        };
        assert!(actual.raw_os_error().is_some());
        assert_eq!(file.metadata().unwrap().len(), 11);
        assert_eq!(file.stream_position().unwrap(), 2);
    }
}
