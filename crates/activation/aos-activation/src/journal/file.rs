//! Linux filesystem storage for durable journal frames.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::frame::{
    FrameCursor, FrameFormat, JournalError, JournalLimits, JournalPayload, JournalRecord,
    MAGIC_LENGTH, MAX_HEADER_LENGTH, RecoveryReport, encode,
};
use rustix::fs::{FlockOperation, Mode, OFlags};

/// A newly opened journal together with its verified recovery report.
#[derive(Debug)]
pub struct JournalOpenResult<T> {
    /// The journal positioned for the next append.
    pub journal: FileJournal<T>,
    /// The verified records and torn-tail repair details.
    pub recovery: RecoveryReport<T>,
}

/// A read-only verified journal prefix and any incomplete final frame.
///
/// A corrupt complete frame is returned as [`JournalError::Corrupt`] instead
/// of being represented here. The snapshot does not create, truncate,
/// synchronize, or otherwise modify the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSnapshot<T> {
    records: Vec<JournalRecord<T>>,
    verified_bytes: u64,
    incomplete_tail_bytes: u64,
}

impl<T> JournalSnapshot<T> {
    /// Returns the complete checksum-verified record prefix.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord<T>] {
        &self.records
    }

    /// Consumes the snapshot and returns its complete verified record prefix.
    #[must_use]
    pub fn into_records(self) -> Vec<JournalRecord<T>> {
        self.records
    }

    /// Returns the byte length of the complete verified prefix.
    #[must_use]
    pub const fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// Returns bytes belonging to an incomplete final header or body.
    #[must_use]
    pub const fn incomplete_tail_bytes(&self) -> u64 {
        self.incomplete_tail_bytes
    }
}

/// Holds a verified read-only prefix and its shared filesystem lock.
///
/// Retaining this guard prevents a writer from changing the journal while a
/// caller reads related state protected by the same journal ownership order.
pub struct JournalReader<T> {
    _file: LockedFile,
    snapshot: JournalSnapshot<T>,
}

impl<T> JournalReader<T> {
    /// Returns the verified prefix while retaining the shared lock.
    #[must_use]
    pub fn snapshot(&self) -> &JournalSnapshot<T> {
        &self.snapshot
    }

    /// Releases the shared lock and returns the verified prefix.
    #[must_use]
    pub fn into_snapshot(self) -> JournalSnapshot<T> {
        self.snapshot
    }
}

/// A single-writer durable journal stored in one append-only file.
///
/// Opening holds a nonblocking exclusive filesystem lock for this value's
/// lifetime. The containing directory must be a trusted controller-owned
/// location; final-component `NOFOLLOW` does not protect an untrusted parent
/// directory from replacement.
///
/// A successful append synchronizes the file before returning. Creation and
/// torn-tail repair also synchronize the containing directory or file as
/// required by their filesystem boundary.
pub struct FileJournal<T> {
    path: PathBuf,
    file: LockedFile,
    limits: JournalLimits,
    next_sequence: u64,
    requires_recovery: bool,
    marker: PhantomData<fn() -> T>,
}

// A fork can temporarily retain the open description despite CLOEXEC. Release
// the advisory lock at the controller's ownership boundary, rather than waiting
// for every inherited descriptor to close in another process.
struct LockedFile(File);

impl std::ops::Deref for LockedFile {
    type Target = File;

    fn deref(&self) -> &File {
        &self.0
    }
}

impl std::ops::DerefMut for LockedFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.0
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        while let Err(error) = rustix::fs::flock(&self.0, FlockOperation::Unlock) {
            if error != rustix::io::Errno::INTR {
                break;
            }
        }
    }
}

impl<T> std::fmt::Debug for FileJournal<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileJournal")
            .field("path", &self.path)
            .field("limits", &self.limits)
            .field("next_sequence", &self.next_sequence)
            .field("requires_recovery", &self.requires_recovery)
            .finish_non_exhaustive()
    }
}

impl<T> FileJournal<T>
where
    T: JournalPayload,
{
    /// Reads a verified prefix under a shared lock held by the returned reader.
    ///
    /// The existing path is opened read-only with `NOFOLLOW` and a nonblocking
    /// shared lock. An active writer's exclusive lock therefore makes the read
    /// fail instead of racing the writer. A partial final frame is reported
    /// through [`JournalSnapshot::incomplete_tail_bytes`] and remains
    /// untouched. Retain the [`JournalReader`] while reading related state
    /// protected by the same journal ownership order; call
    /// [`JournalReader::into_snapshot`] when only the records are needed.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is absent, insecure, unavailable for a
    /// shared lock, exceeds configured limits, or contains a corrupt complete
    /// frame or invalid record body. No bytes are changed.
    pub fn read_locked(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<JournalReader<T>, JournalError> {
        let path = path.as_ref();
        read_locked_file(open_read_only(path)?, path, limits)
    }

    /// Reads a bounded verified prefix without a lock while a writer may remain active.
    ///
    /// The existing private regular file is opened read-only with `NOFOLLOW`.
    /// Decoding stops at the length captured from that descriptor, so later
    /// appends cannot extend this read. An incomplete final frame is reported
    /// without repair; every complete frame receives the same checks as a
    /// locked read.
    ///
    /// This is an observation of checksummed bytes, not evidence that the
    /// writer's synchronization completed. It must not replace
    /// [`FileJournal::read_locked`] when establishing retained execution
    /// authority or reading related files.
    ///
    /// # Errors
    ///
    /// Returns an error for absent or insecure files, exceeded limits, corrupt
    /// complete frames, invalid bodies, or truncation during the read.
    pub fn read_unlocked(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<JournalSnapshot<T>, JournalError> {
        let path = path.as_ref();
        let mut file = open_read_only(path)?;
        validate_private_regular_file(&file, path)?;
        let RecoveryReport {
            records,
            valid_bytes,
            discarded_torn_bytes,
        } = recover::<T>(&mut file, path, limits)?;

        // A concurrent controller may repair an incomplete suffix. If that
        // truncation happens during this read, reject the raced cut instead of
        // implying a stable endpoint. A later read can observe the new cut.
        let captured_length = valid_bytes + discarded_torn_bytes;
        let current_length = file
            .metadata()
            .map_err(|source| io_error("read observation metadata", path, source))?
            .len();
        if current_length < captured_length {
            return Err(io_error(
                "read observed prefix",
                path,
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "journal was truncated during observation",
                ),
            ));
        }

        Ok(JournalSnapshot {
            records,
            verified_bytes: valid_bytes,
            incomplete_tail_bytes: discarded_torn_bytes,
        })
    }

    /// Opens a journal, verifies its complete prefix, and repairs a torn tail.
    ///
    /// A partial final frame is truncated only after every preceding frame has
    /// passed sequence, header-checksum, body-checksum, canonical-encoding,
    /// limits, and schema checks. A complete invalid frame is left untouched.
    /// Existing version 1 frames are verified with their legacy digest chain;
    /// subsequent appends use the current frame format.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be opened or synchronized, a
    /// complete frame is corrupt, or the record schema cannot be decoded.
    pub fn open(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<JournalOpenResult<T>, JournalError> {
        let path = path.as_ref().to_path_buf();
        let (file, created) = open_private(&path)?;
        rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|source| io_error("acquire exclusive lock", &path, source.into()))?;
        let mut file = LockedFile(file);
        validate_private_regular_file(&file, &path)?;

        if created {
            file.sync_all()
                .map_err(|source| io_error("sync newly created file", &path, source))?;
        }
        // Sync after the lock on every open. This closes the race where a
        // second opener observes a newly created entry before its creator has
        // made the containing directory durable.
        sync_parent(&path)?;

        let recovery = recover::<T>(&mut file, &path, limits)?;
        if recovery.discarded_torn_bytes() != 0 {
            file.set_len(recovery.valid_bytes())
                .map_err(|source| io_error("truncate torn tail", &path, source))?;
            file.sync_all()
                .map_err(|source| io_error("sync torn-tail repair", &path, source))?;
        }
        file.seek(SeekFrom::Start(recovery.valid_bytes()))
            .map_err(|source| io_error("seek to append position", &path, source))?;

        let next_sequence = match recovery.records().last() {
            Some(record) => record.sequence().checked_add(1).ok_or_else(|| {
                JournalError::Limit("journal sequence number exhausted".to_string())
            })?,
            None => 1,
        };

        Ok(JournalOpenResult {
            journal: Self {
                path,
                file,
                limits,
                next_sequence,
                requires_recovery: false,
                marker: PhantomData,
            },
            recovery,
        })
    }
}

impl<T> FileJournal<T>
where
    T: JournalPayload,
{
    /// Verifies conservative configured capacity for future maximum-size frames.
    ///
    /// The journal's exclusive writer lock ensures another controller cannot
    /// consume this configured capacity between this check and subsequent
    /// appends through the same value. This does not predict filesystem
    /// `ENOSPC`; an I/O failure after external dispatch remains indeterminate.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested record count or its conservative
    /// maximum encoded bytes would exceed the configured journal limits.
    pub fn ensure_capacity(&mut self, additional_records: usize) -> Result<(), JournalError> {
        let current_records =
            usize::try_from(self.next_sequence.saturating_sub(1)).unwrap_or(usize::MAX);
        let resulting_records = current_records
            .checked_add(additional_records)
            .ok_or_else(|| JournalError::Limit("journal record capacity overflow".to_string()))?;
        if resulting_records > self.limits.max_records {
            return Err(JournalError::Limit(format!(
                "reservation would exceed the {} record journal limit",
                self.limits.max_records
            )));
        }

        let maximum_frame_bytes = FrameFormat::CURRENT
            .header_length()
            .checked_add(self.limits.max_body_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| JournalError::Limit("journal frame capacity overflow".to_string()))?;
        let reserved_bytes = maximum_frame_bytes
            .checked_mul(u64::try_from(additional_records).unwrap_or(u64::MAX))
            .ok_or_else(|| JournalError::Limit("journal byte capacity overflow".to_string()))?;
        let current_length = self
            .file
            .stream_position()
            .map_err(|source| io_error("read capacity position", &self.path, source))?;
        let resulting_length = current_length
            .checked_add(reserved_bytes)
            .ok_or_else(|| JournalError::Limit("journal file capacity overflow".to_string()))?;
        if resulting_length > self.limits.max_file_bytes {
            return Err(JournalError::Limit(format!(
                "reservation would exceed the {} byte journal limit",
                self.limits.max_file_bytes
            )));
        }
        Ok(())
    }

    /// Appends and durably synchronizes one canonical record.
    ///
    /// The journal enters a recovery-required state before issuing the write.
    /// It becomes appendable again only after the whole frame and `sync_all`
    /// succeed. This prevents a caller from appending past an uncertain tail.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding exceeds a limit, canonical encoding
    /// fails, the write is uncertain, or durable synchronization fails.
    pub fn append(&mut self, body: &T) -> Result<JournalRecord<()>, JournalError> {
        if self.requires_recovery {
            return Err(JournalError::RequiresRecovery);
        }

        let encoded = encode(body, self.next_sequence, self.limits)?;
        let encoded_length = u64::try_from(encoded.len()).map_err(|_| {
            JournalError::Limit("encoded frame length is not representable as u64".to_string())
        })?;
        let current_length = self
            .file
            .stream_position()
            .map_err(|source| io_error("read append position", &self.path, source))?;
        let resulting_length = current_length
            .checked_add(encoded_length)
            .ok_or_else(|| JournalError::Limit("journal file length overflow".to_string()))?;
        if resulting_length > self.limits.max_file_bytes {
            return Err(JournalError::Limit(format!(
                "append would exceed the {} byte journal limit",
                self.limits.max_file_bytes
            )));
        }
        if self.next_sequence > u64::try_from(self.limits.max_records).unwrap_or(u64::MAX) {
            return Err(JournalError::Limit(format!(
                "append would exceed the {} record journal limit",
                self.limits.max_records
            )));
        }
        self.requires_recovery = true;
        self.file
            .write_all(&encoded)
            .map_err(|source| io_error("append", &self.path, source))?;
        self.file
            .sync_all()
            .map_err(|source| io_error("sync append", &self.path, source))?;

        let record = JournalRecord {
            sequence: self.next_sequence,
            body: (),
        };
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::Limit("journal sequence number exhausted".to_string()))?;
        self.requires_recovery = false;

        Ok(record)
    }
}

/// Locks and verifies an opened descriptor; `path` is diagnostic only.
fn read_locked_file<T>(
    file: File,
    path: &Path,
    limits: JournalLimits,
) -> Result<JournalReader<T>, JournalError>
where
    T: JournalPayload,
{
    rustix::fs::flock(&file, FlockOperation::NonBlockingLockShared)
        .map_err(|source| io_error("acquire shared lock", path, source.into()))?;
    let mut file = LockedFile(file);
    validate_private_regular_file(&file, path)?;
    let RecoveryReport {
        records,
        valid_bytes,
        discarded_torn_bytes,
    } = recover::<T>(&mut file, path, limits)?;

    Ok(JournalReader {
        _file: file,
        snapshot: JournalSnapshot {
            records,
            verified_bytes: valid_bytes,
            incomplete_tail_bytes: discarded_torn_bytes,
        },
    })
}

fn recover<T>(
    file: &mut File,
    path: &Path,
    limits: JournalLimits,
) -> Result<RecoveryReport<T>, JournalError>
where
    T: JournalPayload,
{
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("seek for recovery", path, source))?;
    let file_length = file
        .metadata()
        .map_err(|source| io_error("read metadata", path, source))?
        .len();
    read_verified_prefix::<T>(file, path, limits, file_length)
}

fn read_verified_prefix<T>(
    reader: &mut impl Read,
    path: &Path,
    limits: JournalLimits,
    file_length: u64,
) -> Result<RecoveryReport<T>, JournalError>
where
    T: JournalPayload,
{
    if file_length > limits.max_file_bytes {
        return Err(JournalError::Limit(format!(
            "journal has {file_length} bytes, limit is {}",
            limits.max_file_bytes
        )));
    }

    // Bound both observation and recovery to one descriptor-captured cut.
    // In particular, an unlocked observer must not chase an appending writer.
    let mut reader = reader.take(file_length);
    let mut records = Vec::new();
    let mut cursor = FrameCursor::new();

    loop {
        if records.len() == limits.max_records {
            if cursor.offset() == file_length {
                break;
            }
            return Err(JournalError::Limit(format!(
                "journal exceeds the {} record limit",
                limits.max_records
            )));
        }

        // The magic selects the header layout. Every short read below
        // exhausts the captured cut, so it can only be a torn final frame.
        let mut header = [0_u8; MAX_HEADER_LENGTH];
        let magic_bytes = read_to_end_of_buffer(&mut reader, &mut header[..MAGIC_LENGTH])
            .map_err(|source| io_error("read frame header", path, source))?;
        if magic_bytes < MAGIC_LENGTH {
            break;
        }
        let header_length = cursor.header_length(&header[..MAGIC_LENGTH]);
        let header = &mut header[..header_length];
        let header_bytes = read_to_end_of_buffer(&mut reader, &mut header[MAGIC_LENGTH..])
            .map_err(|source| io_error("read frame header", path, source))?;
        if MAGIC_LENGTH + header_bytes < header_length {
            break;
        }

        let parsed = cursor.read_header(header, limits)?;
        let mut body = vec![0_u8; parsed.body_length()];
        let body_bytes = read_to_end_of_buffer(&mut reader, &mut body)
            .map_err(|source| io_error("read frame body", path, source))?;
        if body_bytes < parsed.body_length() {
            break;
        }

        records.push(cursor.accept(header, &parsed, &body, limits)?);
    }

    if reader.limit() != 0 {
        return Err(io_error(
            "read captured prefix",
            path,
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "journal ended before its captured length",
            ),
        ));
    }

    Ok(RecoveryReport {
        records,
        valid_bytes: cursor.offset(),
        discarded_torn_bytes: file_length.saturating_sub(cursor.offset()),
    })
}

fn read_to_end_of_buffer(reader: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let bytes = reader.read(&mut buffer[filled..])?;
        if bytes == 0 {
            break;
        }
        filled += bytes;
    }
    Ok(filled)
}

fn open_private(path: &Path) -> Result<(File, bool), JournalError> {
    let common = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mode = Mode::RUSR | Mode::WUSR;
    let created = match rustix::fs::open(path, common | OFlags::CREATE | OFlags::EXCL, mode) {
        Ok(file) => {
            rustix::fs::fchmod(&file, mode)
                .map_err(|source| io_error("set private permissions", path, source.into()))?;
            return Ok((File::from(file), true));
        }
        Err(error) if error == rustix::io::Errno::EXIST => false,
        Err(source) => return Err(io_error("create", path, source.into())),
    };

    let file = rustix::fs::open(path, common, Mode::empty())
        .map_err(|source| io_error("open", path, source.into()))?;
    Ok((File::from(file), created))
}

fn open_read_only(path: &Path) -> Result<File, JournalError> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let file = rustix::fs::open(path, flags, Mode::empty())
        .map_err(|source| io_error("open read-only", path, source.into()))?;
    Ok(File::from(file))
}

fn validate_private_regular_file(file: &File, path: &Path) -> Result<(), JournalError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read metadata", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(JournalError::Limit(format!(
            "journal path {} is not a regular file",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(JournalError::Limit(format!(
            "journal path {} grants group or other permissions",
            path.display()
        )));
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().ok_or_else(|| {
        JournalError::Limit(format!("journal path {} has no parent", path.display()))
    })?;
    let directory = File::open(parent)
        .map_err(|source| io_error("open containing directory", parent, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync containing directory", parent, source))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> JournalError {
    JournalError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[path = "file/observation_tests.rs"]
mod observation_tests;

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::fs::{self, OpenOptions};
    use tempfile::TempDir;

    use super::*;
    use crate::journal::frame::{encode_legacy, reseal_frame, reseal_header};

    const HEADER_LENGTH: usize = FrameFormat::CURRENT.header_length();

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestEvent {
        state: String,
        attempt: u32,
    }

    impl JournalPayload for TestEvent {
        fn validate_for_journal(&self, limits: JournalLimits) -> Result<(), JournalError> {
            if self.state.len() > limits.max_string_bytes {
                return Err(JournalError::Limit(
                    "test event state exceeds the string limit".to_string(),
                ));
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SchemaEvent {
        schema: String,
    }

    impl JournalPayload for SchemaEvent {
        fn validate_for_journal(&self, _limits: JournalLimits) -> Result<(), JournalError> {
            if self.schema == "schema-v1" {
                Ok(())
            } else {
                Err(JournalError::Limit(
                    "schema event has an unsupported discriminator".to_string(),
                ))
            }
        }
    }

    fn event(state: &str, attempt: u32) -> TestEvent {
        TestEvent {
            state: state.to_string(),
            attempt,
        }
    }

    #[test]
    fn lock_ends_with_owner_even_when_a_descriptor_is_inherited() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("execution.journal");
        let limits = JournalLimits::default();
        let opened = FileJournal::<TestEvent>::open(&path, limits).unwrap();
        let inherited = opened.journal.file.0.try_clone().unwrap();
        assert!(FileJournal::<TestEvent>::open(&path, limits).is_err());

        drop(opened);
        let reopened = FileJournal::<TestEvent>::open(&path, limits).unwrap();
        drop(reopened);

        read_locked_file::<TestEvent>(inherited.try_clone().unwrap(), &path, limits).unwrap();
        // The inherited descriptor remains open across both ownership scopes.
        // It must not keep either writer or inspection locks alive.
        let _writer = FileJournal::<TestEvent>::open(&path, limits).unwrap();
        drop(inherited);
    }

    #[test]
    fn append_is_recovered_with_sequence_numbers() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;

        let first = journal.append(&event("intent", 1))?;
        let second = journal.append(&event("completed", 1))?;
        drop(journal);

        let reopened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        assert_eq!(reopened.recovery.discarded_torn_bytes(), 0);
        assert_eq!(reopened.recovery.records().len(), 2);
        assert_eq!(first.sequence(), 1);
        assert_eq!(second.sequence(), 2);
        assert_eq!(reopened.recovery.records()[0].sequence(), 1);
        assert_eq!(reopened.recovery.records()[1].sequence(), 2);
        assert_eq!(
            reopened.recovery.records()[1].body(),
            &event("completed", 1)
        );
        Ok(())
    }

    #[test]
    fn recovery_discards_only_a_torn_final_frame() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        journal.append(&event("intent", 1))?;
        journal.append(&event("completed", 1))?;
        drop(journal);

        let complete_length = fs::metadata(&path)?.len();
        let torn_length = complete_length - 7;
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(torn_length)?;

        let reopened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        assert_eq!(reopened.recovery.records().len(), 1);
        assert!(reopened.recovery.discarded_torn_bytes() > 0);
        assert_eq!(fs::metadata(&path)?.len(), reopened.recovery.valid_bytes());
        assert_eq!(reopened.recovery.records()[0].body(), &event("intent", 1));
        Ok(())
    }

    #[test]
    fn locked_read_reports_a_torn_tail_without_repairing_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        journal.append(&event("intent", 1))?;
        journal.append(&event("completed", 1))?;
        drop(journal);

        let complete_length = fs::metadata(&path)?.len();
        let torn_length = complete_length - 7;
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(torn_length)?;

        let snapshot =
            FileJournal::<TestEvent>::read_locked(&path, JournalLimits::default())?.into_snapshot();
        assert_eq!(snapshot.records().len(), 1);
        assert_eq!(snapshot.records()[0].body(), &event("intent", 1));
        assert!(snapshot.incomplete_tail_bytes() > 0);
        assert_eq!(
            snapshot.verified_bytes() + snapshot.incomplete_tail_bytes(),
            torn_length
        );
        assert_eq!(fs::metadata(&path)?.len(), torn_length);
        Ok(())
    }

    #[test]
    fn locked_read_never_creates_a_missing_journal() {
        let directory = TempDir::new().expect("temporary directory must exist");
        let path = directory.path().join("missing.journal");

        let error = FileJournal::<TestEvent>::read_locked(&path, JournalLimits::default())
            .err()
            .expect("inspection must require an existing journal");

        assert!(matches!(
            error,
            JournalError::Io {
                operation: "open read-only",
                ..
            }
        ));
        assert!(!path.exists());
    }

    #[test]
    fn locked_read_rejects_a_fifo_without_waiting_for_a_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        rustix::fs::mkfifoat(rustix::fs::CWD, &path, Mode::RUSR | Mode::WUSR)?;

        let error = FileJournal::<TestEvent>::read_locked(&path, JournalLimits::default())
            .err()
            .expect("a FIFO must fail regular-file validation");

        assert!(matches!(error, JournalError::Limit(_)));
        Ok(())
    }

    #[test]
    fn recovery_preserves_a_complete_corrupt_frame() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        journal.append(&event("intent", 1))?;
        drop(journal);

        let complete_length = fs::metadata(&path)?.len();
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::End(-1))?;
        let mut final_byte = [0_u8; 1];
        file.read_exact(&mut final_byte)?;
        file.seek(SeekFrom::End(-1))?;
        file.write_all(&[final_byte[0] ^ 1])?;
        file.sync_all()?;
        drop(file);

        let snapshot_error = FileJournal::<TestEvent>::read_locked(&path, JournalLimits::default())
            .err()
            .expect("read-only inspection must report a corrupt complete frame");
        assert!(matches!(snapshot_error, JournalError::Corrupt { .. }));
        assert_eq!(fs::metadata(&path)?.len(), complete_length);

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("a complete frame with changed body bytes must be corruption");
        assert!(matches!(error, JournalError::Corrupt { .. }));
        assert_eq!(fs::metadata(&path)?.len(), complete_length);
        Ok(())
    }

    #[test]
    fn body_limits_apply_before_an_append() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let limits = JournalLimits {
            max_body_bytes: 24,
            ..JournalLimits::default()
        };
        let opened = FileJournal::<TestEvent>::open(&path, limits)?;
        let mut journal = opened.journal;

        let error = journal
            .append(&event("a state name that exceeds the frame limit", 1))
            .expect_err("oversized event must be rejected before writing");
        assert!(matches!(error, JournalError::Limit(_)));
        assert_eq!(fs::metadata(&path)?.len(), 0);
        Ok(())
    }

    #[test]
    fn writer_lock_excludes_recovery_and_another_writer() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let first = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("an active writer must exclude recovery and another writer");
        assert!(matches!(
            error,
            JournalError::Io {
                operation: "acquire exclusive lock",
                ..
            }
        ));
        drop(first);

        assert!(FileJournal::<TestEvent>::open(&path, JournalLimits::default()).is_ok());
        Ok(())
    }

    #[test]
    fn writer_lock_excludes_a_racing_locked_read() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let writer = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;

        let error = FileJournal::<TestEvent>::read_locked(&path, JournalLimits::default())
            .err()
            .expect("inspection must not race an active writer");

        assert!(matches!(
            error,
            JournalError::Io {
                operation: "acquire shared lock",
                ..
            }
        ));
        drop(writer);
        Ok(())
    }

    #[test]
    fn new_journal_has_private_permissions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;

        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        drop(opened);
        Ok(())
    }

    #[test]
    fn existing_journal_with_broad_permissions_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        fs::write(&path, [])?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("protected execution data must not be group-readable");
        assert!(matches!(error, JournalError::Limit(_)));
        Ok(())
    }

    #[test]
    fn complete_frame_with_invalid_body_invariants_is_preserved()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<SchemaEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        journal.append(&SchemaEvent {
            schema: "schema-v1".to_string(),
        })?;
        drop(journal);
        let complete_length = fs::metadata(&path)?.len();

        rewrite_body_same_length(&path, b"schema-v1", b"schema-x1")?;
        let error = FileJournal::<SchemaEvent>::open(&path, JournalLimits::default())
            .expect_err("a complete frame with an unsupported schema must be corrupt");
        assert!(matches!(error, JournalError::Corrupt { .. }));
        assert_eq!(fs::metadata(&path)?.len(), complete_length);
        Ok(())
    }

    #[test]
    fn changed_final_length_is_corruption_instead_of_a_torn_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = one_record_journal(&directory)?;
        let complete_length = fs::metadata(&path)?.len();
        rewrite_header(&path, false, |header| {
            let mut encoded_length = [0_u8; 4];
            encoded_length.copy_from_slice(&header[12..16]);
            let increased_length = u32::from_be_bytes(encoded_length).saturating_add(1);
            header[12..16].copy_from_slice(&increased_length.to_be_bytes());
        })?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("a changed body length must fail its header checksum");
        assert!(matches!(error, JournalError::Corrupt { .. }));
        assert_eq!(fs::metadata(&path)?.len(), complete_length);
        Ok(())
    }

    #[test]
    fn changed_sequence_is_corruption_even_with_a_valid_header_checksum()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = one_record_journal(&directory)?;
        rewrite_header(&path, true, |header| header[23] ^= 1)?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("an unexpected sequence must be corrupt");
        assert!(matches!(error, JournalError::Corrupt { .. }));
        Ok(())
    }

    #[test]
    fn appended_frames_use_the_current_header_layout() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = one_record_journal(&directory)?;
        let bytes = fs::read(&path)?;

        assert_eq!(&bytes[..8], b"AOSJNL2\n");
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 2);
        let body_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(bytes.len(), HEADER_LENGTH + usize::try_from(body_length)?);
        assert_eq!(HEADER_LENGTH, 88);
        Ok(())
    }

    #[test]
    fn legacy_journal_is_recovered_and_continues_in_the_current_format()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let legacy = write_legacy_journal(&path, &[event("intent", 1), event("started", 1)])?;

        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        assert_eq!(opened.recovery.records().len(), 2);
        assert_eq!(opened.recovery.records()[1].body(), &event("started", 1));
        assert_eq!(opened.recovery.discarded_torn_bytes(), 0);
        let mut journal = opened.journal;
        assert_eq!(journal.append(&event("completed", 1))?.sequence(), 3);
        drop(journal);

        let bytes = fs::read(&path)?;
        assert_eq!(&bytes[..legacy.len()], legacy.as_slice());
        assert_eq!(&bytes[legacy.len()..legacy.len() + 8], b"AOSJNL2\n");
        let reopened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        let bodies: Vec<_> = reopened
            .recovery
            .records()
            .iter()
            .map(|record| record.body().clone())
            .collect();
        assert_eq!(
            bodies,
            [
                event("intent", 1),
                event("started", 1),
                event("completed", 1)
            ]
        );
        Ok(())
    }

    #[test]
    fn legacy_torn_tail_is_repaired_using_the_legacy_header_length()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let first_frame = encode_legacy(&event("intent", 1), 1, None);

        // A partial legacy header that is longer than a current header, and an
        // unrecognized tail of the same length, must both remain torn tails.
        let second_frame = encode_legacy(&event("completed", 1), 2, Some(&first_frame));
        for tail in [second_frame[..100].to_vec(), vec![0_u8; 100]] {
            let mut bytes = first_frame.clone();
            bytes.extend_from_slice(&tail);
            write_private(&path, &bytes)?;

            let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
            assert_eq!(opened.recovery.records().len(), 1);
            assert_eq!(opened.recovery.discarded_torn_bytes(), 100);
            assert_eq!(
                fs::metadata(&path)?.len(),
                u64::try_from(first_frame.len())?
            );
        }
        Ok(())
    }

    #[test]
    fn legacy_frame_with_a_broken_chain_is_corruption() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let mut bytes = encode_legacy(&event("intent", 1), 1, None);
        bytes.extend_from_slice(&encode_legacy(&event("completed", 1), 2, None));
        write_private(&path, &bytes)?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("a legacy frame must continue its predecessor's digest chain");
        assert!(matches!(error, JournalError::Corrupt { sequence: 2, .. }));
        assert_eq!(fs::read(&path)?, bytes);
        Ok(())
    }

    #[test]
    fn legacy_frame_after_a_current_frame_is_corruption() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TempDir::new()?;
        let path = one_record_journal(&directory)?;
        let mut bytes = fs::read(&path)?;
        bytes.extend_from_slice(&encode_legacy(&event("completed", 1), 2, None));
        write_private(&path, &bytes)?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("a writer never returns to the legacy format");
        assert!(matches!(error, JournalError::Corrupt { sequence: 2, .. }));
        Ok(())
    }

    #[test]
    fn total_record_limit_bounds_recovery_memory() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let limits = JournalLimits {
            max_records: 1,
            ..JournalLimits::default()
        };
        let opened = FileJournal::<TestEvent>::open(&path, limits)?;
        let mut journal = opened.journal;
        journal.append(&event("intent", 1))?;

        let error = journal
            .append(&event("completed", 1))
            .expect_err("the second record must exceed the journal limit");
        assert!(matches!(error, JournalError::Limit(_)));
        Ok(())
    }

    #[test]
    fn capacity_check_reserves_future_record_slots_before_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let limits = JournalLimits {
            max_records: 4,
            ..JournalLimits::default()
        };
        let opened = FileJournal::<TestEvent>::open(&path, limits)?;
        let mut journal = opened.journal;
        journal.append(&event("planned", 0))?;

        let error = journal
            .ensure_capacity(4)
            .expect_err("dispatch must not consume more slots than remain");
        assert!(matches!(error, JournalError::Limit(_)));
        assert_eq!(
            File::open(&path)?.metadata()?.len(),
            fs::metadata(&path)?.len()
        );
        Ok(())
    }

    #[test]
    fn capacity_check_uses_maximum_frame_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let maximum_frame = u64::try_from(HEADER_LENGTH + 128)?;
        let limits = JournalLimits {
            max_body_bytes: 128,
            max_records: 4,
            max_file_bytes: maximum_frame * 2,
            ..JournalLimits::default()
        };
        let opened = FileJournal::<TestEvent>::open(&path, limits)?;
        let mut journal = opened.journal;
        journal.append(&event("planned", 0))?;
        let length_before = fs::metadata(&path)?.len();

        let error = journal
            .ensure_capacity(2)
            .expect_err("maximum outcome frames must fit before dispatch");
        assert!(matches!(error, JournalError::Limit(_)));
        assert_eq!(fs::metadata(&path)?.len(), length_before);
        Ok(())
    }

    fn one_record_journal(directory: &TempDir) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<TestEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        journal.append(&event("intent", 1))?;
        drop(journal);
        Ok(path)
    }

    fn write_legacy_journal(
        path: &Path,
        events: &[TestEvent],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        let mut previous: Option<Vec<u8>> = None;
        for (index, event) in events.iter().enumerate() {
            let frame = encode_legacy(event, u64::try_from(index + 1)?, previous.as_deref());
            bytes.extend_from_slice(&frame);
            previous = Some(frame);
        }
        write_private(path, &bytes)?;
        Ok(bytes)
    }

    fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn rewrite_header(
        path: &Path,
        refresh_checksum: bool,
        mutate: impl FnOnce(&mut [u8; HEADER_LENGTH]),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut header = [0_u8; HEADER_LENGTH];
        file.read_exact(&mut header)?;
        mutate(&mut header);
        if refresh_checksum {
            reseal_header(&mut header);
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(())
    }

    fn rewrite_body_same_length(
        path: &Path,
        from: &[u8],
        to: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(from.len(), to.len());
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let position = bytes
            .windows(from.len())
            .position(|window| window == from)
            .expect("test frame must contain the schema text");
        bytes[position..position + from.len()].copy_from_slice(to);
        reseal_frame(&mut bytes);

        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
