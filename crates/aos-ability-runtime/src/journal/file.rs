//! Linux filesystem storage for durable journal frames.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::frame::{
    HEADER_LENGTH, JournalError, JournalLimits, JournalPayload, JournalRecord, RecoveryReport,
    decode, encode, encoded_body_length,
};
use aos_contract::Sha256Digest;
use rustix::fs::{FlockOperation, Mode, OFlags};

/// A newly opened journal together with its verified recovery report.
#[derive(Debug)]
pub struct JournalOpenResult<T> {
    /// The journal positioned for the next append.
    pub journal: FileJournal<T>,
    /// The verified records and torn-tail repair details.
    pub recovery: RecoveryReport<T>,
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
    file: File,
    limits: JournalLimits,
    next_sequence: u64,
    previous_digest: Sha256Digest,
    requires_recovery: bool,
    marker: PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for FileJournal<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileJournal")
            .field("path", &self.path)
            .field("limits", &self.limits)
            .field("next_sequence", &self.next_sequence)
            .field("previous_digest", &self.previous_digest)
            .field("requires_recovery", &self.requires_recovery)
            .finish_non_exhaustive()
    }
}

impl<T> FileJournal<T>
where
    T: JournalPayload,
{
    /// Opens a journal, verifies its complete prefix, and repairs a torn tail.
    ///
    /// A partial final frame is truncated only after every preceding frame has
    /// passed sequence, digest-chain, body-digest, canonical-encoding, limits,
    /// and schema checks. A complete invalid frame is left untouched.
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
        let (mut file, created) = open_private(&path)?;
        rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|source| io_error("acquire exclusive lock", &path, source.into()))?;
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
        let previous_digest = recovery
            .records()
            .last()
            .map_or_else(zero_digest, JournalRecord::digest);

        Ok(JournalOpenResult {
            journal: Self {
                path,
                file,
                limits,
                next_sequence,
                previous_digest,
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

        let maximum_frame_bytes = HEADER_LENGTH
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

        let encoded = encode(body, self.next_sequence, self.previous_digest, self.limits)?;
        let encoded_length = u64::try_from(encoded.bytes.len()).map_err(|_| {
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
            .write_all(&encoded.bytes)
            .map_err(|source| io_error("append", &self.path, source))?;
        self.file
            .sync_all()
            .map_err(|source| io_error("sync append", &self.path, source))?;

        let record = JournalRecord {
            sequence: self.next_sequence,
            digest: encoded.digest,
            body: (),
        };
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::Limit("journal sequence number exhausted".to_string()))?;
        self.previous_digest = encoded.digest;
        self.requires_recovery = false;

        Ok(record)
    }
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
    if file_length > limits.max_file_bytes {
        return Err(JournalError::Limit(format!(
            "journal has {file_length} bytes, limit is {}",
            limits.max_file_bytes
        )));
    }

    let mut records = Vec::new();
    let mut offset = 0_u64;
    let mut expected_sequence = 1_u64;
    let mut expected_previous = zero_digest();

    loop {
        if records.len() == limits.max_records {
            if offset == file_length {
                break;
            }
            return Err(JournalError::Limit(format!(
                "journal exceeds the {} record limit",
                limits.max_records
            )));
        }

        let mut header = [0_u8; HEADER_LENGTH];
        let header_bytes = read_to_end_of_buffer(file, &mut header)
            .map_err(|source| io_error("read frame header", path, source))?;
        if header_bytes == 0 {
            break;
        }
        if header_bytes < HEADER_LENGTH {
            break;
        }

        let body_length = encoded_body_length(
            &header,
            expected_sequence,
            expected_previous,
            offset,
            limits,
        )?;
        let mut body = vec![0_u8; body_length];
        let body_bytes = read_to_end_of_buffer(file, &mut body)
            .map_err(|source| io_error("read frame body", path, source))?;
        if body_bytes < body_length {
            break;
        }

        let decoded = decode(
            &header,
            &body,
            expected_sequence,
            expected_previous,
            offset,
            limits,
        )?;
        offset = offset
            .checked_add(u64::try_from(decoded.encoded_length).map_err(|_| {
                JournalError::Limit("frame length is not representable as u64".to_string())
            })?)
            .ok_or_else(|| JournalError::Limit("journal offset overflow".to_string()))?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::Limit("journal sequence number exhausted".to_string()))?;
        expected_previous = decoded.record.digest();
        records.push(decoded.record);
    }

    Ok(RecoveryReport {
        records,
        valid_bytes: offset,
        discarded_torn_bytes: file_length.saturating_sub(offset),
    })
}

fn read_to_end_of_buffer(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let bytes = file.read(&mut buffer[filled..])?;
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

fn zero_digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0_u8; 32])
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> JournalError {
    JournalError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;
    use serde::{Deserialize, Serialize};
    use std::fs::{self, OpenOptions};
    use tempfile::TempDir;

    use super::*;
    use crate::journal::frame::{HEADER_DIGEST_DOMAIN, HEADER_LENGTH, HEADER_PREFIX_LENGTH};

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
    fn append_is_recovered_with_sequence_and_digest_chain() -> Result<(), Box<dyn std::error::Error>>
    {
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
        assert_eq!(reopened.recovery.records()[0].sequence(), 1);
        assert_eq!(reopened.recovery.records()[0].digest(), first.digest());
        assert_eq!(reopened.recovery.records()[1].sequence(), 2);
        assert_eq!(reopened.recovery.records()[1].digest(), second.digest());
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
    fn changed_previous_digest_is_corruption_even_with_a_valid_header_checksum()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = one_record_journal(&directory)?;
        rewrite_header(&path, true, |header| header[55] ^= 1)?;

        let error = FileJournal::<TestEvent>::open(&path, JournalLimits::default())
            .expect_err("an unexpected previous digest must be corrupt");
        assert!(matches!(error, JournalError::Corrupt { .. }));
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
            let digest =
                Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &header[..HEADER_PREFIX_LENGTH]);
            header[HEADER_PREFIX_LENGTH..HEADER_LENGTH].copy_from_slice(digest.as_bytes());
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

        let body_digest = Sha256Digest::separated(
            "aos.ability.execution.journal.body/v1",
            &bytes[HEADER_LENGTH..],
        );
        bytes[56..88].copy_from_slice(body_digest.as_bytes());
        let header_digest =
            Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &bytes[..HEADER_PREFIX_LENGTH]);
        bytes[HEADER_PREFIX_LENGTH..HEADER_LENGTH].copy_from_slice(header_digest.as_bytes());

        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
