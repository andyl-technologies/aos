//! Durable guardian authority state and readiness type-state.
//!
//! The fixed-width local record is committed by write, file `fsync`, rename,
//! directory `fsync`, and exact readback. Its integrity digest detects damage;
//! it is never treated as authority without rechecking the same signed plan
//! and lease against a fresh paired clock.
//!
//! ```text
//! authority-state :=
//!   magic[8] || version:u16 || plan-digest[32] || desired-generation:u64 ||
//!   plan-expiry:i64 || effective-boottime-deadline:u64 ||
//!   local-lease-record[234] || integrity-digest[32]
//! ```

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::{
    DesiredGeneration, LocalLeaseRecord, LocalLeaseRecordCodecError, ObjectDigest,
    decode_local_lease_record, encode_local_lease_record,
};
use rustix::fs::{
    FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, open, openat, renameat, unlinkat,
};
use sha2::{Digest as _, Sha256};

use crate::PendingGuardianState;

const STATE_FILE: &str = "authority-state";
const NEXT_FILE: &str = "authority-state.next";
const LOCK_FILE: &str = "authority-state.lock";
const STATE_MAGIC: &[u8; 8] = b"AOSGLR\0\0";
const STATE_VERSION: u16 = 1;
const LOCAL_LEASE_RECORD_BYTES: usize = 234;
const STATE_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 8 + LOCAL_LEASE_RECORD_BYTES + 32;
const STATE_INTEGRITY_DOMAIN: &[u8] = b"aos-guardian-local-state-v1\0";

/// Stores the complete boot-local authority needed to recover one guardian.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianState {
    plan_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    plan_expires_seconds: i64,
    deadline_boottime_nanoseconds: u64,
    local_lease: LocalLeaseRecord,
    integrity_digest: ObjectDigest,
}

impl GuardianState {
    pub(crate) fn new(
        plan_digest: ObjectDigest,
        desired_generation: DesiredGeneration,
        plan_expires_seconds: i64,
        deadline_boottime_nanoseconds: u64,
        local_lease: LocalLeaseRecord,
    ) -> Result<Self, GuardianStateCodecError> {
        if plan_digest.as_bytes() == &[0; 32]
            || desired_generation.get() == 0
            || plan_expires_seconds <= 0
            || deadline_boottime_nanoseconds == 0
            || deadline_boottime_nanoseconds > local_lease.fail_stop_boottime_nanoseconds()
        {
            return Err(GuardianStateCodecError::InvalidSemantics);
        }
        let mut state = Self {
            plan_digest,
            desired_generation,
            plan_expires_seconds,
            deadline_boottime_nanoseconds,
            local_lease,
            integrity_digest: ObjectDigest::from_bytes([0; 32]),
        };
        state.integrity_digest = state_integrity(&state);
        Ok(state)
    }

    /// Returns the exact verified broker-plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the signed desired-state generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the signed broker-plan wall-clock expiry.
    #[must_use]
    pub const fn plan_expires_seconds(&self) -> i64 {
        self.plan_expires_seconds
    }

    /// Returns the exclusive effective `CLOCK_BOOTTIME` deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the exact accepted ownership-lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.local_lease.lease_generation()
    }

    /// Returns the accepted authority-wall-clock lease expiry.
    #[must_use]
    pub const fn authority_expires_seconds(&self) -> i64 {
        self.local_lease.authority_expires_seconds()
    }

    /// Returns the host boot identity under which the deadline was armed.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        self.local_lease.host_boot_id()
    }

    pub(crate) const fn local_lease(&self) -> &LocalLeaseRecord {
        &self.local_lease
    }

    /// Encodes the fixed-width local persistence format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let local = encode_local_lease_record(&self.local_lease);
        let mut bytes = Vec::with_capacity(STATE_BYTES);
        bytes.extend_from_slice(STATE_MAGIC);
        bytes.extend_from_slice(&STATE_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.plan_digest.as_bytes());
        bytes.extend_from_slice(&self.desired_generation.get().to_be_bytes());
        bytes.extend_from_slice(&self.plan_expires_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(&local);
        bytes.extend_from_slice(self.integrity_digest.as_bytes());
        bytes
    }

    pub(crate) fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.encode()).into())
    }

    /// Decodes and validates the exact fixed-width local persistence format.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianStateCodecError`] for framing, nested lease-record,
    /// sentinel, deadline, or integrity failure.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuardianStateCodecError> {
        if bytes.len() != STATE_BYTES {
            return Err(GuardianStateCodecError::InvalidFraming);
        }
        let mut cursor = 0;
        if take::<8>(bytes, &mut cursor)? != *STATE_MAGIC
            || u16::from_be_bytes(take::<2>(bytes, &mut cursor)?) != STATE_VERSION
        {
            return Err(GuardianStateCodecError::InvalidFraming);
        }
        let plan_digest = ObjectDigest::from_bytes(take::<32>(bytes, &mut cursor)?);
        let desired_generation =
            DesiredGeneration::new(u64::from_be_bytes(take::<8>(bytes, &mut cursor)?));
        let plan_expires_seconds = i64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let deadline_boottime_nanoseconds = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let local_lease =
            decode_local_lease_record(take_slice(bytes, &mut cursor, LOCAL_LEASE_RECORD_BYTES)?)?;
        let integrity_digest = ObjectDigest::from_bytes(take::<32>(bytes, &mut cursor)?);
        if cursor != bytes.len()
            || plan_digest.as_bytes() == &[0; 32]
            || desired_generation.get() == 0
            || plan_expires_seconds <= 0
            || deadline_boottime_nanoseconds == 0
            || deadline_boottime_nanoseconds > local_lease.fail_stop_boottime_nanoseconds()
        {
            return Err(GuardianStateCodecError::InvalidSemantics);
        }
        let state = Self {
            plan_digest,
            desired_generation,
            plan_expires_seconds,
            deadline_boottime_nanoseconds,
            local_lease,
            integrity_digest,
        };
        if state_integrity(&state) != integrity_digest {
            return Err(GuardianStateCodecError::InvalidIntegrity);
        }
        Ok(state)
    }
}

/// Reports rejection of the bounded guardian state format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuardianStateCodecError {
    /// Length, magic, version, or trailing data differs from v1.
    #[error("invalid guardian state framing")]
    InvalidFraming,
    /// The nested local ownership-lease record is invalid.
    #[error("invalid guardian ownership-lease record: {0}")]
    LocalLease(#[from] LocalLeaseRecordCodecError),
    /// A required identity, generation, expiry, or deadline is invalid.
    #[error("invalid guardian state semantics")]
    InvalidSemantics,
    /// The corruption-detection digest does not match the state bytes.
    #[error("guardian state integrity mismatch")]
    InvalidIntegrity,
}

/// Owns the protected directory containing one guardian's durable state.
pub struct GuardianStateStore {
    directory: OwnedFd,
    _lock: OwnedFd,
}

impl GuardianStateStore {
    /// Opens an assignment-private state directory without following a symlink.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianStateStoreError`] unless the directory is owned by the
    /// current unprivileged guardian identity and denies group/other access.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GuardianStateStoreError> {
        let directory = open(
            path.as_ref(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(GuardianStateStoreError::Io)?;
        let metadata = fstat(&directory).map_err(GuardianStateStoreError::Io)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_mode & 0o077 != 0
        {
            return Err(GuardianStateStoreError::InsecureDirectory);
        }
        let lock = openat(
            &directory,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(GuardianStateStoreError::Io)?;
        validate_private_regular(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| GuardianStateStoreError::Locked)?;

        // The retained exclusive lock proves that no live writer owns this
        // fixed temporary name. A prior crash may leave it behind; it is never
        // decoded or promoted as authority.
        match unlinkat(&directory, NEXT_FILE, rustix::fs::AtFlags::empty()) {
            Ok(()) => fsync(&directory).map_err(GuardianStateStoreError::Io)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(GuardianStateStoreError::Io(error)),
        }

        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    /// Loads the prior exact state, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianStateStoreError`] for insecure metadata, I/O,
    /// oversize, or codec failure. Old-boot state is returned as data only and
    /// can never produce a readiness token by itself.
    pub fn load(&self) -> Result<Option<GuardianState>, GuardianStateStoreError> {
        let Some(bytes) = self.read_named(STATE_FILE, true)? else {
            return Ok(None);
        };
        GuardianState::decode(&bytes)
            .map(Some)
            .map_err(GuardianStateStoreError::Codec)
    }

    /// Atomically persists, flushes, and exactly reads back pending authority.
    ///
    /// The returned type is the only input accepted by readiness confirmation.
    /// A failure after rename is intentionally reported as ambiguous and no
    /// readiness acknowledgement may follow.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianStateStoreError`] for any create, write, sync, rename,
    /// metadata, exact-readback, or decoding failure.
    pub fn commit(
        &mut self,
        pending: PendingGuardianState,
    ) -> Result<DurablyPersistedGuardian, GuardianStateStoreError> {
        let current = self.load()?;
        let current_digest = current.as_ref().map(GuardianState::record_digest);
        if current_digest != pending.predecessor_digest {
            return Err(GuardianStateStoreError::PredecessorMismatch);
        }
        let expected = pending.state.encode();
        let descriptor = openat(
            &self.directory,
            NEXT_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(GuardianStateStoreError::Io)?;
        let mut file = File::from(descriptor);
        file.write_all(&expected)
            .map_err(GuardianStateStoreError::StdIo)?;
        file.sync_all().map_err(GuardianStateStoreError::StdIo)?;
        drop(file);

        renameat(&self.directory, NEXT_FILE, &self.directory, STATE_FILE)
            .map_err(GuardianStateStoreError::Io)?;
        fsync(&self.directory).map_err(GuardianStateStoreError::Io)?;

        let observed = self
            .read_named(STATE_FILE, false)?
            .ok_or(GuardianStateStoreError::ReadbackMismatch)?;
        if observed != expected {
            return Err(GuardianStateStoreError::ReadbackMismatch);
        }
        let state = GuardianState::decode(&observed).map_err(GuardianStateStoreError::Codec)?;
        Ok(DurablyPersistedGuardian { state })
    }

    fn read_named(
        &self,
        name: &'static str,
        absent_is_none: bool,
    ) -> Result<Option<Vec<u8>>, GuardianStateStoreError> {
        let descriptor = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) if absent_is_none => return Ok(None),
            Err(error) => return Err(GuardianStateStoreError::Io(error)),
        };
        validate_private_regular(&descriptor)?;
        let mut bytes = Vec::with_capacity(STATE_BYTES);
        let mut file = File::from(descriptor).take((STATE_BYTES + 1) as u64);
        file.read_to_end(&mut bytes)
            .map_err(GuardianStateStoreError::StdIo)?;
        if bytes.len() != STATE_BYTES {
            return Err(GuardianStateStoreError::InvalidSize);
        }
        Ok(Some(bytes))
    }
}

/// Proves that exact guardian authority survived durable readback.
#[derive(Debug)]
pub struct DurablyPersistedGuardian {
    pub(crate) state: GuardianState,
}

impl DurablyPersistedGuardian {
    /// Returns the durably committed guardian state.
    #[must_use]
    pub const fn state(&self) -> &GuardianState {
        &self.state
    }

    /// Returns the exclusive effective `CLOCK_BOOTTIME` deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.state.deadline_boottime_nanoseconds
    }
}

/// Reports state-directory or atomic-persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum GuardianStateStoreError {
    /// A Linux descriptor-relative filesystem operation failed.
    #[error("guardian state filesystem operation failed: {0}")]
    Io(rustix::io::Errno),
    /// A standard buffered I/O operation failed.
    #[error("guardian state I/O failed: {0}")]
    StdIo(std::io::Error),
    /// The state directory is not private to the guardian identity.
    #[error("guardian state directory is not private")]
    InsecureDirectory,
    /// A state file has an unexpected type, owner, links, or permissions.
    #[error("guardian state file metadata is insecure")]
    InsecureStateFile,
    /// Another guardian process already owns the assignment state lock.
    #[error("guardian state is already locked")]
    Locked,
    /// Durable state changed since signed authority admission.
    #[error("guardian state predecessor changed before commit")]
    PredecessorMismatch,
    /// A state file does not have the one exact v1 size.
    #[error("guardian state file has the wrong size")]
    InvalidSize,
    /// Persisted state failed its bounded codec.
    #[error("guardian state decoding failed: {0}")]
    Codec(GuardianStateCodecError),
    /// Exact readback after the durability barrier differed from written bytes.
    #[error("guardian state durable readback mismatch")]
    ReadbackMismatch,
}

fn validate_private_regular(descriptor: &OwnedFd) -> Result<(), GuardianStateStoreError> {
    let metadata = fstat(descriptor).map_err(GuardianStateStoreError::Io)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o177 != 0
    {
        return Err(GuardianStateStoreError::InsecureStateFile);
    }
    Ok(())
}

fn state_integrity(state: &GuardianState) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(STATE_INTEGRITY_DOMAIN);
    hasher.update(state.plan_digest.as_bytes());
    hasher.update(state.desired_generation.get().to_be_bytes());
    hasher.update(state.plan_expires_seconds.to_be_bytes());
    hasher.update(state.deadline_boottime_nanoseconds.to_be_bytes());
    hasher.update(encode_local_lease_record(&state.local_lease));
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], GuardianStateCodecError> {
    let source = take_slice(bytes, cursor, N)?;
    let mut value = [0; N];
    value.copy_from_slice(source);
    Ok(value)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], GuardianStateCodecError> {
    let end = cursor
        .checked_add(length)
        .ok_or(GuardianStateCodecError::InvalidFraming)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(GuardianStateCodecError::InvalidFraming)?;
    *cursor = end;
    Ok(value)
}
