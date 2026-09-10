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

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_core::{
    DesiredGeneration, LocalLeaseRecord, LocalLeaseRecordCodecError, ObjectDigest,
    decode_local_lease_record, encode_local_lease_record,
};
use rustix::fs::{
    CWD, FileType, FlockOperation, Mode, OFlags, ResolveFlags, flock, fstat, fsync, open, openat,
    openat2, renameat, unlinkat,
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
const SYSTEMD_PUBLIC_STATE_PREFIX: &str = "/var/lib/aos/lease-guards";
const SYSTEMD_PUBLIC_STATE_PREFIX_RELATIVE: &str = "var/lib/aos/lease-guards";
const SYSTEMD_PRIVATE_STATE_PREFIX_RELATIVE: &str = "var/lib/private/aos/lease-guards";
const SYSTEMD_ADMINISTRATOR_UID: u32 = 0;

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
    /// Opens an assignment-private state directory without following a symlink
    /// in the final path component.
    ///
    /// Ancestor components retain ordinary path-resolution semantics. This API
    /// does not support systemd `DynamicUser=` state directories, which are
    /// intentionally exposed through a final symlink; the Guardian runtime
    /// validates that managed topology through its dedicated startup path.
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
        Self::initialize(directory, StateDirectoryPolicy::Generic)
    }

    /// Opens the exact systemd-managed state directory for one incarnation.
    ///
    /// The supplied path must byte-for-byte equal the lowercase incarnation
    /// path below `/var/lib/aos/lease-guards`. Resolution starts from a retained
    /// descriptor for `/`: every ancestor is root-owned and not group- or
    /// other-writable, the public final component is a root-owned symlink, and
    /// the corresponding `/var/lib/private` path is independently resolved
    /// without following symlinks. Both paths must resolve to the same directory
    /// inode, owned by the current guardian UID with exact mode 0700.
    ///
    /// Mount crossings are permitted because systemd bind-mounts the private
    /// state directory inside the service mount namespace. Every resolution
    /// still requires `openat2` beneath/no-magic-link enforcement; kernels or
    /// sandboxes that cannot enforce it are rejected without a fallback.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianStateStoreError`] for a path mismatch, unsupported
    /// protected resolution, insecure systemd topology, locking, or I/O failure.
    pub(crate) fn open_systemd_managed(
        path: impl AsRef<Path>,
        expected_incarnation: [u8; 16],
    ) -> Result<Self, GuardianStateStoreError> {
        let expected_path = systemd_managed_state_path(expected_incarnation);
        if expected_incarnation == [0; 16]
            || path.as_ref().as_os_str().as_bytes() != expected_path.as_os_str().as_bytes()
        {
            return Err(GuardianStateStoreError::UnexpectedManagedDirectory);
        }

        let root = openat2(
            CWD,
            "/",
            strict_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(managed_open_error)?;
        let incarnation = hex::encode(expected_incarnation);
        let public_relative =
            PathBuf::from(SYSTEMD_PUBLIC_STATE_PREFIX_RELATIVE).join(&incarnation);
        let private_relative =
            PathBuf::from(SYSTEMD_PRIVATE_STATE_PREFIX_RELATIVE).join(incarnation);
        let current_uid = rustix::process::geteuid().as_raw();
        let directory = open_systemd_managed_at(
            root.as_fd(),
            &public_relative,
            &private_relative,
            SYSTEMD_ADMINISTRATOR_UID,
            current_uid,
        )?;

        Self::initialize(directory, StateDirectoryPolicy::SystemdManaged)
    }

    fn initialize(
        directory: OwnedFd,
        policy: StateDirectoryPolicy,
    ) -> Result<Self, GuardianStateStoreError> {
        validate_state_directory(&directory, policy)?;

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
    /// The systemd-managed state path does not match the expected incarnation.
    #[error("guardian systemd state path does not match the expected incarnation")]
    UnexpectedManagedDirectory,
    /// The systemd-managed public/private directory topology is insecure.
    #[error("guardian systemd state directory topology is insecure")]
    InsecureManagedDirectory,
    /// The kernel cannot enforce the managed directory resolution policy.
    #[error("guardian systemd state opening requires supported, permitted openat2 resolution")]
    UnsupportedManagedOpen,
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

#[derive(Clone, Copy)]
enum StateDirectoryPolicy {
    Generic,
    SystemdManaged,
}

pub(crate) fn systemd_managed_state_path(expected_incarnation: [u8; 16]) -> PathBuf {
    PathBuf::from(SYSTEMD_PUBLIC_STATE_PREFIX).join(hex::encode(expected_incarnation))
}

fn open_systemd_managed_at(
    root: BorrowedFd<'_>,
    public_relative: &Path,
    private_relative: &Path,
    administrator_uid: u32,
    guardian_uid: u32,
) -> Result<OwnedFd, GuardianStateStoreError> {
    validate_administrative_directory(root, administrator_uid)?;

    let public_components = managed_relative_components(public_relative)?;
    let (public_name, public_ancestors) = public_components
        .split_last()
        .ok_or(GuardianStateStoreError::InsecureManagedDirectory)?;
    let public_parent = walk_administrative_directories(root, public_ancestors, administrator_uid)?;
    let public_link = openat2(
        &public_parent,
        *public_name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(managed_open_error)?;
    validate_public_symlink(&public_link, administrator_uid)?;

    // Resolve the public link from the retained namespace root. Its relative
    // target may contain `..`, but BENEATH prevents it from escaping `/` and
    // NO_MAGICLINKS excludes procfs-style descriptor indirection.
    let public_target = resolve_public_directory(root, public_relative)?;

    let private_components = managed_relative_components(private_relative)?;
    let (private_name, private_ancestors) = private_components
        .split_last()
        .ok_or(GuardianStateStoreError::InsecureManagedDirectory)?;
    let private_parent =
        walk_administrative_directories(root, private_ancestors, administrator_uid)?;
    let private_directory = openat2(
        &private_parent,
        *private_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(managed_open_error)?;
    validate_managed_state_directory(&private_directory, guardian_uid)?;

    let public_metadata = fstat(&public_target).map_err(GuardianStateStoreError::Io)?;
    let private_metadata = fstat(&private_directory).map_err(GuardianStateStoreError::Io)?;
    if public_metadata.st_dev != private_metadata.st_dev
        || public_metadata.st_ino != private_metadata.st_ino
    {
        return Err(GuardianStateStoreError::InsecureManagedDirectory);
    }

    Ok(private_directory)
}

fn resolve_public_directory(
    root: BorrowedFd<'_>,
    public_relative: &Path,
) -> Result<OwnedFd, GuardianStateStoreError> {
    openat2(
        root,
        public_relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(managed_open_error)
}

fn managed_relative_components(path: &Path) -> Result<Vec<&OsStr>, GuardianStateStoreError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.first() == Some(&b'/') {
        return Err(GuardianStateStoreError::InsecureManagedDirectory);
    }

    bytes
        .split(|byte| *byte == b'/')
        .map(|component| {
            if component.is_empty()
                || component == b"."
                || component == b".."
                || component.contains(&0)
            {
                Err(GuardianStateStoreError::InsecureManagedDirectory)
            } else {
                Ok(OsStr::from_bytes(component))
            }
        })
        .collect()
}

fn walk_administrative_directories(
    root: BorrowedFd<'_>,
    components: &[&OsStr],
    administrator_uid: u32,
) -> Result<OwnedFd, GuardianStateStoreError> {
    let mut current = None;
    for component in components {
        let parent = current
            .as_ref()
            .map_or(root, |directory: &OwnedFd| directory.as_fd());
        let child = openat2(
            parent,
            *component,
            strict_directory_flags(),
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(managed_open_error)?;
        validate_administrative_directory(&child, administrator_uid)?;
        current = Some(child);
    }
    current.ok_or(GuardianStateStoreError::InsecureManagedDirectory)
}

fn strict_directory_flags() -> OFlags {
    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn validate_administrative_directory(
    descriptor: impl AsFd,
    administrator_uid: u32,
) -> Result<(), GuardianStateStoreError> {
    let metadata = fstat(descriptor).map_err(GuardianStateStoreError::Io)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != administrator_uid
        || metadata.st_mode & 0o022 != 0
    {
        return Err(GuardianStateStoreError::InsecureManagedDirectory);
    }
    Ok(())
}

fn validate_public_symlink(
    descriptor: impl AsFd,
    administrator_uid: u32,
) -> Result<(), GuardianStateStoreError> {
    let metadata = fstat(descriptor).map_err(GuardianStateStoreError::Io)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Symlink
        || metadata.st_uid != administrator_uid
    {
        return Err(GuardianStateStoreError::InsecureManagedDirectory);
    }
    Ok(())
}

fn validate_managed_state_directory(
    descriptor: impl AsFd,
    guardian_uid: u32,
) -> Result<(), GuardianStateStoreError> {
    let metadata = fstat(descriptor).map_err(GuardianStateStoreError::Io)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != guardian_uid
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(GuardianStateStoreError::InsecureManagedDirectory);
    }
    Ok(())
}

fn validate_state_directory(
    descriptor: &OwnedFd,
    policy: StateDirectoryPolicy,
) -> Result<(), GuardianStateStoreError> {
    let metadata = fstat(descriptor).map_err(GuardianStateStoreError::Io)?;
    let permissions_are_private = match policy {
        StateDirectoryPolicy::Generic => metadata.st_mode & 0o077 == 0,
        StateDirectoryPolicy::SystemdManaged => metadata.st_mode & 0o7777 == 0o700,
    };
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || !permissions_are_private
    {
        return Err(GuardianStateStoreError::InsecureDirectory);
    }
    Ok(())
}

fn managed_open_error(error: rustix::io::Errno) -> GuardianStateStoreError {
    if error == rustix::io::Errno::NOSYS
        || error == rustix::io::Errno::PERM
        || error == rustix::io::Errno::INVAL
    {
        GuardianStateStoreError::UnsupportedManagedOpen
    } else if error == rustix::io::Errno::LOOP
        || error == rustix::io::Errno::XDEV
        || error == rustix::io::Errno::NOTDIR
        || error == rustix::io::Errno::ISDIR
        || error == rustix::io::Errno::ACCESS
    {
        GuardianStateStoreError::InsecureManagedDirectory
    } else {
        GuardianStateStoreError::Io(error)
    }
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use rustix::fs::{Mode, OFlags, open, openat2};

    use super::{
        GuardianStateStore, GuardianStateStoreError, LOCK_FILE, NEXT_FILE, STATE_FILE,
        StateDirectoryPolicy, managed_open_error, open_systemd_managed_at,
        resolve_public_directory, strict_directory_flags, systemd_managed_state_path,
        validate_managed_state_directory, validate_public_symlink,
    };

    const INCARNATION: [u8; 16] = [0xab; 16];
    const INCARNATION_HEX: &str = "abababababababababababababababab";

    struct ManagedFixture {
        _temporary: tempfile::TempDir,
        root: OwnedFd,
        root_path: PathBuf,
        public_relative: PathBuf,
        private_relative: PathBuf,
        public_path: PathBuf,
        private_path: PathBuf,
    }

    impl ManagedFixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir()
                .unwrap_or_else(|error| panic!("cannot create managed-state fixture: {error}"));
            set_mode(temporary.path(), 0o700);

            for relative in [
                "var",
                "var/lib",
                "var/lib/aos",
                "var/lib/aos/lease-guards",
                "var/lib/private",
                "var/lib/private/aos",
                "var/lib/private/aos/lease-guards",
            ] {
                let directory = temporary.path().join(relative);
                fs::create_dir_all(&directory).unwrap_or_else(|error| {
                    panic!("cannot create managed-state ancestor {directory:?}: {error}")
                });
                set_mode(&directory, 0o755);
            }

            let public_relative = PathBuf::from("var/lib/aos/lease-guards").join(INCARNATION_HEX);
            let private_relative =
                PathBuf::from("var/lib/private/aos/lease-guards").join(INCARNATION_HEX);
            let public_path = temporary.path().join(&public_relative);
            let private_path = temporary.path().join(&private_relative);
            fs::create_dir(&private_path).unwrap_or_else(|error| {
                panic!("cannot create managed private directory {private_path:?}: {error}")
            });
            set_mode(&private_path, 0o700);
            symlink(
                format!("../../private/aos/lease-guards/{INCARNATION_HEX}"),
                &public_path,
            )
            .unwrap_or_else(|error| panic!("cannot create managed public symlink: {error}"));

            let root = open(temporary.path(), strict_directory_flags(), Mode::empty())
                .unwrap_or_else(|error| panic!("cannot open managed fixture root: {error}"));
            let root_path = temporary.path().to_owned();
            Self {
                _temporary: temporary,
                root,
                root_path,
                public_relative,
                private_relative,
                public_path,
                private_path,
            }
        }

        fn open_directory(&self) -> Result<OwnedFd, GuardianStateStoreError> {
            let uid = rustix::process::geteuid().as_raw();
            open_systemd_managed_at(
                self.root.as_fd(),
                &self.public_relative,
                &self.private_relative,
                uid,
                uid,
            )
        }

        fn replace_public_link(&self, target: impl AsRef<Path>) {
            fs::remove_file(&self.public_path)
                .unwrap_or_else(|error| panic!("cannot remove managed public symlink: {error}"));
            symlink(target, &self.public_path)
                .unwrap_or_else(|error| panic!("cannot replace managed public symlink: {error}"));
        }
    }

    #[test]
    fn systemd_managed_path_is_exact_lowercase_incarnation_path() {
        assert_eq!(
            systemd_managed_state_path(INCARNATION),
            Path::new("/var/lib/aos/lease-guards/abababababababababababababababab")
        );
    }

    #[test]
    fn managed_opener_rejects_path_normalization_and_zero_incarnations_before_io() {
        let normalized = Path::new("/var/lib/aos/lease-guards/./abababababababababababababababab");
        assert!(matches!(
            GuardianStateStore::open_systemd_managed(normalized, INCARNATION),
            Err(GuardianStateStoreError::UnexpectedManagedDirectory)
        ));
        assert!(matches!(
            GuardianStateStore::open_systemd_managed(
                "/var/lib/aos/lease-guards/00000000000000000000000000000000",
                [0; 16],
            ),
            Err(GuardianStateStoreError::UnexpectedManagedDirectory)
        ));
    }

    #[test]
    fn managed_layout_opens_the_independently_resolved_private_inode() {
        let fixture = ManagedFixture::new();
        fs::write(fixture.private_path.join(NEXT_FILE), b"stale")
            .unwrap_or_else(|error| panic!("cannot create stale next file: {error}"));

        let directory = fixture
            .open_directory()
            .unwrap_or_else(|error| panic!("managed layout was rejected: {error}"));
        let store = GuardianStateStore::initialize(directory, StateDirectoryPolicy::SystemdManaged)
            .unwrap_or_else(|error| panic!("managed store initialization failed: {error}"));

        assert!(!fixture.private_path.join(NEXT_FILE).exists());
        assert!(fixture.private_path.join(LOCK_FILE).is_file());
        assert_eq!(
            store
                .load()
                .unwrap_or_else(|error| panic!("load failed: {error}")),
            None
        );
    }

    #[test]
    fn managed_layout_rejects_a_public_link_to_the_wrong_directory() {
        let fixture = ManagedFixture::new();
        let other = fixture
            .root_path
            .join("var/lib/private/aos/lease-guards/other");
        fs::create_dir(&other)
            .unwrap_or_else(|error| panic!("cannot create alternate private directory: {error}"));
        set_mode(&other, 0o700);
        fixture.replace_public_link("../../private/aos/lease-guards/other");

        assert!(matches!(
            fixture.open_directory(),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    #[test]
    fn managed_layout_rejects_an_absolute_public_link_target() {
        let fixture = ManagedFixture::new();
        fixture.replace_public_link(&fixture.private_path);

        assert!(matches!(
            fixture.open_directory(),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    #[test]
    fn managed_layout_rejects_a_non_symlink_public_component() {
        let fixture = ManagedFixture::new();
        fs::remove_file(&fixture.public_path)
            .unwrap_or_else(|error| panic!("cannot remove public link: {error}"));
        fs::create_dir(&fixture.public_path)
            .unwrap_or_else(|error| panic!("cannot create public directory: {error}"));
        set_mode(&fixture.public_path, 0o700);

        assert!(matches!(
            fixture.open_directory(),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    #[test]
    fn managed_layout_rejects_nonexact_private_modes() {
        let fixture = ManagedFixture::new();

        for mode in [0o600, 0o750, 0o1700] {
            set_mode(&fixture.private_path, mode);
            assert!(matches!(
                fixture.open_directory(),
                Err(GuardianStateStoreError::InsecureManagedDirectory)
            ));
        }
    }

    #[test]
    fn managed_layout_rejects_a_group_writable_administrative_ancestor() {
        let fixture = ManagedFixture::new();
        set_mode(&fixture.root_path.join("var/lib/aos"), 0o775);

        assert!(matches!(
            fixture.open_directory(),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    #[test]
    fn managed_layout_rejects_wrong_administrator_and_guardian_owners() {
        let fixture = ManagedFixture::new();
        let uid = rustix::process::geteuid().as_raw();
        let wrong_uid = if uid == 0 { 1 } else { 0 };

        assert!(matches!(
            open_systemd_managed_at(
                fixture.root.as_fd(),
                &fixture.public_relative,
                &fixture.private_relative,
                wrong_uid,
                uid,
            ),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
        assert!(matches!(
            open_systemd_managed_at(
                fixture.root.as_fd(),
                &fixture.public_relative,
                &fixture.private_relative,
                uid,
                wrong_uid,
            ),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    #[test]
    fn managed_layout_rejects_a_procfs_magic_link() {
        let temporary = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("cannot create magic-link target: {error}"));
        let target = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("cannot open magic-link target: {error}"));
        let root = open("/", strict_directory_flags(), Mode::empty())
            .unwrap_or_else(|error| panic!("cannot open namespace root: {error}"));
        let magic_link = PathBuf::from(format!("proc/self/fd/{}", target.as_raw_fd()));

        assert!(matches!(
            resolve_public_directory(root.as_fd(), &magic_link),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    #[test]
    fn managed_directory_validation_precedes_lock_and_stale_file_effects() {
        let fixture = ManagedFixture::new();
        let stale = fixture.private_path.join(NEXT_FILE);
        fs::write(&stale, b"must remain")
            .unwrap_or_else(|error| panic!("cannot create stale next file: {error}"));
        set_mode(&fixture.private_path, 0o750);
        let directory = open(
            &fixture.private_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("cannot open insecure private directory: {error}"));

        assert!(matches!(
            GuardianStateStore::initialize(directory, StateDirectoryPolicy::SystemdManaged),
            Err(GuardianStateStoreError::InsecureDirectory)
        ));
        assert_eq!(
            fs::read(&stale).unwrap_or_else(|error| panic!("stale file was removed: {error}")),
            b"must remain"
        );
        assert!(!fixture.private_path.join(LOCK_FILE).exists());
    }

    #[test]
    fn managed_store_rejects_symlinked_child_files() {
        let fixture = ManagedFixture::new();
        symlink("lock-target", fixture.private_path.join(LOCK_FILE))
            .unwrap_or_else(|error| panic!("cannot create lock symlink: {error}"));
        let directory = fixture
            .open_directory()
            .unwrap_or_else(|error| panic!("managed layout was rejected: {error}"));
        assert!(
            GuardianStateStore::initialize(directory, StateDirectoryPolicy::SystemdManaged)
                .is_err()
        );

        fs::remove_file(fixture.private_path.join(LOCK_FILE))
            .unwrap_or_else(|error| panic!("cannot remove lock symlink: {error}"));
        let directory = fixture
            .open_directory()
            .unwrap_or_else(|error| panic!("managed layout was rejected: {error}"));
        let store = GuardianStateStore::initialize(directory, StateDirectoryPolicy::SystemdManaged)
            .unwrap_or_else(|error| panic!("managed store initialization failed: {error}"));
        symlink("state-target", fixture.private_path.join(STATE_FILE))
            .unwrap_or_else(|error| panic!("cannot create state symlink: {error}"));
        assert!(store.load().is_err());
    }

    #[test]
    fn managed_open_errors_fail_closed_without_an_openat2_fallback() {
        for error in [
            rustix::io::Errno::NOSYS,
            rustix::io::Errno::PERM,
            rustix::io::Errno::INVAL,
        ] {
            assert!(matches!(
                managed_open_error(error),
                GuardianStateStoreError::UnsupportedManagedOpen
            ));
        }
        assert!(matches!(
            managed_open_error(rustix::io::Errno::LOOP),
            GuardianStateStoreError::InsecureManagedDirectory
        ));
    }

    #[test]
    fn public_symlink_and_private_directory_owner_checks_are_exact() {
        let fixture = ManagedFixture::new();
        let uid = rustix::process::geteuid().as_raw();
        let wrong_uid = if uid == 0 { 1 } else { 0 };
        let public_parent = open(
            fixture.root_path.join("var/lib/aos/lease-guards"),
            strict_directory_flags(),
            Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("cannot open public parent: {error}"));
        let public_link = openat2(
            &public_parent,
            INCARNATION_HEX,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .unwrap_or_else(|error| panic!("cannot open public link itself: {error}"));
        let private_directory = open(
            &fixture.private_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("cannot open private directory: {error}"));

        assert!(validate_public_symlink(&public_link, uid).is_ok());
        assert!(matches!(
            validate_public_symlink(&public_link, wrong_uid),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
        assert!(validate_managed_state_directory(&private_directory, uid).is_ok());
        assert!(matches!(
            validate_managed_state_directory(&private_directory, wrong_uid),
            Err(GuardianStateStoreError::InsecureManagedDirectory)
        ));
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .unwrap_or_else(|error| panic!("cannot set mode {mode:o} on {path:?}: {error}"));
    }
}
