//! One-shot, confined physical measurement of a Storage-held ZFS snapshot.
//!
//! The request is selected by the protected Storage owner, never by a public
//! broker method. The reader mounts only that snapshot in its private mount
//! namespace, applies read-only, nodev, nosuid, and noexec attributes while
//! detached, and returns a bounded physical measurement without a descriptor,
//! signature, or SourceRoot receipt.
//!
//! ```text
//! AOSHSR01 request = version:u16 | snapshot-guid:u64 | pool-guid:u64 |
//!                    cut-digest:32 | nonce:16 | name-length:u16 | snapshot-name
//! AOSHSM01 result  = version:u16 | request-digest:32 | content-digest:32 |
//!                    tree-digest:32 | tree-size:u64 | mount-id:u64 |
//!                    root-device:u64 | root-inode:u64 | nodes:u32 | file-bytes:u64 |
//!                    mounted-snapshot-guid:u64
//! ```

use std::fs;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::{CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketSocket};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, StatVfsMountFlags, fstat, fsync, openat, unlinkat,
};
use sha2::{Digest as _, Sha256};

use crate::ResolvedSnapshot;
use crate::held_snapshot_tree::measure_bound_detached_snapshot;
use crate::live_export_key::open_protected_directory;

use super::{
    Deadline, ZfsWorkerError, current_cgroup_path, decode_ack, decode_ready_frame, encode_ack,
    encode_ready_frame, open_cgroup_root, quiesce_worker, receive_before, send_before,
    verify_same_live_subject, verify_same_subject, verify_storaged_peer,
    verify_systemd_activation_peer, wait_for_worker_quiescence,
};

const REQUEST_MAGIC: &[u8; 8] = b"AOSHSR01";
const RESULT_MAGIC: &[u8; 8] = b"AOSHSM01";
const READY_MAGIC: &[u8; 8] = b"AOSHSRD1";
const VERSION: u16 = 1;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.storage.held-snapshot-reader.v1\0";
const SOCKET_PATH: &str = "/run/aos/sandbox-held-snapshot-reader/control.sock";
const NAMESPACE_MARKER: &str = "/run/aos-held-reader-namespace";
const TMPFS_MAGIC: u64 = 0x0102_1994;
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const READER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-held-snapshot-reader@";
const READER_UNIT_PREFIX: &str = "aos-sandbox-held-snapshot-reader@";
const READER_CGROUP_SUFFIX: &str = ".service";
const MAXIMUM_RECOVERED_READERS: usize = 128;
const RESULT_BYTES: usize = 158;
const MAXIMUM_REQUEST_BYTES: usize = 1024;
const MAXIMUM_READY_BYTES: usize = 512;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(45);
const LAUNCH_FENCE_NAME: &str = "held-snapshot-reader.launch";

/// Retains a measured byte identity and mount identity, without authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldSnapshotReaderObservationV1 {
    pub(crate) content_digest: ObjectDigest,
    pub(crate) tree_digest: ObjectDigest,
    pub(crate) tree_size: u64,
    pub(crate) mount_id: u64,
    pub(crate) root_device: u64,
    pub(crate) root_inode: u64,
    pub(crate) nodes: u32,
    pub(crate) file_bytes: u64,
    /// Zero until the mounted descriptor itself proves the immutable ZFS GUID.
    pub(crate) mounted_snapshot_guid: u64,
}

/// A single durable marker covers activation before systemd creates a cgroup.
struct HeldReaderLaunchFence {
    directory: OwnedFd,
    device: u64,
    inode: u64,
    owner_uid: u32,
}

/// Pins the claimed inode until quiescence allows exact-name retirement.
struct ClaimedReaderLaunch<'a> {
    fence: &'a HeldReaderLaunchFence,
    marker: OwnedFd,
    device: u64,
    inode: u64,
}

impl HeldReaderLaunchFence {
    fn open(path: &Path) -> Result<Self, ZfsWorkerError> {
        let anchor = open_protected_directory(path, 0).map_err(|_| ZfsWorkerError::Authority)?;
        let anchored = fstat(&anchor)?;
        let directory = openat(
            &anchor,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let readable = fstat(&directory)?;
        if (anchored.st_dev, anchored.st_ino) != (readable.st_dev, readable.st_ino) {
            return Err(ZfsWorkerError::Authority);
        }
        Ok(Self {
            directory,
            device: readable.st_dev,
            inode: readable.st_ino,
            owner_uid: 0,
        })
    }

    fn claim(&self) -> Result<ClaimedReaderLaunch<'_>, ZfsWorkerError> {
        self.claim_with_sync(|descriptor| fsync(descriptor))
    }

    fn claim_with_sync<F>(&self, mut sync: F) -> Result<ClaimedReaderLaunch<'_>, ZfsWorkerError>
    where
        F: FnMut(&OwnedFd) -> Result<(), rustix::io::Errno>,
    {
        self.validate_directory()?;
        let marker = openat(
            &self.directory,
            LAUNCH_FENCE_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                ZfsWorkerError::Quiescence("an earlier reader launch is unresolved".to_owned())
            } else {
                error.into()
            }
        })?;
        let identity = fstat(&marker)?;
        if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_uid != self.owner_uid
            || identity.st_nlink != 1
            || identity.st_mode & 0o7777 != 0o600
        {
            return Err(ZfsWorkerError::Authority);
        }
        sync(&marker)?;
        sync(&self.directory)?;
        self.validate_directory()?;
        Ok(ClaimedReaderLaunch {
            fence: self,
            marker,
            device: identity.st_dev,
            inode: identity.st_ino,
        })
    }

    fn validate_directory(&self) -> Result<(), ZfsWorkerError> {
        let identity = fstat(&self.directory)?;
        if (identity.st_dev, identity.st_ino) != (self.device, self.inode)
            || identity.st_uid != self.owner_uid
            || identity.st_mode & 0o7777 != 0o700
        {
            return Err(ZfsWorkerError::Authority);
        }
        Ok(())
    }
}

impl ClaimedReaderLaunch<'_> {
    fn retire(self) -> Result<(), ZfsWorkerError> {
        self.fence.validate_directory()?;
        let held = fstat(&self.marker)?;
        if (held.st_dev, held.st_ino) != (self.device, self.inode) {
            return Err(ZfsWorkerError::Authority);
        }
        let marker = openat(
            &self.fence.directory,
            LAUNCH_FENCE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let identity = fstat(&marker)?;
        if (identity.st_dev, identity.st_ino) != (self.device, self.inode)
            || FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_uid != self.fence.owner_uid
            || identity.st_nlink != 1
            || identity.st_mode & 0o7777 != 0o600
        {
            return Err(ZfsWorkerError::Authority);
        }
        unlinkat(&self.fence.directory, LAUNCH_FENCE_NAME, AtFlags::empty())?;
        fsync(&self.fence.directory)?;
        Ok(())
    }
}

/// Authenticates the fixed one-shot reader and proves its whole-unit exit.
pub(crate) struct SystemdHeldSnapshotReaderV1 {
    manager: RetainedCgroupAnchor,
    worker_parent: RetainedCgroupAnchor,
    launch_fence: HeldReaderLaunchFence,
    fail_stopped: bool,
}

impl SystemdHeldSnapshotReaderV1 {
    pub(crate) fn new(
        cgroup_root: CgroupV2Root,
        state_directory: &Path,
    ) -> Result<Self, ZfsWorkerError> {
        Ok(Self {
            manager: cgroup_root.resolve(Path::new("init.scope"))?,
            worker_parent: cgroup_root.resolve(Path::new("aos.slice/aos-control.slice"))?,
            launch_fence: HeldReaderLaunchFence::open(state_directory)?,
            fail_stopped: false,
        })
    }

    pub(crate) fn measure(
        &mut self,
        snapshot: &ResolvedSnapshot,
        expected_pool_guid: u64,
        protected_cut_digest: ObjectDigest,
        nonce: [u8; 16],
    ) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Quiescence(
                "held snapshot reader is fail-stopped".to_owned(),
            ));
        }
        if let Err(error) = self.prove_prior_readers_empty() {
            return fail_stop_unproved_setup(&mut self.fail_stopped, error, None);
        }
        let request = encode_request(snapshot, expected_pool_guid, protected_cut_digest, nonce)?;
        let request_digest = digest_request(&request);
        let deadline = Deadline::after(EXCHANGE_TIMEOUT);
        // The directory entry is durable before connect can queue an activation.
        // A restarted Storage cannot infer absence from an unmaterialized cgroup;
        // an unresolved entry permanently closes dispatch until explicit repair.
        let launch = self
            .launch_fence
            .claim()
            .or_else(|error| fail_stop_unproved_setup(&mut self.fail_stopped, error, None))?;
        // Peer pinning inside connect can fail after the kernel has accepted
        // the connection and systemd has begun starting a reader.
        let mut socket = SeqpacketSocket::connect(Path::new(SOCKET_PATH))
            .map_err(ZfsWorkerError::from)
            .or_else(|error| fail_stop_unproved_setup(&mut self.fail_stopped, error, None))?;
        let ready = (|| {
            socket
                .peer()
                .require_peer_filesystem_path(socket.as_fd()?, Path::new(SOCKET_PATH))?;
            verify_systemd_activation_peer(socket.peer(), &self.manager)?;
            receive_before(&mut socket, MAXIMUM_READY_BYTES, deadline)
        })()
        .or_else(|error| fail_stop_unproved_setup(&mut self.fail_stopped, error, None))?;
        let (ready_payload, reader_subject) = ready.into_parts();
        let reader_setup =
            decode_ready(&ready_payload).and_then(|path| self.verify_reader(&reader_subject, path));
        let reader_cgroup = reader_setup
            .or_else(|error| fail_stop_unproved_setup(&mut self.fail_stopped, error, None))?;
        let population = match reader_cgroup.population_monitor() {
            Ok(population) => population,
            Err(error) => {
                // This cgroup was authenticated, so cancellation can target it.
                // Without its population monitor, cancellation cannot prove
                // whole-unit exit and Storage must stop admitting attempts.
                let cancellation = reader_cgroup.kill_all();
                return fail_stop_unproved_setup(
                    &mut self.fail_stopped,
                    error.into(),
                    cancellation.err(),
                );
            }
        };
        let exchange = (|| {
            send_before(&mut socket, &request, deadline)?;
            let response = receive_before(&mut socket, RESULT_BYTES, deadline)?;
            verify_same_live_subject(&reader_subject, response.subject())?;
            reader_cgroup.verify_exact_membership(response.subject().pidfd())?;
            let measured = decode_result(response.payload(), request_digest, snapshot.guid())?;
            send_before(&mut socket, &encode_ack(), deadline)?;
            Ok(measured)
        })();

        match exchange {
            Ok(measured) => {
                if wait_for_worker_quiescence(&reader_subject, &population, Duration::from_secs(1))
                    .is_ok()
                {
                    launch.retire().or_else(|error| {
                        fail_stop_unproved_setup(&mut self.fail_stopped, error, None)
                    })?;
                    return Ok(measured);
                }
                if quiesce_worker(&reader_subject, &reader_cgroup, &population).is_err() {
                    self.fail_stopped = true;
                } else {
                    launch.retire().or_else(|error| {
                        fail_stop_unproved_setup(&mut self.fail_stopped, error, None)
                    })?;
                }
                Err(ZfsWorkerError::Quiescence(
                    "held snapshot reader did not exit cleanly".to_owned(),
                ))
            }
            Err(error) => {
                if quiesce_worker(&reader_subject, &reader_cgroup, &population).is_err() {
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(
                        "held snapshot reader cancellation was not proved".to_owned(),
                    ));
                }
                launch.retire().or_else(|error| {
                    fail_stop_unproved_setup(&mut self.fail_stopped, error, None)
                })?;
                Err(error)
            }
        }
    }

    fn prove_prior_readers_empty(&self) -> Result<(), ZfsWorkerError> {
        // This catches populated readers not represented by the launch fence.
        // The durable fence below covers accepted but unmaterialized activations.
        let directory = format!("/proc/self/fd/{}", self.worker_parent.as_fd().as_raw_fd());
        let mut reader_count = 0;
        for entry in fs::read_dir(directory)? {
            let name = entry?.file_name();
            if !name.as_bytes().starts_with(READER_UNIT_PREFIX.as_bytes()) {
                continue;
            }
            let name = name.to_str().ok_or(ZfsWorkerError::PeerMismatch)?;
            validate_reader_unit_name(name)?;
            reader_count += 1;
            if reader_count > MAXIMUM_RECOVERED_READERS {
                return Err(ZfsWorkerError::Quiescence(
                    "held snapshot reader recovery count exceeded ceiling".to_owned(),
                ));
            }

            let cgroup = self.worker_parent.resolve_descendant(Path::new(name))?;
            let population = cgroup.population_monitor()?;
            require_prior_reader_empty(population.state()?)?;
        }
        self.worker_parent.validate_current()?;
        Ok(())
    }

    fn verify_reader(
        &self,
        subject: &KernelAuthorizedRecordSubject,
        path: &str,
    ) -> Result<RetainedCgroupAnchor, ZfsWorkerError> {
        let relative = path
            .strip_prefix("aos.slice/aos-control.slice/")
            .ok_or(ZfsWorkerError::PeerMismatch)?;
        validate_reader_unit_name(relative)?;
        let cgroup = self.worker_parent.resolve_descendant(Path::new(relative))?;
        let observed = cgroup.verify_exact_membership(subject.pidfd())?;
        let credentials = subject.credentials();
        if credentials.uid() != 0
            || credentials.gid() != 0
            || observed.pid() != credentials.pid().get()
            || observed.thread_group_id() != credentials.pid().get()
        {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        self.worker_parent.validate_current()?;
        Ok(cgroup)
    }
}

fn validate_reader_unit_name(name: &str) -> Result<(), ZfsWorkerError> {
    let instance = name
        .strip_prefix(READER_UNIT_PREFIX)
        .and_then(|suffix| suffix.strip_suffix(READER_CGROUP_SUFFIX))
        .ok_or(ZfsWorkerError::PeerMismatch)?;
    if instance.is_empty() || instance.len() > 255 || instance.contains('/') {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn require_prior_reader_empty(state: CgroupPopulationState) -> Result<(), ZfsWorkerError> {
    match state {
        CgroupPopulationState::Empty | CgroupPopulationState::Retired => Ok(()),
        CgroupPopulationState::Populated => Err(ZfsWorkerError::Quiescence(
            "a prior held snapshot reader is still populated".to_owned(),
        )),
    }
}

fn fail_stop_unproved_setup<T>(
    fail_stopped: &mut bool,
    error: ZfsWorkerError,
    cancellation_error: Option<aos_sandbox_linux::Error>,
) -> Result<T, ZfsWorkerError> {
    *fail_stopped = true;
    let detail = match cancellation_error {
        Some(cancellation_error) => format!(
            "held snapshot reader setup failed before quiescence was proved: {error}; cancellation: {cancellation_error}"
        ),
        None => format!("held snapshot reader setup failed before quiescence was proved: {error}"),
    };
    Err(ZfsWorkerError::Quiescence(detail))
}

/// Runs one Storage-only reader on its inherited systemd socket.
///
/// # Errors
///
/// Rejects a missing private mount namespace, incorrect Storage peer, malformed
/// request, unsupported snapshot tree, or incomplete bounded exchange.
pub fn run_inherited_held_snapshot_reader() -> Result<(), ZfsWorkerError> {
    aos_sandbox_linux::process::disable_core_dumps()?;
    require_private_mount_namespace()?;

    let storaged = open_cgroup_root()?.resolve(Path::new(STORAGED_CGROUP))?;
    let inherited: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = SeqpacketSocket::from_owned(inherited)?;
    socket
        .peer()
        .require_local_filesystem_path(socket.as_fd()?, Path::new(SOCKET_PATH))?;
    verify_storaged_peer(socket.peer(), &storaged)?;
    socket.enable_record_subjects()?;

    let deadline = Deadline::after(EXCHANGE_TIMEOUT);
    let ready = encode_ready(&current_cgroup_path()?)?;
    send_before(&mut socket, &ready, deadline)?;
    let record = receive_before(&mut socket, MAXIMUM_REQUEST_BYTES, deadline)?;
    verify_same_subject(socket.peer(), record.subject())?;
    storaged.verify_exact_membership(record.subject().pidfd())?;
    let (snapshot_name, expected_pool_guid, expected_snapshot_guid, request_digest) =
        decode_request(record.payload())?;

    let measured =
        measure_bound_detached_snapshot(snapshot_name, expected_pool_guid, expected_snapshot_guid)
            .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
    let observation = HeldSnapshotReaderObservationV1 {
        content_digest: measured.content_digest,
        tree_digest: measured.tree.digest(),
        tree_size: measured.tree.encoded_size(),
        mount_id: measured.mount_id.get(),
        root_device: measured.root_device,
        root_inode: measured.root_inode,
        nodes: u32::try_from(measured.nodes)
            .map_err(|_| ZfsWorkerError::Protocol("measured node count exceeds wire bound"))?,
        file_bytes: u64::try_from(measured.file_bytes)
            .map_err(|_| ZfsWorkerError::Protocol("measured file bytes exceed wire bound"))?,
        // This is asserted only after the mounted root FD's UUID matched both
        // immutable GUIDs before and after the complete byte walk.
        mounted_snapshot_guid: expected_snapshot_guid,
    };
    send_before(
        &mut socket,
        &encode_result(request_digest, observation),
        deadline,
    )?;
    let acknowledgement = receive_before(&mut socket, 10, deadline)?;
    verify_same_subject(socket.peer(), acknowledgement.subject())?;
    storaged.verify_exact_membership(acknowledgement.subject().pidfd())?;
    decode_ack(acknowledgement.payload())
}

fn require_private_mount_namespace() -> Result<(), ZfsWorkerError> {
    // systemd mounts this exact marker only while constructing the service's
    // PrivateMounts namespace. PID 1's nsfs link is inaccessible under
    // ProtectProc=invisible without adding CAP_SYS_PTRACE.
    let marker = rustix::fs::open(
        NAMESPACE_MARKER,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let parent = rustix::fs::open(
        "/run",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let flags = rustix::fs::fstatvfs(&marker)?.f_flag;
    let filesystem = rustix::fs::fstatfs(&marker)?;
    if MountId::from_fd(marker.as_fd())? == MountId::from_fd(parent.as_fd())?
        || filesystem.f_type as u64 != TMPFS_MAGIC
        || !flags.contains(
            StatVfsMountFlags::RDONLY
                | StatVfsMountFlags::NOSUID
                | StatVfsMountFlags::NODEV
                | StatVfsMountFlags::NOEXEC,
        )
    {
        return Err(ZfsWorkerError::Protocol(
            "reader private mount namespace marker is invalid",
        ));
    }
    Ok(())
}

fn encode_request(
    snapshot: &ResolvedSnapshot,
    expected_pool_guid: u64,
    cut_digest: ObjectDigest,
    nonce: [u8; 16],
) -> Result<Vec<u8>, ZfsWorkerError> {
    let name = snapshot.name().as_bytes();
    validate_name(name)?;
    if snapshot.guid() == 0
        || expected_pool_guid == 0
        || cut_digest.as_bytes() == &[0; 32]
        || nonce == [0; 16]
    {
        return Err(ZfsWorkerError::Protocol(
            "reader request identity is invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(76 + name.len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&snapshot.guid().to_be_bytes());
    bytes.extend_from_slice(&expected_pool_guid.to_be_bytes());
    bytes.extend_from_slice(cut_digest.as_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(
        &u16::try_from(name.len())
            .map_err(|_| ZfsWorkerError::Protocol("snapshot name is oversized"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(name);
    Ok(bytes)
}

fn decode_request(bytes: &[u8]) -> Result<(&str, u64, u64, ObjectDigest), ZfsWorkerError> {
    if bytes.len() < 76 || bytes.len() > MAXIMUM_REQUEST_BYTES || &bytes[..8] != REQUEST_MAGIC {
        return Err(ZfsWorkerError::Protocol(
            "reader request length or magic is invalid",
        ));
    }
    if bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..18] == [0; 8]
        || bytes[18..26] == [0; 8]
        || bytes[26..58] == [0; 32]
        || bytes[58..74] == [0; 16]
    {
        return Err(ZfsWorkerError::Protocol(
            "reader request identity is invalid",
        ));
    }
    let length = usize::from(u16::from_be_bytes([bytes[74], bytes[75]]));
    if bytes.len() != 76 + length {
        return Err(ZfsWorkerError::Protocol("reader snapshot length differs"));
    }
    let name = &bytes[76..];
    validate_name(name)?;
    let name = std::str::from_utf8(name)
        .map_err(|_| ZfsWorkerError::Protocol("reader snapshot name is not UTF-8"))?;
    let mut guid = [0; 8];
    guid.copy_from_slice(&bytes[10..18]);
    let mut pool = [0; 8];
    pool.copy_from_slice(&bytes[18..26]);
    Ok((
        name,
        u64::from_be_bytes(pool),
        u64::from_be_bytes(guid),
        digest_request(bytes),
    ))
}

fn validate_name(name: &[u8]) -> Result<(), ZfsWorkerError> {
    let separator = name.iter().position(|byte| *byte == b'@');
    let snapshot_component = separator.and_then(|index| name.get(index + 1..));
    if name.is_empty()
        || name.len() > MAXIMUM_REQUEST_BYTES - 76
        || name.iter().filter(|byte| **byte == b'@').count() != 1
        || snapshot_component.is_none_or(|part| part.is_empty() || part == b"." || part == b"..")
        || !name.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.' | b'@' | b':')
        })
        || name
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b".." || part.starts_with(b"@"))
    {
        return Err(ZfsWorkerError::Protocol("reader snapshot name is invalid"));
    }
    Ok(())
}

fn digest_request(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(REQUEST_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn encode_ready(cgroup: &str) -> Result<Vec<u8>, ZfsWorkerError> {
    if !cgroup.starts_with(READER_CGROUP_PREFIX) || !cgroup.ends_with(READER_CGROUP_SUFFIX) {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    encode_ready_frame(cgroup, READY_MAGIC, VERSION)
}

fn decode_ready(bytes: &[u8]) -> Result<&str, ZfsWorkerError> {
    decode_ready_frame(bytes, READY_MAGIC, VERSION)
}

fn encode_result(
    digest: ObjectDigest,
    measured: HeldSnapshotReaderObservationV1,
) -> [u8; RESULT_BYTES] {
    let mut bytes = [0; RESULT_BYTES];
    bytes[..8].copy_from_slice(RESULT_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(digest.as_bytes());
    bytes[42..74].copy_from_slice(measured.content_digest.as_bytes());
    bytes[74..106].copy_from_slice(measured.tree_digest.as_bytes());
    bytes[106..114].copy_from_slice(&measured.tree_size.to_be_bytes());
    bytes[114..122].copy_from_slice(&measured.mount_id.to_be_bytes());
    bytes[122..130].copy_from_slice(&measured.root_device.to_be_bytes());
    bytes[130..138].copy_from_slice(&measured.root_inode.to_be_bytes());
    bytes[138..142].copy_from_slice(&measured.nodes.to_be_bytes());
    bytes[142..150].copy_from_slice(&measured.file_bytes.to_be_bytes());
    bytes[150..158].copy_from_slice(&measured.mounted_snapshot_guid.to_be_bytes());
    bytes
}

fn decode_result(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
    if bytes.len() != RESULT_BYTES
        || &bytes[..8] != RESULT_MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..42] != *expected.as_bytes()
    {
        return Err(ZfsWorkerError::Protocol("reader result header is invalid"));
    }
    let array = |start: usize| -> [u8; 8] {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[start..start + 8]);
        value
    };
    let mut content = [0; 32];
    content.copy_from_slice(&bytes[42..74]);
    let mut tree = [0; 32];
    tree.copy_from_slice(&bytes[74..106]);
    let measured = HeldSnapshotReaderObservationV1 {
        content_digest: ObjectDigest::from_bytes(content),
        tree_digest: ObjectDigest::from_bytes(tree),
        tree_size: u64::from_be_bytes(array(106)),
        mount_id: u64::from_be_bytes(array(114)),
        root_device: u64::from_be_bytes(array(122)),
        root_inode: u64::from_be_bytes(array(130)),
        nodes: u32::from_be_bytes([bytes[138], bytes[139], bytes[140], bytes[141]]),
        file_bytes: u64::from_be_bytes(array(142)),
        mounted_snapshot_guid: u64::from_be_bytes(array(150)),
    };
    if measured.content_digest.as_bytes() == &[0; 32]
        || measured.tree_digest.as_bytes() == &[0; 32]
        || measured.tree_size == 0
        || measured.mount_id == 0
        || measured.root_inode == 0
        || measured.nodes == 0
        || measured.mounted_snapshot_guid != expected_snapshot_guid
    {
        return Err(ZfsWorkerError::Protocol(
            "reader result has no exact mounted snapshot GUID proof",
        ));
    }
    Ok(measured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    use crate::{ManagedDatasetRoot, ResolvedDataset, StorageDomainsV1};

    fn private_test_state() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn test_launch_fence(path: &Path) -> HeldReaderLaunchFence {
        let directory = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let identity = fstat(&directory).unwrap();
        HeldReaderLaunchFence {
            directory,
            device: identity.st_dev,
            inode: identity.st_ino,
            owner_uid: identity.st_uid,
        }
    }

    #[test]
    fn launch_claim_survives_storage_restart_before_reader_materializes() {
        let state = private_test_state();
        let prior = test_launch_fence(state.path());
        let accepted_but_unmaterialized = prior.claim().unwrap();
        drop(accepted_but_unmaterialized);
        assert!(matches!(prior.claim(), Err(ZfsWorkerError::Quiescence(_))));
        drop(prior);

        let restarted = test_launch_fence(state.path());
        assert!(matches!(
            restarted.claim(),
            Err(ZfsWorkerError::Quiescence(_))
        ));
        assert!(state.path().join(LAUNCH_FENCE_NAME).exists());
    }

    #[test]
    fn incomplete_launch_claim_remains_closed_after_restart() {
        let state = private_test_state();
        // A crash between exclusive create and either fsync can leave this
        // exact empty marker. Its presence alone must close admission.
        std::fs::File::create(state.path().join(LAUNCH_FENCE_NAME)).unwrap();

        let current = test_launch_fence(state.path());
        assert!(matches!(
            current.claim(),
            Err(ZfsWorkerError::Quiescence(_))
        ));
        drop(current);

        let restarted = test_launch_fence(state.path());
        assert!(matches!(
            restarted.claim(),
            Err(ZfsWorkerError::Quiescence(_))
        ));
    }

    #[test]
    fn failed_launch_sync_leaves_restart_fenced() {
        for failed_sync in [1, 2] {
            let state = private_test_state();
            let prior = test_launch_fence(state.path());
            let mut syncs = 0;
            let result = prior.claim_with_sync(|descriptor| {
                syncs += 1;
                if syncs == failed_sync {
                    Err(rustix::io::Errno::IO)
                } else {
                    fsync(descriptor)
                }
            });
            assert!(result.is_err());
            assert!(matches!(prior.claim(), Err(ZfsWorkerError::Quiescence(_))));
            drop(prior);

            let restarted = test_launch_fence(state.path());
            assert!(matches!(
                restarted.claim(),
                Err(ZfsWorkerError::Quiescence(_))
            ));
        }
    }

    #[test]
    fn launch_claim_retires_only_its_own_marker() {
        let state = private_test_state();
        let fence = test_launch_fence(state.path());
        let claim = fence.claim().unwrap();
        let marker = state.path().join(LAUNCH_FENCE_NAME);
        let replacement = state.path().join("replacement");
        std::fs::File::create(&replacement).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(replacement, &marker).unwrap();

        assert!(matches!(claim.retire(), Err(ZfsWorkerError::Authority)));
        assert!(marker.exists());
        assert!(matches!(fence.claim(), Err(ZfsWorkerError::Quiescence(_))));
    }

    #[test]
    fn proved_reader_exit_releases_launch_claim_for_next_attempt() {
        let state = private_test_state();
        let fence = test_launch_fence(state.path());
        let claim = fence.claim().unwrap();
        claim.retire().unwrap();

        let next = test_launch_fence(state.path());
        assert!(next.claim().is_ok());
    }

    #[test]
    fn rejects_ambiguous_snapshot_names() {
        for name in [
            b"pool/../data@snap".as_slice(),
            b"pool/data@x@y",
            b"pool/data@",
            b"pool//data@snap",
            b"pool/data@x\n",
        ] {
            assert!(validate_name(name).is_err());
        }
        assert!(validate_name(b"pool/data@snap-1").is_ok());
    }

    #[test]
    fn ready_frame_preserves_reader_role_and_exact_length() {
        let cgroup = "aos.slice/aos-control.slice/aos-sandbox-held-snapshot-reader@1.service";
        let frame = encode_ready(cgroup).unwrap();

        assert_eq!(decode_ready(&frame).unwrap(), cgroup);
        assert!(super::super::decode_ready(&frame).is_err());
        assert!(decode_ready(&frame[..frame.len() - 1]).is_err());
        assert!(decode_ready(&[frame.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn prior_reader_scan_accepts_only_reserved_unit_names() {
        assert!(validate_reader_unit_name("aos-sandbox-held-snapshot-reader@1.service").is_ok());
        for name in [
            "aos-sandbox-held-snapshot-reader@.service",
            "aos-sandbox-held-snapshot-reader@1.scope",
            "aos-sandbox-held-snapshot-reader@1/other.service",
            "aos-sandbox-zfs-worker@1.service",
        ] {
            assert!(validate_reader_unit_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn prior_reader_scan_requires_empty_or_retired_cgroups() {
        assert!(require_prior_reader_empty(CgroupPopulationState::Empty).is_ok());
        assert!(require_prior_reader_empty(CgroupPopulationState::Retired).is_ok());
        assert!(matches!(
            require_prior_reader_empty(CgroupPopulationState::Populated),
            Err(ZfsWorkerError::Quiescence(_))
        ));
    }

    #[test]
    fn ambiguous_connection_and_pre_ready_failures_fail_stop() {
        let cases = [
            (
                "connection peer pinning",
                ZfsWorkerError::Transport(
                    aos_sandbox_linux::seqpacket::SeqpacketError::PeerIdentity(
                        "peer pinning failed",
                    ),
                ),
            ),
            (
                "socket path authentication",
                ZfsWorkerError::Transport(
                    aos_sandbox_linux::seqpacket::SeqpacketError::PeerIdentity(
                        "socket path changed",
                    ),
                ),
            ),
            ("systemd peer authentication", ZfsWorkerError::PeerMismatch),
            (
                "READY receive",
                ZfsWorkerError::Transport(
                    aos_sandbox_linux::seqpacket::SeqpacketError::EmptyRecord,
                ),
            ),
        ];

        for (stage, error) in cases {
            let mut fail_stopped = false;
            let result: Result<(), ZfsWorkerError> =
                fail_stop_unproved_setup(&mut fail_stopped, error, None);

            assert!(fail_stopped, "{stage}");
            assert!(
                matches!(result, Err(ZfsWorkerError::Quiescence(_))),
                "{stage}"
            );
        }
    }

    #[test]
    fn unproved_ready_setup_fail_stops_and_reports_quiescence() {
        let cases = [
            ZfsWorkerError::Protocol("invalid READY frame"),
            ZfsWorkerError::PeerMismatch,
            ZfsWorkerError::Linux(aos_sandbox_linux::Error::WrongDescriptorType {
                expected: "cgroup.events",
            }),
        ];

        for error in cases {
            let expected = error.to_string();
            let mut fail_stopped = false;
            let result: Result<(), ZfsWorkerError> =
                fail_stop_unproved_setup(&mut fail_stopped, error, None);

            assert!(fail_stopped);
            let Err(ZfsWorkerError::Quiescence(detail)) = result else {
                panic!("unproved reader setup did not report quiescence");
            };
            assert!(detail.contains(&expected));
        }
    }

    #[test]
    fn failed_cancellation_keeps_reader_fail_stopped() {
        let mut fail_stopped = false;
        let cancellation_error = aos_sandbox_linux::Error::WrongDescriptorType {
            expected: "cgroup.kill",
        };
        let result: Result<(), ZfsWorkerError> = fail_stop_unproved_setup(
            &mut fail_stopped,
            ZfsWorkerError::Linux(aos_sandbox_linux::Error::WrongDescriptorType {
                expected: "cgroup.events",
            }),
            Some(cancellation_error),
        );

        assert!(fail_stopped);
        let Err(ZfsWorkerError::Quiescence(detail)) = result else {
            panic!("failed cancellation did not report quiescence");
        };
        assert!(detail.contains("cgroup.events"));
        assert!(detail.contains("cgroup.kill"));
    }

    #[test]
    fn request_decoder_retains_both_expected_guids() {
        let name = b"pool/data@snap";
        let mut request = Vec::new();
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&VERSION.to_be_bytes());
        request.extend_from_slice(&11_u64.to_be_bytes());
        request.extend_from_slice(&13_u64.to_be_bytes());
        request.extend_from_slice(&[3; 32]);
        request.extend_from_slice(&[5; 16]);
        request.extend_from_slice(&(name.len() as u16).to_be_bytes());
        request.extend_from_slice(name);

        let (decoded_name, pool_guid, snapshot_guid, digest) = decode_request(&request).unwrap();
        assert_eq!(decoded_name, "pool/data@snap");
        assert_eq!(pool_guid, 13);
        assert_eq!(snapshot_guid, 11);
        assert_eq!(digest, digest_request(&request));

        request[18..26].fill(0);
        assert!(decode_request(&request).is_err());
    }

    #[test]
    fn rejects_changed_or_truncated_reader_result() {
        let digest = ObjectDigest::from_bytes([1; 32]);
        let measured = HeldSnapshotReaderObservationV1 {
            content_digest: ObjectDigest::from_bytes([2; 32]),
            tree_digest: ObjectDigest::from_bytes([3; 32]),
            tree_size: 1,
            mount_id: 2,
            root_device: 3,
            root_inode: 4,
            nodes: 1,
            file_bytes: 5,
            mounted_snapshot_guid: 7,
        };
        let bytes = encode_result(digest, measured);
        assert_eq!(decode_result(&bytes, digest, 7).unwrap(), measured);
        assert!(decode_result(&bytes, ObjectDigest::from_bytes([9; 32]), 7).is_err());
        assert!(decode_result(&bytes[..157], digest, 7).is_err());
        assert!(decode_result(&bytes, digest, 8).is_err());

        // A missing mounted GUID remains invalid even when the request names
        // the expected snapshot.
        let unbound = encode_result(
            digest,
            HeldSnapshotReaderObservationV1 {
                mounted_snapshot_guid: 0,
                ..measured
            },
        );
        assert!(decode_result(&unbound, digest, 7).is_err());
    }

    #[test]
    #[ignore = "requires the installed systemd reader, native ZFS hold, and cgroup-v2 VM"]
    fn systemd_reader_vm_client() {
        let case = std::fs::read_to_string("/run/aos/held-reader-case").unwrap();
        let fields = case.trim().split(':').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        let variant = fields[0];
        let pool_guid = fields[1].parse::<u64>().unwrap();
        let root_guid = fields[2].parse::<u64>().unwrap();
        let dataset_guid = fields[3].parse::<u64>().unwrap();
        let snapshot_guid = fields[4].parse::<u64>().unwrap();
        let different_guid = |guid: u64| if guid == 1 { 2 } else { guid - 1 };

        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("aosproof", "aosproof/aos", root_guid).unwrap();
        let dataset = ResolvedDataset::from_catalog(
            root,
            "aosproof/aos/project/workspace",
            dataset_guid,
            [5; 32],
            domains,
        )
        .unwrap();
        let expected_snapshot_guid = if variant == "wrong-snapshot" {
            different_guid(snapshot_guid)
        } else {
            snapshot_guid
        };
        let snapshot =
            ResolvedSnapshot::from_catalog(dataset, "held", expected_snapshot_guid, [6; 32])
                .unwrap();
        let expected_pool_guid = if variant == "wrong-pool" {
            different_guid(pool_guid)
        } else {
            pool_guid
        };

        // This fixture supplies a nonzero request binding, not a protected
        // Storage journal cut or any SourceRoot authority.
        let mut reader = SystemdHeldSnapshotReaderV1::new(
            open_cgroup_root().unwrap(),
            Path::new("/var/lib/aos/sandbox-storage"),
        )
        .unwrap();
        let observation = reader.measure(
            &snapshot,
            expected_pool_guid,
            ObjectDigest::from_bytes([7; 32]),
            [8; 16],
        );
        match variant {
            "matched" => {
                let measured = observation.unwrap();
                assert_eq!(measured.mounted_snapshot_guid, snapshot_guid);
                assert_ne!(measured.content_digest.as_bytes(), &[0; 32]);
                assert!(measured.mount_id > 0 && measured.nodes > 0);
            }
            "wrong-pool" | "wrong-snapshot" => {
                assert!(observation.is_err());
                assert!(!reader.fail_stopped);
            }
            _ => panic!("unknown held-reader VM case"),
        }
    }

    #[test]
    #[ignore = "requires a wrong-cgroup systemd service and the installed reader socket"]
    fn systemd_reader_vm_decoy() {
        let mut socket = SeqpacketSocket::connect(Path::new(SOCKET_PATH)).unwrap();
        let deadline = Deadline::after(Duration::from_secs(10));

        loop {
            assert!(
                deadline.remaining().is_some(),
                "decoy peer was not rejected"
            );
            match socket.receive(MAXIMUM_READY_BYTES) {
                Err(aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
                Ok(_) => panic!("reader sent READY to a wrong-cgroup peer"),
            }
        }
    }
}
