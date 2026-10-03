//! One-shot, confined physical measurement of a Storage-held ZFS snapshot.
//!
//! The request is selected by the protected Storage owner, never by a public
//! broker method. The reader mounts only that snapshot in its private mount
//! namespace, applies read-only, nodev, nosuid, and noexec attributes while
//! detached, and returns a bounded physical measurement. The original reply
//! carries no descriptor; the separate versioned reply transfers exactly one
//! read-only detached mount FD to Storage. Neither reply carries a signature
//! or SourceRoot receipt.
//!
//! ```text
//! AOSHSR01 request = version:u16 | snapshot-guid:u64 | pool-guid:u64 |
//!                    cut-digest:32 | nonce:16 | name-length:u16 | snapshot-name
//! AOSHSM02 result  = version:u16 | request-digest:32 | content-digest:32 |
//!                    tree-digest:32 | tree-size:u64 | mount-id:u64 |
//!                    root-device:u64 | root-inode:u64 | nodes:u32 | file-bytes:u64 |
//!                    mounted-snapshot-guid:u64 | root-uid:u32 | root-gid:u32 |
//!                    root-mode:u16 | maximum-uid:u32 | maximum-gid:u32 |
//!                    distinct-inodes:u64 | directory-entries:u64 | identity-tree-digest:32
//! AOSHSR02 request = AOSHSR01 fields with version 2 and a distinct magic
//! AOSHSM03 result  = AOSHSM02 fields with version 3 and exactly one detached
//!                    read-only mount FD in the same authenticated record
//! ```

use std::fs;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::{CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::mount::filesystem_uuid;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketSocket};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, StatVfsMountFlags, fstat, fsync, openat, unlinkat,
};
use sha2::{Digest as _, Sha256};

use crate::ResolvedSnapshot;
use crate::held_snapshot_tree::{
    HeldSnapshotIdentityObservationV1, measure_bound_detached_snapshot,
    measure_bound_detached_snapshot_with_mount, verify_mounted_snapshot_uuid,
};
use crate::live_export_key::open_protected_directory;
use crate::root_policy::PortableRootAttributesV1;

use super::{
    Deadline, ZfsWorkerError, current_cgroup_path, decode_ack, decode_ready_frame, encode_ack,
    encode_ready_frame, open_cgroup_root, quiesce_worker, receive_before,
    receive_one_descriptor_before, send_before, send_with_descriptor_before,
    verify_same_live_subject, verify_same_subject, verify_storaged_peer,
    verify_systemd_activation_peer, wait_for_worker_quiescence,
};

pub(crate) mod original;

const REQUEST_MAGIC: &[u8; 8] = b"AOSHSR01";
const RESULT_MAGIC: &[u8; 8] = b"AOSHSM02";
const MOUNT_REQUEST_MAGIC: &[u8; 8] = b"AOSHSR02";
const MOUNT_RESULT_MAGIC: &[u8; 8] = b"AOSHSM03";
const READY_MAGIC: &[u8; 8] = b"AOSHSRD1";
const VERSION: u16 = 1;
const RESULT_VERSION: u16 = 2;
const MOUNT_REQUEST_VERSION: u16 = 2;
const MOUNT_RESULT_VERSION: u16 = 3;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.storage.held-snapshot-reader.v1\0";
const SOCKET_PATH: &str = "/run/aos/sandbox-held-snapshot-reader/control.sock";
const NAMESPACE_MARKER: &str = "/run/aos-held-reader-namespace";
const TMPFS_MAGIC: u64 = 0x0102_1994;
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const READER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-held-snapshot-reader@";
const READER_UNIT_PREFIX: &str = "aos-sandbox-held-snapshot-reader@";
const READER_CGROUP_SUFFIX: &str = ".service";
const MAXIMUM_RECOVERED_READERS: usize = 128;
const RESULT_BYTES: usize = 224;
const MAXIMUM_REQUEST_BYTES: usize = 1024;
const MAXIMUM_READY_BYTES: usize = 512;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(45);
const LAUNCH_FENCE_NAME: &str = "held-snapshot-reader.launch";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReaderReplyMode {
    MeasurementOnly,
    WithMount,
    OriginalWithMount,
}

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
    /// A bounded observation of the admitted tree's portable identities.
    pub(crate) identity: HeldSnapshotIdentityObservationV1,
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

/// Keeps launch custody independent of the fence loan, including partial work.
///
/// The exact-name comparison drops before the claimed marker, matching the
/// legacy retirement local. Results are historical observations, not exit or
/// durable-absence authority. In particular, unlink success plus sync failure
/// remains unresolved and does not clear either descriptor.
#[derive(Default)]
struct HeldReaderLaunchCapture {
    retirement_marker: Option<OwnedFd>,
    marker: Option<OwnedFd>,
    identity: Option<(u64, u64)>,
    claim_started: bool,
    retirement_started: bool,
    claim: Option<Result<(), ZfsWorkerError>>,
    retirement: Option<Result<(), ZfsWorkerError>>,
    unlink: Option<Result<(), rustix::io::Errno>>,
    directory_sync: Option<Result<(), rustix::io::Errno>>,
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
        let mut capture = HeldReaderLaunchCapture::default();
        self.capture_claim_with_sync(&mut capture, &mut sync)?;
        capture.claim.take().ok_or(ZfsWorkerError::Protocol(
            "reader launch claim is absent",
        ))??;
        let marker = capture.marker.take().ok_or(ZfsWorkerError::Protocol(
            "reader launch marker is absent",
        ))?;
        let (device, inode) = capture.identity.ok_or(ZfsWorkerError::Protocol(
            "reader launch identity is absent",
        ))?;

        Ok(ClaimedReaderLaunch {
            fence: self,
            marker,
            device,
            inode,
        })
    }

    /// Captures the original claim while borrowing only this operation's fence.
    fn capture_claim_with_sync<F>(
        &self,
        capture: &mut HeldReaderLaunchCapture,
        sync: &mut F,
    ) -> Result<(), ZfsWorkerError>
    where
        F: FnMut(&OwnedFd) -> Result<(), rustix::io::Errno>,
    {
        if capture.claim_started
            || capture.retirement_started
            || capture.marker.is_some()
            || capture.claim.is_some()
            || capture.retirement.is_some()
            || capture.retirement_marker.is_some()
            || capture.identity.is_some()
            || capture.unlink.is_some()
            || capture.directory_sync.is_some()
        {
            return Err(ZfsWorkerError::Protocol("reader launch capture is occupied"));
        }

        capture.claim_started = true;
        capture.claim = Some(self.claim_into(capture, sync));
        Ok(())
    }

    fn claim_into<F>(
        &self,
        capture: &mut HeldReaderLaunchCapture,
        sync: &mut F,
    ) -> Result<(), ZfsWorkerError>
    where
        F: FnMut(&OwnedFd) -> Result<(), rustix::io::Errno>,
    {
        self.validate_directory()?;
        capture.marker = Some(
            openat(
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
            })?,
        );
        let marker = capture.marker.as_ref().ok_or(ZfsWorkerError::Protocol(
            "reader launch marker is absent",
        ))?;
        let identity = fstat(marker)?;
        capture.identity = Some((identity.st_dev, identity.st_ino));
        if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_uid != self.owner_uid
            || identity.st_nlink != 1
            || identity.st_mode & 0o7777 != 0o600
        {
            return Err(ZfsWorkerError::Authority);
        }
        sync(marker)?;
        sync(&self.directory)?;
        self.validate_directory()?;
        Ok(())
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

    /// Retains retirement results and the exact-name descriptor before checks.
    fn capture_retirement(
        &self,
        capture: &mut HeldReaderLaunchCapture,
    ) -> Result<(), ZfsWorkerError> {
        if !matches!(&capture.claim, Some(Ok(())))
            || capture.retirement_started
            || capture.retirement.is_some()
            || capture.retirement_marker.is_some()
            || capture.unlink.is_some()
            || capture.directory_sync.is_some()
        {
            return Err(ZfsWorkerError::Protocol(
                "reader launch retirement is not pending",
            ));
        }

        capture.retirement_started = true;
        capture.retirement = Some(self.retire_into(capture));
        Ok(())
    }

    fn retire_into(&self, capture: &mut HeldReaderLaunchCapture) -> Result<(), ZfsWorkerError> {
        self.validate_directory()?;
        let marker = capture.marker.as_ref().ok_or(ZfsWorkerError::Protocol(
            "reader launch marker is absent",
        ))?;
        let expected = capture.identity.ok_or(ZfsWorkerError::Protocol(
            "reader launch identity is absent",
        ))?;
        let held = fstat(marker)?;
        if (held.st_dev, held.st_ino) != expected {
            return Err(ZfsWorkerError::Authority);
        }
        capture.retirement_marker = Some(openat(
            &self.directory,
            LAUNCH_FENCE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let marker = capture.retirement_marker.as_ref().ok_or(ZfsWorkerError::Protocol(
            "reader retirement marker is absent",
        ))?;
        let identity = fstat(marker)?;
        if (identity.st_dev, identity.st_ino) != expected
            || FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_uid != self.owner_uid
            || identity.st_nlink != 1
            || identity.st_mode & 0o7777 != 0o600
        {
            return Err(ZfsWorkerError::Authority);
        }
        capture.unlink = Some(unlinkat(&self.directory, LAUNCH_FENCE_NAME, AtFlags::empty()));
        if let Some(Err(error)) = &capture.unlink {
            return Err((*error).into());
        }
        capture.directory_sync = Some(fsync(&self.directory));
        if let Some(Err(error)) = &capture.directory_sync {
            return Err((*error).into());
        }
        Ok(())
    }
}

impl ClaimedReaderLaunch<'_> {
    fn retire(self) -> Result<(), ZfsWorkerError> {
        let mut capture = HeldReaderLaunchCapture {
            marker: Some(self.marker),
            identity: Some((self.device, self.inode)),
            claim_started: true,
            claim: Some(Ok(())),
            ..HeldReaderLaunchCapture::default()
        };
        self.fence.capture_retirement(&mut capture)?;
        capture.retirement.take().ok_or(ZfsWorkerError::Protocol(
            "reader retirement result is absent",
        ))?
    }
}

/// Authenticates the fixed one-shot reader and proves its whole-unit exit.
pub(crate) struct SystemdHeldSnapshotReaderV1 {
    manager: RetainedCgroupAnchor,
    worker_parent: RetainedCgroupAnchor,
    launch_fence: HeldReaderLaunchFence,
    fail_stopped: bool,
}

/// Retains partial passive owner capture before the next fallible check.
#[derive(Default)]
pub(crate) struct HeldReaderOwnerCaptureV3 {
    manager: Option<RetainedCgroupAnchor>,
    worker_parent: Option<RetainedCgroupAnchor>,
    launch_fence: Option<HeldReaderLaunchFence>,
    cgroup_root: Option<CgroupV2Root>,
}

impl SystemdHeldSnapshotReaderV1 {
    pub(crate) fn new(
        cgroup_root: CgroupV2Root,
        state_directory: &Path,
    ) -> Result<Self, ZfsWorkerError> {
        let mut capture = HeldReaderOwnerCaptureV3::default();
        Self::capture_new(cgroup_root, state_directory, &mut capture)
    }

    pub(crate) fn capture_new(
        cgroup_root: CgroupV2Root,
        state_directory: &Path,
        capture: &mut HeldReaderOwnerCaptureV3,
    ) -> Result<Self, ZfsWorkerError> {
        if capture.cgroup_root.is_some() {
            return Err(ZfsWorkerError::Protocol("reader owner capture is occupied"));
        }
        capture.cgroup_root = Some(cgroup_root);
        let root = capture.cgroup_root.as_ref().ok_or(ZfsWorkerError::Authority)?;
        capture.manager = Some(root.resolve(Path::new("init.scope"))?);
        capture.worker_parent = Some(root.resolve(Path::new("aos.slice/aos-control.slice"))?);
        capture.launch_fence = Some(HeldReaderLaunchFence::open(state_directory)?);
        Ok(Self {
            manager: capture.manager.take().ok_or(ZfsWorkerError::Authority)?,
            worker_parent: capture.worker_parent.take().ok_or(ZfsWorkerError::Authority)?,
            launch_fence: capture.launch_fence.take().ok_or(ZfsWorkerError::Authority)?,
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
        let (measured, mount) = self.measure_inner(
            snapshot,
            expected_pool_guid,
            protected_cut_digest,
            nonce,
            ReaderReplyMode::MeasurementOnly,
        )?;
        if mount.is_some() {
            return Err(ZfsWorkerError::Protocol(
                "measurement-only reader returned a mount",
            ));
        }
        Ok(measured)
    }

    /// Retains one GUID-verified detached mount through reader quiescence.
    pub(crate) fn measure_with_mount(
        &mut self,
        snapshot: &ResolvedSnapshot,
        expected_pool_guid: u64,
        protected_cut_digest: ObjectDigest,
        nonce: [u8; 16],
    ) -> Result<(HeldSnapshotReaderObservationV1, OwnedFd), ZfsWorkerError> {
        let (measured, mount) = self.measure_inner(
            snapshot,
            expected_pool_guid,
            protected_cut_digest,
            nonce,
            ReaderReplyMode::WithMount,
        )?;
        let mount = mount.ok_or(ZfsWorkerError::Protocol(
            "mount reader returned no descriptor",
        ))?;
        Ok((measured, mount))
    }

    fn measure_inner(
        &mut self,
        snapshot: &ResolvedSnapshot,
        expected_pool_guid: u64,
        protected_cut_digest: ObjectDigest,
        nonce: [u8; 16],
        mode: ReaderReplyMode,
    ) -> Result<(HeldSnapshotReaderObservationV1, Option<OwnedFd>), ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Quiescence(
                "held snapshot reader is fail-stopped".to_owned(),
            ));
        }
        if let Err(error) = self.prove_prior_readers_empty() {
            return fail_stop_unproved_setup(&mut self.fail_stopped, error, None);
        }
        let request = encode_request_for(
            snapshot,
            expected_pool_guid,
            protected_cut_digest,
            nonce,
            mode,
        )?;
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
            let result = match mode {
                ReaderReplyMode::MeasurementOnly => {
                    let response = receive_before(&mut socket, RESULT_BYTES, deadline)?;
                    verify_same_live_subject(&reader_subject, response.subject())?;
                    reader_cgroup.verify_exact_membership(response.subject().pidfd())?;
                    (
                        decode_result(response.payload(), request_digest, snapshot.guid())?,
                        None,
                    )
                }
                ReaderReplyMode::WithMount => {
                    let response =
                        receive_one_descriptor_before(&mut socket, RESULT_BYTES, deadline)?;
                    verify_same_live_subject(&reader_subject, response.subject())?;
                    reader_cgroup.verify_exact_membership(response.subject().pidfd())?;
                    let (bytes, _subject, descriptors) = response.into_parts();
                    let (measured, mount) = decode_result_with_mount(
                        &bytes,
                        request_digest,
                        snapshot.guid(),
                        expected_pool_guid,
                        descriptors,
                    )?;
                    (measured, Some(mount))
                }
                ReaderReplyMode::OriginalWithMount => {
                    return Err(ZfsWorkerError::Protocol("original reader requires its checked branch"));
                }
            };
            send_before(&mut socket, &encode_ack(), deadline)?;
            Ok::<_, ZfsWorkerError>(result)
        })();

        match exchange {
            Ok((measured, mount)) => {
                if wait_for_worker_quiescence(&reader_subject, &population, Duration::from_secs(1))
                    .is_ok()
                {
                    launch.retire().or_else(|error| {
                        fail_stop_unproved_setup(&mut self.fail_stopped, error, None)
                    })?;
                    if let Some(descriptor) = mount.as_ref() {
                        verify_received_mount_fd(
                            descriptor.as_fd(),
                            &measured,
                            expected_pool_guid,
                        )?;
                    }
                    return Ok((measured, mount));
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

/// Keeps the original setup failure separate from unproved cancellation debt.
struct ReaderSetupFailure {
    cause: ZfsWorkerError,
    cancellation: Option<aos_sandbox_linux::Error>,
}

impl ReaderSetupFailure {
    /// Explicitly projects a legacy temporary capture into its old text error.
    fn into_legacy_error(self) -> ZfsWorkerError {
        let error = self.cause;
        let detail = match self.cancellation {
            Some(cancellation_error) => format!(
                "held snapshot reader setup failed before quiescence was proved: {error}; cancellation: {cancellation_error}"
            ),
            None => format!("held snapshot reader setup failed before quiescence was proved: {error}"),
        };
        ZfsWorkerError::Quiescence(detail)
    }
}

fn fail_stop_unproved_setup<T>(
    fail_stopped: &mut bool,
    error: ZfsWorkerError,
    cancellation_error: Option<aos_sandbox_linux::Error>,
) -> Result<T, ZfsWorkerError> {
    *fail_stopped = true;
    Err(ReaderSetupFailure {
        cause: error,
        cancellation: cancellation_error,
    }
    .into_legacy_error())
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
    if super::original_cutoff::OriginalWorkerPurposeV3::Reader.selects_introduction(record.payload()) {
        return original::run_original_reader(socket, record, storaged);
    }
    let (snapshot_name, expected_pool_guid, expected_snapshot_guid, request_digest, mode) =
        decode_request(record.payload())?;

    let (measured, mount) = match mode {
        ReaderReplyMode::MeasurementOnly => (
            measure_bound_detached_snapshot(
                snapshot_name,
                expected_pool_guid,
                expected_snapshot_guid,
            )
            .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?,
            None,
        ),
        ReaderReplyMode::WithMount => {
            let (measured, mount) = measure_bound_detached_snapshot_with_mount(
                snapshot_name,
                expected_pool_guid,
                expected_snapshot_guid,
            )
            .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
            (measured, Some(mount))
        }
        ReaderReplyMode::OriginalWithMount => {
            return Err(ZfsWorkerError::Protocol("original reader requires its checked branch"));
        }
    };
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
        identity: measured.identity,
    };
    match mount.as_ref() {
        Some(mount) => send_with_descriptor_before(
            &mut socket,
            &encode_result_with_mount(request_digest, observation),
            mount.as_fd(),
            deadline,
        )?,
        None => send_before(
            &mut socket,
            &encode_result(request_digest, observation),
            deadline,
        )?,
    }
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

fn encode_request_for(
    snapshot: &ResolvedSnapshot,
    expected_pool_guid: u64,
    cut_digest: ObjectDigest,
    nonce: [u8; 16],
    mode: ReaderReplyMode,
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
    let (magic, version) = match mode {
        ReaderReplyMode::MeasurementOnly => (REQUEST_MAGIC, VERSION),
        ReaderReplyMode::WithMount => (MOUNT_REQUEST_MAGIC, MOUNT_REQUEST_VERSION),
        ReaderReplyMode::OriginalWithMount => {
            return Err(ZfsWorkerError::Protocol("original reader has no legacy request encoding"));
        }
    };
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_be_bytes());
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

fn decode_request(
    bytes: &[u8],
) -> Result<(&str, u64, u64, ObjectDigest, ReaderReplyMode), ZfsWorkerError> {
    if bytes.len() < 76 || bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "reader request length or magic is invalid",
        ));
    }
    let mode = match (&bytes[..8], &bytes[8..10]) {
        (magic, version) if magic == REQUEST_MAGIC && version == VERSION.to_be_bytes() => {
            ReaderReplyMode::MeasurementOnly
        }
        (magic, version)
            if magic == MOUNT_REQUEST_MAGIC && version == MOUNT_REQUEST_VERSION.to_be_bytes() =>
        {
            ReaderReplyMode::WithMount
        }
        _ => {
            return Err(ZfsWorkerError::Protocol(
                "reader request version is invalid",
            ));
        }
    };
    if bytes[10..18] == [0; 8]
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
        mode,
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
    encode_result_for(digest, measured, ReaderReplyMode::MeasurementOnly)
}

fn encode_result_with_mount(
    digest: ObjectDigest,
    measured: HeldSnapshotReaderObservationV1,
) -> [u8; RESULT_BYTES] {
    encode_result_for(digest, measured, ReaderReplyMode::WithMount)
}

fn encode_result_for(
    digest: ObjectDigest,
    measured: HeldSnapshotReaderObservationV1,
    mode: ReaderReplyMode,
) -> [u8; RESULT_BYTES] {
    let mut bytes = [0; RESULT_BYTES];
    let (magic, version) = match mode {
        ReaderReplyMode::MeasurementOnly => (RESULT_MAGIC, RESULT_VERSION),
        ReaderReplyMode::WithMount => (MOUNT_RESULT_MAGIC, MOUNT_RESULT_VERSION),
        ReaderReplyMode::OriginalWithMount => (b"AOSHSM04", 4),
    };
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&version.to_be_bytes());
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
    bytes[158..162].copy_from_slice(&measured.identity.root_attributes.uid().to_be_bytes());
    bytes[162..166].copy_from_slice(&measured.identity.root_attributes.gid().to_be_bytes());
    bytes[166..168].copy_from_slice(&measured.identity.root_attributes.mode().to_be_bytes());
    bytes[168..172].copy_from_slice(&measured.identity.maximum_portable_uid.to_be_bytes());
    bytes[172..176].copy_from_slice(&measured.identity.maximum_portable_gid.to_be_bytes());
    bytes[176..184].copy_from_slice(&measured.identity.distinct_inode_count.to_be_bytes());
    bytes[184..192].copy_from_slice(&measured.identity.directory_entry_count.to_be_bytes());
    bytes[192..224].copy_from_slice(measured.identity.identity_tree_digest.as_bytes());
    bytes
}

fn decode_result(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
    decode_result_for(
        bytes,
        expected,
        expected_snapshot_guid,
        ReaderReplyMode::MeasurementOnly,
    )
}

fn decode_result_with_mount(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
    expected_pool_guid: u64,
    descriptors: Vec<OwnedFd>,
) -> Result<(HeldSnapshotReaderObservationV1, OwnedFd), ZfsWorkerError> {
    let [mount]: [OwnedFd; 1] = descriptors.try_into().map_err(|_| {
        ZfsWorkerError::Protocol("reader descriptor result requires exactly one mount")
    })?;
    let measured = validate_result_with_mount(
        bytes,
        expected,
        expected_snapshot_guid,
        expected_pool_guid,
        std::slice::from_ref(&mount),
    )?;
    Ok((measured, mount))
}

/// Borrows the complete table; no descriptor or record subject leaves custody.
fn validate_result_with_mount(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
    expected_pool_guid: u64,
    descriptors: &[OwnedFd],
) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
    validate_result_with_mount_for(
        bytes, expected, expected_snapshot_guid, expected_pool_guid, descriptors,
        ReaderReplyMode::WithMount,
    )
}

fn validate_result_with_mount_for(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
    expected_pool_guid: u64,
    descriptors: &[OwnedFd],
    mode: ReaderReplyMode,
) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
    let [mount] = descriptors else {
        return Err(ZfsWorkerError::Protocol(
            "reader descriptor result requires exactly one mount",
        ));
    };
    let measured = decode_result_for(
        bytes,
        expected,
        expected_snapshot_guid,
        mode,
    )?;
    verify_received_mount_fd(mount.as_fd(), &measured, expected_pool_guid)?;
    Ok(measured)
}

fn decode_result_for(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
    mode: ReaderReplyMode,
) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
    let (magic, version) = match mode {
        ReaderReplyMode::MeasurementOnly => (RESULT_MAGIC, RESULT_VERSION),
        ReaderReplyMode::WithMount => (MOUNT_RESULT_MAGIC, MOUNT_RESULT_VERSION),
        ReaderReplyMode::OriginalWithMount => (b"AOSHSM04", 4),
    };
    if bytes.len() != RESULT_BYTES
        || &bytes[..8] != magic
        || bytes[8..10] != version.to_be_bytes()
        || bytes[10..42] != *expected.as_bytes()
    {
        return Err(ZfsWorkerError::Protocol("reader result header is invalid"));
    }
    let array = |start: usize| -> [u8; 8] {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[start..start + 8]);
        value
    };
    let array4 = |start: usize| -> [u8; 4] {
        let mut value = [0; 4];
        value.copy_from_slice(&bytes[start..start + 4]);
        value
    };
    let mut content = [0; 32];
    content.copy_from_slice(&bytes[42..74]);
    let mut tree = [0; 32];
    tree.copy_from_slice(&bytes[74..106]);
    let mut identity_tree_digest = [0; 32];
    identity_tree_digest.copy_from_slice(&bytes[192..224]);
    let root_attributes = PortableRootAttributesV1::new(
        u32::from_be_bytes(array4(158)),
        u32::from_be_bytes(array4(162)),
        u32::from(u16::from_be_bytes([bytes[166], bytes[167]])),
    )
    .map_err(|_| ZfsWorkerError::Protocol("reader identity root is invalid"))?;
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
        identity: HeldSnapshotIdentityObservationV1 {
            root_attributes,
            maximum_portable_uid: u32::from_be_bytes(array4(168)),
            maximum_portable_gid: u32::from_be_bytes(array4(172)),
            distinct_inode_count: u64::from_be_bytes(array(176)),
            directory_entry_count: u64::from_be_bytes(array(184)),
            identity_tree_digest: ObjectDigest::from_bytes(identity_tree_digest),
        },
    };
    if measured.content_digest.as_bytes() == &[0; 32]
        || measured.tree_digest.as_bytes() == &[0; 32]
        || measured.tree_size == 0
        || measured.mount_id == 0
        || measured.root_inode == 0
        || measured.nodes == 0
        || measured.mounted_snapshot_guid != expected_snapshot_guid
        || measured.identity.maximum_portable_uid == u32::MAX
        || measured.identity.maximum_portable_gid == u32::MAX
        || measured.identity.maximum_portable_uid < measured.identity.root_attributes.uid()
        || measured.identity.maximum_portable_gid < measured.identity.root_attributes.gid()
        || measured.identity.distinct_inode_count != u64::from(measured.nodes)
        || measured.identity.directory_entry_count.checked_add(1)
            != Some(measured.identity.distinct_inode_count)
        || measured.identity.identity_tree_digest.as_bytes() == &[0; 32]
    {
        return Err(ZfsWorkerError::Protocol(
            "reader result has no exact mounted snapshot GUID proof",
        ));
    }
    Ok(measured)
}

pub(crate) fn verify_received_mount_fd(
    mount: BorrowedFd<'_>,
    measured: &HeldSnapshotReaderObservationV1,
    expected_pool_guid: u64,
) -> Result<(), ZfsWorkerError> {
    let metadata = fstat(mount)?;
    let mount_id = MountId::from_fd(mount)?;
    let flags = rustix::fs::fstatvfs(mount)?.f_flag;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || mount_id.get() != measured.mount_id
        || metadata.st_dev != measured.root_device
        || metadata.st_ino != measured.root_inode
        || metadata.st_uid != measured.identity.root_attributes.uid()
        || metadata.st_gid != measured.identity.root_attributes.gid()
        || metadata.st_mode & 0o7777 != u32::from(measured.identity.root_attributes.mode())
        || !flags.contains(
            StatVfsMountFlags::RDONLY
                | StatVfsMountFlags::NOSUID
                | StatVfsMountFlags::NODEV
                | StatVfsMountFlags::NOEXEC,
        )
    {
        return Err(ZfsWorkerError::Protocol(
            "reader mount descriptor differs from measured read-only root",
        ));
    }

    let readable = rustix::fs::openat(
        mount,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if MountId::from_fd(readable.as_fd())? != mount_id {
        return Err(ZfsWorkerError::Protocol(
            "reader mount descriptor changed after transfer",
        ));
    }
    verify_mounted_snapshot_uuid(
        filesystem_uuid(readable.as_fd())?,
        expected_pool_guid,
        measured.mounted_snapshot_guid,
    )
    .map_err(|_| ZfsWorkerError::Protocol("reader mount UUID differs from selected snapshot"))
}

#[cfg(test)]
mod lower_custody_tests {
    use super::*;

    #[test]
    fn borrowed_mount_validation_rejects_missing_custody_before_the_header() {
        let descriptors = Vec::new();
        let result = validate_result_with_mount(
            b"invalid header",
            ObjectDigest::from_bytes([1; 32]),
            7,
            9,
            &descriptors,
        );

        assert!(matches!(
            result,
            Err(ZfsWorkerError::Protocol(
                "reader descriptor result requires exactly one mount",
            )),
        ));
        assert!(descriptors.is_empty());
    }

    #[test]
    fn retirement_sync_debt_does_not_replace_claim_or_unlink_history() {
        // This is only error-bookkeeping DATA, not a constructed marker or
        // proof that a real directory entry was removed.
        let capture = HeldReaderLaunchCapture {
            claim_started: true,
            claim: Some(Ok(())),
            retirement_started: true,
            retirement: Some(Err(ZfsWorkerError::Kernel(rustix::io::Errno::IO))),
            unlink: Some(Ok(())),
            directory_sync: Some(Err(rustix::io::Errno::IO)),
            ..HeldReaderLaunchCapture::default()
        };

        assert!(matches!(&capture.claim, Some(Ok(()))));
        assert!(matches!(&capture.unlink, Some(Ok(()))));
        assert!(matches!(
            &capture.directory_sync,
            Some(Err(rustix::io::Errno::IO)),
        ));
        assert!(matches!(
            &capture.retirement,
            Some(Err(ZfsWorkerError::Kernel(rustix::io::Errno::IO))),
        ));
    }

    #[test]
    fn setup_capture_keeps_the_original_cause_separate_from_cancellation_debt() {
        let capture = ReaderSetupFailure {
            cause: ZfsWorkerError::Protocol("original setup"),
            cancellation: Some(aos_sandbox_linux::Error::WrongDescriptorType {
                expected: "cgroup.kill",
            }),
        };

        assert!(matches!(
            &capture.cause,
            ZfsWorkerError::Protocol("original setup"),
        ));
        let expected = format!(
            "held snapshot reader setup failed before quiescence was proved: {}; cancellation: {}",
            capture.cause,
            capture.cancellation.as_ref().unwrap(),
        );
        let ZfsWorkerError::Quiescence(detail) = capture.into_legacy_error() else {
            panic!("setup projection changed its legacy error");
        };
        assert_eq!(detail, expected);
    }
}

#[cfg(test)]
#[path = "held_snapshot_reader_vm_tests.rs"]
mod vm_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
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

        let (decoded_name, pool_guid, snapshot_guid, digest, mode) =
            decode_request(&request).unwrap();
        assert_eq!(decoded_name, "pool/data@snap");
        assert_eq!(pool_guid, 13);
        assert_eq!(snapshot_guid, 11);
        assert_eq!(digest, digest_request(&request));
        assert_eq!(mode, ReaderReplyMode::MeasurementOnly);

        request[18..26].fill(0);
        assert!(decode_request(&request).is_err());
        request[18..26].copy_from_slice(&13_u64.to_be_bytes());
        request[..8].copy_from_slice(MOUNT_REQUEST_MAGIC);
        request[8..10].copy_from_slice(&MOUNT_REQUEST_VERSION.to_be_bytes());
        assert_eq!(
            decode_request(&request).unwrap().4,
            ReaderReplyMode::WithMount
        );
        request[8..10].copy_from_slice(&VERSION.to_be_bytes());
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
            identity: HeldSnapshotIdentityObservationV1 {
                root_attributes: PortableRootAttributesV1::new(0, 0, 0o755).unwrap(),
                maximum_portable_uid: 0,
                maximum_portable_gid: 0,
                distinct_inode_count: 1,
                directory_entry_count: 0,
                identity_tree_digest: ObjectDigest::from_bytes([8; 32]),
            },
        };
        let bytes = encode_result(digest, measured);
        assert_eq!(decode_result(&bytes, digest, 7).unwrap(), measured);
        assert!(decode_result(&bytes, ObjectDigest::from_bytes([9; 32]), 7).is_err());
        assert!(decode_result(&bytes[..223], digest, 7).is_err());
        assert!(decode_result(&bytes, digest, 8).is_err());

        let mut old_version = bytes;
        old_version[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(decode_result(&old_version, digest, 7).is_err());
        old_version = bytes;
        old_version[..8].copy_from_slice(b"AOSHSM01");
        assert!(decode_result(&old_version, digest, 7).is_err());

        let mut invalid_summary = bytes;
        invalid_summary[168..172].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_result(&invalid_summary, digest, 7).is_err());
        invalid_summary = bytes;
        invalid_summary[138..142].copy_from_slice(&2_u32.to_be_bytes());
        assert!(decode_result(&invalid_summary, digest, 7).is_err());
        invalid_summary = bytes;
        invalid_summary[184..192].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode_result(&invalid_summary, digest, 7).is_err());

        let mut request = Vec::new();
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&VERSION.to_be_bytes());
        request.extend_from_slice(&7_u64.to_be_bytes());
        request.extend_from_slice(&9_u64.to_be_bytes());
        request.extend_from_slice(&[3; 32]);
        request.extend_from_slice(&[4; 16]);
        request.extend_from_slice(&1_u16.to_be_bytes());
        request.push(b'x');
        let original_request_digest = digest_request(&request);
        let bound_result = encode_result(original_request_digest, measured);
        request[26] ^= 1; // Protected cut digest substitution.
        assert!(decode_result(&bound_result, digest_request(&request), 7).is_err());
        request[26] ^= 1;
        request[58] ^= 1; // One-shot nonce substitution.
        assert!(decode_result(&bound_result, digest_request(&request), 7).is_err());
        invalid_summary = bytes;
        invalid_summary[192..224].fill(0);
        assert!(decode_result(&invalid_summary, digest, 7).is_err());

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
    fn descriptor_result_requires_one_fd_and_its_own_wire_version() {
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
            identity: HeldSnapshotIdentityObservationV1 {
                root_attributes: PortableRootAttributesV1::new(0, 0, 0o755).unwrap(),
                maximum_portable_uid: 0,
                maximum_portable_gid: 0,
                distinct_inode_count: 1,
                directory_entry_count: 0,
                identity_tree_digest: ObjectDigest::from_bytes([8; 32]),
            },
        };
        let version_three = encode_result_with_mount(digest, measured);
        let version_two = encode_result(digest, measured);
        let temporary = tempfile::tempfile().unwrap();
        let descriptor = rustix::io::dup(temporary.as_fd()).unwrap();

        assert!(decode_result_with_mount(&version_three, digest, 7, 9, Vec::new()).is_err());
        assert!(
            decode_result_with_mount(
                &version_three,
                digest,
                7,
                9,
                vec![rustix::io::dup(temporary.as_fd()).unwrap(), descriptor],
            )
            .is_err()
        );
        assert!(
            decode_result_with_mount(
                &version_two,
                digest,
                7,
                9,
                vec![rustix::io::dup(temporary.as_fd()).unwrap()],
            )
            .is_err()
        );
        assert!(
            decode_result_with_mount(
                &version_three,
                ObjectDigest::from_bytes([9; 32]),
                7,
                9,
                vec![rustix::io::dup(temporary.as_fd()).unwrap()],
            )
            .is_err()
        );
        assert!(
            decode_result_with_mount(
                &version_three,
                digest,
                7,
                9,
                vec![rustix::io::dup(temporary.as_fd()).unwrap()],
            )
            .is_err()
        ); // A regular file cannot impersonate a detached snapshot mount.
    }

    #[test]
    fn descriptor_result_transport_rejects_missing_or_extra_rights() {
        let (mut receiver, sender_fd) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender_fd).unwrap();
        sender.send(b"AOSHSM03").unwrap();
        assert!(receiver.receive_with_descriptors(RESULT_BYTES, 1).is_err());

        let (mut receiver, sender_fd) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender_fd).unwrap();
        let file = tempfile::tempfile().unwrap();
        sender
            .send_with_descriptors(b"AOSHSM03", &[file.as_fd(), file.as_fd()])
            .unwrap();
        assert!(receiver.receive_with_descriptors(RESULT_BYTES, 1).is_err());
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
        let expected_snapshot_guid = if matches!(variant, "wrong-snapshot" | "wrong-snapshot-mount")
        {
            different_guid(snapshot_guid)
        } else {
            snapshot_guid
        };
        let snapshot =
            ResolvedSnapshot::from_catalog(dataset, "held", expected_snapshot_guid, [6; 32])
                .unwrap();
        let expected_pool_guid = if matches!(variant, "wrong-pool" | "wrong-pool-mount") {
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
        let observation = if variant.ends_with("-mount") {
            reader
                .measure_with_mount(
                    &snapshot,
                    expected_pool_guid,
                    ObjectDigest::from_bytes([7; 32]),
                    [8; 16],
                )
                .map(|(measured, mount)| (measured, Some(mount)))
        } else {
            reader
                .measure(
                    &snapshot,
                    expected_pool_guid,
                    ObjectDigest::from_bytes([7; 32]),
                    [8; 16],
                )
                .map(|measured| (measured, None))
        };
        match variant {
            "matched" | "matched-mount" => {
                let (measured, mount) = observation.unwrap();
                assert_eq!(measured.mounted_snapshot_guid, snapshot_guid);
                assert_ne!(measured.content_digest.as_bytes(), &[0; 32]);
                assert!(measured.mount_id > 0);
                assert_eq!(measured.nodes, 5);
                assert_eq!(measured.file_bytes, 31);
                assert_eq!(measured.identity.root_attributes.uid(), 0);
                assert_eq!(measured.identity.root_attributes.gid(), 0);
                assert_eq!(measured.identity.maximum_portable_uid, 42);
                assert_eq!(measured.identity.maximum_portable_gid, 43);
                assert_eq!(measured.identity.root_attributes.mode(), 0o755);
                assert_eq!(
                    measured.identity.distinct_inode_count,
                    u64::from(measured.nodes)
                );
                assert_eq!(
                    measured.identity.directory_entry_count + 1,
                    measured.identity.distinct_inode_count
                );
                assert_ne!(measured.identity.identity_tree_digest.as_bytes(), &[0; 32]);
                // Independently hash the documented identity-tree preimage:
                // root, nested, nested/deeper, nested/deeper/data, payload.
                // Directories are 0:0/0755; data is 0:0/0644; payload is 42:43/0644.
                assert_eq!(
                    measured.identity.identity_tree_digest.to_string(),
                    "sha256:cbd8b117f5f23a573e18f47d8768a45fc0970152a0583b1ac3484e2b882dd206",
                );
                if variant == "matched-mount" {
                    let mount = mount.unwrap();

                    // measure_with_mount waits for the whole one-shot unit to
                    // quiesce before returning. Its detached root must remain
                    // readable after the privileged reader has exited.
                    reader.prove_prior_readers_empty().unwrap();
                    verify_received_mount_fd(mount.as_fd(), &measured, pool_guid).unwrap();
                    let payload = openat(
                        mount.as_fd(),
                        "payload",
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .unwrap();
                    let mut payload = fs::File::from(payload);
                    let mut contents = String::new();
                    payload.read_to_string(&mut contents).unwrap();
                    assert_eq!(contents, "held reader service payload\n");

                    let nested = openat(
                        mount.as_fd(),
                        "nested/deeper/data",
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .unwrap();
                    let mut contents = String::new();
                    fs::File::from(nested)
                        .read_to_string(&mut contents)
                        .unwrap();
                    assert_eq!(contents, "abc");
                } else {
                    assert!(mount.is_none());
                }
            }
            "wrong-pool" | "wrong-snapshot" | "wrong-pool-mount" | "wrong-snapshot-mount" => {
                assert!(observation.is_err());
                assert!(!reader.fail_stopped);
            }
            _ => panic!("unknown held-reader VM case"),
        }
    }

    #[test]
    #[ignore = "requires UID0, held ZFS snapshot, and VM-only private mount namespace"]
    fn systemd_reader_vm_mount_crossings() {
        use crate::held_snapshot_tree::{
            HeldSnapshotTreeErrorV1, measure_read_only_held_snapshot_tree,
        };
        use aos_sandbox_linux::mount::{DetachedMount, FileSystemContext, MountAttributes};
        use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
        use std::os::unix::fs::MetadataExt as _;

        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let namespace = fs::metadata("/proc/self/ns/mnt").unwrap();
        let host_namespace = fs::metadata("/proc/1/ns/mnt").unwrap();
        assert_ne!(
            (namespace.dev(), namespace.ino()),
            (host_namespace.dev(), host_namespace.ino()),
            "mount mutations require the fleet's isolated test namespace",
        );

        let case = fs::read_to_string("/run/aos/held-reader-case").unwrap();
        let fields = case.trim().split(':').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        let (measured, mount) = measure_bound_detached_snapshot_with_mount(
            "aosproof/aos/project/workspace@held",
            fields[1].parse().unwrap(),
            fields[4].parse().unwrap(),
        )
        .unwrap();
        assert_eq!((measured.nodes, measured.file_bytes), (5, 31));

        let directory = private_test_state();
        fs::create_dir(directory.path().join("root")).unwrap();
        let parent = BeneathRoot::from_owned(
            rustix::fs::open(
                directory.path(),
                OFlags::PATH | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        mount
            .attach(
                &parent
                    .resolve(Path::new("root"), ResolveOptions::directory())
                    .unwrap(),
            )
            .unwrap();
        let root_path = directory.path().join("root");
        let root = BeneathRoot::from_owned(
            rustix::fs::open(&root_path, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap(),
        )
        .unwrap();
        let baseline = measure_read_only_held_snapshot_tree(
            rustix::io::dup(root.as_fd()).unwrap(),
            measured.content_digest,
        )
        .unwrap();
        assert_eq!((baseline.nodes, baseline.file_bytes), (5, 31));

        // Directory nesting is not mount nesting. Reject an actual mount
        // crossing even when its device is identical to the selected root.
        for same_filesystem in [true, false] {
            let child = if same_filesystem {
                DetachedMount::clone_from(
                    &root
                        .resolve(Path::new("nested/deeper"), ResolveOptions::directory())
                        .unwrap(),
                    false,
                )
                .unwrap()
            } else {
                FileSystemContext::open("tmpfs")
                    .unwrap()
                    .create()
                    .unwrap()
                    .mount()
                    .unwrap()
            };
            child
                .set_attributes(
                    true,
                    MountAttributes::secure_read_only().with_no_exec(true),
                    None,
                )
                .unwrap();
            child
                .attach(
                    &root
                        .resolve(Path::new("nested"), ResolveOptions::directory())
                        .unwrap(),
                )
                .unwrap();
            let crossed = openat(
                root.as_fd(),
                "nested",
                OFlags::PATH | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            assert_eq!(
                fstat(&crossed).unwrap().st_dev == measured.root_device,
                same_filesystem
            );
            assert_ne!(
                MountId::from_fd(crossed.as_fd()).unwrap(),
                measured.mount_id
            );

            let error = measure_read_only_held_snapshot_tree(
                rustix::io::dup(root.as_fd()).unwrap(),
                measured.content_digest,
            )
            .unwrap_err();
            let HeldSnapshotTreeErrorV1::Linux(aos_sandbox_linux::Error::Syscall {
                source, ..
            }) = error
            else {
                panic!("walk did not reject the mount crossing with EXDEV: {error}");
            };
            assert_eq!(
                source.raw_os_error(),
                Some(rustix::io::Errno::XDEV.raw_os_error())
            );
            drop(crossed);
            rustix::mount::unmount(
                root_path.join("nested"),
                rustix::mount::UnmountFlags::NOFOLLOW,
            )
            .unwrap();
        }
        drop(root);
        rustix::mount::unmount(&root_path, rustix::mount::UnmountFlags::NOFOLLOW).unwrap();
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
