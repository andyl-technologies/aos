//! Bounded original procfs descriptors observed under an actual retained pidfd.
//!
//! The reservoir parks stat and context descriptors before inspecting or reading
//! them. Continued observations rewind those same descriptors; they never open
//! a child pathname again. This is nonauthorizing DATA: its owner must retain and
//! supply the same original pidfd, authenticate its role and apply current policy.
//! Err, incomplete capture and caught unwind permanently close the reservoir.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::process::Child;

use rustix::fs::{Mode, OFlags, fcntl_getfl, fstatfs, open};

use super::identity::{MAXIMUM_PROC_STAT_BYTES, identity_from_stat, parse_proc_stat};
use super::{NamespaceFd, NamespaceIdentity, NamespaceKind, PidFd, PidFdInfo, PidFdProcessIdentity};
use crate::{Error, Result};

const PROCFS_MAGIC: u64 = 0x9fa0;
const CONTEXT_BYTES: usize = 256;
const READ_INTERRUPT_LIMIT: usize = 8;
const NIX_HELPER_STATUS_BYTES: usize = 64 * 1024;
const NIX_HELPER_MAPS_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationPhaseV1 {
    Fresh,
    StatCaptured,
    Ready,
    Closed,
}

#[derive(Clone, Copy)]
enum ProcFileV1 {
    Stat,
    Context,
    NixHelperStatus,
    NixHelperMaps,
    HostCanaryStatus,
    HostCanaryMaps,
}

impl ProcFileV1 {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Stat => "stat",
            Self::Context => "attr/current",
            Self::NixHelperStatus | Self::HostCanaryStatus => "status",
            Self::NixHelperMaps | Self::HostCanaryMaps => "maps",
        }
    }

    const fn maximum(self) -> usize {
        match self {
            Self::Stat => MAXIMUM_PROC_STAT_BYTES,
            Self::Context => CONTEXT_BYTES,
            Self::NixHelperStatus | Self::HostCanaryStatus => NIX_HELPER_STATUS_BYTES,
            Self::NixHelperMaps | Self::HostCanaryMaps => NIX_HELPER_MAPS_BYTES,
        }
    }
}

struct NixHelperOriginalsV1 {
    status: ProcDescriptorV1,
    executable: Option<File>,
    executable_identity: Option<(u64, u64, u64)>,
    maps: ProcDescriptorV1,
    captured: bool,
}

impl NixHelperOriginalsV1 {
    const fn empty() -> Self {
        Self {
            status: ProcDescriptorV1::empty(),
            executable: None,
            executable_identity: None,
            maps: ProcDescriptorV1::empty(),
            captured: false,
        }
    }
}

struct ProcDescriptorV1 {
    file: Option<File>,
    initial: Vec<u8>,
    current: Vec<u8>,
}

/// Retains original inspection DATA for an actual child of Guest PID 1.
///
/// The selected immutable bootstrap supplies the `Child` returned by its one
/// fixed Agent spawn. This owner selects no caller PID, path, descriptor or
/// namespace. It proves neither which executable was approved nor who launched
/// it; the genuine bootstrap and Host must perform those purpose comparisons.
/// Failed observations retain returned originals and partial buffers, while
/// fencing this instance. Lower syscall/library pre-return prefixes remain
/// outside its custody, and dropping it is not a process-drain observation.
pub struct HostCanaryLocalChildOriginalsV1 {
    raw_pidfd: Option<OwnedFd>,
    child: Option<PidFd>,
    observations: Option<PidFdProcObservationsV1>,
    executable: Option<File>,
    executable_identity: Option<(u64, u64, u64)>,
    maps: ProcDescriptorV1,
    status: ProcDescriptorV1,
    namespace_raw: [Option<OwnedFd>; 4],
    namespaces: [Option<NamespaceFd>; 4],
    original_info: Option<PidFdInfo>,
    sent_reports: u8,
    attempted: bool,
    closed: bool,
}

impl HostCanaryLocalChildOriginalsV1 {
    /// Creates fixed empty slots without acquiring or authorizing a process.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            raw_pidfd: None,
            child: None,
            observations: None,
            executable: None,
            executable_identity: None,
            maps: ProcDescriptorV1::empty(),
            status: ProcDescriptorV1::empty(),
            namespace_raw: [None, None, None, None],
            namespaces: [None, None, None, None],
            original_info: None,
            sent_reports: 0,
            attempted: false,
            closed: false,
        }
    }

    /// Captures only the real child lent by the selected Guest bootstrap.
    ///
    /// Every returned descriptor enters a resident slot before its subsequent
    /// validation. The caller must park the actual `Child` before this call and
    /// retain it, this owner and the first returned error until real cleanup.
    ///
    /// # Errors
    /// Refuses repetition, a caller other than root Guest PID 1, an unavailable
    /// or foreign child, changed identity, denied proc/namespace access, wrong
    /// descriptor kinds, failed reads and records beyond the fixed bounds.
    /// Errors and caught unwinds leave this same owner permanently closed.
    pub fn capture_original(&mut self, actual_child: &Child) -> Result<()> {
        if self.attempted || self.closed {
            return Err(closed());
        }
        self.attempted = true;
        self.closed = true;
        self.capture_inner(actual_child)?;
        self.closed = false;
        Ok(())
    }

    fn capture_inner(&mut self, actual_child: &Child) -> Result<()> {
        if std::process::id() != 1 || rustix::process::geteuid().as_raw() != 0 {
            return Err(Error::invalid("Guest child originals", "caller is not root Guest PID 1"));
        }
        let pid = actual_child.id();
        if pid <= 1 {
            return Err(Error::invalid("Guest child originals", "actual child ID is unavailable"));
        }

        self.raw_pidfd = Some(crate::uapi::pidfd_open(pid)?);
        PidFd::validate_owned_kind(self.raw_pidfd.as_ref().ok_or_else(closed)?.as_fd())?;
        if let Some(fd) = self.raw_pidfd.take() {
            self.child = Some(PidFd { fd });
        }
        let info = self.child()?.info()?;
        if info.pid() != pid || info.thread_group_id() != pid || info.parent_pid() != 1
            || !self.child()?.is_alive()?
        {
            return Err(Error::invalid("Guest child originals", "pin differs from the actual child"));
        }
        self.original_info = Some(info);
        self.observations = Some(self.child()?.prepare_proc_observations_v1());
        {
            let child = self.child.as_ref().ok_or_else(closed)?;
            let observations = self.observations.as_mut().ok_or_else(closed)?;
            observations.capture_stat(child)?;
            observations.capture_context(child)?;
        }
        self.require_same_child()?;

        let path = format!("/proc/{pid}/exe");
        let descriptor = open(path.as_str(), OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|source| Error::Syscall {
                operation: "open(original Guest child executable)",
                source: source.into(),
            })?;
        self.executable = Some(File::from(descriptor));
        let executable = self.executable.as_ref().ok_or_else(closed)?;
        let metadata = executable.metadata().map_err(|source| Error::Syscall {
            operation: "fstat(original Guest child executable)",
            source,
        })?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(Error::invalid("Guest child originals", "executed image is not regular"));
        }
        self.executable_identity = Some((metadata.dev(), metadata.ino(), metadata.len()));
        self.require_same_child()?;

        self.maps.capture(pid, ProcFileV1::HostCanaryMaps)?;
        self.require_same_child()?;
        self.status.capture(pid, ProcFileV1::HostCanaryStatus)?;
        self.require_same_child()?;

        for (slot, kind) in CANARY_CHILD_NAMESPACES.into_iter().enumerate() {
            self.namespace_raw[slot] = Some(self.child()?.acquire_namespace_original(kind)?);
            let identity = NamespaceFd::validate_original_kind(
                self.namespace_raw[slot].as_ref().ok_or_else(closed)?.as_fd(), kind,
            )?;
            self.require_same_child()?;
            if let Some(fd) = self.namespace_raw[slot].take() {
                self.namespaces[slot] = Some(NamespaceFd { fd, kind, identity });
            }
        }
        self.require_same_child()
    }

    fn child(&self) -> Result<&PidFd> {
        self.child.as_ref().ok_or_else(closed)
    }

    fn require_same_child(&self) -> Result<()> {
        if self.original_info != Some(self.child()?.info()?) || !self.child()?.is_alive()? {
            return Err(Error::invalid("Guest child originals", "original child changed or exited"));
        }
        Ok(())
    }

    /// Rechecks the same live child and rereads only its retained originals.
    ///
    /// # Errors
    /// Refuses an incomplete/closed owner or changed identity, image, namespace,
    /// stat, denied metadata access and bounded-read failure. It never reopens
    /// a proc pathname or restores an owner after error or interruption.
    pub fn recheck_original(&mut self) -> Result<()> {
        if !self.attempted || self.closed {
            return Err(closed());
        }
        self.closed = true;
        self.recheck_inner()?;
        self.closed = false;
        Ok(())
    }

    fn recheck_inner(&mut self) -> Result<()> {
        self.require_same_child()?;
        let child = self.child.as_ref().ok_or_else(closed)?;
        let observations = self.observations.as_mut().ok_or_else(closed)?;
        observations.observe_identity(child)?;
        observations.observe_context(child)?;
        self.maps.read(NIX_HELPER_MAPS_BYTES)?;
        self.status.read(NIX_HELPER_STATUS_BYTES)?;

        let metadata = self.executable.as_ref().ok_or_else(closed)?.metadata()
            .map_err(|source| Error::Syscall {
                operation: "fstat(original Guest child executable)", source,
            })?;
        if self.executable_identity != Some((metadata.dev(), metadata.ino(), metadata.len())) {
            return Err(Error::invalid("Guest child originals", "original executed image changed"));
        }
        for (slot, kind) in CANARY_CHILD_NAMESPACES.into_iter().enumerate() {
            let namespace = self.namespaces[slot].as_ref().ok_or_else(closed)?;
            if NamespaceFd::validate_original_kind(namespace.as_fd(), kind)? != namespace.identity() {
                return Err(Error::invalid("Guest child originals", "original namespace changed"));
            }
        }
        self.require_same_child()
    }

    pub(crate) fn first_report_descriptors(&self) -> Result<[BorrowedFd<'_>; 5]> {
        if self.closed {
            return Err(closed());
        }
        let observations = self.observations.as_ref().ok_or_else(closed)?;
        Ok([
            self.child()?.as_fd(),
            self.executable.as_ref().ok_or_else(closed)?.as_fd(),
            self.maps.file.as_ref().ok_or_else(closed)?.as_fd(),
            observations.stat.file.as_ref().ok_or_else(closed)?.as_fd(),
            self.status.file.as_ref().ok_or_else(closed)?.as_fd(),
        ])
    }

    pub(crate) fn second_report_descriptors(&self) -> Result<[BorrowedFd<'_>; 5]> {
        if self.closed {
            return Err(closed());
        }
        let observations = self.observations.as_ref().ok_or_else(closed)?;
        let namespace = |slot: usize| -> Result<BorrowedFd<'_>> {
            Ok(self.namespaces[slot].as_ref().ok_or_else(closed)?.as_fd())
        };
        Ok([
            observations.context.file.as_ref().ok_or_else(closed)?.as_fd(),
            namespace(0)?, namespace(1)?, namespace(2)?, namespace(3)?,
        ])
    }

    pub(crate) fn local_child_pid(&self) -> Result<u32> {
        self.original_info.map(|info| info.pid()).ok_or_else(closed)
    }

    pub(crate) fn require_report_stage(&mut self, stage: u8) -> Result<()> {
        if self.closed || self.sent_reports != stage || stage > 1 {
            self.closed = true;
            return Err(closed());
        }
        self.recheck_original()
    }

    pub(crate) fn record_sent_stage(&mut self, stage: u8) {
        // The sender checked this stage before the atomic syscall. Recording
        // its completed effect precedes every fallible post-send observation.
        self.sent_reports = stage + 1;
    }

    pub(crate) fn fence(&mut self) {
        self.closed = true;
    }
}

impl Default for HostCanaryLocalChildOriginalsV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Retains the two fixed original-child reports observed by the actual Host.
///
/// The carrier establishes kernel nomination and same-socket continuity only.
/// This owner keeps Guest-local proc coordinates separate from Host-visible
/// pidfd facts. The Host must independently authenticate the measured Guest
/// bootstrap, package/image, mapping, cgroup, invocation, job and original D.
/// No received bytes or namespace object is a launch or currentness authority.
pub struct HostCanaryReceivedChildOriginalsV1 {
    supervisor_record: Option<crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord>,
    supervisor_payload: Vec<u8>,
    supervisor_subject: Option<crate::seqpacket::KernelAuthorizedRecordSubject>,
    supervisor_executable: Option<File>,
    supervisor_network: Option<OwnedFd>,
    supervisor_stat: ProcDescriptorV1,
    supervisor_identity: Option<PidFdProcessIdentity>,
    supervisor_network_identity: Option<NamespaceIdentity>,
    supervisor_attempted: bool,
    supervisor_captured: bool,
    bootstrap_records: [Option<crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord>; 3],
    bootstrap_raw: [Option<OwnedFd>; 11],
    bootstrap_payloads: [Vec<u8>; 3],
    bootstrap_subjects: [Option<crate::seqpacket::KernelAuthorizedRecordSubject>; 3],
    bootstrap_stat: ProcDescriptorV1,
    bootstrap_status: ProcDescriptorV1,
    bootstrap_context: ProcDescriptorV1,
    bootstrap_uid_map: ProcDescriptorV1,
    bootstrap_gid_map: ProcDescriptorV1,
    bootstrap_info: Option<PidFdInfo>,
    bootstrap_local_identity: Option<(u32, u32, u64)>,
    bootstrap_namespaces: [Option<NamespaceIdentity>; 4],
    bootstrap_attempted: bool,
    bootstrap_captured: bool,
    systemd_record: Option<crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord>,
    systemd_payload: Vec<u8>,
    systemd_subject: Option<crate::seqpacket::KernelAuthorizedRecordSubject>,
    systemd_executable: Option<File>,
    systemd_executable_identity: Option<(u64, u64, u64)>,
    systemd_attempted: bool,
    systemd_captured: bool,
    records: [Option<crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord>; 2],
    payloads: [Vec<u8>; 2],
    subjects: [Option<crate::seqpacket::KernelAuthorizedRecordSubject>; 2],
    raw: [Option<OwnedFd>; 10],
    child: Option<PidFd>,
    executable: Option<File>,
    executable_identity: Option<(u64, u64, u64)>,
    stat: ProcDescriptorV1,
    maps: ProcDescriptorV1,
    status: ProcDescriptorV1,
    context: ProcDescriptorV1,
    namespace_identities: [Option<NamespaceIdentity>; 4],
    original_info: Option<PidFdInfo>,
    local_identity: Option<(u32, u32, u64)>,
    cookie: Option<std::num::NonZeroU64>,
    attempted: bool,
    closed: bool,
}

/// Preserves the actual inspection or carrier cause for received-child DATA.
#[derive(Debug, thiserror::Error)]
pub enum HostCanaryReceivedChildErrorV1 {
    /// A borrowed kernel, descriptor or bounded observation failed.
    #[error(transparent)]
    Inspection(#[from] Error),
    /// The actual original socket or consumed report did not correlate.
    #[error(transparent)]
    Carrier(#[from] crate::seqpacket::SeqpacketError),
}

impl HostCanaryReceivedChildOriginalsV1 {
    /// Creates empty fixed resident slots without receiving or validating DATA.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            supervisor_record: None,
            supervisor_payload: Vec::new(),
            supervisor_subject: None,
            supervisor_executable: None,
            supervisor_network: None,
            supervisor_stat: ProcDescriptorV1::empty(),
            supervisor_identity: None,
            supervisor_network_identity: None,
            supervisor_attempted: false,
            supervisor_captured: false,
            bootstrap_records: [None, None, None],
            bootstrap_raw: [None, None, None, None, None, None, None, None, None, None, None],
            bootstrap_payloads: [Vec::new(), Vec::new(), Vec::new()],
            bootstrap_subjects: [None, None, None],
            bootstrap_stat: ProcDescriptorV1::empty(),
            bootstrap_status: ProcDescriptorV1::empty(),
            bootstrap_context: ProcDescriptorV1::empty(),
            bootstrap_uid_map: ProcDescriptorV1::empty(),
            bootstrap_gid_map: ProcDescriptorV1::empty(),
            bootstrap_info: None,
            bootstrap_local_identity: None,
            bootstrap_namespaces: [None; 4],
            bootstrap_attempted: false,
            bootstrap_captured: false,
            systemd_record: None,
            systemd_payload: Vec::new(),
            systemd_subject: None,
            systemd_executable: None,
            systemd_executable_identity: None,
            systemd_attempted: false,
            systemd_captured: false,
            records: [None, None],
            payloads: [Vec::new(), Vec::new()],
            subjects: [None, None],
            raw: [None, None, None, None, None, None, None, None, None, None],
            child: None,
            executable: None,
            executable_identity: None,
            stat: ProcDescriptorV1::empty(),
            maps: ProcDescriptorV1::empty(),
            status: ProcDescriptorV1::empty(),
            context: ProcDescriptorV1::empty(),
            namespace_identities: [None; 4],
            original_info: None,
            local_identity: None,
            cookie: None,
            attempted: false,
            closed: false,
        }
    }

    /// Parks the native supervisor's three fixed original-report roles once.
    ///
    /// The carrier and canonical stat observation are DATA. Authentic manager
    /// MainPID/invocation/cgroup, approved image and job matching remain the
    /// actual Host consumer's responsibility. The self-stat original avoids
    /// assuming that cap-zero Host can reopen the supervisor's proc pathname.
    ///
    /// # Errors
    /// Refuses repeated/out-of-order capture, foreign carrier/framing/counts,
    /// invalid namespaces or proc originals, changed process facts and exit.
    /// The entire record is resident before checking its fixed three roles;
    /// all returned originals remain owned and failure/unwind fences the loan.
    pub fn capture_original_supervisor_report(
        &mut self,
        record: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        socket: &mut crate::seqpacket::SeqpacketSocket,
    ) -> std::result::Result<(), HostCanaryReceivedChildErrorV1> {
        if self.supervisor_attempted || self.bootstrap_attempted || self.closed {
            self.closed = true;
            return Err(closed().into());
        }
        self.supervisor_record = Some(record);
        self.supervisor_attempted = true;
        self.closed = true;
        self.capture_supervisor_inner(socket)?;
        self.supervisor_captured = true;
        self.closed = false;
        Ok(())
    }

    fn capture_supervisor_inner(&mut self, socket: &mut crate::seqpacket::SeqpacketSocket)
        -> std::result::Result<(), HostCanaryReceivedChildErrorV1>
    {
        self.cookie = Some(socket.peer().socket_cookie());
        let record = self.supervisor_record.as_ref().ok_or_else(closed)?;
        socket.require_host_canary_report_original_v1(record)?;
        let payload = record.payload();
        if payload.len() != 176 || record.descriptors().len() != 3
            || &payload[..8] != b"AOSHCR01"
            || payload[8..10] != 1_u16.to_be_bytes()
            || payload[10..12] != 1_u16.to_be_bytes()
            || payload[12..16] != 176_u32.to_be_bytes()
            || payload[160..176] != [0; 16]
        {
            return Err(Error::invalid("native supervisor original", "fixed report differs").into());
        }

        // Exact role count is known before this infallible transfer. Each File
        // is installed in the resident owner before flags, namespace ioctls,
        // stat reads or process postchecks can fail.
        if let Some(record) = self.supervisor_record.take() {
            let (payload, subject, descriptors) = record.into_parts();
            self.supervisor_payload = payload;
            self.supervisor_subject = Some(subject);
            for (slot, descriptor) in descriptors.into_iter().enumerate() {
                match slot {
                    0 => self.supervisor_executable = Some(File::from(descriptor)),
                    1 => self.supervisor_network = Some(descriptor),
                    2 => self.supervisor_stat.file = Some(File::from(descriptor)),
                    _ => unreachable!(),
                }
            }
        }
        self.supervisor_network_identity = Some(NamespaceFd::validate_original_kind(
            self.supervisor_network.as_ref().ok_or_else(closed)?.as_fd(),
            NamespaceKind::Network,
        )?);
        self.supervisor_stat.require_read_only_proc()?;
        self.supervisor_identity = Some(self.read_supervisor_identity()?);
        socket.require_host_canary_cookie(self.cookie.ok_or_else(closed)?)?;
        Ok(())
    }

    fn read_supervisor_identity(&mut self) -> Result<PidFdProcessIdentity> {
        let subject = self.supervisor_subject.as_ref().ok_or_else(closed)?;
        let original = subject.pidfd();
        let before = original.info()?;
        if before != subject.initial_info() || !subject.is_alive()? {
            return Err(Error::invalid("native supervisor original", "original subject changed or exited"));
        }
        self.supervisor_stat.read(MAXIMUM_PROC_STAT_BYTES)?;
        let parsed = parse_proc_stat(&self.supervisor_stat.current)?;
        if parsed.start_time_ticks() == 0 {
            return Err(Error::invalid("native supervisor original", "original start ticks are zero"));
        }
        let after = original.info()?;
        identity_from_stat(original, before, parsed, after)
    }

    /// Parks the Guest bootstrap's three fixed original-report records once.
    ///
    /// The actual receiver supplies complete records, never bare descriptors.
    /// The same carrier, namespace validator, bounded proc reader and canonical
    /// stat parser are used for both bootstrap and child. All received objects
    /// remain resident on failure; the caller retains the actual first cause.
    /// This proves neither the approved bootstrap image nor its cgroup/root.
    ///
    /// # Errors
    /// Refuses repetition, wrong framing/counts, changed subjects, failed
    /// descriptor inspection, denied reads and non-PID1 local coordinates.
    pub fn capture_original_bootstrap_reports(
        &mut self,
        root: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        metadata: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        executable: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        socket: &mut crate::seqpacket::SeqpacketSocket,
    ) -> std::result::Result<(), HostCanaryReceivedChildErrorV1> {
        if self.bootstrap_attempted || self.attempted || self.closed || !self.supervisor_captured {
            self.closed = true;
            return Err(closed().into());
        }
        self.bootstrap_records = [Some(root), Some(metadata), Some(executable)];
        self.bootstrap_attempted = true;
        self.closed = true;
        self.capture_bootstrap_inner(socket)?;
        self.bootstrap_captured = true;
        self.closed = false;
        Ok(())
    }

    fn capture_bootstrap_inner(&mut self, socket: &mut crate::seqpacket::SeqpacketSocket)
        -> std::result::Result<(), HostCanaryReceivedChildErrorV1>
    {
        self.cookie = Some(socket.peer().socket_cookie());
        for (stage, (kind, count)) in [(3_u16, 5), (4, 5), (5, 1)].into_iter().enumerate() {
            let record = self.bootstrap_records[stage].as_ref().ok_or_else(closed)?;
            socket.require_host_canary_report_original_v1(record)?;
            let payload = record.payload();
            if payload.len() != 176 || record.descriptors().len() != count
                || &payload[..8] != b"AOSHCR01"
                || payload[8..10] != 1_u16.to_be_bytes()
                || payload[10..12] != kind.to_be_bytes()
                || payload[12..16] != 176_u32.to_be_bytes()
                || payload[168..176] != (stage as u64).to_be_bytes()
            {
                return Err(Error::invalid("Guest bootstrap originals", "fixed report differs").into());
            }
            let first = self.bootstrap_records[0].as_ref().ok_or_else(closed)?;
            if payload[16..168] != first.payload()[16..168]
                || payload[16..168] != self.supervisor_payload[16..168]
                || record.subject().initial_info() != first.subject().initial_info()
                || !record.subject().is_alive()?
            {
                return Err(Error::invalid("Guest bootstrap originals", "original sender differs").into());
            }
        }

        // Counts and ordering were checked while every complete record stayed
        // parked. All moves into fixed original slots are now infallible.
        for stage in 0..3 {
            if let Some(record) = self.bootstrap_records[stage].take() {
                let (payload, subject, descriptors) = record.into_parts();
                self.bootstrap_payloads[stage] = payload;
                self.bootstrap_subjects[stage] = Some(subject);
                for (index, descriptor) in descriptors.into_iter().enumerate() {
                    self.bootstrap_raw[stage * 5 + index] = Some(descriptor);
                }
            }
        }
        self.bootstrap_info = Some(self.bootstrap_subjects[0].as_ref().ok_or_else(closed)?.initial_info());
        for (slot, kind) in CANARY_CHILD_NAMESPACES.into_iter().enumerate() {
            self.bootstrap_namespaces[slot] = Some(NamespaceFd::validate_original_kind(
                self.bootstrap_raw[1 + slot].as_ref().ok_or_else(closed)?.as_fd(), kind,
            )?);
        }
        self.bootstrap_stat.file = self.bootstrap_raw[5].take().map(File::from);
        self.bootstrap_status.file = self.bootstrap_raw[6].take().map(File::from);
        self.bootstrap_context.file = self.bootstrap_raw[7].take().map(File::from);
        self.bootstrap_uid_map.file = self.bootstrap_raw[8].take().map(File::from);
        self.bootstrap_gid_map.file = self.bootstrap_raw[9].take().map(File::from);
        for descriptor in [
            &self.bootstrap_stat, &self.bootstrap_status, &self.bootstrap_context,
            &self.bootstrap_uid_map, &self.bootstrap_gid_map,
        ] {
            descriptor.require_read_only_proc()?;
        }
        self.reread_bootstrap_originals()?;
        let stat = parse_proc_stat(&self.bootstrap_stat.current)?;
        if stat.pid() != 1 || stat.parent_pid() != 0 || stat.start_time_ticks() == 0 {
            return Err(Error::invalid("Guest bootstrap originals", "local process is not PID1").into());
        }
        self.bootstrap_local_identity = Some((stat.pid(), stat.parent_pid(), stat.start_time_ticks()));
        self.require_bootstrap_subjects()?;
        socket.require_host_canary_cookie(self.cookie.ok_or_else(closed)?)?;
        Ok(())
    }

    fn reread_bootstrap_originals(&mut self) -> Result<()> {
        self.bootstrap_stat.read(MAXIMUM_PROC_STAT_BYTES)?;
        self.bootstrap_status.read(NIX_HELPER_STATUS_BYTES)?;
        self.bootstrap_context.read(CONTEXT_BYTES)?;
        self.bootstrap_uid_map.read(128)?;
        self.bootstrap_gid_map.read(128)
    }

    fn require_bootstrap_subjects(&self) -> Result<()> {
        for subject in &self.bootstrap_subjects {
            let subject = subject.as_ref().ok_or_else(closed)?;
            if Some(subject.pidfd().info()?) != self.bootstrap_info || !subject.is_alive()? {
                return Err(Error::invalid("Guest bootstrap originals", "original sender changed or exited"));
            }
        }
        let supervisor = self.supervisor_subject.as_ref().ok_or_else(closed)?;
        if supervisor.pidfd().info()? != supervisor.initial_info() || !supervisor.is_alive()?
            || self.bootstrap_info.ok_or_else(closed)?.parent_pid() != supervisor.initial_info().pid()
        {
            return Err(Error::invalid("Guest bootstrap originals", "original supervisor lineage differs"));
        }
        Ok(())
    }

    /// Parks and inspects the actual ordered five/five child reports once.
    ///
    /// Both complete records enter resident slots before any fallible check.
    /// Typed pidfd construction uses the same borrowed validator and only an
    /// infallible move after success. The caller retains this owner and the
    /// first returned cause on error or unwind; no original is cloned.
    ///
    /// # Errors
    /// Refuses repeated capture, foreign origins, wrong fixed framing/roles,
    /// inconsistent subjects/child identity, denied reads, malformed local
    /// stat, excess bytes and wrong namespace objects. Failure fences this
    /// owner; unreturned lower receive prefixes remain the caller's custody.
    pub fn capture_original_reports(
        &mut self,
        first: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        second: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        original_socket: &mut crate::seqpacket::SeqpacketSocket,
    ) -> std::result::Result<(), HostCanaryReceivedChildErrorV1> {
        if self.attempted || self.closed || !self.bootstrap_captured {
            self.closed = true;
            return Err(closed().into());
        }
        self.records = [Some(first), Some(second)];
        self.attempted = true;
        self.closed = true;
        self.capture_reports_inner(original_socket)?;
        self.closed = false;
        Ok(())
    }

    fn capture_reports_inner(&mut self, socket: &mut crate::seqpacket::SeqpacketSocket)
        -> std::result::Result<(), HostCanaryReceivedChildErrorV1>
    {
        self.cookie = Some(socket.peer().socket_cookie());
        for (stage, expected_kind) in [7_u16, 8_u16].into_iter().enumerate() {
            let record = self.records[stage].as_ref().ok_or_else(closed)?;
            socket.require_host_canary_report_original_v1(record)?;
            let payload = record.payload();
            if payload.len() != 176 || record.descriptors().len() != 5
                || &payload[..8] != b"AOSHCR01"
                || payload[8..10] != 1_u16.to_be_bytes()
                || payload[10..12] != expected_kind.to_be_bytes()
                || payload[12..16] != 176_u32.to_be_bytes()
            {
                return Err(Error::invalid("received Guest child", "fixed report framing differs").into());
            }
        }
        let first = self.records[0].as_ref().ok_or_else(closed)?;
        let second = self.records[1].as_ref().ok_or_else(closed)?;
        if first.payload()[16..176] != second.payload()[16..176]
            || first.payload()[16..168] != self.bootstrap_payloads[0][16..168]
            || first.subject().initial_info() != second.subject().initial_info()
            || !first.subject().is_alive()? || !second.subject().is_alive()?
        {
            return Err(Error::invalid("received Guest child", "original reports or subjects differ").into());
        }

        // Exact counts were checked while both complete records remained
        // resident. Transfer every original into fixed slots before validation.
        for stage in 0..2 {
            if let Some(record) = self.records[stage].take() {
                let (payload, subject, descriptors) = record.into_parts();
                self.payloads[stage] = payload;
                self.subjects[stage] = Some(subject);
                for (slot, descriptor) in descriptors.into_iter().enumerate() {
                    self.raw[stage * 5 + slot] = Some(descriptor);
                }
            }
        }
        PidFd::validate_owned_kind(self.raw[0].as_ref().ok_or_else(closed)?.as_fd())?;
        for (slot, kind) in CANARY_CHILD_NAMESPACES.into_iter().enumerate() {
            self.namespace_identities[slot] = Some(NamespaceFd::validate_original_kind(
                self.raw[6 + slot].as_ref().ok_or_else(closed)?.as_fd(), kind,
            )?);
            if self.namespace_identities[slot] != self.bootstrap_namespaces[slot] {
                return Err(Error::invalid("received Guest child", "child left the original bootstrap namespace").into());
            }
        }
        if let Some(fd) = self.raw[0].take() {
            self.child = Some(PidFd { fd });
        }
        if let Some(fd) = self.raw[1].take() {
            self.executable = Some(File::from(fd));
        }
        self.maps.file = self.raw[2].take().map(File::from);
        self.stat.file = self.raw[3].take().map(File::from);
        self.status.file = self.raw[4].take().map(File::from);
        self.context.file = self.raw[5].take().map(File::from);

        let child = self.child.as_ref().ok_or_else(closed)?;
        self.original_info = Some(child.info()?);
        self.require_child_and_subjects()?;
        self.executable_identity = Some(self.executed_identity()?);
        for descriptor in [&self.stat, &self.maps, &self.status, &self.context] {
            descriptor.require_read_only_proc()?;
        }
        self.reread_local_originals()?;
        let local = self.parsed_local_identity()?;
        let sequence: [u8; 8] = self.payloads[0][168..176].try_into()
            .map_err(|_| closed())?;
        if u64::from_be_bytes(sequence) != u64::from(local.0) || local.0 <= 1
            || local.1 != 1 || local.2 == 0
        {
            return Err(Error::invalid("received Guest child", "original local child coordinates differ").into());
        }
        self.local_identity = Some(local);
        self.require_child_and_subjects()?;
        socket.require_host_canary_cookie(self.cookie.ok_or_else(closed)?)?;
        Ok(())
    }

    fn require_child_and_subjects(&self) -> Result<()> {
        self.require_bootstrap_subjects()?;
        let child = self.child.as_ref().ok_or_else(closed)?;
        if Some(child.info()?) != self.original_info || !child.is_alive()? {
            return Err(Error::invalid("received Guest child", "original child changed or exited"));
        }
        if child.info()?.parent_pid() != self.bootstrap_info.ok_or_else(closed)?.pid() {
            return Err(Error::invalid("received Guest child", "parent is not the original bootstrap"));
        }
        for subject in &self.subjects {
            let subject = subject.as_ref().ok_or_else(closed)?;
            if subject.pidfd().info()? != subject.initial_info()
                || Some(subject.initial_info()) != self.bootstrap_info || !subject.is_alive()?
            {
                return Err(Error::invalid("received Guest child", "original bootstrap subject changed"));
            }
        }
        Ok(())
    }

    fn executed_identity(&self) -> Result<(u64, u64, u64)> {
        let file = self.executable.as_ref().ok_or_else(closed)?;
        let metadata = file.metadata().map_err(|source| Error::Syscall {
            operation: "fstat(received Guest child executable)", source,
        })?;
        let flags = fcntl_getfl(file).map_err(|source| Error::Syscall {
            operation: "fcntl(received Guest child executable)", source: source.into(),
        })?;
        if !metadata.is_file() || metadata.len() == 0
            || flags & OFlags::ACCMODE != OFlags::RDONLY || flags.contains(OFlags::PATH)
        {
            return Err(Error::invalid("received Guest child", "executed image is not regular read-only"));
        }
        Ok((metadata.dev(), metadata.ino(), metadata.len()))
    }

    fn reread_local_originals(&mut self) -> Result<()> {
        self.stat.read(MAXIMUM_PROC_STAT_BYTES)?;
        self.maps.read(NIX_HELPER_MAPS_BYTES)?;
        self.status.read(NIX_HELPER_STATUS_BYTES)?;
        self.context.read(CONTEXT_BYTES)
    }

    fn parsed_local_identity(&self) -> Result<(u32, u32, u64)> {
        let parsed = parse_proc_stat(&self.stat.current)?;
        Ok((parsed.pid(), parsed.parent_pid(), parsed.start_time_ticks()))
    }

    /// Parks the same Guest PID1's actual post-exec systemd image report.
    ///
    /// The pre-exec bootstrap image remains a separate original. This record
    /// nominates the same live bootstrap task, but only the genuine Host's
    /// independent package comparator can establish which image was executed.
    /// No process pathname is reopened and no descriptor is duplicated.
    ///
    /// # Errors
    /// Refuses incomplete child capture, repetition, a foreign carrier or
    /// subject, wrong framing/count, changed process identity or unreadable
    /// executable. The complete record is parked before all new checks;
    /// failure and unwind keep the owner fenced and its originals resident.
    pub fn capture_original_systemd_report(
        &mut self,
        record: crate::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        socket: &mut crate::seqpacket::SeqpacketSocket,
    ) -> std::result::Result<(), HostCanaryReceivedChildErrorV1> {
        if !self.attempted || self.closed || self.systemd_attempted {
            self.closed = true;
            return Err(closed().into());
        }
        self.systemd_record = Some(record);
        self.systemd_attempted = true;
        self.closed = true;
        self.capture_systemd_inner(socket)?;
        self.systemd_captured = true;
        self.closed = false;
        Ok(())
    }

    fn capture_systemd_inner(&mut self, socket: &mut crate::seqpacket::SeqpacketSocket)
        -> std::result::Result<(), HostCanaryReceivedChildErrorV1>
    {
        let record = self.systemd_record.as_ref().ok_or_else(closed)?;
        socket.require_host_canary_report_original_v1(record)?;
        let payload = record.payload();
        if payload.len() != 176 || record.descriptors().len() != 1
            || &payload[..8] != b"AOSHCR01"
            || payload[8..10] != 1_u16.to_be_bytes()
            || payload[10..12] != 6_u16.to_be_bytes()
            || payload[12..16] != 176_u32.to_be_bytes()
            || payload[16..168] != self.bootstrap_payloads[0][16..168]
            || payload[168..176] != 3_u64.to_be_bytes()
            || Some(record.subject().initial_info()) != self.bootstrap_info
            || !record.subject().is_alive()?
        {
            return Err(Error::invalid("Guest systemd original", "fixed post-exec report differs").into());
        }
        self.require_child_and_subjects()?;

        // The complete record remains resident until its exact single role
        // and original subject have been checked. The following moves cannot
        // fail; inspection occurs only after the File enters its fixed slot.
        if let Some(record) = self.systemd_record.take() {
            let (payload, subject, descriptors) = record.into_parts();
            self.systemd_payload = payload;
            self.systemd_subject = Some(subject);
            for descriptor in descriptors {
                self.systemd_executable = Some(File::from(descriptor));
            }
        }
        self.systemd_executable_identity = Some(self.systemd_image_identity()?);
        self.require_systemd_subject()?;
        self.require_child_and_subjects()?;
        socket.require_host_canary_cookie(self.cookie.ok_or_else(closed)?)?;
        Ok(())
    }

    fn systemd_image_identity(&self) -> Result<(u64, u64, u64)> {
        let file = self.systemd_executable.as_ref().ok_or_else(closed)?;
        let metadata = file.metadata().map_err(|source| Error::Syscall {
            operation: "fstat(received Guest systemd executable)", source,
        })?;
        let flags = fcntl_getfl(file).map_err(|source| Error::Syscall {
            operation: "fcntl(received Guest systemd executable)", source: source.into(),
        })?;
        if !metadata.is_file() || metadata.len() == 0
            || flags & OFlags::ACCMODE != OFlags::RDONLY || flags.contains(OFlags::PATH)
        {
            return Err(Error::invalid("Guest systemd original", "executed image is not regular read-only"));
        }
        Ok((metadata.dev(), metadata.ino(), metadata.len()))
    }

    fn require_systemd_subject(&self) -> Result<()> {
        let subject = self.systemd_subject.as_ref().ok_or_else(closed)?;
        if Some(subject.pidfd().info()?) != self.bootstrap_info || !subject.is_alive()? {
            return Err(Error::invalid("Guest systemd original", "original task changed or exited"));
        }
        Ok(())
    }

    /// Rereads the same originals without any remote proc or namespace reopen.
    ///
    /// # Errors
    /// Refuses closed custody, carrier change, child/subject exit or change,
    /// bounded-read denial, changed local coordinates/image/namespace and native
    /// failures. The caller keeps the first actual cause and cleanup debt.
    pub fn recheck_original(&mut self, socket: &mut crate::seqpacket::SeqpacketSocket)
        -> std::result::Result<(), HostCanaryReceivedChildErrorV1>
    {
        if !self.attempted || self.closed {
            return Err(closed().into());
        }
        self.closed = true;
        self.recheck_received_inner(socket)?;
        self.closed = false;
        Ok(())
    }

    fn recheck_received_inner(&mut self, socket: &mut crate::seqpacket::SeqpacketSocket)
        -> std::result::Result<(), HostCanaryReceivedChildErrorV1>
    {
        if Some(self.read_supervisor_identity()?) != self.supervisor_identity
            || Some(NamespaceFd::validate_original_kind(
                self.supervisor_network.as_ref().ok_or_else(closed)?.as_fd(),
                NamespaceKind::Network,
            )?) != self.supervisor_network_identity
        {
            return Err(Error::invalid("native supervisor original", "original identity or network changed").into());
        }
        self.reread_bootstrap_originals()?;
        let bootstrap_stat = parse_proc_stat(&self.bootstrap_stat.current)?;
        if Some((bootstrap_stat.pid(), bootstrap_stat.parent_pid(), bootstrap_stat.start_time_ticks()))
            != self.bootstrap_local_identity
        {
            return Err(Error::invalid("Guest bootstrap originals", "original local identity changed").into());
        }
        for (slot, kind) in CANARY_CHILD_NAMESPACES.into_iter().enumerate() {
            if Some(NamespaceFd::validate_original_kind(
                self.bootstrap_raw[1 + slot].as_ref().ok_or_else(closed)?.as_fd(), kind,
            )?) != self.bootstrap_namespaces[slot]
            {
                return Err(Error::invalid("Guest bootstrap originals", "original namespace changed").into());
            }
        }
        socket.require_host_canary_cookie(self.cookie.ok_or_else(closed)?)?;
        self.require_child_and_subjects()?;
        if self.systemd_captured {
            self.require_systemd_subject()?;
            if Some(self.systemd_image_identity()?) != self.systemd_executable_identity {
                return Err(Error::invalid("Guest systemd original", "original image inode changed").into());
            }
        }
        self.reread_local_originals()?;
        if Some(self.parsed_local_identity()?) != self.local_identity
            || Some(self.executed_identity()?) != self.executable_identity
        {
            return Err(Error::invalid("received Guest child", "original local/image coordinates changed").into());
        }
        for (slot, kind) in CANARY_CHILD_NAMESPACES.into_iter().enumerate() {
            if Some(NamespaceFd::validate_original_kind(
                self.raw[6 + slot].as_ref().ok_or_else(closed)?.as_fd(), kind,
            )?) != self.namespace_identities[slot]
            {
                return Err(Error::invalid("received Guest child", "original namespace changed").into());
            }
        }
        self.require_child_and_subjects()?;
        socket.require_host_canary_cookie(self.cookie.ok_or_else(closed)?)?;
        Ok(())
    }

    /// Borrows the actual child pin after completed observation, not authority.
    ///
    /// # Errors
    /// Refuses incomplete or fenced custody.
    pub fn child(&self) -> Result<&PidFd> {
        self.require_ready()?;
        self.child.as_ref().ok_or_else(closed)
    }

    /// Borrows the original native supervisor's kernel nomination and stat DATA.
    ///
    /// # Errors
    /// Refuses incomplete/fenced custody. Actual MainPID, invocation and
    /// cgroup matching must be supplied by the Host's genuine manager owner.
    pub fn supervisor_observation(&self)
        -> Result<(&crate::seqpacket::KernelAuthorizedRecordSubject, PidFdProcessIdentity)>
    {
        self.require_ready()?;
        Ok((
            self.supervisor_subject.as_ref().ok_or_else(closed)?,
            self.supervisor_identity.ok_or_else(closed)?,
        ))
    }

    /// Borrows the original native executed image and validated network DATA.
    ///
    /// # Errors
    /// Refuses incomplete/fenced custody. The approved package and original
    /// launch network must independently match these received original objects.
    pub fn supervisor_image_and_network(&self) -> Result<(BorrowedFd<'_>, NamespaceIdentity)> {
        self.require_ready()?;
        Ok((
            self.supervisor_executable.as_ref().ok_or_else(closed)?.as_fd(),
            self.supervisor_network_identity.ok_or_else(closed)?,
        ))
    }

    /// Borrows the original kernel-nominated bootstrap subject for each report.
    ///
    /// # Errors
    /// Refuses incomplete/fenced custody or a stage outside the fixed pair.
    pub fn bootstrap_subject(&self, stage: usize)
        -> Result<&crate::seqpacket::KernelAuthorizedRecordSubject>
    {
        self.require_ready()?;
        self.bootstrap_subjects.get(stage).and_then(Option::as_ref).ok_or_else(closed)
    }

    /// Borrows the bootstrap's global kernel facts and local proc coordinates.
    ///
    /// The two tuples retain their actual namespace perspectives. A consumer
    /// must independently match the sealed mapping, original supervisor,
    /// manager invocation and cgroup before using them in a local observation.
    ///
    /// # Errors
    /// Refuses incomplete or fenced original custody.
    pub fn bootstrap_observation(&self) -> Result<(PidFdInfo, (u32, u32, u64))> {
        self.require_ready()?;
        Ok((
            self.bootstrap_info.ok_or_else(closed)?,
            self.bootstrap_local_identity.ok_or_else(closed)?,
        ))
    }

    /// Borrows the common original report header without releasing its owner.
    ///
    /// Its bytes carry no admission or currentness authority. The genuine
    /// selected Host must compare the complete fixed fields with its retained
    /// independent job and actual bound launch before accepting a report.
    ///
    /// # Errors
    /// Refuses incomplete or fenced custody.
    pub fn original_report_header(&self) -> Result<&[u8]> {
        self.require_ready()?;
        Ok(&self.supervisor_payload)
    }

    /// Borrows the original bootstrap root and pre-systemd executed image.
    ///
    /// # Errors
    /// Refuses incomplete/fenced custody. These received objects are DATA for
    /// the Host's original root/package comparator, never a current image proof.
    pub fn bootstrap_root_and_image(&self) -> Result<(BorrowedFd<'_>, BorrowedFd<'_>)> {
        self.require_ready()?;
        Ok((
            self.bootstrap_raw[0].as_ref().ok_or_else(closed)?.as_fd(),
            self.bootstrap_raw[10].as_ref().ok_or_else(closed)?.as_fd(),
        ))
    }

    /// Borrows the actual final systemd image separately from bootstrap DATA.
    ///
    /// # Errors
    /// Refuses incomplete, failed or missing post-exec capture. The descriptor
    /// supplies only original image DATA for independent package measurement.
    pub fn systemd_executed_image(&self) -> Result<BorrowedFd<'_>> {
        self.require_ready()?;
        if !self.systemd_captured {
            return Err(closed());
        }
        Ok(self.systemd_executable.as_ref().ok_or_else(closed)?.as_fd())
    }

    /// Borrows current bootstrap status/context and original-opener ID maps.
    ///
    /// Status IDs are rendered in the Guest opener's user namespace; the Host
    /// must use these genuine maps to compare Host-visible GET_INFO credentials.
    ///
    /// # Errors
    /// Refuses incomplete/fenced custody; no decoded mapping creates authority.
    pub fn bootstrap_inspection_bytes(&self) -> Result<(&[u8], &[u8], &[u8], &[u8])> {
        self.require_ready()?;
        Ok((
            &self.bootstrap_status.current,
            &self.bootstrap_context.current,
            &self.bootstrap_uid_map.current,
            &self.bootstrap_gid_map.current,
        ))
    }

    /// Returns original Guest-proc PID/PPID/start-time DATA in its own namespace.
    ///
    /// # Errors
    /// Refuses incomplete or fenced custody; this never creates global identity.
    pub fn local_coordinates(&self) -> Result<(u32, u32, u64)> {
        self.require_ready()?;
        self.local_identity.ok_or_else(closed)
    }

    /// Borrows the retained executed image for independent package measurement.
    ///
    /// # Errors
    /// Refuses incomplete or fenced custody. No owned descriptor is released.
    pub fn executed_image(&self) -> Result<BorrowedFd<'_>> {
        self.require_ready()?;
        Ok(self.executable.as_ref().ok_or_else(closed)?.as_fd())
    }

    /// Borrows current bounded original maps/status/context DATA.
    ///
    /// # Errors
    /// Refuses incomplete or fenced custody; the caller owns all role checks.
    pub fn inspection_bytes(&self) -> Result<(&[u8], &[u8], &[u8])> {
        self.require_ready()?;
        Ok((&self.maps.current, &self.status.current, &self.context.current))
    }

    /// Returns the fixed user/mount/network/pid original namespace identities.
    ///
    /// # Errors
    /// Refuses incomplete or fenced custody; these are inode DATA, not setns.
    pub fn namespace_coordinates(&self) -> Result<[NamespaceIdentity; 4]> {
        self.require_ready()?;
        let [Some(user), Some(mount), Some(network), Some(pid)] = self.namespace_identities
            else { return Err(closed()) };
        Ok([user, mount, network, pid])
    }

    fn require_ready(&self) -> Result<()> {
        if !self.attempted || self.closed { return Err(closed()) }
        Ok(())
    }
}

impl Default for HostCanaryReceivedChildOriginalsV1 {
    fn default() -> Self {
        Self::new()
    }
}

const CANARY_CHILD_NAMESPACES: [NamespaceKind; 4] = [
    NamespaceKind::User, NamespaceKind::Mount, NamespaceKind::Network, NamespaceKind::Pid,
];

impl ProcDescriptorV1 {
    const fn empty() -> Self {
        Self {
            file: None,
            initial: Vec::new(),
            current: Vec::new(),
        }
    }

    fn capture(&mut self, pid: u32, kind: ProcFileV1) -> Result<()> {
        let path = format!("/proc/{pid}/{}", kind.suffix());
        let descriptor = open(
            path.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| Error::Syscall {
            operation: "open(original proc observation)",
            source: source.into(),
        })?;

        // No fallible operation follows receipt before this actual owner slot.
        self.file = Some(File::from(descriptor));
        self.require_read_only_proc()?;

        self.read(kind.maximum())?;
        self.initial.try_reserve_exact(self.current.len()).map_err(|_| {
            Error::invalid("proc observation", "bounded initial-byte allocation failed")
        })?;
        self.initial.extend_from_slice(&self.current);
        Ok(())
    }

    fn require_read_only_proc(&self) -> Result<()> {
        let file = self.file.as_ref().ok_or_else(closed)?;
        let filesystem = fstatfs(file).map_err(|source| Error::Syscall {
            operation: "fstatfs(original proc observation)",
            source: source.into(),
        })?;
        let flags = fcntl_getfl(file).map_err(|source| Error::Syscall {
            operation: "fcntl(original proc observation)",
            source: source.into(),
        })?;
        if filesystem.f_type as u64 != PROCFS_MAGIC
            || flags & OFlags::ACCMODE != OFlags::RDONLY
            || flags.contains(OFlags::PATH)
        {
            return Err(Error::invalid("proc observation", "descriptor is not read-only procfs"));
        }

        Ok(())
    }

    fn read(&mut self, maximum: usize) -> Result<()> {
        // The fixed extra byte distinguishes exact EOF from an oversized read.
        // Failed partial bytes remain in current; successful earlier reads are
        // not advertised as a complete observation history.
        self.current.clear();
        let bound = maximum.checked_add(1).ok_or_else(closed)?;
        self.current.try_reserve_exact(bound).map_err(|_| {
            Error::invalid("proc observation", "bounded read allocation failed")
        })?;
        let file = self.file.as_mut().ok_or_else(closed)?;
        file.seek(SeekFrom::Start(0)).map_err(|source| Error::Syscall {
            operation: "rewind(original proc observation)",
            source,
        })?;

        let mut scratch = [0_u8; 256];
        let mut interrupted = 0;
        while self.current.len() < bound {
            let available = (bound - self.current.len()).min(scratch.len());
            let count = match file.read(&mut scratch[..available]) {
                Ok(count) => count,
                Err(source) if source.kind() == std::io::ErrorKind::Interrupted
                    && interrupted < READ_INTERRUPT_LIMIT =>
                {
                    interrupted += 1;
                    continue;
                }
                Err(source) => return Err(Error::Syscall {
                    operation: "read(original proc observation)",
                    source,
                }),
            };
            if count == 0 {
                return Ok(());
            }
            self.current.extend_from_slice(&scratch[..count]);
            interrupted = 0;
        }

        Err(Error::invalid("proc observation", "record exceeds its fixed bound"))
    }
}

/// Retains bounded stat/context descriptor DATA without granting process authority.
///
/// Construction is available only through a named method on an actual pidfd.
/// No descriptor, pathname, role, caller maximum or observation setter is exposed.
/// Its purpose owner must keep supplying that same original pin. The reservoir
/// is neither an image/subject proof nor a snapshot across time or process exit.
pub struct PidFdProcObservationsV1 {
    stat: ProcDescriptorV1,
    context: ProcDescriptorV1,
    original_info: Option<PidFdInfo>,
    original_identity: Option<PidFdProcessIdentity>,
    phase: ObservationPhaseV1,
    nix_helper: Option<NixHelperOriginalsV1>,
}

impl PidFd {
    /// Prepares empty nonauthorizing slots before original procfs acquisition.
    #[must_use]
    pub fn prepare_proc_observations_v1(&self) -> PidFdProcObservationsV1 {
        PidFdProcObservationsV1 {
            stat: ProcDescriptorV1::empty(),
            context: ProcDescriptorV1::empty(),
            original_info: None,
            original_identity: None,
            phase: ObservationPhaseV1::Fresh,
            nix_helper: None,
        }
    }
}

impl PidFdProcObservationsV1 {
    /// Parks fixed Nix helper status, executable and maps originals before HELLO.
    ///
    /// This selected DATA capture follows the ordinary stat/context capture on
    /// the same actual pidfd. Every returned descriptor remains resident before
    /// metadata, reads or postchecks. No pathname, FD, role or bound is supplied.
    /// Full loader, executable and purpose checks belong to the genuine owner.
    ///
    /// # Errors
    /// Permanently fences repeated capture, changed/exited processes, failed
    /// original opens/reads or oversized records. Partial files and bytes stay.
    pub fn capture_nix_offline_helper_originals_v1(&mut self, original: &PidFd) -> Result<()> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.capture_nix_helper_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)
    }

    fn capture_nix_helper_inner(&mut self, original: &PidFd) -> Result<()> {
        if self.nix_helper.is_some() {
            return Err(closed());
        }
        self.nix_helper = Some(NixHelperOriginalsV1::empty());
        let before = self.require_original_info(original)?;
        self.nix_helper.as_mut().ok_or_else(closed)?.status
            .capture(before.pid(), ProcFileV1::NixHelperStatus)?;
        self.require_original_info(original)?;

        let path = format!("/proc/{}/exe", before.pid());
        let descriptor = open(path.as_str(), OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|source| Error::Syscall {
                operation: "open(original Nix helper executable)",
                source: source.into(),
            })?;
        self.nix_helper.as_mut().ok_or_else(closed)?.executable = Some(File::from(descriptor));
        let helper = self.nix_helper.as_mut().ok_or_else(closed)?;
        let file = helper.executable.as_ref().ok_or_else(closed)?;
        let flags = fcntl_getfl(file).map_err(|source| Error::Syscall {
            operation: "fcntl(original Nix helper executable)",
            source: source.into(),
        })?;
        let metadata = file.metadata().map_err(|source| Error::Syscall {
            operation: "stat(original Nix helper executable)", source,
        })?;
        if !metadata.is_file() || flags & OFlags::ACCMODE != OFlags::RDONLY
            || flags.contains(OFlags::PATH)
        {
            return Err(Error::invalid("Nix helper executable", "original is not a readable regular file"));
        }
        helper.executable_identity = Some((metadata.dev(), metadata.ino(), metadata.len()));
        self.require_original_info(original)?;
        self.nix_helper.as_mut().ok_or_else(closed)?.maps
            .capture(before.pid(), ProcFileV1::NixHelperMaps)?;
        self.require_original_info(original)?;
        self.nix_helper.as_mut().ok_or_else(closed)?.captured = true;
        Ok(())
    }

    /// Borrows bounded pre-HELLO maps DATA from the original completed capture.
    ///
    /// # Errors
    /// Rejects uncompleted/failed capture. This does not reread maps after ACK.
    pub fn nix_offline_helper_maps_v1(&self) -> Result<&[u8]> {
        let helper = self.nix_helper.as_ref().ok_or_else(closed)?;
        if self.phase != ObservationPhaseV1::Ready || !helper.captured {
            return Err(closed());
        }
        Ok(&helper.maps.initial)
    }

    /// Compares the original executable descriptor under the same retained pidfd.
    ///
    /// Returned device/inode/length is DATA for the genuine image comparator;
    /// neither a received tuple nor historical maps can admit this observation.
    ///
    /// # Errors
    /// Fences absent measurement, changed metadata, original process or liveness.
    pub fn observe_nix_offline_helper_executable_v1(
        &mut self,
        original: &PidFd,
    ) -> Result<(u64, u64, u64)> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_nix_helper_executable_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)
    }

    fn observe_nix_helper_executable_inner(&self, original: &PidFd) -> Result<(u64, u64, u64)> {
        self.require_original_info(original)?;
        let helper = self.nix_helper.as_ref().ok_or_else(closed)?;
        if !helper.captured {
            return Err(closed());
        }
        let metadata = helper.executable.as_ref().ok_or_else(closed)?.metadata()
            .map_err(|source| Error::Syscall {
                operation: "stat(original Nix helper executable)", source,
            })?;
        let observed = (metadata.dev(), metadata.ino(), metadata.len());
        if Some(observed) != helper.executable_identity {
            return Err(Error::invalid("Nix helper executable", "original inode changed"));
        }
        self.require_original_info(original)?;
        Ok(observed)
    }

    /// Rereads bounded Nix helper status from the same zero-offset descriptor.
    ///
    /// This can be used after nondumpable ACK without reopening a proc name.
    /// Capability/NNP matching is purpose-local; bytes alone grant nothing.
    ///
    /// # Errors
    /// Fences absent measurement, failed reread or changed/exited original task.
    pub fn observe_nix_offline_helper_status_v1(&mut self, original: &PidFd) -> Result<&[u8]> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_nix_helper_status_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)?;
        Ok(&self.nix_helper.as_ref().ok_or_else(closed)?.status.current)
    }

    fn observe_nix_helper_status_inner(&mut self, original: &PidFd) -> Result<()> {
        self.require_original_info(original)?;
        let helper = self.nix_helper.as_mut().ok_or_else(closed)?;
        if !helper.captured {
            return Err(closed());
        }
        helper.status.read(NIX_HELPER_STATUS_BYTES)?;
        self.require_original_info(original)?;
        Ok(())
    }

    /// Captures stat once under the owner's same original pidfd.
    ///
    /// # Errors
    /// Rejects closed/repeated capture, procfs denial or malformed/oversized stat,
    /// changed GET_INFO facts, and process exit. Partial custody stays owned.
    pub fn capture_stat(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(ObservationPhaseV1::Fresh)?;
        let result = operation.observations.capture_stat_inner(original);
        operation.finish(result, ObservationPhaseV1::StatCaptured)
    }

    fn capture_stat_inner(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let before = original.info()?;
        self.original_info = Some(before);
        self.stat.capture(before.pid(), ProcFileV1::Stat)?;
        let stat = parse_proc_stat(&self.stat.current)?;
        let after = original.info()?;
        let identity = identity_from_stat(original, before, stat, after)?;
        self.original_identity = Some(identity);
        Ok(identity)
    }

    /// Captures the same process's context once, following stat capture.
    ///
    /// # Errors
    /// Rejects wrong phase, unavailable/oversized context or changed original
    /// process facts. The bytes are DATA; the purpose owner must match its role.
    pub fn capture_context(&mut self, original: &PidFd) -> Result<&[u8]> {
        let operation = self.begin(ObservationPhaseV1::StatCaptured)?;
        let result = operation.observations.capture_context_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)?;
        Ok(&self.context.current)
    }

    fn capture_context_inner(&mut self, original: &PidFd) -> Result<()> {
        let before = self.require_original_info(original)?;
        self.context.capture(before.pid(), ProcFileV1::Context)?;
        self.require_original_info(original)?;
        Ok(())
    }

    /// Observes fresh identity using the same original stat descriptor.
    ///
    /// # Errors
    /// Rejects uncompleted/closed capture, reread denial, malformed stat,
    /// changed original process facts or exit. No pathname is reopened.
    pub fn observe_identity(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_identity_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)
    }

    fn observe_identity_inner(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let identity = self.reread_identity_inner(original)?;
        if Some(identity) != self.original_identity {
            return Err(Error::invalid("proc observation", "original process identity changed"));
        }
        Ok(identity)
    }

    // Current-self purpose comparison remains in Core, with its original error.
    pub(super) fn observe_stat_identity(
        &mut self,
        original: &PidFd,
    ) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(ObservationPhaseV1::StatCaptured)?;
        let result = operation.observations.reread_identity_inner(original);
        operation.finish(result, ObservationPhaseV1::StatCaptured)
    }

    fn reread_identity_inner(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let before = original.info()?;
        self.stat.read(MAXIMUM_PROC_STAT_BYTES)?;
        let stat = parse_proc_stat(&self.stat.current)?;
        let after = original.info()?;
        identity_from_stat(original, before, stat, after)
    }

    pub(super) fn fence(&mut self) {
        self.phase = ObservationPhaseV1::Closed;
    }

    /// Rereads current context from the same original descriptor.
    ///
    /// # Errors
    /// Rejects uncompleted/closed capture, reread denial, excess bytes,
    /// changed original GET_INFO facts or exit. Role matching remains separate.
    pub fn observe_context(&mut self, original: &PidFd) -> Result<&[u8]> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_context_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)?;
        Ok(&self.context.current)
    }

    fn observe_context_inner(&mut self, original: &PidFd) -> Result<()> {
        self.require_original_info(original)?;
        self.context.read(CONTEXT_BYTES)?;
        self.require_original_info(original)?;
        Ok(())
    }

    fn require_original_info(&self, original: &PidFd) -> Result<PidFdInfo> {
        let observed = original.info()?;
        if Some(observed) != self.original_info || !original.is_alive()? {
            return Err(Error::invalid("proc observation", "original process changed or exited"));
        }
        Ok(observed)
    }

    fn begin(&mut self, expected: ObservationPhaseV1) -> Result<ProcObservationOperationV1<'_>> {
        if self.phase != expected {
            self.phase = ObservationPhaseV1::Closed;
            return Err(closed());
        }
        // Arm BEFORE every syscall; caught unwind/drop/forget cannot reopen it.
        self.phase = ObservationPhaseV1::Closed;
        Ok(ProcObservationOperationV1 { observations: self })
    }
}

struct ProcObservationOperationV1<'observation> {
    observations: &'observation mut PidFdProcObservationsV1,
}

impl ProcObservationOperationV1<'_> {
    fn finish<T>(self, result: Result<T>, next: ObservationPhaseV1) -> Result<T> {
        if result.is_ok() {
            self.observations.phase = next;
        }
        result
    }
}

fn closed() -> Error {
    Error::invalid("proc observation", "original observation is permanently closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(phase: ObservationPhaseV1) -> PidFdProcObservationsV1 {
        PidFdProcObservationsV1 {
            stat: ProcDescriptorV1::empty(),
            context: ProcDescriptorV1::empty(),
            original_info: None,
            original_identity: None,
            phase,
            nix_helper: None,
        }
    }

    #[test]
    fn stat_only_state_does_not_satisfy_public_ready_gate() {
        let mut observations = empty(ObservationPhaseV1::StatCaptured);
        let operation = observations.begin(ObservationPhaseV1::StatCaptured).unwrap();
        operation
            .finish(Ok(()), ObservationPhaseV1::StatCaptured)
            .unwrap();

        assert_eq!(observations.phase, ObservationPhaseV1::StatCaptured);
        assert!(observations.begin(ObservationPhaseV1::Ready).is_err());
        assert_eq!(observations.phase, ObservationPhaseV1::Closed);
    }

    #[test]
    fn stat_only_outer_fence_is_permanent() {
        let mut observations = empty(ObservationPhaseV1::StatCaptured);
        observations.fence();

        assert_eq!(observations.phase, ObservationPhaseV1::Closed);
        assert!(observations.begin(ObservationPhaseV1::StatCaptured).is_err());
    }

    #[test]
    fn unfinished_and_forgotten_observations_stay_closed() {
        let mut dropped = empty(ObservationPhaseV1::Fresh);
        drop(dropped.begin(ObservationPhaseV1::Fresh).unwrap());
        assert_eq!(dropped.phase, ObservationPhaseV1::Closed);

        let mut forgotten = empty(ObservationPhaseV1::Ready);
        std::mem::forget(forgotten.begin(ObservationPhaseV1::Ready).unwrap());
        assert_eq!(forgotten.phase, ObservationPhaseV1::Closed);
    }

    #[test]
    fn only_same_successful_open_operation_restores_next_phase() {
        let mut observations = empty(ObservationPhaseV1::Fresh);
        observations.begin(ObservationPhaseV1::Fresh).unwrap()
            .finish(Ok(()), ObservationPhaseV1::StatCaptured).unwrap();
        assert_eq!(observations.phase, ObservationPhaseV1::StatCaptured);

        assert!(observations.begin(ObservationPhaseV1::Fresh).is_err());
        assert_eq!(observations.phase, ObservationPhaseV1::Closed);
        assert!(observations.begin(ObservationPhaseV1::StatCaptured).is_err());
    }

    #[test]
    fn original_err_and_caught_unwind_do_not_reopen_observations() {
        let mut failed = empty(ObservationPhaseV1::Ready);
        let result = failed.begin(ObservationPhaseV1::Ready).unwrap()
            .finish::<()>(Err(closed()), ObservationPhaseV1::Ready);
        assert!(result.is_err());
        assert_eq!(failed.phase, ObservationPhaseV1::Closed);

        let mut unwound = empty(ObservationPhaseV1::Fresh);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _operation = unwound.begin(ObservationPhaseV1::Fresh).unwrap();
            panic!("pure observation unwind");
        }));
        assert!(caught.is_err());
        assert_eq!(unwound.phase, ObservationPhaseV1::Closed);
    }
}
