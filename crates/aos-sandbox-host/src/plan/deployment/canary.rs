//! Original Host startup and private bootstrap-canary custody.
//!
//! A phase-0 owner supplies a measured packaged executable, not completed
//! backend readiness. The private bootstrap compiler borrows that actual
//! owner while the independently signed fixed job is observed. Only the
//! installed coordinator may use this recipe; it cannot escape as readiness.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inherited_fd::HostCanaryInitialActivationTableV1;
use aos_sandbox_linux::inventory::{MountId, MountNamespace};
use aos_sandbox_linux::pidfd::{CurrentSelfPidFdCustodyV1, PidFdProcessIdentity};
use aos_sandbox_linux::protected_file::{ExactReadFailure, read_exact_positioned_retaining_cause};
use aos_sandbox_linux::seqpacket::{
    RecordSubjectListener, RecordSubjectListenerAdmissionAttemptV1,
};
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::VerifiedPhase0ClaimV1;
use crate::broker::canary_job::OriginalHostCanaryJobV1;
use crate::{HostError, Result};

const HOST_UNIT: &str = "aos-sandbox-hostd.service";
const HOST_CONTEXT: &str = "system_u:system_r:aos_sandbox_host_t";
const PROFILE_ROLE: &str = "aos-host-startup-profile";
const PID1_ROLE: &str = "aos-host-pid1-image";
const PROFILE_PLACEHOLDER: &str = "@AOS_HOST_CANARY_PROFILE@";
const MAXIMUM_PROFILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_FRAGMENT_BYTES: usize = 64 * 1024;
const MAXIMUM_PROGRAM_BYTES: usize = 98_504;
const MAXIMUM_STARTUP_OBSERVATIONS: usize = 64;
const LISTENER_ROLES: [(&str, &str); 3] = [
    ("aos-sandbox-host", "/run/aos/sandbox-host/control.sock"),
    ("aos-sandbox-host-root-mount", "/run/aos/sandbox-host/root-mount.sock"),
    ("aos-sandbox-host-storage", "/run/aos/sandbox-host/storage.sock"),
];
const STARTUP_SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax", "NFileDescriptorStore", "SELinuxContext",
    "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges",
    "ExecStart", "ExecStartPre", "ExecStartPost",
    "CPUQuotaPerSecUSec", "CPUQuotaPeriodUSec", "MemoryMax", "TasksMax",
    "LimitNOFILE", "LimitNOFILESoft",
];
const STARTUP_UNIT_PROPERTIES: &[&str] = &[
    "FragmentPath", "DropInPaths", "Transient", "InvocationID",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostCanaryStartupProfileV1 {
    version: u32,
    pid1_path: String,
    pid1_sha256: [u8; 32],
    host_path: String,
    host_sha256: [u8; 32],
    argv: Vec<String>,
    exec_start_pre: Vec<Vec<String>>,
    exec_start_post: Vec<Vec<String>>,
    unit_sha256: [u8; 32],
    policy_path: String,
    policy_sha256: [u8; 32],
    payload_programs_path: String,
    payload_programs_sha256: [u8; 32],
    parent_resources: [u64; 22],
    cpu_period_usec: u64,
    host_service_limits: [u64; 4],
    guardian_service_limits: [u64; 4],
}

#[derive(Debug, thiserror::Error)]
enum StartupFailure {
    #[error(transparent)]
    Native(#[from] rustix::io::Errno),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Read(#[from] ExactReadFailure),
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("Host canary startup originals or fixed roles differ")]
    Original,
    #[error("Host canary startup fixed allocation failed")]
    Allocation,
}

/// Retains the selected Host's complete original process-start table.
///
/// Only actual initial capture can populate this owner. Its inherited PID1
/// file is original launch provenance, not a currently executed manager or
/// reexec proof. Unique-manager service observations separately bind the
/// selected immutable unit, MainPID and invocation. No backend readiness is
/// produced by this startup capture alone.
#[must_use]
pub struct HostCanaryStartupV1 {
    table: HostCanaryInitialActivationTableV1,
    raw: [Option<OwnedFd>; 5],
    listeners: [Option<RecordSubjectListenerAdmissionAttemptV1>; 3],
    admitted_listeners: [Option<RecordSubjectListener>; 3],
    files: [Option<File>; 7],
    snapshots: [Option<crate::plan::NspawnExecutableSnapshot>; 7],
    bytes: [Vec<u8>; 6],
    normalized_fragment: Vec<u8>,
    process: CurrentSelfPidFdCustodyV1,
    process_identity: Option<PidFdProcessIdentity>,
    profile_path: Option<PathBuf>,
    fragment_path: Option<String>,
    canonical_fragment: Option<std::io::Result<PathBuf>>,
    profile: Option<HostCanaryStartupProfileV1>,
    parent_root: Option<CgroupV2Root>,
    parent_anchor: Option<RetainedCgroupAnchor>,
    parent_controls: [Option<File>; 3],
    parent_control_identities: [Option<crate::plan::NspawnExecutableSnapshot>; 3],
    parent_control_originals: [Vec<u8>; 3],
    observations: Vec<std::result::Result<(Vec<OwnedValue>, Vec<OwnedValue>), aos_systemd::Error>>,
    attempted: bool,
    closed: bool,
    first_failure: Option<StartupFailure>,
}

impl HostCanaryStartupV1 {
    /// Creates fixed resident slots before any descriptor is opened.
    pub fn new() -> Self {
        Self {
            table: HostCanaryInitialActivationTableV1::new(),
            raw: std::array::from_fn(|_| None),
            listeners: std::array::from_fn(|_| None),
            admitted_listeners: std::array::from_fn(|_| None),
            files: std::array::from_fn(|_| None),
            snapshots: [None; 7],
            bytes: std::array::from_fn(|_| Vec::new()),
            normalized_fragment: Vec::new(),
            process: CurrentSelfPidFdCustodyV1::new(),
            process_identity: None,
            profile_path: None,
            fragment_path: None,
            canonical_fragment: None,
            profile: None,
            parent_root: None,
            parent_anchor: None,
            parent_controls: std::array::from_fn(|_| None),
            parent_control_identities: [None; 3],
            parent_control_originals: std::array::from_fn(|_| Vec::new()),
            observations: Vec::new(),
            attempted: false,
            closed: false,
            first_failure: None,
        }
    }

    /// Captures the exact five-entry initial table once, before protected opens.
    ///
    /// # Errors
    /// Refuses a foreign activation envelope, name, listener, file or extent.
    /// Returned duplicates and listener-admission prefixes stay resident on
    /// rejection. A failed or abandoned selected startup terminates before
    /// releasing its fields; this is not proof of population drain.
    pub fn capture_original(&mut self) -> Result<()> {
        if self.attempted {
            return Err(canary_refusal());
        }
        self.attempted = true;
        self.closed = true;
        match self.capture_inner() {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(canary_refusal())
            }
        }
    }

    fn capture_inner(&mut self) -> std::result::Result<(), StartupFailure> {
        self.table.observe_once().map_err(|_| StartupFailure::Original)?;
        self.raw = self.table.take_completed_entries().ok_or(StartupFailure::Original)?;

        if std::env::var("LISTEN_PID").ok().as_deref() != Some(std::process::id().to_string().as_str())
            || std::env::var("LISTEN_FDS").ok().as_deref() != Some("5")
        {
            return Err(StartupFailure::Original);
        }
        let names = std::env::var("LISTEN_FDNAMES").map_err(|_| StartupFailure::Original)?;
        if names.len() > 256 {
            return Err(StartupFailure::Original);
        }
        let names = names.split(':').collect::<Vec<_>>();
        if names.len() != 5 {
            return Err(StartupFailure::Original);
        }
        let roles = [LISTENER_ROLES[0].0, LISTENER_ROLES[1].0, LISTENER_ROLES[2].0, PID1_ROLE, PROFILE_ROLE];
        for (role_index, role) in roles.iter().enumerate() {
            let mut found = names.iter().enumerate().filter(|(_, supplied)| **supplied == *role);
            let index = found.next().ok_or(StartupFailure::Original)?.0;
            if found.next().is_some() {
                return Err(StartupFailure::Original);
            }
            let original = self.raw[index].take().ok_or(StartupFailure::Original)?;
            if role_index < 3 {
                self.listeners[role_index] = Some(RecordSubjectListenerAdmissionAttemptV1::new(original));
            } else {
                self.files[role_index - 3] = Some(File::from(original));
            }
        }
        for (index, (_, path)) in LISTENER_ROLES.iter().enumerate() {
            self.listeners[index].as_mut().ok_or(StartupFailure::Original)?
                .admit_once(Path::new(path)).map_err(|_| StartupFailure::Original)?;
        }
        self.observations.try_reserve_exact(MAXIMUM_STARTUP_OBSERVATIONS)
            .map_err(|_| StartupFailure::Allocation)?;

        for slot in 0..2 {
            self.require_read_only_file(slot)?;
            self.snapshots[slot] = Some(crate::plan::nspawn_executable_snapshot(self.file(slot)?.as_fd())?);
        }
        let profile_path = std::fs::read_link(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(self.file(1)?)))?;
        require_store_path(&profile_path)?;
        self.profile_path = Some(profile_path);
        self.read_fixed(1, 0, MAXIMUM_PROFILE_BYTES)?;
        let profile: HostCanaryStartupProfileV1 = serde_json::from_slice(&self.bytes[0])
            .map_err(|_| StartupFailure::Original)?;
        if profile.version != 2
            || serde_json::to_vec(&profile).map_err(|_| StartupFailure::Original)? != self.bytes[0]
        {
            return Err(StartupFailure::Original);
        }
        require_resource_profile(&profile)?;
        for path in [&profile.pid1_path, &profile.host_path, &profile.policy_path, &profile.payload_programs_path] {
            require_store_path(Path::new(path))?;
        }
        self.profile = Some(profile);
        self.require_original_files()
    }

    /// Transfers only the three completely admitted fixed listeners once.
    ///
    /// # Errors
    /// Refuses incomplete or failed capture. Each actual listener is parked
    /// back into this owner before a failed handoff can dispose of anything.
    /// No file, descriptor number or caller-selected listener is accepted.
    pub fn take_original_listeners(
        &mut self,
    ) -> Result<(RecordSubjectListener, RecordSubjectListener, RecordSubjectListener)> {
        if self.closed || self.profile.is_none()
            || self.listeners.iter().any(Option::is_none)
            || self.admitted_listeners.iter().any(Option::is_some)
        {
            return Err(canary_refusal());
        }
        self.closed = true;
        for index in 0..3 {
            self.admitted_listeners[index] = self.listeners[index].as_mut()
                .and_then(RecordSubjectListenerAdmissionAttemptV1::take_completed_listener);
        }
        let originals = std::mem::replace(&mut self.admitted_listeners, [None, None, None]);
        match originals {
            [Some(controller), Some(root), Some(storage)] => {
                self.closed = false;
                Ok((controller, root, storage))
            }
            incomplete => {
                self.admitted_listeners = incomplete;
                Err(canary_refusal())
            }
        }
    }

    pub(crate) async fn admit_original(
        &mut self,
        job: &OriginalHostCanaryJobV1,
        systemd: &SystemdClient,
    ) -> Result<()> {
        if self.closed || self.profile.is_none() || self.files[2].is_some() {
            return Err(canary_refusal());
        }
        self.closed = true;
        match self.admit_inner(job, systemd).await {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(canary_refusal())
            }
        }
    }

    async fn admit_inner(&mut self, job: &OriginalHostCanaryJobV1, systemd: &SystemdClient)
        -> std::result::Result<(), StartupFailure>
    {
        self.require_original_files()?;
        let profile = self.profile.as_ref().ok_or(StartupFailure::Original)?;
        if profile.pid1_sha256 != job.pins[5]
            || profile.host_sha256 != job.pins[2]
            || profile.policy_sha256 != job.pins[1]
            || <[u8; 32]>::from(Sha256::digest(&self.bytes[0])) != job.pins[6]
        {
            return Err(StartupFailure::Original);
        }
        let (_, pid1_digest) = super::super::readiness::snapshot_and_hash_executable(self.file(0)?.as_fd())?;
        if pid1_digest != profile.pid1_sha256 {
            return Err(StartupFailure::Original);
        }
        let host_path = profile.host_path.clone();
        let descriptor = rustix::fs::open(
            host_path.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        self.files[3] = Some(File::from(descriptor));
        self.require_read_only_file(3)?;
        self.snapshots[3] = Some(crate::plan::nspawn_executable_snapshot(self.file(3)?.as_fd())?);
        let host_original = std::fs::metadata("/proc/self/exe")?;
        let host_retained = self.snapshots[3].ok_or(StartupFailure::Original)?;
        use std::os::unix::fs::MetadataExt as _;
        if host_original.dev() != host_retained.device || host_original.ino() != host_retained.inode {
            return Err(StartupFailure::Original);
        }
        let (_, host_digest) = super::super::readiness::snapshot_and_hash_executable(self.file(3)?.as_fd())?;
        if host_digest != job.pins[2] {
            return Err(StartupFailure::Original);
        }
        self.process_identity = Some(self.process.capture_current()?);
        for (slot, path) in [(4, "/proc/self/status"), (5, "/proc/self/cgroup")] {
            let descriptor = rustix::fs::open(
                path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            self.files[slot] = Some(File::from(descriptor));
            let stat = rustix::fs::fstat(self.file(slot)?)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || rustix::fs::fstatfs(self.file(slot)?)?.f_type as u64 != 0x9fa0
            {
                return Err(StartupFailure::Original);
            }
        }
        self.require_self()?;
        self.observe_selected(systemd).await?;
        self.capture_fragment()?;
        self.read_fixed(2, 1, MAXIMUM_FRAGMENT_BYTES)?;
        self.require_fragment()?;
        self.capture_original_programs()?;
        self.require_original_files()?;
        self.require_self()?;
        self.observe_selected(systemd).await?;
        self.require_original_files()
    }

    pub(crate) async fn recheck_original(
        &mut self,
        job: &OriginalHostCanaryJobV1,
        systemd: &SystemdClient,
    ) -> Result<()> {
        if self.closed || self.files[2].is_none() || self.process_identity.is_none() {
            return Err(canary_refusal());
        }
        self.closed = true;
        match self.recheck_inner(job, systemd).await {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(canary_refusal())
            }
        }
    }

    async fn recheck_inner(&mut self, job: &OriginalHostCanaryJobV1, systemd: &SystemdClient)
        -> std::result::Result<(), StartupFailure>
    {
        self.require_original_files()?;
        if KernelBootId::current()?.into_bytes() != job.boot_id {
            return Err(StartupFailure::Original);
        }
        self.require_self()?;
        if self.parent_anchor.is_some() {
            self.require_parent_controls()?;
        }
        self.observe_selected(systemd).await?;
        self.require_fragment()?;
        self.require_original_files()?;
        self.require_self()?;
        self.observe_selected(systemd).await?;
        self.require_original_files()?;
        if self.parent_anchor.is_some() {
            self.require_parent_controls()?;
        }
        Ok(())
    }

    fn file(&self, slot: usize) -> std::result::Result<&File, StartupFailure> {
        self.files[slot].as_ref().ok_or(StartupFailure::Original)
    }

    fn require_read_only_file(&self, slot: usize) -> std::result::Result<(), StartupFailure> {
        let file = self.file(slot)?;
        let stat = rustix::fs::fstat(file)?;
        let flags = rustix::fs::fcntl_getfl(file)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != 0 || stat.st_mode & 0o022 != 0
            || flags & OFlags::ACCMODE != OFlags::RDONLY
        {
            return Err(StartupFailure::Original);
        }
        let mount = MountId::from_fd(file.as_fd()).map_err(|_| StartupFailure::Original)?;
        if !MountNamespace::current().observe(mount).map_err(|_| StartupFailure::Original)?.is_read_only() {
            return Err(StartupFailure::Original);
        }
        Ok(())
    }

    fn read_fixed(&mut self, file_slot: usize, byte_slot: usize, maximum: usize)
        -> std::result::Result<(), StartupFailure>
    {
        let length = usize::try_from(self.snapshots[file_slot].ok_or(StartupFailure::Original)?.bytes)
            .map_err(|_| StartupFailure::Original)?;
        if length == 0 || length > maximum {
            return Err(StartupFailure::Original);
        }
        self.bytes[byte_slot].try_reserve_exact(length).map_err(|_| StartupFailure::Allocation)?;
        self.bytes[byte_slot].resize(length, 0);
        read_exact_positioned_retaining_cause(
            self.files[file_slot].as_ref().ok_or(StartupFailure::Original)?,
            &mut self.bytes[byte_slot],
        )?;
        self.require_original_files()
    }

    fn require_original_files(&self) -> std::result::Result<(), StartupFailure> {
        for slot in 0..7 {
            let Some(snapshot) = self.snapshots[slot] else { continue };
            let file = self.file(slot)?;
            self.require_read_only_file(slot)?;
            if crate::plan::nspawn_executable_snapshot(file.as_fd())? != snapshot {
                return Err(StartupFailure::Original);
            }
            let path = match slot {
                0 => match &self.profile {
                    Some(profile) => Path::new(&profile.pid1_path),
                    None => continue,
                },
                1 => self.profile_path.as_deref().ok_or(StartupFailure::Original)?,
                2 => Path::new(self.fragment_path.as_deref().ok_or(StartupFailure::Original)?),
                3 => Path::new(&self.profile.as_ref().ok_or(StartupFailure::Original)?.host_path),
                6 => Path::new(&self.profile.as_ref().ok_or(StartupFailure::Original)?.payload_programs_path),
                _ => continue,
            };
            let named = rustix::fs::statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
            if named.st_dev != snapshot.device || named.st_ino != snapshot.inode {
                return Err(StartupFailure::Original);
            }
        }
        Ok(())
    }

    fn capture_original_programs(&mut self) -> std::result::Result<(), StartupFailure> {
        if self.files[6].is_some() || !self.bytes[5].is_empty() {
            return Err(StartupFailure::Original);
        }
        let profile = self.profile.as_ref().ok_or(StartupFailure::Original)?;
        let descriptor = rustix::fs::open(
            profile.payload_programs_path.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        self.files[6] = Some(File::from(descriptor));
        self.require_read_only_file(6)?;
        self.snapshots[6] = Some(crate::plan::nspawn_executable_snapshot(self.file(6)?.as_fd())?);
        self.read_fixed(6, 5, MAXIMUM_PROGRAM_BYTES)?;
        let profile = self.profile.as_ref().ok_or(StartupFailure::Original)?;
        if <[u8; 32]>::from(Sha256::digest(&self.bytes[5])) != profile.payload_programs_sha256 {
            return Err(StartupFailure::Original);
        }
        Ok(())
    }

    pub(crate) fn original_programs(&self) -> Result<&[u8]> {
        if self.closed || self.bytes[5].is_empty() || self.files[6].is_none() {
            return Err(canary_refusal());
        }
        self.require_original_files().map_err(|_| canary_refusal())?;
        Ok(&self.bytes[5])
    }

    fn require_fragment(&mut self) -> std::result::Result<(), StartupFailure> {
        let profile = self.profile.as_ref().ok_or(StartupFailure::Original)?;
        let path = self.profile_path.as_ref().ok_or(StartupFailure::Original)?;
        let original = format!("OpenFile={}:{}:read-only\n", path.display(), PROFILE_ROLE);
        let replacement = format!("OpenFile={PROFILE_PLACEHOLDER}:{PROFILE_ROLE}:read-only\n");
        let text = std::str::from_utf8(&self.bytes[1]).map_err(|_| StartupFailure::Original)?;
        if text.split_inclusive('\n').filter(|line| *line == original).count() != 1 {
            return Err(StartupFailure::Original);
        }
        let normalized_length = self.bytes[1].len().checked_sub(original.len())
            .and_then(|length| length.checked_add(replacement.len()))
            .filter(|length| *length <= MAXIMUM_FRAGMENT_BYTES)
            .ok_or(StartupFailure::Original)?;
        self.normalized_fragment.clear();
        self.normalized_fragment.try_reserve_exact(normalized_length)
            .map_err(|_| StartupFailure::Allocation)?;
        for line in text.split_inclusive('\n') {
            self.normalized_fragment.extend_from_slice(
                if line == original { replacement.as_bytes() } else { line.as_bytes() },
            );
        }
        if <[u8; 32]>::from(Sha256::digest(&self.normalized_fragment)) != profile.unit_sha256 {
            return Err(StartupFailure::Original);
        }
        Ok(())
    }

    fn require_self(&mut self) -> std::result::Result<(), StartupFailure> {
        aos_sandbox_linux::guest_confinement::require_subject(HOST_CONTEXT)
            .map_err(|_| StartupFailure::Original)?;
        if [rustix::process::getuid().as_raw(), rustix::process::geteuid().as_raw(),
            rustix::process::getgid().as_raw(), rustix::process::getegid().as_raw()] != [0; 4]
        {
            return Err(StartupFailure::Original);
        }
        let limits = self.profile.as_ref().ok_or(StartupFailure::Original)?.host_service_limits;
        let descriptors = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        if descriptors.current != Some(limits[3]) || descriptors.maximum != Some(limits[3]) {
            return Err(StartupFailure::Original);
        }
        if Some(self.process.observe_identity()?) != self.process_identity {
            return Err(StartupFailure::Original);
        }
        let process = self.process.pidfd()?;
        let info = process.info()?;
        if !process.is_alive()? || info.parent_pid() != 1 {
            return Err(StartupFailure::Original);
        }
        let credentials = info.credentials().ok_or(StartupFailure::Original)?;
        if [credentials.real_user_id(), credentials.effective_user_id(),
            credentials.saved_user_id(), credentials.filesystem_user_id()] != [0; 4]
            || [credentials.real_group_id(), credentials.effective_group_id(),
                credentials.saved_group_id(), credentials.filesystem_group_id()] != [0; 4]
        {
            return Err(StartupFailure::Original);
        }

        // Retained files and read prefixes survive the same original purpose
        // checks. The existing Host status function is the sole cap parser.
        self.read_self_original(4, 2, 65_536)?;
        super::verify_zero_capability_status(
            std::str::from_utf8(&self.bytes[4]).map_err(|_| StartupFailure::Original)?,
        )?;
        self.read_self_original(5, 3, 4096)?;
        let cgroup = std::str::from_utf8(&self.bytes[4]).map_err(|_| StartupFailure::Original)?;
        let mut unified = cgroup.lines().filter(|line| line.starts_with("0::"));
        if unified.next() != Some("0::/system.slice/aos-sandbox-hostd.service")
            || unified.next().is_some()
        {
            return Err(StartupFailure::Original);
        }
        Ok(())
    }

    fn read_self_original(&mut self, slot: usize, original_slot: usize, maximum: usize)
        -> std::result::Result<(), StartupFailure>
    {
        let file = self.files[slot].as_mut().ok_or(StartupFailure::Original)?;
        read_bounded_original(file, &mut self.bytes[4], maximum)?;
        if self.bytes[original_slot].is_empty() {
            let length = self.bytes[4].len();
            self.bytes[original_slot].try_reserve_exact(length)
                .map_err(|_| StartupFailure::Allocation)?;
            let (originals, scratch) = self.bytes.split_at_mut(4);
            originals[original_slot].extend_from_slice(&scratch[0]);
        }
        Ok(())
    }

    pub(crate) fn capture_parent_original(
        &mut self,
        worker: &crate::worker::SystemdOneShotWorker,
    ) -> Result<()> {
        if self.closed || self.parent_root.is_some() || self.parent_anchor.is_some() {
            return Err(canary_refusal());
        }
        self.closed = true;
        match self.capture_parent_inner(worker) {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                if self.first_failure.is_none() {
                    self.first_failure = Some(cause);
                }
                Err(canary_refusal())
            }
        }
    }

    fn capture_parent_inner(&mut self, worker: &crate::worker::SystemdOneShotWorker)
        -> std::result::Result<(), StartupFailure>
    {
        self.require_self()?;
        // These existing clone/resolver constructors have unreturned-prefix
        // boundaries. Only returned originals are claimed as resident here.
        self.parent_root = Some(CgroupV2Root::from_owned(
            worker.original_canary_cgroup_root().as_fd().try_clone_to_owned()?,
        )?);
        self.parent_anchor = Some(self.parent_root.as_ref().ok_or(StartupFailure::Original)?
            .resolve(Path::new("system.slice/aos-sandbox-hostd.service"))?);
        let anchor = self.parent_anchor.as_ref().ok_or(StartupFailure::Original)?;
        anchor.verify_exact_membership(self.process.pidfd()?)?;

        for (slot, name) in ["cpu.max", "memory.max", "pids.max"].iter().enumerate() {
            let descriptor = rustix::fs::openat(
                self.parent_anchor.as_ref().ok_or(StartupFailure::Original)?.as_fd(),
                *name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            self.parent_controls[slot] = Some(File::from(descriptor));
            let file = self.parent_controls[slot].as_ref().ok_or(StartupFailure::Original)?;
            let stat = rustix::fs::fstat(file)?;
            if rustix::fs::fstatfs(file)?.f_type as u64 != 0x6367_7270
                || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != 0 || stat.st_ino == 0
            {
                return Err(StartupFailure::Original);
            }
            self.parent_control_identities[slot] = Some(crate::plan::nspawn_executable_snapshot(file.as_fd())?);
        }
        self.require_parent_controls()?;
        self.require_self()
    }

    fn require_parent_controls(&mut self) -> std::result::Result<(), StartupFailure> {
        let anchor = self.parent_anchor.as_ref().ok_or(StartupFailure::Original)?;
        let before = anchor.verify_exact_membership(self.process.pidfd()?)?;
        let limits = self.profile.as_ref().ok_or(StartupFailure::Original)?.host_service_limits;
        for (slot, name) in ["cpu.max", "memory.max", "pids.max"].iter().enumerate() {
            let file = self.parent_controls[slot].as_mut().ok_or(StartupFailure::Original)?;
            let held = crate::plan::nspawn_executable_snapshot(file.as_fd())?;
            if self.parent_control_identities[slot] != Some(held)
                || rustix::fs::fcntl_getfl(&*file)? & OFlags::ACCMODE != OFlags::RDONLY
            {
                return Err(StartupFailure::Original);
            }
            read_bounded_original(file, &mut self.bytes[4], 256)?;
            let expected = if slot == 0 {
                format!("{} 100000\n", limits[0])
            } else {
                format!("{}\n", limits[slot])
            };
            if self.bytes[4] != expected.as_bytes() {
                return Err(StartupFailure::Original);
            }
            let original = &mut self.parent_control_originals[slot];
            if original.is_empty() {
                original.try_reserve_exact(257).map_err(|_| StartupFailure::Allocation)?;
                original.extend_from_slice(&self.bytes[4]);
            } else if original != &self.bytes[4] {
                return Err(StartupFailure::Original);
            }
            let named = rustix::fs::statat(anchor.as_fd(), *name, AtFlags::SYMLINK_NOFOLLOW)?;
            if named.st_dev != held.device || named.st_ino != held.inode
                || crate::plan::nspawn_executable_snapshot(file.as_fd())? != held
            {
                return Err(StartupFailure::Original);
            }
        }
        if anchor.verify_exact_membership(self.process.pidfd()?)? != before {
            return Err(StartupFailure::Original);
        }
        Ok(())
    }

    async fn observe_selected(&mut self, systemd: &SystemdClient)
        -> std::result::Result<(), StartupFailure>
    {
        if self.observations.len() == MAXIMUM_STARTUP_OBSERVATIONS {
            return Err(StartupFailure::Original);
        }
        self.observations.push(systemd.observe_pid1_service_startup_properties(
            HOST_UNIT, std::process::id(), STARTUP_SERVICE_PROPERTIES, STARTUP_UNIT_PROPERTIES,
        ).await);
        let values = self.observations.last().ok_or(StartupFailure::Original)?
            .as_ref().map_err(|_| StartupFailure::Original)?;
        require_selected_properties(values, self.profile_path.as_deref().ok_or(StartupFailure::Original)?,
            self.profile.as_ref().ok_or(StartupFailure::Original)?)?;
        let fragment = values.1.first().and_then(|value| <&str>::try_from(value).ok())
            .ok_or(StartupFailure::Original)?;
        if fragment.is_empty() || fragment.len() > 4096 {
            return Err(StartupFailure::Original);
        }
        match &self.fragment_path {
            Some(original) if original != fragment => return Err(StartupFailure::Original),
            Some(_) => {}
            None => {
                let mut original = String::new();
                original.try_reserve_exact(fragment.len()).map_err(|_| StartupFailure::Allocation)?;
                original.push_str(fragment);
                self.fragment_path = Some(original);
            }
        }
        let first = self.observations.first().ok_or(StartupFailure::Original)?
            .as_ref().map_err(|_| StartupFailure::Original)?;
        if first != values {
            return Err(StartupFailure::Original);
        }
        Ok(())
    }

    fn capture_fragment(&mut self) -> std::result::Result<(), StartupFailure> {
        if self.files[2].is_some() || self.canonical_fragment.is_some() {
            return Err(StartupFailure::Original);
        }
        let path = Path::new(self.fragment_path.as_deref().ok_or(StartupFailure::Original)?);
        require_store_path(path)?;
        if path.file_name().and_then(|name| name.to_str()) != Some(HOST_UNIT) {
            return Err(StartupFailure::Original);
        }

        // Discovery is DATA from the retained first authentic PID1 flight.
        // The resolved name and actual immutable object are checked separately.
        self.canonical_fragment = Some(std::fs::canonicalize(path));
        let canonical = self.canonical_fragment.as_ref().ok_or(StartupFailure::Original)?
            .as_ref().map_err(|_| StartupFailure::Original)?;
        if canonical.as_os_str().len() > 4096 || canonical != path {
            return Err(StartupFailure::Original);
        }
        let descriptor = rustix::fs::open(
            canonical,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        self.files[2] = Some(File::from(descriptor));
        self.require_read_only_file(2)?;
        self.snapshots[2] = Some(crate::plan::nspawn_executable_snapshot(self.file(2)?.as_fd())?);
        self.require_original_files()
    }

    pub(crate) fn pid1_original(&self) -> Result<BorrowedFd<'_>> {
        self.require_original_files().map_err(|_| canary_refusal())?;
        Ok(self.file(0).map_err(|_| canary_refusal())?.as_fd())
    }

    pub(crate) fn parent_resources(&self) -> Result<aos_sandbox_core::ResourceVector> {
        if self.closed || self.process_identity.is_none() || self.parent_anchor.is_none() {
            return Err(canary_refusal());
        }
        let profile = self.profile.as_ref().ok_or_else(canary_refusal)?;
        Ok(aos_sandbox_core::ResourceVector::new(profile.parent_resources))
    }

    pub(crate) fn original_policy_digest(&self) -> Result<[u8; 32]> {
        self.parent_resources()?;
        self.require_original_files().map_err(|_| canary_refusal())?;
        Ok(self.profile.as_ref().ok_or_else(canary_refusal)?.policy_sha256)
    }

    pub(crate) fn service_limits(&self) -> Result<([u64; 4], [u64; 4])> {
        self.parent_resources()?;
        let profile = self.profile.as_ref().ok_or_else(canary_refusal)?;
        Ok((profile.host_service_limits, profile.guardian_service_limits))
    }

    pub(crate) fn original_retained_charge(&self) -> Result<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as Dimension, ResourceVector};
        let (limits, _) = self.service_limits()?;
        let pinned = self.snapshots.iter().flatten().try_fold(0_u64, |total, snapshot| {
            let bytes = u64::try_from(snapshot.bytes).map_err(|_| HostError::ResourceExhausted)?;
            total.checked_add(bytes).ok_or(HostError::ResourceExhausted)
        })?;
        Ok(ResourceVector::ZERO
            .with(Dimension::CpuMicrosPerPeriod, limits[0])
            .with(Dimension::MemoryBytes, limits[1])
            .with(Dimension::Pids, limits[2])
            .with(Dimension::OpenFiles, limits[3])
            .with(Dimension::PinnedBytes, pinned)
            .with(Dimension::MetadataEntries, 12)
            .with(Dimension::ConcurrentOperations, 1))
    }
}

fn read_bounded_original(file: &mut File, output: &mut Vec<u8>, maximum: usize)
    -> std::result::Result<(), StartupFailure>
{
    let bound = maximum.checked_add(1).ok_or(StartupFailure::Original)?;
    output.clear();
    output.try_reserve_exact(bound).map_err(|_| StartupFailure::Allocation)?;
    file.rewind()?;
    file.take(bound as u64).read_to_end(output)?;
    if output.len() > maximum {
        return Err(StartupFailure::Original);
    }
    Ok(())
}

impl Default for HostCanaryStartupV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HostCanaryStartupV1 {
    fn drop(&mut self) {
        if self.attempted && self.closed {
            std::process::abort();
        }
    }
}

fn require_store_path(path: &Path) -> std::result::Result<(), StartupFailure> {
    let value = path.to_str().ok_or(StartupFailure::Original)?;
    if !value.starts_with("/nix/store/") || value.contains("//") || value.contains('\0')
        || path.components().any(|part| matches!(part, std::path::Component::ParentDir | std::path::Component::CurDir))
    {
        return Err(StartupFailure::Original);
    }
    Ok(())
}

fn require_resource_profile(profile: &HostCanaryStartupProfileV1)
    -> std::result::Result<(), StartupFailure>
{
    if profile.cpu_period_usec != 100_000
        || profile.parent_resources.iter().any(|value| *value > i64::MAX as u64)
        || profile.host_service_limits.iter().zip(&profile.parent_resources)
            .any(|(limit, parent)| *limit == 0 || limit > parent)
        || profile.host_service_limits[0] % 1000 != 0
        || profile.host_service_limits[0].checked_mul(10).is_none()
        || profile.host_service_limits[1] % 4096 != 0
        || profile.guardian_service_limits.iter().zip(&profile.parent_resources)
            .any(|(limit, parent)| *limit == 0 || limit > parent)
        || profile.guardian_service_limits[0] % 1000 != 0
        || profile.guardian_service_limits[0].checked_mul(10).is_none()
        || profile.guardian_service_limits[1] % 4096 != 0
    {
        return Err(StartupFailure::Original);
    }
    Ok(())
}

fn require_selected_properties(
    observed: &(Vec<OwnedValue>, Vec<OwnedValue>),
    profile_path: &Path,
    profile: &HostCanaryStartupProfileV1,
) -> std::result::Result<(), StartupFailure> {
    let (service, unit) = observed;
    let [cgroup, open_files, extras, store_max, stored, context, bounding, ambient,
        nnp, start, pre, post, cpu, period, memory, tasks, nofile, nofile_soft] = service.as_slice() else {
        return Err(StartupFailure::Original);
    };
    let [fragment, drop_ins, transient, invocation] = unit.as_slice() else {
        return Err(StartupFailure::Original);
    };
    let string = |value: &OwnedValue, expected: &str| <&str>::try_from(value).ok() == Some(expected);
    let empty = |value: &OwnedValue| matches!(&**value, Value::Array(values) if values.is_empty());
    if !string(cgroup, "/system.slice/aos-sandbox-hostd.service")
        || !matches!(&**context, Value::Structure(value)
            if matches!(value.fields(), [Value::Bool(false), Value::Str(context)]
                if context.as_str() == HOST_CONTEXT))
        || u64::try_from(bounding).ok() != Some(0) || u64::try_from(ambient).ok() != Some(0)
        || u32::try_from(store_max).ok() != Some(0) || u32::try_from(stored).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true) || !empty(extras)
        || !matches!(<&str>::try_from(fragment), Ok(path) if !path.is_empty() && path.len() <= 4096)
        || !empty(drop_ins) || bool::try_from(transient).ok() != Some(false)
        || !matches!(&**invocation, Value::Array(values)
            if values.len() == 16
                && values.inner().iter().all(|value| matches!(value, Value::U8(_)))
                && values.inner().iter().any(|value| matches!(value, Value::U8(byte) if *byte != 0)))
    {
        return Err(StartupFailure::Original);
    }
    let limits = profile.host_service_limits;
    let per_second = limits[0].checked_mul(10).ok_or(StartupFailure::Original)?;
    if u64::try_from(cpu).ok() != Some(per_second)
        || u64::try_from(period).ok() != Some(profile.cpu_period_usec)
        || u64::try_from(memory).ok() != Some(limits[1])
        || u64::try_from(tasks).ok() != Some(limits[2])
        || u64::try_from(nofile).ok() != Some(limits[3])
        || u64::try_from(nofile_soft).ok() != Some(limits[3])
    {
        return Err(StartupFailure::Original);
    }
    // Exact command/OpenFile layouts are supplied by PID1, not env claims.
    let Value::Array(files) = &**open_files else {
        return Err(StartupFailure::Original);
    };
    let expected_open = [
        (profile.pid1_path.as_str(), PID1_ROLE),
        (profile_path.to_str().ok_or(StartupFailure::Original)?, PROFILE_ROLE),
    ];
    let mut found = [false; 2];
    if files.len() != 2 {
        return Err(StartupFailure::Original);
    }
    for entry in files.inner() {
        let Value::Structure(entry) = entry else {
            return Err(StartupFailure::Original);
        };
        let [Value::Str(path), Value::Str(role), Value::U64(1)] = entry.fields() else {
            return Err(StartupFailure::Original);
        };
        let index = expected_open.iter().position(|pair| *pair == (path.as_str(), role.as_str()))
            .ok_or(StartupFailure::Original)?;
        if found[index] {
            return Err(StartupFailure::Original);
        }
        found[index] = true;
    }
    if found != [true; 2] || profile.argv.first().map(String::as_str) != Some(profile.host_path.as_str()) {
        return Err(StartupFailure::Original);
    }
    require_commands(start, std::slice::from_ref(&profile.argv), Some(std::process::id()))?;
    require_commands(pre, &profile.exec_start_pre, None)?;
    require_commands(post, &profile.exec_start_post, None)?;
    Ok(())
}

fn require_commands(
    observed: &OwnedValue,
    expected: &[Vec<String>],
    main_pid: Option<u32>,
) -> std::result::Result<(), StartupFailure> {
    let Value::Array(commands) = &**observed else {
        return Err(StartupFailure::Original);
    };
    if commands.len() != expected.len() {
        return Err(StartupFailure::Original);
    }
    for (command, expected) in commands.inner().iter().zip(expected) {
        let Value::Structure(command) = command else {
            return Err(StartupFailure::Original);
        };
        let [Value::Str(path), Value::Array(argv), Value::Bool(false),
            Value::U64(_), Value::U64(_), Value::U64(_), Value::U64(_),
            Value::U32(pid), Value::I32(_), Value::I32(_)] = command.fields() else {
            return Err(StartupFailure::Original);
        };
        if expected.first().map(String::as_str) != Some(path.as_str())
            || main_pid.is_some_and(|original| original != *pid)
            || argv.len() != expected.len()
            || argv.inner().iter().zip(expected).any(|(actual, expected)|
                !matches!(actual, Value::Str(actual) if actual.as_str() == expected))
        {
            return Err(StartupFailure::Original);
        }
    }
    Ok(())
}

pub(crate) struct CanaryNspawnConfigV1 {
    original: VerifiedPhase0ClaimV1,
    startup: Arc<Mutex<HostCanaryStartupV1>>,
    timeout_start: Duration,
    timeout_stop: Duration,
    phase: CanaryConfigPhaseV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CanaryConfigPhaseV1 {
    Captured,
    Admitted,
    Closed,
}

impl CanaryNspawnConfigV1 {
    pub(crate) fn complete_original_canary(
        &self,
        payload: &crate::plan::PreparedLaunch,
        readback: &crate::worker::HostCanaryPayloadReadbackV1,
        live: &crate::plan::VerifiedLiveSupervisorPolicyV1,
    ) -> Result<crate::plan::NspawnConfig> {
        self.revalidate_executable()?;
        let startup = self.startup.lock().map_err(|_| canary_refusal())?;
        let readiness = self.original.readiness.complete_original_canary(
            &self.original.packaged, live, payload, readback, &startup,
        )?;
        crate::plan::NspawnConfig::from_readiness(readiness, self.timeout_start, self.timeout_stop)
    }

    // This first move is infallible custody, not admission. The coordinator
    // parks the returned protected proof before later job/startup bookends.
    pub(crate) fn retain_original_phase0(
        original: VerifiedPhase0ClaimV1,
        startup: Arc<Mutex<HostCanaryStartupV1>>,
    ) -> Self {
        Self {
            original,
            startup,
            timeout_start: Duration::from_secs(30),
            timeout_stop: Duration::from_secs(30),
            phase: CanaryConfigPhaseV1::Captured,
        }
    }

    pub(crate) fn admit_original(&mut self, job: &OriginalHostCanaryJobV1) -> Result<()> {
        if self.phase != CanaryConfigPhaseV1::Captured {
            return Err(canary_refusal());
        }
        self.phase = CanaryConfigPhaseV1::Closed;
        let binding = self.original.readiness.canary_original_binding();
        if binding.boot_id != job.boot_id
            || binding.executable_sha256 != job.pins[3]
            || self.original.policy_digest != job.pins[1]
        {
            return Err(canary_refusal());
        }
        binding.revalidate(job.boot_id)?;
        {
            let observed = self.startup.lock().map_err(|_| canary_refusal())?;
            if observed.closed || observed.process_identity.is_none() {
                return Err(canary_refusal());
            }
            self.original.packaged.revalidate_canary(&self.original.readiness, &observed)?;
        }
        self.phase = CanaryConfigPhaseV1::Admitted;
        Ok(())
    }

    pub(crate) fn revalidate_executable(&self) -> Result<()> {
        if self.phase != CanaryConfigPhaseV1::Admitted {
            return Err(canary_refusal());
        }
        let boot = KernelBootId::current()
            .map_err(|error| HostError::State(error.to_string()))?;
        self.original.readiness.canary_original_binding().revalidate(boot.into_bytes())?;
        let startup = self.startup.lock().map_err(|_| canary_refusal())?;
        if startup.closed {
            return Err(canary_refusal());
        }
        self.original.packaged.revalidate_canary(&self.original.readiness, &startup)
    }

    pub(crate) fn executable_pin(&self) -> BorrowedFd<'_> {
        self.original.readiness.canary_original_binding().executable_pin.as_fd()
    }

    pub(crate) fn executable_pin_arc(&self) -> &Arc<OwnedFd> {
        &self.original.readiness.canary_original_binding().executable_pin
    }

    pub(crate) fn timeouts(&self) -> (Duration, Duration) {
        (self.timeout_start, self.timeout_stop)
    }

    pub(crate) async fn observe_original_supervisor_policy(
        &self,
        manager: &SystemdClient,
        payload: &crate::plan::PreparedLaunch,
        supervisor_pid: u32,
    ) -> Result<crate::plan::VerifiedLiveSupervisorPolicyV1> {
        if self.phase != CanaryConfigPhaseV1::Admitted {
            return Err(canary_refusal());
        }
        let startup = self.startup.lock().map_err(|_| canary_refusal())?;
        if startup.closed {
            return Err(canary_refusal());
        }
        self.original.packaged.verify_original_canary_supervisor_policy(
            &self.original.readiness, manager, payload.spec(), supervisor_pid, &startup,
        ).await
    }
}

fn canary_refusal() -> HostError {
    HostError::Fence("original Host canary package or policy differs from approval")
}
