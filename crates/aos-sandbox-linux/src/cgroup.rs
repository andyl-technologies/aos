//! Retained kernel cgroup-v2 directory identity and exact membership snapshots.
//!
//! The supported profile is a 64-bit Linux kernel/process. Linux 6.18.33
//! `include/linux/cgroup.h:cgroup_id` returns `cgrp->kn->id`, while
//! `include/linux/kernfs.h:kernfs_id_ino` preserves that complete ID only on
//! 64-bit kernels. Admission checks the descriptor's cgroup2 filesystem before
//! interpreting its inode number; an ordinary filesystem inode is never a
//! cgroup identifier. A retained inode pins its kernfs node against ID reuse.
//!
//! Directory link counts do not establish liveness: kernfs refreshes them even
//! for removed directories. Instead, a fresh read-only open of `cgroup.procs`
//! observes an active kernfs file (`fs/kernfs/file.c:kernfs_fop_open`). This is
//! available on the hierarchy root too, unlike `cgroup.events`. No task list is
//! read and no cgroup is modified. None of these observations fence migration,
//! removal, process exit, or a subsequent effect. The separate exact-cgroup
//! kill primitive is explicitly mutating and requires an independent retained
//! population observation before it establishes quiescence.

use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Component, Path};

use crate::path::{
    BeneathRoot, PendingBeneathRootV5, PendingRegularFileV1, PendingResolvedPathV5,
    ResolveOptions,
};
use crate::pidfd::{PidFd, PidFdInfo};
use crate::{Error, Result, uapi};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAXIMUM_DESCENDANT_HINT_BYTES: usize = 4096;

const LIMIT_CONTROL_BYTES: usize = 256;

/// Names the closed read-only files used by a service-limit observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupLimitControlV1 {
    /// Available controllers, not enabled subtree controllers.
    Controllers,
    /// Controllers enabled for children.
    SubtreeControl,
    /// Domain/threaded topology classification.
    Type,
    /// Finite task limit or the literal `max`.
    PidsMax,
    /// CPU scheduling weight, not inherited bandwidth.
    CpuWeight,
    /// Raw memory-high value; no page normalization is implied.
    MemoryHigh,
    /// Raw memory-max value; no page normalization is implied.
    MemoryMax,
}

impl CgroupLimitControlV1 {
    const ALL: [Self; 7] = [
        Self::Controllers,
        Self::SubtreeControl,
        Self::Type,
        Self::PidsMax,
        Self::CpuWeight,
        Self::MemoryHigh,
        Self::MemoryMax,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Controllers => "cgroup.controllers",
            Self::SubtreeControl => "cgroup.subtree_control",
            Self::Type => "cgroup.type",
            Self::PidsMax => "pids.max",
            Self::CpuWeight => "cpu.weight",
            Self::MemoryHigh => "memory.high",
            Self::MemoryMax => "memory.max",
        }
    }
}

#[derive(Debug)]
struct LimitControlSlotV1 {
    opening: PendingRegularFileV1,
    bookend: PendingRegularFileV1,
    final_name: PendingRegularFileV1,
    absent: Option<Error>,
    absence_bookend: Option<Error>,
    final_absence: Option<Error>,
    bytes: [u8; LIMIT_CONTROL_BYTES + 1],
    length: usize,
    final_bytes: [u8; LIMIT_CONTROL_BYTES + 1],
    final_length: usize,
}

impl Default for LimitControlSlotV1 {
    fn default() -> Self {
        Self {
            opening: PendingRegularFileV1::default(),
            bookend: PendingRegularFileV1::default(),
            final_name: PendingRegularFileV1::default(),
            absent: None,
            absence_bookend: None,
            final_absence: None,
            bytes: [0; LIMIT_CONTROL_BYTES + 1],
            length: 0,
            final_bytes: [0; LIMIT_CONTROL_BYTES + 1],
            final_length: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimitReadbackPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Current,
    Failed,
}

/// Retains fixed control-file descriptors, bounded bytes and the first error.
///
/// This is observed DATA, not an enforcement or currentness capability. An
/// interrupted capture cannot be retried. Missing files remain explicit kernel
/// observations; callers must decide which files their actual topology requires.
#[derive(Debug)]
pub struct CgroupLimitReadbackV1 {
    slots: [LimitControlSlotV1; 7],
    phase: LimitReadbackPhaseV1,
    failure: Option<Error>,
}

impl Default for CgroupLimitReadbackV1 {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| LimitControlSlotV1::default()),
            phase: LimitReadbackPhaseV1::Fresh,
            failure: None,
        }
    }
}

impl CgroupLimitReadbackV1 {
    /// Captures one bounded observation through the actual retained anchor.
    ///
    /// # Errors
    ///
    /// Rejects reentry, stale anchors, failed opens/reads, changed named files,
    /// and malformed or oversized records. The original first error stays here;
    /// the returned error is only a negative status, never a positive permit.
    pub fn capture(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.phase != LimitReadbackPhaseV1::Fresh {
            return Err(Error::invalid("cgroup limit capture", "already attempted"));
        }
        self.phase = LimitReadbackPhaseV1::Checking;
        match self.capture_once(anchor) {
            Ok(()) => {
                self.phase = LimitReadbackPhaseV1::Ready;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error);
                self.phase = LimitReadbackPhaseV1::Failed;
                Err(Error::invalid("cgroup limit capture", "original failure retained"))
            }
        }
    }

    /// Borrows the first actual native/parser error without releasing custody.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    /// Borrows an actual missing-file cause without synthesizing a default.
    ///
    /// Absence is negative DATA even when this caller's topology permits it.
    #[must_use]
    pub fn absence(&self, control: CgroupLimitControlV1) -> Option<&Error> {
        self.slots[control as usize].absent.as_ref()
    }

    /// Borrows a complete record only after the whole capture succeeded.
    #[must_use]
    pub fn bytes(&self, control: CgroupLimitControlV1) -> Option<&[u8]> {
        if !matches!(self.phase, LimitReadbackPhaseV1::Ready | LimitReadbackPhaseV1::Current) {
            return None;
        }
        let slot = &self.slots[control as usize];
        slot.absent.is_none().then_some(&slot.bytes[..slot.length])
    }

    /// Performs the sole final same-OFD and named-identity bookend.
    ///
    /// # Errors
    ///
    /// Rejects non-ready/repeated calls, changes, removal and native read/open
    /// errors. A failure or interrupted bookend leaves all originals resident.
    pub fn recheck(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.phase != LimitReadbackPhaseV1::Ready {
            return Err(Error::invalid("cgroup limit bookend", "not initially ready"));
        }
        self.phase = LimitReadbackPhaseV1::Checking;
        match self.recheck_once(anchor) {
            Ok(()) => {
                self.phase = LimitReadbackPhaseV1::Current;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error);
                self.phase = LimitReadbackPhaseV1::Failed;
                Err(Error::invalid("cgroup limit bookend", "original failure retained"))
            }
        }
    }

    fn recheck_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        anchor.validate_current()?;
        for control in CgroupLimitControlV1::ALL {
            let slot = &mut self.slots[control as usize];
            let path = Path::new(control.name());
            if slot.absent.is_some() {
                match anchor.root.open_regular_retaining(path, &mut slot.final_name) {
                    Err(error) if is_missing(&error) => {
                        slot.final_absence = Some(error);
                        continue;
                    }
                    Err(error) => return Err(error),
                    Ok(()) => return Err(Error::invalid("cgroup control", "absent file appeared")),
                }
            }
            read_limit_record(
                slot.opening.file()?.as_fd(), &mut slot.final_bytes, &mut slot.final_length,
            )?;
            if slot.bytes[..slot.length] != slot.final_bytes[..slot.final_length] {
                return Err(Error::invalid("cgroup control", "same-OFD record changed"));
            }
            anchor.root.open_regular_retaining(path, &mut slot.final_name)?;
            if slot.opening.file()?.identity() != slot.final_name.file()?.identity() {
                return Err(Error::invalid("cgroup control", "final named identity changed"));
            }
        }
        anchor.validate_current()
    }

    fn capture_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        anchor.validate_current()?;
        for control in CgroupLimitControlV1::ALL {
            let slot = &mut self.slots[control as usize];
            let path = Path::new(control.name());
            match anchor.root.open_regular_retaining(path, &mut slot.opening) {
                Err(error @ Error::Syscall { .. }) if is_missing(&error) => {
                    slot.absent = Some(error);
                    match anchor.root.open_regular_retaining(path, &mut slot.bookend) {
                        Err(error) if is_missing(&error) => {
                            slot.absence_bookend = Some(error);
                            continue;
                        }
                        Err(error) => return Err(error),
                        Ok(()) => return Err(Error::invalid("cgroup control", "absent file appeared")),
                    }
                }
                Err(error) => return Err(error),
                Ok(()) => {}
            }

            // The same readable OFD supplies every byte, from offset zero. The
            // sentinel and each returned prefix are resident before validation.
            read_limit_record(slot.opening.file()?.as_fd(), &mut slot.bytes, &mut slot.length)?;
            validate_limit_record(control, &slot.bytes[..slot.length])?;
            anchor.root.open_regular_retaining(path, &mut slot.bookend)?;
            if slot.opening.file()?.identity() != slot.bookend.file()?.identity() {
                return Err(Error::invalid("cgroup control", "named identity changed"));
            }
        }
        anchor.validate_current()
    }
}

fn read_limit_record(
    fd: BorrowedFd<'_>,
    bytes: &mut [u8; LIMIT_CONTROL_BYTES + 1],
    length: &mut usize,
) -> Result<()> {
    loop {
        let read = rustix::io::pread(fd, &mut bytes[*length..], *length as u64)
            .map_err(|source| Error::Syscall {
                operation: "read fixed cgroup control", source: source.into(),
            })?;
        *length += read;
        if *length > LIMIT_CONTROL_BYTES {
            return Err(Error::ObservationLimitExceeded {
                object: "fixed cgroup control", limit: LIMIT_CONTROL_BYTES,
            });
        }
        if read == 0 {
            return Ok(());
        }
    }
}

fn is_missing(error: &Error) -> bool {
    matches!(error, Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::ENOENT))
}

fn validate_limit_record(control: CgroupLimitControlV1, bytes: &[u8]) -> Result<()> {
    let body = bytes.strip_suffix(b"\n").ok_or_else(|| {
        Error::invalid("cgroup control", "record lacks its single final newline")
    })?;
    let valid = match control {
        CgroupLimitControlV1::Controllers | CgroupLimitControlV1::SubtreeControl => {
            let mut seen = 0_u16;
            body.is_empty() || body.split(|byte| *byte == b' ').all(|word| {
                let bit = match word {
                    b"cpu" => 1,
                    b"pids" => 2,
                    b"memory" => 4,
                    b"cpuset" => 8,
                    b"io" => 16,
                    b"hugetlb" => 32,
                    b"rdma" => 64,
                    b"misc" => 128,
                    _ => return false,
                };
                let fresh = seen & bit == 0;
                seen |= bit;
                fresh
            })
        }
        CgroupLimitControlV1::Type => matches!(
            body, b"domain" | b"domain threaded" | b"domain invalid" | b"threaded"
        ),
        CgroupLimitControlV1::PidsMax | CgroupLimitControlV1::MemoryHigh | CgroupLimitControlV1::MemoryMax => {
            body == b"max" || parse_limit_decimal(body).is_some()
        }
        CgroupLimitControlV1::CpuWeight => {
            parse_limit_decimal(body).is_some_and(|weight| (1..=10_000).contains(&weight))
        }
    };
    if !valid {
        return Err(Error::invalid("cgroup control", "malformed fixed record"));
    }
    Ok(())
}

fn parse_limit_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 20 || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        byte.is_ascii_digit().then_some(())?;
        value.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

macro_rules! require_cgroup_identity_platform {
    () => {
        if !cfg!(target_pointer_width = "64") {
            return Err(Error::invalid(
                "cgroup identity profile",
                "requires a 64-bit kernel/process",
            ));
        }
    };
}

macro_rules! anchor_from_root {
    ($root:ident) => {
        RetainedCgroupAnchor {
            kernel_id: $root.identity().inode,
            root: $root,
        }
    };
}

/// Retains a kernel cgroup-v2 directory as a strict descendant-resolution root.
///
/// The caller chooses its trusted scope; this type proves neither that the
/// root is the global hierarchy root nor that a particular principal owns it.
#[derive(Debug)]
pub struct CgroupV2Root {
    anchor: RetainedCgroupAnchor,
}

impl CgroupV2Root {
    /// Adopts an owned cgroup-v2 directory after kernel identity and active-file checks.
    ///
    /// # Errors
    ///
    /// Rejects unsupported word size, non-directory or non-cgroup2 descriptors,
    /// zero identity, inaccessible/deactivated `cgroup.procs`, and kernel errors.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        Self::try_from(BeneathRoot::from_owned(fd)?)
    }

    /// Resolves and retains one exact cgroup beneath this root.
    ///
    /// `.` selects the root itself. Resolution rejects symlinks, magic links,
    /// mount crossings, absolute paths and parent traversal using `openat2`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed strict resolution, a stale
    /// root or target, unsupported filesystem identity, or kernel failures.
    pub fn resolve(&self, relative: &Path) -> Result<RetainedCgroupAnchor> {
        self.anchor.resolve_child(relative)
    }

    /// Borrows the retained resolution-root descriptor.
    ///
    /// Subsequent descriptor-relative operations retain ordinary kernel access
    /// checks; this borrow is not a read-only restriction on the subtree.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.anchor.as_fd()
    }
}

impl TryFrom<BeneathRoot> for CgroupV2Root {
    type Error = Error;

    /// Validates and consumes an existing descriptor-relative root as cgroup-v2 scope.
    ///
    /// # Errors
    ///
    /// Returns the same filesystem, active-file and platform errors as
    /// [`Self::from_owned`], without replacing the retained descriptor.
    fn try_from(root: BeneathRoot) -> Result<Self> {
        Ok(Self {
            anchor: RetainedCgroupAnchor::new(root)?,
        })
    }
}

/// Pins one exact cgroup-v2 object and its complete kernel identifier.
///
/// Exact and explicitly hinted descendant checks remain distinct. The retained
/// FD prevents reuse of this object's kernfs identity, but does not prevent
/// cgroup removal or movement of processes. Neither the ID nor a snapshot grants an
/// application principal, service provenance, or filesystem/effect authority.
#[derive(Debug)]
pub struct RetainedCgroupAnchor {
    root: BeneathRoot,
    kernel_id: u64,
}

/// Retains initial hierarchy and fixed offline-provisioner cgroup observations.
///
/// This move-only DATA reservoir parks a returned root duplicate and every
/// returned child/probe before validation. It proves kernel object identity,
/// not service provenance, privilege, startup admission, funding or currentness.
/// Its only descendant is `system.slice/aos-sandbox-nix-floor-provision.service`.
/// It retains at most two directory descriptors and four active-file probes;
/// transitions between candidate and validated slots never duplicate an FD.
/// The external caller keeps the reservoir alive on error or caught unwind.
#[derive(Debug, Default)]
pub struct NixOfflineInitialCgroupReadbackV5 {
    attempted: bool,
    complete: bool,
    root_candidate: PendingBeneathRootV5,
    hierarchy_candidate: Option<RetainedCgroupAnchor>,
    root: Option<CgroupV2Root>,
    root_probe: PendingRegularFileV1,
    child: InitialCgroupChildV5,
}

#[derive(Debug, Default)]
struct InitialCgroupChildV5 {
    resolution: PendingResolvedPathV5,
    anchor: Option<RetainedCgroupAnchor>,
    probes: [PendingRegularFileV1; 3],
}

impl NixOfflineInitialCgroupReadbackV5 {
    /// Creates fixed empty slots without acquiring or admitting an object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures a returned hierarchy duplicate and the one fixed self cgroup.
    ///
    /// The first call parks the candidate before its directory checks. The
    /// actual error is returned by value for the external owner to retain;
    /// partial descriptors remain here. Failure or unwind fences this instance.
    /// An unrequested owned argument to a repeated call is dropped normally,
    /// without releasing any previously captured original.
    ///
    /// # Errors
    /// Returns the original directory, cgroup, resolution or kernel error.
    /// Refuses a repeated/interrupted capture without resampling its originals.
    pub fn capture_provisioner(&mut self, original_root_candidate: OwnedFd) -> Result<()> {
        if self.attempted {
            self.complete = false;
            return Err(Error::invalid("initial cgroup capture", "already attempted"));
        }
        self.attempted = true;
        self.complete = false;

        self.root_candidate.retain(original_root_candidate)?;
        let Some(root) = self.root_candidate.take_validated() else {
            std::process::abort();
        };
        self.hierarchy_candidate = Some(anchor_from_root!(root));
        self.hierarchy_candidate
            .as_ref()
            .ok_or_else(|| {
                Error::invalid("initial cgroup capture", "hierarchy candidate is absent")
            })?
            .validate_initial_retaining(&mut self.root_probe)?;

        let Some(anchor) = self.hierarchy_candidate.take() else {
            std::process::abort();
        };
        self.root = Some(CgroupV2Root { anchor });
        self.root
            .as_ref()
            .ok_or_else(|| {
                Error::invalid("initial cgroup capture", "hierarchy root is absent")
            })?
            .anchor
            .resolve_initial_provisioner_retaining(&mut self.child)?;

        self.complete = true;
        Ok(())
    }

    /// Transfers the two fully validated kernel objects once, leaving probes resident.
    ///
    /// Returns `None` before full success, after transfer, or after a failed or
    /// interrupted capture. Both slots are checked before either owning move.
    /// This supplies kernel DATA, never an admitted service origin or floor.
    #[must_use]
    pub fn take_validated_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        if !self.complete || self.root.is_none() || self.child.anchor.is_none() {
            return None;
        }
        self.complete = false;

        match (self.root.take(), self.child.anchor.take()) {
            (Some(root), Some(anchor)) => Some((root, anchor)),
            _ => std::process::abort(),
        }
    }
}

/// Retains the kernel population file for one exact cgroup lifetime.
#[derive(Debug)]
pub struct CgroupPopulationMonitor {
    events: File,
}

/// Retains one fixed Nix runtime cgroup absence or stopped-population observation.
///
/// This holder owns at most seven returned descriptors, including partial
/// resolution and active-file checks. It grants no service, process, resource
/// or destruction authority. Fixed names are DATA locators beneath the actual
/// supplied cgroup-v2 root; the purpose owner must authenticate that root.
#[derive(Debug, Default)]
pub struct NixOfflineStoppedCgroupReadbackV5 {
    attempted: bool,
    complete: bool,
    resolution: PendingResolvedPathV5,
    anchor: Option<RetainedCgroupAnchor>,
    probes: [PendingRegularFileV1; 5],
    event_open: PendingRegularFileV1,
    events: Option<File>,
    absence: Option<Error>,
    state: Option<CgroupPopulationState>,
    failure: Option<Error>,
}

impl NixOfflineStoppedCgroupReadbackV5 {
    /// Observes only the fixed Controller cgroup through this original root.
    ///
    /// # Errors
    /// Retains the first actual acquisition, identity or population failure.
    /// Reentry and interrupted capture remain fenced with all partials resident.
    pub fn capture_controller(&mut self, root: &CgroupV2Root) -> Result<()> {
        self.capture(root, Path::new("aos.slice/aos-control.slice/aos-sandboxd.service"))
    }

    /// Observes only the fixed Nix-owner cgroup through this original root.
    ///
    /// # Errors
    /// Uses the same acquisition and failure semantics as Controller capture.
    /// A missing directory is retained negative DATA, not a retirement proof.
    pub fn capture_nix_owner(&mut self, root: &CgroupV2Root) -> Result<()> {
        self.capture(root, Path::new("aos.slice/aos-control.slice/aos-sandbox-nixd.service"))
    }

    /// Borrows an actual complete population observation, if a cgroup existed.
    #[must_use]
    pub fn population(&self) -> Option<CgroupPopulationState> {
        self.complete.then_some(self.state).flatten()
    }

    /// Borrows the actual original missing-directory cause as negative DATA.
    #[must_use]
    pub fn absence(&self) -> Option<&Error> {
        self.complete.then_some(self.absence.as_ref()).flatten()
    }

    /// Borrows the first actual failure without moving any original descriptor.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    fn capture(&mut self, root: &CgroupV2Root, relative: &Path) -> Result<()> {
        if self.attempted {
            self.complete = false;
            return Err(Error::invalid("offline Nix cgroup observation", "already attempted"));
        }
        self.attempted = true;
        match self.capture_once(root, relative) {
            Ok(()) => {
                self.complete = true;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error);
                Err(Error::invalid("offline Nix cgroup observation", "original failure retained"))
            }
        }
    }

    fn capture_once(&mut self, root: &CgroupV2Root, relative: &Path) -> Result<()> {
        root.anchor.validate_active_retaining(&mut self.probes[0])?;
        match root.anchor.root.resolve_directory_retaining(relative, &mut self.resolution) {
            Err(error) if is_missing(&error) => {
                self.absence = Some(error);
                return root.anchor.validate_active_retaining(&mut self.probes[1]);
            }
            Err(error) => return Err(error),
            Ok(()) => {}
        }

        let child = self.resolution.take_directory_root().ok_or_else(|| {
            Error::invalid("offline Nix cgroup observation", "validated directory is absent")
        })?;
        self.anchor = Some(RetainedCgroupAnchor {
            kernel_id: child.identity().inode,
            root: child,
        });
        let anchor = self.anchor.as_ref().ok_or_else(|| {
            Error::invalid("offline Nix cgroup observation", "original anchor is absent")
        })?;
        if !cfg!(target_pointer_width = "64") {
            return Err(Error::invalid("cgroup identity profile", "requires a 64-bit kernel/process"));
        }
        anchor.validate_active_retaining(&mut self.probes[1])?;
        root.anchor.validate_active_retaining(&mut self.probes[2])?;
        anchor.validate_active_retaining(&mut self.probes[3])?;
        anchor.root.open_regular_retaining(Path::new("cgroup.events"), &mut self.event_open)?;
        self.events = self.event_open.take_readable_file();
        let events = self.events.as_ref().ok_or_else(|| {
            Error::invalid("offline Nix cgroup observation", "original events file is absent")
        })?;
        self.state = Some(read_population_state(events)?);
        anchor.validate_active_retaining(&mut self.probes[4])
    }
}

/// Reports whether an exact cgroup-v2 subtree is accepting scheduler time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupFreezerState {
    /// The subtree is thawed.
    Thawed,
    /// The subtree and all of its descendants are frozen.
    Frozen,
}

/// Describes the recursive task population of one retained cgroup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupPopulationState {
    /// The cgroup or at least one descendant contains a live task.
    Populated,
    /// The active cgroup and all descendants contain no live task.
    Empty,
    /// The exact retained cgroup has been removed from the active hierarchy.
    Retired,
}

impl CgroupPopulationMonitor {
    /// Reports the population or authenticated retirement of the retained cgroup.
    ///
    /// Linux permits cgroup removal only after the cgroup has no live tasks or
    /// online children. For the base `cgroup.events` file, an `ENODEV` read from
    /// its already-authenticated retained kernfs descriptor therefore proves
    /// retirement of that exact empty subtree. Callers must still pair
    /// [`CgroupPopulationState::Retired`] with any required process-liveness
    /// evidence; retirement alone says nothing about a separately retained
    /// pidfd.
    ///
    /// # Errors
    ///
    /// Returns an error for every read failure other than the kernel's exact
    /// `ENODEV` retirement signal, or when the bounded `cgroup.events` record
    /// omits its mandatory `populated` field.
    pub fn state(&self) -> Result<CgroupPopulationState> {
        read_population_state(&self.events)
    }
}

fn read_population_state(events: &File) -> Result<CgroupPopulationState> {
        let mut bytes = [0_u8; 4097];
        let length = match events.read_at(&mut bytes, 0) {
            Ok(length) => length,
            Err(source) if source.raw_os_error() == Some(libc::ENODEV) => {
                return Ok(CgroupPopulationState::Retired);
            }
            Err(source) => {
                return Err(Error::Syscall {
                    operation: "read cgroup.events",
                    source,
                });
            }
        };
        if length == 0 || length == bytes.len() {
            return Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "population record is empty or oversized".to_owned(),
            });
        }
        let text =
            std::str::from_utf8(&bytes[..length]).map_err(|_| Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "population record is not UTF-8".to_owned(),
            })?;
        match text
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(CgroupPopulationState::Empty),
            Some("1") => Ok(CgroupPopulationState::Populated),
            _ => Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "population field is absent or invalid".to_owned(),
            }),
        }
}

macro_rules! active_reference_step {
    (Local, $anchor:ident, $pending:ident) => {
        let _active = $anchor.root.open_regular(Path::new("cgroup.procs"))?;
    };
    (Retained, $anchor:ident, $pending:ident) => {
        $anchor.root.open_regular_retaining(Path::new("cgroup.procs"), $pending)?;
    };
}

macro_rules! validate_active_recipe {
    ($anchor:ident, $disposition:ident, $pending:ident) => {{
        if uapi::filesystem_type($anchor.root.as_fd())? != CGROUP2_SUPER_MAGIC {
            return Err(Error::WrongDescriptorType {
                expected: "kernel cgroup-v2 directory",
            });
        }
        let stat = uapi::fstat($anchor.root.as_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || $anchor.kernel_id == 0
            || stat.st_ino != $anchor.kernel_id
            || stat.st_dev != $anchor.root.identity().device
        {
            return Err(Error::invalid(
                "cgroup anchor",
                "kernel directory identity changed or is unspecified",
            ));
        }
        // A retained removed directory may still report a positive nlink.
        // Opening this fixed regular kernfs file checks an active reference;
        // all lookup constraints remain enforced by BeneathRoot.
        active_reference_step!($disposition, $anchor, $pending);
        Ok(())
    }};
}

macro_rules! child_resolution_step {
    (Local, active, $anchor:ident, $pending:ident, $index:literal) => {
        $anchor.validate_active()?;
    };
    (Retained, active, $anchor:ident, $pending:ident, $index:literal) => {
        $anchor.validate_active_retaining(&mut $pending.probes[$index])?;
    };
    (Local, resolve, $anchor:ident, $relative:ident, $pending:ident, $resolved:ident) => {
        let $resolved = $anchor.root.resolve($relative, ResolveOptions::directory())?;
    };
    (Retained, resolve, $anchor:ident, $relative:ident, $pending:ident, $resolved:ident) => {
        $anchor.root.resolve_directory_retaining(
            $relative,
            &mut $pending.resolution,
        )?;
    };
    (Local, construct, $pending:ident, $resolved:ident, $child:ident) => {
        let $child = Self::new(BeneathRoot::from_resolved($resolved)?)?;
    };
    (Retained, construct, $pending:ident, $resolved:ident, $child:ident) => {
        let Some(root) = $pending.resolution.take_directory_root() else {
            std::process::abort();
        };
        $pending.anchor = Some(anchor_from_root!(root));
        $pending.anchor
            .as_ref()
            .ok_or_else(|| {
                Error::invalid("initial cgroup capture", "self anchor is absent")
            })?
            .validate_initial_retaining(&mut $pending.probes[1])?;
    };
    (Local, finish, $child:ident) => {
        Ok($child)
    };
    (Retained, finish, $child:ident) => {
        Ok(())
    };
}

// The ordinary expansion retains its consuming locals and original check order.
// Only the selected disposition changes where returned child/probe FDs reside.
macro_rules! resolve_child_recipe {
    ($anchor:ident, $relative:ident, $disposition:ident, $pending:ident) => {{
        child_resolution_step!($disposition, active, $anchor, $pending, 0);
        child_resolution_step!($disposition, resolve, $anchor, $relative, $pending, resolved);
        child_resolution_step!($disposition, construct, $pending, resolved, child);
        child_resolution_step!($disposition, active, $anchor, $pending, 2);
        child_resolution_step!($disposition, finish, child)
    }};
}

impl RetainedCgroupAnchor {
    /// Resolves and retains one proper descendant cgroup beneath this anchor.
    ///
    /// The relative path is only a locator. Strict `openat2` resolution and
    /// the returned descriptor establish the exact cgroup identity; callers
    /// must separately authenticate any process claimed to belong to it.
    ///
    /// # Errors
    ///
    /// Rejects oversized, empty or dot-only hints, invalid/traversing paths,
    /// failed strict resolution, a stale anchor or target, and kernel errors.
    pub fn resolve_descendant(&self, relative_hint: &Path) -> Result<Self> {
        if relative_hint.as_os_str().len() > MAXIMUM_DESCENDANT_HINT_BYTES
            || !relative_hint
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
        {
            return Err(Error::invalid(
                "descendant cgroup hint",
                "must name a proper descendant within the 4096-byte limit",
            ));
        }
        self.resolve_child(relative_hint)
    }

    /// Opens a repeatable population monitor for this exact cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained cgroup is stale or its kernel events
    /// file cannot be securely opened.
    pub fn population_monitor(&self) -> Result<CgroupPopulationMonitor> {
        self.validate_active()?;
        let events = self.root.open_regular(Path::new("cgroup.events"))?;
        Ok(CgroupPopulationMonitor {
            events: File::from(events.into_owned_fd()),
        })
    }

    /// Reads the kernel-confirmed freezer state of this exact cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained cgroup is stale, its bounded
    /// `cgroup.events` record cannot be read, or the record omits a canonical
    /// `frozen` field.
    pub fn freezer_state(&self) -> Result<CgroupFreezerState> {
        self.validate_active()?;
        let events = self.root.open_regular(Path::new("cgroup.events"))?;
        let mut bytes = [0_u8; 4097];
        let length = File::from(events.into_owned_fd())
            .read_at(&mut bytes, 0)
            .map_err(|source| Error::Syscall {
                operation: "read cgroup.events",
                source,
            })?;
        if length == 0 || length == bytes.len() {
            return Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "freezer record is empty or oversized".to_owned(),
            });
        }
        parse_freezer_state(&bytes[..length])
    }

    /// Requests a freezer transition for this exact cgroup subtree.
    ///
    /// Completion of the write does not prove that every task has reached the
    /// requested state. Callers must observe [`Self::freezer_state`] until it
    /// reports the requested value before treating the transition as complete.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained cgroup is stale, the freezer control
    /// file is not an exact regular cgroup-v2 file, permission is denied, or
    /// the kernel does not accept the complete control record.
    pub fn request_freezer_state(&self, state: CgroupFreezerState) -> Result<()> {
        self.validate_active()?;
        let freezer = rustix::fs::openat(
            self.root.as_fd(),
            Path::new("cgroup.freeze"),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|source| Error::Syscall {
            operation: "open cgroup.freeze",
            source: source.into(),
        })?;
        if uapi::filesystem_type(freezer.as_fd())? != CGROUP2_SUPER_MAGIC
            || uapi::fstat(freezer.as_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(Error::WrongDescriptorType {
                expected: "cgroup-v2 freezer control",
            });
        }
        let mut remaining: &[u8] = match state {
            CgroupFreezerState::Thawed => b"0\n",
            CgroupFreezerState::Frozen => b"1\n",
        };
        while !remaining.is_empty() {
            match rustix::io::write(&freezer, remaining) {
                Ok(0) => {
                    return Err(Error::MalformedKernelResponse {
                        object: "cgroup.freeze",
                        message: "kernel accepted an incomplete freezer record".to_owned(),
                    });
                }
                Ok(written) => remaining = &remaining[written..],
                Err(rustix::io::Errno::INTR) => continue,
                Err(source) => {
                    return Err(Error::Syscall {
                        operation: "write cgroup.freeze",
                        source: source.into(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Sends `SIGKILL` to every task in this exact cgroup and its descendants.
    ///
    /// This writes the cgroup-v2 `cgroup.kill` control file relative to the
    /// retained directory. Completion of the write initiates cancellation; it
    /// does not prove process exit. Pair it with a retained population monitor
    /// and exact pidfds when quiescence is required.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup became stale, the kill interface is not
    /// an exact regular cgroup-v2 file, permission is denied, or the complete
    /// control record cannot be written.
    pub fn kill_all(&self) -> Result<()> {
        self.kill_all_with_current_cut(|| Ok(()))
    }

    /// Rechecks the owner's held cut immediately before each original kill write.
    ///
    /// The callback runs after the existing cgroup/control FD identity checks
    /// and before every write or interrupted-write retry. It can only deny the
    /// fixed operation; it cannot choose a target, supply a control FD or
    /// manufacture authorization. Owners retain their original authority and
    /// classify any attempted write as potentially ambiguous. Fail-stop cleanup
    /// callers continue to use [`Self::kill_all`] without an authority deadline.
    ///
    /// # Errors
    /// Returns the callback's denial or a converted typed error for stale
    /// cgroup custody, invalid control identity, permission or incomplete writes.
    pub fn kill_all_with_current_cut<E>(
        &self,
        mut current: impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E>
    where
        E: From<Error>,
    {
        let kill = self.open_kill_control().map_err(E::from)?;
        let mut remaining: &[u8] = b"1\n";
        while !remaining.is_empty() {
            current()?;
            match rustix::io::write(&kill, remaining) {
                Ok(0) => {
                    return Err(Error::MalformedKernelResponse {
                        object: "cgroup.kill",
                        message: "kernel accepted an incomplete kill record".to_owned(),
                    }
                    .into());
                }
                Ok(written) => remaining = &remaining[written..],
                Err(rustix::io::Errno::INTR) => continue,
                Err(source) => {
                    return Err(Error::Syscall {
                        operation: "write cgroup.kill",
                        source: source.into(),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    fn open_kill_control(&self) -> Result<OwnedFd> {
        self.validate_active()?;
        let kill = rustix::fs::openat(
            self.root.as_fd(),
            Path::new("cgroup.kill"),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|source| Error::Syscall {
            operation: "open cgroup.kill",
            source: source.into(),
        })?;
        if uapi::filesystem_type(kill.as_fd())? != CGROUP2_SUPER_MAGIC
            || uapi::fstat(kill.as_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(Error::WrongDescriptorType {
                expected: "cgroup-v2 kill control",
            });
        }
        Ok(kill)
    }

    /// Reobserves the retained cgroup's filesystem identity and active kernfs file.
    ///
    /// This does not authenticate a member or fence later removal. It allows
    /// trusted provisioning to reject a stale anchor before exposing a channel.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained identity is invalid or a fresh
    /// `cgroup.procs` open cannot obtain an active kernel reference.
    pub fn validate_current(&self) -> Result<()> {
        self.validate_active()
    }

    fn new(root: BeneathRoot) -> Result<Self> {
        require_cgroup_identity_platform!();
        let anchor = anchor_from_root!(root);
        anchor.validate_active()?;
        Ok(anchor)
    }

    fn validate_initial_retaining(&self, pending: &mut PendingRegularFileV1) -> Result<()> {
        require_cgroup_identity_platform!();
        self.validate_active_retaining(pending)
    }

    /// Returns the retained object's full kernel cgroup ID, not an authorization token.
    #[must_use]
    pub const fn kernel_id(&self) -> u64 {
        self.kernel_id
    }

    /// Borrows the descriptor that keeps the exact kernfs identity pinned.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// Observes exact cgroup membership of a retained live process.
    ///
    /// Checks active-file availability, reads fresh pidfd information, compares
    /// the complete cgroup ID, checks active-file availability again, and rereads
    /// pidfd information before final liveness. Both observations must agree on
    /// PID, thread group and cgroup. The freshest information is returned; it is
    /// not a migration lock, subtree proof, or authority for a later effect.
    /// Migration away and back between observations is not detected.
    ///
    /// # Errors
    ///
    /// Rejects an inaccessible/deactivated anchor, omitted cgroup information,
    /// different exact membership, process exit, or any kernel failure.
    pub fn verify_exact_membership(&self, process: &PidFd) -> Result<PidFdInfo> {
        self.validate_active()?;
        let info = process.info()?;
        if info.cgroup_id() != Some(self.kernel_id) {
            return Err(Error::invalid(
                "exact cgroup membership",
                "pidfd does not name this cgroup",
            ));
        }
        self.validate_active()?;
        recheck_process(process, info)
    }

    /// Observes membership in a strictly resolved proper descendant cgroup.
    ///
    /// The relative hint locates a candidate; it is not trusted membership
    /// evidence. Strict bounded resolution beneath this retained anchor and
    /// fresh pidfd cgroup-ID equality establish the observed relationship.
    /// Cgroup-v2 does not permit reparenting a cgroup, so retaining the resolved
    /// object preserves its ancestry. No alternate candidate is tried after a
    /// mismatch. Use [`Self::verify_exact_membership`] for the anchor itself.
    ///
    /// The process information is rechecked after the outer anchor's final
    /// active-file check. This detects observed migration, not a move away and
    /// back between observations. It neither discovers an arbitrary process's
    /// path nor fences migration or cgroup removal after its observations.
    ///
    /// # Errors
    ///
    /// Rejects oversized, empty or dot-only hints, invalid/traversing paths,
    /// failed strict resolution, inaccessible/deactivated anchors, mismatched
    /// membership, process exit, and kernel errors.
    pub fn verify_descendant_membership(
        &self,
        process: &PidFd,
        relative_hint: &Path,
    ) -> Result<PidFdInfo> {
        let child = self.resolve_descendant(relative_hint)?;
        let info = child.verify_exact_membership(process)?;
        self.validate_active()?;
        recheck_process(process, info)
    }

    fn resolve_child(&self, relative: &Path) -> Result<Self> {
        resolve_child_recipe!(self, relative, Local, unused)
    }

    fn resolve_initial_provisioner_retaining(
        &self,
        pending: &mut InitialCgroupChildV5,
    ) -> Result<()> {
        let relative = Path::new("system.slice/aos-sandbox-nix-floor-provision.service");
        resolve_child_recipe!(self, relative, Retained, pending)
    }

    /// Rechecks the retained identity and an active kernfs control inode.
    ///
    /// This does not fence migration or grant write access to the cgroup.
    ///
    /// # Errors
    ///
    /// Rejects changed identity, a removed/inaccessible cgroup, or kernel error.
    pub fn validate_active(&self) -> Result<()> {
        validate_active_recipe!(self, Local, unused)
    }

    fn validate_active_retaining(&self, pending: &mut PendingRegularFileV1) -> Result<()> {
        validate_active_recipe!(self, Retained, pending)
    }
}

fn parse_freezer_state(bytes: &[u8]) -> Result<CgroupFreezerState> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::MalformedKernelResponse {
        object: "cgroup.events",
        message: "freezer record is not UTF-8".to_owned(),
    })?;
    let mut fields = text.lines().filter_map(|line| line.strip_prefix("frozen "));
    let state = match fields.next() {
        Some("0") => CgroupFreezerState::Thawed,
        Some("1") => CgroupFreezerState::Frozen,
        _ => {
            return Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "frozen field is absent or invalid".to_owned(),
            });
        }
    };
    if fields.next().is_some() {
        return Err(Error::MalformedKernelResponse {
            object: "cgroup.events",
            message: "frozen field is repeated".to_owned(),
        });
    }
    Ok(state)
}

fn recheck_process(process: &PidFd, before: PidFdInfo) -> Result<PidFdInfo> {
    let after = process.info()?;
    if after.pid() != before.pid()
        || after.thread_group_id() != before.thread_group_id()
        || after.cgroup_id() != before.cgroup_id()
    {
        return Err(Error::invalid(
            "cgroup membership observation",
            "process identity or membership changed during observation",
        ));
    }
    if !process.is_alive()? {
        return Err(Error::invalid(
            "cgroup membership observation",
            "pinned process exited",
        ));
    }
    Ok(after)
}

#[cfg(test)]
mod limit_readback_tests {
    use super::*;

    #[test]
    fn finite_decimal_rejects_max_overflow_and_noncanonical_numbers() {
        assert_eq!(parse_limit_decimal(b"42"), Some(42));
        for bytes in [b"max".as_slice(), b"01", b"-1", b"18446744073709551616", b""] {
            assert_eq!(parse_limit_decimal(bytes), None);
        }
    }

    #[test]
    fn controller_records_reject_duplicate_unknown_and_trailing_fields() {
        assert!(validate_limit_record(CgroupLimitControlV1::Controllers, b"cpu memory pids\n").is_ok());
        for bytes in [b"cpu cpu\n".as_slice(), b"cpu foreign\n", b"cpu \n", b"cpu\n\n"] {
            assert!(validate_limit_record(CgroupLimitControlV1::Controllers, bytes).is_err());
        }
    }

    #[test]
    fn control_records_require_one_newline_and_closed_weight_range() {
        for bytes in [b"0\n".as_slice(), b"10001\n", b"100\nextra", b"100"] {
            assert!(validate_limit_record(CgroupLimitControlV1::CpuWeight, bytes).is_err());
        }
        assert!(validate_limit_record(CgroupLimitControlV1::CpuWeight, b"10000\n").is_ok());
        assert!(validate_limit_record(CgroupLimitControlV1::MemoryMax, b"max\n").is_ok());
    }

    #[test]
    fn fresh_and_interrupted_slots_do_not_expose_records() {
        let mut readback = CgroupLimitReadbackV1::default();
        assert!(readback.bytes(CgroupLimitControlV1::PidsMax).is_none());

        readback.phase = LimitReadbackPhaseV1::Checking;
        assert!(readback.bytes(CgroupLimitControlV1::PidsMax).is_none());
        assert!(readback.failure().is_none());
    }
}

#[cfg(test)]
mod initial_cgroup_phase_tests {
    use super::NixOfflineInitialCgroupReadbackV5;

    #[test]
    fn empty_initial_cgroup_cannot_transfer_objects() {
        let mut original = NixOfflineInitialCgroupReadbackV5::new();

        assert!(original.take_validated_pair().is_none());
        assert!(!original.attempted);
        assert!(!original.complete);
    }

    #[test]
    fn interrupted_initial_cgroup_remains_closed() {
        let mut original = NixOfflineInitialCgroupReadbackV5 {
            attempted: true,
            ..NixOfflineInitialCgroupReadbackV5::default()
        };

        assert!(original.take_validated_pair().is_none());
        assert!(original.attempted);
        assert!(!original.complete);
    }

    #[test]
    fn completion_marker_alone_cannot_transfer_kernel_objects() {
        let mut original = NixOfflineInitialCgroupReadbackV5 {
            attempted: true,
            complete: true,
            ..NixOfflineInitialCgroupReadbackV5::default()
        };

        assert!(original.take_validated_pair().is_none());
        assert!(original.root.is_none());
        assert!(original.child.anchor.is_none());
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Read-only kernel fixture failures intentionally panic."
)]
mod tests {
    use super::*;
    use std::fs::File;
    #[cfg(feature = "kernel-tests")]
    use std::num::NonZeroU32;
    #[cfg(feature = "kernel-tests")]
    use std::process::{Child, Command};
    #[cfg(feature = "kernel-tests")]
    use std::time::{Duration, Instant};

    #[test]
    fn freezer_state_requires_one_canonical_kernel_field() {
        assert_eq!(
            parse_freezer_state(b"populated 1\nfrozen 0\n").expect("thawed state"),
            CgroupFreezerState::Thawed
        );
        assert_eq!(
            parse_freezer_state(b"populated 1\nfrozen 1\n").expect("frozen state"),
            CgroupFreezerState::Frozen
        );
        for invalid in [
            b"populated 1\n".as_slice(),
            b"frozen 2\n".as_slice(),
            b"frozen 0\nfrozen 1\n".as_slice(),
            b"frozen 1\xff\n".as_slice(),
        ] {
            assert!(parse_freezer_state(invalid).is_err());
        }
    }

    #[test]
    fn ordinary_directory_with_matching_file_names_is_not_a_cgroup() {
        let temporary = tempfile::tempdir().expect("test directory");
        File::create(temporary.path().join("cgroup.procs")).expect("fake cgroup file");
        let fd = File::open(temporary.path())
            .expect("open ordinary directory")
            .into();
        assert!(matches!(
            CgroupV2Root::from_owned(fd),
            Err(Error::WrongDescriptorType { .. })
        ));
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn real_readonly_hierarchy_resolves_exact_current_membership() {
        let root = CgroupV2Root::try_from(
            BeneathRoot::from_owned(
                File::open("/sys/fs/cgroup")
                    .expect("open cgroup-v2 hierarchy")
                    .into(),
            )
            .expect("pin cgroup root"),
        )
        .expect("admit real cgroup root");
        let process =
            PidFd::open(NonZeroU32::new(std::process::id()).expect("test PID")).expect("pin self");
        let membership = std::fs::read_to_string("/proc/self/cgroup").expect("read own membership");
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .expect("unified membership");
        let relative = if relative.is_empty() { "." } else { relative };
        let anchor = root
            .resolve(Path::new(relative))
            .expect("resolve current cgroup");
        let info = anchor
            .verify_exact_membership(&process)
            .expect("exact self membership");
        assert_eq!(info.cgroup_id(), Some(anchor.kernel_id()));
        let hierarchy = root.resolve(Path::new(".")).expect("pin hierarchy root");
        if hierarchy.kernel_id() != anchor.kernel_id() {
            assert!(matches!(
                hierarchy.verify_exact_membership(&process),
                Err(Error::InvalidInput {
                    field: "exact cgroup membership",
                    ..
                })
            ));
            assert_eq!(
                hierarchy
                    .verify_descendant_membership(&process, Path::new(relative))
                    .expect("hinted descendant membership")
                    .cgroup_id(),
                Some(anchor.kernel_id())
            );
        }
        for invalid in ["", ".", "./.", "../outside", "/sys/fs/cgroup"] {
            assert!(
                hierarchy
                    .verify_descendant_membership(&process, Path::new(invalid))
                    .is_err()
            );
        }
        let oversized = "./".repeat(MAXIMUM_DESCENDANT_HINT_BYTES / 2 + 1);
        assert!(matches!(
            hierarchy.verify_descendant_membership(&process, Path::new(&oversized)),
            Err(Error::InvalidInput {
                field: "descendant cgroup hint",
                ..
            })
        ));
        for invalid in ["", "/", "..", "../cgroup", "cgroup.procs"] {
            assert!(
                root.resolve(Path::new(invalid)).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn retained_population_distinguishes_empty_retired_and_recreated_cgroups() {
        let hierarchy = CgroupV2Root::from_owned(
            File::open("/sys/fs/cgroup")
                .expect("open cgroup-v2 hierarchy")
                .into(),
        )
        .expect("admit cgroup-v2 hierarchy");
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").expect("read test process membership");
        let current = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .expect("unified test process membership");
        let fixture_name = format!("aos-retirement-proof-{}", std::process::id());
        let fixture_relative = Path::new(current).join(&fixture_name);
        let member_relative = fixture_relative.join("member");
        let fixture_path = Path::new("/sys/fs/cgroup").join(&fixture_relative);
        let member_path = Path::new("/sys/fs/cgroup").join(&member_relative);

        std::fs::create_dir(&fixture_path).expect("create fixture cgroup");
        std::fs::create_dir(&member_path).expect("create member cgroup");
        let fixture = hierarchy
            .resolve(&fixture_relative)
            .expect("retain fixture cgroup");
        let first_member = hierarchy
            .resolve(&member_relative)
            .expect("retain first member cgroup");
        let fixture_population = fixture
            .population_monitor()
            .expect("retain fixture population");
        let first_population = first_member
            .population_monitor()
            .expect("retain first member population");
        assert_eq!(
            fixture_population.state().expect("empty fixture"),
            CgroupPopulationState::Empty
        );
        assert_eq!(
            first_population.state().expect("empty member"),
            CgroupPopulationState::Empty
        );

        let mut first_process = spawn_fixture_process();
        let first_pid = NonZeroU32::new(first_process.id()).expect("nonzero first fixture PID");
        let first_pidfd = PidFd::open(first_pid).expect("retain first fixture process");
        move_process(&member_path, first_pid);
        assert_eq!(
            first_population.state().expect("populated member"),
            CgroupPopulationState::Populated
        );
        assert_eq!(
            fixture_population.state().expect("populated fixture"),
            CgroupPopulationState::Populated
        );
        assert_busy_removal(&member_path, "populated member cgroup");
        assert_busy_removal(&fixture_path, "fixture with a live descendant");

        stop_fixture_process(&mut first_process);
        wait_for_population(&first_population, CgroupPopulationState::Empty);
        wait_for_population(&fixture_population, CgroupPopulationState::Empty);
        assert!(
            !first_pidfd
                .is_alive()
                .expect("first fixture pidfd liveness")
        );
        std::fs::remove_dir(&member_path).expect("retire first member cgroup");
        assert_eq!(
            first_population.state().expect("retired first member"),
            CgroupPopulationState::Retired
        );
        assert!(first_member.validate_current().is_err());

        std::fs::create_dir(&member_path).expect("recreate same member path");
        let second_member = hierarchy
            .resolve(&member_relative)
            .expect("retain recreated member cgroup");
        let second_population = second_member
            .population_monitor()
            .expect("retain recreated member population");
        assert_ne!(first_member.kernel_id(), second_member.kernel_id());
        assert_eq!(
            first_population.state().expect("old member stays retired"),
            CgroupPopulationState::Retired
        );
        assert_eq!(
            second_population.state().expect("empty recreated member"),
            CgroupPopulationState::Empty
        );

        let mut second_process = spawn_fixture_process();
        let second_pid = NonZeroU32::new(second_process.id()).expect("nonzero second fixture PID");
        let second_pidfd = PidFd::open(second_pid).expect("retain second fixture process");
        move_process(&member_path, second_pid);
        assert_eq!(
            second_population
                .state()
                .expect("populated recreated member"),
            CgroupPopulationState::Populated
        );
        assert_eq!(
            first_population
                .state()
                .expect("old member remains retired"),
            CgroupPopulationState::Retired
        );
        assert_busy_removal(&fixture_path, "fixture with recreated live descendant");

        stop_fixture_process(&mut second_process);
        wait_for_population(&second_population, CgroupPopulationState::Empty);
        wait_for_population(&fixture_population, CgroupPopulationState::Empty);
        assert!(
            !second_pidfd
                .is_alive()
                .expect("second fixture pidfd liveness")
        );
        std::fs::remove_dir(&member_path).expect("retire recreated member cgroup");
        assert_eq!(
            second_population.state().expect("retired recreated member"),
            CgroupPopulationState::Retired
        );
        std::fs::remove_dir(&fixture_path).expect("retire fixture cgroup");
        assert_eq!(
            fixture_population.state().expect("retired fixture"),
            CgroupPopulationState::Retired
        );
    }

    #[cfg(feature = "kernel-tests")]
    fn spawn_fixture_process() -> Child {
        Command::new(std::env::var_os("AOS_CGROUP_TEST_SLEEP").expect("sleep fixture path"))
            .arg("30")
            .spawn()
            .expect("spawn cgroup member process")
    }

    #[cfg(feature = "kernel-tests")]
    fn move_process(cgroup: &Path, pid: NonZeroU32) {
        std::fs::write(cgroup.join("cgroup.procs"), format!("{}\n", pid.get()))
            .expect("move fixture process into cgroup");
    }

    #[cfg(feature = "kernel-tests")]
    fn stop_fixture_process(process: &mut Child) {
        process.kill().expect("kill fixture process");
        process.wait().expect("reap fixture process");
    }

    #[cfg(feature = "kernel-tests")]
    fn wait_for_population(population: &CgroupPopulationMonitor, expected: CgroupPopulationState) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = population.state().expect("observe cgroup population");
            if observed == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "expected {expected:?}, observed {observed:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(feature = "kernel-tests")]
    fn assert_busy_removal(path: &Path, context: &str) {
        let error = std::fs::remove_dir(path).expect_err(context);
        assert_eq!(
            error.raw_os_error(),
            Some(libc::EBUSY),
            "{context}: {error}"
        );
    }
}
