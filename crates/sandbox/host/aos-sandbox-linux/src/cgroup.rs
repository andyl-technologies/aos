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

mod network_worker_absence;
pub use network_worker_absence::{NetworkWorkerCgroupAbsenceOriginalV4, NetworkWorkerCgroupAbsenceRefusalV4};

mod host_inventory;
pub use host_inventory::{HostRuntimeCgroupAbsenceOriginalV5, HostRuntimeCgroupAbsenceRefusalV5};

mod network_worker_aggregate;
pub use network_worker_aggregate::NetworkWorkerAggregateAssociationOriginalV4;

mod active_original;
pub use active_original::CgroupActiveOriginalV2;

mod single_task;
pub use single_task::CgroupSingleTaskObservationV1;

mod population_observation;
mod issued_quiescence;
pub use issued_quiescence::{IssuedCgroupQuiescenceAttemptV2, IssuedCgroupQuiescenceRefusalV2};
pub use population_observation::{CgroupPopulationObservationV1, CgroupPopulationObservationRefusalV1};
use population_observation::read_population_state;

mod network_birth_population;
pub use network_birth_population::NetworkBirthPopulationDonationOriginalV2;
mod network_child_control;
pub use network_child_control::{NetworkChildControlDonationOriginalV2,
    NetworkChildControlKindV2, NetworkChildControlValueV2};
mod network_child_ancestry;
pub use network_child_ancestry::NetworkChildAggregateAncestryOriginalV2;

mod recovery_quiescence;
pub use recovery_quiescence::{StorageWorkerRecoveryQuiescenceV1, StorageRecoveryQuiescenceErrorV1, quiesce_storage_worker_cgroup_v1};

mod recovery_directory;
pub use recovery_directory::{
    StorageWorkerRecoveryDirectoryV1, StorageWorkerRecoveryDirectoryErrorV1,
    StorageWorkerRecoveryDirectoryRefusalV1, read_storage_worker_recovery_names_v1,
};

mod storage_executor_startup;
pub use storage_executor_startup::StorageExecutorInitialCgroupReadbackV1;

mod limit_currentness;
pub use limit_currentness::{CgroupLimitCurrentnessSampleV1, CpuLimitCurrentnessSampleV1};

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

mod control_readback;
use control_readback::{
    capture_limit_control_slot_v1, recheck_limit_control_slot_v1,
    capture_limit_control_slot_with_native_disposition_v4,
    recheck_limit_control_slot_with_native_disposition_v4,
};

mod runtime_pids;
pub use runtime_pids::{
    CgroupControllerReadbackV2,
    PidsLimitReadbackV1, PidsLimitReadbackRefusalV1,
    MemoryLimitReadbackV1, MemoryLimitReadbackRefusalV1,
};

mod membership_readback;
mod runtime_scope_membership;
mod storage_output_client;
pub use storage_output_client::StorageOutputClientCgroupOriginalV2;
pub use runtime_scope_membership::{
    RuntimeScopeMembershipFilesDisposedV4, RuntimeScopeMembershipOriginalV1,
};
pub use membership_readback::{ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1};

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
    bookend_disposed: Option<crate::path::FileIdentity>,
    final_name_disposed: Option<crate::path::FileIdentity>,
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
            bookend_disposed: None,
            final_name_disposed: None,
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

#[derive(Debug)]
struct CgroupLimitFilesDisposedV4 {
    opening_identities: [Option<crate::path::FileIdentity>; 7],
}

/// Retains fixed control-file descriptors, bounded bytes and the first error.
///
/// This is observed DATA, not an enforcement or currentness capability. An
/// interrupted capture cannot be retried. Missing files remain explicit kernel
/// observations; callers must decide which files their actual topology requires.
#[derive(Debug)]
pub struct CgroupLimitReadbackV1 {
    slots: [LimitControlSlotV1; 7],
    active_probes: [PendingRegularFileV1; 4],
    retain_active: bool,
    native_disposed: Option<CgroupLimitFilesDisposedV4>,
    initial_active_disposed: Option<[crate::path::FileIdentity; 2]>,
    final_active_disposed: Option<[crate::path::FileIdentity; 2]>,
    phase: LimitReadbackPhaseV1,
    failure: Option<Error>,
}

impl Default for CgroupLimitReadbackV1 {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| LimitControlSlotV1::default()),
            active_probes: std::array::from_fn(|_| PendingRegularFileV1::default()),
            retain_active: false,
            native_disposed: None,
            initial_active_disposed: None,
            final_active_disposed: None,
            phase: LimitReadbackPhaseV1::Fresh,
            failure: None,
        }
    }
}

impl CgroupLimitReadbackV1 {
    /// Disposes successful verification names while retaining original OFDs.
    ///
    /// This releases only completed positive bookend/name handles. Initial and
    /// final bytes, absence observations, phase and native Results remain on
    /// this owner. It creates no new observation or authority. A failed or
    /// interrupted original cannot dispose its partial acquisitions here.
    ///
    /// # Errors
    /// Refuses an incomplete or failed final bookend before changing any slot.
    pub fn settle_positive_named_verifications_v1(&mut self) -> Result<()> {
        if self.phase != LimitReadbackPhaseV1::Current || self.failure.is_some() {
            return Err(Error::invalid("cgroup named settlement", "final original is not positive"));
        }
        for slot in &mut self.slots {
            drop(std::mem::take(&mut slot.bookend));
            drop(std::mem::take(&mut slot.final_name));
        }
        if self.retain_active {
            for probe in &mut self.active_probes { drop(std::mem::take(probe)); }
        }
        Ok(())
    }


    /// Reports whether the exact retained final control flight can retire.
    ///
    /// This is nonauthorizing point-in-time DATA. The upper caller must finish
    /// its whole semantic conjunction before consuming the actual files.
    #[must_use]
    pub fn completed_files_are_disposable_v4(&self) -> bool {
        self.retain_active && self.native_disposed.is_none()
            && self.phase == LimitReadbackPhaseV1::Current && self.failure.is_none()
            && self.slots.iter().all(|slot| {
                slot.absent.is_some() || (slot.opening.file().is_ok()
                    && slot.bookend_disposed.is_some() && slot.final_name_disposed.is_some())
            })
    }

    /// Physically retires complete control files, retaining bytes and witnesses.
    ///
    /// # Errors
    /// Refuses a partial, failed, ordinary or already disposed original. The
    /// caller completes all comparisons and owed local posts before entry.
    pub fn retire_completed_files_once_v4(&mut self) -> Result<()> {
        if !self.completed_files_are_disposable_v4() {
            return Err(Error::invalid("cgroup control file retirement", "original final flight is not positive"));
        }
        let identities = std::array::from_fn(|index| {
            self.slots[index].opening.file().ok().map(|file| file.identity())
        });
        self.settle_positive_named_verifications_v1()?;
        for slot in &mut self.slots {
            drop(slot.opening.take_readable_file());
        }
        self.native_disposed = Some(CgroupLimitFilesDisposedV4 { opening_identities: identities });
        Ok(())
    }

    /// Reports actual physical retirement on this exact completed original.
    #[must_use]
    pub fn native_files_are_disposed_v4(&self) -> bool {
        self.native_disposed.as_ref().is_some_and(|proof| {
            self.phase == LimitReadbackPhaseV1::Current && self.failure.is_none()
                && self.slots.iter().zip(&proof.opening_identities).all(|(slot, identity)| {
                    slot.opening.file().is_err() && (slot.absent.is_some() || identity.is_some())
                })
        })
    }

    /// Captures the same control recipe with retained boundary active probes.
    ///
    /// The existing `recheck` automatically retains its same final boundary
    /// probes for this original. Ordinary `capture` keeps its original native
    /// disposition. Only a whole positive final named settlement releases them.
    ///
    /// # Errors
    /// Retains actual probe/control/native errors and refuses repeated capture.
    pub fn capture_retaining_v2(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.phase != LimitReadbackPhaseV1::Fresh {
            return Err(Error::invalid("cgroup limit capture", "already attempted"));
        }
        self.retain_active = true;
        self.capture(anchor)
    }

    /// Retires only the complete initial active probes after caller comparisons.
    ///
    /// # Errors
    /// Refuses ordinary, partial, failed or repeated initial observations.
    pub fn retire_initial_active_files_once_v4(&mut self) -> Result<()> {
        if !self.retain_active || self.phase != LimitReadbackPhaseV1::Ready
            || self.failure.is_some() || self.initial_active_disposed.is_some()
        {
            return Err(Error::invalid("initial control active retirement", "original capture is not positive"));
        }
        let identities = [self.active_probes[0].file()?.identity(), self.active_probes[1].file()?.identity()];
        for probe in &mut self.active_probes[..2] {
            drop(probe.take_readable_file());
        }
        self.initial_active_disposed = Some(identities);
        Ok(())
    }

    /// Performs the same final recipe after exact initial-probe disposal.
    ///
    /// # Errors
    /// Refuses absent actual initial disposal before native IO, or preserves
    /// the existing final-recheck native/parser failure and reached prefix.
    pub fn recheck_after_initial_disposal_v4(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.initial_active_disposed.is_none() {
            return Err(Error::invalid("segmented control bookend", "initial probes remain occupied"));
        }
        self.recheck(anchor)
    }

    /// Retires the complete final active probes without dropping control OFDs.
    ///
    /// # Errors
    /// Refuses missing initial disposal, incomplete/failing final capture or
    /// repeat retirement. The caller retains all original anchors separately.
    pub fn retire_final_active_files_once_v4(&mut self) -> Result<()> {
        if !self.retain_active || self.phase != LimitReadbackPhaseV1::Current
            || self.failure.is_some() || self.initial_active_disposed.is_none()
            || self.final_active_disposed.is_some()
        {
            return Err(Error::invalid("final control active retirement", "original final flight is not positive"));
        }
        let identities = [self.active_probes[2].file()?.identity(), self.active_probes[3].file()?.identity()];
        for probe in &mut self.active_probes[2..] {
            drop(probe.take_readable_file());
        }
        self.final_active_disposed = Some(identities);
        Ok(())
    }

    /// Bounds the segmented initial/final active-file interval used by Host.
    ///
    /// Initial and final native entry are separated by an actual same-reader
    /// physical-disposal gate. The old unsegmented supplier remains unchanged.
    #[must_use]
    pub fn segmented_active_receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(8 * 13)?, 2, 1))
    }

    /// Bounds the actual reader and four additional boundary probe descriptors.
    ///
    /// The seven existing control-file obligations remain separate. Repeated
    /// probes name only the same one `cgroup.procs` entry, not four new rows.
    #[must_use]
    pub fn retained_active_receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(8 * 13)?, 4, 1))
    }

    /// Bounds the seven original control files and one named verification file.
    ///
    /// This additional supplier is for `capture_retaining_v2`: successful
    /// per-control name comparisons close their exact named descriptor before
    /// the next slot. A failed comparison keeps that descriptor and terminates
    /// the reader. Original readable OFDs remain held through final recheck.
    /// The four retained active probes have their separate existing supplier.
    #[must_use]
    pub fn retained_control_receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let paths = CgroupLimitControlV1::ALL.iter().try_fold(0_usize, |bytes, control| {
            bytes.checked_add(control.name().len().checked_add(1)?)
        })?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(paths.checked_mul(3)?)?
            .checked_add(21 * 128)?;
        Some((bytes, 7 + 1, 7))
    }

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
        self.validate_boundary_active(anchor, 2)?;
        for control in CgroupLimitControlV1::ALL {
            recheck_limit_control_slot_with_native_disposition_v4(
                anchor, control, &mut self.slots[control as usize], self.retain_active,
            )?;
        }
        self.validate_boundary_active(anchor, 3)
    }

    fn capture_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.validate_boundary_active(anchor, 0)?;
        for control in CgroupLimitControlV1::ALL {
            capture_limit_control_slot_with_native_disposition_v4(
                anchor, control, &mut self.slots[control as usize], self.retain_active,
            )?;
        }
        self.validate_boundary_active(anchor, 1)
    }

    fn validate_boundary_active(&mut self, anchor: &RetainedCgroupAnchor, index: usize) -> Result<()> {
        if self.retain_active {
            anchor.validate_active_retaining(&mut self.active_probes[index])
        } else {
            anchor.validate_current()
        }
    }
}

/// Retains the single finite `cpu.max` observation for FirstGlobal admission.
///
/// This read-only original is separate from the ordinary seven-control reader.
/// It neither changes cgroup limits nor grants access to the underlying anchor.
#[derive(Debug, Default)]
pub struct FirstGlobalCpuReadbackV1 {
    slot: LimitControlSlotV1,
    attempted: bool,
    failure: Option<Error>,
    quota: Option<(u64, u64)>,
    retained_active: Option<[CgroupActiveOriginalV2; 4]>,
    initial_files_retired: Option<[crate::path::FileIdentity; 2]>,
}

impl FirstGlobalCpuReadbackV1 {
    /// Closes a complete retained initial CPU proof after all owner comparisons.
    ///
    /// Native bytes, quota, named identities and once fences remain. This
    /// transition is for an initial-only consumer; a later recheck refuses.
    ///
    /// # Errors
    /// Refuses partial, failed, ordinary, rechecked or retired observations.
    pub fn retire_positive_initial_files_once_v2(&mut self) -> Result<()> {
        if !self.attempted || self.failure.is_some() || self.quota.is_none()
            || self.initial_files_retired.is_some() || self.slot.final_length != 0 {
            return Err(Error::invalid("initial CPU proof retirement", "original capture is not positive"));
        }
        let identities = [self.slot.opening.file()?.identity(), self.slot.bookend.file()?.identity()];
        let probes = self.retained_active.as_mut().ok_or_else(|| {
            Error::invalid("initial CPU proof retirement", "no retained initial probes")
        })?;
        probes[0].retire_positive_file_once_v2()?;
        probes[1].retire_positive_file_once_v2()?;
        drop(self.slot.opening.take_readable_file());
        drop(self.slot.bookend.take_readable_file());
        self.initial_files_retired = Some(identities);
        Ok(())
    }

    /// Captures the same CPU recipe while retaining its reached active probes.
    ///
    /// The ordinary capture keeps its existing native disposition. This
    /// original also retains both reached recheck probes on a later recheck;
    /// no failed prefix or native cause is replaced by the returned marker.
    ///
    /// # Errors
    /// Refuses reentry and retains actual active/control/record native errors.
    pub fn capture_retaining_v2(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.attempted || self.retained_active.is_some() {
            return Err(Error::invalid("FirstGlobal cpu.max", "already attempted"));
        }
        self.retained_active = Some(std::array::from_fn(|_| CgroupActiveOriginalV2::new()));
        self.capture(anchor)
    }

    /// Prices the complete retaining capture/recheck, beyond a donated input.
    ///
    /// Three control OFDs and four actual active probes remain held. Repeated
    /// probes name the same cgroup.procs entry beside the fixed cpu.max name.
    #[must_use]
    pub fn retained_receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(active.0.checked_mul(4)?)?.checked_add(6 * 256)?;
        Some((bytes, 3_usize.checked_add(active.1.checked_mul(4)?)?, 2))
    }

    /// Prices only the actual retaining initial CPU capture, without recheck.
    #[must_use]
    pub fn retained_initial_obligations_v2() -> Option<(usize, usize, usize)> {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(active.0.checked_mul(2)?)?.checked_add(4 * 256)?;
        Some((bytes, 2_usize.checked_add(active.1.checked_mul(2)?)?, 2))
    }

    fn active_boundary(&mut self, anchor: &RetainedCgroupAnchor, index: usize) -> Result<()> {
        match self.retained_active.as_mut() {
            Some(probes) => probes[index].capture_once_v2(anchor),
            None => anchor.validate_current(),
        }
    }

    /// Disposes positive CPU verification names, preserving the readable OFD.
    ///
    /// Initial/final bytes, parsed quota and native failure slots remain held.
    /// Failed or incomplete readers retain every partial descriptor instead.
    ///
    /// # Errors
    /// Refuses missing initial quota, a failed original or no final byte sample.
    pub fn settle_positive_named_verifications_v1(&mut self) -> Result<()> {
        if self.quota.is_none() || self.failure.is_some() || self.slot.final_length == 0 {
            return Err(Error::invalid("cpu named settlement", "final original is not positive"));
        }
        drop(std::mem::take(&mut self.slot.bookend));
        drop(std::mem::take(&mut self.slot.final_name));
        Ok(())
    }


    /// Captures the same original finite CPU quota and exact period once.
    ///
    /// # Errors
    /// Retains stale-anchor, open/read/name and malformed or unbounded-quota
    /// errors. Reentry cannot replace any original descriptor or cause.
    pub fn capture(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.attempted {
            return Err(Error::invalid("FirstGlobal cpu.max", "already attempted"));
        }
        self.attempted = true;
        match self.capture_once(anchor) {
            Ok(quota) => {
                self.quota = Some(quota);
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error);
                Err(Error::invalid("FirstGlobal cpu.max", "original failure retained"))
            }
        }
    }

    fn capture_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<(u64, u64)> {
        self.active_boundary(anchor, 0)?;
        let path = Path::new("cpu.max");
        anchor.root.open_regular_retaining(path, &mut self.slot.opening)?;
        read_limit_record(
            self.slot.opening.file()?.as_fd(), &mut self.slot.bytes, &mut self.slot.length,
        )?;
        let body = self.slot.bytes[..self.slot.length].strip_suffix(b"\n")
            .ok_or_else(|| Error::invalid("FirstGlobal cpu.max", "missing final newline"))?;
        let mut fields = body.split(|byte| *byte == b' ');
        let quota = fields.next()
            .ok_or_else(|| Error::invalid("FirstGlobal cpu.max", "missing quota"))?;
        let period = fields.next()
            .filter(|_| fields.next().is_none())
            .ok_or_else(|| Error::invalid("FirstGlobal cpu.max", "missing or extra period field"))?;
        let quota = parse_limit_decimal(quota)
            .filter(|value| *value > 0)
            .ok_or_else(|| Error::invalid("FirstGlobal cpu.max", "quota is not finite and positive"))?;
        let period = parse_limit_decimal(period)
            .filter(|value| *value > 0)
            .ok_or_else(|| Error::invalid("FirstGlobal cpu.max", "period is not finite and positive"))?;
        anchor.root.open_regular_retaining(path, &mut self.slot.bookend)?;
        if self.slot.opening.file()?.identity() != self.slot.bookend.file()?.identity() {
            return Err(Error::invalid("FirstGlobal cpu.max", "named identity changed"));
        }
        self.active_boundary(anchor, 1)?;
        Ok((quota, period))
    }

    /// Borrows the complete finite quota and period after successful capture.
    #[must_use]
    pub fn quota_and_period(&self) -> Option<(u64, u64)> {
        self.failure.is_none().then_some(self.quota).flatten()
    }

    /// Borrows the first authentic native or validation failure.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.retained_active.as_ref().and_then(|probes| probes.iter().find_map(|probe| probe.failure()))
            .or(self.failure.as_ref())
    }

    /// Rechecks the original OFD and fresh named identity without replacing it.
    ///
    /// # Errors
    /// Retains changed records, stale anchors and native read/open errors.
    pub fn recheck(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.quota.is_none() || self.failure.is_some() || self.slot.final_length != 0
            || self.initial_files_retired.is_some() {
            return Err(Error::invalid("FirstGlobal cpu.max", "not ready for final bookend"));
        }
        let result = (|| {
            self.active_boundary(anchor, 2)?;
            read_limit_record(
                self.slot.opening.file()?.as_fd(),
                &mut self.slot.final_bytes,
                &mut self.slot.final_length,
            )?;
            if self.slot.bytes[..self.slot.length] != self.slot.final_bytes[..self.slot.final_length] {
                return Err(Error::invalid("FirstGlobal cpu.max", "same-OFD quota changed"));
            }
            anchor.root.open_regular_retaining(Path::new("cpu.max"), &mut self.slot.final_name)?;
            if self.slot.opening.file()?.identity() != self.slot.final_name.file()?.identity() {
                return Err(Error::invalid("FirstGlobal cpu.max", "final named identity changed"));
            }
            self.active_boundary(anchor, 3)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.failure = Some(error);
                Err(Error::invalid("FirstGlobal cpu.max", "original bookend failure retained"))
            }
        }
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

/// Retains an owned cgroup root and the same `.` resolution through validation.
///
/// The existing root/active-file/child engine owns every reached FD. This
/// supplies kernel identity DATA only; callers authenticate its actual Host,
/// protocol descriptor role, assignment and purpose independently.
#[derive(Debug, Default)]
pub struct RuntimeScopeCgroupOriginalV1 {
    original: InitialServiceCgroupCaptureV1,
    result: Option<Result<()>>,
    retired_probes: Option<[crate::path::FileIdentity; 4]>,
}

impl RuntimeScopeCgroupOriginalV1 {
    /// Creates empty native destinations without opening or validating anything.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Runs the same owned-root admission followed by exact `.` resolution.
    ///
    /// # Errors
    /// Retains the original directory, active-file, cgroup or resolution error.
    /// An interrupted or failed attempt cannot be repeated.
    pub fn capture_once(&mut self, root: OwnedFd) -> Result<()> {
        if self.result.is_some() { return Err(Error::invalid("runtime scope cgroup", "already attempted")); }
        self.result = Some(self.original.capture_initial(root, InitialServiceCgroupV1::RuntimeScopeSameRoot));
        if matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(Error::invalid("runtime scope cgroup", "original admission failed")) }
    }

    /// Moves only the actual validated root and same-root anchor once.
    ///
    /// Probe originals remain resident beside the caller's full native window.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.original.take_validated_pair()
    }

    /// Borrows the first actual native admission/resolution error.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.result.as_ref()?.as_ref().err()
    }

    /// Retires four positive temporary probes after the actual pair moved.
    ///
    /// The caller retains both admitted directory objects. This original keeps
    /// its native result and exact four probe identities without resetting its
    /// entry fence or releasing any resource charge.
    ///
    /// # Errors
    /// Refuses incomplete, failed, unmoved or previously retired originals.
    pub fn retire_positive_probes_once_v2(&mut self) -> Result<()> {
        if !matches!(self.result, Some(Ok(()))) || self.retired_probes.is_some()
            || self.original.root.is_some() || self.original.child.anchor.is_some() {
            return Err(Error::invalid("runtime cgroup probe retirement", "the original pair has not completed its move"));
        }
        let identities = [self.original.root_probe.file()?.identity(),
            self.original.child.probes[0].file()?.identity(),
            self.original.child.probes[1].file()?.identity(),
            self.original.child.probes[2].file()?.identity()];
        drop(self.original.root_probe.take_readable_file());
        for probe in &mut self.original.child.probes { drop(probe.take_readable_file()); }
        self.retired_probes = Some(identities);
        Ok(())
    }

    /// Returns fixed byte, native-FD and two-name representation DATA.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(8192)?, 6, 2))
    }
}

/// Retains initial hierarchy and fixed offline-provisioner cgroup observations.
///
/// This move-only DATA reservoir parks a returned root duplicate and every
/// returned child/probe before validation. It proves kernel object identity,
/// not service provenance, privilege, startup admission, funding or currentness.
/// Its descendant is selected only by the private fixed service roles.
/// It retains at most two directory descriptors and four active-file probes;
/// transitions between candidate and validated slots never duplicate an FD.
/// The external caller keeps the reservoir alive on error or caught unwind.
#[derive(Debug, Default)]
struct InitialServiceCgroupCaptureV1 {
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

/// Retains only the original Nix floor provisioner's fixed cgroup prefix.
///
/// All partial native objects stay in the same private capture engine used by
/// other closed initial roles. This supplies identity DATA, never a service or
/// resource original, and accepts no caller-selected descendant pathname.
#[derive(Debug, Default)]
pub struct NixOfflineInitialCgroupReadbackV5 {
    original: InitialServiceCgroupCaptureV1,
}

impl NixOfflineInitialCgroupReadbackV5 {
    /// Creates empty capture slots without a native observation.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Captures the one fixed original floor provisioner and hierarchy root.
    ///
    /// # Errors
    /// Retains the native partial acquisition and returns its original cause.
    pub fn capture_provisioner(&mut self, root: OwnedFd) -> Result<()> {
        self.original.capture_initial(root, InitialServiceCgroupV1::NixProvisioner)
    }

    /// Moves only the fully validated pair once without a new observation.
    #[must_use]
    pub fn take_validated_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        self.original.take_validated_pair()
    }
}

#[derive(Clone, Copy)]
enum InitialServiceCgroupV1 {
    NixProvisioner,
    RuntimeScopeSameRoot,
    RuntimeBootPreparation,
    SourceSigner,
    CacheSigner,
    MountService,
    NetworkService,
    NetworkReceivingAggregate,
    Ownership,
    Controller,
    Storage,
    StorageReceivingAggregate,
    StorageAggregateMain,
    Root,
    ControllerStartupHost,
    HostPhase0Target,
    ControllerStartupMount,
    ControllerPublisher,
    StorageManager,
    StorageControl,
}

impl InitialServiceCgroupV1 {
    fn relative(self) -> &'static Path {
        Path::new(match self {
            Self::NixProvisioner => "system.slice/aos-sandbox-nix-floor-provision.service",
            Self::RuntimeScopeSameRoot => ".",
            Self::RuntimeBootPreparation => "aos.slice/aos-control.slice/aos-sandbox-runtime-publisher.service",
            Self::StorageManager => "init.scope",
            Self::StorageControl => "aos.slice/aos-control.slice",
            Self::SourceSigner => "aoscomponents.slice/aos-sandbox-source-signerd.service",
            Self::CacheSigner => "aoscomponents.slice/aos-sandbox-cache-signerd.service",
            Self::MountService => "aoscomponents.slice/aos-sandbox-mountd.service",
            Self::NetworkService => "aoscomponents.slice/aoscomponents-network.slice/aos-netd.service",
            Self::NetworkReceivingAggregate => "aoscomponents.slice/aoscomponents-network.slice",
            Self::Ownership => "aoscomponents.slice/aos-sandbox-ownershipd.service",
            Self::Controller => "aos.slice/aos-control.slice/aos-sandboxd.service",
            Self::Storage => StorageCgroupLayoutV1::Ordinary.main_relative_v1(),
            Self::StorageReceivingAggregate => StorageCgroupLayoutV1::ReceivingAggregate.worker_parent_relative_v1(),
            Self::StorageAggregateMain => "aos-storaged.service",
            Self::Root => "system.slice/aos-sandbox-policy-authorityd.service",
            Self::HostPhase0Target => "system.slice/aos-sandbox-host-phase0-target.service",
            Self::ControllerStartupHost => "system.slice/aos-sandbox-hostd.service",
            Self::ControllerStartupMount => "aos.slice/aos-control.slice/aos-sandbox-mountd.service",
            Self::ControllerPublisher => "aos.slice/aos-control.slice/aos-view-publisher.service",
        })
    }
}

// Fixed running roles retain the root-open Result before entering the same
// original hierarchy/child/probe engine. They never accept an owned descriptor
// or caller path; those are identity DATA, never a source of service payment.
#[derive(Debug, Default)]
struct FixedRunningServiceCgroupCaptureV1 {
    original: InitialServiceCgroupCaptureV1,
    root_open: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    capture: Option<Result<()>>,
    closed: Option<Error>,
    entered: bool,
}

impl FixedRunningServiceCgroupCaptureV1 {
    fn capture_once(&mut self, role: InitialServiceCgroupV1) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| Error::invalid(
                "fixed initial cgroup capture", "already attempted"));
            return Err(Error::invalid("fixed initial cgroup capture", "original failure retained"));
        }
        self.entered = true;
        self.root_open = Some(rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ));
        let returned = self.root_open.take();
        match returned {
            Some(Ok(root)) => {
                // The owning move goes straight into the existing pending
                // original before its first directory/filesystem validation.
                self.capture = Some(self.original.capture_initial(root, role));
            }
            returned => { self.root_open = returned; }
        }
        if matches!(self.capture, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::invalid("fixed initial cgroup capture", "original failure retained"))
        }
    }

    fn take_validated_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        if self.closed.is_some() || !matches!(self.capture, Some(Ok(()))) {
            return None;
        }
        self.original.take_validated_pair()
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.root_open { return Some(cause); }
        if let Some(Err(cause)) = &self.capture { return Some(cause); }
        self.closed.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

macro_rules! fixed_running_initial_cgroup {
    ($name:ident, $role:ident, $description:literal) => {
        #[doc = $description]
        ///
        /// The fixed hierarchy, child and four active-file probes remain owned
        /// on failure. At most six FDs are retained. This supplies kernel DATA;
        /// PID1/service admission, process membership and funding stay external.
        #[derive(Debug, Default)]
        pub struct $name {
            original: FixedRunningServiceCgroupCaptureV1,
        }

        impl $name {
            /// Creates empty native slots without observing or opening anything.
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            /// Opens only the compiled hierarchy and fixed running-service role.
            ///
            /// # Errors
            /// Retains the whole root-open/capture Result and every partial
            /// object. Reentry performs no native observation or acquisition.
            pub fn capture_once(&mut self) -> Result<()> {
                self.original.capture_once(InitialServiceCgroupV1::$role)
            }

            /// Moves the complete validated root/child pair once without IO.
            ///
            /// Failed, repeated, incomplete or previously transferred attempts
            /// return `None`; no decoded marker constructs kernel objects.
            #[must_use]
            pub fn take_validated_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
                self.original.take_validated_pair()
            }

            /// Borrows the original first failure without another observation.
            #[must_use]
            pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.original.failure()
            }
        }
    };
}

fixed_running_initial_cgroup!(
    StorageRecoveryControlCgroupReadbackV1, StorageControl,
    "Retains only the compiled ordinary Storage remnant-parent directory."
);

impl StorageRecoveryControlCgroupReadbackV1 {
    /// Counts the fixed hierarchy, control-slice components and active names.
    ///
    /// The filesystem root and each hierarchy/control path component occur
    /// once. Two cgroup.procs names cover the root and selected control parent;
    /// repeated probes and native Result fields add no namespace entries.
    #[must_use]
    pub fn receiving_namespace_entries_v1() -> usize {
        Path::new("/sys/fs/cgroup").components().count()
            + InitialServiceCgroupV1::StorageControl.relative().components().count()
            + 2
    }
}

fixed_running_initial_cgroup!(
    RuntimeBootPreparationInitialCgroupReadbackV1, RuntimeBootPreparation,
    "Retains only the fixed BootPreparation publisher cgroup and native probes."
);

fixed_running_initial_cgroup!(
    SourceSignerInitialCgroupReadbackV1, SourceSigner,
    "Retains the fixed running Source signer hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    CacheSignerInitialCgroupReadbackV1, CacheSigner,
    "Retains the fixed running Cache signer hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    MountInitialCgroupReadbackV4, MountService,
    "Retains the fixed Parent04 Mount hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    NetworkInitialCgroupReadbackV4, NetworkService,
    "Retains the fixed Parent04 Network hierarchy, child and native probes."
);
// The main retains its own independently authenticated cgroup identity. This
// separate fixed capture supplies only the aggregate that must enclose main
// and both enrolled one-shot helpers under that same receiving original.
fixed_running_initial_cgroup!(
    NetworkReceivingAggregateCgroupReadbackV4, NetworkReceivingAggregate,
    "Retains the fixed Network aggregate hierarchy, directory and active probes."
);

impl NetworkReceivingAggregateCgroupReadbackV4 {
    /// Bounds the actual fixed capture layout, pathname backing and native peak.
    ///
    /// The six descriptors are the hierarchy and aggregate directories plus
    /// the same four active probes. Namespace entries name the hierarchy,
    /// each aggregate path component and the two actual cgroup.procs lookups;
    /// struct fields are not namespace entries. The hierarchy's root component
    /// is included, matching the fixed Root reader's namespace convention.
    /// This DATA supplies no service or worker grant.
    #[must_use]
    pub fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let aggregate = InitialServiceCgroupV1::NetworkReceivingAggregate.relative();
        let path_bytes = aggregate.as_os_str().as_encoded_bytes().len();
        let backing = path_bytes.checked_add(1)?.checked_mul(2)?
            .checked_add(2 * ("/sys/fs/cgroup".len() + 1))?
            .checked_add(4 * ("cgroup.procs".len() + 1))?;
        let names = Path::new("/sys/fs/cgroup").components().count()
            .checked_add(aggregate.components().count())?
            .checked_add(2)?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(backing)?, 6, names))
    }
}

fixed_running_initial_cgroup!(
    OwnershipInitialCgroupReadbackV1, Ownership,
    "Retains the fixed running Ownership hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    ControllerInitialCgroupReadbackV1, Controller,
    "Retains the fixed running Controller hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    StorageInitialCgroupReadbackV1, Storage,
    "Retains the fixed running Storage hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    StorageReceivingAggregateCgroupReadbackV1, StorageReceivingAggregate,
    "Retains the selected Storage aggregate hierarchy, child and native probes."
);
fixed_running_initial_cgroup!(
    RootInitialCgroupReadbackV1, Root,
    "Retains the fixed running Root hierarchy, child and native probes."
);

impl RootInitialCgroupReadbackV1 {
    /// Bounds the fixed Root hierarchy, service path and active-file names.
    ///
    /// The hierarchy includes its filesystem root and three named components.
    /// Each fixed Root role component and the two `cgroup.procs` entries are
    /// counted once; repeated probes and retained identities add no names.
    /// This performs no IO and grants no acquisition or namespace authority.
    #[must_use]
    pub fn receiving_namespace_entries_v1() -> usize {
        Path::new("/sys/fs/cgroup").components().count()
            + InitialServiceCgroupV1::Root.relative().components().count()
            + 2
    }
}


fixed_running_initial_cgroup!(
    HostPhase0TargetCgroupReadbackV2, HostPhase0Target,
    "Retains only the fixed Host phase-0 target cgroup and native probes."
);

impl HostPhase0TargetCgroupReadbackV2 {
    /// Bounds the shared fixed capture, six FDs and actual path/active names.
    ///
    /// This passive layout neither selects a loaded unit's cgroup nor grants
    /// process, service or receiving authority. Repeated probes reuse names.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let relative = InitialServiceCgroupV1::HostPhase0Target.relative();
        let backing = relative.as_os_str().as_encoded_bytes().len()
            .checked_add(1)?.checked_mul(2)?
            .checked_add(2 * ("/sys/fs/cgroup".len() + 1))?
            .checked_add(4 * ("cgroup.procs".len() + 1))?;
        let names = Path::new("/sys/fs/cgroup").components().count()
            .checked_add(relative.components().count())?.checked_add(2)?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(backing)?, 6, names))
    }
}


// Selected Controller startup first compares the actual unique PID1 snapshot
// ControlGroup with this compiled role. Host's main unit has no Slice override;
// its inspector's control-slice setting must never select the Host recipe.
fixed_running_initial_cgroup!(
    ControllerStartupHostCgroupReadbackV1, ControllerStartupHost,
    "Retains the selected Controller startup Host cgroup and native probes."
);
fixed_running_initial_cgroup!(
    ControllerStartupMountCgroupReadbackV1, ControllerStartupMount,
    "Retains the selected Controller startup Mount cgroup and native probes."
);

// The selected Publisher receiver first joins this exact PID1 ControlGroup
// with the actual main PID and credential-pinned UID/GID. This facade supplies
// only retained native DATA through the same shared capture engine.
fixed_running_initial_cgroup!(
    ControllerPublisherCgroupReadbackV1, ControllerPublisher,
    "Retains the selected Controller Publisher cgroup and native probes."
);

impl InitialServiceCgroupCaptureV1 {
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
    fn capture_initial(&mut self, original_root_candidate: OwnedFd, role: InitialServiceCgroupV1) -> Result<()> {
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
            .resolve_initial_service_retaining(&mut self.child, role)?;

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
    owner_kernel_id: u64,
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
    /// Compares this retained events original with its actual cgroup anchor.
    ///
    /// This passive join neither refreshes names nor proves empty population.
    /// Both original descriptors remain owned by their existing typed holders.
    ///
    /// # Errors
    /// Refuses a monitor opened from a different retained cgroup lifetime.
    pub fn require_same_cgroup(&self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.owner_kernel_id == 0 || self.owner_kernel_id != anchor.kernel_id {
            return Err(Error::invalid("cgroup population original", "different retained cgroup"));
        }
        Ok(())
    }

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

macro_rules! population_monitor_step {
    (Local, active, $anchor:ident, $probe:ident) => {
        $anchor.validate_active()?;
    };
    (Retained, active, $anchor:ident, $probe:ident) => {
        $anchor.validate_active_retaining($probe)?;
    };
    (Local, events, $anchor:ident, $pending:ident, $events:ident) => {
        let opened = $anchor.root.open_regular(Path::new("cgroup.events"))?;
        let $events = File::from(opened.into_owned_fd());
    };
    (Retained, events, $anchor:ident, $pending:ident, $events:ident) => {
        $anchor.root.open_regular_retaining(Path::new("cgroup.events"), $pending)?;
        let Some($events) = $pending.take_readable_file() else { std::process::abort() };
    };
}

macro_rules! population_monitor_recipe {
    ($anchor:ident, $disposition:ident, $probe:ident, $pending:ident) => {{
        population_monitor_step!($disposition, active, $anchor, $probe);
        population_monitor_step!($disposition, events, $anchor, $pending, events);
        Ok(CgroupPopulationMonitor { events, owner_kernel_id: $anchor.kernel_id })
    }};
}

// Both dispositions keep the exact active/open/read/length/parse order. Only
// the destination of each actual descriptor, bytes and returned error differs.
macro_rules! freezer_step {
    (Local, active, $anchor:ident, $original:ident) => { $anchor.validate_active()?; };
    (Retained, active, $anchor:ident, $original:ident) => {
        $original.active = Some($anchor.validate_active_retaining(&mut $original.probe));
        if !matches!($original.active, Some(Ok(()))) { return Err(retained_native::closed()); }
    };
    (Local, open, $anchor:ident, $original:ident, $events:ident) => {
        let $events = $anchor.root.open_regular(Path::new("cgroup.events"))?;
    };
    (Retained, open, $anchor:ident, $original:ident, $events:ident) => {
        $original.opened = Some($anchor.root.open_regular_retaining(Path::new("cgroup.events"), &mut $original.events));
        if !matches!($original.opened, Some(Ok(()))) { return Err(retained_native::closed()); }
        $original.file = $original.events.take_readable_file();
    };
    (Local, buffer, $original:ident, $bytes:ident) => { let mut $bytes = [0_u8; 4097]; };
    (Retained, buffer, $original:ident, $bytes:ident) => {};
    (Local, limit, $original:ident, $bytes:ident) => { $bytes.len() };
    (Retained, limit, $original:ident, $bytes:ident) => { $original.bytes.len() };
    (Local, read, $original:ident, $events:ident, $bytes:ident) => {
        File::from($events.into_owned_fd()).read_at(&mut $bytes, 0)
            .map_err(|source| Error::Syscall { operation: "read cgroup.events", source })?
    };
    (Retained, read, $original:ident, $events:ident, $bytes:ident) => {{
        $original.read = Some($original.file.as_ref().ok_or_else(retained_native::closed)?
            .read_at(&mut $original.bytes, 0));
        match $original.read.as_ref() {
            Some(Ok(length)) => *length,
            _ => return Err(retained_native::closed()),
        }
    }};
    (Local, bytes, $original:ident, $bytes:ident, $length:ident) => { &$bytes[..$length] };
    (Retained, bytes, $original:ident, $bytes:ident, $length:ident) => { &$original.bytes[..$length] };
}

macro_rules! freezer_recipe {
    ($anchor:ident, $mode:ident, $original:ident) => {{
        freezer_step!($mode, active, $anchor, $original);
        freezer_step!($mode, open, $anchor, $original, events);
        freezer_step!($mode, buffer, $original, bytes);
        let length = freezer_step!($mode, read, $original, events, bytes);
        if length == 0 || length == freezer_step!($mode, limit, $original, bytes) {
            return Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "freezer record is empty or oversized".to_owned(),
            });
        }
        parse_freezer_state(freezer_step!($mode, bytes, $original, bytes, length))
    }};
}

// The consuming arm keeps the old control descriptor's lexical lifetime.
// The retained arm parks the same open before its first validation or write.
macro_rules! freezer_request_step {
    (Local, active, $anchor:ident, $original:ident) => { $anchor.validate_active()? };
    (Retained, active, $anchor:ident, $original:ident) => {{
        $original.active = Some($anchor.validate_active_retaining(&mut $original.probe));
        if !matches!($original.active, Some(Ok(()))) {
            return Err(freezer_request::closed());
        }
    }};
    (Local, open, $original:ident, $expression:expr) => { $expression? };
    (Retained, open, $original:ident, $expression:expr) => {{
        $original.opened = Some($expression);
        match $original.opened.as_ref() {
            Some(Ok(file)) => file,
            _ => return Err(freezer_request::closed()),
        }
    }};
    (Local, native, $original:ident, $field:ident, $expression:expr) => { $expression? };
    (Retained, native, $original:ident, $field:ident, $expression:expr) => {{
        $original.$field = Some($expression);
        match $original.$field.as_ref() {
            Some(Ok(value)) => *value,
            _ => return Err(freezer_request::closed()),
        }
    }};
    (Local, write, $original:ident, $gate:ident, $expression:expr) => { $expression };
    (Retained, write, $original:ident, $gate:ident, $expression:expr) => {{
        freezer_request::FreezerRequestOriginalV2::require_write_once_v2(
            &mut $original.write_attempts, &mut $original.write_gate, &mut $gate,
        )?;
        // EINTR remains the original retry. It creates no new descriptor or
        // owning buffer; the terminal result and actual control stay held.
        $original.write = Some($expression);
        match $original.write.as_ref() {
            Some(Ok(written)) => Ok(*written),
            Some(Err(error)) => Err(*error),
            None => return Err(freezer_request::closed()),
        }
    }};
}

macro_rules! freezer_request_recipe {
    ($anchor:ident, $state:ident, $mode:ident, $original:ident, $gate:ident) => {{
        freezer_request_step!($mode, active, $anchor, $original);
        let freezer = freezer_request_step!($mode, open, $original, rustix::fs::openat(
            $anchor.root.as_fd(),
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
        }));
        if freezer_request_step!($mode, native, $original, filesystem, uapi::filesystem_type(freezer.as_fd())) != CGROUP2_SUPER_MAGIC
            || freezer_request_step!($mode, native, $original, metadata, uapi::fstat(freezer.as_fd())).st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(Error::WrongDescriptorType {
                expected: "cgroup-v2 freezer control",
            });
        }
        let mut remaining: &[u8] = match $state {
            CgroupFreezerState::Thawed => b"0\n",
            CgroupFreezerState::Frozen => b"1\n",
        };
        while !remaining.is_empty() {
            match freezer_request_step!($mode, write, $original, $gate, rustix::io::write(&freezer, remaining)) {
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
    }};
}

mod freezer_request;
pub use freezer_request::FreezerRequestOriginalV2;

mod retained_native;
pub use retained_native::{CgroupRootOriginalV2, CgroupChildOriginalV2, FreezerReadOriginalV2};

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
        validate_descendant_hint(relative_hint)?;
        self.resolve_child(relative_hint)
    }

    /// Opens a repeatable population monitor for this exact cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained cgroup is stale or its kernel events
    /// file cannot be securely opened.
    pub fn population_monitor(&self) -> Result<CgroupPopulationMonitor> {
        population_monitor_recipe!(self, Local, unused, unused)
    }

    /// Reads the kernel-confirmed freezer state of this exact cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained cgroup is stale, its bounded
    /// `cgroup.events` record cannot be read, or the record omits a canonical
    /// `frozen` field.
    pub fn freezer_state(&self) -> Result<CgroupFreezerState> {
        freezer_recipe!(self, Local, unused)
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
        freezer_request_recipe!(self, state, Local, unused, unused)
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
        kill_attempt::write_control(&kill, &mut current, &mut kill_attempt::LocalWrite)
    }

    fn open_kill_control(&self) -> Result<OwnedFd> {
        kill_attempt::open_local(self)
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
        membership_readback::observe_exact(self, process, &mut membership_readback::LocalMembership)
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

    fn population_monitor_retaining(
        &self,
        probe: &mut PendingRegularFileV1,
        pending: &mut PendingRegularFileV1,
    ) -> Result<CgroupPopulationMonitor> {
        population_monitor_recipe!(self, Retained, probe, pending)
    }

    fn resolve_worker_descendant_retaining(
        &self,
        relative: &Path,
        pending: &mut InitialCgroupChildV5,
    ) -> Result<()> {
        validate_descendant_hint(relative)?;
        resolve_child_recipe!(self, relative, Retained, pending)
    }

    fn resolve_initial_service_retaining(
        &self,
        pending: &mut InitialCgroupChildV5,
        role: InitialServiceCgroupV1,
    ) -> Result<()> {
        let relative = role.relative();
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
    membership_readback::recheck_process(process, before, &mut membership_readback::LocalMembership)
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
        assert!(!original.original.attempted);
        assert!(!original.original.complete);
    }

    #[test]
    fn interrupted_initial_cgroup_remains_closed() {
        let mut original = NixOfflineInitialCgroupReadbackV5::default();
        original.original.attempted = true;

        assert!(original.take_validated_pair().is_none());
        assert!(original.original.attempted);
        assert!(!original.original.complete);
    }

    #[test]
    fn completion_marker_alone_cannot_transfer_kernel_objects() {
        let mut original = NixOfflineInitialCgroupReadbackV5::default();
        original.original.attempted = true;
        original.original.complete = true;

        assert!(original.take_validated_pair().is_none());
        assert!(original.original.root.is_none());
        assert!(original.original.child.anchor.is_none());
    }

    #[test]
    fn failed_fixed_root_validation_retains_original_directory_through_reentry() {
        use std::os::unix::fs::MetadataExt as _;
        use super::{InitialServiceCgroupCaptureV1, InitialServiceCgroupV1};

        let first = tempfile::tempdir().unwrap();
        let replacement = tempfile::tempdir().unwrap();
        let identity = first.path().metadata().unwrap();
        let mut original = InitialServiceCgroupCaptureV1::default();
        let cause = original.capture_initial(
            std::fs::File::open(first.path()).unwrap().into(),
            InitialServiceCgroupV1::Controller,
        );

        assert!(matches!(cause, Err(crate::Error::WrongDescriptorType { .. })));
        assert!(original.take_validated_pair().is_none());
        let retained = original.hierarchy_candidate.as_ref().unwrap();
        let stat = rustix::fs::fstat(retained.as_fd()).unwrap();
        assert_eq!((stat.st_dev, stat.st_ino), (identity.dev(), identity.ino()));

        assert!(original.capture_initial(
            std::fs::File::open(replacement.path()).unwrap().into(),
            InitialServiceCgroupV1::Storage,
        ).is_err());
        let retained = original.hierarchy_candidate.as_ref().unwrap();
        let stat = rustix::fs::fstat(retained.as_fd()).unwrap();
        assert_eq!((stat.st_dev, stat.st_ino), (identity.dev(), identity.ino()));
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

#[cfg(test)]
mod positive_named_settlement_tests {
    use super::*;

    #[test]
    fn incomplete_and_failed_native_readers_cannot_settle_partial_owners() {
        let mut controls = CgroupLimitReadbackV1::default();
        assert!(controls.settle_positive_named_verifications_v1().is_err());
        controls.phase = LimitReadbackPhaseV1::Checking;
        assert!(controls.settle_positive_named_verifications_v1().is_err());
        controls.failure = Some(Error::invalid("actual read", "retained failure"));
        let original = controls.failure().unwrap() as *const Error;
        assert!(controls.settle_positive_named_verifications_v1().is_err());
        assert_eq!(controls.failure().unwrap() as *const Error, original);

        let mut cpu = FirstGlobalCpuReadbackV1::default();
        assert!(cpu.settle_positive_named_verifications_v1().is_err());
        cpu.failure = Some(Error::invalid("actual CPU read", "retained failure"));
        let original = cpu.failure().unwrap() as *const Error;
        assert!(cpu.settle_positive_named_verifications_v1().is_err());
        assert_eq!(cpu.failure().unwrap() as *const Error, original);
    }
}

fn validate_descendant_hint(relative_hint: &Path) -> Result<()> {
    if relative_hint.as_os_str().len() > MAXIMUM_DESCENDANT_HINT_BYTES
        || !relative_hint.components().any(|part| matches!(part, Component::Normal(_)))
    {
        return Err(Error::invalid(
            "descendant cgroup hint",
            "must name a proper descendant within the 4096-byte limit",
        ));
    }
    Ok(())
}

mod worker_opening;
pub use worker_opening::{WorkerCgroupOpeningRefusalV1, WorkerCgroupOpeningV1};

mod population_monitor;
pub use population_monitor::CgroupPopulationMonitorOriginalV3;

mod worker_aggregate;
pub use worker_aggregate::StorageWorkerAggregateReadbackV1;

mod storage_layout;
pub use storage_layout::StorageCgroupLayoutV1;

mod kill_attempt;
pub use kill_attempt::{CgroupKillAttemptV1, CgroupKillRefusalV1};

#[cfg(test)]
mod retained_limit_active_tests {
    use super::*;

    #[test]
    fn complete_initial_boundary_probes_retire_before_the_next_native_interval() {
        let descriptor = rustix::fs::open("/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let root = CgroupV2Root::from_owned(descriptor).unwrap();
        let mut reader = CgroupLimitReadbackV1::default();
        // Like the existing boundary test, this isolates actual active probes
        // from the host kernel's independently closed controller grammar.
        reader.retain_active = true;
        reader.validate_boundary_active(&root.anchor, 0).unwrap();
        reader.validate_boundary_active(&root.anchor, 1).unwrap();
        reader.phase = LimitReadbackPhaseV1::Ready;
        let identities = [reader.active_probes[0].file().unwrap().identity(),
            reader.active_probes[1].file().unwrap().identity()];

        reader.retire_initial_active_files_once_v4().unwrap();

        assert_eq!(reader.initial_active_disposed, Some(identities));
        assert!(reader.active_probes[..2].iter().all(|probe| probe.file().is_err()));
        assert!(uapi::fstat(root.anchor.as_fd()).is_ok());
        assert!(reader.retire_initial_active_files_once_v4().is_err());
        assert!(reader.final_active_disposed.is_none());
        let mut fresh = CgroupLimitReadbackV1::default();
        assert!(fresh.recheck_after_initial_disposal_v4(&root.anchor).is_err());
        assert!(fresh.active_probes.iter().all(|probe| probe.file().is_err()));
    }

    #[test]
    fn failed_final_anchor_keeps_actual_completed_initial_active_probes() {
        let descriptor = rustix::fs::open("/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let root = CgroupV2Root::from_owned(descriptor).unwrap();
        let mut reader = CgroupLimitReadbackV1::default();
        // This test isolates the boundary probes from the host's controller
        // vocabulary. A newer kernel may advertise controllers outside this
        // reader's closed control grammar before the final-anchor frontier.
        reader.retain_active = true;
        reader.validate_boundary_active(&root.anchor, 0).unwrap();
        reader.validate_boundary_active(&root.anchor, 1).unwrap();
        reader.phase = LimitReadbackPhaseV1::Ready;
        assert!(reader.active_probes[..2].iter().all(|probe| probe.file().is_ok()));

        let directory = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(directory.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let ordinary = BeneathRoot::from_owned(descriptor).unwrap();
        let invalid = RetainedCgroupAnchor { kernel_id: ordinary.identity().inode, root: ordinary };
        assert!(reader.recheck(&invalid).is_err());
        let first = reader.failure().unwrap() as *const Error;

        assert!(reader.settle_positive_named_verifications_v1().is_err());
        assert!(!reader.completed_files_are_disposable_v4());
        assert!(reader.retire_completed_files_once_v4().is_err());
        assert!(!reader.native_files_are_disposed_v4());
        assert_eq!(reader.failure().unwrap() as *const Error, first);
        assert!(reader.active_probes[..2].iter().all(|probe|
            probe.file().is_ok_and(|file| uapi::fstat(file.as_fd()).is_ok())));
        assert!(reader.recheck(&root.anchor).is_err());
        assert_eq!(reader.failure().unwrap() as *const Error, first);
    }
}
