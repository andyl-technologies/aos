//! Joins an actual donated Network control OFD to its canonical anchor/name.
//!
//! These retained native observations are DATA. The genuine PID1 child factory
//! separately authenticates the Source, child, original fee and physical roles.
//! This module cannot install limits, create an account or grant an effect.

use super::*;

/// Selects one literal native control name without granting a resource role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkChildControlKindV2 {
    /// Selects the finite memory.max record.
    MemoryMax,
    /// Selects the finite pids.max record.
    PidsMax,
    /// Selects the finite cpu.max quota and period.
    CpuMax,
}

/// Reports only finite native comparison DATA from the same actual control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkChildControlValueV2 {
    /// Reports the actual finite memory or task count.
    Scalar(u64),
    /// Reports the actual finite quota and its period in microseconds.
    Cpu {
        /// Captured CPU quota in microseconds.
        quota: u64,
        /// Captured CPU period in microseconds.
        period: u64,
    },
}

#[derive(Clone, Copy)]
enum First { Order, Input, Before, Cloexec, Stat, Filesystem, Flags, Canonical,
    CanonicalStat, Identity, Scalar, After }

/// Retains one donated native control and all canonical joining prefixes.
#[derive(Default)]
pub struct NetworkChildControlDonationOriginalV2 {
    entered: bool,
    kind: Option<NetworkChildControlKindV2>,
    donated: Option<File>,
    before: CgroupActiveOriginalV2,
    before_result: Option<Result<()>>,
    cloexec: Option<Result<bool>>,
    stat: Option<Result<libc::stat>>,
    filesystem: Option<Result<libc::c_long>>,
    flags: Option<Result<libc::c_int>>,
    named: LimitControlSlotV1,
    cpu: FirstGlobalCpuReadbackV1,
    canonical: Option<Result<()>>,
    canonical_stat: Option<Result<libc::stat>>,
    value: Option<NetworkChildControlValueV2>,
    after: CgroupActiveOriginalV2,
    after_result: Option<Result<()>>,
    first: Option<First>,
    closed: Option<Error>,
    retired_named: Option<[crate::path::FileIdentity; 2]>,
    proofs_retired: bool,
}

impl NetworkChildControlDonationOriginalV2 {
    /// Creates inert native destinations without opening or validating anything.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Joins the actual donation through the sole canonical native reader.
    ///
    /// Ownership moves before validation; refused reentry leaves a new input
    /// slot untouched. Its independently owed active after still runs after
    /// any reached before, donated descriptor or canonical read failure.
    ///
    /// # Errors
    /// Retains wrong input, native type/flag/filesystem failures, stale cgroup,
    /// different named object, malformed or nonfinite record and repeated entry.
    pub fn capture_once_v2(&mut self, input: &mut Option<OwnedFd>,
        anchor: &RetainedCgroupAnchor, kind: NetworkChildControlKindV2) -> Result<()>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        self.kind = Some(kind);
        let Some(input) = input.take() else { return self.refuse(First::Input); };
        self.donated = Some(File::from(input));
        self.before_result = Some(self.before.capture_once_v2(anchor));
        if matches!(self.before_result, Some(Ok(()))) {
            let _ = self.capture_inner(anchor, kind);
        } else { self.first = Some(First::Before); }

        self.after_result = Some(self.after.capture_once_v2(anchor));
        if !matches!(self.after_result, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        if self.first.is_some() { Err(closed()) } else { Ok(()) }
    }

    fn capture_inner(&mut self, anchor: &RetainedCgroupAnchor,
        kind: NetworkChildControlKindV2) -> Result<()>
    {
        let Some(donated) = self.donated.as_ref() else { return self.refuse(First::Input); };
        self.cloexec = Some(aos_linux_descriptors::native::is_cloexec(donated.as_fd()));
        if !matches!(self.cloexec, Some(Ok(true))) { return self.refuse(First::Cloexec); }
        self.stat = Some(uapi::fstat(donated.as_fd()));
        let Some(Ok(stat)) = self.stat.as_ref() else { return self.refuse(First::Stat); };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_ino == 0 { return self.refuse(First::Input); }
        self.filesystem = Some(uapi::filesystem_type(donated.as_fd()));
        if !matches!(self.filesystem, Some(Ok(CGROUP2_SUPER_MAGIC))) { return self.refuse(First::Filesystem); }
        self.flags = Some(aos_linux_descriptors::native::get_status_flags(donated.as_fd()));
        let Some(Ok(flags)) = self.flags.as_ref() else { return self.refuse(First::Flags); };
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 { return self.refuse(First::Input); }

        let control = match kind {
            NetworkChildControlKindV2::MemoryMax => Some(CgroupLimitControlV1::MemoryMax),
            NetworkChildControlKindV2::PidsMax => Some(CgroupLimitControlV1::PidsMax),
            NetworkChildControlKindV2::CpuMax => None,
        };
        self.canonical = Some(match control {
            Some(control) => capture_limit_control_slot_v1(anchor, control, &mut self.named),
            None => self.cpu.capture_retaining_v2(anchor),
        });
        if !matches!(self.canonical, Some(Ok(()))) { return self.refuse(First::Canonical); }
        let slot = match control { Some(_) => &self.named, None => &self.cpu.slot };
        let file = match slot.opening.file() { Ok(file) => file, Err(_) => return self.refuse(First::Canonical) };
        self.canonical_stat = Some(uapi::fstat(file.as_fd()));
        let Some(Ok(named)) = self.canonical_stat.as_ref() else { return self.refuse(First::CanonicalStat); };
        if named.st_dev != stat.st_dev || named.st_ino != stat.st_ino
            || named.st_mode & libc::S_IFMT != libc::S_IFREG { return self.refuse(First::Identity); }
        self.value = match control {
            Some(_) => slot.bytes[..slot.length].strip_suffix(b"\n")
                .and_then(parse_limit_decimal).filter(|value| *value != 0)
                .map(NetworkChildControlValueV2::Scalar),
            None => self.cpu.quota_and_period().map(|(quota, period)| {
                NetworkChildControlValueV2::Cpu { quota, period }
            }),
        };
        if self.value.is_none() { return self.refuse(First::Scalar); }
        Ok(())
    }

    fn refuse(&mut self, cause: First) -> Result<()> {
        self.first.get_or_insert(cause);
        self.closed.get_or_insert_with(closed);
        Err(closed())
    }

    /// Borrows finite native DATA only after the complete actual donation join.
    #[must_use]
    pub fn value_data_v2(&self) -> Option<NetworkChildControlValueV2> {
        if self.first.is_some() || !matches!(self.after_result, Some(Ok(()))) { return None; }
        self.value
    }

    /// Retires only complete canonical-name and active proof temporaries.
    ///
    /// The donated control OFD, original bytes, native stat identities, parsed
    /// value and every once fence remain owned. No debt or limit is changed.
    ///
    /// # Errors
    /// Refuses any partial, failed or already retired donation join.
    pub fn retire_positive_proofs_once_v2(&mut self) -> Result<()> {
        if self.proofs_retired || self.first.is_some() || self.value.is_none()
            || self.donated.is_none() || !matches!(self.after_result, Some(Ok(()))) {
            return Err(closed());
        }
        match self.kind {
            Some(NetworkChildControlKindV2::CpuMax) => self.cpu.retire_positive_initial_files_once_v2()?,
            Some(_) => {
                let identities = [self.named.opening.file()?.identity(), self.named.bookend.file()?.identity()];
                drop(self.named.opening.take_readable_file());
                drop(self.named.bookend.take_readable_file());
                self.retired_named = Some(identities);
            }
            None => return Err(closed()),
        }
        self.before.retire_positive_file_once_v2()?;
        self.after.retire_positive_file_once_v2()?;
        self.proofs_retired = true;
        Ok(())
    }

    /// Borrows the first actual native cause without sampling or replacing it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native = match self.first? {
            First::Before => self.before.failure(),
            First::Cloexec => self.cloexec.as_ref()?.as_ref().err(),
            First::Stat => self.stat.as_ref()?.as_ref().err(),
            First::Filesystem => self.filesystem.as_ref()?.as_ref().err(),
            First::Flags => self.flags.as_ref()?.as_ref().err(),
            First::Canonical => self.cpu.failure()
                .or_else(|| self.canonical.as_ref()?.as_ref().err()),
            First::CanonicalStat => self.canonical_stat.as_ref()?.as_ref().err(),
            First::After => self.after.failure(),
            First::Order | First::Input | First::Identity | First::Scalar => None,
        };
        native.or(self.closed.as_ref()).map(|cause| cause as _)
    }

    /// Prices actual native joining beyond the already-paid donated descriptor.
    #[must_use]
    pub fn receiving_obligations_data_v2(kind: NetworkChildControlKindV2)
        -> Option<(usize, usize, usize)>
    {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let cpu = match kind {
            NetworkChildControlKindV2::CpuMax => FirstGlobalCpuReadbackV1::retained_initial_obligations_v2()?,
            _ => (0, 2, 1),
        };
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(active.0.checked_mul(2)?)?.checked_add(cpu.0)?.checked_add(4 * 256)?;
        Some((bytes, active.1.checked_mul(2)?.checked_add(cpu.1)?,
            active.2.checked_mul(2)?.checked_add(cpu.2)?))
    }
}

fn closed() -> Error {
    Error::invalid("Network child control donation", "the original native control join is closed")
}
