//! Shares the fixed FD6/7/4 custody recipe with retained installed startup.

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use rustix::fs::{FileType, SealFlags, fcntl_get_seals, fstat};

use crate::cgroup::{
    CgroupChildOriginalV2, CgroupRootOriginalV2, CgroupV2Root, ExactCgroupMembershipReadbackV1,
    RetainedCgroupAnchor,
};
use crate::immutable_file::{SealedMemfdMapping, SealedMemfdReadOriginalV2};
use crate::pidfd::{PidFd, PidFdOpenAttemptV1};
use crate::{Error, Result};

use super::{
    GUEST_CGROUP_CUSTODY_BYTES, GUEST_CGROUP_CUSTODY_FD, GUEST_PAYLOAD_CGROUP_FD,
    GuestPayloadCgroupCustodyV1, require_carrier,
};

/// Retains the original fixed startup descriptors before native validation.
pub struct GuestPayloadCgroupCustodyOriginalV2 {
    owner: Option<Box<crate::guest_confinement::GuestOwnerOriginalV2>>,
    parent: Option<Box<super::agent_parent::AgentParentOriginalV1>>,
    raw: [Option<Result<OwnedFd>>; 3],
    seals: Option<rustix::io::Result<SealFlags>>,
    stat: [Option<rustix::io::Result<rustix::fs::Stat>>; 2],
    sealed: SealedMemfdReadOriginalV2,
    root: CgroupRootOriginalV2,
    root_output: Option<CgroupV2Root>,
    child: CgroupChildOriginalV2,
    payload: Option<RetainedCgroupAnchor>,
    pidfd: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    membership: ExactCgroupMembershipReadbackV1,
    body: Option<Result<()>>,
    reentry: Option<Error>,
}

impl Default for GuestPayloadCgroupCustodyOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestPayloadCgroupCustodyOriginalV2 {
    /// Creates inert fixed storage before duplicating any inherited descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: None,
            parent: None,
            raw: std::array::from_fn(|_| None),
            seals: None,
            stat: [None, None],
            sealed: SealedMemfdReadOriginalV2::new(),
            root: CgroupRootOriginalV2::new(),
            root_output: None,
            child: CgroupChildOriginalV2::new(),
            payload: None,
            pidfd: PidFdOpenAttemptV1::new(),
            process: None,
            membership: ExactCgroupMembershipReadbackV1::new(),
            body: None,
            reentry: None,
        }
    }

    /// Runs the sole fixed custody engine while preserving every reached owner.
    ///
    /// # Errors
    /// Refuses foreign Owner context, missing/changed FD6/7/4, unsealed or
    /// mismatched carrier, wrong native root/membership, or repeated entry.
    pub fn capture_once_v2(&mut self) -> Result<()> {
        if self.body.is_some() {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.body = Some(self.capture(true, None));
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    pub(super) fn ordinary() -> Result<GuestPayloadCgroupCustodyV1> {
        let mut original = Self::new();
        original.capture(false, None)?;
        original.take_payload()
    }

    pub(super) fn capture_agent_once(
        &mut self,
        record: super::handoff::TopologyRecordV1,
    ) -> Result<()> {
        if self.body.is_some() {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.body = Some(self.capture(true, Some(record)));
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn capture(
        &mut self,
        retained: bool,
        record: Option<super::handoff::TopologyRecordV1>,
    ) -> Result<()> {
        if retained {
            super::require_owner_retaining(&mut self.owner)?;
        } else {
            crate::guest_confinement::require_guest_owner()?;
        }
        for (index, number) in [GUEST_PAYLOAD_CGROUP_FD, GUEST_CGROUP_CUSTODY_FD, 4]
            .into_iter()
            .enumerate()
        {
            self.raw[index] = Some(crate::inherited_fd::duplicate_inherited_descriptor(number));
            if !matches!(self.raw[index], Some(Ok(_))) {
                return match self.raw[index].take() {
                    Some(Err(error)) if !retained => Err(error),
                    other => {
                        self.raw[index] = other;
                        Err(closed())
                    }
                };
            }
        }
        let provisioning = self.file(2)?;
        self.seals = Some(fcntl_get_seals(provisioning));
        match self.seals.as_ref() {
            Some(Ok(seals))
                if seals.contains(
                    SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
                ) => {}
            Some(Err(source)) => return Err(io("read original Guest provisioning seals", *source)),
            _ => {
                return Err(Error::invalid(
                    "Guest cgroup custody",
                    "original provisioning is not fully sealed",
                ));
            }
        }
        self.stat[0] = Some(fstat(self.file(2)?));
        let _ = stat(&self.stat[0], "stat original Guest provisioning")?;
        self.stat[1] = Some(fstat(self.file(0)?));
        let credential = stat(&self.stat[0], "stat original Guest provisioning")?;
        let directory = stat(&self.stat[1], "stat Guest payload cgroup")?;
        let expected = [
            credential.st_dev,
            credential.st_ino,
            credential.st_size as u64,
            directory.st_dev,
            directory.st_ino,
        ];
        let carrier = self.take_file(1)?;
        if retained {
            self.sealed
                .prepare_once(
                    carrier,
                    GUEST_CGROUP_CUSTODY_BYTES as u64,
                    GUEST_CGROUP_CUSTODY_BYTES as u64,
                )
                .map_err(|_| closed())?;
            self.sealed
                .with_bytes(|bytes, _| require_carrier(bytes, expected))
                .map_err(|_| closed())??;
        } else {
            SealedMemfdMapping::run(
                carrier,
                GUEST_CGROUP_CUSTODY_BYTES as u64,
                GUEST_CGROUP_CUSTODY_BYTES as u64,
                |bytes, _| require_carrier(bytes, expected),
            )
            .map_err(|_| {
                Error::invalid("Guest cgroup carrier", "sealed carrier is unavailable")
            })??;
        }
        let credential = stat(&self.stat[0], "stat original Guest provisioning")?;
        let directory = stat(&self.stat[1], "stat Guest payload cgroup")?;
        if FileType::from_raw_mode(credential.st_mode) != FileType::RegularFile
            || credential.st_size != 258
            || directory.st_uid != 0
            || directory.st_mode & 0o022 != 0
        {
            return Err(Error::invalid(
                "Guest cgroup custody",
                "original descriptor profile differs",
            ));
        }
        let payload = self.take_file(0)?;
        if retained {
            self.root.admit_once(payload)?;
            self.root_output = self.root.take_completed_once();
            self.child.resolve_once(
                self.root_output.as_ref().ok_or_else(closed)?,
                Path::new("."),
            )?;
            self.payload = self.child.take_completed_once();
        } else {
            self.payload = Some(CgroupV2Root::from_owned(payload)?.resolve(Path::new("."))?);
        }
        let payload = self.payload.as_ref().ok_or_else(closed)?;
        crate::guest_confinement::require_guest_cgroup_object(payload.as_fd())?;
        let pid = NonZeroU32::new(std::process::id())
            .ok_or_else(|| Error::invalid("Guest owner", "PID is zero"))?;
        if retained {
            self.pidfd.capture_once(pid).map_err(|_| closed())?;
            self.process = self.pidfd.take_validated();
            if let Some(record) = record {
                self.parent = Some(Box::new(super::agent_parent::AgentParentOriginalV1::new()));
                self.parent.as_mut().ok_or_else(closed)?.capture_once(
                    payload,
                    stat(&self.stat[0], "stat original Guest provisioning")?,
                    self.process.as_ref().ok_or_else(closed)?,
                    record,
                )?;
            } else {
                self.membership
                    .capture_once(payload, self.process.as_ref().ok_or_else(closed)?)
                    .map_err(|_| closed())?;
            }
        } else {
            payload.verify_exact_membership(&PidFd::open(pid)?)?;
        }
        Ok(())
    }

    fn file(&self, index: usize) -> Result<&OwnedFd> {
        self.raw[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(closed)
    }

    fn take_file(&mut self, index: usize) -> Result<OwnedFd> {
        match self.raw[index].take() {
            Some(result) => result,
            None => Err(closed()),
        }
    }

    fn take_payload(&mut self) -> Result<GuestPayloadCgroupCustodyV1> {
        let payload = self.payload.take().ok_or_else(closed)?;
        let provisioning = match self.raw[2].take() {
            Some(Ok(file)) => file,
            other => {
                self.payload = Some(payload);
                self.raw[2] = other;
                return Err(closed());
            }
        };
        Ok(GuestPayloadCgroupCustodyV1 {
            payload,
            provisioning,
        })
    }

    /// Moves only the same full-positive native payload custody once.
    ///
    /// Complete read-only originals may then physically retire; a failed
    /// mapping/root/member prefix never exposes or disposes its native owners.
    #[must_use]
    pub fn take_completed_once_v2(&mut self) -> Option<GuestPayloadCgroupCustodyV1> {
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return None;
        }
        self.take_payload().ok()
    }

    /// Borrows the chronological actual native/semantic source.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner
            .as_ref()
            .and_then(|original| original.failure())
            .or_else(|| {
                self.raw
                    .iter()
                    .find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _))
                    .or_else(|| self.sealed.failure())
                    .or_else(|| self.root.failure().map(|cause| cause as _))
                    .or_else(|| self.child.failure().map(|cause| cause as _))
                    .or_else(|| self.pidfd.failure().map(|cause| cause as _))
                    .or_else(|| self.membership.failure().map(|cause| cause as _))
                    .or_else(|| self.parent.as_ref().and_then(|original| original.failure()))
                    .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
                    .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            })
    }

    /// Prices the exact fixed inherited-file, mapping and native-root recipe.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let root = CgroupRootOriginalV2::receiving_obligations_v2()?;
        let child = CgroupChildOriginalV2::receiving_obligations_v2(1)?;
        let owner = crate::guest_confinement::GuestOwnerOriginalV2::receiving_obligations_v2()?;
        let parent = super::agent_parent::AgentParentOriginalV1::receiving_obligations_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(root.0)?
            .checked_add(child.0)?
            .checked_add(SealedMemfdReadOriginalV2::receiving_memory_bytes_v2()?)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(GUEST_CGROUP_CUSTODY_BYTES.checked_mul(2)?)?
            .checked_add(4 * 256)?
            .checked_add(owner.0)?
            .checked_add(parent.0)?;
        Some((
            bytes,
            root.1
                .checked_add(child.1)?
                .checked_add(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?
                .checked_add(3 + 1)?
                .checked_add(parent.1)?,
            (root.2.checked_add(child.2)?.checked_add(3)?)
                .checked_add(owner.2)?
                .checked_add(parent.2)?,
        ))
    }
}

fn stat<'a>(
    value: &'a Option<rustix::io::Result<rustix::fs::Stat>>,
    operation: &'static str,
) -> Result<&'a rustix::fs::Stat> {
    match value {
        Some(Ok(stat)) => Ok(stat),
        Some(Err(source)) => Err(io(operation, *source)),
        None => Err(closed()),
    }
}

fn io(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: source.into(),
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest inherited cgroup custody",
        "actual native original remains occupied",
    )
}
