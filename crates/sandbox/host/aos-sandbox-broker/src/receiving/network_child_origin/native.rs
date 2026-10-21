//! Joins actual authenticated PID1 child donations to the recipient itself.
//!
//! The native result is a necessary bootstrap fact, not a financial bank or
//! effect permission. The enclosing issuer must separately prove the complete
//! prepaid programme and its first actual ongoing Source response.

use super::*;
use std::fs::{File, Metadata};
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt as _;
use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor,
    RuntimeScopeCgroupOriginalV1, RuntimeScopeMembershipOriginalV1,
    NetworkChildControlDonationOriginalV2, NetworkChildControlKindV2 as Kind,
    NetworkChildControlValueV2 as Value, NetworkChildAggregateAncestryOriginalV2};
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::RuntimeScopeReceivedPidFdOriginalV1;
use aos_sandbox_linux::pidfd::PidFdOpenAttemptV1;
use aos_sandbox_linux::pidfd::PidFdOpenRefusalV1;
use aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1;

#[derive(Clone, Copy)]
enum First { Order, Donations, SourcePidFd, OwnPidFd, Cgroup(usize), Identity(usize),
    Coordinates, Membership(usize), Control(usize), Limits, Ancestry, Boot,
    ExecutableOpen, ExecutableMetadata, ExecutableShape, SourceAfter, OwnAfter,
    MembershipAfter(usize), ExecutableAfter, Retirement(usize) }

pub(super) struct NativeOriginalV2 {
    entered: bool,
    raw: [Option<OwnedFd>; 9],
    source_original: RuntimeScopeReceivedPidFdOriginalV1,
    source_result: Option<Result<(), aos_linux_descriptors::Error>>,
    source: Option<PidFd>,
    own_original: PidFdOpenAttemptV1,
    own_result: Option<Result<(), PidFdOpenRefusalV1>>,
    own: Option<PidFd>,
    cgroup_originals: [RuntimeScopeCgroupOriginalV1; 3],
    cgroup_results: [Option<Result<(), aos_linux_descriptors::Error>>; 3],
    cgroups: [Option<(CgroupV2Root, RetainedCgroupAnchor)>; 3],
    identities: [PidFdProcessIdentityOriginalV1; 2],
    identity_results: [Option<Result<(), aos_linux_descriptors::Error>>; 2],
    membership: [RuntimeScopeMembershipOriginalV1; 2],
    membership_results: [Option<Result<(), aos_linux_descriptors::Error>>; 2],
    controls: [NetworkChildControlDonationOriginalV2; 5],
    control_results: [Option<Result<(), aos_linux_descriptors::Error>>; 5],
    limits: Option<rustix::process::Rlimit>,
    ancestry: NetworkChildAggregateAncestryOriginalV2,
    ancestry_result: Option<Result<(), aos_linux_descriptors::Error>>,
    boot: RootOriginalKernelBootIdAttemptV1,
    executable: Option<Result<OwnedFd, rustix::io::Errno>>,
    executable_result: Option<Result<(), rustix::io::Errno>>,
    executable_file: Option<File>,
    executable_metadata: Option<std::io::Result<Metadata>>,
    source_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    own_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    membership_after: [RuntimeScopeMembershipOriginalV1; 2],
    membership_after_results: [Option<Result<(), aos_linux_descriptors::Error>>; 2],
    executable_after: Option<std::io::Result<Metadata>>,
    first: Option<First>,
    complete: bool,
    retirement: [Option<Result<(), aos_linux_descriptors::Error>>; 16],
    proofs_retired: bool,
}

impl NativeOriginalV2 {
    pub(super) fn held_source_for_owed_wait(&self, packet: &[u8]) -> Option<&PidFd> {
        // Cached actual identities, not decoded coordinates alone, establish
        // which held process is the original Netd and which is this recipient.
        for (index, offsets) in [[224, 232, 240], [248, 256, 264]].into_iter().enumerate() {
            if !matches!(self.identity_results[index], Some(Ok(()))) { return None; }
            let identity = self.identities[index].identity()?;
            let (_, anchor) = self.cgroups[index].as_ref()?;
            if read_u64(packet, offsets[0]) != Some(u64::from(identity.pid()))
                || read_u64(packet, offsets[1]) != Some(identity.start_time_ticks())
                || read_u64(packet, offsets[2]) != Some(anchor.kernel_id())
                || identity.thread_group_id() != identity.pid() || identity.parent_pid() != 1
                || identity.cgroup_id() != Some(anchor.kernel_id())
                || index == 1 && identity.pid() != std::process::id()
            { return None; }
        }
        self.own.as_ref()?;
        self.source.as_ref()
    }

    pub(super) fn held_source_pidfd(&self) -> Option<&PidFd> {
        self.source.as_ref()
    }

    pub(super) fn held_source_info(&self)
        -> Option<Result<aos_linux_descriptors::pidfd::PidFdInfo, aos_linux_descriptors::Error>>
    {
        self.source.as_ref().map(PidFd::info)
    }

    pub(super) fn completed(&self) -> bool { self.complete }

    pub(super) fn held_liveness(&self, index: usize) -> Option<Result<bool, aos_linux_descriptors::Error>> {
        match index { 0 => self.source.as_ref(), 1 => self.own.as_ref(), _ => None }
            .map(PidFd::is_alive)
    }

    pub(super) fn new() -> Self {
        Self { entered: false, raw: std::array::from_fn(|_| None),
            source_original: RuntimeScopeReceivedPidFdOriginalV1::new(), source_result: None, source: None,
            own_original: PidFdOpenAttemptV1::new(), own_result: None, own: None,
            cgroup_originals: std::array::from_fn(|_| RuntimeScopeCgroupOriginalV1::new()),
            cgroup_results: std::array::from_fn(|_| None), cgroups: std::array::from_fn(|_| None),
            identities: std::array::from_fn(|_| PidFdProcessIdentityOriginalV1::new()),
            identity_results: std::array::from_fn(|_| None),
            membership: std::array::from_fn(|_| RuntimeScopeMembershipOriginalV1::new()),
            membership_results: std::array::from_fn(|_| None),
            controls: std::array::from_fn(|_| NetworkChildControlDonationOriginalV2::new()),
            control_results: std::array::from_fn(|_| None), limits: None,
            ancestry: NetworkChildAggregateAncestryOriginalV2::new(), ancestry_result: None,
            boot: RootOriginalKernelBootIdAttemptV1::new(), executable: None, executable_result: None,
            executable_file: None, executable_metadata: None,
            source_after: None, own_after: None,
            membership_after: std::array::from_fn(|_| RuntimeScopeMembershipOriginalV1::new()),
            membership_after_results: std::array::from_fn(|_| None), executable_after: None,
            first: None, complete: false,
            retirement: std::array::from_fn(|_| None), proofs_retired: false }
    }

    pub(super) fn capture_once(&mut self, record: &mut ReceivedDescriptorRecord)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        let _ = self.capture_inner(record);

        // Each reached subject/control/executable has its own owed post.
        // An earlier wrong donation never suppresses another actual pin.
        if let Some(source) = self.source.as_ref() {
            self.source_after = Some(source.is_alive());
            if !matches!(self.source_after, Some(Ok(true))) { self.first.get_or_insert(First::SourceAfter); }
        }
        if let Some(own) = self.own.as_ref() {
            self.own_after = Some(own.is_alive());
            if !matches!(self.own_after, Some(Ok(true))) { self.first.get_or_insert(First::OwnAfter); }
        }
        for index in 0..2 {
            let process = if index == 0 { self.source.as_ref() } else { self.own.as_ref() };
            if let (Some(process), Some((_, anchor))) = (process, self.cgroups[index].as_ref()) {
                self.membership_after_results[index] = Some(self.membership_after[index].capture_once(anchor, process, None));
                if !matches!(self.membership_after_results[index], Some(Ok(()))) {
                    self.first.get_or_insert(First::MembershipAfter(index));
                }
            }
        }
        if let Some(file) = self.executable_file.as_ref() {
            self.executable_after = Some(file.metadata());
            if !self.same_executable_after() { self.first.get_or_insert(First::ExecutableAfter); }
        }
        self.complete = self.first.is_none();
        if self.complete { Ok(()) } else { Err(NetworkChildOriginClosedV2) }
    }

    fn capture_inner(&mut self, record: &mut ReceivedDescriptorRecord)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        let Some(donations) = record.take_network_child_origin_descriptors_data_v2()
            else { return self.refuse(First::Donations); };
        // Move every actual donation before the first role validator enters.
        for (slot, donation) in self.raw.iter_mut().zip(donations) { *slot = Some(donation); }
        let Some(source) = self.raw[0].take() else { return self.refuse(First::Donations); };
        self.source_result = Some(self.source_original.capture_once(source));
        if !matches!(self.source_result, Some(Ok(()))) { return self.refuse(First::SourcePidFd); }
        self.source = self.source_original.take_completed_once();
        let Some(own_pid) = NonZeroU32::new(std::process::id()) else { return self.refuse(First::Coordinates); };
        self.own_result = Some(self.own_original.capture_once(own_pid));
        if !matches!(self.own_result, Some(Ok(()))) { return self.refuse(First::OwnPidFd); }
        self.own = self.own_original.take_validated();

        for (index, donation) in [1, 2, 5].into_iter().enumerate() {
            let Some(input) = self.raw[donation].take() else { return self.refuse(First::Donations); };
            self.cgroup_results[index] = Some(self.cgroup_originals[index].capture_once(input));
            if !matches!(self.cgroup_results[index], Some(Ok(()))) { return self.refuse(First::Cgroup(index)); }
            self.cgroups[index] = self.cgroup_originals[index].take_completed_once();
        }
        let (Some(source), Some(own)) = (self.source.as_ref(), self.own.as_ref())
            else { return self.refuse(First::Donations); };
        let mut failed_identity = None;
        {
            for (index, process) in [source, own].into_iter().enumerate() {
                self.identity_results[index] = Some(self.identities[index].capture_once(process));
                if !matches!(self.identity_results[index], Some(Ok(()))) {
                    failed_identity = Some(index);
                    break;
                }
            }
        }
        if let Some(index) = failed_identity { return self.refuse(First::Identity(index)); }
        let packet = record.payload();
        for (index, offsets) in [[224, 232, 240], [248, 256, 264]].into_iter().enumerate() {
            let Some(identity) = self.identities[index].identity() else { return self.refuse(First::Identity(index)); };
            let Some((_, anchor)) = self.cgroups[index].as_ref() else { return self.refuse(First::Donations); };
            if read_u64(packet, offsets[0]) != Some(u64::from(identity.pid()))
                || read_u64(packet, offsets[1]) != Some(identity.start_time_ticks())
                || read_u64(packet, offsets[2]) != Some(anchor.kernel_id())
                || identity.thread_group_id() != identity.pid() || identity.parent_pid() != 1
                || identity.cgroup_id() != Some(anchor.kernel_id())
                || index == 1 && identity.pid() != std::process::id()
            { return self.refuse(First::Coordinates); }
        }
        for index in 0..2 {
            let process = if index == 0 { self.source.as_ref() } else { self.own.as_ref() };
            let (Some(process), Some((_, anchor))) = (process, self.cgroups[index].as_ref())
                else { return self.refuse(First::Donations); };
            self.membership_results[index] = Some(self.membership[index].capture_once(anchor, process, None));
            if !matches!(self.membership_results[index], Some(Ok(()))) { return self.refuse(First::Membership(index)); }
        }
        for (index, (donation, group, kind)) in [
            (3, 1, Kind::MemoryMax), (4, 1, Kind::PidsMax),
            (6, 2, Kind::MemoryMax), (7, 2, Kind::PidsMax), (8, 2, Kind::CpuMax),
        ].into_iter().enumerate() {
            let Some((_, anchor)) = self.cgroups[group].as_ref() else { return self.refuse(First::Donations); };
            self.control_results[index] = Some(self.controls[index].capture_once_v2(&mut self.raw[donation], anchor, kind));
            if !matches!(self.control_results[index], Some(Ok(()))) { return self.refuse(First::Control(index)); }
        }
        self.limits = Some(rustix::process::getrlimit(rustix::process::Resource::Nofile));
        let Some(limits) = self.limits.as_ref() else { return self.refuse(First::Limits); };
        if self.controls[0].value_data_v2() != read_u64(packet, 272).map(Value::Scalar)
            || self.controls[1].value_data_v2() != read_u64(packet, 288).map(Value::Scalar)
            || limits.current != read_u64(packet, 280) || limits.maximum != read_u64(packet, 280)
            || self.controls[2].value_data_v2() != read_u64(packet, 664).map(Value::Scalar)
            || self.controls[3].value_data_v2() != read_u64(packet, 672).map(Value::Scalar)
            || !matches!(self.controls[4].value_data_v2(), Some(Value::Cpu { quota, period })
                if Some(quota) == read_u64(packet, 656) && period == 100_000)
        { return self.refuse(First::Limits); }
        let (Some((_, source)), Some((_, worker)), Some((_, aggregate))) =
            (self.cgroups[0].as_ref(), self.cgroups[1].as_ref(), self.cgroups[2].as_ref())
            else { return self.refuse(First::Donations); };
        self.ancestry_result = Some(self.ancestry.capture_once_v2(source, worker, aggregate));
        if !matches!(self.ancestry_result, Some(Ok(()))) { return self.refuse(First::Ancestry); }
        if self.boot.observe_once().ok().map(|boot| boot.into_bytes()) != packet.get(16..32).and_then(|bytes| bytes.try_into().ok()) {
            return self.refuse(First::Boot);
        }
        // The fixed kernel procfs link names this recipient's actual image.
        // PID1 independently compares it with its selected held worker image.
        self.executable = Some(rustix::fs::open("/proc/self/exe",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::empty()));
        self.executable_result = self.executable.as_ref().map(|result| {
            result.as_ref().map(|_| ()).map_err(|cause| *cause)
        });
        if !matches!(self.executable, Some(Ok(_))) { return self.refuse(First::ExecutableOpen); }
        if let Some(Ok(file)) = self.executable.take() { self.executable_file = Some(File::from(file)); }
        let Some(file) = self.executable_file.as_ref() else { return self.refuse(First::ExecutableOpen); };
        self.executable_metadata = Some(file.metadata());
        let Some(Ok(metadata)) = self.executable_metadata.as_ref() else { return self.refuse(First::ExecutableMetadata); };
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o6022 != 0
            || metadata.mode() & 0o111 == 0 || metadata.ino() == 0 {
            return self.refuse(First::ExecutableShape);
        }
        Ok(())
    }

    fn same_executable_after(&self) -> bool {
        let (Some(Ok(before)), Some(Ok(after))) =
            (self.executable_metadata.as_ref(), self.executable_after.as_ref()) else { return false; };
        before.dev() == after.dev() && before.ino() == after.ino()
            && before.mode() == after.mode() && before.uid() == after.uid() && before.gid() == after.gid()
            && before.len() == after.len() && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }

    /// Retires only completed proof temporaries after the first live query.
    ///
    /// This is entered by the sole inherited owner after the real query and
    /// all initial native posts succeed. The nine donations, actual own PIDFD,
    /// executable, three native root/anchor pairs and original channel stay
    /// owned. All cached bytes, identities and once fences remain resident.
    pub(super) fn retire_positive_proofs_once(&mut self)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if !self.complete || self.first.is_some() || self.proofs_retired {
            return Err(NetworkChildOriginClosedV2);
        }
        for index in 0..16 {
            let result = match index {
                0..=2 => self.cgroup_originals[index].retire_positive_probes_once_v2(),
                3..=4 => self.identities[index - 3].retire_positive_stat_file_once_v2(),
                5..=6 => self.membership[index - 5].retire_completed_files_once_v4()
                    .map(|_| ()).ok_or_else(retirement_closed),
                7..=8 => self.membership_after[index - 7].retire_completed_files_once_v4()
                    .map(|_| ()).ok_or_else(retirement_closed),
                9..=13 => self.controls[index - 9].retire_positive_proofs_once_v2(),
                14 => self.ancestry.retire_positive_proofs_once_v2(),
                15 => self.boot.retire_positive_file_once().map_err(|_| retirement_closed()),
                _ => Err(retirement_closed()),
            };
            self.retirement[index] = Some(result);
            if !matches!(self.retirement[index], Some(Ok(()))) {
                self.first = Some(First::Retirement(index));
                self.complete = false;
                return Err(NetworkChildOriginClosedV2);
            }
        }
        self.proofs_retired = true;
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::SourcePidFd => self.source_original.failure().map(|cause| cause as _),
            First::OwnPidFd => self.own_original.failure().map(|cause| cause as _),
            First::Cgroup(index) => self.cgroup_originals[index].failure().map(|cause| cause as _),
            First::Identity(index) => self.identities[index].failure().map(|cause| cause as _),
            First::Membership(index) => self.membership[index].failure().map(|cause| cause as _),
            First::Control(index) => self.controls[index].failure(),
            First::Ancestry => self.ancestry.failure(),
            First::Boot => self.boot.failure(),
            First::ExecutableOpen => self.executable_result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ExecutableMetadata => self.executable_metadata.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SourceAfter => self.source_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::OwnAfter => self.own_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::MembershipAfter(index) => self.membership_after[index].failure().map(|cause| cause as _),
            First::ExecutableAfter => self.executable_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Retirement(15) => self.boot.failure().or_else(||
                self.retirement[15].as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Retirement(index) => self.retirement[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            _ => None,
        };
        cause.or(Some(&NetworkChildOriginClosedV2))
    }

    fn refuse(&mut self, first: First) -> Result<(), NetworkChildOriginClosedV2> {
        self.first.get_or_insert(first);
        Err(NetworkChildOriginClosedV2)
    }

    pub(super) fn obligations_data_v2() -> Option<ResourceVector> {
        let source = RuntimeScopeReceivedPidFdOriginalV1::receiving_demand_v1()?;
        let cgroup = RuntimeScopeCgroupOriginalV1::receiving_demand_v1()?;
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let membership = RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?;
        let ancestry = NetworkChildAggregateAncestryOriginalV2::receiving_obligations_data_v2()?;
        let mut bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(source.0)?.checked_add(cgroup.0.checked_mul(3)?)?
            .checked_add(identity.0.checked_mul(2)?)?
            .checked_add(membership.0.checked_mul(4)?)?.checked_add(ancestry.0)?
            .checked_add(RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?)?
            .checked_add(2 * std::mem::size_of::<PidFdOpenAttemptV1>())?;
        bytes = bytes.checked_add(2 * ("Network child proof retirement".len()
            + "the completed native prefix is unavailable".len()))?;
        // All nine inputs already belong to the carrier's receive invoice.
        // The own PIDFD and executable are genuinely additional native opens.
        let mut files = source.1.checked_sub(1)?
            .checked_add(cgroup.1.checked_sub(1)?.checked_mul(3)?)?
            .checked_add(identity.1.checked_mul(2)?)?
            .checked_add(membership.1.checked_mul(4)?)?.checked_add(ancestry.1)?
            .checked_add(1 + 1 + 1)?;
        let mut names = cgroup.2.checked_mul(3)?
            .checked_add(membership.2.checked_mul(4)?)?.checked_add(ancestry.2)?
            .checked_add(RootOriginalKernelBootIdAttemptV1::receiving_metadata_cells_v1())?
            .checked_add(1)?;
        for kind in [Kind::MemoryMax, Kind::PidsMax, Kind::MemoryMax, Kind::PidsMax, Kind::CpuMax] {
            let quote = NetworkChildControlDonationOriginalV2::receiving_obligations_data_v2(kind)?;
            bytes = bytes.checked_add(quote.0)?;
            files = files.checked_add(quote.1)?;
            names = names.checked_add(quote.2)?;
        }
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(names).ok()?))
    }
}

fn retirement_closed() -> aos_linux_descriptors::Error {
    aos_linux_descriptors::Error::InvalidInput {
        field: "Network child proof retirement",
        message: "the completed native prefix is unavailable".into(),
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}
