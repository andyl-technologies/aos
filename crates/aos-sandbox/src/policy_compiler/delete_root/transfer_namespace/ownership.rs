//! Owns fresh fixed local Ownership PID1, kernel and immutable unit bookends.
//!
//! The caller is the real paid Root namespace interval. This private native
//! owner grants no default-off Runtime, lease, Transfer or six-owner authority.

use std::error::Error;
use std::num::NonZeroU32;
use std::path::PathBuf;

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use aos_sandbox_broker::immutable_image::ImmutableFileAcquisitionOriginalV1;
use aos_sandbox_broker::immutable_image::{
    ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{
    CgroupV2Root, ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1,
    OwnershipInitialCgroupReadbackV1, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo, PidFdOpenAttemptV1, PidFdOpenRefusalV1};
use aos_systemd::{
    FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1, FixedPid1PropertyValuesV1,
    FixedPid1PropertyWorkerSlotV1, OwnedValue, Value,
};

const MATERIALIZED: usize = 64 * 1024;
const CGROUP: &str = "/aoscomponents.slice/aos-sandbox-ownershipd.service";
const UNIT: &str = "aos-sandbox-ownershipd.service";

#[derive(Debug, thiserror::Error)]
#[error("fixed active Ownership profile differs or is unavailable")]
pub(in crate::policy_compiler::delete_root) struct OwnershipProfileClosedV1;

#[derive(Eq, PartialEq)]
struct ProfileData {
    pid: NonZeroU32,
    invocation: [u8; 16],
    fragment: PathBuf,
    executable: String,
}

#[derive(Clone, Copy)]
enum First {
    PrepareBefore,
    PrepareAfter,
    QueueBefore,
    ReadBefore,
    DecodeBefore,
    Fragment,
    Kernel,
    QueueAfter,
    ReadAfter,
    DecodeAfter,
    MembershipAfter,
    LivenessAfter,
    FragmentAfter,
    Changed,
    Reentry,
}

pub(in crate::policy_compiler::delete_root) struct RootOwnershipProfileOriginalV1 {
    expected_controller: [u32; 2],
    cutoff: u64,
    archive: [FixedPid1PropertyArchiveV1; 2],
    prepared: [Option<Result<(), FixedPid1PropertyErrorV1>>; 2],
    queued_clock: [Option<rustix::time::Timespec>; 2],
    queued: [Option<Result<(), OwnershipProfileClosedV1>>; 2],
    reads: [Option<Result<FixedPid1PropertyValuesV1, FixedPid1PropertyErrorV1>>; 2],
    decoded: [Option<Result<ProfileData, OwnershipProfileClosedV1>>; 2],
    fragment: ImmutableFileAcquisitionOriginalV1,
    fragment_result: Option<Result<(), ImmutableImageErrorV1>>,
    fragment_after: ImmutableFileRevalidationOriginalV1,
    fragment_post: Option<Result<(), ImmutableImageErrorV1>>,
    cgroup: OwnershipInitialCgroupReadbackV1,
    cgroup_result: Option<aos_sandbox_linux::Result<()>>,
    pair: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    pidfd: PidFdOpenAttemptV1,
    pidfd_result: Option<Result<(), PidFdOpenRefusalV1>>,
    process: Option<PidFd>,
    membership: [ExactCgroupMembershipReadbackV1; 2],
    membership_results: [Option<Result<(), ExactCgroupMembershipRefusalV1>>; 2],
    process_binding: [Option<Result<(), OwnershipProfileClosedV1>>; 2],
    kernel_result: Option<Result<(), OwnershipProfileClosedV1>>,
    liveness: Option<aos_sandbox_linux::Result<bool>>,
    comparison: Option<Result<(), OwnershipProfileClosedV1>>,
    entered: bool,
    finished: bool,
    first: Option<First>,
    closed: Option<OwnershipProfileClosedV1>,
}

impl RootOwnershipProfileOriginalV1 {
    pub(in crate::policy_compiler::delete_root) fn new(expected_controller: [u32; 2], cutoff: u64) -> Self {
        Self {
            expected_controller,
            cutoff,
            archive: std::array::from_fn(|_| {
                FixedPid1PropertyArchiveV1::with_materialization_limit(1, MATERIALIZED)
            }),
            prepared: [None, None],
            queued_clock: [None, None],
            queued: [None, None],
            reads: [None, None],
            decoded: [None, None],
            fragment: ImmutableFileAcquisitionOriginalV1::new(),
            fragment_result: None,
            fragment_after: Default::default(),
            fragment_post: None,
            cgroup: OwnershipInitialCgroupReadbackV1::new(),
            cgroup_result: None,
            pair: None,
            pidfd: PidFdOpenAttemptV1::new(),
            pidfd_result: None,
            process: None,
            membership: std::array::from_fn(|_| ExactCgroupMembershipReadbackV1::new()),
            membership_results: [None, None],
            process_binding: [None, None],
            kernel_result: None,
            liveness: None,
            comparison: None,
            entered: false,
            finished: false,
            first: None,
            closed: None,
        }
    }

    pub(in crate::policy_compiler::delete_root) fn planning_data_v1(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningOwnershipDataV1,
        OwnershipProfileClosedV1,
    > {
        use aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningOwnershipDataV1;
        use sha2::{Digest as _, Sha256};
        if !self.finished || self.first.is_some() { return Err(OwnershipProfileClosedV1); }
        positive(&self.comparison)?;
        let profile = positive(&self.decoded[0])?;
        let kernel = self.membership[1].result().and_then(|result| result.as_ref().ok())
            .ok_or(OwnershipProfileClosedV1)?;
        let data = DeleteRootPlanningOwnershipDataV1 {
            pid: profile.pid.get(), invocation: profile.invocation,
            cgroup: kernel.cgroup_id().ok_or(OwnershipProfileClosedV1)?,
            unit: self.fragment.completed_measurement().ok_or(OwnershipProfileClosedV1)?
                .measured_digest_v1(),
            executable: Sha256::new()
                .chain_update(b"aos.sandbox.delete-root.planning-ownership-executable.v1\0")
                .chain_update(profile.executable.as_bytes()).finalize().into(),
        };
        data.commitment_v1().map_err(|_| OwnershipProfileClosedV1)?;
        Ok(data)
    }

    pub(in crate::policy_compiler::delete_root) fn demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let row = aos_sandbox_broker::receiving::fixed_property_archive_demand_v1(MATERIALIZED)
            .map_err(|_| invalid())?;
        let membership =
            ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1().ok_or_else(invalid)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(membership.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(MATERIALIZED.checked_mul(4)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let native_files = 6_usize
            .checked_add(1)
            .and_then(|files| {
                files.checked_add(
                    ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)?,
                )
            })
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(invalid)?;
        let acquisition = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(MATERIALIZED)
            .ok_or_else(invalid)?;
        let post =
            ImmutableFileRevalidationOriginalV1::receiving_demand_v1().ok_or_else(invalid)?;
        row.checked_add(row)?
            .checked_add(acquisition)?
            .checked_add(post)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, native_files)
                    .with(D::Pids, 1)
                    .with(D::MetadataEntries, native_files),
            )
            .map_err(Into::into)
    }

    pub(in crate::policy_compiler::delete_root) fn begin_once_v1(&mut self) -> Result<(), OwnershipProfileClosedV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(OwnershipProfileClosedV1);
            return Err(OwnershipProfileClosedV1);
        }
        self.entered = true;
        self.read_once(0)?;
        let first = positive(&self.decoded[0])?;
        self.fragment_result = Some(self.fragment.open_and_measure_once(
            first.fragment.clone(),
            None,
            MATERIALIZED as u64,
            false,
        ));
        self.require(
            matches!(self.fragment_result, Some(Ok(()))),
            First::Fragment,
        )?;
        self.kernel_result = Some(self.capture_kernel());
        self.require(matches!(self.kernel_result, Some(Ok(()))), First::Kernel)
    }

    fn capture_kernel(&mut self) -> Result<(), OwnershipProfileClosedV1> {
        let pid = positive(&self.decoded[0])?.pid;
        self.cgroup_result = Some(self.cgroup.capture_once());
        positive(&self.cgroup_result)?;
        self.pair = self.cgroup.take_validated_pair();
        self.pidfd_result = Some(self.pidfd.capture_once(pid));
        positive(&self.pidfd_result)?;
        self.process = self.pidfd.take_validated();
        self.capture_membership(0)
    }

    fn capture_membership(&mut self, index: usize) -> Result<(), OwnershipProfileClosedV1> {
        let (_, anchor) = self.pair.as_ref().ok_or(OwnershipProfileClosedV1)?;
        let process = self.process.as_ref().ok_or(OwnershipProfileClosedV1)?;
        self.membership_results[index] = Some(self.membership[index].capture_once(anchor, process));
        positive(&self.membership_results[index])?;
        self.process_binding[index] = Some((|| {
            let info = self.membership[index]
                .result()
                .and_then(|result| result.as_ref().ok())
                .ok_or(OwnershipProfileClosedV1)?;
            if !root_process(*info, positive(&self.decoded[0])?.pid.get()) {
                return Err(OwnershipProfileClosedV1);
            }
            Ok(())
        })());
        positive(&self.process_binding[index]).map(|_| ())
    }

    pub(in crate::policy_compiler::delete_root) fn finish_if_owed_v1(&mut self) -> Result<(), OwnershipProfileClosedV1> {
        if !self.entered || self.finished {
            return Ok(());
        }
        self.finished = true;
        // Every prepaid after remains independent of a failed before/profile.
        let _ = self.read_once(1);
        if self.pair.is_some() && self.process.is_some() {
            let result = self.capture_membership(1);
            if result.is_err() {
                self.first.get_or_insert(First::MembershipAfter);
            }
        }
        if let Some(process) = &self.process {
            self.liveness = Some(process.is_alive());
            if !matches!(self.liveness, Some(Ok(true))) {
                self.first.get_or_insert(First::LivenessAfter);
            }
        }
        self.fragment_post = self
            .fragment
            .observe_available_held_once_v1(&mut self.fragment_after);
        if !matches!(self.fragment_post, Some(Ok(()))) {
            self.first.get_or_insert(First::FragmentAfter);
        }
        self.comparison = Some((|| {
            if positive(&self.decoded[0])? != positive(&self.decoded[1])? {
                return Err(OwnershipProfileClosedV1);
            }
            positive(&self.kernel_result)?;
            positive(&self.process_binding[1])?;
            if !matches!(self.liveness, Some(Ok(true))) {
                return Err(OwnershipProfileClosedV1);
            }
            positive(&self.fragment_post)?;
            Ok(())
        })());
        if !matches!(self.comparison, Some(Ok(()))) {
            self.first.get_or_insert(First::Changed);
        }
        if self.first.is_some() {
            Err(OwnershipProfileClosedV1)
        } else {
            Ok(())
        }
    }

    fn read_once(&mut self, index: usize) -> Result<(), OwnershipProfileClosedV1> {
        self.prepared[index] = Some(self.archive[index].prepare_once());
        self.require(
            matches!(self.prepared[index], Some(Ok(()))),
            if index == 0 {
                First::PrepareBefore
            } else {
                First::PrepareAfter
            },
        )?;
        let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();
        self.queued_clock[index] =
            Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.queued[index] = Some(require_cutoff(
            self.queued_clock[index].as_ref(),
            self.cutoff,
        ));
        self.require(
            matches!(self.queued[index], Some(Ok(()))),
            if index == 0 {
                First::QueueBefore
            } else {
                First::QueueAfter
            },
        )?;
        self.reads[index] = Some(
            self.archive[index].read_fixed_ownership_profile_under_slot_v1(&mut slot, self.cutoff),
        );
        drop(slot);
        self.require(
            matches!(self.reads[index], Some(Ok(_))),
            if index == 0 {
                First::ReadBefore
            } else {
                First::ReadAfter
            },
        )?;
        self.decoded[index] = Some(
            positive(&self.reads[index])
                .and_then(|(service, unit)| decode(service, unit, self.expected_controller)),
        );
        self.require(
            matches!(self.decoded[index], Some(Ok(_))),
            if index == 0 {
                First::DecodeBefore
            } else {
                First::DecodeAfter
            },
        )
    }

    fn require(&mut self, positive: bool, first: First) -> Result<(), OwnershipProfileClosedV1> {
        if positive {
            Ok(())
        } else {
            self.first.get_or_insert(first);
            Err(OwnershipProfileClosedV1)
        }
    }

    pub(in crate::policy_compiler::delete_root) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::PrepareBefore | First::ReadBefore => self.archive[0].failure_view(),
            First::PrepareAfter | First::ReadAfter => self.archive[1].failure_view(),
            _ => None,
        }
    }

    pub(in crate::policy_compiler::delete_root) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::PrepareBefore => cause(&self.prepared[0]),
            First::PrepareAfter => cause(&self.prepared[1]),
            First::QueueBefore => cause(&self.queued[0]),
            First::QueueAfter => cause(&self.queued[1]),
            First::ReadBefore => cause(&self.reads[0]),
            First::ReadAfter => cause(&self.reads[1]),
            First::DecodeBefore => cause(&self.decoded[0]),
            First::DecodeAfter => cause(&self.decoded[1]),
            First::Fragment => self
                .fragment
                .failure()
                .or_else(|| cause(&self.fragment_result)),
            First::Kernel => self
                .cgroup
                .failure()
                .or_else(|| self.pidfd.failure().map(|cause| cause as _))
                .or_else(|| self.membership[0].failure().map(|cause| cause as _))
                .or_else(|| cause(&self.process_binding[0]))
                .or_else(|| cause(&self.kernel_result)),
            First::MembershipAfter => self.membership[1]
                .failure()
                .map(|cause| cause as _)
                .or_else(|| cause(&self.process_binding[1])),
            First::LivenessAfter => cause(&self.liveness).or(Some(&OwnershipProfileClosedV1)),
            First::FragmentAfter => self
                .fragment_after
                .failure()
                .or_else(|| cause(&self.fragment_post)),
            First::Changed => cause(&self.comparison),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn decode(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    expected: [u32; 2],
) -> Result<ProfileData, OwnershipProfileClosedV1> {
    let [
        pid,
        cgroup,
        state,
        state_mode,
        user,
        group,
        caps,
        ambient,
        nnp,
        exec,
        runtime,
        runtime_mode,
    ] = service
    else {
        return Err(OwnershipProfileClosedV1);
    };
    let [fragment, drops, transient, invocation] = unit else {
        return Err(OwnershipProfileClosedV1);
    };
    let pid = u32::try_from(pid)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(OwnershipProfileClosedV1)?;
    if <&str>::try_from(cgroup).ok() != Some(CGROUP)
        || !one_string(state, "aos/sandbox/multi-node")
        || u32::try_from(state_mode).ok() != Some(0o700)
        || !one_string(runtime, "aos/sandbox-ownership")
        || u32::try_from(runtime_mode).ok() != Some(0o711)
        || !matches!(<&str>::try_from(user).ok(), Some("" | "root"))
        || !matches!(<&str>::try_from(group).ok(), Some("" | "root"))
        || u64::try_from(caps).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || bool::try_from(transient).ok() != Some(false)
        || !empty_strings(drops)
    {
        return Err(OwnershipProfileClosedV1);
    }
    let fragment = PathBuf::from(<&str>::try_from(fragment).map_err(|_| OwnershipProfileClosedV1)?);
    if !fragment.starts_with("/nix/store") || fragment.file_name().is_none_or(|name| name != UNIT) {
        return Err(OwnershipProfileClosedV1);
    }
    let Value::Array(invocation) = &**invocation else {
        return Err(OwnershipProfileClosedV1);
    };
    let invocation = crate::systemd_property_data::nonzero_invocation_bytes(invocation.inner())
        .ok_or(OwnershipProfileClosedV1)?;
    let command =
        crate::systemd_property_data::single_exec_start(exec).ok_or(OwnershipProfileClosedV1)?;
    let [Value::Str(program), Value::Str(uid), Value::Str(gid)] = command.argv else {
        return Err(OwnershipProfileClosedV1);
    };
    if command.pid != pid.get()
        || !command.path.starts_with("/nix/store/")
        || !command.path.ends_with("/bin/aos-sandbox-ownershipd")
        || program.as_str() != command.path
        || uid.as_str() != expected[0].to_string()
        || gid.as_str() != expected[1].to_string()
    {
        return Err(OwnershipProfileClosedV1);
    }
    Ok(ProfileData {
        pid,
        invocation,
        fragment,
        executable: command.path.to_owned(),
    })
}

fn one_string(value: &OwnedValue, expected: &str) -> bool {
    let Value::Array(values) = &**value else {
        return false;
    };
    matches!(values.inner(), [Value::Str(value)] if value.as_str() == expected)
}

fn empty_strings(value: &OwnedValue) -> bool {
    let Value::Array(values) = &**value else {
        return false;
    };
    values.is_empty() && values.element_signature() == Value::from("").value_signature()
}

fn root_process(info: PidFdInfo, pid: u32) -> bool {
    let Some(c) = info.credentials() else {
        return false;
    };
    info.pid() == pid
        && info.thread_group_id() == pid
        && info.parent_pid() == 1
        && [
            c.real_user_id(),
            c.effective_user_id(),
            c.saved_user_id(),
            c.filesystem_user_id(),
            c.real_group_id(),
            c.effective_group_id(),
            c.saved_group_id(),
            c.filesystem_group_id(),
        ]
        .iter()
        .all(|value| *value == 0)
}

fn require_cutoff(
    sample: Option<&rustix::time::Timespec>,
    cutoff: u64,
) -> Result<(), OwnershipProfileClosedV1> {
    let now = sample.and_then(|sample| {
        let nanos = u64::try_from(sample.tv_nsec).ok()?;
        if nanos >= 1_000_000_000 {
            return None;
        }
        u64::try_from(sample.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(nanos)
    });
    if now.is_some_and(|now| now < cutoff) {
        Ok(())
    } else {
        Err(OwnershipProfileClosedV1)
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, OwnershipProfileClosedV1> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(OwnershipProfileClosedV1)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn profile() -> (Vec<OwnedValue>, Vec<OwnedValue>) {
        let executable = "/nix/store/fixture-package/bin/aos-sandbox-ownershipd";
        let command = (
            executable.to_owned(),
            vec![executable.to_owned(), "1000".into(), "1001".into()],
            false,
            0u64,
            0u64,
            0u64,
            0u64,
            42u32,
            0i32,
            0i32,
        );
        (
            vec![
                value(42u32),
                value(CGROUP),
                value(vec!["aos/sandbox/multi-node"]),
                value(0o700u32),
                value(""),
                value("root"),
                value(0u64),
                value(0u64),
                value(true),
                value(vec![command]),
                value(vec!["aos/sandbox-ownership"]),
                value(0o711u32),
            ],
            vec![
                value("/nix/store/fixture-unit/aos-sandbox-ownershipd.service"),
                value(Vec::<String>::new()),
                value(false),
                value(vec![1u8; 16]),
            ],
        )
    }

    #[test]
    fn only_the_active_local_profile_with_the_actual_controller_arguments_matches() {
        let (service, unit) = profile();
        assert!(decode(&service, &unit, [1000, 1001]).is_ok());
        assert!(decode(&service, &unit, [1000, 1002]).is_err());
        for (index, malformed) in [
            (1, value("/foreign/unit")),
            (2, value(vec!["foreign"])),
            (3, value(0o755u32)),
            (4, value("nobody")),
            (6, value(1u64)),
            (8, value(false)),
            (10, value(vec!["foreign"])),
            (11, value(0o777u32)),
        ] {
            let (mut service, unit) = profile();
            service[index] = malformed;
            assert!(decode(&service, &unit, [1000, 1001]).is_err());
        }
        let (service, mut unit) = profile();
        unit[3] = value(vec![0u8; 16]);
        assert!(decode(&service, &unit, [1000, 1001]).is_err());
    }

    #[test]
    fn native_queue_sample_rejects_equal_expired_or_invalid_original_cutoff() {
        let sample = rustix::time::Timespec {
            tv_sec: 1,
            tv_nsec: 2,
        };
        assert!(require_cutoff(Some(&sample), 1_000_000_003).is_ok());
        assert!(require_cutoff(Some(&sample), 1_000_000_002).is_err());
        assert!(require_cutoff(Some(&sample), 1_000_000_001).is_err());
        assert!(require_cutoff(None, u64::MAX).is_err());
    }
}
