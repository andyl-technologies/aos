//! Owns fixed pre-thread Guest delegation through the same Launch lifetime.
//!
//! Each startup actor moves only its own TGID: PID 1 enters init.scope before
//! spawning its actual Agent, which then enters the fixed private Agent leaf.
//! The delegation is shared by later executions; individual SSH completion
//! must never disable it or migrate either actor back.

use std::num::NonZeroU32;
use std::os::fd::AsFd as _;

use crate::cgroup::{
    CgroupActiveOriginalV2, CgroupControllerReadbackV2, CgroupSingleTaskObservationV1,
    ExactCgroupMembershipReadbackV1, RetainedCgroupAnchor,
};
use crate::pidfd::{
    PidFd, PidFdOpenAttemptV1, PidFdProcessIdentity, PidFdProcessIdentityOriginalV1,
};
use crate::{Error, Result};

use super::GuestPayloadCgroupCustodyV1;
use super::control::ControlWriteOriginalV1;
use super::directory::DirectoryOriginalV1;
use super::inherited::GuestPayloadCgroupCustodyOriginalV2;

const MEMORY: u16 = 4;
const PIDS: u16 = 2;
const REQUIRED: u16 = MEMORY | PIDS;

/// Bounds the actual PID 1 caller's private header and fixed Command carriers.
///
/// The installed caller has a compile-time layout assertion against this
/// prospective byte reservoir. This is receiving cost, never a task grant.
pub const GUEST_PID1_STARTUP_CONTROL_BYTES_V1: usize = 4096;

#[derive(Clone, Copy, Eq, PartialEq)]
enum StartupRoleV1 {
    Pid1,
    Agent,
}

/// Reports closed startup while the caller retains its whole original.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("original Guest topology startup refused")]
pub struct GuestRuntimeTopologyClosedV1;

/// Retains pre-thread own-Agent placement and fixed controller delegation.
///
/// The actual Host Launch owner prepays its compiled source before catalog or
/// Guest spawn. This native constructor creates no financial account, process,
/// assignment, command lifetime or cancellation permission. It consumes only
/// the original FD6/7-bound payload custody, never a caller path or PID.
pub struct GuestRuntimeTopologyOriginalV1 {
    role: Option<StartupRoleV1>,
    handoff: super::handoff::TopologyHandoffOriginalV1,
    agent_completion: super::agent_completion::AgentCompletionOriginalV1,
    record: Option<super::handoff::TopologyRecordV1>,
    provisioning_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    owner: Option<Box<crate::guest_confinement::GuestOwnerOriginalV2>>,
    inherited: Option<Box<GuestPayloadCgroupCustodyOriginalV2>>,
    payload: Option<GuestPayloadCgroupCustodyV1>,
    execution_directory: DirectoryOriginalV1,
    agent_directory: DirectoryOriginalV1,
    execution_root: Option<RetainedCgroupAnchor>,
    agent_leaf: Option<RetainedCgroupAnchor>,
    tasks: [Option<Box<CgroupSingleTaskObservationV1>>; 2],
    pidfd: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    identity: [Option<Box<PidFdProcessIdentityOriginalV1>>; 2],
    identities: [Option<PidFdProcessIdentity>; 2],
    membership: [Option<Box<ExactCgroupMembershipReadbackV1>>; 2],
    reader: Option<Box<CgroupControllerReadbackV2>>,
    controller_masks: [Option<u16>; 6],
    writes: [ControlWriteOriginalV1; 3],
    after: [Option<Box<CgroupActiveOriginalV2>>; 2],
    inherited_marks: [Option<Result<()>>; 3],
    body: Option<Result<()>>,
    reentry: Option<Error>,
    topology_entered: bool,
    completed: bool,
    taken: bool,
}

impl std::fmt::Debug for GuestRuntimeTopologyOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestRuntimeTopologyOriginalV1")
            .field("topology_entered", &self.topology_entered)
            .field("completed", &self.completed)
            .field("failure", &self.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for GuestRuntimeTopologyOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => write!(formatter, "original Guest topology failed: {cause}"),
            None => formatter.write_str("original Guest topology remains occupied"),
        }
    }
}

impl std::error::Error for GuestRuntimeTopologyOriginalV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

impl Default for GuestRuntimeTopologyOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestRuntimeTopologyOriginalV1 {
    /// Creates inert destinations before the actual inherited payload is moved.
    #[must_use]
    pub fn new() -> Self {
        Self {
            role: None,
            handoff: super::handoff::TopologyHandoffOriginalV1::new(),
            agent_completion: super::agent_completion::AgentCompletionOriginalV1::new(),
            record: None,
            provisioning_stat: None,
            owner: None,
            inherited: None,
            payload: None,
            execution_directory: DirectoryOriginalV1::new(),
            agent_directory: DirectoryOriginalV1::new(),
            execution_root: None,
            agent_leaf: None,
            tasks: std::array::from_fn(|_| None),
            pidfd: PidFdOpenAttemptV1::new(),
            process: None,
            identity: std::array::from_fn(|_| None),
            identities: [None, None],
            membership: std::array::from_fn(|_| None),
            reader: None,
            controller_masks: [None; 6],
            writes: std::array::from_fn(|_| ControlWriteOriginalV1::new()),
            after: std::array::from_fn(|_| None),
            inherited_marks: [None, None, None],
            body: None,
            reentry: None,
            topology_entered: false,
            completed: false,
            taken: false,
        }
    }

    /// Runs the sole selected startup before any Bridge or execution thread.
    ///
    /// # Errors
    /// Retains all original payload/leaf descriptors, exact native write/read
    /// errors and independent posts. A refused original must remain occupied
    /// until the same original Host startup Guardian terminates the Guest.
    pub fn capture_inherited_once_v1(
        &mut self,
    ) -> std::result::Result<(), GuestRuntimeTopologyClosedV1> {
        self.capture_once(StartupRoleV1::Agent)
    }

    /// Produces the fixed topology while PID 1 is still the sole payload task.
    ///
    /// # Errors
    /// Retains the whole native prefix on refusal. Only the original actual
    /// PID 1 bootstrap calls this before spawning its Agent or execing systemd.
    pub fn capture_initial_pid1_once_v1(
        &mut self,
    ) -> std::result::Result<(), GuestRuntimeTopologyClosedV1> {
        self.capture_once(StartupRoleV1::Pid1)
    }

    fn capture_once(
        &mut self,
        role: StartupRoleV1,
    ) -> std::result::Result<(), GuestRuntimeTopologyClosedV1> {
        if self.body.is_some() || self.inherited.is_some() || self.payload.is_some() {
            self.reentry.get_or_insert_with(closed);
            self.completed = false;
            return Err(GuestRuntimeTopologyClosedV1);
        }
        self.body = Some((|| {
            if (std::process::id() == 1) != (role == StartupRoleV1::Pid1) {
                return Err(closed());
            }
            self.role = Some(role);
            // The installed normal caller is already in the original
            // Guardian-bound payload. Preserve even a failed first Owner
            // observation until that same payload is disposed.
            self.topology_entered = true;
            super::require_owner_retaining(&mut self.owner)?;
            if role == StartupRoleV1::Pid1 {
                // Reserve both fixed child slots before any CLOEXEC startup
                // duplicate could occupy them. Failed setup remains on PID 1.
                self.topology_entered = true;
                self.handoff.reserve_pid1_once()?;
            }
            if role == StartupRoleV1::Agent {
                self.record = Some(self.handoff.read_agent_once()?);
            }
            self.inherited = Some(Box::new(GuestPayloadCgroupCustodyOriginalV2::new()));
            let inherited = self.inherited.as_mut().ok_or_else(closed)?;
            match self.record {
                Some(record) => inherited.capture_agent_once(record)?,
                None => inherited.capture_once_v2()?,
            }
            self.payload = inherited.take_completed_once_v2();
            if self.payload.is_none() {
                return Err(closed());
            }
            // Its complete seal/root/member native phase is positive before
            // the new topology phase; only actual payload custody survives.
            drop(self.inherited.take());
            self.capture_inner()
        })());
        // Both available actual-anchor observations are owed after primary
        // poison. These readonly posts confer no new mutation permission.
        if let Some(payload) = self.payload.as_ref() {
            self.after[0] = Some(Box::new(CgroupActiveOriginalV2::new()));
            let _ = self.after[0]
                .as_mut()
                .map(|after| after.capture_once_v2(&payload.payload));
        }
        if let Some(root) = self.execution_root.as_ref() {
            self.after[1] = Some(Box::new(CgroupActiveOriginalV2::new()));
            let _ = self.after[1]
                .as_mut()
                .map(|after| after.capture_once_v2(root));
        }
        self.completed = matches!(self.body, Some(Ok(()))) && self.failure().is_none();
        if !self.completed {
            return Err(GuestRuntimeTopologyClosedV1);
        }

        // All compared self identities/membership/delegation and both final
        // actual anchors are positive. These temporary observations retire;
        // the actual payload, execution root and Agent leaf remain resident.
        for slot in &mut self.tasks {
            drop(slot.take());
        }
        for slot in &mut self.identity {
            drop(slot.take());
        }
        for slot in &mut self.membership {
            drop(slot.take());
        }
        for slot in &mut self.after {
            drop(slot.take());
        }
        drop(self.process.take());
        if role == StartupRoleV1::Agent {
            self.handoff.retire_completed_agent_read();
            // PID 1 cannot exec systemd until this exact whole topology,
            // including the independent final observations, has completed.
            if self.handoff.acknowledge_agent_once().is_err() {
                self.completed = false;
                return Err(GuestRuntimeTopologyClosedV1);
            }
        }
        Ok(())
    }

    fn capture_inner(&mut self) -> Result<()> {
        let role = self.role.ok_or_else(closed)?;
        let payload = &self.payload.as_ref().ok_or_else(closed)?.payload;
        if role == StartupRoleV1::Pid1 {
            self.tasks[0] = Some(Box::new(CgroupSingleTaskObservationV1::new()));
            self.tasks[0]
                .as_mut()
                .ok_or_else(closed)?
                .capture_current_only_once(payload)?;
            self.tasks[0]
                .as_mut()
                .ok_or_else(closed)?
                .dispose_positive_after_posts_v1()?;
        }

        // Reject unsupported delegation before creating a child or moving
        // the Agent. No Bridge or execution thread exists at this boundary.
        read_controllers(
            &mut self.reader,
            &mut self.controller_masks[0],
            payload,
            true,
        )?;
        if self.controller_masks[0].ok_or_else(closed)? & REQUIRED != REQUIRED {
            return Err(Error::invalid(
                "Guest controller delegation",
                "memory and pids are unavailable",
            ));
        }
        self.topology_entered = true;
        self.execution_directory.capture_execution_root(payload)?;
        self.execution_root = self.execution_directory.take_completed_once();
        if role == StartupRoleV1::Pid1 {
            self.agent_directory.capture_manager_leaf(payload)?;
        } else {
            self.agent_directory.capture_agent_leaf(payload)?;
        }
        self.agent_leaf = self.agent_directory.take_completed_once();
        let execution_root = self.execution_root.as_ref().ok_or_else(closed)?;
        if let Some(record) = self.record {
            if execution_root.kernel_id() != record.execution {
                return Err(closed());
            }
        }
        let leaf = self.agent_leaf.as_ref().ok_or_else(closed)?;
        let pid = NonZeroU32::new(std::process::id()).ok_or_else(closed)?;
        self.pidfd.capture_once(pid).map_err(|_| closed())?;
        self.process = self.pidfd.take_validated();
        let process = self.process.as_ref().ok_or_else(closed)?;
        self.identity[0] = Some(Box::new(PidFdProcessIdentityOriginalV1::new()));
        self.identity[0]
            .as_mut()
            .ok_or_else(closed)?
            .capture_once(process)?;
        self.identities[0] = self.identity[0]
            .as_ref()
            .and_then(|identity| identity.identity());
        // Only this process's actual TGID is written. No caller PID is accepted.
        self.writes[0].migrate_self_once(leaf)?;
        self.membership[0] = Some(Box::new(ExactCgroupMembershipReadbackV1::new()));
        self.membership[0]
            .as_mut()
            .ok_or_else(closed)?
            .capture_once(leaf, process)
            .map_err(|_| closed())?;
        if !self.membership[0]
            .as_mut()
            .ok_or_else(closed)?
            .retire_completed_files_once_v1()
        {
            return Err(closed());
        }
        self.tasks[1] = Some(Box::new(CgroupSingleTaskObservationV1::new()));
        self.tasks[1]
            .as_mut()
            .ok_or_else(closed)?
            .capture_empty_once_v2(payload)?;
        self.tasks[1]
            .as_mut()
            .ok_or_else(closed)?
            .dispose_positive_after_posts_v1()?;

        read_controllers(
            &mut self.reader,
            &mut self.controller_masks[1],
            payload,
            false,
        )?;
        let old = self.controller_masks[1].ok_or_else(closed)?;
        if old & REQUIRED != REQUIRED {
            if role != StartupRoleV1::Pid1 {
                return Err(closed());
            }
            self.writes[1].delegate_once(payload, old & MEMORY == 0, old & PIDS == 0)?;
        }
        read_controllers(
            &mut self.reader,
            &mut self.controller_masks[2],
            payload,
            false,
        )?;
        if self.controller_masks[2] != Some(old | REQUIRED) {
            return Err(closed());
        }

        read_controllers(
            &mut self.reader,
            &mut self.controller_masks[3],
            execution_root,
            true,
        )?;
        if self.controller_masks[3].ok_or_else(closed)? & REQUIRED != REQUIRED {
            return Err(closed());
        }
        read_controllers(
            &mut self.reader,
            &mut self.controller_masks[4],
            execution_root,
            false,
        )?;
        let old = self.controller_masks[4].ok_or_else(closed)?;
        if old & REQUIRED != REQUIRED {
            if role != StartupRoleV1::Pid1 {
                return Err(closed());
            }
            self.writes[2].delegate_once(execution_root, old & MEMORY == 0, old & PIDS == 0)?;
        }
        read_controllers(
            &mut self.reader,
            &mut self.controller_masks[5],
            execution_root,
            false,
        )?;
        if self.controller_masks[5] != Some(old | REQUIRED) {
            return Err(closed());
        }

        self.membership[1] = Some(Box::new(ExactCgroupMembershipReadbackV1::new()));
        self.membership[1]
            .as_mut()
            .ok_or_else(closed)?
            .capture_once(leaf, process)
            .map_err(|_| closed())?;
        self.identity[1] = Some(Box::new(PidFdProcessIdentityOriginalV1::new()));
        self.identity[1]
            .as_mut()
            .ok_or_else(closed)?
            .capture_once(process)?;
        self.identities[1] = self.identity[1]
            .as_ref()
            .and_then(|identity| identity.identity());
        let before = self.identities[0].ok_or_else(closed)?;
        let after = self.identities[1].ok_or_else(closed)?;
        if before.pid() != after.pid()
            || before.thread_group_id() != after.thread_group_id()
            || before.parent_pid() != after.parent_pid()
            || before.start_time_ticks() != after.start_time_ticks()
            || before.cgroup_id()
                != Some(
                    self.record
                        .map_or(payload.kernel_id(), |record| record.manager),
                )
            || after.cgroup_id() != Some(leaf.kernel_id())
        {
            return Err(closed());
        }
        if role == StartupRoleV1::Pid1 {
            self.provisioning_stat = Some(rustix::fs::fstat(
                &self.payload.as_ref().ok_or_else(closed)?.provisioning,
            ));
            let stat = match self.provisioning_stat.as_ref() {
                Some(Ok(stat)) => stat,
                Some(Err(source)) => {
                    return Err(Error::Syscall {
                        operation: "stat actual PID1 topology provisioning",
                        source: (*source).into(),
                    });
                }
                None => return Err(closed()),
            };
            self.handoff
                .publish_pid1_once(super::handoff::TopologyRecordV1 {
                    root: payload.kernel_id(),
                    provisioning: [stat.st_dev, stat.st_ino, stat.st_size as u64],
                    execution: execution_root.kernel_id(),
                    manager: leaf.kernel_id(),
                    parent_start: after.start_time_ticks(),
                })?;
            return Ok(());
        }
        for (index, descriptor) in [6, 7].into_iter().enumerate() {
            self.inherited_marks[index] =
                Some(crate::inherited_fd::mark_inherited_descriptor_close_on_exec(descriptor));
            if !matches!(self.inherited_marks[index], Some(Ok(()))) {
                return Err(closed());
            }
        }
        for descriptor in [6, 7] {
            use std::os::fd::FromRawFd as _;
            // SAFETY: this is the existing fixed bootstrap retirement. The
            // one-shot installed constructor owns numeric FD6/7 from nspawn;
            // all typed custodians are fresh duplicates and all checks above
            // completed before any original numeric entry is closed.
            drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) });
        }
        // Keep the original handoff entry charged, but never leak it through
        // later tenant exec. No new descriptor or replacement is installed.
        self.inherited_marks[2] = Some(
            crate::inherited_fd::mark_inherited_descriptor_close_on_exec(
                super::handoff::DESCRIPTOR,
            ),
        );
        if !matches!(self.inherited_marks[2], Some(Ok(()))) {
            return Err(closed());
        }
        Ok(())
    }

    /// Moves only the same completed payload and execution root into Effects.
    ///
    /// The Agent leaf and original headers remain in this owner until whole
    /// Guest death. Individual execution disposal cannot reverse delegation.
    #[must_use]
    pub fn take_completed_parts_v1(
        &mut self,
    ) -> Option<(GuestPayloadCgroupCustodyV1, RetainedCgroupAnchor)> {
        if !self.completed || self.taken || self.failure().is_some() {
            return None;
        }
        if self.payload.is_none() || self.execution_root.is_none() {
            return None;
        }
        let payload = self.payload.take()?;
        let Some(root) = self.execution_root.take() else {
            self.payload = Some(payload);
            return None;
        };
        self.taken = true;
        Some((payload, root))
    }

    /// Captures SSH birth's own kernel and actual parent hard-cgroup backstop.
    ///
    /// This rejoins only the payload/execution root moved by this completed
    /// Agent topology. It opens no destination and supplies no financial or
    /// child authority; the complete source is separately prepaid by Accept.
    ///
    /// # Errors
    /// Refuses a foreign or failed topology, PID 1 purpose, changed native
    /// membership, unbounded parent memory limit or mismatched kernel notes.
    pub fn capture_ssh_birth_source_once_v1(
        &self,
        payload: &GuestPayloadCgroupCustodyV1,
        execution_root: &RetainedCgroupAnchor,
        original: &mut super::ssh::source::GuestSshBirthSourceOriginalV1,
        copied_files: u32,
        highest_fd: u32,
        future_files: u64,
    ) -> Result<()> {
        let binding = (|| {
            if self.role != Some(StartupRoleV1::Agent) || !self.completed || !self.taken
                || self.failure().is_some()
            { return Err(closed()); }
            let record = self.record.ok_or_else(closed)?;
            if record.root != payload.payload.kernel_id()
                || record.execution != execution_root.kernel_id()
            { return Err(closed()); }
            Ok(self.agent_leaf.as_ref().ok_or_else(closed)?)
        })();
        original.capture_once_v1(binding, payload, execution_root, copied_files, highest_fd, future_files)
    }

    /// Reports whether the fixed native startup original was entered.
    ///
    /// This diagnostic disposition permits no cleanup or further mutation.
    #[must_use]
    pub fn requires_original_guardian_hold_v1(&self) -> bool {
        self.topology_entered
    }

    /// Stops inheritance of only the completed PID 1 handoff before systemd exec.
    ///
    /// The actual Agent was already spawned with its own FD9 table entry.
    ///
    /// # Errors
    /// Retains failed, repeated, foreign-role or incomplete native disposition.
    pub fn prepare_systemd_exec_once_v1(&mut self) -> Result<()> {
        if self.role != Some(StartupRoleV1::Pid1)
            || !self.completed
            || self.taken
            || self.failure().is_some()
        {
            return Err(closed());
        }
        self.handoff.prepare_systemd_exec_once()
    }

    /// Waits once for the already-spawned actual Agent's topology completion.
    ///
    /// The original Launch Guardian and payload BindsTo containment remain
    /// armed throughout this wait. No new deadline or retry is introduced.
    ///
    /// # Errors
    /// Retains EOF, partial, interrupted, foreign-role or repeated completion.
    pub fn wait_actual_agent_topology_once_v1(&mut self, actual_child: &PidFd) -> Result<()> {
        if self.role != Some(StartupRoleV1::Pid1)
            || !self.completed
            || self.taken
            || self.failure().is_some()
        {
            self.reentry.get_or_insert_with(closed);
            self.completed = false;
            return Err(closed());
        }
        let result = (|| {
            self.handoff.wait_pid1_once()?;
            let payload = &self.payload.as_ref().ok_or_else(closed)?.payload;
            self.agent_completion.capture_once(payload, actual_child)
        })();
        if result.is_err() {
            self.reentry.get_or_insert_with(closed);
            self.completed = false;
        }
        result
    }

    /// Borrows only PID 1's same completed native roots through its Agent spawn.
    ///
    /// Both actual owners remain here through successful systemd exec or the
    /// original Guardian's negative disposal. No path or role is reconstructed.
    #[must_use]
    pub fn borrow_pid1_parts_v1(
        &self,
    ) -> Option<(&GuestPayloadCgroupCustodyV1, &RetainedCgroupAnchor)> {
        if self.role != Some(StartupRoleV1::Pid1)
            || !self.completed
            || self.taken
            || self.failure().is_some()
        {
            return None;
        }
        Some((self.payload.as_ref()?, self.execution_root.as_ref()?))
    }

    /// Borrows the actual failed prefix; no sampling or live permission occurs.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner
            .as_ref()
            .and_then(|original| original.failure())
            .or_else(|| {
                self.inherited
                    .as_ref()
                    .and_then(|original| original.failure())
                    .or_else(|| self.handoff.failure())
                    .or_else(|| self.agent_completion.failure())
                    .or_else(|| {
                        self.tasks[0]
                            .as_ref()
                            .and_then(|original| original.failure())
                    })
                    .or_else(|| self.execution_directory.failure())
                    .or_else(|| self.agent_directory.failure())
                    .or_else(|| self.pidfd.failure().map(|cause| cause as _))
                    .or_else(|| {
                        self.identity[0]
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
                    .or_else(|| self.writes[0].failure())
                    .or_else(|| {
                        self.membership[0]
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
                    .or_else(|| {
                        self.tasks[1]
                            .as_ref()
                            .and_then(|original| original.failure())
                    })
                    .or_else(|| {
                        self.reader
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
                    .or_else(|| self.writes[1].failure())
                    .or_else(|| self.writes[2].failure())
                    .or_else(|| {
                        self.membership[1]
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
                    .or_else(|| {
                        self.identity[1]
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
                    .or_else(|| {
                        self.inherited_marks.iter().find_map(|result| {
                            result.as_ref()?.as_ref().err().map(|cause| cause as _)
                        })
                    })
                    .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
                    .or_else(|| {
                        self.after
                            .iter()
                            .flatten()
                            .find_map(|original| original.failure().map(|cause| cause as _))
                    })
                    .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            })
    }

    /// Prices the fixed original topology before the actual Guest process starts.
    ///
    /// Native read/write/directory phases close only after full positive posts;
    /// all negative phases stop and remain occupied. Steady payload/namespace
    /// and Agent descriptors are counted separately by the real Launch caller.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let directory = DirectoryOriginalV1::receiving_obligations_v1()?;
        let writer = ControlWriteOriginalV1::receiving_obligations_v1()?;
        let reader = CgroupControllerReadbackV2::receiving_obligations_v2()?;
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let membership = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let inherited = GuestPayloadCgroupCustodyOriginalV2::receiving_obligations_v2()?;
        let handoff = super::handoff::TopologyHandoffOriginalV1::receiving_obligations_v1()?;
        let completion =
            super::agent_completion::AgentCompletionOriginalV1::receiving_obligations_v1()?;
        let owner = crate::guest_confinement::GuestOwnerOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(directory.0.checked_mul(2)?)?
            .checked_add(writer.0.checked_mul(3)?)?
            .checked_add(reader.0)?
            .checked_add(active.0.checked_mul(2)?)?
            .checked_add(CgroupSingleTaskObservationV1::requested_bytes_v1()?.checked_mul(2)?)?
            .checked_add(identity.0.checked_mul(2)?)?
            .checked_add(membership.checked_mul(2)?)?
            .checked_add(2 * std::mem::size_of::<PidFdOpenAttemptV1>())?
            .checked_add(inherited.0)?
            .checked_add(2 * 256)?
            .checked_add(owner.0)?
            .checked_add(handoff.0)?
            .checked_add(completion.0)?;
        // Each positive directory/write/read phase closes before the next.
        // The before identity and own pidfd survive all remaining phases;
        // final membership+identity+two anchor posts coexist only at the end.
        // Payload/leaf/output directories belong to the separate steady census.
        let final_phase = ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1
            .checked_add(identity.1)?
            .checked_add(active.1.checked_mul(2)?)?;
        let after_placement = 1_usize.checked_add(identity.1)?.checked_add(
            reader
                .1
                .max(writer.1)
                .max(final_phase)
                .max(CgroupSingleTaskObservationV1::MAXIMUM_RETAINED_FILES_V1)
                .max(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1),
        )?;
        // Numeric FD6/7 are retired only at the final full-positive topology
        // boundary; both remain alongside any preceding topology refusal.
        let native = directory
            .1
            .max(after_placement)
            .max(CgroupSingleTaskObservationV1::MAXIMUM_RETAINED_FILES_V1)
            .checked_add(2)?
            .max(inherited.1)
            .checked_add(handoff.1)?;
        Some((
            bytes,
            native,
            directory
                .2
                .checked_mul(2)?
                .checked_add(writer.2.checked_mul(3)?)?
                .checked_add(reader.2)?
                .checked_add(active.2.checked_mul(2)?)?
                .checked_add(inherited.2)?
                .checked_add(3)?
                .checked_add(owner.2)?
                .checked_add(handoff.2)?,
        ))
    }

    /// Prices both actual startup actors and their source-ordered native peaks.
    ///
    /// The caller supplies only the canonical initial-handshake native cost
    /// from its real raw receiver. This passive arithmetic grants no resource.
    #[must_use]
    pub fn whole_guest_startup_obligations_v1(
        initial_handshake_files: usize,
    ) -> Option<(usize, usize, usize)> {
        let all = Self::receiving_obligations_v1()?;
        let parent_shape = super::agent_parent::AgentParentOriginalV1::receiving_obligations_v1()?;
        let inherited = GuestPayloadCgroupCustodyOriginalV2::receiving_obligations_v2()?;
        let initial_inherited = inherited.1.checked_sub(parent_shape.1)?;
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let reader = CgroupControllerReadbackV2::receiving_obligations_v2()?;
        let directory = DirectoryOriginalV1::receiving_obligations_v1()?;
        let sealer = crate::immutable_file::SealedReadOnlyCredentialCreateOriginalsV1
            ::receiving_footprint_v1("aos-guest-topology-handoff-v1".len(), 64)?;
        let final_before_handoff = 1_usize
            .checked_add(identity.1.checked_mul(2)?)?
            .checked_add(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?;
        let completion =
            super::agent_completion::AgentCompletionOriginalV1::receiving_obligations_v1()?;
        let pipe = super::completion::CompletionOriginalV1::receiving_obligations_v1()?;
        let common = reader.1.checked_add(1 + identity.1)?.max(directory.1);
        // PID1 failure prevents Agent spawn. Before publication, its own pidfd,
        // both identity files and final membership can coexist with the sealer.
        let pid1_native = initial_inherited
            .max(common)
            .max(final_before_handoff.checked_add(sealer.open_files)?)
            .max(completion.1)
            .checked_add(2)?
            .checked_add(pipe.1)?;
        // The Agent retains its FD9 reader through the complete inherited
        // root/actual-parent proof. Numeric6/7 remain until its final boundary.
        let agent_native = inherited.1.max(common).checked_add(1 + 2 + 1)?;
        let pid1_baseline = Self::pid1_resident_files_v1();
        let agent_baseline = Self::agent_resident_files_v1();
        // std::Command's three fixed null stdio descriptions and exec-error
        // pipe can still be in the parent as its child begins fixed startup.
        let spawning_parent_files = 3 + 2;
        let dual = pid1_baseline
            .checked_add(agent_baseline)?
            .checked_add(spawning_parent_files)?;
        let files = pid1_baseline
            .checked_add(pid1_native)?
            .max(dual.checked_add(agent_native)?)
            .max(
                dual.checked_add(initial_handshake_files)?
                    .checked_add(completion.1)?,
            );
        // Count actual shared names once across actors and observations:
        // payload anchor + three fixed descendants; root's four controls,
        // execRoot's three, and one procs name on each private leaf; two
        // calling-thread context names, two shared policy files, two task stat
        // files, five bounded memfd proc aliases, and the shared null device.
        let names = (1 + 3) + (4 + 3 + 1 + 1) + (2 + 2) + 2 + 5 + 1;
        Some((
            all.0
                .checked_mul(2)?
                .checked_add(GUEST_PID1_STARTUP_CONTROL_BYTES_V1)?
                .checked_add(identity.0)?,
            files,
            names,
        ))
    }

    /// Counts actual Agent descriptor roles after complete topology disposal.
    #[must_use]
    pub const fn agent_resident_files_v1() -> usize {
        // stdio3, raw3/4/5, payload/provisioning2, execRoot/AgentLeaf2,
        // Bridge listener1, Agent socket/peer2, original handoff9 and ACK10.
        3 + 3 + 2 + 2 + 1 + 2 + 2
    }

    /// Counts the still-unproven PID 1 parent prefix beside the Agent.
    #[must_use]
    pub const fn pid1_resident_files_v1() -> usize {
        // stdio3, raw3/4, payload/provisioning2, execRoot/init.scope2,
        // original handoff9, typed Host socket/peer2, actual child/identity2,
        // and both fresh completion pipe endpoints until their positive cut.
        // Before spawn those final two cover raw5 plus its one trust reader.
        3 + 2 + 2 + 2 + 1 + 2 + 2 + 2
    }

    /// Counts the parent's actual child-completion readback failure prefix.
    ///
    /// The Agent can reach its first handshake while PID 1 is still performing
    /// this readback. Remote Sent provides no physical retirement proof.
    #[must_use]
    pub fn pid1_completion_files_v1() -> Option<usize> {
        Some(super::agent_completion::AgentCompletionOriginalV1::receiving_obligations_v1()?.1)
    }
}

fn read_controllers(
    reader: &mut Option<Box<CgroupControllerReadbackV2>>,
    destination: &mut Option<u16>,
    anchor: &RetainedCgroupAnchor,
    available: bool,
) -> Result<()> {
    if reader.is_some() || destination.is_some() {
        return Err(closed());
    }
    *reader = Some(Box::new(if available {
        CgroupControllerReadbackV2::available_v2()
    } else {
        CgroupControllerReadbackV2::delegated_v2()
    }));
    let original = reader.as_mut().ok_or_else(closed)?;
    original.capture_once_v2(anchor).map_err(|_| closed())?;
    *destination = Some(controller_mask(original.bytes_v2().ok_or_else(closed)?)?);
    original.dispose_positive_once_v2().map_err(|_| closed())?;
    drop(reader.take());
    Ok(())
}

fn controller_mask(bytes: &[u8]) -> Result<u16> {
    let body = bytes.strip_suffix(b"\n").ok_or_else(closed)?;
    let mut mask = 0;
    if body.is_empty() {
        return Ok(mask);
    }
    for name in body.split(|byte| *byte == b' ') {
        mask |= match name {
            b"cpu" => 1,
            b"pids" => PIDS,
            b"memory" => MEMORY,
            b"cpuset" => 8,
            b"io" => 16,
            b"hugetlb" => 32,
            b"rdma" => 64,
            b"misc" => 128,
            _ => return Err(closed()),
        };
    }
    Ok(mask)
}

fn closed() -> Error {
    Error::invalid("original Guest topology", "native source remains occupied")
}
