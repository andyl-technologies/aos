//! Retains Host's shifted-target inspection on the original readonly manager.
//!
//! A complete observation is deployment DATA, not backend readiness. The
//! actual Phase0 owner prepays this whole native/property destination and keeps
//! the same control, Source, package and paired-clock posts independently.

use std::error::Error as StdError;
use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{
    ExactCgroupMembershipReadbackV1, HostPhase0TargetCgroupReadbackV2, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::pidfd::PidFdNamespaceOriginalV2;
use aos_sandbox_linux::pidfd::PidFdOpenAttemptV1;
use aos_systemd_client::{ServiceControlGroupReadOriginalV2, ServicePropertiesReadOriginalV2};

use super::*;

const TARGET_CGROUP: &str = "/system.slice/aos-sandbox-host-phase0-target.service";
// Reuse the selected Host startup status read's existing bounded proc contract.
const STATUS_BYTES: usize = 65_536;

#[derive(Clone, Copy)]
enum First {
    Policy(usize),
    Host(usize),
    Target(usize),
    Service(usize),
    Status(usize),
    Opening,
    BeforeInfo,
    Cgroup,
    Membership(usize),
    Namespace(usize),
    AfterInfo,
    Alive,
    Reentry,
}

/// Reports a retained, incomplete or repeated shifted-target inspection.
#[derive(Debug, thiserror::Error)]
#[error("original Host shifted-target verification remains closed")]
pub(in crate::plan::deployment) struct HostShiftedTargetClosedV2;

/// Retains the actual service, process, cgroup, namespace and status prefixes.
///
/// All manager calls use the supplied same Arc. The two exact-membership
/// observations use the same retained root/anchor and pidfd, while each active
/// probe and each namespace acquisition has its own native destination.
pub(in crate::plan::deployment) struct HostShiftedTargetOriginalV2 {
    host: [ServicePropertiesReadOriginalV2; 2],
    target: [ServicePropertiesReadOriginalV2; 2],
    service: [ServiceControlGroupReadOriginalV2; 2],
    status: [StatusOriginalV2; 2],
    opening: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    before_info: Option<aos_linux_descriptors::Result<PidFdInfo>>,
    cgroup: HostPhase0TargetCgroupReadbackV2,
    root: Option<CgroupV2Root>,
    anchor: Option<RetainedCgroupAnchor>,
    membership: [ExactCgroupMembershipReadbackV1; 2],
    namespace: [PidFdNamespaceOriginalV2; 4],
    namespaces: [Option<NamespaceFd>; 4],
    after_info: Option<aos_linux_descriptors::Result<PidFdInfo>>,
    alive: Option<aos_linux_descriptors::Result<bool>>,
    policies: [Option<Result<()>>; 16],
    first: Option<First>,
    reentry: Option<HostError>,
    entered: bool,
    native_entered: bool,
    complete: bool,
}

impl HostShiftedTargetOriginalV2 {
    /// Creates inert destinations without a query, connection or native open.
    pub(in crate::plan::deployment) fn new() -> Self {
        Self {
            host: std::array::from_fn(|_| ServicePropertiesReadOriginalV2::new()),
            target: std::array::from_fn(|_| ServicePropertiesReadOriginalV2::new()),
            service: std::array::from_fn(|_| ServiceControlGroupReadOriginalV2::new()),
            status: std::array::from_fn(|_| StatusOriginalV2::new()),
            opening: PidFdOpenAttemptV1::new(),
            process: None,
            before_info: None,
            cgroup: HostPhase0TargetCgroupReadbackV2::new(),
            root: None,
            anchor: None,
            membership: std::array::from_fn(|_| ExactCgroupMembershipReadbackV1::new()),
            namespace: std::array::from_fn(|_| PidFdNamespaceOriginalV2::new()),
            namespaces: std::array::from_fn(|_| None),
            after_info: None,
            alive: None,
            policies: std::array::from_fn(|_| None),
            first: None,
            reentry: None,
            entered: false,
            native_entered: false,
            complete: false,
        }
    }

    /// Quotes actual native custody and the pure fixed-profile comparison work.
    ///
    /// The enclosing same-manager schedule separately pays the 90 existing
    /// calls and their raw/decoded property backing: 2*(14+3), 2*(12+6),
    /// and 2*10. This quote adds no manager connection or RPC invoice.
    pub(in crate::plan::deployment) fn receiving_demand_v2() -> Option<ResourceVector> {
        let (cgroup_memory, cgroup_files, names) =
            HostPhase0TargetCgroupReadbackV2::receiving_obligations_v2()?;
        let membership_memory = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let membership_dynamic =
            membership_memory.checked_sub(std::mem::size_of::<ExactCgroupMembershipReadbackV1>())?;
        let mut memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                cgroup_memory
                    .checked_sub(2 * std::mem::size_of::<HostPhase0TargetCgroupReadbackV2>())?,
            )?
            .checked_add(2 * membership_dynamic)?;
        // Property archive inline carriers are already in Self. Only the
        // actual table arrays and bounded copied unit names are additional.
        for count in [
            HOST_FILTER_PROPERTIES.len(),
            TARGET_HARDENING_PROPERTIES.len(),
        ] {
            let extra = ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(count, 0)?
                .checked_sub(2 * std::mem::size_of::<ServicePropertiesReadOriginalV2>())?;
            memory = memory.checked_add(2 * extra)?;
        }
        // Two retained bounded reads, each reserving max+1 before read_to_end;
        // the std reader's separate 32-byte probe can coexist with that Vec.
        memory = memory
            .checked_add(2 * (STATUS_BYTES + 1 + 32))?
            .checked_add(host_filter_comparison_bytes_v2()?)?
            // Every fixed policy/result slot can own its original diagnostic.
            // Use the actual longest literal of these shared pure predicates;
            // these String bytes are Memory, never namespace entries.
            .checked_add((16 + 2 + 1) *
                "Host NNP or installed seccomp filter is absent during shifted-target inspection".len())?;
        // The fixed cgroup capture, pidfd opening, two info Results, liveness
        // Result and four namespace Results can each retain one native String
        // diagnostic. Their fixed-path native messages fit the same literal
        // bound above; the membership supplier already prices its own errors.
        memory = memory.checked_add(
            (1 + 1 + 2 + 1 + 4)
                * "Host NNP or installed seccomp filter is absent during shifted-target inspection"
                    .len(),
        )?;
        let files = cgroup_files
            .checked_add(1)? // actual target pidfd
            .checked_add(4)? // four retained namespace originals
            .checked_add(2 * ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?
            .checked_add(2)?; // independently retained status files
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                // Membership probes reuse the fixed reader's cgroup.procs entry.
                .with(
                    D::MetadataEntries,
                    u64::try_from(names.checked_add(1)?).ok()?,
                )
                .with(D::OutputBytes, u64::try_from(2 * (STATUS_BYTES + 1)).ok()?),
        )
    }

    /// Observes the fixed target and always finishes entered native bookends.
    ///
    /// The caller supplies its actual already-paid manager and canonical signed
    /// probe expectation. Reentry observes nothing and preserves earlier causes.
    pub(in crate::plan::deployment) async fn observe_once_v2(
        &mut self,
        systemd: &Arc<SystemdClient>,
        expected: Phase0ProbeObservationV2,
    ) -> std::result::Result<(), HostShiftedTargetClosedV2> {
        if self.entered {
            self.reentry
                .get_or_insert_with(|| state("shifted target already inspected"));
            self.first.get_or_insert(First::Reentry);
            return Err(HostShiftedTargetClosedV2);
        }
        self.entered = true;
        let primary = self.observe_body(systemd, expected).await;
        if self.native_entered {
            // These destinations are independent of primary success. Later
            // errors cannot replace the selected earlier native/semantic cause.
            self.observe_native_after(systemd, expected).await;
        }
        self.complete = primary.is_ok() && self.first.is_none();
        if self.complete {
            Ok(())
        } else {
            Err(HostShiftedTargetClosedV2)
        }
    }

    async fn observe_body(
        &mut self,
        systemd: &Arc<SystemdClient>,
        expected: Phase0ProbeObservationV2,
    ) -> std::result::Result<(), HostShiftedTargetClosedV2> {
        let pid = std::process::id();
        if self.host[0]
            .observe_startup_once_v2(systemd, HOST_SERVICE, pid, HOST_FILTER_PROPERTIES, &[])
            .await
            .is_err()
        {
            self.select(First::Host(0));
            return Err(HostShiftedTargetClosedV2);
        }
        self.policy(
            0,
            require_host_filter_shape_v2(self.host[0].service_values_v2()),
        )?;
        self.policy(
            1,
            verify_host_filter_properties(
                self.host[0]
                    .service_values_v2()
                    .ok_or(HostShiftedTargetClosedV2)?,
            ),
        )?;
        if self.status[0].observe().is_err() {
            self.select(First::Status(0));
            return Err(HostShiftedTargetClosedV2);
        }
        if self.service[0]
            .observe_once_v2(systemd, PROBE_TARGET_SERVICE)
            .await
            .is_err()
        {
            self.select(First::Service(0));
            return Err(HostShiftedTargetClosedV2);
        }
        let service = self.service[0]
            .completed_v2()
            .ok_or(HostShiftedTargetClosedV2)?;
        let service_pid = service.main_pid;
        self.policy(
            2,
            verify_shifted_service_pid(expected.target_pid, service_pid.get()),
        )?;
        self.policy(
            3,
            if self.service[0]
                .completed_v2()
                .map(|s| s.control_group.as_str())
                == Some(TARGET_CGROUP)
            {
                Ok(())
            } else {
                Err(state("shifted target cgroup differs from the fixed role"))
            },
        )?;
        if self.target[0]
            .observe_once_v2(
                systemd,
                PROBE_TARGET_SERVICE,
                expected.target_pid,
                TARGET_HARDENING_PROPERTIES,
                &[],
            )
            .await
            .is_err()
        {
            self.select(First::Target(0));
            return Err(HostShiftedTargetClosedV2);
        }
        self.policy(
            4,
            verify_target_unit_hardening(
                self.target[0]
                    .service_values_v2()
                    .ok_or(HostShiftedTargetClosedV2)?,
            ),
        )?;
        self.native_entered = true;
        if self.opening.capture_once(service_pid).is_err() {
            self.select(First::Opening);
            return Err(HostShiftedTargetClosedV2);
        }
        self.process = self.opening.take_validated();
        self.before_info = Some(
            self.process
                .as_ref()
                .ok_or(HostShiftedTargetClosedV2)?
                .info(),
        );
        let before = match self.before_info.as_ref() {
            Some(Ok(value)) => *value,
            _ => {
                self.select(First::BeforeInfo);
                return Err(HostShiftedTargetClosedV2);
            }
        };
        self.policy(
            5,
            verify_shifted_process_identity(
                expected.target_pid,
                before.pid(),
                before.thread_group_id(),
                before.parent_pid(),
            ),
        )?;
        if self.cgroup.capture_once().is_err() {
            self.select(First::Cgroup);
            return Err(HostShiftedTargetClosedV2);
        }
        let (root, anchor) = self
            .cgroup
            .take_validated_pair()
            .ok_or(HostShiftedTargetClosedV2)?;
        self.root = Some(root);
        self.anchor = Some(anchor);
        if self.membership[0]
            .capture_once(
                self.anchor.as_ref().ok_or(HostShiftedTargetClosedV2)?,
                self.process.as_ref().ok_or(HostShiftedTargetClosedV2)?,
            )
            .is_err()
        {
            self.select(First::Membership(0));
            return Err(HostShiftedTargetClosedV2);
        }
        let membership = self.membership[0]
            .result()
            .and_then(|r| r.as_ref().ok())
            .copied();
        self.policy(
            6,
            if membership.and_then(|m| m.cgroup_id()) == Some(expected.cgroup_id) {
                Ok(())
            } else {
                Err(state("shifted target cgroup differs from the signed probe"))
            },
        )?;
        for (index, (kind, identity)) in [
            (NamespaceKind::User, expected.user),
            (NamespaceKind::Mount, expected.mount),
            (NamespaceKind::Network, expected.network),
            (NamespaceKind::Pid, expected.pid),
        ]
        .into_iter()
        .enumerate()
        {
            if self.namespace[index]
                .capture_once(
                    self.process.as_ref().ok_or(HostShiftedTargetClosedV2)?,
                    kind,
                )
                .is_err()
            {
                self.select(First::Namespace(index));
                return Err(HostShiftedTargetClosedV2);
            }
            self.namespaces[index] = self.namespace[index].take_completed_once();
            self.policy(
                7 + index,
                if self.namespaces[index].as_ref().map(|n| n.identity()) == Some(identity) {
                    Ok(())
                } else {
                    Err(state("shifted namespace differs from the signed probe"))
                },
            )?;
        }
        Ok(())
    }

    async fn observe_native_after(
        &mut self,
        systemd: &Arc<SystemdClient>,
        expected: Phase0ProbeObservationV2,
    ) {
        if let Some(process) = self.process.as_ref() {
            self.after_info = Some(process.info());
            if matches!(self.after_info, Some(Err(_))) {
                self.select(First::AfterInfo);
            }
        }
        if self.target[1]
            .observe_once_v2(
                systemd,
                PROBE_TARGET_SERVICE,
                expected.target_pid,
                TARGET_HARDENING_PROPERTIES,
                &[],
            )
            .await
            .is_err()
        {
            self.select(First::Target(1));
        } else {
            let result = self.target[1]
                .service_values_v2()
                .ok_or_else(|| state("target after properties absent"))
                .and_then(verify_target_unit_hardening);
            let _post = self.policy(11, result);
        }
        if self.host[1]
            .observe_startup_once_v2(
                systemd,
                HOST_SERVICE,
                std::process::id(),
                HOST_FILTER_PROPERTIES,
                &[],
            )
            .await
            .is_err()
        {
            self.select(First::Host(1));
        } else {
            let result =
                require_host_filter_shape_v2(self.host[1].service_values_v2()).and_then(|()| {
                    self.host[1]
                        .service_values_v2()
                        .ok_or_else(|| state("Host after properties absent"))
                        .and_then(verify_host_filter_properties)
                });
            let _post = self.policy(12, result);
        }
        if self.status[1].observe().is_err() {
            self.select(First::Status(1));
        }
        if let (Some(anchor), Some(process)) = (self.anchor.as_ref(), self.process.as_ref()) {
            if self.membership[1].capture_once(anchor, process).is_err() {
                self.select(First::Membership(1));
            }
        }
        if let Some(process) = self.process.as_ref() {
            self.alive = Some(process.is_alive());
            if matches!(self.alive, Some(Err(_))) {
                self.select(First::Alive);
            }
        }
        if self.service[1]
            .observe_once_v2(systemd, PROBE_TARGET_SERVICE)
            .await
            .is_err()
        {
            self.select(First::Service(1));
        }
        let unchanged = matches!((&self.before_info, &self.after_info), (Some(Ok(a)), Some(Ok(b))) if a == b)
            && matches!(self.alive, Some(Ok(true)))
            && self.membership[0]
                .result()
                .and_then(|r| r.as_ref().ok())
                .zip(self.membership[1].result().and_then(|r| r.as_ref().ok()))
                .is_some_and(|(a, b)| a == b)
            && self.service[0]
                .completed_v2()
                .zip(self.service[1].completed_v2())
                .is_some_and(|(a, b)| a == b);
        let _post = self.policy(
            13,
            if unchanged {
                Ok(())
            } else {
                Err(state("shifted target changed during Host pidfd inspection"))
            },
        );
    }

    fn select(&mut self, first: First) {
        self.first.get_or_insert(first);
    }

    fn policy(
        &mut self,
        index: usize,
        result: Result<()>,
    ) -> std::result::Result<(), HostShiftedTargetClosedV2> {
        let failed = result.is_err();
        self.policies[index] = Some(result);
        if failed {
            self.select(First::Policy(index));
            Err(HostShiftedTargetClosedV2)
        } else {
            Ok(())
        }
    }

    /// Retires the same manager's aliases only after the whole leaf succeeds.
    ///
    /// The enclosing Phase0 owner calls this before physical manager disposal.
    /// Partial and failed observations keep all their native proxy prefixes.
    pub(in crate::plan::deployment) fn retire_completed_native_aliases_v2(&mut self) -> bool {
        if !self.complete {
            return false;
        }
        let mut retired = true;
        for original in self.host.iter_mut().chain(self.target.iter_mut()) {
            retired &= original.retire_completed_native_aliases_v2();
        }
        for original in &mut self.service {
            retired &= original.retire_completed_native_aliases_v2();
        }
        retired
    }

    /// Borrows the exact cause selected before any later independently owed post.
    pub(in crate::plan::deployment) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        fn error<T, E: StdError + 'static>(
            r: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn StdError + 'static)> {
            r.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn StdError)
        }
        match self.first? {
            First::Policy(i) => error(&self.policies[i]),
            First::Host(i) => self.host[i].failure().map(|e| e as &dyn StdError),
            First::Target(i) => self.target[i].failure().map(|e| e as &dyn StdError),
            First::Service(i) => self.service[i].failure().map(|e| e as &dyn StdError),
            First::Status(i) => self.status[i].failure(),
            First::Opening => self.opening.failure().map(|e| e as &dyn StdError),
            First::BeforeInfo => error(&self.before_info),
            First::Cgroup => self.cgroup.failure(),
            First::Membership(i) => self.membership[i].failure().map(|e| e as &dyn StdError),
            First::Namespace(i) => self.namespace[i].failure().map(|e| e as &dyn StdError),
            First::AfterInfo => error(&self.after_info),
            First::Alive => error(&self.alive),
            First::Reentry => self.reentry.as_ref().map(|e| e as &dyn StdError),
        }
    }
}

struct StatusOriginalV2 {
    open: Option<std::io::Result<File>>,
    bytes: Vec<u8>,
    read: Option<std::result::Result<(), StartupFailure>>,
    utf8: Option<std::result::Result<(), std::str::Utf8Error>>,
    policy: Option<Result<()>>,
}

impl StatusOriginalV2 {
    fn new() -> Self {
        Self {
            open: None,
            bytes: Vec::new(),
            read: None,
            utf8: None,
            policy: None,
        }
    }

    fn observe(&mut self) -> std::result::Result<(), HostShiftedTargetClosedV2> {
        self.open = Some(File::open("/proc/self/status"));
        let Some(Ok(file)) = self.open.as_mut() else {
            return Err(HostShiftedTargetClosedV2);
        };
        self.read = Some(read_bounded_original(file, &mut self.bytes, STATUS_BYTES));
        if !matches!(self.read, Some(Ok(()))) {
            return Err(HostShiftedTargetClosedV2);
        }
        let text = std::str::from_utf8(&self.bytes);
        self.utf8 = Some(text.as_ref().map(|_| ()).map_err(|e| *e));
        let Ok(text) = text else {
            return Err(HostShiftedTargetClosedV2);
        };
        self.policy = Some(verify_zero_capability_status(text));
        if matches!(self.policy, Some(Ok(()))) {
            Ok(())
        } else {
            Err(HostShiftedTargetClosedV2)
        }
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.open
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(|e| e as &dyn StdError)
            .or_else(|| {
                self.read
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .map(|e| e as &dyn StdError)
            })
            .or_else(|| {
                self.utf8
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .map(|e| e as &dyn StdError)
            })
            .or_else(|| {
                self.policy
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .map(|e| e as &dyn StdError)
            })
    }
}

fn state(message: &str) -> HostError {
    HostError::State(message.to_owned())
}

#[cfg(target_arch = "x86_64")]
fn host_filter_comparison_bytes_v2() -> Option<usize> {
    let strings = HOST_SYSCALL_PROFILE.bytes().filter(|b| *b == b'"').count() / 2;
    // The guard below bounds cloned Value array cells and converted String
    // cells by this very canonical schema. Separate Vec old/new growth for
    // conversion and JSON decoding, typed text, parsed text, and JSON scratch
    // can coexist. No namespace entry comes from these Rust allocations.
    strings
        .checked_mul(3 * std::mem::size_of::<Value<'static>>() + 6 * std::mem::size_of::<String>())?
        .checked_add(5 * HOST_SYSCALL_PROFILE.len())?
        .checked_add(std::mem::size_of::<HostSyscallProfileV1>())?
        .checked_add(6 * std::mem::size_of::<Value<'static>>())
}

#[cfg(not(target_arch = "x86_64"))]
fn host_filter_comparison_bytes_v2() -> Option<usize> {
    Some(0)
}

#[cfg(target_arch = "x86_64")]
fn require_host_filter_shape_v2(values: Option<&[OwnedValue]>) -> Result<()> {
    let Some([filter, architectures, _]) = values else {
        return Err(state("Host seccomp readback is incomplete"));
    };
    let Value::Structure(filter) = &**filter else {
        return Err(state("Host seccomp filter is malformed"));
    };
    let [Value::Bool(_), Value::Array(syscalls)] = filter.fields() else {
        return Err(state("Host seccomp filter is malformed"));
    };
    let Value::Array(architectures) = &**architectures else {
        return Err(state("Host seccomp architectures are malformed"));
    };
    let maximum = HOST_SYSCALL_PROFILE.bytes().filter(|b| *b == b'"').count() / 2;
    let mut cells = 0_usize;
    let mut bytes = 0_usize;
    for value in syscalls.inner().iter().chain(architectures.inner()) {
        let Value::Str(name) = value else {
            return Err(state("Host seccomp string is malformed"));
        };
        cells = cells
            .checked_add(1)
            .ok_or_else(|| state("Host seccomp shape overflow"))?;
        bytes = bytes
            .checked_add(name.len())
            .ok_or_else(|| state("Host seccomp shape overflow"))?;
        if cells > maximum || bytes > HOST_SYSCALL_PROFILE.len() {
            return Err(state("Host seccomp differs from the fixed profile shape"));
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn require_host_filter_shape_v2(_values: Option<&[OwnedValue]>) -> Result<()> {
    Err(state(
        "Host phase-0 seccomp profile is not qualified for this architecture",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_policy_cause_is_not_replaced_by_later_after_or_reentry() {
        let mut original = HostShiftedTargetOriginalV2::new();
        assert!(original.policy(0, Err(state("before failed"))).is_err());
        let first = original.failure().unwrap() as *const dyn StdError;

        assert!(original.policy(13, Err(state("after failed"))).is_err());
        original.reentry = Some(state("reentry"));
        original.select(First::Reentry);

        assert!(std::ptr::eq(original.failure().unwrap(), first));
        assert!(!original.complete);
    }

    #[test]
    fn quote_preserves_real_native_fds_and_fixed_namespace_names() {
        let demand = HostShiftedTargetOriginalV2::receiving_demand_v2().unwrap();
        let (_, cgroup_files, names) =
            HostPhase0TargetCgroupReadbackV2::receiving_obligations_v2().unwrap();
        assert_eq!(
            demand.get(D::OpenFiles),
            (cgroup_files + 1 + 4 + 4 + 2) as u64
        );
        assert_eq!(demand.get(D::MetadataEntries), (names + 1) as u64);
    }
}
