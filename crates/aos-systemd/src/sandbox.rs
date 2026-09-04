//! Typed systemd transport for AOS sandbox transient services.
//!
//! This module deliberately does not expose systemd's generic transient-unit
//! property map.  A caller supplies a bounded command, an incarnation-derived
//! unit name, a pinned network namespace, and typed resource limits; this
//! module compiles the only property set accepted by the sandbox transport.
//! Runtime policy and nspawn argument compilation remain responsibilities of
//! the sandbox host broker.

use std::fmt;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedValue, Str, Value};

use crate::client::{JobOutcome, SystemdClient};
use crate::error::{Error, Result, is_no_such_unit};
use crate::manager_proxy::{AuxiliaryUnit, ServiceProxy, TransientProperty, UnitProxy};

const UNIT_PREFIX: &str = "aos-sandbox-";
const UNIT_SUFFIX: &str = ".service";
const GUARD_PREFIX: &str = "aos-lease-guard-";
const SANDBOX_SLICE: &str = "aos-sandboxes.slice";
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 128 * 1024;
const MAX_DEVICES: usize = 64;
const MIN_CPU_WEIGHT: u64 = 1;
const MAX_CPU_WEIGHT: u64 = 10_000;
const USEC_PER_SECOND: u64 = 1_000_000;
// This is the phase-0 candidate ceiling for the outer nspawn supervisor, not
// the payload capability set. The VM probe must pin it against the packaged
// nspawn build before the backend is enabled on a node.
const NSPAWN_SUPERVISOR_CAPABILITIES: u64 = 1
    | (1 << 1)
    | (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 10)
    | (1 << 12)
    | (1 << 18)
    | (1 << 21)
    | (1 << 27)
    | (1 << 29)
    | (1 << 31);
const NSPAWN_ADDRESS_FAMILIES: &[&str] = &["AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"];
const NSPAWN_ALLOWED_SYSCALLS: &[&str] = &[
    "@system-service",
    "chroot",
    "clone",
    "clone3",
    "fsconfig",
    "fsmount",
    "fsopen",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "pivot_root",
    "setdomainname",
    "sethostname",
    "setns",
    "umount2",
    "unshare",
];
const NSPAWN_ENVIRONMENT: &[&str] = &["LANG=C.UTF-8", "PATH=", "SYSTEMD_LOG_TARGET=journal"];
const NSPAWN_SUPERVISOR_SELINUX_CONTEXT: &str = "system_u:system_r:aos_nspawn_t:s0";
const PAYLOAD_SELINUX_CONTEXT: &str = "system_u:system_r:aos_sandbox_payload_t:s0";
const PAYLOAD_DROPPED_CAPABILITIES: &str = "CAP_AUDIT_CONTROL,CAP_AUDIT_READ,CAP_AUDIT_WRITE,CAP_BLOCK_SUSPEND,CAP_BPF,CAP_CHECKPOINT_RESTORE,CAP_DAC_READ_SEARCH,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_MAC_ADMIN,CAP_MAC_OVERRIDE,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_BROADCAST,CAP_NET_RAW,CAP_PERFMON,CAP_SYSLOG,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_CHROOT,CAP_SYS_MODULE,CAP_SYS_NICE,CAP_SYS_PACCT,CAP_SYS_PTRACE,CAP_SYS_RAWIO,CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_WAKE_ALARM";
const PAYLOAD_SYSTEM_CALL_FILTER: &str =
    "~@mount @module @raw-io @reboot bpf perf_event_open ptrace setns unshare";

/// A node-local systemd service name derived from one sandbox incarnation.
///
/// Names are opaque and flat beneath `aos-sandboxes.slice`; they intentionally
/// do not encode the logical sandbox ancestry tree.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SandboxUnitName {
    service: String,
    guardian: String,
}

impl SandboxUnitName {
    /// Derives the service and guardian names from an exact incarnation value.
    #[must_use]
    pub fn from_incarnation(incarnation: [u8; 16]) -> Self {
        let encoded = encode_hex(incarnation);
        Self {
            service: format!("{UNIT_PREFIX}{encoded}{UNIT_SUFFIX}"),
            guardian: format!("{GUARD_PREFIX}{encoded}{UNIT_SUFFIX}"),
        }
    }

    /// Returns the sandbox service unit name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.service
    }

    /// Returns the assignment guardian service required by this unit.
    #[must_use]
    pub fn guardian(&self) -> &str {
        &self.guardian
    }

    fn expected_cgroup(&self) -> String {
        format!("/{SANDBOX_SLICE}/{}", self.service)
    }
}

impl fmt::Display for SandboxUnitName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.service.fmt(formatter)
    }
}

/// A validated cgroup-v2 path for one sandbox service.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SandboxCgroupPath(String);

impl SandboxCgroupPath {
    /// Returns the path relative to the cgroup-v2 mount root.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxCgroupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A validated cgroup-v2 CPU weight in systemd's `[1, 10000]` range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuWeight(u64);

impl CpuWeight {
    /// Constructs a CPU weight accepted by systemd and cgroup v2.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] when `value` is outside
    /// `[1, 10000]`.
    pub fn new(value: u64) -> Result<Self> {
        if !(MIN_CPU_WEIGHT..=MAX_CPU_WEIGHT).contains(&value) {
            return Err(invalid(format!(
                "CPU weight must be in {MIN_CPU_WEIGHT}..={MAX_CPU_WEIGHT}"
            )));
        }
        Ok(Self(value))
    }

    /// Returns the validated systemd property value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Hard and pressure resource controls for a sandbox service cgroup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxResources {
    memory_high_bytes: u64,
    memory_max_bytes: u64,
    tasks_max: u64,
    cpu_weight: CpuWeight,
    cpu_quota_per_second: Option<Duration>,
    io_weight: Option<u64>,
    open_files: Option<u64>,
}

impl SandboxResources {
    /// Constructs mandatory memory, task, and CPU-weight limits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] for zero limits, a memory-high
    /// value above memory-max, or an invalid CPU weight.
    pub fn new(
        memory_high_bytes: u64,
        memory_max_bytes: u64,
        tasks_max: u64,
        cpu_weight: u64,
    ) -> Result<Self> {
        if memory_high_bytes == 0 || memory_max_bytes == 0 || tasks_max == 0 {
            return Err(invalid("memory and task limits must be non-zero"));
        }
        if memory_high_bytes > memory_max_bytes {
            return Err(invalid("MemoryHigh must not exceed MemoryMax"));
        }
        Ok(Self {
            memory_high_bytes,
            memory_max_bytes,
            tasks_max,
            cpu_weight: CpuWeight::new(cpu_weight)?,
            cpu_quota_per_second: None,
            io_weight: None,
            open_files: None,
        })
    }

    /// Adds a cgroup CPU quota expressed as allowed runtime in each second.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] for a zero duration, a duration
    /// above one second, or a value that cannot be represented in microseconds.
    pub fn with_cpu_quota(mut self, quota: Duration) -> Result<Self> {
        let micros = duration_micros(quota, "CPU quota")?;
        if micros > USEC_PER_SECOND {
            return Err(invalid("CPU quota must not exceed one second"));
        }
        self.cpu_quota_per_second = Some(quota);
        Ok(self)
    }

    /// Adds a cgroup-v2 I/O weight.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] unless `weight` is in
    /// `[1, 10000]`.
    pub fn with_io_weight(mut self, weight: u64) -> Result<Self> {
        if !(MIN_CPU_WEIGHT..=MAX_CPU_WEIGHT).contains(&weight) {
            return Err(invalid("I/O weight must be in 1..=10000"));
        }
        self.io_weight = Some(weight);
        Ok(self)
    }

    /// Adds a finite open-file descriptor ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] when `limit` is zero.
    pub fn with_open_file_limit(mut self, limit: u64) -> Result<Self> {
        if limit == 0 {
            return Err(invalid("open-file limit must be non-zero"));
        }
        self.open_files = Some(limit);
        Ok(self)
    }
}

/// A device class that the outer nspawn supervisor may access.
///
/// The enum prevents callers from injecting arbitrary device paths or access
/// strings into `DeviceAllow=`. Payload exposure remains separately governed
/// by the resolved nspawn profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxDevice {
    /// The KVM accelerator device, read/write.
    Kvm,
    /// The kernel TUN/TAP control device, read/write.
    Tun,
    /// The FUSE control device, read/write.
    Fuse,
}

/// Carries the two host paths resolved atomically for one launch assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxResolvedPaths {
    root_directory: String,
    network_namespace_path: String,
    _root_pin: SandboxDescriptorPath,
    _network_pin: SandboxDescriptorPath,
}

/// Carries the sole nspawn command profile accepted by the typed transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxNspawnCommand {
    executable: String,
    _executable_pin: SandboxDescriptorPath,
    incarnation: [u8; 16],
    uid_range_start: u32,
    uid_range_size: u32,
}

/// Names an owned descriptor through the broker's current procfs fd table.
///
/// Values cannot be parsed from strings. The constructor accepts a live
/// borrowed descriptor and derives both the process and descriptor numbers.
#[derive(Clone, Debug)]
pub struct SandboxDescriptorPath {
    path: String,
    _pin: Arc<OwnedFd>,
}

impl PartialEq for SandboxDescriptorPath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for SandboxDescriptorPath {}

impl SandboxDescriptorPath {
    /// Derives a descriptor path for the current broker process.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor cannot be duplicated into owned,
    /// close-on-exec storage.
    pub fn for_current_process(fd: BorrowedFd<'_>) -> std::io::Result<Self> {
        let pin = Arc::new(fd.try_clone_to_owned()?);
        Ok(Self {
            path: format!("/proc/{}/fd/{}", std::process::id(), pin.as_raw_fd()),
            _pin: pin,
        })
    }

    /// Returns the internally derived absolute procfs path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }
}

impl SandboxNspawnCommand {
    /// Constructs the fixed profile with an executable addressed by an owned descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel incarnation or invalid private identity range.
    pub fn private_user_descriptor_v1(
        executable: SandboxDescriptorPath,
        incarnation: [u8; 16],
        uid_range_start: u32,
        uid_range_size: u32,
    ) -> Result<Self> {
        if incarnation == [0; 16]
            || uid_range_start == 0
            || uid_range_size < 65_536
            || uid_range_start.checked_add(uid_range_size).is_none()
        {
            return Err(invalid("nspawn identity or private user range is invalid"));
        }
        Ok(Self {
            executable: executable.path.clone(),
            _executable_pin: executable,
            incarnation,
            uid_range_start,
            uid_range_size,
        })
    }

    fn arguments(&self, root: &str) -> Vec<String> {
        let machine = encode_hex(self.incarnation);
        vec![
            "--boot".to_owned(),
            "--quiet".to_owned(),
            "--keep-unit".to_owned(),
            "--register=no".to_owned(),
            "--settings=no".to_owned(),
            format!("--machine=aos-{machine}"),
            format!("--directory={root}"),
            format!(
                "--private-users={}:{}",
                self.uid_range_start, self.uid_range_size
            ),
            "--private-users-ownership=map".to_owned(),
            "--notify-ready=yes".to_owned(),
            format!("--selinux-context={PAYLOAD_SELINUX_CONTEXT}"),
            "--no-new-privileges=yes".to_owned(),
            format!("--drop-capability={PAYLOAD_DROPPED_CAPABILITIES}"),
            format!("--system-call-filter={PAYLOAD_SYSTEM_CALL_FILTER}"),
            "--aos-payload-seccomp-profile=aos-sandbox-payload-v1".to_owned(),
        ]
    }
}

impl SandboxResolvedPaths {
    /// Constructs launch paths solely from live broker-owned descriptors.
    #[must_use]
    pub fn from_descriptors(
        root_directory: SandboxDescriptorPath,
        network_namespace: SandboxDescriptorPath,
    ) -> Self {
        Self {
            root_directory: root_directory.path.clone(),
            network_namespace_path: network_namespace.path.clone(),
            _root_pin: root_directory,
            _network_pin: network_namespace,
        }
    }

    /// Returns the resolved private sandbox root.
    #[must_use]
    pub fn root_directory(&self) -> &str {
        &self.root_directory
    }

    /// Returns the path to the pinned prepared network namespace.
    #[must_use]
    pub fn network_namespace_path(&self) -> &str {
        &self.network_namespace_path
    }
}

impl SandboxDevice {
    fn property(self) -> (&'static str, &'static str) {
        match self {
            Self::Kvm => ("/dev/kvm", "rw"),
            Self::Tun => ("/dev/net/tun", "rw"),
            Self::Fuse => ("/dev/fuse", "rw"),
        }
    }
}

/// The complete typed input used to create one sandbox transient service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxUnitSpec {
    name: SandboxUnitName,
    command: SandboxNspawnCommand,
    arguments: Vec<String>,
    paths: SandboxResolvedPaths,
    resources: SandboxResources,
    devices: Vec<SandboxDevice>,
    timeout_start: Duration,
    timeout_stop: Duration,
}

impl SandboxUnitSpec {
    /// Constructs a closed sandbox service specification.
    ///
    /// The command owns the complete fixed argv profile; the root and network
    /// namespace paths are expected to come from one assignment-bound broker
    /// catalog resolution.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] when the command incarnation does
    /// not match the unit, the fixed argv exceeds a transport bound, or either
    /// timeout is zero or unrepresentable in microseconds.
    pub fn new_nspawn(
        name: SandboxUnitName,
        command: SandboxNspawnCommand,
        paths: SandboxResolvedPaths,
        resources: SandboxResources,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        if name != SandboxUnitName::from_incarnation(command.incarnation) {
            return Err(invalid(
                "nspawn command incarnation does not match unit name",
            ));
        }
        let arguments = command.arguments(paths.root_directory());
        validate_arguments(&arguments)?;
        duration_micros(timeout_start, "start timeout")?;
        duration_micros(timeout_stop, "stop timeout")?;

        Ok(Self {
            name,
            command,
            arguments,
            paths,
            resources,
            devices: Vec::new(),
            timeout_start,
            timeout_stop,
        })
    }

    /// Adds a typed supervisor device allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] when the list exceeds 64 entries
    /// or contains duplicate device classes.
    pub fn with_devices(mut self, devices: Vec<SandboxDevice>) -> Result<Self> {
        if devices.len() > MAX_DEVICES {
            return Err(invalid("device allowlist exceeds 64 entries"));
        }
        for (index, device) in devices.iter().enumerate() {
            if devices[..index].contains(device) {
                return Err(invalid("device allowlist contains a duplicate"));
            }
        }
        self.devices = devices;
        Ok(self)
    }

    /// Returns the incarnation-derived service name.
    #[must_use]
    pub fn name(&self) -> &SandboxUnitName {
        &self.name
    }

    /// Returns the validated absolute executable path.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.command.executable
    }

    /// Returns arguments excluding the executable `argv[0]` inserted by the
    /// typed transport.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the validated pinned network-namespace path.
    #[must_use]
    pub fn network_namespace_path(&self) -> &str {
        self.paths.network_namespace_path()
    }

    /// Returns the broker-resolved private root exposed to the supervisor.
    #[must_use]
    pub fn root_directory(&self) -> &str {
        self.paths.root_directory()
    }

    fn properties(&self) -> Result<Vec<TransientProperty>> {
        let mut argv = Vec::with_capacity(self.arguments.len() + 1);
        argv.push(self.command.executable.clone());
        argv.extend(self.arguments.iter().cloned());

        let mut properties = vec![
            string_property("Description", format!("AOS sandbox {}", self.name)),
            string_property("Type", "notify"),
            string_property("NotifyAccess", "main"),
            bool_property("Delegate", true),
            string_property("DelegateSubgroup", "supervisor"),
            string_property("Slice", SANDBOX_SLICE),
            string_property("Restart", "no"),
            string_property("CollectMode", "inactive-or-failed"),
            string_property("KillMode", "mixed"),
            string_property("OOMPolicy", "kill"),
            u64_property("CapabilityBoundingSet", NSPAWN_SUPERVISOR_CAPABILITIES),
            complex_property(
                "RestrictAddressFamilies",
                (
                    true,
                    NSPAWN_ADDRESS_FAMILIES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            complex_property(
                "SystemCallFilter",
                (
                    true,
                    NSPAWN_ALLOWED_SYSCALLS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            string_array_property("SystemCallArchitectures", vec!["native".to_owned()])?,
            string_property("ProtectSystem", "strict"),
            string_property("SELinuxContext", NSPAWN_SUPERVISOR_SELINUX_CONTEXT),
            bool_property("LockPersonality", true),
            bool_property("RestrictRealtime", true),
            string_property("KeyringMode", "private"),
            u32_property("UMask", 0o077),
            string_array_property("ReadWritePaths", vec![self.paths.root_directory.clone()])?,
            string_array_property(
                "Environment",
                NSPAWN_ENVIRONMENT
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            )?,
            bool_property("SetLoginEnvironment", false),
            string_array_property("BindsTo", vec![self.name.guardian.to_string()])?,
            string_array_property("After", vec![self.name.guardian.to_string()])?,
            u64_property("TasksMax", self.resources.tasks_max),
            u64_property("MemoryHigh", self.resources.memory_high_bytes),
            u64_property("MemoryMax", self.resources.memory_max_bytes),
            u64_property("MemorySwapMax", 0),
            u64_property("CPUWeight", self.resources.cpu_weight.get()),
            bool_property("CPUAccounting", true),
            bool_property("MemoryAccounting", true),
            bool_property("IOAccounting", true),
            bool_property("TasksAccounting", true),
            string_property("DevicePolicy", "closed"),
            string_property("NetworkNamespacePath", &self.paths.network_namespace_path),
            u64_property(
                "TimeoutStartUSec",
                duration_micros(self.timeout_start, "start timeout")?,
            ),
            u64_property(
                "TimeoutStopUSec",
                duration_micros(self.timeout_stop, "stop timeout")?,
            ),
            exec_property(&self.command.executable, argv)?,
        ];

        if let Some(quota) = self.resources.cpu_quota_per_second {
            properties.push(u64_property(
                "CPUQuotaPerSecUSec",
                duration_micros(quota, "CPU quota")?,
            ));
        }
        if let Some(weight) = self.resources.io_weight {
            properties.push(u64_property("IOWeight", weight));
        }
        if let Some(limit) = self.resources.open_files {
            properties.push(u64_property("LimitNOFILE", limit));
            properties.push(u64_property("LimitNOFILESoft", limit));
        }
        if !self.devices.is_empty() {
            let allow = self
                .devices
                .iter()
                .map(|device| {
                    let (path, permissions) = device.property();
                    (path.to_string(), permissions.to_string())
                })
                .collect::<Vec<_>>();
            properties.push(complex_property("DeviceAllow", allow)?);
        }

        Ok(properties)
    }
}

/// A typed cgroup freezer observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FreezerState {
    /// The cgroup is running.
    Running,
    /// A freeze has been requested but has not completed.
    Freezing,
    /// The cgroup and descendants are frozen.
    Frozen,
    /// A newer systemd returned a state this client does not yet classify.
    Unknown(String),
}

impl FreezerState {
    fn from_systemd(value: String) -> Self {
        match value.as_str() {
            "running" => Self::Running,
            "freezing" => Self::Freezing,
            "frozen" => Self::Frozen,
            _ => Self::Unknown(value),
        }
    }
}

/// A point-in-time observation of one transient sandbox service.
///
/// Every field is ephemeral. In particular, the supervisor PID is not the
/// guest PID 1 and must be pidfd-pinned before any namespace operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxUnitObservation {
    /// Incarnation-derived unit that was queried.
    pub unit: SandboxUnitName,
    /// systemd unit load state.
    pub load_state: String,
    /// High-level activation state.
    pub active_state: String,
    /// Service-specific activation sub-state.
    pub sub_state: String,
    /// Current cgroup freezer state.
    pub freezer_state: FreezerState,
    /// Exact validated cgroup path, absent before cgroup realization.
    pub cgroup: Option<SandboxCgroupPath>,
    /// Current nspawn supervisor PID, absent when systemd reports zero.
    pub supervisor_pid: Option<NonZeroU32>,
    /// Current systemd invocation identifier, absent when all zeroes.
    pub invocation_id: Option<[u8; 16]>,
}

impl SystemdClient {
    /// Creates and starts one typed transient sandbox service, then awaits its
    /// start job result.
    ///
    /// # Errors
    ///
    /// Returns an error when typed property compilation fails, systemd rejects
    /// the transient unit, the D-Bus connection fails, or the job result stream
    /// closes before completion.
    pub async fn start_sandbox_unit(&self, spec: &SandboxUnitSpec) -> Result<JobOutcome> {
        let properties = spec.properties()?;
        let auxiliary_units: Vec<AuxiliaryUnit> = Vec::new();
        let path = self
            .manager
            .start_transient_unit(spec.name.as_str(), "fail", &properties, &auxiliary_units)
            .await?;
        self.await_job(path).await
    }

    /// Freezes a sandbox service's complete cgroup subtree.
    ///
    /// # Errors
    ///
    /// Returns an error when systemd rejects the request or D-Bus fails.
    pub async fn freeze_sandbox_unit(&self, name: &SandboxUnitName) -> Result<()> {
        self.manager.freeze_unit(name.as_str()).await?;
        Ok(())
    }

    /// Thaws a sandbox service's complete cgroup subtree.
    ///
    /// # Errors
    ///
    /// Returns an error when systemd rejects the request or D-Bus fails.
    pub async fn thaw_sandbox_unit(&self, name: &SandboxUnitName) -> Result<()> {
        self.manager.thaw_unit(name.as_str()).await?;
        Ok(())
    }

    /// Stops one incarnation-derived sandbox service and awaits its job.
    ///
    /// # Errors
    ///
    /// Returns an error when systemd rejects the request, the D-Bus transport
    /// fails, or the job result stream closes before completion.
    pub async fn stop_sandbox_unit(&self, name: &SandboxUnitName) -> Result<JobOutcome> {
        self.stop_unit(name.as_str()).await
    }

    /// Sends `SIGKILL` to every process in one sandbox service cgroup.
    ///
    /// The signal and `all` process selector are fixed by this typed method;
    /// callers cannot use it as a generic signal-delivery API.
    ///
    /// # Errors
    ///
    /// Returns an error when systemd rejects the request or D-Bus fails.
    pub async fn kill_sandbox_unit(&self, name: &SandboxUnitName) -> Result<()> {
        self.manager
            .kill_unit(name.as_str(), "all", libc::SIGKILL)
            .await?;
        Ok(())
    }

    /// Observes the current unit, cgroup, invocation, and supervisor leader.
    ///
    /// An unloaded unit returns `Ok(None)`. The returned PID is only systemd's
    /// current service leader; callers must open a pidfd and revalidate its
    /// membership before acting on it.
    ///
    /// # Errors
    ///
    /// Returns an error for D-Bus failures, malformed invocation identifiers,
    /// or a cgroup path outside the unit's exact expected location.
    pub async fn observe_sandbox_unit(
        &self,
        name: &SandboxUnitName,
    ) -> Result<Option<SandboxUnitObservation>> {
        let path = match self.manager.get_unit(name.as_str()).await {
            Ok(path) => path,
            Err(error) if is_no_such_unit(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let unit = UnitProxy::builder(&self.conn)
            .path(path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let service = ServiceProxy::builder(&self.conn)
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;

        let invocation_id = parse_invocation_id(unit.invocation_id().await?)?;
        let cgroup = parse_cgroup(name, service.control_group().await?)?;
        Ok(Some(SandboxUnitObservation {
            unit: name.clone(),
            load_state: unit.load_state().await?,
            active_state: unit.active_state().await?,
            sub_state: unit.sub_state().await?,
            freezer_state: FreezerState::from_systemd(unit.freezer_state().await?),
            cgroup,
            supervisor_pid: NonZeroU32::new(service.main_pid().await?),
            invocation_id,
        }))
    }

    /// Returns systemd's current service leader for a sandbox unit.
    ///
    /// This is a convenience projection of [`SystemdClient::observe_sandbox_unit`]
    /// and has the same pidfd revalidation requirement.
    ///
    /// # Errors
    ///
    /// Returns any observation validation or D-Bus error.
    pub async fn sandbox_supervisor_leader(
        &self,
        name: &SandboxUnitName,
    ) -> Result<Option<NonZeroU32>> {
        Ok(self
            .observe_sandbox_unit(name)
            .await?
            .and_then(|observation| observation.supervisor_pid))
    }
}

fn encode_hex(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidSandboxUnit(message.into())
}

fn validate_arguments(arguments: &[String]) -> Result<()> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(invalid(format!(
            "command exceeds {MAX_ARGUMENTS} arguments"
        )));
    }
    let mut bytes = 0usize;
    for argument in arguments {
        if argument.as_bytes().contains(&0) {
            return Err(invalid("command argument contains NUL"));
        }
        bytes = bytes
            .checked_add(argument.len())
            .and_then(|total| total.checked_add(1))
            .ok_or_else(|| invalid("command argument size overflow"))?;
        if bytes > MAX_ARGUMENT_BYTES {
            return Err(invalid(format!(
                "command arguments exceed {MAX_ARGUMENT_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn duration_micros(duration: Duration, label: &str) -> Result<u64> {
    if duration.is_zero() {
        return Err(invalid(format!("{label} must be non-zero")));
    }
    u64::try_from(duration.as_micros())
        .map_err(|_| invalid(format!("{label} does not fit systemd's microsecond field")))
}

fn string_property(name: &str, value: impl AsRef<str>) -> TransientProperty {
    (
        name.to_string(),
        OwnedValue::from(Str::from(value.as_ref().to_string())),
    )
}

fn bool_property(name: &str, value: bool) -> TransientProperty {
    (name.to_string(), OwnedValue::from(value))
}

fn u64_property(name: &str, value: u64) -> TransientProperty {
    (name.to_string(), OwnedValue::from(value))
}

fn u32_property(name: &str, value: u32) -> TransientProperty {
    (name.to_string(), OwnedValue::from(value))
}

fn string_array_property(name: &str, value: Vec<String>) -> Result<TransientProperty> {
    complex_property(name, value)
}

fn exec_property(executable: &str, argv: Vec<String>) -> Result<TransientProperty> {
    complex_property("ExecStart", vec![(executable.to_string(), argv, false)])
}

fn complex_property<T>(name: &str, value: T) -> Result<TransientProperty>
where
    T: Into<Value<'static>>,
{
    let dynamic: Value<'static> = value.into();
    let value = OwnedValue::try_from(dynamic)
        .map_err(|error| invalid(format!("cannot encode {name}: {error}")))?;
    Ok((name.to_string(), value))
}

fn parse_invocation_id(bytes: Vec<u8>) -> Result<Option<[u8; 16]>> {
    let value: [u8; 16] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        invalid(format!(
            "systemd returned a {}-byte invocation ID, expected 16",
            bytes.len()
        ))
    })?;
    Ok((value != [0; 16]).then_some(value))
}

fn parse_cgroup(name: &SandboxUnitName, path: String) -> Result<Option<SandboxCgroupPath>> {
    if path.is_empty() {
        return Ok(None);
    }
    let expected = name.expected_cgroup();
    if path != expected {
        return Err(invalid(format!(
            "unit {} reported cgroup {path:?}, expected {expected:?}",
            name.as_str()
        )));
    }
    Ok(Some(SandboxCgroupPath(path)))
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use super::*;

    fn descriptor_path(path: &str) -> SandboxDescriptorPath {
        let file = std::fs::File::open(path).unwrap();
        SandboxDescriptorPath::for_current_process(file.as_fd()).unwrap()
    }

    fn command(incarnation: [u8; 16]) -> SandboxNspawnCommand {
        SandboxNspawnCommand::private_user_descriptor_v1(
            descriptor_path("/proc/self/exe"),
            incarnation,
            65_536,
            65_536,
        )
        .unwrap()
    }

    fn paths() -> SandboxResolvedPaths {
        SandboxResolvedPaths::from_descriptors(
            descriptor_path("/"),
            descriptor_path("/proc/self/ns/net"),
        )
    }

    fn fixture() -> SandboxUnitSpec {
        let resources = SandboxResources::new(512, 1024, 128, 100)
            .and_then(|value| value.with_cpu_quota(Duration::from_millis(500)))
            .and_then(|value| value.with_io_weight(200))
            .and_then(|value| value.with_open_file_limit(1024))
            .unwrap();
        SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation([0xab; 16]),
            command([0xab; 16]),
            paths(),
            resources,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .and_then(|value| value.with_devices(vec![SandboxDevice::Tun]))
        .unwrap()
    }

    #[test]
    fn names_are_flat_canonical_projections() {
        let name = SandboxUnitName::from_incarnation([0xab; 16]);
        assert_eq!(
            name.as_str(),
            "aos-sandbox-abababababababababababababababab.service"
        );
        assert_eq!(
            name.guardian(),
            "aos-lease-guard-abababababababababababababababab.service"
        );
    }

    #[test]
    fn resource_bounds_fail_closed() {
        assert!(SandboxResources::new(2, 1, 1, 100).is_err());
        assert!(SandboxResources::new(1, 1, 0, 100).is_err());
        assert!(SandboxResources::new(1, 1, 1, 0).is_err());
        assert!(SandboxResources::new(1, 1, 1, 10_001).is_err());
    }

    #[test]
    fn command_and_namespace_paths_are_bounded_and_normalized() {
        assert!(
            SandboxNspawnCommand::private_user_descriptor_v1(
                descriptor_path("/proc/self/exe"),
                [1; 16],
                0,
                65_536
            )
            .is_err()
        );

        let resources = SandboxResources::new(1, 1, 1, 1).unwrap();
        assert!(
            SandboxUnitSpec::new_nspawn(
                SandboxUnitName::from_incarnation([1; 16]),
                command([2; 16]),
                paths(),
                resources,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .is_err()
        );
    }

    #[test]
    fn descriptor_launch_paths_are_derived_and_expire_with_ownership() {
        let executable = std::fs::File::open("/proc/self/exe").unwrap();
        let root = std::fs::File::open("/").unwrap();
        let network = std::fs::File::open("/proc/self/ns/net").unwrap();
        let executable_path =
            SandboxDescriptorPath::for_current_process(executable.as_fd()).unwrap();
        let root_path = SandboxDescriptorPath::for_current_process(root.as_fd()).unwrap();
        let network_path = SandboxDescriptorPath::for_current_process(network.as_fd()).unwrap();
        let expired = root_path.as_str().to_owned();
        let spec = SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation([1; 16]),
            SandboxNspawnCommand::private_user_descriptor_v1(
                executable_path,
                [1; 16],
                65_536,
                65_536,
            )
            .unwrap(),
            SandboxResolvedPaths::from_descriptors(root_path, network_path),
            SandboxResources::new(1, 1, 1, 1).unwrap(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let prefix = format!("/proc/{}/fd/", std::process::id());
        assert!(spec.executable().starts_with(&prefix));
        assert!(spec.root_directory().starts_with(&prefix));
        assert!(spec.network_namespace_path().starts_with(&prefix));
        assert!(
            spec.arguments()
                .iter()
                .any(|argument| argument == &format!("--directory={}", spec.root_directory()))
        );

        drop(root);
        assert!(std::fs::metadata(&expired).is_ok());
        drop(spec);
        assert!(std::fs::metadata(expired).is_err());
    }

    #[test]
    fn property_set_is_closed_and_has_exact_dbus_shapes() {
        let properties = fixture().properties().unwrap();
        let names = properties
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "Description",
                "Type",
                "NotifyAccess",
                "Delegate",
                "DelegateSubgroup",
                "Slice",
                "Restart",
                "CollectMode",
                "KillMode",
                "OOMPolicy",
                "CapabilityBoundingSet",
                "RestrictAddressFamilies",
                "SystemCallFilter",
                "SystemCallArchitectures",
                "ProtectSystem",
                "SELinuxContext",
                "LockPersonality",
                "RestrictRealtime",
                "KeyringMode",
                "UMask",
                "ReadWritePaths",
                "Environment",
                "SetLoginEnvironment",
                "BindsTo",
                "After",
                "TasksMax",
                "MemoryHigh",
                "MemoryMax",
                "MemorySwapMax",
                "CPUWeight",
                "CPUAccounting",
                "MemoryAccounting",
                "IOAccounting",
                "TasksAccounting",
                "DevicePolicy",
                "NetworkNamespacePath",
                "TimeoutStartUSec",
                "TimeoutStopUSec",
                "ExecStart",
                "CPUQuotaPerSecUSec",
                "IOWeight",
                "LimitNOFILE",
                "LimitNOFILESoft",
                "DeviceAllow",
            ]
        );

        let signatures = properties
            .iter()
            .map(|(name, value)| (name.as_str(), value.value_signature().to_string()))
            .collect::<Vec<_>>();
        assert!(signatures.contains(&("ExecStart", "a(sasb)".to_string())));
        assert!(signatures.contains(&("DeviceAllow", "a(ss)".to_string())));
        assert!(signatures.contains(&("BindsTo", "as".to_string())));
        assert!(signatures.contains(&("CapabilityBoundingSet", "t".to_string())));
        assert!(signatures.contains(&("RestrictAddressFamilies", "(bas)".to_string())));
        assert!(signatures.contains(&("SystemCallFilter", "(bas)".to_string())));
        assert!(signatures.contains(&("SystemCallArchitectures", "as".to_string())));
        assert!(signatures.contains(&("SELinuxContext", "s".to_string())));
        assert!(signatures.contains(&("ReadWritePaths", "as".to_string())));
        assert!(signatures.contains(&("MemorySwapMax", "t".to_string())));
        assert!(signatures.contains(&("LimitNOFILE", "t".to_string())));
    }

    #[test]
    fn invocation_and_cgroup_observations_are_strict() {
        assert_eq!(parse_invocation_id(vec![0; 16]).unwrap(), None);
        assert_eq!(parse_invocation_id(vec![7; 16]).unwrap(), Some([7; 16]));
        assert!(parse_invocation_id(vec![7; 15]).is_err());

        let name = SandboxUnitName::from_incarnation([3; 16]);
        let path = name.expected_cgroup();
        assert_eq!(
            parse_cgroup(&name, path.clone()).unwrap().unwrap().as_str(),
            path
        );
        assert!(parse_cgroup(&name, "/system.slice/other.service".into()).is_err());
    }
}
