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
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_DEVICES: usize = 64;
const MIN_CPU_WEIGHT: u64 = 1;
const MAX_CPU_WEIGHT: u64 = 10_000;
const USEC_PER_SECOND: u64 = 1_000_000;

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
    executable: String,
    arguments: Vec<String>,
    network_namespace_path: String,
    resources: SandboxResources,
    devices: Vec<SandboxDevice>,
    timeout_start: Duration,
    timeout_stop: Duration,
}

impl SandboxUnitSpec {
    /// Constructs a closed sandbox service specification.
    ///
    /// `arguments` excludes argument zero; the compiler always uses the exact
    /// executable path as `argv[0]`. The network namespace path is expected to
    /// name a broker-pinned namespace descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSandboxUnit`] when a path or argument is empty,
    /// non-absolute where required, contains NUL, exceeds a transport bound,
    /// or when either timeout is zero or unrepresentable in microseconds.
    pub fn new(
        name: SandboxUnitName,
        executable: impl Into<String>,
        arguments: Vec<String>,
        network_namespace_path: impl Into<String>,
        resources: SandboxResources,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        let executable = executable.into();
        let network_namespace_path = network_namespace_path.into();
        validate_absolute_path(&executable, "executable")?;
        validate_absolute_path(&network_namespace_path, "network namespace")?;
        validate_arguments(&arguments)?;
        duration_micros(timeout_start, "start timeout")?;
        duration_micros(timeout_stop, "stop timeout")?;

        Ok(Self {
            name,
            executable,
            arguments,
            network_namespace_path,
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

    fn properties(&self) -> Result<Vec<TransientProperty>> {
        let mut argv = Vec::with_capacity(self.arguments.len() + 1);
        argv.push(self.executable.clone());
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
            string_array_property("BindsTo", vec![self.name.guardian.to_string()])?,
            string_array_property("After", vec![self.name.guardian.to_string()])?,
            u64_property("TasksMax", self.resources.tasks_max),
            u64_property("MemoryHigh", self.resources.memory_high_bytes),
            u64_property("MemoryMax", self.resources.memory_max_bytes),
            u64_property("CPUWeight", self.resources.cpu_weight.get()),
            string_property("DevicePolicy", "closed"),
            string_property("NetworkNamespacePath", &self.network_namespace_path),
            u64_property(
                "TimeoutStartUSec",
                duration_micros(self.timeout_start, "start timeout")?,
            ),
            u64_property(
                "TimeoutStopUSec",
                duration_micros(self.timeout_stop, "stop timeout")?,
            ),
            exec_property(&self.executable, argv)?,
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

fn validate_absolute_path(path: &str, label: &str) -> Result<()> {
    if path.is_empty() || !path.starts_with('/') || path.len() > MAX_PATH_BYTES {
        return Err(invalid(format!(
            "{label} path must be absolute, non-empty, and at most {MAX_PATH_BYTES} bytes"
        )));
    }
    if path.as_bytes().contains(&0) || path.split('/').any(|component| component == "..") {
        return Err(invalid(format!("{label} path is not normalized")));
    }
    Ok(())
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
    use super::*;

    fn fixture() -> SandboxUnitSpec {
        let resources = SandboxResources::new(512, 1024, 128, 100)
            .and_then(|value| value.with_cpu_quota(Duration::from_millis(500)))
            .and_then(|value| value.with_io_weight(200))
            .unwrap();
        SandboxUnitSpec::new(
            SandboxUnitName::from_incarnation([0xab; 16]),
            "/nix/store/nspawn/bin/systemd-nspawn",
            vec!["--settings=no".to_string(), "--boot".to_string()],
            "/proc/123/fd/9",
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
        let resources = SandboxResources::new(1, 1, 1, 1).unwrap();
        let name = SandboxUnitName::from_incarnation([1; 16]);
        assert!(
            SandboxUnitSpec::new(
                name.clone(),
                "relative",
                Vec::new(),
                "/proc/1/fd/2",
                resources,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(
            SandboxUnitSpec::new(
                name,
                "/bin/tool",
                Vec::new(),
                "/proc/1/../2",
                resources,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .is_err()
        );
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
                "BindsTo",
                "After",
                "TasksMax",
                "MemoryHigh",
                "MemoryMax",
                "CPUWeight",
                "DevicePolicy",
                "NetworkNamespacePath",
                "TimeoutStartUSec",
                "TimeoutStopUSec",
                "ExecStart",
                "CPUQuotaPerSecUSec",
                "IOWeight",
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
