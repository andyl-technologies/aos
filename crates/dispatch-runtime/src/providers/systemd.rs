//! Systemd-managed workers with application-owned hierarchical accounting.
//!
//! Trusted configuration selects one stable profile. The provider verifies
//! configured aggregate slices, then starts each runner in a transient service
//! with resource policy applied before input or native-engine allocation.
//! Warm workers retain their accounting owner; they are never moved between
//! applications. Explicit session shutdown awaits whole-unit termination.

mod accounting;
mod policy;

pub use policy::{ManagerScope, SystemdProfile, WorkerLimits};

use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use tempfile::TempDir;
use tokio::{net::UnixListener, sync::Mutex, time::Instant};
use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

use super::{
    EnforcedLimits, ExecutionProvider, ResourceGrant, WorkerConnection, WorkerControl, WorkerLaunch,
};
use crate::{RuntimeError, WorkerFailureCause, WorkerFailureReport};

const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";

/// Reports policy, manager, connection, or confirmed-cleanup failure.
#[derive(Debug, thiserror::Error)]
pub enum SystemdError {
    /// The target platform cannot enforce systemd cgroup guarantees.
    #[error("systemd execution requires Linux with a unified cgroup hierarchy")]
    UnsupportedPlatform,
    /// Trusted configuration could not be decoded.
    #[error("systemd profile configuration could not be decoded")]
    Configuration(#[from] serde_json::Error),
    /// The selected application has no configured execution entitlement.
    #[error("systemd profile configuration does not authorize application {0}")]
    UnknownApplication(String),
    /// The configured profile cannot establish its declared guarantees.
    #[error("invalid systemd execution policy: {0}")]
    InvalidPolicy(&'static str),
    /// A systemd manager operation failed without losing its concrete source.
    #[error("systemd operation {operation} failed")]
    Manager {
        /// The failed operation or property access.
        operation: &'static str,
        /// The underlying D-Bus error.
        #[source]
        source: zbus::Error,
    },
    /// The private channel or kernel accounting interface could not be accessed.
    #[error("systemd worker or accounting I/O failed")]
    Io(#[from] std::io::Error),
    /// The configured aggregate hierarchy is missing an enforced ceiling.
    #[error("application slice {0} lacks explicit CPU, memory, or task policy")]
    AggregatePolicy(String),
    /// The resource owner's service is no longer active.
    #[error("resource owner {0} is not active")]
    OwnerInactive(String),
    /// The configured owner is outside its application accounting boundary.
    #[error("resource owner {0} is outside its configured application slice")]
    OwnerOutsideSlice(String),
    /// A configured control is not reflected in the worker's cgroup files.
    #[error("unit {unit} does not enforce its {resource} policy")]
    UnenforcedResource {
        /// The unit whose actual resource controls failed validation.
        unit: String,
        /// The kernel resource control that is missing or inconsistent.
        resource: &'static str,
    },
    /// A worker failed to establish its authenticated private connection.
    #[error("worker startup did not complete before its deadline")]
    StartupTimeout,
    /// An aggregate slice failed to initialize within the authorized interval.
    #[error("application resource boundaries did not initialize before their deadline")]
    InitializationTimeout,
    /// A connection did not originate from the managed main process.
    #[error("worker connection credentials do not match the managed process")]
    PeerMismatch,
    /// The unit could not be confirmed stopped within the cleanup interval.
    #[error("unit {0} did not stop before its cleanup deadline")]
    CleanupTimeout(String),
}

fn manager_error(operation: &'static str, source: zbus::Error) -> SystemdError {
    SystemdError::Manager { operation, source }
}

fn runtime_error(error: SystemdError) -> RuntimeError {
    RuntimeError::Provider(Box::new(error))
}

/// Starts bounded workers under a preconfigured application resource owner.
///
/// The provider uses the manager's ordinary authorization. It does not provide
/// a privileged broker, install policy, or accept allocation-supplied unit
/// names. The application and solver slices must already be configured.
pub struct SystemdProvider {
    connection: Connection,
    profile: SystemdProfile,
    enforced_limits: EnforcedLimits,
}

impl SystemdProvider {
    /// Connects to the selected manager and checks aggregate accounting policy.
    ///
    /// # Errors
    /// Returns an error when the manager is unavailable, authorization fails,
    /// the owner is inactive, or configured slices lack enforced limits.
    pub async fn connect(profile: SystemdProfile) -> Result<Self, SystemdError> {
        let connection = match profile.manager() {
            ManagerScope::User => Connection::session().await,
            ManagerScope::System => Connection::system().await,
        }
        .map_err(|source| manager_error("connect", source))?;

        Self::with_connection(connection, profile).await
    }

    /// Checks policy using an explicitly supplied manager connection.
    ///
    /// This supports externally supervised environments and private test buses.
    /// The caller is responsible for authenticating the connection's manager.
    ///
    /// # Errors
    /// Returns an error for unavailable units, an inactive owner, or missing
    /// aggregate resource controls.
    pub async fn with_connection(
        connection: Connection,
        profile: SystemdProfile,
    ) -> Result<Self, SystemdError> {
        check_slice(&connection, &profile.application_slice()).await?;
        check_slice(&connection, &profile.solver_slice()).await?;
        check_owner(&connection, &profile).await?;
        let enforced_limits = accounting::initialize(&connection, &profile).await?;

        Ok(Self {
            connection,
            profile,
            enforced_limits,
        })
    }

    /// Returns the trusted profile and its deterministic accounting names.
    pub fn profile(&self) -> &SystemdProfile {
        &self.profile
    }

    async fn launch_worker(&self, launch: WorkerLaunch) -> Result<WorkerConnection, SystemdError> {
        check_owner(&self.connection, &self.profile).await?;

        let directory = tempfile::Builder::new()
            .prefix("dispatch-control-")
            .tempdir()?;
        let socket_path = directory.path().join("worker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let unit = format!(
            "dispatch-{}-worker-{}.service",
            self.profile.application(),
            uuid::Uuid::new_v4().simple(),
        );
        let properties = service_properties(&self.profile, &launch, &socket_path)?;
        let control = Arc::new(SystemdControl {
            connection: self.connection.clone(),
            unit,
            cleanup_timeout: Duration::from_secs(self.profile.limits().cleanup_timeout_seconds),
            memory_observation: Mutex::new(None),
            _socket_directory: directory,
        });

        let manager = manager_proxy(&self.connection).await?;
        let _: OwnedObjectPath = manager
            .call(
                "StartTransientUnit",
                &(
                    control.unit.as_str(),
                    "fail",
                    properties,
                    Vec::<(String, Vec<(String, OwnedValue)>)>::new(),
                ),
            )
            .await
            .map_err(|source| manager_error("StartTransientUnit", source))?;

        let connection_result = tokio::time::timeout(
            Duration::from_secs(self.profile.limits().startup_timeout_seconds),
            async {
                let (stream, _) = listener.accept().await?;
                let service = service_proxy(&self.connection, &control.unit).await?;
                let main_pid: u32 = service
                    .get_property("MainPID")
                    .await
                    .map_err(|source| manager_error("MainPID", source))?;
                let credentials = stream.peer_cred()?;

                if main_pid == 0
                    || credentials.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(main_pid)
                    || credentials.uid() != rustix::process::geteuid().as_raw()
                {
                    return Err(SystemdError::PeerMismatch);
                }

                check_enforcement(&self.connection, &control.unit, &self.profile).await?;
                let group: String = service
                    .get_property("ControlGroup")
                    .await
                    .map_err(|source| manager_error("worker accounting ControlGroup", source))?;
                let observation = accounting::MemoryObservation::capture(
                    accounting::directory(&group)?,
                    &self.enforced_limits,
                )
                .await?;
                *control.memory_observation.lock().await = Some(observation);

                Ok(stream)
            },
        )
        .await
        .map_err(|_| SystemdError::StartupTimeout)
        .and_then(|result| result);

        let stream = match connection_result {
            Ok(stream) => stream,
            Err(error) => {
                // Returning a startup failure must not leave an admitted unit
                // computing indefinitely. Cleanup failure remains observable.
                tokio::time::timeout(control.cleanup_timeout, control.stop_unit())
                    .await
                    .map_err(|_| SystemdError::CleanupTimeout(control.unit.clone()))??;
                return Err(error);
            }
        };

        let (reader, writer) = stream.into_split();
        Ok(WorkerConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            control,
        })
    }
}

#[async_trait]
impl ExecutionProvider for SystemdProvider {
    fn grant(&self) -> ResourceGrant {
        ResourceGrant {
            hard_cancellation: true,
            independent_memory: true,
            aggregate_accounting: true,
            owner_cleanup: true,
            enforced_memory_bytes: self
                .enforced_limits
                .effective_worker_ceiling
                .memory_max_bytes,
            enforced_limits: Some(self.enforced_limits.clone()),
            description: format!(
                "systemd worker cgroup beneath {}; CPU weights express contention shares, not deadline guarantees; enclosing limits remain effective",
                self.profile.application_slice(),
            ),
        }
    }

    async fn launch(&self, launch: WorkerLaunch) -> Result<WorkerConnection, RuntimeError> {
        self.launch_worker(launch).await.map_err(runtime_error)
    }
}

async fn manager_proxy(connection: &Connection) -> Result<Proxy<'_>, SystemdError> {
    Proxy::new(connection, DESTINATION, MANAGER_PATH, MANAGER_INTERFACE)
        .await
        .map_err(|source| manager_error("manager proxy", source))
}

async fn unit_path(connection: &Connection, name: &str) -> Result<OwnedObjectPath, SystemdError> {
    manager_proxy(connection)
        .await?
        .call("LoadUnit", &(name,))
        .await
        .map_err(|source| manager_error("LoadUnit", source))
}

async fn service_proxy<'a>(
    connection: &'a Connection,
    name: &str,
) -> Result<Proxy<'a>, SystemdError> {
    Proxy::new(
        connection,
        DESTINATION,
        unit_path(connection, name).await?,
        "org.freedesktop.systemd1.Service",
    )
    .await
    .map_err(|source| manager_error("service proxy", source))
}

async fn check_owner(
    connection: &Connection,
    profile: &SystemdProfile,
) -> Result<(), SystemdError> {
    let owner = profile.owner_unit();
    let unit = Proxy::new(
        connection,
        DESTINATION,
        unit_path(connection, owner).await?,
        "org.freedesktop.systemd1.Unit",
    )
    .await
    .map_err(|source| manager_error("owner proxy", source))?;
    let state: String = unit
        .get_property("ActiveState")
        .await
        .map_err(|source| manager_error("owner ActiveState", source))?;

    if !matches!(state.as_str(), "active" | "activating") {
        return Err(SystemdError::OwnerInactive(owner.to_owned()));
    }

    let service = service_proxy(connection, owner).await?;
    let group: String = service
        .get_property("ControlGroup")
        .await
        .map_err(|source| manager_error("owner ControlGroup", source))?;
    if Path::new(&group)
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        != Some(profile.application_slice().as_str())
    {
        return Err(SystemdError::OwnerOutsideSlice(owner.to_owned()));
    }

    Ok(())
}

async fn check_enforcement(
    connection: &Connection,
    name: &str,
    profile: &SystemdProfile,
) -> Result<(), SystemdError> {
    let service = service_proxy(connection, name).await?;
    let group: String = service
        .get_property("ControlGroup")
        .await
        .map_err(|source| manager_error("worker ControlGroup", source))?;
    let relative = group
        .strip_prefix('/')
        .ok_or_else(|| SystemdError::UnenforcedResource {
            unit: name.to_owned(),
            resource: "cgroup path",
        })?;
    if Path::new(relative)
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(SystemdError::UnenforcedResource {
            unit: name.to_owned(),
            resource: "cgroup path",
        });
    }

    let directory = Path::new("/sys/fs/cgroup").join(relative);
    let limits = profile.limits();
    for (resource, maximum) in [
        ("memory.max", limits.memory_max_bytes),
        ("memory.high", limits.memory_high_bytes),
        ("pids.max", limits.tasks_max),
    ] {
        let text = tokio::fs::read_to_string(directory.join(resource)).await?;
        if !text
            .trim()
            .parse::<u64>()
            .is_ok_and(|value| value > 0 && value <= maximum)
        {
            return Err(SystemdError::UnenforcedResource {
                unit: name.to_owned(),
                resource,
            });
        }
    }

    let cpu_weight = tokio::fs::read_to_string(directory.join("cpu.weight")).await?;
    if cpu_weight.trim().parse::<u64>().ok() != Some(limits.cpu_weight) {
        return Err(SystemdError::UnenforcedResource {
            unit: name.to_owned(),
            resource: "cpu.weight",
        });
    }

    let cpu_max = tokio::fs::read_to_string(directory.join("cpu.max")).await?;
    let mut fields = cpu_max.split_whitespace();
    let quota = fields.next().and_then(|field| field.parse::<u64>().ok());
    let period = fields.next().and_then(|field| field.parse::<u64>().ok());
    if fields.next().is_some()
        || !matches!((quota, period), (Some(quota), Some(period)) if quota > 0 && period > 0 && u128::from(quota) * 100 <= u128::from(period) * u128::from(limits.cpu_quota_percent))
    {
        return Err(SystemdError::UnenforcedResource {
            unit: name.to_owned(),
            resource: "cpu.max",
        });
    }

    // Actual parent controls ensure the application cannot gain entitlement by
    // multiplying sessions, even when manager properties exist but a resource
    // controller was disabled higher in the hierarchy.
    let parent = directory
        .parent()
        .ok_or(SystemdError::InvalidPolicy("worker cgroup has no parent"))?;
    let application = parent.parent().ok_or(SystemdError::InvalidPolicy(
        "solver cgroup has no application parent",
    ))?;
    if parent.file_name().and_then(|name| name.to_str()) != Some(profile.solver_slice().as_str())
        || application.file_name().and_then(|name| name.to_str())
            != Some(profile.application_slice().as_str())
    {
        return Err(SystemdError::UnenforcedResource {
            unit: name.to_owned(),
            resource: "application hierarchy",
        });
    }
    for ancestor in [parent, application] {
        for resource in ["memory.max", "pids.max", "cpu.weight"] {
            let text = tokio::fs::read_to_string(ancestor.join(resource)).await?;
            if !text
                .trim()
                .parse::<u64>()
                .is_ok_and(|value| value > 0 && value < u64::MAX)
            {
                return Err(SystemdError::UnenforcedResource {
                    unit: name.to_owned(),
                    resource,
                });
            }
        }
    }

    Ok(())
}

async fn check_slice(connection: &Connection, name: &str) -> Result<u64, SystemdError> {
    let slice = Proxy::new(
        connection,
        DESTINATION,
        unit_path(connection, name).await?,
        "org.freedesktop.systemd1.Slice",
    )
    .await
    .map_err(|source| manager_error("slice proxy", source))?;
    let memory: u64 = slice
        .get_property("MemoryMax")
        .await
        .map_err(|source| manager_error("slice MemoryMax", source))?;
    let tasks: u64 = slice
        .get_property("TasksMax")
        .await
        .map_err(|source| manager_error("slice TasksMax", source))?;
    let weight: u64 = slice
        .get_property("CPUWeight")
        .await
        .map_err(|source| manager_error("slice CPUWeight", source))?;

    if memory == 0
        || memory == u64::MAX
        || tasks == 0
        || tasks == u64::MAX
        || !(1..=10_000).contains(&weight)
    {
        return Err(SystemdError::AggregatePolicy(name.to_owned()));
    }

    Ok(memory)
}

fn executable_text(path: &Path) -> Result<String, SystemdError> {
    if !path.is_absolute() {
        return Err(SystemdError::InvalidPolicy(
            "worker executables must use absolute paths",
        ));
    }

    path.to_str()
        .filter(|path| !path.contains('\0'))
        .map(str::to_owned)
        .ok_or(SystemdError::InvalidPolicy(
            "worker paths must be UTF-8 without NUL bytes",
        ))
}

fn service_properties(
    profile: &SystemdProfile,
    launch: &WorkerLaunch,
    socket: &Path,
) -> Result<Vec<(&'static str, Value<'static>)>, SystemdError> {
    let executable = executable_text(&launch.runner)?;
    let mut arguments = vec![
        executable.clone(),
        "--connect".into(),
        executable_text(socket)?,
        "--backend".into(),
        executable_text(&launch.native_backend)?,
        "--max-frame-bytes".into(),
        launch.max_frame_bytes.to_string(),
    ];

    for argument in &launch.native_arguments {
        if argument.contains('\0') {
            return Err(SystemdError::InvalidPolicy(
                "backend arguments must not contain NUL bytes",
            ));
        }

        arguments.push("--backend-arg".into());
        arguments.push(argument.clone());
    }

    let limits = profile.limits();
    Ok(vec![
        (
            "Description",
            Value::from(format!("Dispatch worker for {}", profile.application())),
        ),
        ("Type", Value::from("exec")),
        ("Slice", Value::from(profile.solver_slice())),
        (
            "BindsTo",
            Value::from(vec![profile.owner_unit().to_owned()]),
        ),
        ("After", Value::from(vec![profile.owner_unit().to_owned()])),
        (
            "User",
            Value::from(rustix::process::geteuid().as_raw().to_string()),
        ),
        (
            "ExecStart",
            Value::from(vec![(executable, arguments, false)]),
        ),
        ("CPUAccounting", Value::from(true)),
        ("MemoryAccounting", Value::from(true)),
        ("TasksAccounting", Value::from(true)),
        ("CPUWeight", Value::from(limits.cpu_weight)),
        (
            "CPUQuotaPerSecUSec",
            Value::from(u64::from(limits.cpu_quota_percent) * 10_000),
        ),
        ("CPUQuotaPeriodUSec", Value::from(100_000u64)),
        ("MemoryHigh", Value::from(limits.memory_high_bytes)),
        ("MemoryMax", Value::from(limits.memory_max_bytes)),
        ("MemorySwapMax", Value::from(0u64)),
        ("TasksMax", Value::from(limits.tasks_max)),
        (
            "RuntimeMaxUSec",
            Value::from(limits.lifetime_seconds * 1_000_000),
        ),
        (
            "TimeoutStartUSec",
            Value::from(limits.startup_timeout_seconds * 1_000_000),
        ),
        (
            "TimeoutStopUSec",
            Value::from(limits.cleanup_timeout_seconds * 1_000_000 / 2),
        ),
        ("KillMode", Value::from("control-group")),
        ("SendSIGKILL", Value::from(true)),
        ("Restart", Value::from("no")),
        ("CollectMode", Value::from("inactive")),
        // Retain the small runner when the native child is the OOM victim so
        // postmortem local counters remain readable until explicit cleanup.
        ("OOMPolicy", Value::from("continue")),
        ("NoNewPrivileges", Value::from(true)),
        ("StandardOutput", Value::from("null")),
        ("StandardError", Value::from("journal")),
    ])
}

struct SystemdControl {
    connection: Connection,
    unit: String,
    cleanup_timeout: Duration,
    memory_observation: Mutex<Option<accounting::MemoryObservation>>,
    _socket_directory: TempDir,
}

impl SystemdControl {
    async fn stop_unit(&self) -> Result<(), SystemdError> {
        let manager = manager_proxy(&self.connection).await?;
        let stop: zbus::Result<OwnedObjectPath> = manager
            .call("StopUnit", &(self.unit.as_str(), "replace"))
            .await;
        if let Err(source) = stop {
            if is_missing_unit(&source) {
                return Ok(());
            }

            return Err(manager_error("StopUnit", source));
        }

        let deadline =
            Instant::now()
                .checked_add(self.cleanup_timeout)
                .ok_or(SystemdError::InvalidPolicy(
                    "cleanup deadline exceeds the monotonic clock range",
                ))?;
        loop {
            let path: zbus::Result<OwnedObjectPath> =
                manager.call("GetUnit", &(self.unit.as_str(),)).await;
            let path = match path {
                Ok(path) => path,
                Err(source) if is_missing_unit(&source) => return Ok(()),
                Err(source) => return Err(manager_error("GetUnit during cleanup", source)),
            };
            let unit = Proxy::new(
                &self.connection,
                DESTINATION,
                path,
                "org.freedesktop.systemd1.Unit",
            )
            .await
            .map_err(|source| manager_error("cleanup unit proxy", source))?;
            let state: String = match unit.get_property("ActiveState").await {
                Ok(state) => state,
                Err(source) if is_missing_unit(&source) => return Ok(()),
                Err(source) => return Err(manager_error("cleanup ActiveState", source)),
            };

            if matches!(state.as_str(), "inactive" | "failed") {
                let reset: zbus::Result<()> = manager
                    .call("ResetFailedUnit", &(self.unit.as_str(),))
                    .await;
                if let Err(source) = reset
                    && !is_missing_unit(&source)
                {
                    return Err(manager_error("ResetFailedUnit during cleanup", source));
                }
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(SystemdError::CleanupTimeout(self.unit.clone()));
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn is_missing_unit(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, _, _) => matches!(
            name.as_str(),
            "org.freedesktop.systemd1.NoSuchUnit"
                | "org.freedesktop.systemd1.NoSuchUnitFile"
                | "org.freedesktop.DBus.Error.UnknownObject"
        ),
        zbus::Error::FDO(source) => matches!(source.as_ref(), zbus::fdo::Error::UnknownObject(_)),
        _ => false,
    }
}

#[async_trait]
impl WorkerControl for SystemdControl {
    async fn begin_job(&self) -> Result<(), RuntimeError> {
        let previous = self
            .memory_observation
            .lock()
            .await
            .clone()
            .ok_or_else(|| {
                runtime_error(SystemdError::InvalidPolicy(
                    "worker accounting baseline is absent",
                ))
            })?;
        let refreshed = previous.refresh().await.map_err(runtime_error)?;
        *self.memory_observation.lock().await = Some(refreshed);
        Ok(())
    }

    async fn failure_report(&self) -> Option<WorkerFailureReport> {
        let previous = self.memory_observation.lock().await.clone();
        match previous {
            Some(observation) => Some(match observation.report().await {
                Ok(report) => report,
                Err(error) => WorkerFailureReport {
                    cause: WorkerFailureCause::Unknown,
                    detail: format!(
                        "worker resource origin cannot be established because local accounting evidence is unavailable: {error}"
                    ),
                },
            }),
            None => Some(WorkerFailureReport {
                cause: WorkerFailureCause::Unknown,
                detail: "worker failed before accounting evidence could be established".to_owned(),
            }),
        }
    }

    async fn stop(&self) -> Result<(), RuntimeError> {
        tokio::time::timeout(self.cleanup_timeout, self.stop_unit())
            .await
            .map_err(|_| runtime_error(SystemdError::CleanupTimeout(self.unit.clone())))?
            .map_err(runtime_error)
    }
}

impl Drop for SystemdControl {
    fn drop(&mut self) {
        // Explicit close confirms cleanup. Drop is only a supplementary best
        // effort; BindsTo and RuntimeMaxUSec remain independent lifetime bounds.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let connection = self.connection.clone();
            let unit = self.unit.clone();
            let timeout = self.cleanup_timeout;
            runtime.spawn(async move {
                let cleanup = async {
                    if let Ok(manager) = manager_proxy(&connection).await {
                        let _: zbus::Result<OwnedObjectPath> =
                            manager.call("StopUnit", &(unit.as_str(), "replace")).await;
                        let _: zbus::Result<()> =
                            manager.call("ResetFailedUnit", &(unit.as_str(),)).await;
                    }
                };

                let _ = tokio::time::timeout(timeout, cleanup).await;
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn profile() -> SystemdProfile {
        SystemdProfile::new(
            "test",
            "controller.service",
            ManagerScope::User,
            WorkerLimits {
                cpu_weight: 250,
                cpu_quota_percent: 150,
                memory_high_bytes: 4096,
                memory_max_bytes: 8192,
                tasks_max: 8,
                lifetime_seconds: 600,
                startup_timeout_seconds: 5,
                cleanup_timeout_seconds: 2,
            },
        )
        .unwrap()
    }

    fn launch() -> WorkerLaunch {
        WorkerLaunch {
            runner: "/trusted/dispatch-worker".into(),
            native_backend: "/trusted/dispatch-rebalancer".into(),
            native_arguments: vec!["literal;$argument".into()],
            session_generation: 1,
            worker_generation: 2,
            max_frame_bytes: 65536,
        }
    }

    #[test]
    fn properties_apply_whole_unit_limits_before_execution() {
        let properties =
            service_properties(&profile(), &launch(), Path::new("/private/worker.sock")).unwrap();
        let get = |name| {
            properties
                .iter()
                .find(|(key, _)| *key == name)
                .unwrap()
                .1
                .clone()
        };

        assert_eq!(get("MemoryMax").downcast_ref::<u64>().unwrap(), 8192);
        assert_eq!(
            get("CPUQuotaPerSecUSec").downcast_ref::<u64>().unwrap(),
            1_500_000
        );
        assert_eq!(get("TasksMax").downcast_ref::<u64>().unwrap(), 8);
        assert_eq!(
            get("CPUQuotaPeriodUSec").downcast_ref::<u64>().unwrap(),
            100_000
        );
        assert_eq!(get("OOMPolicy").downcast_ref::<&str>().unwrap(), "continue");
        assert_eq!(
            get("RuntimeMaxUSec").downcast_ref::<u64>().unwrap(),
            600_000_000
        );
        assert_eq!(
            get("Slice").downcast_ref::<&str>().unwrap(),
            "dispatch-test-solver.slice"
        );
        assert_eq!(
            get("KillMode").downcast_ref::<&str>().unwrap(),
            "control-group"
        );
        assert!(!properties.iter().any(|(name, _)| *name == "CPUQuota"));
    }

    #[test]
    fn executable_and_argument_policy_rejects_ambiguous_launches() {
        let mut relative = launch();
        relative.runner = "dispatch-worker".into();
        assert!(
            service_properties(&profile(), &relative, Path::new("/private/worker.sock")).is_err()
        );

        let mut invalid_argument = launch();
        invalid_argument
            .native_arguments
            .push("bad\0argument".into());
        assert!(
            service_properties(
                &profile(),
                &invalid_argument,
                Path::new("/private/worker.sock")
            )
            .is_err()
        );
    }
}
