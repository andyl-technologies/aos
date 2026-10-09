//! Execution providers authorize resources and supervise trusted runners.

mod embedded;
mod subprocess;

#[cfg(all(target_os = "linux", feature = "systemd"))]
pub mod systemd;

#[cfg(all(not(target_os = "linux"), feature = "systemd"))]
#[path = "systemd/unavailable.rs"]
pub mod systemd;

pub use embedded::{CooperativeCancellation, EmbeddedBackend, EmbeddedProvider, EmbeddedSolution};
pub use subprocess::SubprocessProvider;

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::RuntimeError;

/// Reports concrete controls without confusing limits with reservations.
///
/// CPU quota and period use microseconds. Their ratio is the available CPU
/// ceiling; CPU weight separately describes relative sibling importance.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Relative CPU weight at this boundary, when explicitly configured.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub cpu_weight: Option<u64>,
    /// Maximum CPU runtime per scheduling period, or no quota ceiling.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub cpu_quota_micros: Option<u64>,
    /// Scheduling period for the CPU ceiling, when available.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub cpu_period_micros: Option<u64>,
    /// Maximum processes and threads, independent of solve concurrency.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub task_limit: Option<u64>,
    /// Memory reclaim and throttling threshold in bytes.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub memory_high_bytes: Option<u64>,
    /// Hard memory ceiling in bytes, without physical reservation semantics.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub memory_max_bytes: Option<u64>,
}

/// Identifies a manager-owned accounting boundary and its kernel controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBoundary {
    /// The configured service or slice unit identity.
    pub unit: String,
    /// The actual cgroup path, relative to the unified hierarchy root.
    pub cgroup_path: String,
    /// Controls read from this boundary's kernel interface.
    pub limits: ResourceLimits,
}

/// Describes authorized worker policy and checked aggregate accounting.
///
/// Parent controls are an initialization snapshot. The provider verifies the
/// worker's actual leaf controls before returning its connection. Host policy
/// can subsequently tighten controls; these values do not promise deadlines.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedLimits {
    /// Stable authorized worker controls, subject to enclosing ceilings.
    pub worker_policy: ResourceLimits,
    /// Worker ceilings restricted by all visible ancestor controls.
    ///
    /// CPU weight remains local importance; relative share depends on the
    /// reported hierarchy and other active groups, rather than one number.
    pub effective_worker_ceiling: ResourceLimits,
    /// Aggregate application boundary shared by all its sessions.
    pub application: ResourceBoundary,
    /// Nested allowance shared by all of the application's solver workers.
    pub solvers: ResourceBoundary,
    /// Additional visible ancestors above the application boundary.
    pub outer_ancestors: Vec<ResourceBoundary>,
    /// Service whose loss independently stops the workers.
    pub owner_unit: String,
}

/// Describes authorized execution guarantees and their accounting scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceGrant {
    /// Whether native execution can be terminated independently of cooperation.
    pub hard_cancellation: bool,
    /// Whether a worker has a separately enforced memory ceiling.
    pub independent_memory: bool,
    /// Whether all sessions share an externally enforced application allowance.
    pub aggregate_accounting: bool,
    /// Whether owner loss independently initiates bounded cleanup.
    pub owner_cleanup: bool,
    /// The enforced worker memory ceiling, when independently available.
    #[serde(with = "crate::types::optional_decimal_u64")]
    pub enforced_memory_bytes: Option<u64>,
    /// Concrete policy and checked boundaries, when exposed by the provider.
    #[serde(default)]
    pub enforced_limits: Option<EnforcedLimits>,
    /// Names the enforcement mechanisms and any limitations.
    pub description: String,
}

/// Supplies immutable executable configuration for one worker generation.
#[derive(Clone, Debug)]
pub struct WorkerLaunch {
    /// The trusted Rust runner executable.
    pub runner: PathBuf,
    /// The native backend executable selected by trusted configuration.
    pub native_backend: PathBuf,
    /// Literal backend arguments; these are never evaluated by a shell.
    pub native_arguments: Vec<String>,
    /// The owning session generation.
    pub session_generation: u64,
    /// The new worker generation.
    pub worker_generation: u64,
    /// Maximum protocol frame payload bytes.
    pub max_frame_bytes: u32,
}

/// Supplies the runner's private framed connection and external termination.
pub struct WorkerConnection {
    /// The runner's protocol output.
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    /// The runner's protocol input.
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    /// Independent control over the full execution boundary.
    pub control: Arc<dyn WorkerControl>,
}

/// Terminates an execution boundary independently of native solver control.
#[async_trait]
pub trait WorkerControl: Send + Sync {
    /// Captures per-operation accounting evidence before model materialization.
    ///
    /// # Errors
    /// Returns an error when a provider cannot establish its operation baseline.
    async fn begin_job(&self) -> Result<(), crate::RuntimeError> {
        Ok(())
    }

    /// Returns provider-established failure attribution before cleanup.
    ///
    /// Absence means the provider has no trustworthy attribution. This method
    /// must not turn process loss into an allocation infeasibility claim.
    async fn failure_report(&self) -> Option<crate::WorkerFailureReport> {
        None
    }

    /// Stops and reaps the worker boundary.
    ///
    /// # Errors
    /// Returns an error when termination or confirmed cleanup fails.
    async fn stop(&self) -> Result<(), RuntimeError>;
}

/// Authorizes a stable profile and launches workers within that profile.
#[async_trait]
pub trait ExecutionProvider: Send + Sync {
    /// Returns the immutable authorized guarantees.
    fn grant(&self) -> ResourceGrant;

    /// Starts a trusted runner with policy established before allocation.
    ///
    /// Startup must be cancellation safe: dropping the launch future must
    /// initiate cleanup of partially established execution. Once a connection
    /// is returned, the runtime retains its slot until cleanup is confirmed.
    ///
    /// # Errors
    /// Returns an error when authorization, startup, or connection fails.
    async fn launch(&self, launch: WorkerLaunch) -> Result<WorkerConnection, RuntimeError>;
}
