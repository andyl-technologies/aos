//! Rejects Linux-only execution policy explicitly on other platforms.

#[path = "policy.rs"]
mod policy;

pub use policy::{ManagerScope, SystemdProfile, WorkerLimits};

use async_trait::async_trait;
use zbus::Connection;

use crate::{
    RuntimeError,
    providers::{ExecutionProvider, ResourceGrant, WorkerConnection, WorkerLaunch},
};

/// Reports configuration failure or unavailable platform enforcement.
#[derive(Debug, thiserror::Error)]
pub enum SystemdError {
    /// Trusted configuration could not be decoded.
    #[error("systemd profile configuration could not be decoded")]
    Configuration(#[from] serde_json::Error),
    /// The selected application has no configured execution entitlement.
    #[error("systemd profile configuration does not authorize application {0}")]
    UnknownApplication(String),
    /// The configured profile cannot establish its declared guarantees.
    #[error("invalid systemd execution policy: {0}")]
    InvalidPolicy(&'static str),
    /// The target platform cannot enforce systemd cgroup guarantees.
    #[error("systemd execution requires Linux with a unified cgroup hierarchy")]
    UnsupportedPlatform,
}

/// Represents the unavailable systemd provider on a non-Linux target.
///
/// Constructors reject selection explicitly. Applications can retain one
/// portable configuration API without silently falling back to weaker limits.
pub struct SystemdProvider {
    profile: SystemdProfile,
}

impl SystemdProvider {
    /// Rejects a Linux execution profile on this target.
    ///
    /// # Errors
    /// Always returns [`SystemdError::UnsupportedPlatform`].
    pub async fn connect(_profile: SystemdProfile) -> Result<Self, SystemdError> {
        Err(SystemdError::UnsupportedPlatform)
    }

    /// Rejects a supplied manager connection on this target.
    ///
    /// # Errors
    /// Always returns [`SystemdError::UnsupportedPlatform`].
    pub async fn with_connection(
        _connection: Connection,
        _profile: SystemdProfile,
    ) -> Result<Self, SystemdError> {
        Err(SystemdError::UnsupportedPlatform)
    }

    /// Returns the profile associated with this provider representation.
    pub fn profile(&self) -> &SystemdProfile {
        &self.profile
    }
}

#[async_trait]
impl ExecutionProvider for SystemdProvider {
    fn grant(&self) -> ResourceGrant {
        ResourceGrant {
            hard_cancellation: false,
            independent_memory: false,
            aggregate_accounting: false,
            owner_cleanup: false,
            enforced_memory_bytes: None,
            enforced_limits: None,
            description: "systemd execution is unavailable on this platform".to_owned(),
        }
    }

    async fn launch(&self, _launch: WorkerLaunch) -> Result<WorkerConnection, RuntimeError> {
        Err(RuntimeError::Provider(Box::new(
            SystemdError::UnsupportedPlatform,
        )))
    }
}
