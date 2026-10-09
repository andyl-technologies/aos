//! Validated resource policy and deterministic application slice names.
//!
//! Trusted configuration contains named application records. An empty grant
//! set is represented by the following versioned JSON envelope:
//!
//! ```json
//! {"schema":"dispatch.systemd-profiles","version":1,"applications":{}}
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::SystemdError;

/// Selects the manager that owns the application's resource hierarchy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagerScope {
    /// Uses the calling user's manager and its enclosing user slice.
    User,
    /// Uses the system manager with its normal D-Bus authorization.
    System,
}

/// Defines hard worker limits and a stable relative CPU importance.
///
/// The application slice supplies the aggregate entitlement. These limits
/// restrict each worker further; additional workers cannot bypass that parent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLimits {
    /// Relative CPU weight within the solver slice, from 1 through 10,000.
    pub cpu_weight: u64,
    /// CPU ceiling as a percentage of one CPU, including values above 100.
    pub cpu_quota_percent: u32,
    /// Memory reclaim and throttling threshold in bytes.
    pub memory_high_bytes: u64,
    /// Hard memory ceiling in bytes; swapping is disabled for the worker.
    pub memory_max_bytes: u64,
    /// Maximum processes and threads, rather than concurrent solve requests.
    pub tasks_max: u64,
    /// Maximum whole worker lifetime, including idle time, up to one year.
    pub lifetime_seconds: u64,
    /// Maximum time to establish the private connection, up to one hour.
    pub startup_timeout_seconds: u64,
    /// Maximum time to await confirmed termination, up to five minutes.
    pub cleanup_timeout_seconds: u64,
}

impl WorkerLimits {
    pub(super) fn validate(&self) -> Result<(), SystemdError> {
        if !(1..=10_000).contains(&self.cpu_weight) {
            return Err(SystemdError::InvalidPolicy("CPU weight must be 1..=10000"));
        }

        if self.cpu_quota_percent == 0 {
            return Err(SystemdError::InvalidPolicy("CPU quota must be nonzero"));
        }

        if self.memory_high_bytes == 0
            || self.memory_high_bytes > self.memory_max_bytes
            || self.memory_max_bytes == u64::MAX
        {
            return Err(SystemdError::InvalidPolicy(
                "memory high must be positive and no greater than a finite memory max",
            ));
        }

        if self.tasks_max == 0 || self.tasks_max == u64::MAX {
            return Err(SystemdError::InvalidPolicy(
                "task limit must be positive and finite",
            ));
        }

        if self.lifetime_seconds == 0
            || self.startup_timeout_seconds == 0
            || self.cleanup_timeout_seconds == 0
            || self.startup_timeout_seconds > self.lifetime_seconds
        {
            return Err(SystemdError::InvalidPolicy(
                "worker time limits must be positive and startup must fit its lifetime",
            ));
        }

        if self.lifetime_seconds > 31_536_000
            || self.startup_timeout_seconds > 3_600
            || self.cleanup_timeout_seconds > 300
        {
            return Err(SystemdError::InvalidPolicy(
                "worker lifetime exceeds one year, startup exceeds one hour, or cleanup exceeds five minutes",
            ));
        }

        for seconds in [
            self.lifetime_seconds,
            self.startup_timeout_seconds,
            self.cleanup_timeout_seconds,
        ] {
            if seconds.checked_mul(1_000_000).is_none() {
                return Err(SystemdError::InvalidPolicy(
                    "time limit overflows microseconds",
                ));
            }
        }

        Ok(())
    }
}

/// Binds trusted application identity to its owner service and worker policy.
///
/// Construct this value from administrator or supervisor configuration, not
/// from an allocation problem. D-Bus authorization still applies; this type
/// does not grant permission to create services in either manager.
#[derive(Clone, Debug)]
pub struct SystemdProfile {
    application: String,
    owner_unit: String,
    manager: ManagerScope,
    limits: WorkerLimits,
}

impl SystemdProfile {
    /// Loads one application grant from trusted profile configuration bytes.
    ///
    /// The configuration uses schema `dispatch.systemd-profiles`, version 1,
    /// with an `applications` object keyed by application identity. Reading
    /// these bytes does not authorize their source: callers must obtain them
    /// from their supervisor or administrator, outside allocation requests.
    ///
    /// # Errors
    /// Returns an error for malformed or unsupported configuration, an absent
    /// application grant, or invalid identity and resource policy.
    pub fn from_configuration(bytes: &[u8], application: &str) -> Result<Self, SystemdError> {
        let mut configuration: ProfileConfiguration = serde_json::from_slice(bytes)?;
        if configuration.schema != "dispatch.systemd-profiles" || configuration.version != 1 {
            return Err(SystemdError::InvalidPolicy(
                "unsupported profile configuration schema",
            ));
        }

        let record = configuration
            .applications
            .remove(application)
            .ok_or_else(|| SystemdError::UnknownApplication(application.to_owned()))?;
        if record.application != application {
            return Err(SystemdError::InvalidPolicy(
                "application grant identity differs from its key",
            ));
        }

        Self::new(
            record.application,
            record.owner_unit,
            record.manager,
            record.limits,
        )
    }

    /// Validates a supervisor-selected execution profile.
    ///
    /// Application names use ASCII letters, digits, and underscores, without
    /// hyphens, so generated slice hierarchy cannot acquire unexpected parents.
    ///
    /// # Errors
    /// Returns an error for ambiguous unit names or invalid resource limits.
    pub fn new(
        application: impl Into<String>,
        owner_unit: impl Into<String>,
        manager: ManagerScope,
        limits: WorkerLimits,
    ) -> Result<Self, SystemdError> {
        let application = application.into();
        let owner_unit = owner_unit.into();

        if application.is_empty()
            || application.len() > 64
            || !application
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(SystemdError::InvalidPolicy(
                "application must contain 1..=64 ASCII letters, digits, or underscores",
            ));
        }

        let owner_name = owner_unit.strip_suffix(".service").unwrap_or_default();
        if owner_name.is_empty()
            || owner_unit.len() > 180
            || !owner_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(SystemdError::InvalidPolicy(
                "owner must be a plain service unit without paths or template instances",
            ));
        }

        limits.validate()?;

        Ok(Self {
            application,
            owner_unit,
            manager,
            limits,
        })
    }

    /// Returns the configured resource owner's application identity.
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Returns the service whose loss stops its solver workers.
    pub fn owner_unit(&self) -> &str {
        &self.owner_unit
    }

    /// Returns the manager that supplies authorization and aggregate limits.
    pub fn manager(&self) -> ManagerScope {
        self.manager
    }

    /// Returns the stable limits applied before worker execution.
    pub fn limits(&self) -> &WorkerLimits {
        &self.limits
    }

    /// Returns the aggregate application slice shared by all its sessions.
    pub fn application_slice(&self) -> String {
        format!("dispatch-{}.slice", self.application)
    }

    /// Returns the solver slice nested beneath the application slice.
    pub fn solver_slice(&self) -> String {
        format!("dispatch-{}-solver.slice", self.application)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileConfiguration {
    schema: String,
    version: u32,
    applications: BTreeMap<String, ProfileRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRecord {
    application: String,
    owner_unit: String,
    manager: ManagerScope,
    limits: WorkerLimits,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn limits() -> WorkerLimits {
        WorkerLimits {
            cpu_weight: 100,
            cpu_quota_percent: 200,
            memory_high_bytes: 1024,
            memory_max_bytes: 2048,
            tasks_max: 16,
            lifetime_seconds: 60,
            startup_timeout_seconds: 5,
            cleanup_timeout_seconds: 3,
        }
    }

    #[test]
    fn application_identity_cannot_inject_slice_hierarchy() {
        for application in ["", "tenant-other", "../tenant", "tenant.slice", "tenant\n"] {
            assert!(
                SystemdProfile::new(application, "owner.service", ManagerScope::User, limits())
                    .is_err()
            );
        }

        let profile =
            SystemdProfile::new("tenant_42", "owner.service", ManagerScope::User, limits())
                .unwrap();
        assert_eq!(profile.application_slice(), "dispatch-tenant_42.slice");
        assert_eq!(profile.solver_slice(), "dispatch-tenant_42-solver.slice");
    }

    #[test]
    fn owner_identity_cannot_inject_paths_or_extra_dependencies() {
        for owner in [
            "owner",
            "owner.slice",
            "owner@other.service",
            "../owner.service",
            "owner.service\n",
        ] {
            assert!(SystemdProfile::new("tenant", owner, ManagerScope::System, limits()).is_err());
        }
    }

    #[test]
    fn resource_limits_reject_unbounded_or_inconsistent_values() {
        let mut invalid = limits();
        invalid.cpu_weight = 10_001;
        assert!(invalid.validate().is_err());

        invalid = limits();
        invalid.memory_high_bytes = invalid.memory_max_bytes + 1;
        assert!(invalid.validate().is_err());

        invalid = limits();
        invalid.lifetime_seconds = u64::MAX;
        assert!(invalid.validate().is_err());

        invalid = limits();
        invalid.tasks_max = 0;
        assert!(invalid.validate().is_err());

        invalid = limits();
        invalid.tasks_max = u64::MAX;
        assert!(invalid.validate().is_err());

        invalid = limits();
        invalid.memory_max_bytes = u64::MAX;
        assert!(invalid.validate().is_err());

        invalid = limits();
        invalid.cleanup_timeout_seconds = 301;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn profile_configuration_preserves_authorized_application_identity() {
        let configuration = serde_json::json!({
            "schema": "dispatch.systemd-profiles",
            "version": 1,
            "applications": {
                "tenant": {
                    "application": "tenant",
                    "owner_unit": "owner.service",
                    "manager": "system",
                    "limits": limits(),
                }
            }
        });
        let bytes = serde_json::to_vec(&configuration).unwrap();

        let profile = SystemdProfile::from_configuration(&bytes, "tenant").unwrap();
        assert_eq!(profile.application_slice(), "dispatch-tenant.slice");
        assert!(matches!(
            SystemdProfile::from_configuration(&bytes, "other"),
            Err(SystemdError::UnknownApplication(_))
        ));

        let mut mismatched = configuration;
        mismatched["applications"]["tenant"]["application"] = "other".into();
        assert!(
            SystemdProfile::from_configuration(&serde_json::to_vec(&mismatched).unwrap(), "tenant")
                .is_err()
        );
    }
}
