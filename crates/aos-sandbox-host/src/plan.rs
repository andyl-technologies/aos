//! Trusted catalog resolution and fixed nspawn launch compilation.

use std::time::Duration;

use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use aos_systemd::{SandboxResolvedPaths, SandboxResources, SandboxUnitName, SandboxUnitSpec};

use crate::{HostError, Result};

const PROCESSES: u8 = 2;
const MEMORY: u8 = 3;
const CPU_WEIGHT: u8 = 4;
const CPU_QUOTA: u8 = 5;
const IO_WEIGHT: u8 = 6;
const OPEN_FILES: u8 = 9;
const MICROS_PER_SECOND: u64 = 1_000_000;
pub(crate) const WORKSPACE_PIN_PREFIX: &str = "/run/aos/sandbox-pins/workspaces/";
pub(crate) const NETWORK_PIN_PREFIX: &str = "/run/aos/sandbox-pins/netns/";
const SUPPORTED_BACKEND_FEATURES: &[(&str, u32, u32)] = &[
    ("aos.sandbox.runtime.linux-systemd", 1, 0),
    ("aos.sandbox.identity.posix32", 1, 0),
    ("aos.sandbox.enforcement.cgroup-v2", 1, 0),
    ("aos.sandbox.enforcement.broker-ledger", 1, 0),
];

/// Names an opaque catalog handle carried only inside the local protocol.
pub type OpaqueHandle = [u8; 32];

/// Describes a broker-catalogued private root after identity verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWorkspace {
    /// Absolute directory containing the assembled private sandbox root.
    pub root_directory: String,
    /// Device identity verified against the publisher record.
    pub device: u64,
    /// Inode identity verified against the publisher record.
    pub inode: u64,
}

/// Describes a broker-catalogued prepared network namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNetwork {
    /// Absolute path to a host-owned pinned network namespace descriptor.
    pub namespace_path: String,
    /// Nsfs device identity verified against the publisher record.
    pub device: u64,
    /// Namespace inode identity verified against the publisher record.
    pub inode: u64,
}

/// Describes an incarnation-bound subordinate UID/GID allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedIdentityAllocation {
    /// First host identity mapped to guest identity zero.
    pub range_start: u32,
    /// Number of mapped identities.
    pub range_size: u32,
    /// Catalog generation that allocated this nonoverlapping range.
    pub catalog_generation: u64,
}

/// Carries one assignment-bound, atomically resolved launch resource tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedLaunchResources {
    /// Private assembled runtime root.
    pub workspace: ResolvedWorkspace,
    /// Prepared default-drop network namespace.
    pub network: ResolvedNetwork,
    /// Incarnation-bound private user-namespace allocation.
    pub identity: ResolvedIdentityAllocation,
}

/// Resolves only broker-minted node-local handles into privileged resources.
pub trait HostCatalog {
    /// Resolves and verifies one atomic workspace/network/attachment snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, stale, mismatched, or unready handle.
    fn resolve(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<ResolvedLaunchResources>;
}

/// Proves that the exact node-local nspawn backend passed all executable gates.
///
/// The type intentionally has no production constructor yet. The phase-0
/// probe publisher must eventually construct it only after binding the exact
/// executable store object, MAC policy generation, supervisor allowlist,
/// payload filter, user-namespace behavior, and prepared-network behavior. It
/// must also prove immutable root-owned pin publication across verify-to-exec
/// and enable the worker's post-launch pin-identity check. Until then hostd
/// cannot construct this token and does not advertise runtime launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendReadiness {
    executable: String,
    executable_device: u64,
    executable_inode: u64,
    probe_generation: u64,
    mac_policy_digest: [u8; 32],
    supervisor_profile_digest: [u8; 32],
    payload_filter_digest: [u8; 32],
}

/// Stores node-owned constants used to compile a launch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NspawnConfig {
    executable: String,
    timeout_start: Duration,
    timeout_stop: Duration,
}

impl NspawnConfig {
    /// Constructs an immutable host launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidPlan`] for nonabsolute/unnormalized paths,
    /// an invalid `SELinux` context token, or zero timeouts.
    #[cfg(test)]
    fn new(
        readiness: BackendReadiness,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        let executable = readiness.executable;
        validate_absolute(&executable, "nspawn executable")?;
        if readiness.executable_device == 0
            || readiness.executable_inode == 0
            || readiness.probe_generation == 0
            || readiness.mac_policy_digest == [0; 32]
            || readiness.supervisor_profile_digest == [0; 32]
            || readiness.payload_filter_digest == [0; 32]
        {
            return Err(HostError::InvalidPlan(
                "nspawn backend readiness evidence is incomplete".to_owned(),
            ));
        }
        if timeout_start.is_zero() || timeout_stop.is_zero() {
            return Err(HostError::InvalidPlan(
                "systemd operation timeouts must be nonzero".to_owned(),
            ));
        }
        Ok(Self {
            executable,
            timeout_start,
            timeout_stop,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(executable: impl Into<String>) -> Result<Self> {
        let executable = executable.into();
        Self::new(
            BackendReadiness {
                executable: executable.clone(),
                executable_device: 1,
                executable_inode: 2,
                probe_generation: 1,
                mac_policy_digest: [3; 32],
                supervisor_profile_digest: [4; 32],
                payload_filter_digest: [5; 32],
            },
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
    }

    /// Resolves opaque resources and compiles the sole accepted nspawn argv.
    ///
    /// # Errors
    ///
    /// Returns an error when catalog resolution fails, mandatory cgroup limits
    /// are missing or invalid, or a trusted catalog returns an unsafe path.
    pub fn compile<C: HostCatalog>(
        &self,
        catalog: &C,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<SandboxUnitSpec> {
        let resolved = catalog.resolve(fence, plan)?;
        self.compile_resolved(fence, plan, resolved)
    }

    /// Compiles a launch from the exact resources admitted by the caller.
    ///
    /// Keeping resolution outside this method lets the broker resolve the
    /// controller-authorized opaque handles exactly once for local compilation.
    /// Kernel identities remain node-local checks and never enter the portable
    /// signed request semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported features, invalid required resources,
    /// unsafe resolved paths, or a contradictory identity allocation.
    pub(crate) fn compile_resolved(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        resolved: ResolvedLaunchResources,
    ) -> Result<SandboxUnitSpec> {
        validate_backend_features(plan)?;
        let workspace = resolved.workspace;
        let network = resolved.network;
        validate_resolved_identity(&resolved.identity, plan)?;
        validate_published_pin(
            &workspace.root_directory,
            WORKSPACE_PIN_PREFIX,
            "workspace root",
        )?;
        validate_published_pin(
            &network.namespace_path,
            NETWORK_PIN_PREFIX,
            "network namespace",
        )?;

        let memory_max = required_limit(plan, MEMORY, "memory")?;
        let memory_high = memory_max.saturating_sub(memory_max / 10).max(1);
        let tasks_max = required_limit(plan, PROCESSES, "process")?;
        let cpu_weight = required_limit(plan, CPU_WEIGHT, "CPU weight")?;
        let mut resources = SandboxResources::new(memory_high, memory_max, tasks_max, cpu_weight)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        resources = resources
            .with_open_file_limit(required_limit(plan, OPEN_FILES, "open-file")?)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        if let Some(quota) = optional_limit(plan, CPU_QUOTA) {
            if quota == 0 || quota > MICROS_PER_SECOND {
                return Err(HostError::InvalidPlan(
                    "CPU quota must be in 1..=1000000 microseconds".to_owned(),
                ));
            }
            resources = resources
                .with_cpu_quota(Duration::from_micros(quota))
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        }
        if let Some(weight) = optional_limit(plan, IO_WEIGHT) {
            resources = resources
                .with_io_weight(weight)
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        }

        let command = aos_systemd::SandboxNspawnCommand::private_user_v1(
            self.executable.clone(),
            *fence.incarnation_id(),
            resolved.identity.range_start,
            resolved.identity.range_size,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let paths = SandboxResolvedPaths::new(workspace.root_directory, network.namespace_path)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation(*fence.incarnation_id()),
            command,
            paths,
            resources,
            self.timeout_start,
            self.timeout_stop,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))
    }
}

fn validate_resolved_identity(
    identity: &ResolvedIdentityAllocation,
    plan: &ValidatedRuntimePlan,
) -> Result<()> {
    if identity.range_start == 0
        || identity.range_size < 65_536
        || identity
            .range_start
            .checked_add(identity.range_size)
            .is_none()
        || identity.catalog_generation == 0
        || identity.range_start != plan.uid_range_start()
        || identity.range_size != plan.uid_range_size()
    {
        return Err(HostError::InvalidPlan(
            "runtime identity request does not match its catalog allocation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_backend_features(plan: &ValidatedRuntimePlan) -> Result<()> {
    for feature in plan.required_features() {
        if !backend_supports_feature(feature.namespace(), feature.major(), feature.minor()) {
            return Err(HostError::InvalidPlan(format!(
                "nspawn backend does not implement required feature {} version {}.{}",
                feature.namespace(),
                feature.major(),
                feature.minor()
            )));
        }
    }
    Ok(())
}

fn backend_supports_feature(namespace: &str, major: u32, minor: u32) -> bool {
    SUPPORTED_BACKEND_FEATURES
        .iter()
        .any(|candidate| candidate == &(namespace, major, minor))
}

fn required_limit(plan: &ValidatedRuntimePlan, dimension: u8, label: &str) -> Result<u64> {
    let value = optional_limit(plan, dimension)
        .ok_or_else(|| HostError::InvalidPlan(format!("mandatory {label} limit is absent")))?;
    if value == 0 {
        return Err(HostError::InvalidPlan(format!(
            "mandatory {label} limit is zero"
        )));
    }
    Ok(value)
}

fn optional_limit(plan: &ValidatedRuntimePlan, dimension: u8) -> Option<u64> {
    plan.limits()
        .iter()
        .find(|limit| limit.dimension() == dimension)
        .map(|limit| limit.value())
}

fn validate_absolute(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || !value.starts_with('/')
        || value.as_bytes().contains(&0)
        || value.strip_prefix('/').is_none_or(|tail| {
            tail.is_empty()
                || tail
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
        })
    {
        return Err(HostError::InvalidPlan(format!(
            "{label} is not a bounded normalized absolute path"
        )));
    }
    Ok(())
}

pub(crate) fn validate_published_pin(value: &str, prefix: &str, label: &str) -> Result<()> {
    validate_absolute(value, label)?;
    let name = value.strip_prefix(prefix).ok_or_else(|| {
        HostError::InvalidPlan(format!("{label} is outside its root-owned pin publisher"))
    })?;
    if name.is_empty() || name == "." || name.contains('/') {
        return Err(HostError::InvalidPlan(format!(
            "{label} is not one exact published pin"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_feature_admission_is_an_exact_allowlist() {
        assert!(backend_supports_feature(
            "aos.sandbox.runtime.linux-systemd",
            1,
            0
        ));
        assert!(!backend_supports_feature(
            "aos.sandbox.storage.zfs-held-snapshot",
            1,
            0
        ));
        assert!(!backend_supports_feature(
            "aos.sandbox.runtime.linux-systemd",
            1,
            1
        ));
    }

    #[test]
    fn publisher_pin_paths_reject_root_dot_and_nested_names() {
        assert!(validate_published_pin("/", WORKSPACE_PIN_PREFIX, "workspace").is_err());
        assert!(
            validate_published_pin(
                "/run/aos/sandbox-pins/workspaces/.",
                WORKSPACE_PIN_PREFIX,
                "workspace"
            )
            .is_err()
        );
        assert!(
            validate_published_pin(
                "/run/aos/sandbox-pins/workspaces/a/b",
                WORKSPACE_PIN_PREFIX,
                "workspace"
            )
            .is_err()
        );
        assert!(
            validate_published_pin(
                "/run/aos/sandbox-pins/workspaces/a",
                WORKSPACE_PIN_PREFIX,
                "workspace"
            )
            .is_ok()
        );
    }
}
