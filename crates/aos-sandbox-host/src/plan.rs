//! Trusted catalog resolution and fixed nspawn launch compilation.

use std::time::Duration;

use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use aos_systemd::{SandboxResources, SandboxUnitName, SandboxUnitSpec};

use crate::{HostError, Result};

const PROCESSES: u8 = 2;
const MEMORY: u8 = 3;
const CPU_WEIGHT: u8 = 4;
const CPU_QUOTA: u8 = 5;
const IO_WEIGHT: u8 = 6;
const MICROS_PER_SECOND: u64 = 1_000_000;

/// Names an opaque catalog handle carried only inside the local protocol.
pub type OpaqueHandle = [u8; 32];

/// Describes a broker-catalogued private root after identity verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWorkspace {
    /// Absolute directory containing the assembled private sandbox root.
    pub root_directory: String,
}

/// Describes a broker-catalogued prepared network namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNetwork {
    /// Absolute path to a host-owned pinned network namespace descriptor.
    pub namespace_path: String,
}

/// Resolves only broker-minted node-local handles into privileged resources.
pub trait HostCatalog {
    /// Resolves a workspace and verifies its exact immutable root descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, stale, mismatched, or unready handle.
    fn resolve_workspace(&self, plan: &ValidatedRuntimePlan) -> Result<ResolvedWorkspace>;

    /// Resolves a prepared, default-drop network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, stale, mismatched, or unready handle.
    fn resolve_network(&self, plan: &ValidatedRuntimePlan) -> Result<ResolvedNetwork>;

    /// Verifies every attachment handle is installed for this exact launch.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, stale, mismatched, or unready handle.
    fn validate_attachments(&self, plan: &ValidatedRuntimePlan) -> Result<()>;
}

/// Selects the immutable nspawn payload security profile compiled into AOS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadSecurityProfile {
    /// Private-user-namespace baseline with the fixed pre-PID1 syscall filter.
    PrivateUserBaseline,
}

/// Stores node-owned constants used to compile a launch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NspawnConfig {
    executable: String,
    payload_selinux_context: String,
    security_profile: PayloadSecurityProfile,
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
    pub fn new(
        executable: impl Into<String>,
        payload_selinux_context: impl Into<String>,
        security_profile: PayloadSecurityProfile,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        let executable = executable.into();
        let payload_selinux_context = payload_selinux_context.into();
        validate_absolute(&executable, "nspawn executable")?;
        validate_token(&payload_selinux_context, "payload SELinux context")?;
        if timeout_start.is_zero() || timeout_stop.is_zero() {
            return Err(HostError::InvalidPlan(
                "systemd operation timeouts must be nonzero".to_owned(),
            ));
        }
        Ok(Self {
            executable,
            payload_selinux_context,
            security_profile,
            timeout_start,
            timeout_stop,
        })
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
        let workspace = catalog.resolve_workspace(plan)?;
        let network = catalog.resolve_network(plan)?;
        catalog.validate_attachments(plan)?;
        validate_absolute(&workspace.root_directory, "workspace root")?;
        validate_absolute(&network.namespace_path, "network namespace")?;

        let memory_max = required_limit(plan, MEMORY, "memory")?;
        let memory_high = memory_max.saturating_sub(memory_max / 10).max(1);
        let tasks_max = required_limit(plan, PROCESSES, "process")?;
        let cpu_weight = required_limit(plan, CPU_WEIGHT, "CPU weight")?;
        let mut resources = SandboxResources::new(memory_high, memory_max, tasks_max, cpu_weight)
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

        let arguments = self.arguments(fence, plan, &workspace.root_directory);
        SandboxUnitSpec::new(
            SandboxUnitName::from_incarnation(*fence.incarnation_id()),
            self.executable.clone(),
            arguments,
            network.namespace_path,
            resources,
            self.timeout_start,
            self.timeout_stop,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))
    }

    fn arguments(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        root: &str,
    ) -> Vec<String> {
        let machine = encode_hex(*fence.incarnation_id());
        let user_range = format!("{}:{}", plan.uid_range_start(), plan.uid_range_size());
        let mut arguments = vec![
            "--boot".to_owned(),
            "--quiet".to_owned(),
            "--keep-unit".to_owned(),
            "--register=no".to_owned(),
            "--settings=no".to_owned(),
            format!("--machine=aos-{machine}"),
            format!("--directory={root}"),
            format!("--private-users={user_range}"),
            "--private-users-ownership=map".to_owned(),
            "--notify-ready=yes".to_owned(),
            format!("--selinux-context={}", self.payload_selinux_context),
            "--no-new-privileges=yes".to_owned(),
        ];
        match self.security_profile {
            PayloadSecurityProfile::PrivateUserBaseline => {
                arguments.push("--aos-payload-filter=private-user-v1".to_owned());
            }
        }
        arguments
    }
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
        || value.split('/').any(|component| component == "..")
    {
        return Err(HostError::InvalidPlan(format!(
            "{label} is not a bounded normalized absolute path"
        )));
    }
    Ok(())
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
    {
        return Err(HostError::InvalidPlan(format!(
            "{label} is not a normalized token"
        )));
    }
    Ok(())
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
