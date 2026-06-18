//! Host policy parsing for RFC-0001 package permission admission.
//!
//! The policy file lives at `/etc/aos/policy.toml` on AOS hosts. It names a
//! coarse policy tier, then optionally adds explicit allowlists for individual
//! permissions. A minimal file is:
//!
//! ```toml
//! tier = "baseline"
//!
//! [allow]
//! networks = ["private"]
//! syscall-profiles = ["system-service"]
//!
//! kernel-modules = ["br_netfilter"]
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::types::{
    HostPathPermission, NetworkPermission, PackageMeta, PermissionsMeta, PolicyTier,
    SyscallProfile, validate_absolute_path, validate_capability_name, validate_kernel_module_name,
    validate_package_name, validate_permissions_meta, validate_registry_name,
    validate_security_label,
};

/// Default host policy path on an AOS system.
pub const DEFAULT_POLICY_PATH: &str = "/etc/aos/policy.toml";

/// Admit all permission-bearing package metadata entries against host policy.
///
/// Empty manifests need no policy grants and do not require the policy file to
/// exist, preserving ordinary package installs on non-AOS development hosts.
///
/// # Errors
///
/// Returns an error when any permission-bearing package exceeds the host
/// policy or when the policy file cannot be read.
pub fn admit_package_roots<'a>(metas: impl IntoIterator<Item = &'a PackageMeta>) -> Result<()> {
    let permission_roots: Vec<&PackageMeta> = metas
        .into_iter()
        .filter(|meta| {
            meta.permissions
                .requires_policy_admission_for_package(&meta.name)
        })
        .collect();
    if permission_roots.is_empty() {
        return Ok(());
    }

    let policy = HostPolicy::load_from_root(&policy_root())
        .context("loading /etc/aos/policy.toml for permission-bearing package admission")?;
    for meta in permission_roots {
        policy
            .admit_for_package(&meta.name, &meta.permissions)
            .with_context(|| format!("admitting permissions for package '{}'", meta.name))?;
    }
    Ok(())
}

pub(crate) fn policy_root() -> PathBuf {
    std::env::var("AOS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

/// Parsed host policy used to admit package permission manifests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicy {
    /// Named coarse policy tier.
    #[serde(default)]
    pub tier: PolicyTier,
    /// Optional per-permission allowlist extensions.
    #[serde(default)]
    pub allow: PolicyAllow,
    /// Host-fulfilled kernel modules allowed on this host.
    #[serde(default, rename = "kernel-modules")]
    pub kernel_modules: Vec<String>,
    /// Maximum allowed `systemd-analyze security` exposure score for this tier.
    #[serde(default, rename = "systemd-security-threshold")]
    pub systemd_security_threshold: Option<f64>,
    /// Fleet-managed BPF-LSM policy packages selected for this host.
    #[serde(default, rename = "ebpf-lsm")]
    pub ebpf_lsm: EbpfLsmPolicySet,
}

impl HostPolicy {
    /// Parse a host policy from TOML text.
    ///
    /// # Errors
    ///
    /// Returns an error when the TOML is invalid or the policy references
    /// malformed path/module/capability entries.
    pub fn parse_str(content: &str) -> Result<Self> {
        let policy: Self = toml::from_str(content).context("invalid AOS policy TOML")?;
        policy.validate()?;
        Ok(policy)
    }

    /// Load the host policy from `root` plus [`DEFAULT_POLICY_PATH`].
    ///
    /// # Errors
    ///
    /// Returns an error when the policy file cannot be read or parsed.
    pub fn load_from_root(root: &Path) -> Result<Self> {
        let relative = DEFAULT_POLICY_PATH.trim_start_matches('/');
        let path = root.join(relative);
        Self::load_from_path(&path)
    }

    /// Load the host policy from an explicit path.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy file cannot be read or parsed.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse_str(&content).with_context(|| format!("parsing {}", path.display()))
    }

    /// Return `Ok(())` when this policy admits the requested permissions.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first requested permission that exceeds
    /// this host policy.
    pub fn admit(&self, permissions: &PermissionsMeta) -> Result<()> {
        self.admit_inner("package", permissions, false)
    }

    /// Return `Ok(())` when this policy admits a package's requested permissions.
    ///
    /// The generated default security label `aos-pkg-<package>` is metadata
    /// for package-scoped display and does not require a host policy allowlist.
    /// Custom labels remain policy-controlled.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first requested permission that exceeds
    /// this host policy.
    pub fn admit_for_package(
        &self,
        package_name: &str,
        permissions: &PermissionsMeta,
    ) -> Result<()> {
        self.admit_inner(package_name, permissions, true)
    }

    fn admit_inner(
        &self,
        package_name: &str,
        permissions: &PermissionsMeta,
        allow_generated_label: bool,
    ) -> Result<()> {
        validate_permissions_meta(package_name, permissions)?;

        let network = permissions.network.unwrap_or(NetworkPermission::Private);
        if !self.allows_network(network) {
            bail!("network mode '{network:?}' is not allowed by host policy");
        }

        for port in &permissions.tcp_bind {
            if !self.allows_tcp_bind(*port) {
                bail!("TCP bind port {port} is not allowed by host policy");
            }
        }

        for port in &permissions.tcp_connect {
            if !self.allows_tcp_connect(*port) {
                bail!("TCP connect port {port} is not allowed by host policy");
            }
        }

        for capability in &permissions.capabilities {
            if !self.allows_capability(capability) {
                bail!("capability '{capability}' is not allowed by host policy");
            }
        }

        for device in &permissions.devices {
            if !self.allows_device(device) {
                bail!("device '{device}' is not allowed by host policy");
            }
        }

        for host_path in &permissions.host_paths {
            if !self.allows_host_path(host_path) {
                bail!(
                    "host path '{} ({:?})' is not allowed by host policy",
                    host_path.path,
                    host_path.mode
                );
            }
        }

        if permissions.cgroup_delegate && !self.allows_cgroup_delegate() {
            bail!("cgroup delegation is not allowed by host policy");
        }

        if permissions.privileged_users && !self.allows_privileged_users() {
            bail!("privileged users are not allowed by host policy");
        }

        for module in &permissions.kernel_modules {
            if !self.kernel_modules.iter().any(|allowed| allowed == module) {
                bail!("kernel module '{module}' is not allowed by host policy");
            }
        }

        if let Some(profile) = permissions.syscalls {
            if !self.allows_syscall_profile(profile) {
                bail!("syscall profile '{profile:?}' is not allowed by host policy");
            }
        }

        if let Some(label) = &permissions.security_label {
            if !(allow_generated_label && is_generated_security_label(label, package_name))
                && !self.allows_security_label(label)
            {
                bail!("security label '{label}' is not allowed by host policy");
            }
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        for module in &self.kernel_modules {
            validate_kernel_module_name(module)?;
        }
        for capability in &self.allow.capabilities {
            validate_capability_name(capability)?;
        }
        for device in &self.allow.devices {
            validate_absolute_path(device, "device")?;
        }
        for host_path in &self.allow.host_paths {
            validate_absolute_path(&host_path.path, "host path")?;
        }
        for label in &self.allow.security_labels {
            validate_security_label(label)?;
        }
        self.ebpf_lsm.validate()?;
        validate_policy_ports("allow.tcp-bind", &self.allow.tcp_bind)?;
        validate_policy_ports("allow.tcp-connect", &self.allow.tcp_connect)?;
        Ok(())
    }

    fn allows_network(&self, network: NetworkPermission) -> bool {
        self.allow.networks.contains(&network)
            || match self.tier {
                PolicyTier::Restricted | PolicyTier::Baseline => {
                    network == NetworkPermission::Private
                }
                PolicyTier::Privileged => true,
            }
    }

    fn allows_capability(&self, capability: &str) -> bool {
        self.tier == PolicyTier::Privileged
            || self
                .allow
                .capabilities
                .iter()
                .any(|allowed| allowed == capability)
    }

    fn allows_tcp_bind(&self, port: u16) -> bool {
        self.tier == PolicyTier::Privileged || self.allow.tcp_bind.contains(&port)
    }

    fn allows_tcp_connect(&self, port: u16) -> bool {
        self.tier == PolicyTier::Privileged || self.allow.tcp_connect.contains(&port)
    }

    fn allows_device(&self, device: &str) -> bool {
        self.tier == PolicyTier::Privileged
            || self.allow.devices.iter().any(|allowed| allowed == device)
    }

    fn allows_host_path(&self, host_path: &HostPathPermission) -> bool {
        if self.tier == PolicyTier::Privileged {
            return true;
        }

        self.allow
            .host_paths
            .iter()
            .any(|allowed| allowed.path == host_path.path && allowed.mode == host_path.mode)
    }

    fn allows_cgroup_delegate(&self) -> bool {
        self.tier == PolicyTier::Privileged || self.allow.cgroup_delegate
    }

    fn allows_privileged_users(&self) -> bool {
        self.tier == PolicyTier::Privileged || self.allow.privileged_users
    }

    fn allows_syscall_profile(&self, profile: SyscallProfile) -> bool {
        self.allow.syscall_profiles.contains(&profile)
            || match self.tier {
                PolicyTier::Restricted => profile == SyscallProfile::Restricted,
                PolicyTier::Baseline => {
                    matches!(
                        profile,
                        SyscallProfile::Restricted | SyscallProfile::SystemService
                    )
                }
                PolicyTier::Privileged => true,
            }
    }

    fn allows_security_label(&self, label: &str) -> bool {
        self.tier == PolicyTier::Privileged
            || self
                .allow
                .security_labels
                .iter()
                .any(|allowed| allowed == label)
    }
}

fn is_generated_security_label(label: &str, package_name: &str) -> bool {
    label == format!("aos-pkg-{package_name}")
}

fn validate_policy_ports(kind: &str, ports: &[u16]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for port in ports {
        if *port == 0 {
            bail!("{kind} contains invalid TCP port 0");
        }
        if !seen.insert(port) {
            bail!("{kind} contains duplicate TCP port {port}");
        }
    }
    Ok(())
}

/// Per-permission host policy overrides.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAllow {
    /// Additional capabilities allowed by this host.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Additional network modes allowed by this host.
    #[serde(default)]
    pub networks: Vec<NetworkPermission>,
    /// TCP ports packages may bind under Landlock/eBPF network policy.
    #[serde(default, rename = "tcp-bind")]
    pub tcp_bind: Vec<u16>,
    /// TCP ports packages may connect to under Landlock/eBPF network policy.
    #[serde(default, rename = "tcp-connect")]
    pub tcp_connect: Vec<u16>,
    /// Additional device nodes allowed by this host.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Additional host paths allowed by this host.
    #[serde(default, rename = "host-paths")]
    pub host_paths: Vec<HostPathPermission>,
    /// Whether this host allows cgroup controller delegation.
    #[serde(default, rename = "cgroup-delegate")]
    pub cgroup_delegate: bool,
    /// Whether this host allows disabling user namespace isolation.
    #[serde(default, rename = "privileged-users")]
    pub privileged_users: bool,
    /// Additional syscall profiles allowed by this host.
    #[serde(default, rename = "syscall-profiles")]
    pub syscall_profiles: Vec<SyscallProfile>,
    /// Additional generated security labels allowed by this host.
    #[serde(default, rename = "security-labels")]
    pub security_labels: Vec<String>,
}

/// Fleet-managed BPF-LSM policy references selected by host policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfLsmPolicySet {
    /// Signed policy packages to load on this host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<EbpfLsmPolicyRef>,
}

impl EbpfLsmPolicySet {
    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !seen.insert(&policy.name) {
                bail!("duplicate ebpf-lsm policy '{}'", policy.name);
            }
        }
        Ok(())
    }
}

/// A signed registry package and artifact paths for one fleet BPF-LSM policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfLsmPolicyRef {
    /// Stable policy name used for bpffs link pins.
    pub name: String,
    /// Registry that supplied the installed policy package.
    pub registry: String,
    /// Installed package carrying the BPF-LSM policy artifact.
    pub package: String,
    /// Exact package version selected by fleet policy.
    pub version: String,
    /// Relative JSON policy path inside the installed package root.
    pub policy: String,
    /// Relative BPF object path inside the installed package root.
    pub object: String,
    /// BPF program names expected in the object and policy JSON.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<String>,
}

impl EbpfLsmPolicyRef {
    fn validate(&self) -> Result<()> {
        validate_safe_label("ebpf-lsm policy name", &self.name)?;
        validate_registry_name(&self.registry)?;
        validate_package_name(&self.package)?;
        validate_version(&self.version)?;
        validate_relative_artifact_path("ebpf-lsm policy", &self.policy, ".json")?;
        validate_relative_artifact_path("ebpf-lsm object", &self.object, ".bpf.o")?;
        if self.programs.is_empty() {
            bail!(
                "ebpf-lsm policy '{}' must name at least one program",
                self.name
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for program in &self.programs {
            validate_bpf_program_name(program)?;
            if !seen.insert(program) {
                bail!(
                    "ebpf-lsm policy '{}' contains duplicate program '{}'",
                    self.name,
                    program
                );
            }
        }
        Ok(())
    }
}

fn validate_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\'))
    {
        bail!("invalid ebpf-lsm package version '{version}'");
    }
    Ok(())
}

fn validate_relative_artifact_path(kind: &str, path: &str, suffix: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || !path.ends_with(suffix) {
        bail!("{kind} path '{path}' must be a relative *{suffix} path");
    }
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) if !part.is_empty() => {}
            _ => bail!("{kind} path '{path}' must not contain '.', '..', or prefixes"),
        }
    }
    Ok(())
}

fn validate_safe_label(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        bail!("invalid {kind} '{value}'");
    }
    Ok(())
}

fn validate_bpf_program_name(program: &str) -> Result<()> {
    let mut chars = program.chars();
    let Some(first) = chars.next() else {
        bail!("BPF program name must not be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        bail!("invalid BPF program name '{program}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HostPathMode;

    #[test]
    fn parses_policy_file_format() {
        let policy = HostPolicy::parse_str(
            r#"
tier = "baseline"
kernel-modules = ["br_netfilter"]
systemd-security-threshold = 5.5

[allow]
networks = ["private-outbound"]
tcp-bind = [8080]
tcp-connect = [443]
capabilities = ["CAP_NET_BIND_SERVICE"]
devices = ["/dev/net/tun"]
host-paths = [{ path = "/var/lib/rancher", mode = "rw" }]
syscall-profiles = ["system-service"]

[[ebpf-lsm.policies]]
name = "aos-lsm-task-audit"
registry = "aos"
package = "aos-ebpf-lsm-policy"
version = "0"
policy = "share/aos/ebpf-lsm/aos-task-audit.json"
object = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
programs = ["aos_lsm_file_mprotect"]
"#,
        )
        .unwrap();

        assert_eq!(policy.tier, PolicyTier::Baseline);
        assert_eq!(policy.kernel_modules, vec!["br_netfilter"]);
        assert_eq!(policy.systemd_security_threshold, Some(5.5));
        assert!(
            policy
                .allow
                .networks
                .contains(&NetworkPermission::PrivateOutbound)
        );
        assert_eq!(policy.allow.tcp_bind, vec![8080]);
        assert_eq!(policy.allow.tcp_connect, vec![443]);
        assert_eq!(policy.ebpf_lsm.policies.len(), 1);
        assert_eq!(
            policy.ebpf_lsm.policies[0].object,
            "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
        );
    }

    #[test]
    fn admits_only_requested_permissions_within_policy() {
        let policy = HostPolicy::parse_str(
            r#"
tier = "restricted"
kernel-modules = ["br_netfilter"]

[allow]
networks = ["private-outbound"]
tcp-bind = [8080]
tcp-connect = [443]
capabilities = ["CAP_NET_BIND_SERVICE"]
host-paths = [{ path = "/srv/data", mode = "read-only" }]
syscall-profiles = ["system-service"]
"#,
        )
        .unwrap();

        let permissions = PermissionsMeta {
            capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            network: Some(NetworkPermission::PrivateOutbound),
            tcp_bind: vec![8080],
            tcp_connect: vec![443],
            host_paths: vec![HostPathPermission {
                path: "/srv/data".into(),
                mode: HostPathMode::ReadOnly,
            }],
            kernel_modules: vec!["br_netfilter".into()],
            syscalls: Some(SyscallProfile::SystemService),
            ..PermissionsMeta::default()
        };

        policy.admit(&permissions).unwrap();
    }

    #[test]
    fn rejects_network_policy_ports_outside_policy() {
        let policy = HostPolicy::parse_str(
            r#"
tier = "baseline"

[allow]
tcp-connect = [443]
"#,
        )
        .unwrap();

        let err = policy
            .admit(&PermissionsMeta {
                tcp_connect: vec![8443],
                ..PermissionsMeta::default()
            })
            .unwrap_err();
        assert!(err.to_string().contains("TCP connect port 8443"));

        let err = HostPolicy::parse_str(
            r#"
[allow]
tcp-bind = [8080, 8080]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate TCP port 8080"));
    }

    #[test]
    fn generated_metadata_alone_does_not_require_policy_admission() {
        let mut permissions = PermissionsMeta {
            security_label: Some("aos-pkg-expose-minimal".into()),
            ..PermissionsMeta::default()
        };
        permissions.confinement = Some(permissions.computed_confinement());

        assert!(!permissions.requires_policy_admission());
        assert!(!permissions.requires_policy_admission_for_package("expose-minimal"));

        permissions.security_label = Some("custom.expose-minimal".into());
        assert!(permissions.requires_policy_admission_for_package("expose-minimal"));

        permissions.security_label = Some("aos-pkg-expose-minimal".into());
        permissions.kernel_modules = vec!["br_netfilter".into()];
        assert!(permissions.requires_policy_admission());

        let policy = HostPolicy::parse_str(
            r#"
tier = "restricted"
kernel-modules = ["br_netfilter"]
"#,
        )
        .unwrap();
        policy
            .admit_for_package("expose-minimal", &permissions)
            .unwrap();

        let err = policy.admit(&permissions).unwrap_err();
        assert!(
            err.to_string()
                .contains("security label 'aos-pkg-expose-minimal'"),
            "got: {err}"
        );

        permissions.security_label = Some("custom.expose-minimal".into());
        let err = policy
            .admit_for_package("expose-minimal", &permissions)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("security label 'custom.expose-minimal'"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_non_allowlisted_kernel_module() {
        let policy = HostPolicy::parse_str(
            r#"
tier = "privileged"
kernel-modules = ["br_netfilter"]
"#,
        )
        .unwrap();

        let permissions = PermissionsMeta {
            kernel_modules: vec!["zfs".into()],
            ..PermissionsMeta::default()
        };

        let err = policy.admit(&permissions).unwrap_err();
        assert!(err.to_string().contains("kernel module 'zfs'"));
    }

    #[test]
    fn rejects_unsafe_ebpf_lsm_policy_references() {
        let err = HostPolicy::parse_str(
            r#"
[[ebpf-lsm.policies]]
name = "bad"
registry = "aos"
package = "aos-ebpf-lsm-policy"
version = "0"
policy = "../policy.json"
object = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
programs = ["aos_lsm_file_mprotect"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not contain"));

        let err = HostPolicy::parse_str(
            r#"
[[ebpf-lsm.policies]]
name = "bad"
registry = "aos"
package = "aos-ebpf-lsm-policy"
version = "0"
policy = "share/aos/ebpf-lsm/aos-task-audit.json"
object = "/nix/store/object.bpf.o"
programs = ["aos_lsm_file_mprotect"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("relative *.bpf.o"));
    }
}
