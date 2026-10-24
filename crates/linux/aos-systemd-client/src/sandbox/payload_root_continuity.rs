//! Canonical fixed payload-root-continuity policy.
//!
//! This module owns the ordered nspawn argument and transient-unit property
//! programs. The same closed projection compiles production launch data and
//! feeds the domain-separated policy digest.
//!
//! Canonical strings and sequence lengths use unsigned 64-bit big-endian
//! lengths; enum tags and booleans use one byte:
//!
//! ```text
//! domain || root-role || attachment-role || argument-program || property-program
//! ```

use sha2::{Digest as _, Sha256};
use zbus::zvariant::Fd;

use crate::manager_proxy::TransientProperty;

use super::{
    Result, SandboxDevice, SandboxNspawnCommand, SandboxUnitSpec, bool_property, complex_property,
    duration_micros, encode_hex, encode_hex32, invalid, named_exec_property, semantic_string,
    string_array_property, string_property, u32_property, u64_property,
};

#[macro_use]
mod property_recipe;

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
const NSPAWN_ROOT_DESCRIPTOR_ROLE: &str = "aos-sandbox-root-mount-v1";
const NSPAWN_ATTACHMENT_ANCHOR_DESCRIPTOR_ROLE: &str = "aos-sandbox-attachment-anchor-v1";
const NSPAWN_ATTACHMENT_ANCHOR_NAMESPACE_DESCRIPTOR_ROLE: &str =
    "aos-sandbox-attachment-anchor-namespace-v1";
const GUEST_CHANNEL_ROLE_V2: &str = "aos-sandbox-guest-agent-channel-v1";
const GUEST_PROVISIONING_ROLE_V2: &str = "aos-sandbox-guest-agent-provisioning-v1";
const GUEST_ATTACH_TRUST_ROLE_V2: &str = "aos-sandbox-guest-attach-trust-v1";
const HOST_REPORT_ROLE_V2: &str = "aos-host-readiness-report";
const NSPAWN_SUPERVISOR_SELINUX_CONTEXT: &str = "system_u:system_r:aos_nspawn_t:s0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescriptorRoleV1 {
    Root,
    AttachmentAnchor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorRoleVocabularyV1<'a> {
    root: &'a str,
    attachment_anchor: &'a str,
    attachment_anchor_namespace: &'a str,
}

impl<'a> DescriptorRoleVocabularyV1<'a> {
    fn resolve(self, role: DescriptorRoleV1) -> &'a str {
        match role {
            DescriptorRoleV1::Root => self.root,
            DescriptorRoleV1::AttachmentAnchor => self.attachment_anchor,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NspawnArgumentPolicyV1<'a> {
    Literal(&'a str),
    Machine {
        option: &'a str,
        prefix: &'a str,
    },
    Descriptor {
        option: &'a str,
        role: DescriptorRoleV1,
        optional: bool,
    },
    PrivateUsers {
        option: &'a str,
        separator: &'a str,
    },
    GuestAgentFds {
        option: &'a str,
        roles: [&'a str; 3],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeviceAllowRuleV1<'a> {
    device: SandboxDevice,
    path: &'a str,
    permissions: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceU64FieldV1 {
    TasksMax,
    MemoryHigh,
    MemoryMax,
    CpuWeight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurationU64FieldV1 {
    TimeoutStart,
    TimeoutStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionalU64FieldV1 {
    CpuQuota,
    IoWeight,
    OpenFiles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnitPropertyPolicyV1<'a> {
    Description {
        name: &'a str,
        prefix: &'a str,
    },
    String {
        name: &'a str,
        value: &'a str,
    },
    Bool {
        name: &'a str,
        value: bool,
    },
    U32 {
        name: &'a str,
        value: u32,
    },
    U64 {
        name: &'a str,
        value: u64,
    },
    BoolStringArray {
        name: &'a str,
        allow: bool,
        values: &'a [&'a str],
    },
    StringArray {
        name: &'a str,
        values: &'a [&'a str],
    },
    StringPairs {
        name: &'a str,
        values: &'a [(&'a str, &'a str)],
    },
    ExtraFileDescriptors {
        name: &'a str,
    },
    Environment {
        name: &'a str,
        fixed: &'a [&'a str],
        binding_prefix: &'a str,
    },
    GuardianDependency {
        name: &'a str,
    },
    ResourceU64 {
        name: &'a str,
        field: ResourceU64FieldV1,
    },
    DurationU64 {
        name: &'a str,
        field: DurationU64FieldV1,
    },
    OptionalU64 {
        name: &'a str,
        field: OptionalU64FieldV1,
    },
    NetworkNamespace {
        name: &'a str,
    },
    ExecStart {
        name: &'a str,
        ignore_failure: bool,
    },
    DeviceAllow {
        name: &'a str,
        rules: &'a [DeviceAllowRuleV1<'a>],
    },
}

impl<'a> UnitPropertyPolicyV1<'a> {
    const fn name(self) -> &'a str {
        match self {
            Self::Description { name, .. }
            | Self::String { name, .. }
            | Self::Bool { name, .. }
            | Self::U32 { name, .. }
            | Self::U64 { name, .. }
            | Self::BoolStringArray { name, .. }
            | Self::StringArray { name, .. }
            | Self::StringPairs { name, .. }
            | Self::ExtraFileDescriptors { name }
            | Self::Environment { name, .. }
            | Self::GuardianDependency { name }
            | Self::ResourceU64 { name, .. }
            | Self::DurationU64 { name, .. }
            | Self::OptionalU64 { name, .. }
            | Self::NetworkNamespace { name }
            | Self::ExecStart { name, .. }
            | Self::DeviceAllow { name, .. } => name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadRootContinuityProjectionV1<'a> {
    // This vocabulary is shared by argv and D-Bus fd compilation.
    descriptor_roles: DescriptorRoleVocabularyV1<'a>,
    nspawn_arguments: &'a [NspawnArgumentPolicyV1<'a>],
    unit_properties: &'a [UnitPropertyPolicyV1<'a>],
}

const NSPAWN_ARGUMENT_POLICY_V1: &[NspawnArgumentPolicyV1<'_>] = &[
    NspawnArgumentPolicyV1::Literal("--boot"),
    NspawnArgumentPolicyV1::Literal("--quiet"),
    NspawnArgumentPolicyV1::Literal("--keep-unit"),
    NspawnArgumentPolicyV1::Literal("--register=no"),
    NspawnArgumentPolicyV1::Literal("--settings=no"),
    NspawnArgumentPolicyV1::Machine {
        option: "--machine=",
        prefix: "aos-",
    },
    NspawnArgumentPolicyV1::Descriptor {
        option: "--aos-root-mount-fd=",
        role: DescriptorRoleV1::Root,
        optional: false,
    },
    NspawnArgumentPolicyV1::PrivateUsers {
        option: "--private-users=",
        separator: ":",
    },
    NspawnArgumentPolicyV1::Literal("--private-users-ownership=map"),
    NspawnArgumentPolicyV1::Literal("--notify-ready=yes"),
    // Launch bytes belong to this portable canonical program. Linux
    // conformance checks join the context to the actual Guest Owner subject.
    NspawnArgumentPolicyV1::Literal(
        "--selinux-context=system_u:system_r:aos_sandbox_guest_owner_t:s0",
    ),
    NspawnArgumentPolicyV1::Literal("--no-new-privileges=yes"),
    NspawnArgumentPolicyV1::Literal(concat!(
        "--drop-capability=",
        "CAP_AUDIT_CONTROL,CAP_AUDIT_READ,CAP_AUDIT_WRITE,CAP_BLOCK_SUSPEND,",
        "CAP_BPF,CAP_CHECKPOINT_RESTORE,CAP_DAC_READ_SEARCH,CAP_IPC_LOCK,",
        "CAP_IPC_OWNER,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_MAC_ADMIN,",
        "CAP_MAC_OVERRIDE,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_BROADCAST,CAP_NET_RAW,",
        "CAP_PERFMON,CAP_SYSLOG,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_CHROOT,",
        "CAP_SYS_MODULE,CAP_SYS_NICE,CAP_SYS_PACCT,CAP_SYS_PTRACE,CAP_SYS_RAWIO,",
        "CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_WAKE_ALARM"
    )),
    NspawnArgumentPolicyV1::Literal(concat!(
        "--system-call-filter=",
        "~@mount @module @raw-io @reboot bpf perf_event_open ptrace setns unshare"
    )),
    NspawnArgumentPolicyV1::Literal("--aos-payload-seccomp-profile=aos-sandbox-payload-v1"),
    NspawnArgumentPolicyV1::Literal("--aos-lifecycle-profile=aos-sandbox-lifecycle-v1"),
    NspawnArgumentPolicyV1::Descriptor {
        option: "--aos-attachment-anchor-fd=",
        role: DescriptorRoleV1::AttachmentAnchor,
        optional: true,
    },
    NspawnArgumentPolicyV1::GuestAgentFds {
        option: "--aos-guest-agent-fds=",
        roles: [
            "aos-sandbox-guest-agent-channel-v1",
            "aos-sandbox-guest-agent-provisioning-v1",
            "aos-sandbox-guest-attach-trust-v1",
        ],
    },
];

const NSPAWN_DENIED_SYSCALLS: &[&str] = &["bpf:EPERM", "reboot:EPERM"];
const NSPAWN_SYSCALL_ARCHITECTURES: &[&str] = &["native"];
const NSPAWN_TEMPORARY_FILESYSTEMS: &[(&str, &str)] = &[(
    "/run/systemd/nspawn",
    "rw,mode=0700,nosuid,nodev,noexec,size=16M",
)];
const DEVICE_ALLOW_RULES_V1: &[DeviceAllowRuleV1<'_>] = &[
    DeviceAllowRuleV1 {
        device: SandboxDevice::Kvm,
        path: "/dev/kvm",
        permissions: "rw",
    },
    DeviceAllowRuleV1 {
        device: SandboxDevice::Tun,
        path: "/dev/net/tun",
        permissions: "rw",
    },
    DeviceAllowRuleV1 {
        device: SandboxDevice::Fuse,
        path: "/dev/fuse",
        permissions: "rw",
    },
];

const UNIT_PROPERTY_POLICY_V1: &[UnitPropertyPolicyV1<'_>] = &[
    UnitPropertyPolicyV1::Description {
        name: "Description",
        prefix: "AOS sandbox ",
    },
    UnitPropertyPolicyV1::String {
        name: "Type",
        value: "notify",
    },
    UnitPropertyPolicyV1::String {
        name: "NotifyAccess",
        value: "main",
    },
    UnitPropertyPolicyV1::Bool {
        name: "Delegate",
        value: true,
    },
    UnitPropertyPolicyV1::String {
        name: "DelegateSubgroup",
        value: "supervisor",
    },
    UnitPropertyPolicyV1::String {
        name: "Slice",
        value: "aos-sandboxes.slice",
    },
    // Automatic restart could resolve a recycled broker procfs fd alias.
    UnitPropertyPolicyV1::String {
        name: "Restart",
        value: "no",
    },
    UnitPropertyPolicyV1::String {
        name: "CollectMode",
        value: "inactive-or-failed",
    },
    UnitPropertyPolicyV1::String {
        name: "KillMode",
        value: "mixed",
    },
    UnitPropertyPolicyV1::String {
        name: "OOMPolicy",
        value: "kill",
    },
    UnitPropertyPolicyV1::U64 {
        name: "CapabilityBoundingSet",
        value: NSPAWN_SUPERVISOR_CAPABILITIES,
    },
    UnitPropertyPolicyV1::BoolStringArray {
        name: "RestrictAddressFamilies",
        allow: true,
        values: NSPAWN_ADDRESS_FAMILIES,
    },
    UnitPropertyPolicyV1::BoolStringArray {
        name: "SystemCallFilter",
        allow: true,
        values: NSPAWN_ALLOWED_SYSCALLS,
    },
    // Repeated filters are ordered; startup probes receive nonfatal denials.
    UnitPropertyPolicyV1::BoolStringArray {
        name: "SystemCallFilter",
        allow: false,
        values: NSPAWN_DENIED_SYSCALLS,
    },
    UnitPropertyPolicyV1::StringArray {
        name: "SystemCallArchitectures",
        values: NSPAWN_SYSCALL_ARCHITECTURES,
    },
    UnitPropertyPolicyV1::String {
        name: "ProtectSystem",
        value: "strict",
    },
    UnitPropertyPolicyV1::String {
        name: "SELinuxContext",
        value: NSPAWN_SUPERVISOR_SELINUX_CONTEXT,
    },
    UnitPropertyPolicyV1::Bool {
        name: "LockPersonality",
        value: true,
    },
    UnitPropertyPolicyV1::Bool {
        name: "RestrictRealtime",
        value: true,
    },
    UnitPropertyPolicyV1::String {
        name: "KeyringMode",
        value: "private",
    },
    UnitPropertyPolicyV1::U32 {
        name: "UMask",
        value: 0o077,
    },
    UnitPropertyPolicyV1::ExtraFileDescriptors {
        name: "ExtraFileDescriptors",
    },
    UnitPropertyPolicyV1::Bool {
        name: "PrivateTmp",
        value: true,
    },
    // Nspawn's propagation/export state stays private to the supervisor.
    UnitPropertyPolicyV1::StringPairs {
        name: "TemporaryFileSystem",
        values: NSPAWN_TEMPORARY_FILESYSTEMS,
    },
    UnitPropertyPolicyV1::Environment {
        name: "Environment",
        fixed: NSPAWN_ENVIRONMENT,
        binding_prefix: "AOS_SANDBOX_LAUNCH_BINDING=",
    },
    UnitPropertyPolicyV1::Bool {
        name: "SetLoginEnvironment",
        value: false,
    },
    UnitPropertyPolicyV1::GuardianDependency { name: "BindsTo" },
    UnitPropertyPolicyV1::GuardianDependency { name: "After" },
    UnitPropertyPolicyV1::ResourceU64 {
        name: "TasksMax",
        field: ResourceU64FieldV1::TasksMax,
    },
    UnitPropertyPolicyV1::ResourceU64 {
        name: "MemoryHigh",
        field: ResourceU64FieldV1::MemoryHigh,
    },
    UnitPropertyPolicyV1::ResourceU64 {
        name: "MemoryMax",
        field: ResourceU64FieldV1::MemoryMax,
    },
    UnitPropertyPolicyV1::U64 {
        name: "MemorySwapMax",
        value: 0,
    },
    UnitPropertyPolicyV1::ResourceU64 {
        name: "CPUWeight",
        field: ResourceU64FieldV1::CpuWeight,
    },
    UnitPropertyPolicyV1::Bool {
        name: "CPUAccounting",
        value: true,
    },
    UnitPropertyPolicyV1::Bool {
        name: "MemoryAccounting",
        value: true,
    },
    UnitPropertyPolicyV1::Bool {
        name: "IOAccounting",
        value: true,
    },
    UnitPropertyPolicyV1::Bool {
        name: "TasksAccounting",
        value: true,
    },
    UnitPropertyPolicyV1::String {
        name: "DevicePolicy",
        value: "closed",
    },
    UnitPropertyPolicyV1::NetworkNamespace {
        name: "NetworkNamespacePath",
    },
    UnitPropertyPolicyV1::DurationU64 {
        name: "TimeoutStartUSec",
        field: DurationU64FieldV1::TimeoutStart,
    },
    UnitPropertyPolicyV1::DurationU64 {
        name: "TimeoutStopUSec",
        field: DurationU64FieldV1::TimeoutStop,
    },
    UnitPropertyPolicyV1::ExecStart {
        name: "ExecStart",
        ignore_failure: false,
    },
    UnitPropertyPolicyV1::OptionalU64 {
        name: "CPUQuotaPerSecUSec",
        field: OptionalU64FieldV1::CpuQuota,
    },
    UnitPropertyPolicyV1::OptionalU64 {
        name: "IOWeight",
        field: OptionalU64FieldV1::IoWeight,
    },
    UnitPropertyPolicyV1::OptionalU64 {
        name: "LimitNOFILE",
        field: OptionalU64FieldV1::OpenFiles,
    },
    UnitPropertyPolicyV1::OptionalU64 {
        name: "LimitNOFILESoft",
        field: OptionalU64FieldV1::OpenFiles,
    },
    UnitPropertyPolicyV1::DeviceAllow {
        name: "DeviceAllow",
        rules: DEVICE_ALLOW_RULES_V1,
    },
];

const PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1: PayloadRootContinuityProjectionV1<'static> =
    PayloadRootContinuityProjectionV1 {
        descriptor_roles: DescriptorRoleVocabularyV1 {
            root: NSPAWN_ROOT_DESCRIPTOR_ROLE,
            attachment_anchor: NSPAWN_ATTACHMENT_ANCHOR_DESCRIPTOR_ROLE,
            attachment_anchor_namespace: NSPAWN_ATTACHMENT_ANCHOR_NAMESPACE_DESCRIPTOR_ROLE,
        },
        nspawn_arguments: NSPAWN_ARGUMENT_POLICY_V1,
        unit_properties: UNIT_PROPERTY_POLICY_V1,
    };

impl PayloadRootContinuityProjectionV1<'_> {
    fn digest(self) -> [u8; 32] {
        const DOMAIN: &[u8] = b"aos.systemd.payload-root-continuity-policy.v1\0";

        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        semantic_string(&mut hash, self.descriptor_roles.root);
        semantic_string(&mut hash, self.descriptor_roles.attachment_anchor);
        semantic_string(&mut hash, self.descriptor_roles.attachment_anchor_namespace);
        hash.update(canonical_len(self.nspawn_arguments.len()));
        for argument in self.nspawn_arguments {
            match argument {
                NspawnArgumentPolicyV1::Literal(value) => {
                    hash.update([0]);
                    semantic_string(&mut hash, value);
                }
                NspawnArgumentPolicyV1::Machine { option, prefix } => {
                    hash.update([1]);
                    semantic_string(&mut hash, option);
                    semantic_string(&mut hash, prefix);
                }
                NspawnArgumentPolicyV1::Descriptor {
                    option,
                    role,
                    optional,
                } => {
                    hash.update([2]);
                    semantic_string(&mut hash, option);
                    hash.update([descriptor_role_tag(*role)]);
                    hash.update([u8::from(*optional)]);
                }
                NspawnArgumentPolicyV1::PrivateUsers { option, separator } => {
                    hash.update([3]);
                    semantic_string(&mut hash, option);
                    semantic_string(&mut hash, separator);
                }
                NspawnArgumentPolicyV1::GuestAgentFds { option, roles } => {
                    hash.update([4]);
                    semantic_string(&mut hash, option);
                    for role in roles {
                        semantic_string(&mut hash, role);
                    }
                }
            }
        }

        hash.update(canonical_len(self.unit_properties.len()));
        for property in self.unit_properties {
            match property {
                UnitPropertyPolicyV1::Description { name, prefix } => {
                    hash.update([0]);
                    semantic_string(&mut hash, name);
                    semantic_string(&mut hash, prefix);
                }
                UnitPropertyPolicyV1::String { name, value } => {
                    hash.update([1]);
                    semantic_string(&mut hash, name);
                    semantic_string(&mut hash, value);
                }
                UnitPropertyPolicyV1::Bool { name, value } => {
                    hash.update([2]);
                    semantic_string(&mut hash, name);
                    hash.update([u8::from(*value)]);
                }
                UnitPropertyPolicyV1::U32 { name, value } => {
                    hash.update([3]);
                    semantic_string(&mut hash, name);
                    hash.update(value.to_be_bytes());
                }
                UnitPropertyPolicyV1::U64 { name, value } => {
                    hash.update([4]);
                    semantic_string(&mut hash, name);
                    hash.update(value.to_be_bytes());
                }
                UnitPropertyPolicyV1::BoolStringArray {
                    name,
                    allow,
                    values,
                } => {
                    hash.update([5]);
                    semantic_string(&mut hash, name);
                    hash.update([u8::from(*allow)]);
                    canonical_strings(&mut hash, values);
                }
                UnitPropertyPolicyV1::StringArray { name, values } => {
                    hash.update([6]);
                    semantic_string(&mut hash, name);
                    canonical_strings(&mut hash, values);
                }
                UnitPropertyPolicyV1::StringPairs { name, values } => {
                    hash.update([7]);
                    semantic_string(&mut hash, name);
                    hash.update(canonical_len(values.len()));
                    for (first, second) in *values {
                        semantic_string(&mut hash, first);
                        semantic_string(&mut hash, second);
                    }
                }
                UnitPropertyPolicyV1::ExtraFileDescriptors { name } => {
                    hash.update([8]);
                    semantic_string(&mut hash, name);
                }
                UnitPropertyPolicyV1::Environment {
                    name,
                    fixed,
                    binding_prefix,
                } => {
                    hash.update([9]);
                    semantic_string(&mut hash, name);
                    canonical_strings(&mut hash, fixed);
                    semantic_string(&mut hash, binding_prefix);
                }
                UnitPropertyPolicyV1::GuardianDependency { name } => {
                    hash.update([10]);
                    semantic_string(&mut hash, name);
                }
                UnitPropertyPolicyV1::ResourceU64 { name, field } => {
                    hash.update([11]);
                    semantic_string(&mut hash, name);
                    hash.update([resource_u64_field_tag(*field)]);
                }
                UnitPropertyPolicyV1::DurationU64 { name, field } => {
                    hash.update([12]);
                    semantic_string(&mut hash, name);
                    hash.update([duration_u64_field_tag(*field)]);
                }
                UnitPropertyPolicyV1::OptionalU64 { name, field } => {
                    hash.update([13]);
                    semantic_string(&mut hash, name);
                    hash.update([optional_u64_field_tag(*field)]);
                }
                UnitPropertyPolicyV1::NetworkNamespace { name } => {
                    hash.update([14]);
                    semantic_string(&mut hash, name);
                }
                UnitPropertyPolicyV1::ExecStart {
                    name,
                    ignore_failure,
                } => {
                    hash.update([15]);
                    semantic_string(&mut hash, name);
                    hash.update([u8::from(*ignore_failure)]);
                }
                UnitPropertyPolicyV1::DeviceAllow { name, rules } => {
                    hash.update([16]);
                    semantic_string(&mut hash, name);
                    hash.update(canonical_len(rules.len()));
                    for rule in *rules {
                        hash.update([sandbox_device_tag(rule.device)]);
                        semantic_string(&mut hash, rule.path);
                        semantic_string(&mut hash, rule.permissions);
                    }
                }
            }
        }
        hash.finalize().into()
    }

    fn arguments(
        self,
        command: &SandboxNspawnCommand,
        has_attachment_anchor: bool,
        has_guest_agent: bool,
    ) -> Vec<String> {
        let machine = encode_hex(command.incarnation);
        self.nspawn_arguments
            .iter()
            .filter_map(|argument| match argument {
                NspawnArgumentPolicyV1::Literal(value) => Some((*value).to_owned()),
                NspawnArgumentPolicyV1::Machine { option, prefix } => {
                    Some(format!("{option}{prefix}{machine}"))
                }
                NspawnArgumentPolicyV1::Descriptor {
                    option,
                    role,
                    optional,
                } => (!*optional || has_attachment_anchor)
                    .then(|| format!("{option}{}", self.descriptor_roles.resolve(*role))),
                NspawnArgumentPolicyV1::PrivateUsers { option, separator } => Some(format!(
                    "{option}{}{separator}{}",
                    command.uid_range_start, command.uid_range_size
                )),
                NspawnArgumentPolicyV1::GuestAgentFds { option, roles } => has_guest_agent
                    .then(|| format!("{option}{}:{}:{}", roles[0], roles[1], roles[2])),
            })
            .collect()
    }
}

pub(super) fn arguments(
    command: &SandboxNspawnCommand,
    has_attachment_anchor: bool,
    has_guest_agent: bool,
) -> Vec<String> {
    PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.arguments(command, has_attachment_anchor, has_guest_agent)
}

pub(super) fn digest_v1() -> [u8; 32] {
    PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.digest()
}

pub(super) const fn supervisor_capability_bounding_set() -> u64 {
    NSPAWN_SUPERVISOR_CAPABILITIES
}

pub(super) const fn supervisor_selinux_context() -> &'static str {
    NSPAWN_SUPERVISOR_SELINUX_CONTEXT
}

#[cfg(test)]
pub(super) fn property_names() -> Vec<&'static str> {
    PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
        .unit_properties
        .iter()
        .map(|policy| policy.name())
        .collect()
}

fn canonical_len(value: usize) -> [u8; 8] {
    u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes()
}

fn canonical_strings(hash: &mut Sha256, values: &[&str]) {
    hash.update(canonical_len(values.len()));
    for value in values {
        semantic_string(hash, value);
    }
}

const fn descriptor_role_tag(role: DescriptorRoleV1) -> u8 {
    match role {
        DescriptorRoleV1::Root => 0,
        DescriptorRoleV1::AttachmentAnchor => 1,
    }
}

const fn resource_u64_field_tag(field: ResourceU64FieldV1) -> u8 {
    match field {
        ResourceU64FieldV1::TasksMax => 0,
        ResourceU64FieldV1::MemoryHigh => 1,
        ResourceU64FieldV1::MemoryMax => 2,
        ResourceU64FieldV1::CpuWeight => 3,
    }
}

const fn duration_u64_field_tag(field: DurationU64FieldV1) -> u8 {
    match field {
        DurationU64FieldV1::TimeoutStart => 0,
        DurationU64FieldV1::TimeoutStop => 1,
    }
}

const fn optional_u64_field_tag(field: OptionalU64FieldV1) -> u8 {
    match field {
        OptionalU64FieldV1::CpuQuota => 0,
        OptionalU64FieldV1::IoWeight => 1,
        OptionalU64FieldV1::OpenFiles => 2,
    }
}

const fn sandbox_device_tag(device: SandboxDevice) -> u8 {
    match device {
        SandboxDevice::Kvm => 1,
        SandboxDevice::Tun => 2,
        SandboxDevice::Fuse => 3,
    }
}

impl PayloadRootContinuityProjectionV1<'_> {
    fn properties(self, spec: &SandboxUnitSpec) -> Result<Vec<TransientProperty>> {
        payload_properties_v2!(Local, unused, self, spec)
    }
}

pub(super) fn properties(spec: &SandboxUnitSpec) -> Result<Vec<TransientProperty>> {
    PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.properties(spec)
}

pub(super) fn properties_retaining_v2(
    spec: &SandboxUnitSpec,
    original: &mut super::payload_property_original::PayloadUnitPropertyOriginalV2,
) -> Result<()> {
    let projection = PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1;
    payload_properties_v2!(Retained, original, projection, spec)
}

pub(super) fn property_count_v2() -> usize { UNIT_PROPERTY_POLICY_V1.len() }

pub(super) fn property_literal_bytes_v2() -> Option<usize> {
    let mut bytes = 0usize;
    for property in UNIT_PROPERTY_POLICY_V1 {
        bytes = bytes.checked_add(property.name().len())?;
        match property {
            UnitPropertyPolicyV1::Description { prefix, .. } => {
                bytes = bytes.checked_add(prefix.len())?;
            }
            UnitPropertyPolicyV1::String { value, .. } => {
                bytes = bytes.checked_add(value.len())?;
            }
            UnitPropertyPolicyV1::BoolStringArray { values, .. }
            | UnitPropertyPolicyV1::StringArray { values, .. } => {
                for value in *values { bytes = bytes.checked_add(value.len())?; }
            }
            UnitPropertyPolicyV1::StringPairs { values, .. } => {
                for (first, second) in *values {
                    bytes = bytes.checked_add(first.len())?.checked_add(second.len())?;
                }
            }
            UnitPropertyPolicyV1::ExtraFileDescriptors { .. } => {
                for role in [NSPAWN_ROOT_DESCRIPTOR_ROLE, NSPAWN_ATTACHMENT_ANCHOR_DESCRIPTOR_ROLE,
                    NSPAWN_ATTACHMENT_ANCHOR_NAMESPACE_DESCRIPTOR_ROLE, GUEST_CHANNEL_ROLE_V2,
                    GUEST_PROVISIONING_ROLE_V2, GUEST_ATTACH_TRUST_ROLE_V2, HOST_REPORT_ROLE_V2,
                    "aos-host-component-readiness-report"]
                { bytes = bytes.checked_add(role.len())?; }
            }
            UnitPropertyPolicyV1::Environment { fixed, binding_prefix, .. } => {
                for value in *fixed { bytes = bytes.checked_add(value.len())?; }
                bytes = bytes.checked_add(binding_prefix.len())?.checked_add(64)?;
            }
            UnitPropertyPolicyV1::DeviceAllow { rules, .. } => {
                let maximum = rules.iter().map(|rule| rule.path.len() + rule.permissions.len()).max().unwrap_or(0);
                bytes = bytes.checked_add(maximum.checked_mul(super::MAX_DEVICES)?)?;
            }
            _ => {}
        }
    }
    Some(bytes)
}

// D-Bus strings use their UTF-8 byte lengths plus fixed alignment/length
// words. Every dynamic byte comes from the existing validated argument cap,
// generated unit names, proc FD aliases, or the SAME fixed property vocabulary.
pub(super) fn maximum_encoded_request_bytes_v2() -> Option<usize> {
    let descriptor_alias = "/proc//fd/".len().checked_add(2 * (u32::MAX.ilog10() as usize + 1))?;
    let unit_name = super::UNIT_PREFIX.len().max(super::GUARD_PREFIX.len())
        .checked_add(32)?.checked_add(super::UNIT_SUFFIX.len())?;
    let source_text = super::MAX_ARGUMENT_BYTES.checked_add(2 * descriptor_alias)?
        .checked_add(4 * unit_name)?.checked_add(property_literal_bytes_v2()?)?;
    let rows = property_namespace_entries_v2()?;
    // Each scalar/array record has at most 32 framing/alignment bytes beyond
    // its text; each named variant property additionally has 64. The fixed
    // header pays eight maximal 255-byte D-Bus name/signature fields separately.
    source_text.checked_add(rows.checked_mul(32)?)?
        .checked_add(property_count_v2().checked_mul(64)?)?
        .checked_add(16 + 8 * (8 + 4 + 255 + 1))
}

pub(super) fn property_namespace_entries_v2() -> Option<usize> {
    let mut entries = UNIT_PROPERTY_POLICY_V1.len();
    for property in UNIT_PROPERTY_POLICY_V1 {
        let rows = match property {
            UnitPropertyPolicyV1::BoolStringArray { values, .. } => values.len().checked_add(1)?,
            UnitPropertyPolicyV1::StringArray { values, .. } => values.len(),
            UnitPropertyPolicyV1::StringPairs { values, .. } => values.len(),
            UnitPropertyPolicyV1::ExtraFileDescriptors { .. } => 7,
            UnitPropertyPolicyV1::Environment { fixed, .. } => fixed.len().checked_add(1)?,
            UnitPropertyPolicyV1::ExecStart { .. } => super::MAX_ARGUMENTS.checked_add(2)?,
            UnitPropertyPolicyV1::DeviceAllow { .. } => super::MAX_DEVICES,
            _ => 0,
        };
        entries = entries.checked_add(rows)?;
    }
    Some(entries)
}


#[cfg(test)]
mod tests;
