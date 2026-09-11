//! Canonical projection coverage and mutation tests.

use sha2::{Digest as _, Sha256};

use super::super::encode_hex32;
use super::*;

fn assert_argument_policy_mutation(index: usize, replacement: NspawnArgumentPolicyV1<'_>) {
    let baseline = PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.digest();
    let mut arguments = NSPAWN_ARGUMENT_POLICY_V1.to_vec();
    arguments[index] = replacement;
    let projection = PayloadRootContinuityProjectionV1 {
        nspawn_arguments: &arguments,
        ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
    };
    assert_ne!(projection.digest(), baseline, "argument {index}");
}

fn assert_property_policy_mutation(index: usize, replacement: UnitPropertyPolicyV1<'_>) {
    let baseline = PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.digest();
    let mut properties = UNIT_PROPERTY_POLICY_V1.to_vec();
    properties[index] = replacement;
    let projection = PayloadRootContinuityProjectionV1 {
        unit_properties: &properties,
        ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
    };
    assert_ne!(projection.digest(), baseline, "property {index}");
}

#[test]
fn root_continuity_policy_digest_is_sensitive_to_every_projected_choice() {
    let baseline = PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.digest();
    for descriptor_roles in [
        DescriptorRoleVocabularyV1 {
            root: "changed-root-role",
            ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.descriptor_roles
        },
        DescriptorRoleVocabularyV1 {
            attachment_anchor: "changed-attachment-role",
            ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1.descriptor_roles
        },
    ] {
        assert_ne!(
            PayloadRootContinuityProjectionV1 {
                descriptor_roles,
                ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
            }
            .digest(),
            baseline
        );
    }

    for (index, argument) in NSPAWN_ARGUMENT_POLICY_V1.iter().copied().enumerate() {
        match argument {
            NspawnArgumentPolicyV1::Literal(_) => assert_argument_policy_mutation(
                index,
                NspawnArgumentPolicyV1::Literal("changed-literal"),
            ),
            NspawnArgumentPolicyV1::Machine { option, prefix } => {
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::Machine {
                        option: "--changed-machine=",
                        prefix,
                    },
                );
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::Machine {
                        option,
                        prefix: "changed-prefix-",
                    },
                );
            }
            NspawnArgumentPolicyV1::Descriptor {
                option,
                role,
                optional,
            } => {
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::Descriptor {
                        option: "--changed-descriptor=",
                        role,
                        optional,
                    },
                );
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::Descriptor {
                        option,
                        role: match role {
                            DescriptorRoleV1::Root => DescriptorRoleV1::AttachmentAnchor,
                            DescriptorRoleV1::AttachmentAnchor => DescriptorRoleV1::Root,
                        },
                        optional,
                    },
                );
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::Descriptor {
                        option,
                        role,
                        optional: !optional,
                    },
                );
            }
            NspawnArgumentPolicyV1::PrivateUsers { option, separator } => {
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::PrivateUsers {
                        option: "--changed-private-users=",
                        separator,
                    },
                );
                assert_argument_policy_mutation(
                    index,
                    NspawnArgumentPolicyV1::PrivateUsers {
                        option,
                        separator: "/",
                    },
                );
            }
        }

        let mut removed = NSPAWN_ARGUMENT_POLICY_V1.to_vec();
        removed.remove(index);
        assert_ne!(
            PayloadRootContinuityProjectionV1 {
                nspawn_arguments: &removed,
                ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
            }
            .digest(),
            baseline,
            "removed argument {index}"
        );
    }
    for index in 0..NSPAWN_ARGUMENT_POLICY_V1.len() - 1 {
        let mut reordered = NSPAWN_ARGUMENT_POLICY_V1.to_vec();
        reordered.swap(index, index + 1);
        assert_ne!(
            PayloadRootContinuityProjectionV1 {
                nspawn_arguments: &reordered,
                ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
            }
            .digest(),
            baseline,
            "argument order at {index}"
        );
    }

    for (index, property) in UNIT_PROPERTY_POLICY_V1.iter().copied().enumerate() {
        match property {
            UnitPropertyPolicyV1::Description { name, prefix } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::Description {
                        name: "ChangedDescription",
                        prefix,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::Description {
                        name,
                        prefix: "Changed sandbox ",
                    },
                );
            }
            UnitPropertyPolicyV1::String { name, value } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::String {
                        name: "ChangedString",
                        value,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::String {
                        name,
                        value: "changed-value",
                    },
                );
            }
            UnitPropertyPolicyV1::Bool { name, value } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::Bool {
                        name: "ChangedBool",
                        value,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::Bool {
                        name,
                        value: !value,
                    },
                );
            }
            UnitPropertyPolicyV1::U32 { name, value } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::U32 {
                        name: "ChangedU32",
                        value,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::U32 {
                        name,
                        value: value.wrapping_add(1),
                    },
                );
            }
            UnitPropertyPolicyV1::U64 { name, value } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::U64 {
                        name: "ChangedU64",
                        value,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::U64 {
                        name,
                        value: value ^ 1,
                    },
                );
            }
            UnitPropertyPolicyV1::BoolStringArray {
                name,
                allow,
                values,
            } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::BoolStringArray {
                        name: "ChangedBoolStringArray",
                        allow,
                        values,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::BoolStringArray {
                        name,
                        allow: !allow,
                        values,
                    },
                );
                for value_index in 0..values.len() {
                    let mut changed_values = values.to_vec();
                    changed_values[value_index] = "changed-list-entry";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::BoolStringArray {
                            name,
                            allow,
                            values: &changed_values,
                        },
                    );

                    let mut removed_value = values.to_vec();
                    removed_value.remove(value_index);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::BoolStringArray {
                            name,
                            allow,
                            values: &removed_value,
                        },
                    );
                }
                for order_index in 0..values.len().saturating_sub(1) {
                    let mut reordered = values.to_vec();
                    reordered.swap(order_index, order_index + 1);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::BoolStringArray {
                            name,
                            allow,
                            values: &reordered,
                        },
                    );
                }
            }
            UnitPropertyPolicyV1::StringArray { name, values } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::StringArray {
                        name: "ChangedStringArray",
                        values,
                    },
                );
                for value_index in 0..values.len() {
                    let mut changed_values = values.to_vec();
                    changed_values[value_index] = "changed-list-entry";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringArray {
                            name,
                            values: &changed_values,
                        },
                    );

                    let mut removed_value = values.to_vec();
                    removed_value.remove(value_index);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringArray {
                            name,
                            values: &removed_value,
                        },
                    );
                }
                for order_index in 0..values.len().saturating_sub(1) {
                    let mut reordered = values.to_vec();
                    reordered.swap(order_index, order_index + 1);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringArray {
                            name,
                            values: &reordered,
                        },
                    );
                }
            }
            UnitPropertyPolicyV1::StringPairs { name, values } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::StringPairs {
                        name: "ChangedStringPairs",
                        values,
                    },
                );
                for value_index in 0..values.len() {
                    let mut changed_first = values.to_vec();
                    changed_first[value_index].0 = "changed-first";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringPairs {
                            name,
                            values: &changed_first,
                        },
                    );

                    let mut changed_second = values.to_vec();
                    changed_second[value_index].1 = "changed-second";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringPairs {
                            name,
                            values: &changed_second,
                        },
                    );

                    let mut removed_value = values.to_vec();
                    removed_value.remove(value_index);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringPairs {
                            name,
                            values: &removed_value,
                        },
                    );
                }
                for order_index in 0..values.len().saturating_sub(1) {
                    let mut reordered = values.to_vec();
                    reordered.swap(order_index, order_index + 1);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::StringPairs {
                            name,
                            values: &reordered,
                        },
                    );
                }
            }
            UnitPropertyPolicyV1::ExtraFileDescriptors { .. } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::ExtraFileDescriptors {
                        name: "ChangedExtraFileDescriptors",
                    },
                );
            }
            UnitPropertyPolicyV1::Environment {
                name,
                fixed,
                binding_prefix,
            } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::Environment {
                        name: "ChangedEnvironment",
                        fixed,
                        binding_prefix,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::Environment {
                        name,
                        fixed,
                        binding_prefix: "CHANGED_BINDING=",
                    },
                );
                for value_index in 0..fixed.len() {
                    let mut changed_fixed = fixed.to_vec();
                    changed_fixed[value_index] = "CHANGED=1";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::Environment {
                            name,
                            fixed: &changed_fixed,
                            binding_prefix,
                        },
                    );

                    let mut removed_fixed = fixed.to_vec();
                    removed_fixed.remove(value_index);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::Environment {
                            name,
                            fixed: &removed_fixed,
                            binding_prefix,
                        },
                    );
                }
                for order_index in 0..fixed.len().saturating_sub(1) {
                    let mut reordered = fixed.to_vec();
                    reordered.swap(order_index, order_index + 1);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::Environment {
                            name,
                            fixed: &reordered,
                            binding_prefix,
                        },
                    );
                }
            }
            UnitPropertyPolicyV1::GuardianDependency { .. } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::GuardianDependency {
                        name: "ChangedDependency",
                    },
                );
            }
            UnitPropertyPolicyV1::ResourceU64 { name, field } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::ResourceU64 {
                        name: "ChangedResource",
                        field,
                    },
                );
                let changed_field = match field {
                    ResourceU64FieldV1::TasksMax => ResourceU64FieldV1::MemoryHigh,
                    ResourceU64FieldV1::MemoryHigh => ResourceU64FieldV1::MemoryMax,
                    ResourceU64FieldV1::MemoryMax => ResourceU64FieldV1::CpuWeight,
                    ResourceU64FieldV1::CpuWeight => ResourceU64FieldV1::TasksMax,
                };
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::ResourceU64 {
                        name,
                        field: changed_field,
                    },
                );
            }
            UnitPropertyPolicyV1::DurationU64 { name, field } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::DurationU64 {
                        name: "ChangedDuration",
                        field,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::DurationU64 {
                        name,
                        field: match field {
                            DurationU64FieldV1::TimeoutStart => DurationU64FieldV1::TimeoutStop,
                            DurationU64FieldV1::TimeoutStop => DurationU64FieldV1::TimeoutStart,
                        },
                    },
                );
            }
            UnitPropertyPolicyV1::OptionalU64 { name, field } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::OptionalU64 {
                        name: "ChangedOptional",
                        field,
                    },
                );
                let changed_field = match field {
                    OptionalU64FieldV1::CpuQuota => OptionalU64FieldV1::IoWeight,
                    OptionalU64FieldV1::IoWeight => OptionalU64FieldV1::OpenFiles,
                    OptionalU64FieldV1::OpenFiles => OptionalU64FieldV1::CpuQuota,
                };
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::OptionalU64 {
                        name,
                        field: changed_field,
                    },
                );
            }
            UnitPropertyPolicyV1::NetworkNamespace { .. } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::NetworkNamespace {
                        name: "ChangedNetworkNamespace",
                    },
                );
            }
            UnitPropertyPolicyV1::ExecStart {
                name,
                ignore_failure,
            } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::ExecStart {
                        name: "ChangedExecStart",
                        ignore_failure,
                    },
                );
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::ExecStart {
                        name,
                        ignore_failure: !ignore_failure,
                    },
                );
            }
            UnitPropertyPolicyV1::DeviceAllow { name, rules } => {
                assert_property_policy_mutation(
                    index,
                    UnitPropertyPolicyV1::DeviceAllow {
                        name: "ChangedDeviceAllow",
                        rules,
                    },
                );
                for rule_index in 0..rules.len() {
                    let mut changed_device = rules.to_vec();
                    changed_device[rule_index].device = match changed_device[rule_index].device {
                        SandboxDevice::Kvm => SandboxDevice::Tun,
                        SandboxDevice::Tun => SandboxDevice::Fuse,
                        SandboxDevice::Fuse => SandboxDevice::Kvm,
                    };
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::DeviceAllow {
                            name,
                            rules: &changed_device,
                        },
                    );

                    let mut changed_path = rules.to_vec();
                    changed_path[rule_index].path = "/dev/changed";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::DeviceAllow {
                            name,
                            rules: &changed_path,
                        },
                    );

                    let mut changed_permissions = rules.to_vec();
                    changed_permissions[rule_index].permissions = "r";
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::DeviceAllow {
                            name,
                            rules: &changed_permissions,
                        },
                    );

                    let mut removed_rule = rules.to_vec();
                    removed_rule.remove(rule_index);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::DeviceAllow {
                            name,
                            rules: &removed_rule,
                        },
                    );
                }
                for order_index in 0..rules.len().saturating_sub(1) {
                    let mut reordered = rules.to_vec();
                    reordered.swap(order_index, order_index + 1);
                    assert_property_policy_mutation(
                        index,
                        UnitPropertyPolicyV1::DeviceAllow {
                            name,
                            rules: &reordered,
                        },
                    );
                }
            }
        }

        let mut removed = UNIT_PROPERTY_POLICY_V1.to_vec();
        removed.remove(index);
        assert_ne!(
            PayloadRootContinuityProjectionV1 {
                unit_properties: &removed,
                ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
            }
            .digest(),
            baseline,
            "removed property {index}"
        );
    }
    for index in 0..UNIT_PROPERTY_POLICY_V1.len() - 1 {
        let mut reordered = UNIT_PROPERTY_POLICY_V1.to_vec();
        reordered.swap(index, index + 1);
        assert_ne!(
            PayloadRootContinuityProjectionV1 {
                unit_properties: &reordered,
                ..PAYLOAD_ROOT_CONTINUITY_PROJECTION_V1
            }
            .digest(),
            baseline,
            "property order at {index}"
        );
    }
}

#[test]
fn root_continuity_policy_v1_has_stable_independent_preimage() {
    fn append_string(preimage: &mut Vec<u8>, value: &str) {
        preimage.extend_from_slice(&(value.len() as u64).to_be_bytes());
        preimage.extend_from_slice(value.as_bytes());
    }

    fn append_strings(preimage: &mut Vec<u8>, values: &[&str]) {
        preimage.extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            append_string(preimage, value);
        }
    }

    fn literal_argument(preimage: &mut Vec<u8>, value: &str) {
        preimage.push(0);
        append_string(preimage, value);
    }

    fn named_value(preimage: &mut Vec<u8>, tag: u8, name: &str, value: &str) {
        preimage.push(tag);
        append_string(preimage, name);
        append_string(preimage, value);
    }

    fn named_bool(preimage: &mut Vec<u8>, name: &str, value: bool) {
        preimage.push(2);
        append_string(preimage, name);
        preimage.push(u8::from(value));
    }

    fn named_u32(preimage: &mut Vec<u8>, name: &str, value: u32) {
        preimage.push(3);
        append_string(preimage, name);
        preimage.extend_from_slice(&value.to_be_bytes());
    }

    fn named_u64(preimage: &mut Vec<u8>, name: &str, value: u64) {
        preimage.push(4);
        append_string(preimage, name);
        preimage.extend_from_slice(&value.to_be_bytes());
    }

    fn bool_string_array(preimage: &mut Vec<u8>, name: &str, allow: bool, values: &[&str]) {
        preimage.push(5);
        append_string(preimage, name);
        preimage.push(u8::from(allow));
        append_strings(preimage, values);
    }

    fn string_array(preimage: &mut Vec<u8>, name: &str, values: &[&str]) {
        preimage.push(6);
        append_string(preimage, name);
        append_strings(preimage, values);
    }

    fn named_tag(preimage: &mut Vec<u8>, tag: u8, name: &str) {
        preimage.push(tag);
        append_string(preimage, name);
    }

    fn named_field(preimage: &mut Vec<u8>, tag: u8, name: &str, field: u8) {
        named_tag(preimage, tag, name);
        preimage.push(field);
    }

    let mut preimage = b"aos.systemd.payload-root-continuity-policy.v1\0".to_vec();
    append_string(&mut preimage, "aos-sandbox-root-mount-v1");
    append_string(&mut preimage, "aos-sandbox-attachment-anchor-v1");

    // This independently spells out every canonical tag, width, and field
    // rather than traversing the production projection or its encoders.
    preimage.extend_from_slice(&17_u64.to_be_bytes());
    for value in [
        "--boot",
        "--quiet",
        "--keep-unit",
        "--register=no",
        "--settings=no",
    ] {
        literal_argument(&mut preimage, value);
    }
    preimage.push(1);
    append_string(&mut preimage, "--machine=");
    append_string(&mut preimage, "aos-");
    preimage.push(2);
    append_string(&mut preimage, "--aos-root-mount-fd=");
    preimage.extend_from_slice(&[0, 0]);
    preimage.push(3);
    append_string(&mut preimage, "--private-users=");
    append_string(&mut preimage, ":");
    for value in [
        "--private-users-ownership=map",
        "--notify-ready=yes",
        "--selinux-context=system_u:system_r:aos_sandbox_payload_t:s0",
        "--no-new-privileges=yes",
        concat!(
            "--drop-capability=",
            "CAP_AUDIT_CONTROL,CAP_AUDIT_READ,CAP_AUDIT_WRITE,CAP_BLOCK_SUSPEND,",
            "CAP_BPF,CAP_CHECKPOINT_RESTORE,CAP_DAC_READ_SEARCH,CAP_IPC_LOCK,",
            "CAP_IPC_OWNER,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_MAC_ADMIN,",
            "CAP_MAC_OVERRIDE,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_BROADCAST,CAP_NET_RAW,",
            "CAP_PERFMON,CAP_SYSLOG,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_CHROOT,",
            "CAP_SYS_MODULE,CAP_SYS_NICE,CAP_SYS_PACCT,CAP_SYS_PTRACE,CAP_SYS_RAWIO,",
            "CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_WAKE_ALARM"
        ),
        "--system-call-filter=~@mount @module @raw-io @reboot bpf perf_event_open ptrace setns unshare",
        "--aos-payload-seccomp-profile=aos-sandbox-payload-v1",
        "--aos-lifecycle-profile=aos-sandbox-lifecycle-v1",
    ] {
        literal_argument(&mut preimage, value);
    }
    preimage.push(2);
    append_string(&mut preimage, "--aos-attachment-anchor-fd=");
    preimage.extend_from_slice(&[1, 1]);

    preimage.extend_from_slice(&47_u64.to_be_bytes());
    named_value(&mut preimage, 0, "Description", "AOS sandbox ");
    for (name, value) in [("Type", "notify"), ("NotifyAccess", "main")] {
        named_value(&mut preimage, 1, name, value);
    }
    named_bool(&mut preimage, "Delegate", true);
    for (name, value) in [
        ("DelegateSubgroup", "supervisor"),
        ("Slice", "aos-sandboxes.slice"),
        ("Restart", "no"),
        ("CollectMode", "inactive-or-failed"),
        ("KillMode", "mixed"),
        ("OOMPolicy", "kill"),
    ] {
        named_value(&mut preimage, 1, name, value);
    }
    named_u64(&mut preimage, "CapabilityBoundingSet", 2_820_937_211);
    bool_string_array(
        &mut preimage,
        "RestrictAddressFamilies",
        true,
        &["AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"],
    );
    bool_string_array(
        &mut preimage,
        "SystemCallFilter",
        true,
        &[
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
        ],
    );
    bool_string_array(
        &mut preimage,
        "SystemCallFilter",
        false,
        &["bpf:EPERM", "reboot:EPERM"],
    );
    string_array(&mut preimage, "SystemCallArchitectures", &["native"]);
    for (name, value) in [
        ("ProtectSystem", "strict"),
        ("SELinuxContext", "system_u:system_r:aos_nspawn_t:s0"),
    ] {
        named_value(&mut preimage, 1, name, value);
    }
    named_bool(&mut preimage, "LockPersonality", true);
    named_bool(&mut preimage, "RestrictRealtime", true);
    named_value(&mut preimage, 1, "KeyringMode", "private");
    named_u32(&mut preimage, "UMask", 0o077);
    named_tag(&mut preimage, 8, "ExtraFileDescriptors");
    named_bool(&mut preimage, "PrivateTmp", true);
    named_tag(&mut preimage, 7, "TemporaryFileSystem");
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    append_string(&mut preimage, "/run/systemd/nspawn");
    append_string(&mut preimage, "rw,mode=0700,nosuid,nodev,noexec,size=16M");
    named_tag(&mut preimage, 9, "Environment");
    append_strings(
        &mut preimage,
        &["LANG=C.UTF-8", "PATH=", "SYSTEMD_LOG_TARGET=journal"],
    );
    append_string(&mut preimage, "AOS_SANDBOX_LAUNCH_BINDING=");
    named_bool(&mut preimage, "SetLoginEnvironment", false);
    named_tag(&mut preimage, 10, "BindsTo");
    named_tag(&mut preimage, 10, "After");
    named_field(&mut preimage, 11, "TasksMax", 0);
    named_field(&mut preimage, 11, "MemoryHigh", 1);
    named_field(&mut preimage, 11, "MemoryMax", 2);
    named_u64(&mut preimage, "MemorySwapMax", 0);
    named_field(&mut preimage, 11, "CPUWeight", 3);
    for name in [
        "CPUAccounting",
        "MemoryAccounting",
        "IOAccounting",
        "TasksAccounting",
    ] {
        named_bool(&mut preimage, name, true);
    }
    named_value(&mut preimage, 1, "DevicePolicy", "closed");
    named_tag(&mut preimage, 14, "NetworkNamespacePath");
    named_field(&mut preimage, 12, "TimeoutStartUSec", 0);
    named_field(&mut preimage, 12, "TimeoutStopUSec", 1);
    named_tag(&mut preimage, 15, "ExecStart");
    preimage.push(0);
    named_field(&mut preimage, 13, "CPUQuotaPerSecUSec", 0);
    named_field(&mut preimage, 13, "IOWeight", 1);
    named_field(&mut preimage, 13, "LimitNOFILE", 2);
    named_field(&mut preimage, 13, "LimitNOFILESoft", 2);
    named_tag(&mut preimage, 16, "DeviceAllow");
    preimage.extend_from_slice(&3_u64.to_be_bytes());
    for (device, path, permissions) in [
        (1, "/dev/kvm", "rw"),
        (2, "/dev/net/tun", "rw"),
        (3, "/dev/fuse", "rw"),
    ] {
        preimage.push(device);
        append_string(&mut preimage, path);
        append_string(&mut preimage, permissions);
    }

    let independently_assembled_digest: [u8; 32] = Sha256::digest(preimage).into();
    assert_eq!(
        encode_hex32(independently_assembled_digest),
        "18cdd877bdd79baae664104954b5a3461dae4d14cb86428621d9959246a9424a"
    );
    assert_eq!(digest_v1(), independently_assembled_digest);
}
