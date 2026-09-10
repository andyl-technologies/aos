//! Pure manager-query schema for namespace-inspector activation evidence.
//!
//! The eventual privileged helper will query systemd 259 through its retained
//! private-manager stream. This module deliberately owns only the closed query
//! description, a bounded canonical response record, and pure A/B comparison.
//! Decoding a record does not authenticate systemd, a unit, a process, or the
//! protected deployment contract.
//!
//! ```text
//! AOSNIMS1 | version:u16 | kind:u8 | reserved:u8 | total:u32
//! contract-digest:32 | dynamic activation fields | manager-environment
//! property-count:u16 | property observations in descriptor-table order
//! ```

use thiserror::Error;

use super::launch_contract::{
    NamespaceInspectorDeploymentContractV1, NamespaceInspectorDeploymentDigestV1,
};

pub(super) mod codec;

#[cfg(test)]
mod manifest_tests;

const SNAPSHOT_MAGIC: &[u8; 8] = b"AOSNIMS1";
const SNAPSHOT_KIND: u8 = 2;
const MAXIMUM_UNIT_ID_BYTES: usize = 256;
const MAXIMUM_INSTANCE_BYTES: usize = 192;
const MAXIMUM_CGROUP_BYTES: usize = 512;

const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const SOCKET_INTERFACE: &str = "org.freedesktop.systemd1.Socket";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

/// Describes which retained systemd object supplies a queried property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagerQueryObjectV1 {
    /// The fixed system manager object supplies the property.
    Manager,
    /// The self-derived inspector service instance supplies the property.
    InspectorService,
    /// The fixed inspector socket unit supplies the property.
    InspectorSocket,
}

/// Distinguishes prepublished expectations from boot-local evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagerPropertyBindingV1 {
    /// The protected contract carries the exact expected canonical value.
    StaticContract,
    /// The value is compared across A/B snapshots but is not prepublished.
    DynamicActivation,
}

/// Defines the canonical treatment of a D-Bus property's top-level value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagerPropertyShapeV1 {
    /// The entire D-Bus value is one canonical scalar payload.
    Scalar,
    /// Array element order is semantically significant and retained.
    OrderedArray,
    /// Array elements form a duplicate-free, bytewise-sorted set.
    UnorderedSet,
}

/// Defines one closed systemd 259 property query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagerPropertyDescriptorV1 {
    /// Stable ordinal encoded in snapshot and contract records.
    pub(crate) id: u16,
    /// Retained object on which `Properties.Get` is invoked.
    pub(crate) object: ManagerQueryObjectV1,
    /// Actual systemd D-Bus interface exporting the property.
    pub(crate) interface: &'static str,
    /// Exact property name.
    pub(crate) property: &'static str,
    /// Actual systemd 259 D-Bus value signature.
    pub(crate) signature: &'static str,
    /// Whether the expected value is static or boot-local.
    pub(crate) binding: ManagerPropertyBindingV1,
    /// Canonical top-level collection semantics.
    pub(crate) shape: ManagerPropertyShapeV1,
}

macro_rules! property {
    ($id:expr, $object:ident, $interface:expr, $name:expr, $signature:expr, $binding:ident, $shape:ident) => {
        ManagerPropertyDescriptorV1 {
            id: $id,
            object: ManagerQueryObjectV1::$object,
            interface: $interface,
            property: $name,
            signature: $signature,
            binding: ManagerPropertyBindingV1::$binding,
            shape: ManagerPropertyShapeV1::$shape,
        }
    };
}

/// Closed property table for the first systemd 259 query protocol.
///
/// Unit-level cgroup, execution, and kill properties are exported on the
/// concrete `Service` or `Socket` interface in systemd 259. They are not
/// queried through invented cgroup or execution interfaces. This table is a
/// protocol allowlist, not proof that the listed settings were applied to a
/// particular process; later kernel and protected-source evidence is required.
/// For every `Exec*` descriptor, contract records carry only path, ordered
/// argv, and ignore-failure or flag-set policy, while snapshots carry the full
/// systemd tuple including boot-local status fields. The matcher projects the
/// validated full tuple before comparing it with the static contract.
pub(crate) const MANAGER_PROPERTY_TABLE_V1: &[ManagerPropertyDescriptorV1] = &[
    property!(
        0,
        Manager,
        MANAGER_INTERFACE,
        "Environment",
        "as",
        DynamicActivation,
        UnorderedSet
    ),
    property!(
        1,
        InspectorService,
        UNIT_INTERFACE,
        "Id",
        "s",
        DynamicActivation,
        Scalar
    ),
    property!(
        2,
        InspectorService,
        UNIT_INTERFACE,
        "Names",
        "as",
        DynamicActivation,
        UnorderedSet
    ),
    property!(
        3,
        InspectorService,
        UNIT_INTERFACE,
        "LoadState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        4,
        InspectorService,
        UNIT_INTERFACE,
        "ActiveState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        5,
        InspectorService,
        UNIT_INTERFACE,
        "FreezerState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        6,
        InspectorService,
        UNIT_INTERFACE,
        "SubState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        7,
        InspectorService,
        UNIT_INTERFACE,
        "FragmentPath",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        8,
        InspectorService,
        UNIT_INTERFACE,
        "SourcePath",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        9,
        InspectorService,
        UNIT_INTERFACE,
        "DropInPaths",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        10,
        InspectorService,
        UNIT_INTERFACE,
        "UnitFileState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        11,
        InspectorService,
        UNIT_INTERFACE,
        "Job",
        "(uo)",
        DynamicActivation,
        Scalar
    ),
    property!(
        12,
        InspectorService,
        UNIT_INTERFACE,
        "NeedDaemonReload",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        13,
        InspectorService,
        UNIT_INTERFACE,
        "Transient",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        14,
        InspectorService,
        UNIT_INTERFACE,
        "InvocationID",
        "ay",
        DynamicActivation,
        Scalar
    ),
    property!(
        15,
        InspectorService,
        UNIT_INTERFACE,
        "TriggeredBy",
        "as",
        StaticContract,
        UnorderedSet
    ),
    property!(
        16,
        InspectorService,
        SERVICE_INTERFACE,
        "Slice",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        17,
        InspectorService,
        SERVICE_INTERFACE,
        "ControlGroup",
        "s",
        DynamicActivation,
        Scalar
    ),
    property!(
        18,
        InspectorService,
        SERVICE_INTERFACE,
        "ControlGroupId",
        "t",
        DynamicActivation,
        Scalar
    ),
    property!(
        19,
        InspectorService,
        SERVICE_INTERFACE,
        "Type",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        20,
        InspectorService,
        SERVICE_INTERFACE,
        "Restart",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        21,
        InspectorService,
        SERVICE_INTERFACE,
        "TimeoutStartUSec",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        22,
        InspectorService,
        SERVICE_INTERFACE,
        "TimeoutStopUSec",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        23,
        InspectorService,
        SERVICE_INTERFACE,
        "RuntimeMaxUSec",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        24,
        InspectorService,
        SERVICE_INTERFACE,
        "MainPID",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        25,
        InspectorService,
        SERVICE_INTERFACE,
        "ControlPID",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        26,
        InspectorService,
        SERVICE_INTERFACE,
        "UID",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        27,
        InspectorService,
        SERVICE_INTERFACE,
        "GID",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        28,
        InspectorService,
        SERVICE_INTERFACE,
        "NRestarts",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        29,
        InspectorService,
        SERVICE_INTERFACE,
        "Result",
        "s",
        DynamicActivation,
        Scalar
    ),
    property!(
        30,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecCondition",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        31,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecConditionEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        32,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStartPre",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        33,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStartPreEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        34,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStart",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        35,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStartEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        36,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStartPost",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        37,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStartPostEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        38,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecReload",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        39,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecReloadEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        40,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecReloadPost",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        41,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecReloadPostEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        42,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStop",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        43,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStopEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        44,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStopPost",
        "a(sasbttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        45,
        InspectorService,
        SERVICE_INTERFACE,
        "ExecStopPostEx",
        "a(sasasttttuii)",
        StaticContract,
        OrderedArray
    ),
    property!(
        46,
        InspectorService,
        SERVICE_INTERFACE,
        "Environment",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        47,
        InspectorService,
        SERVICE_INTERFACE,
        "EnvironmentFiles",
        "a(sb)",
        StaticContract,
        OrderedArray
    ),
    property!(
        48,
        InspectorService,
        SERVICE_INTERFACE,
        "PassEnvironment",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        49,
        InspectorService,
        SERVICE_INTERFACE,
        "UnsetEnvironment",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        50,
        InspectorService,
        SERVICE_INTERFACE,
        "UMask",
        "u",
        StaticContract,
        Scalar
    ),
    property!(
        51,
        InspectorService,
        SERVICE_INTERFACE,
        "StandardInput",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        52,
        InspectorService,
        SERVICE_INTERFACE,
        "StandardOutput",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        53,
        InspectorService,
        SERVICE_INTERFACE,
        "StandardError",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        54,
        InspectorService,
        SERVICE_INTERFACE,
        "User",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        55,
        InspectorService,
        SERVICE_INTERFACE,
        "Group",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        56,
        InspectorService,
        SERVICE_INTERFACE,
        "SupplementaryGroups",
        "as",
        StaticContract,
        UnorderedSet
    ),
    property!(
        57,
        InspectorService,
        SERVICE_INTERFACE,
        "CapabilityBoundingSet",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        58,
        InspectorService,
        SERVICE_INTERFACE,
        "AmbientCapabilities",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        59,
        InspectorService,
        SERVICE_INTERFACE,
        "NoNewPrivileges",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        60,
        InspectorService,
        SERVICE_INTERFACE,
        "PrivateTmp",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        61,
        InspectorService,
        SERVICE_INTERFACE,
        "PrivateDevices",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        62,
        InspectorService,
        SERVICE_INTERFACE,
        "PrivateNetwork",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        63,
        InspectorService,
        SERVICE_INTERFACE,
        "PrivateIPC",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        64,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectSystem",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        65,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectHome",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        66,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectProc",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        67,
        InspectorService,
        SERVICE_INTERFACE,
        "ProcSubset",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        68,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectControlGroups",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        69,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectKernelTunables",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        70,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectKernelModules",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        71,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectKernelLogs",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        72,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectClock",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        73,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectHostname",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        74,
        InspectorService,
        SERVICE_INTERFACE,
        "ReadWritePaths",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        75,
        InspectorService,
        SERVICE_INTERFACE,
        "ReadOnlyPaths",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        76,
        InspectorService,
        SERVICE_INTERFACE,
        "InaccessiblePaths",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        77,
        InspectorService,
        SERVICE_INTERFACE,
        "RestrictNamespaces",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        78,
        InspectorService,
        SERVICE_INTERFACE,
        "RestrictAddressFamilies",
        "(bas)",
        StaticContract,
        Scalar
    ),
    property!(
        79,
        InspectorService,
        SERVICE_INTERFACE,
        "SystemCallFilter",
        "(bas)",
        StaticContract,
        Scalar
    ),
    property!(
        80,
        InspectorService,
        SERVICE_INTERFACE,
        "SystemCallArchitectures",
        "as",
        StaticContract,
        UnorderedSet
    ),
    property!(
        81,
        InspectorService,
        SERVICE_INTERFACE,
        "SystemCallErrorNumber",
        "i",
        StaticContract,
        Scalar
    ),
    property!(
        82,
        InspectorService,
        SERVICE_INTERFACE,
        "SystemCallLog",
        "(bas)",
        StaticContract,
        Scalar
    ),
    property!(
        83,
        InspectorService,
        SERVICE_INTERFACE,
        "MemoryDenyWriteExecute",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        84,
        InspectorService,
        SERVICE_INTERFACE,
        "LockPersonality",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        85,
        InspectorService,
        SERVICE_INTERFACE,
        "RestrictRealtime",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        86,
        InspectorService,
        SERVICE_INTERFACE,
        "RestrictSUIDSGID",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        87,
        InspectorService,
        SERVICE_INTERFACE,
        "RemoveIPC",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        88,
        InspectorService,
        SERVICE_INTERFACE,
        "SELinuxContext",
        "(bs)",
        StaticContract,
        Scalar
    ),
    property!(
        89,
        InspectorService,
        SERVICE_INTERFACE,
        "KillMode",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        90,
        InspectorService,
        SERVICE_INTERFACE,
        "DevicePolicy",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        91,
        InspectorService,
        SERVICE_INTERFACE,
        "DeviceAllow",
        "a(ss)",
        StaticContract,
        OrderedArray
    ),
    property!(
        92,
        InspectorService,
        SERVICE_INTERFACE,
        "TasksMax",
        "t",
        StaticContract,
        Scalar
    ),
    property!(
        93,
        InspectorSocket,
        UNIT_INTERFACE,
        "Id",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        94,
        InspectorSocket,
        UNIT_INTERFACE,
        "Names",
        "as",
        StaticContract,
        UnorderedSet
    ),
    property!(
        95,
        InspectorSocket,
        UNIT_INTERFACE,
        "LoadState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        96,
        InspectorSocket,
        UNIT_INTERFACE,
        "ActiveState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        97,
        InspectorSocket,
        UNIT_INTERFACE,
        "FreezerState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        98,
        InspectorSocket,
        UNIT_INTERFACE,
        "SubState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        99,
        InspectorSocket,
        UNIT_INTERFACE,
        "FragmentPath",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        100,
        InspectorSocket,
        UNIT_INTERFACE,
        "SourcePath",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        101,
        InspectorSocket,
        UNIT_INTERFACE,
        "DropInPaths",
        "as",
        StaticContract,
        OrderedArray
    ),
    property!(
        102,
        InspectorSocket,
        UNIT_INTERFACE,
        "UnitFileState",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        103,
        InspectorSocket,
        UNIT_INTERFACE,
        "Job",
        "(uo)",
        DynamicActivation,
        Scalar
    ),
    property!(
        104,
        InspectorSocket,
        UNIT_INTERFACE,
        "NeedDaemonReload",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        105,
        InspectorSocket,
        UNIT_INTERFACE,
        "Transient",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        106,
        InspectorSocket,
        UNIT_INTERFACE,
        "InvocationID",
        "ay",
        DynamicActivation,
        Scalar
    ),
    property!(
        107,
        InspectorSocket,
        SOCKET_INTERFACE,
        "Listen",
        "a(ss)",
        StaticContract,
        OrderedArray
    ),
    property!(
        108,
        InspectorSocket,
        SOCKET_INTERFACE,
        "Accept",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        109,
        InspectorSocket,
        SOCKET_INTERFACE,
        "PassCredentials",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        110,
        InspectorSocket,
        SOCKET_INTERFACE,
        "PassPIDFD",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        111,
        InspectorSocket,
        SOCKET_INTERFACE,
        "AcceptFileDescriptors",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        112,
        InspectorSocket,
        SOCKET_INTERFACE,
        "SocketMode",
        "u",
        StaticContract,
        Scalar
    ),
    property!(
        113,
        InspectorSocket,
        SOCKET_INTERFACE,
        "DirectoryMode",
        "u",
        StaticContract,
        Scalar
    ),
    property!(
        114,
        InspectorSocket,
        SOCKET_INTERFACE,
        "SocketUser",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        115,
        InspectorSocket,
        SOCKET_INTERFACE,
        "SocketGroup",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        116,
        InspectorSocket,
        SOCKET_INTERFACE,
        "RemoveOnStop",
        "b",
        StaticContract,
        Scalar
    ),
    property!(
        117,
        InspectorSocket,
        SOCKET_INTERFACE,
        "MaxConnections",
        "u",
        StaticContract,
        Scalar
    ),
    property!(
        118,
        InspectorSocket,
        SOCKET_INTERFACE,
        "MaxConnectionsPerSource",
        "u",
        StaticContract,
        Scalar
    ),
    property!(
        119,
        InspectorSocket,
        SOCKET_INTERFACE,
        "ControlPID",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        120,
        InspectorSocket,
        SOCKET_INTERFACE,
        "Result",
        "s",
        DynamicActivation,
        Scalar
    ),
    property!(
        121,
        InspectorSocket,
        SOCKET_INTERFACE,
        "UID",
        "u",
        DynamicActivation,
        Scalar
    ),
    property!(
        122,
        InspectorSocket,
        SOCKET_INTERFACE,
        "GID",
        "u",
        DynamicActivation,
        Scalar
    ),
    // Lossless multi-mode companions to the legacy boolean service accessors.
    property!(
        123,
        InspectorService,
        SERVICE_INTERFACE,
        "PrivateTmpEx",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        124,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectControlGroupsEx",
        "s",
        StaticContract,
        Scalar
    ),
    property!(
        125,
        InspectorService,
        SERVICE_INTERFACE,
        "ProtectHostnameEx",
        "(ss)",
        StaticContract,
        Scalar
    ),
];

/// Describes one allowed D-Bus method invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagerMethodDescriptorV1 {
    /// Exact object role on which the method is invoked.
    pub(crate) object: ManagerQueryObjectV1,
    /// Exact D-Bus interface.
    pub(crate) interface: &'static str,
    /// Exact method member.
    pub(crate) member: &'static str,
    /// Concatenated input argument signature.
    pub(crate) input_signature: &'static str,
    /// Concatenated output argument signature.
    pub(crate) output_signature: &'static str,
}

/// Closed method table for the first manager-query protocol.
pub(crate) const MANAGER_METHOD_TABLE_V1: &[ManagerMethodDescriptorV1] = &[
    ManagerMethodDescriptorV1 {
        object: ManagerQueryObjectV1::Manager,
        interface: MANAGER_INTERFACE,
        member: "GetUnitByPIDFD",
        input_signature: "h",
        output_signature: "osay",
    },
    ManagerMethodDescriptorV1 {
        object: ManagerQueryObjectV1::Manager,
        interface: PROPERTIES_INTERFACE,
        member: "Get",
        input_signature: "ss",
        output_signature: "v",
    },
    ManagerMethodDescriptorV1 {
        object: ManagerQueryObjectV1::InspectorService,
        interface: PROPERTIES_INTERFACE,
        member: "Get",
        input_signature: "ss",
        output_signature: "v",
    },
    ManagerMethodDescriptorV1 {
        object: ManagerQueryObjectV1::InspectorSocket,
        interface: PROPERTIES_INTERFACE,
        member: "Get",
        input_signature: "ss",
        output_signature: "v",
    },
];

/// Carries one descriptor-indexed canonical property value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagerPropertyObservationV1 {
    pub(super) descriptor_id: u16,
    pub(super) value: CanonicalManagerPropertyValueV1,
}

/// Carries a canonical property value without claiming D-Bus provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalManagerPropertyValueV1 {
    /// One canonical scalar or tuple representation.
    Scalar(Vec<u8>),
    /// An order-sensitive array of canonical element representations.
    OrderedArray(Vec<Vec<u8>>),
    /// A duplicate-free array in strict bytewise order.
    UnorderedSet(Vec<Vec<u8>>),
}

impl CanonicalManagerPropertyValueV1 {
    fn shape(&self) -> ManagerPropertyShapeV1 {
        match self {
            Self::Scalar(_) => ManagerPropertyShapeV1::Scalar,
            Self::OrderedArray(_) => ManagerPropertyShapeV1::OrderedArray,
            Self::UnorderedSet(_) => ManagerPropertyShapeV1::UnorderedSet,
        }
    }
}

/// Holds one decoded but unauthenticated manager activation snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedNamespaceInspectorActivationSnapshotV1 {
    contract_digest: NamespaceInspectorDeploymentDigestV1,
    service_unit_id: String,
    service_instance: String,
    invocation_id: [u8; 16],
    main_pid: u32,
    control_group: String,
    control_group_id: u64,
    accept_ordinal: u64,
    accepted_socket_cookie: u64,
    connecting_pid: u32,
    connecting_pidfd_inode: u64,
    connecting_uid: u32,
    properties: Vec<ManagerPropertyObservationV1>,
}

impl ObservedNamespaceInspectorActivationSnapshotV1 {
    /// Decodes a bounded canonical snapshot without authenticating its source.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when the frame is
    /// oversized, malformed, noncanonical, truncated, or violates the closed
    /// property table and per-field limits.
    pub(crate) fn decode_untrusted(
        bytes: &[u8],
    ) -> Result<Self, NamespaceInspectorManagerQueryError> {
        codec::decode_snapshot(bytes)
    }

    /// Encodes the canonical snapshot record.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when this value violates
    /// a structural limit or the closed property table.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
        self.validate()?;
        codec::encode_snapshot(self)
    }

    fn validate(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        if self.service_unit_id.is_empty()
            || self.service_unit_id.len() > MAXIMUM_UNIT_ID_BYTES
            || self.service_instance.is_empty()
            || self.service_instance.len() > MAXIMUM_INSTANCE_BYTES
            || self.invocation_id == [0; 16]
            || self.main_pid == 0
            || self.control_group.is_empty()
            || self.control_group.len() > MAXIMUM_CGROUP_BYTES
            || self.control_group_id == 0
            || self.accepted_socket_cookie == 0
            || self.connecting_pid == 0
            || self.connecting_pidfd_inode == 0
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidSnapshot);
        }
        codec::validate_text(&self.service_unit_id)?;
        codec::validate_text(&self.service_instance)?;
        codec::validate_text(&self.control_group)?;
        validate_property_sequence(&self.properties, false)?;
        validate_dynamic_property_correlations(self)
    }
}

fn validate_dynamic_property_correlations(
    snapshot: &ObservedNamespaceInspectorActivationSnapshotV1,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let control_group_id = snapshot.control_group_id.to_le_bytes();
    let main_pid = snapshot.main_pid.to_le_bytes();
    let expected = [
        (1, snapshot.service_unit_id.as_bytes()),
        (14, snapshot.invocation_id.as_slice()),
        (17, snapshot.control_group.as_bytes()),
        (18, control_group_id.as_slice()),
        (24, main_pid.as_slice()),
    ];
    for (descriptor_index, expected_bytes) in expected {
        let Some(ManagerPropertyObservationV1 {
            descriptor_id,
            value: CanonicalManagerPropertyValueV1::Scalar(observed_bytes),
        }) = snapshot.properties.get(descriptor_index)
        else {
            return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
        };
        if usize::from(*descriptor_id) != descriptor_index || observed_bytes != expected_bytes {
            return Err(NamespaceInspectorManagerQueryError::InvalidSnapshot);
        }
    }
    Ok(())
}

/// Holds pure A/B equality evidence without granting activation authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MatchedNamespaceInspectorActivationSnapshotsV1 {
    _snapshot: ObservedNamespaceInspectorActivationSnapshotV1,
}

/// Compares two decoded snapshots with one static deployment contract.
///
/// This operation proves only canonical structural equality and equality of
/// the static property projection. It does not authenticate the manager,
/// helper, protected contract source, retained descriptors, or live kernel
/// identities, and cannot mint an inspector activation token.
///
/// # Errors
///
/// Returns [`NamespaceInspectorManagerQueryError`] when the contract or either
/// snapshot is invalid, the advertised digest is wrong, any A/B field differs,
/// or a static property differs from the contract.
pub(crate) fn match_namespace_inspector_activation_snapshots(
    contract: &NamespaceInspectorDeploymentContractV1,
    first: ObservedNamespaceInspectorActivationSnapshotV1,
    second: ObservedNamespaceInspectorActivationSnapshotV1,
) -> Result<MatchedNamespaceInspectorActivationSnapshotsV1, NamespaceInspectorManagerQueryError> {
    contract.validate()?;
    first.validate()?;
    second.validate()?;

    let contract_digest = contract.digest()?;
    if first.contract_digest != contract_digest
        || second.contract_digest != contract_digest
        || first != second
    {
        return Err(NamespaceInspectorManagerQueryError::SnapshotMismatch);
    }

    let observed_static = first
        .properties
        .iter()
        .zip(MANAGER_PROPERTY_TABLE_V1)
        .filter(|(_, descriptor)| descriptor.binding == ManagerPropertyBindingV1::StaticContract);
    for ((observation, descriptor), expected) in observed_static.zip(contract.static_properties()) {
        if codec::static_contract_projection(descriptor, observation)? != *expected {
            return Err(NamespaceInspectorManagerQueryError::StaticPropertyMismatch);
        }
    }

    Ok(MatchedNamespaceInspectorActivationSnapshotsV1 { _snapshot: first })
}

pub(super) fn validate_property_sequence(
    properties: &[ManagerPropertyObservationV1],
    static_only: bool,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let expected = MANAGER_PROPERTY_TABLE_V1.iter().filter(|descriptor| {
        !static_only || descriptor.binding == ManagerPropertyBindingV1::StaticContract
    });

    let mut count = 0usize;
    for (observation, descriptor) in properties.iter().zip(expected) {
        count += 1;
        if observation.descriptor_id != descriptor.id
            || observation.value.shape() != descriptor.shape
        {
            return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
        }
        codec::validate_property_value(descriptor, &observation.value, static_only)?;
    }

    let expected_count = if static_only {
        MANAGER_PROPERTY_TABLE_V1
            .iter()
            .filter(|descriptor| descriptor.binding == ManagerPropertyBindingV1::StaticContract)
            .count()
    } else {
        MANAGER_PROPERTY_TABLE_V1.len()
    };
    if count != expected_count || properties.len() != expected_count {
        return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
    }
    Ok(())
}

/// Reports bounded codec or structural matching failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum NamespaceInspectorManagerQueryError {
    /// The complete frame exceeds the protocol maximum.
    #[error("namespace-inspector manager-query frame exceeds its limit")]
    FrameTooLarge,
    /// The record header, version, kind, reserved bytes, or length is invalid.
    #[error("invalid namespace-inspector manager-query frame")]
    InvalidFrame,
    /// A length or element count exceeds its field-specific limit.
    #[error("namespace-inspector manager-query field exceeds its limit")]
    FieldTooLarge,
    /// A text field is empty where forbidden, invalid UTF-8, or contains NUL.
    #[error("invalid namespace-inspector manager-query text")]
    InvalidText,
    /// A set is duplicated or not in strict canonical bytewise order.
    #[error("noncanonical namespace-inspector manager-query set")]
    NoncanonicalSet,
    /// Property ordinals, counts, or value shapes do not match the closed table.
    #[error("namespace-inspector manager-query property table mismatch")]
    PropertyTableMismatch,
    /// A decoded activation snapshot violates structural invariants.
    #[error("invalid namespace-inspector activation snapshot")]
    InvalidSnapshot,
    /// A decoded deployment contract violates structural invariants.
    #[error("invalid namespace-inspector deployment contract")]
    InvalidContract,
    /// A/B snapshots or their advertised contract digest differ.
    #[error("namespace-inspector activation snapshots differ")]
    SnapshotMismatch,
    /// An observed static property differs from protected expected bytes.
    #[error("namespace-inspector static property mismatch")]
    StaticPropertyMismatch,
}
