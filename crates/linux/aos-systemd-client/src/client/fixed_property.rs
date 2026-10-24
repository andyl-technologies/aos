//! Checks fixed selected property schemas before recursive value decoding.
//!
//! Ordinary clients keep the generated getter engine. The selected readonly
//! connection uses the same Properties.Get and zvariant decoder with an exact
//! signature check followed by concrete Rust carrier decoding. The catalog
//! describes interface wire types, not allowed values, deployment roles,
//! collection limits or resource authority.

use serde::de::DeserializeOwned;
use zbus::zvariant::{OwnedValue, Type, Value};
#[cfg(test)]
use zbus::zvariant::Signature;

use super::{Error, Result, SystemdClient};

#[derive(Clone, Copy)]
pub(super) enum PropertyDecodingV1 {
    Ordinary,
    Fixed,
}

impl PropertyDecodingV1 {
    pub(super) fn for_client(client: &SystemdClient) -> Self {
        if client.uses_fixed_property_decoding_v2() { Self::Fixed } else { Self::Ordinary }
    }

    pub(super) async fn get<T>(
        self,
        proxy: &zbus::Proxy<'_>,
        name: &str,
    ) -> zbus::Result<T>
    where
        T: TryFrom<OwnedValue> + Type + DeserializeOwned,
        T::Error: Into<zbus::Error>,
    {
        match self {
            Self::Ordinary => proxy.get_property(name).await,
            Self::Fixed => proxy.get_uncached_property_typed(name).await,
        }
    }

    pub(super) async fn value(
        self,
        properties: &zbus::fdo::PropertiesProxy<'_>,
        source: &zbus::Proxy<'_>,
        interface: zbus::names::InterfaceName<'_>,
        name: &str,
    ) -> Result<OwnedValue> {
        match self {
            Self::Ordinary => Ok(properties.get(interface, name).await?),
            Self::Fixed => schema(interface.as_str(), name)?.read(source, name).await,
        }
    }
}

type CredentialPathV1 = (String, String);
type CredentialDataV1 = (String, Vec<u8>);
type OpenFileV1 = (String, String, u64);
type CommandV1 = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

#[derive(Clone, Copy)]
enum PropertySchemaV1 {
    String,
    Strings,
    CredentialPaths,
    CredentialData,
    Boolean,
    U32,
    I32,
    SyscallFilter,
    U64,
    Bytes,
    OpenFiles,
    Context,
    Commands,
}

impl PropertySchemaV1 {
    #[cfg(test)]
    fn signature(self) -> &'static Signature {
        match self {
            Self::String => String::SIGNATURE,
            Self::Strings => Vec::<String>::SIGNATURE,
            Self::CredentialPaths => Vec::<CredentialPathV1>::SIGNATURE,
            Self::CredentialData => Vec::<CredentialDataV1>::SIGNATURE,
            Self::Boolean => bool::SIGNATURE,
            Self::U32 => u32::SIGNATURE,
            Self::I32 => i32::SIGNATURE,
            Self::SyscallFilter => <(bool, Vec<String>)>::SIGNATURE,
            Self::U64 => u64::SIGNATURE,
            Self::Bytes => Vec::<u8>::SIGNATURE,
            Self::OpenFiles => Vec::<OpenFileV1>::SIGNATURE,
            Self::Context => <(bool, String)>::SIGNATURE,
            Self::Commands => Vec::<CommandV1>::SIGNATURE,
        }
    }

    async fn read(self, source: &zbus::Proxy<'_>, name: &str) -> Result<OwnedValue> {
        // Project concrete strings/arrays into the existing property table.
        // String -> Str creates Arc<str>; the static wrapper then preserves it;
        // no second ownership-promotion walk or descriptor duplication runs.
        macro_rules! read {
            ($type:ty) => {{
                let value: $type = source.get_uncached_property_typed(name).await?;
                Ok(OwnedValue::from_static_value(Value::from(value)))
            }};
        }
        match self {
            Self::String => read!(String),
            Self::Strings => read!(Vec<String>),
            Self::CredentialPaths => read!(Vec<CredentialPathV1>),
            Self::CredentialData => read!(Vec<CredentialDataV1>),
            Self::Boolean => read!(bool),
            Self::U32 => read!(u32),
            Self::I32 => read!(i32),
            Self::SyscallFilter => read!((bool, Vec<String>)),
            Self::U64 => read!(u64),
            Self::Bytes => read!(Vec<u8>),
            Self::OpenFiles => read!(Vec<OpenFileV1>),
            Self::Context => read!((bool, String)),
            Self::Commands => read!(Vec<CommandV1>),
        }
    }
}

fn schema(interface: &str, name: &str) -> Result<PropertySchemaV1> {
    let schema = match (interface, name) {
        ("org.freedesktop.systemd1.Service", "Result" | "NotifyAccess" | "DelegateSubgroup" | "DevicePolicy" | "ProtectSystem" | "ControlGroup" | "ExitType" | "KillMode" | "Type" | "Restart" | "User" | "Group")
        | ("org.freedesktop.systemd1.Unit", "FragmentPath") => PropertySchemaV1::String,
        ("org.freedesktop.systemd1.Service", "SystemCallArchitectures" | "ExtraFileDescriptorNames" | "ImportCredential" | "StateDirectory" | "RuntimeDirectory")
        | ("org.freedesktop.systemd1.Unit", "DropInPaths" | "Requires" | "After") => PropertySchemaV1::Strings,
        ("org.freedesktop.systemd1.Service", "LoadCredential" | "LoadCredentialEncrypted"
            | "ImportCredentialEx") => PropertySchemaV1::CredentialPaths,
        ("org.freedesktop.systemd1.Service", "SetCredential" | "SetCredentialEncrypted") => {
            PropertySchemaV1::CredentialData
        }
        ("org.freedesktop.systemd1.Service", "RemainAfterExit" | "MemoryDenyWriteExecute" | "Delegate" | "LockPersonality" | "PrivateTmp" | "PrivateNetwork" | "PrivateDevices" | "NoNewPrivileges")
        | ("org.freedesktop.systemd1.Unit", "Transient") => PropertySchemaV1::Boolean,
        ("org.freedesktop.systemd1.Service", "UMask" | "FileDescriptorStoreMax" | "NFileDescriptorStore" | "MainPID" | "StateDirectoryMode" | "RuntimeDirectoryMode") => PropertySchemaV1::U32,
        ("org.freedesktop.systemd1.Service", "RestrictNamespaces" | "CapabilityBoundingSet" | "AmbientCapabilities"
            | "TimeoutStopUSec" | "TasksMax" | "CPUQuotaPerSecUSec" | "CPUQuotaPeriodUSec"
            | "MemoryMax" | "LimitNOFILE" | "LimitNOFILESoft") => PropertySchemaV1::U64,
        ("org.freedesktop.systemd1.Service", "AOSResourceProducerEpoch")
        | ("org.freedesktop.systemd1.Unit", "InvocationID") => PropertySchemaV1::Bytes,
        ("org.freedesktop.systemd1.Service", "SystemCallFilter") => PropertySchemaV1::SyscallFilter,
        ("org.freedesktop.systemd1.Service", "ExecMainCode" | "ExecMainStatus" | "SystemCallErrorNumber") => PropertySchemaV1::I32,
        ("org.freedesktop.systemd1.Service", "OpenFile") => PropertySchemaV1::OpenFiles,
        ("org.freedesktop.systemd1.Service", "SELinuxContext") => PropertySchemaV1::Context,
        ("org.freedesktop.systemd1.Service", "ExecStart" | "ExecStartPre" | "ExecStartPost" | "ExecReload" | "ExecCondition") => {
            PropertySchemaV1::Commands
        }
        _ => return Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
    };
    Ok(schema)
}

// Counts requested storage in the actual finite typed decoder/projection.
// There is no dictionary, nested variant or FD model in this catalog.
// Element counts include canonical-but-semantically-invalid values; partial
// concrete records have separate slack, before any table projection occurs.
pub(super) fn decoded_geometry_v1(materialized_bytes: usize) -> Option<(usize, usize)> {
    let maximum = super::ControllerPropertyObserverAttemptV1::MESSAGE_BYTES;
    if materialized_bytes > maximum {
        return None;
    }
    decoded_geometry_for_schedule_v2(materialized_bytes,
        super::ControllerPropertyObserverAttemptV1::INCOMING_MESSAGES)
}

pub(super) fn decoded_geometry_for_schedule_v2(
    materialized_bytes: usize,
    messages: usize,
) -> Option<(usize, usize)> {
    use std::mem::size_of;

    if messages == 0 {
        return None;
    }
    // ArraySeqDeserializer supplies no announced element-count hint. Serde
    // pushes only reached values. RawVec doubles capacity (minimum <=8), so
    // three reached carrier widths cover old+new growth allocations.
    // Byte sums, without alignment assumptions: as has >=5 bytes/string;
    // a(sst) has >=18 bytes/record; command records have >=57 fixed bytes,
    // plus >=5 per argv string. Text payload storage is a separate +1 byte.
    let concrete_density = (3 * size_of::<String>()).div_ceil(5)
        .max((3 * size_of::<OpenFileV1>()).div_ceil(18))
        // Two strings consume at least10 bytes; string+byte-array consumes
        // at least9. Empty credential values remain canonical native input.
        .max((3 * size_of::<CredentialPathV1>()).div_ceil(10))
        .max((3 * size_of::<CredentialDataV1>()).div_ceil(9))
        .max((3 * size_of::<CommandV1>()).div_ceil(57))
        .max(3)
        .checked_add(1)?;
    let partial_bytes = messages.checked_mul(
        (3 * size_of::<CommandV1>())
            .checked_add(3 * size_of::<OpenFileV1>())?
            .checked_add(32 * size_of::<String>())?
            .checked_add(8)?,
    )?;
    let concrete_bytes = materialized_bytes.checked_mul(concrete_density)?
        .checked_add(partial_bytes)?;

    // Str::from(String) copies into Arc<str> while the String still exists.
    // Include the second text extent and each Arc's strong/weak counters;
    // the static Value wrapper avoids any further ownership-promotion copy.
    let projection_strings = materialized_bytes.div_ceil(5)
        .checked_add(messages.checked_mul(16)?)?;
    let projection_text_bytes = materialized_bytes.checked_add(
        projection_strings.checked_mul(2 * size_of::<usize>())?,
    )?;

    // Array::from(Vec<T>) collects its exact-size map, and the static wrapper
    // keeps that same Vec. Bytes need one Value each. OpenFile's outer+4
    // structure cells fit its >=18 wire bytes; command's outer+24 peak
    // structure cells and argv cells fit >=57+5*argc. A context is fixed.
    let fixed_cells = messages.checked_mul(64)?;
    let value_cells = materialized_bytes.checked_add(fixed_cells)?;

    // Dynamic tuple signatures need at most14 Signature slots/command and
    // three/OpenFile, within respectively57 and18 consumed wire bytes.
    // Header/prefix signatures can be hostile, but every `g` has <=255
    // bytes. One retained header tree/message plus eight current parser/
    // clone/error trees is charged with three slots/node for Vec growth.
    let header_signature_cells = messages.checked_add(8)?
        .checked_mul(255)?.checked_mul(3)?;
    // Credential byte arrays add a nested array signature to their pair.
    // Three slots per >=9-byte record cover that same Value projection.
    let signature_cells = materialized_bytes.div_ceil(4)
        .max(materialized_bytes.div_ceil(9).checked_mul(3)?)
        .checked_add(messages.checked_mul(16)?)?
        .checked_add(header_signature_cells)?;
    let memory = value_cells.checked_mul(size_of::<Value<'static>>())?
        .checked_add(concrete_bytes)?
        .checked_add(projection_text_bytes)?
        .checked_add(signature_cells.checked_mul(size_of::<zbus::zvariant::Signature>())?)?;

    // Strings consume >=5 wire bytes per allocation. Tuple/argv/signature
    // allocations consume <one per two body bytes, with all fixed roots and
    // current growth allocations covered separately. This is a representation
    // count, not an estimate of the allocator's own hidden metadata bytes.
    let metadata = materialized_bytes.div_ceil(2)
        .checked_add(header_signature_cells)?
        .checked_add(fixed_cells)?;
    Some((memory, metadata))
}

#[cfg(test)]
fn expected_signature(interface: &str, name: &str) -> Result<Signature> {
    schema(interface, name).map(|schema| schema.signature().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_properties_match_the_original_pid1_wire_types() {
        let service = "org.freedesktop.systemd1.Service";
        for name in ["Type", "Restart"] {
            assert_eq!(&expected_signature(service, name).unwrap(), String::SIGNATURE);
        }
        for name in ["LoadCredential", "LoadCredentialEncrypted", "ImportCredentialEx"] {
            assert_eq!(&expected_signature(service, name).unwrap(), Vec::<CredentialPathV1>::SIGNATURE);
        }
        for name in ["SetCredential", "SetCredentialEncrypted"] {
            assert_eq!(&expected_signature(service, name).unwrap(), Vec::<CredentialDataV1>::SIGNATURE);
        }
        assert_eq!(&expected_signature(service, "ImportCredential").unwrap(), Vec::<String>::SIGNATURE);
    }

    #[test]
    fn geometry_includes_empty_semantically_invalid_records_and_reached_bytes() {
        use zbus::zvariant::{serialized::Context, to_bytes, LE};

        // Empty paths/names remain canonical wire values and materialize before
        // any role semantic validator. They cannot be omitted from geometry.
        let values: Vec<Value<'static>> = vec![
            Value::from(vec![0_u8; 4096]),
            Value::from(vec![String::new(); 256]),
            Value::from(vec![(String::new(), String::new()); 128]),
            Value::from(vec![(String::new(), vec![0_u8; 4096]); 4]),
            Value::from(vec![(String::new(), String::new(), 0_u64); 64]),
            Value::from(vec![(String::new(), vec![String::new(); 64], false,
                0_u64, 0_u64, 0_u64, 0_u64, 0_u32, 0_i32, 0_i32); 8]),
        ];
        for value in values {
            let wire = to_bytes(Context::new_dbus(LE, 0), &value).unwrap();
            let (memory, metadata) = decoded_geometry_v1(wire.len()).unwrap();
            let owned = OwnedValue::from_static_value(value);

            assert_eq!(to_bytes(Context::new_dbus(LE, 0), &owned).unwrap().to_vec(), wire.to_vec());
            assert!(memory > wire.len());
            assert!(metadata >= super::super::ControllerPropertyObserverAttemptV1::INCOMING_MESSAGES);
        }
        assert!(decoded_geometry_v1(
            super::super::ControllerPropertyObserverAttemptV1::MESSAGE_BYTES + 1,
        ).is_none());
        assert!(decoded_geometry_v1(usize::MAX).is_none());
    }

    #[test]
    fn selected_property_carriers_exclude_fds_and_recursive_variants() {
        let service = "org.freedesktop.systemd1.Service";
        for name in [
            "ControlGroup", "OpenFile", "ExtraFileDescriptorNames",
            "FileDescriptorStoreMax", "NFileDescriptorStore", "SELinuxContext",
            "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges",
            "AOSResourceProducerEpoch", "ExecStart", "ExecStartPre", "ExecStartPost",
            "ExitType", "KillMode", "TimeoutStopUSec", "TasksMax",
        ] {
            let signature = expected_signature(service, name).unwrap().to_string();
            assert!(!signature.contains('h'), "{name}: {signature}");
            assert!(!signature.contains('v'), "{name}: {signature}");
        }
        for name in ["FragmentPath", "DropInPaths", "Transient", "InvocationID"] {
            let signature = expected_signature("org.freedesktop.systemd1.Unit", name)
                .unwrap().to_string();
            assert!(!signature.contains('h'), "{name}: {signature}");
            assert!(!signature.contains('v'), "{name}: {signature}");
        }
        // The independent initial/final bookends request these same concrete
        // types directly; their expected signatures cannot carry FD trees.
        for signature in [String::SIGNATURE, u32::SIGNATURE, Vec::<u8>::SIGNATURE] {
            let signature = signature.to_string();
            assert!(!signature.contains('h'));
            assert!(!signature.contains('v'));
        }
    }

    #[test]
    fn compound_catalog_matches_the_actual_systemd_wire_carriers() {
        type OpenFile = Vec<(String, String, u64)>;
        type Command = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
        let service = "org.freedesktop.systemd1.Service";
        assert_eq!(&expected_signature(service, "OpenFile").unwrap(), OpenFile::SIGNATURE);
        assert_eq!(&expected_signature(service, "SELinuxContext").unwrap(), <(bool, String)>::SIGNATURE);
        for name in ["ExecStart", "ExecStartPre", "ExecStartPost"] {
            assert_eq!(&expected_signature(service, name).unwrap(), Vec::<Command>::SIGNATURE);
        }
        assert!(expected_signature(service, "UnknownProperty").is_err());
        assert!(expected_signature("org.freedesktop.systemd1.Unit", "ExecStart").is_err());
    }
}

#[cfg(test)]
mod ownership_profile_schema_tests {
    use super::*;

    #[test]
    fn local_ownership_properties_keep_their_concrete_interface_signatures() {
        for (name, expected) in [("MainPID", "u"), ("StateDirectoryMode", "u"),
            ("RuntimeDirectoryMode", "u"), ("StateDirectory", "as"),
            ("RuntimeDirectory", "as"), ("User", "s"), ("Group", "s")] {
            assert_eq!(schema("org.freedesktop.systemd1.Service", name).unwrap().signature().to_string(), expected);
            assert!(schema("org.freedesktop.systemd1.Unit", name).is_err());
        }
    }
}

#[cfg(test)]
mod phase0_property_schema_tests {
    use super::*;

    #[test]
    fn phase0_and_supervisor_types_match_pinned_pid1_vtables() {
        let service = "org.freedesktop.systemd1.Service";
        for (name, signature) in [
            ("UMask", "u"), ("ExecMainCode", "i"), ("ExecMainStatus", "i"), ("RemainAfterExit", "b"), ("Result", "s"),
            ("SystemCallFilter", "(bas)"), ("SystemCallArchitectures", "as"),
            ("SystemCallErrorNumber", "i"), ("MemoryDenyWriteExecute", "b"), ("PrivateNetwork", "b"),
            ("PrivateDevices", "b"), ("ProtectSystem", "s"),
            ("RestrictNamespaces", "t"), ("NotifyAccess", "s"),
            ("Delegate", "b"), ("DelegateSubgroup", "s"),
            ("LockPersonality", "b"), ("PrivateTmp", "b"), ("DevicePolicy", "s"),
        ] {
            assert_eq!(expected_signature(service, name).unwrap().to_string(), signature);
            assert!(expected_signature("org.freedesktop.systemd1.Unit", name).is_err());
        }
    }
}
