//! Observes the fixed Controller Git Source socket at the unique PID 1 owner.
//!
//! Uncached Socket properties are read twice between exact Unit observations.
//! The unique manager owner must survive the complete readback. The result is
//! data only: Security separately retains the original listener, kernel options,
//! socket node, installed Controller profile, and immutable unit fragment.
//! Numeric socket ownership does not prove a task role or Source authority.

use std::time::Duration;

use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedValue, Type};

use super::{Error, ManagerProxy, Result, SystemdClient, UnitProxy};

const UNIT: &str = "aos-sandbox-git-source-cut.socket";
const SERVICE: &str = "aos-sandboxd.service";
const SOCKET: &str = "/run/aos/sandbox-git/source-cut.sock";
const DESCRIPTOR: &str = "aos-git-source-cut";
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Records the fixed Git socket invocation and numeric ownership selectors.
///
/// This value cannot adopt a descriptor or authenticate a Git execution. Its
/// consumers independently join the UID/GID with their installed Controller
/// profile and original socket node, and retain the actual immutable fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSourceSocketObservationV1 {
    invocation: [u8; 16],
    fragment: String,
    uid: u32,
    gid: u32,
}

impl GitSourceSocketObservationV1 {
    /// Returns the nonzero socket-unit invocation observed during readback.
    #[must_use]
    pub const fn invocation(&self) -> [u8; 16] {
        self.invocation
    }

    /// Returns the observed fragment locator, not a retained immutable file.
    #[must_use]
    pub fn fragment_path(&self) -> &str {
        &self.fragment
    }

    /// Returns the configured numeric socket owner as observation data.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the configured numeric socket group as observation data.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }
}

#[derive(Eq, PartialEq)]
struct SocketProperties {
    listen: Vec<(String, String)>,
    name: String,
    accept: bool,
    pass_credentials: bool,
    pass_pidfd: bool,
    mode: u32,
    user: String,
    group: String,
    triggers: Vec<String>,
    fragment: String,
    drop_ins: Vec<String>,
    transient: bool,
}

impl SocketProperties {
    fn validate(self, invocation: [u8; 16]) -> Result<GitSourceSocketObservationV1> {
        let expected_listen = [("SequentialPacket".to_owned(), SOCKET.to_owned())];
        let expected_triggers = [SERVICE.to_owned()];

        if self.listen != expected_listen
            || self.name != DESCRIPTOR
            || self.accept
            || !self.pass_credentials
            || !self.pass_pidfd
            || self.mode != 0o600
            || self.triggers != expected_triggers
            || self.transient
            || !self.drop_ins.is_empty()
        {
            return Err(changed("fixed Git Source socket properties do not match"));
        }

        // A locator is checked here, but immutable-file custody belongs to the
        // consumer. A store-shaped string is never a retained image or permit.
        if !self.fragment.starts_with("/nix/store/")
            || self.fragment.len() > 4096
            || self.fragment.as_bytes()[1..]
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
            || std::path::Path::new(&self.fragment).file_name()
                != Some(std::ffi::OsStr::new(UNIT))
            || !std::path::Path::new(&self.fragment).is_absolute()
            || !std::path::Path::new(&self.fragment).components().all(|part| {
                matches!(part, std::path::Component::RootDir | std::path::Component::Normal(_))
            })
            || self.fragment.as_bytes().contains(&0)
        {
            return Err(changed("fixed Git Source socket properties do not match"));
        }

        let uid = numeric_identity(&self.user)?;
        let gid = numeric_identity(&self.group)?;

        Ok(GitSourceSocketObservationV1 {
            invocation,
            fragment: self.fragment,
            uid,
            gid,
        })
    }
}

#[derive(Eq, PartialEq)]
struct UnitProperties {
    id: String,
    active: String,
    substate: String,
    invocation: Vec<u8>,
}

pub(super) async fn observe(client: &SystemdClient) -> Result<GitSourceSocketObservationV1> {
    tokio::time::timeout(OBSERVATION_TIMEOUT, observe_original(client))
        .await
        .map_err(|_| Error::ExactUnitTimeout("fixed Git Source socket observation"))?
}

async fn observe_original(client: &SystemdClient) -> Result<GitSourceSocketObservationV1> {
    let bus = zbus::fdo::DBusProxy::new(&client.conn).await?;
    let manager_name = zbus::names::BusName::try_from("org.freedesktop.systemd1")
        .map_err(|error| changed(&error.to_string()))?;
    let owner = bus.get_name_owner(manager_name.clone()).await?;
    let owner_name = owner.as_str().try_into()
        .map_err(|error: zbus::names::Error| changed(&error.to_string()))?;
    let manager_pid = bus.get_connection_unix_process_id(owner_name).await?;
    require_manager_pid(manager_pid)?;

    // Every object proxy addresses this exact unique owner. Resolving the
    // well-known name again cannot silently select a replacement manager.
    let manager = ManagerProxy::builder(&client.conn)
        .destination(owner.clone())?
        .build()
        .await?;
    let path = manager.get_unit(UNIT).await?;
    let unit = UnitProxy::builder(&client.conn)
        .destination(owner.clone())?
        .path(path.clone())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let properties = zbus::fdo::PropertiesProxy::builder(&client.conn)
        .destination(owner.clone())?
        .path(path)?
        .build()
        .await?;

    let before = read_unit_properties(&unit, &properties).await?;
    let first = read_fixed_properties(&properties).await?;
    let second = read_fixed_properties(&properties).await?;
    let after = read_unit_properties(&unit, &properties).await?;
    require_original_readback(&before, &after, &first, &second)?;

    let final_owner = bus.get_name_owner(manager_name).await?;
    require_same_manager_owner(owner.as_str(), final_owner.as_str())?;
    let invocation = before.invocation.as_slice().try_into()
        .map_err(|_| changed("fixed Git Source socket invocation has wrong width"))?;

    first.validate(invocation)
}

async fn read_unit_properties(
    proxy: &UnitProxy<'_>,
    properties: &zbus::fdo::PropertiesProxy<'_>,
) -> Result<UnitProperties> {
    let unit = zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Unit")
        .map_err(|error| changed(&error.to_string()))?;

    Ok(UnitProperties {
        id: proxy.id().await?,
        active: proxy.active_state().await?,
        substate: proxy.sub_state().await?,
        // Preserve the generated getter's bus error mapping while requiring
        // the actual byte-array schema before any element conversion.
        invocation: decode(
            properties.get(unit, "InvocationID").await
                .map_err(zbus::Error::from)?,
        )?,
    })
}

async fn read_fixed_properties(proxy: &zbus::fdo::PropertiesProxy<'_>) -> Result<SocketProperties> {
    let socket = zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Socket")
        .map_err(|error| changed(&error.to_string()))?;
    let unit = zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Unit")
        .map_err(|error| changed(&error.to_string()))?;

    // These fixed property names and types are the packaged systemd 261.2
    // vtable. SocketUser/SocketGroup are strings, not Unit process identities.
    Ok(SocketProperties {
        listen: decode(proxy.get(socket.clone(), "Listen").await?)?,
        name: decode(proxy.get(socket.clone(), "FileDescriptorName").await?)?,
        accept: decode(proxy.get(socket.clone(), "Accept").await?)?,
        pass_credentials: decode(proxy.get(socket.clone(), "PassCredentials").await?)?,
        pass_pidfd: decode(proxy.get(socket.clone(), "PassPIDFD").await?)?,
        mode: decode(proxy.get(socket.clone(), "SocketMode").await?)?,
        user: decode(proxy.get(socket.clone(), "SocketUser").await?)?,
        group: decode(proxy.get(socket, "SocketGroup").await?)?,
        triggers: decode(proxy.get(unit.clone(), "Triggers").await?)?,
        fragment: decode(proxy.get(unit.clone(), "FragmentPath").await?)?,
        drop_ins: decode(proxy.get(unit.clone(), "DropInPaths").await?)?,
        transient: decode(proxy.get(unit, "Transient").await?)?,
    })
}

fn require_manager_pid(pid: u32) -> Result<()> {
    if pid != 1 {
        return Err(changed("fixed Git Source socket manager is not PID 1"));
    }

    Ok(())
}

fn require_original_readback(
    before: &UnitProperties,
    after: &UnitProperties,
    first: &SocketProperties,
    second: &SocketProperties,
) -> Result<()> {
    if before != after
        || first != second
        || before.id != UNIT
        || before.active != "active"
        || before.substate != "listening"
        || before.invocation.len() != 16
        || before.invocation.iter().all(|byte| *byte == 0)
    {
        return Err(changed("fixed Git Source socket changed during PID 1 readback"));
    }

    Ok(())
}

fn require_same_manager_owner(before: &str, after: &str) -> Result<()> {
    if before != after {
        return Err(changed("fixed Git Source socket changed during PID 1 readback"));
    }

    Ok(())
}

fn decode<T>(value: OwnedValue) -> Result<T>
where
    T: Type + TryFrom<OwnedValue, Error = zbus::zvariant::Error>,
{
    // Compound conversions can accept another schema or ignore tuple fields.
    // Check the complete enclosed schema before the existing conversion runs.
    if value.value_signature() != T::SIGNATURE {
        return Err(Error::Zbus(zbus::zvariant::Error::IncorrectType.into()));
    }

    T::try_from(value).map_err(|error| Error::Zbus(error.into()))
}

fn numeric_identity(text: &str) -> Result<u32> {
    let value = text.parse::<u32>()
        .map_err(|_| changed("fixed Git Source socket identity is not numeric"))?;
    if value == 0 || value == u32::MAX || value.to_string() != text {
        return Err(changed("fixed Git Source socket identity is not canonical nonroot"));
    }

    Ok(value)
}

fn changed(message: &str) -> Error {
    Error::InvalidSandboxUnit(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures are property DATA only. No test mocks a live PID 1 bus owner,
    // invokes the public observation API, or reconstructs application authority.
    fn socket_properties() -> SocketProperties {
        SocketProperties {
            listen: vec![("SequentialPacket".to_owned(), SOCKET.to_owned())],
            name: DESCRIPTOR.to_owned(),
            accept: false,
            pass_credentials: true,
            pass_pidfd: true,
            mode: 0o600,
            user: "1234".to_owned(),
            group: "1234".to_owned(),
            triggers: vec![SERVICE.to_owned()],
            fragment: "/nix/store/installed/aos-sandbox-git-source-cut.socket".to_owned(),
            drop_ins: Vec::new(),
            transient: false,
        }
    }

    fn unit_properties() -> UnitProperties {
        UnitProperties {
            id: UNIT.to_owned(),
            active: "active".to_owned(),
            substate: "listening".to_owned(),
            invocation: vec![1; 16],
        }
    }

    #[test]
    fn canonical_invocation_bytes_use_the_shared_byte_array_schema() {
        let expected = vec![1_u8; 16];
        let property = OwnedValue::try_from(zbus::zvariant::Value::from(expected.clone())).unwrap();

        assert_eq!(property.value_signature(), <Vec<u8>>::SIGNATURE);
        let invocation = decode::<Vec<u8>>(property).unwrap();

        assert_eq!(invocation, expected);
    }

    #[test]
    fn invocation_variant_or_wrong_element_arrays_reject_before_byte_conversion() {
        let variants = (0..16)
            .map(|_| zbus::zvariant::Value::new(zbus::zvariant::Value::from(1_u8)))
            .collect::<Vec<_>>();
        let variant_array = zbus::zvariant::Value::from(variants);
        let wrong_element_array = zbus::zvariant::Value::from(vec![1_u32; 16]);
        let empty_wrong_array = zbus::zvariant::Value::from(Vec::<u32>::new());
        let wrapped_array = zbus::zvariant::Value::new(
            zbus::zvariant::Value::from(vec![1_u8; 16]),
        );

        for value in [
            variant_array,
            wrong_element_array,
            empty_wrong_array,
            wrapped_array,
        ] {
            let property = OwnedValue::try_from(value).unwrap();

            let result = decode::<Vec<u8>>(property);

            assert!(matches!(
                result,
                Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
            ));
        }
    }

    #[test]
    fn canonical_compound_property_matches_the_shared_schema_before_decoding() {
        let expected = vec![("SequentialPacket".to_owned(), SOCKET.to_owned())];
        let property = OwnedValue::try_from(zbus::zvariant::Value::from(expected.clone())).unwrap();

        assert_eq!(property.value_signature(), <Vec<(String, String)>>::SIGNATURE);
        let decoded = decode::<Vec<(String, String)>>(property).unwrap();

        assert_eq!(decoded, expected);
    }

    #[test]
    fn canonical_string_arrays_decode_triggers_and_empty_drop_ins() {
        let expected = vec![SERVICE.to_owned()];
        let trigger = OwnedValue::try_from(zbus::zvariant::Value::from(expected.clone())).unwrap();
        let empty = OwnedValue::try_from(zbus::zvariant::Value::from(Vec::<String>::new())).unwrap();

        let triggers = decode::<Vec<String>>(trigger).unwrap();
        let drop_ins = decode::<Vec<String>>(empty).unwrap();

        assert_eq!(triggers, expected);
        assert!(drop_ins.is_empty());
    }

    #[test]
    fn short_or_extra_tuple_fields_refuse_before_compound_conversion() {
        let short = zbus::zvariant::Value::from(vec![("SequentialPacket".to_owned(),)]);
        let extra = zbus::zvariant::Value::from(vec![(
            "SequentialPacket".to_owned(),
            SOCKET.to_owned(),
            "unexpected".to_owned(),
        )]);

        for value in [short, extra] {
            let property = OwnedValue::try_from(value).unwrap();

            let result = decode::<Vec<(String, String)>>(property);

            assert!(matches!(
                result,
                Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
            ));
        }
    }

    #[test]
    fn empty_wrong_element_schema_does_not_decode_as_missing_drop_ins() {
        let value = zbus::zvariant::Value::from(Vec::<u32>::new());
        let property = OwnedValue::try_from(value).unwrap();

        let result = decode::<Vec<String>>(property);

        assert!(matches!(
            result,
            Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
        ));
    }

    #[test]
    fn variant_wrapped_compound_elements_refuse_the_selected_array_schema() {
        let compound = zbus::zvariant::Value::from((
            "SequentialPacket".to_owned(),
            SOCKET.to_owned(),
        ));
        let value = zbus::zvariant::Value::from(vec![zbus::zvariant::Value::new(compound)]);
        let property = OwnedValue::try_from(value).unwrap();

        let result = decode::<Vec<(String, String)>>(property);

        assert!(matches!(
            result,
            Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
        ));
    }

    #[test]
    fn wrong_scalar_and_variant_wrapped_array_retain_the_existing_type_error() {
        let scalar = OwnedValue::from(false);
        let array = zbus::zvariant::Value::from(vec![SERVICE.to_owned()]);
        let variant = OwnedValue::try_from(zbus::zvariant::Value::new(array)).unwrap();

        let wrong_scalar = decode::<u32>(scalar);
        let wrong_variant = decode::<Vec<String>>(variant);

        assert!(matches!(
            wrong_scalar,
            Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
        ));
        assert!(matches!(
            wrong_variant,
            Err(Error::Zbus(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))),
        ));
    }

    #[test]
    fn numeric_socket_ownership_rejects_names_root_and_noncanonical_numbers() {
        assert_eq!(numeric_identity("1234").unwrap(), 1234);

        for value in ["root", "0", "01", "+1", " 1", "4294967295", "4294967296"] {
            assert!(numeric_identity(value).is_err(), "{value}");
        }
    }

    #[test]
    fn non_pid1_process_and_changed_unique_owner_are_rejected() {
        for pid in [0, 2, 1234, u32::MAX] {
            assert!(require_manager_pid(pid).is_err(), "pid {pid}");
        }

        assert!(require_same_manager_owner(":1.10", ":1.11").is_err());
    }

    #[test]
    fn changed_unit_invocation_or_properties_break_the_original_bracket() {
        let before = unit_properties();
        let first = socket_properties();
        let second = socket_properties();
        let mut after = unit_properties();
        after.invocation[0] = 2;

        assert!(require_original_readback(&before, &after, &first, &second).is_err());

        let after = unit_properties();
        let mut changed_properties = socket_properties();
        changed_properties.user = "1235".to_owned();

        assert!(require_original_readback(&before, &after, &first, &changed_properties).is_err());
    }

    #[test]
    fn stable_but_wrong_unit_state_or_invocation_is_rejected() {
        let first = socket_properties();
        let second = socket_properties();

        for case in ["unit", "inactive", "substate", "zero", "short", "long"] {
            let mut before = unit_properties();
            let mut after = unit_properties();
            match case {
                "unit" => {
                    before.id = "another.socket".to_owned();
                    after.id = before.id.clone();
                }
                "inactive" => {
                    before.active = "inactive".to_owned();
                    after.active = before.active.clone();
                }
                "substate" => {
                    before.substate = "dead".to_owned();
                    after.substate = before.substate.clone();
                }
                "zero" => {
                    before.invocation = vec![0; 16];
                    after.invocation = before.invocation.clone();
                }
                "short" => {
                    before.invocation = vec![1; 15];
                    after.invocation = before.invocation.clone();
                }
                "long" => {
                    before.invocation = vec![1; 17];
                    after.invocation = before.invocation.clone();
                }
                _ => unreachable!(),
            }

            assert!(
                require_original_readback(&before, &after, &first, &second).is_err(),
                "{case}",
            );
        }
    }

    #[test]
    fn listener_descriptor_options_or_ownership_cannot_select_another_profile() {
        for case in [
            "duplicate",
            "type",
            "path",
            "descriptor",
            "accept",
            "credentials",
            "pidfd",
            "mode",
            "trigger",
            "root-group",
        ] {
            let mut properties = socket_properties();
            match case {
                "duplicate" => properties.listen.push(properties.listen[0].clone()),
                "type" => properties.listen[0].0 = "Stream".to_owned(),
                "path" => properties.listen[0].1 = "/run/another.sock".to_owned(),
                "descriptor" => properties.name = "another-descriptor".to_owned(),
                "accept" => properties.accept = true,
                "credentials" => properties.pass_credentials = false,
                "pidfd" => properties.pass_pidfd = false,
                "mode" => properties.mode = 0o660,
                "trigger" => properties.triggers.push("another.service".to_owned()),
                "root-group" => properties.group = "0".to_owned(),
                _ => unreachable!(),
            }

            assert!(properties.validate([1; 16]).is_err(), "{case}");
        }
    }

    #[test]
    fn fragment_locator_rejects_substitution_and_noncanonical_components() {
        for fragment in [
            "/run/aos-sandbox-git-source-cut.socket",
            "/nix/store/installed/another.socket",
            "/nix/store//aos-sandbox-git-source-cut.socket",
            "/nix/store/./aos-sandbox-git-source-cut.socket",
            "/nix/store/../aos-sandbox-git-source-cut.socket",
            "/nix/store/installed/aos-sandbox-git-source-cut.socket\0",
        ] {
            let mut properties = socket_properties();
            properties.fragment = fragment.to_owned();

            assert!(properties.validate([1; 16]).is_err(), "{fragment:?}");
        }

        let mut oversized = socket_properties();
        oversized.fragment = format!("/nix/store/{}/{}", "x".repeat(4096), UNIT);

        assert!(oversized.validate([1; 16]).is_err());
    }

    #[test]
    fn drop_ins_or_transient_state_cannot_override_the_fixed_socket() {
        let mut overridden = socket_properties();
        overridden.drop_ins.push("/run/systemd/system/override.conf".to_owned());
        let mut transient = socket_properties();
        transient.transient = true;

        assert!(overridden.validate([1; 16]).is_err());
        assert!(transient.validate([1; 16]).is_err());
    }

    #[test]
    fn valid_property_data_does_not_include_a_descriptor_or_application_permit() {
        let properties = socket_properties();

        let observation = properties.validate([1; 16]).unwrap();

        assert_eq!(observation.invocation(), [1; 16]);
        assert_eq!(observation.uid(), 1234);
        assert_eq!(observation.gid(), 1234);
        assert_eq!(
            observation.fragment_path(),
            "/nix/store/installed/aos-sandbox-git-source-cut.socket",
        );
        assert_eq!(OBSERVATION_TIMEOUT, Duration::from_secs(2));
    }
}
