//! Shared unique-PID-1 property readback for active and startup service checks.
//!
//! This observation neither makes a notify service ready nor freezes PID 1's
//! policy. Consumers must validate retained kernel objects independently.

use std::borrow::Cow;

use zbus::proxy::{CacheProperties, ProxyImpl as _};
use zbus::zvariant::OwnedValue;

use super::fixed_property::PropertyDecodingV1;

mod retained;
pub use retained::{ServicePropertiesReadOriginalV2, ServicePropertiesReadClosedV2,
    ServiceControlGroupReadOriginalV2};
use retained::{BookendCaptureOriginalV2, BookendAfterOriginalV2};

use super::{Error, ManagerProxy, NixOfflineAbsenceObservationV5, Result, ServiceProxy, SystemdClient, UnitProxy};

#[derive(Clone, Copy)]
pub(super) enum ObservationPhase {
    Active,
    OptionalActive,
    StartingOrRunning,
    StoppedNix,
    SuccessfulOneshot,
    Configuration,
}

pub(super) async fn observe(
    client: &SystemdClient,
    name: &str,
    expected_main_pid: u32,
    service_properties: &[&str],
    unit_properties: &[&str],
    phase: ObservationPhase,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>)> {
    observe_recipe(client, name, expected_main_pid, service_properties,
        unit_properties, phase, false).await
}

pub(super) const OWNERSHIP_PROFILE_PROPERTIES_V1: &[&str] = &[
    "MainPID", "ControlGroup", "StateDirectory", "StateDirectoryMode",
    "User", "Group", "CapabilityBoundingSet", "AmbientCapabilities",
    "NoNewPrivileges", "ExecStart", "RuntimeDirectory", "RuntimeDirectoryMode",
];
pub(super) const OWNERSHIP_PROFILE_UNIT_PROPERTIES_V1: &[&str] = &[
    "FragmentPath", "DropInPaths", "Transient", "InvocationID",
];

pub(super) async fn observe_fixed_ownership_profile_v1(client: &SystemdClient)
    -> Result<(Vec<OwnedValue>, Vec<OwnedValue>)> {
    observe_recipe(client, "aos-sandbox-ownershipd.service", 0,
        OWNERSHIP_PROFILE_PROPERTIES_V1, OWNERSHIP_PROFILE_UNIT_PROPERTIES_V1,
        ObservationPhase::Active, true).await
}

async fn observe_recipe(
    client: &SystemdClient, name: &str, expected_main_pid: u32,
    service_properties: &[&str], unit_properties: &[&str], phase: ObservationPhase,
    discover_main_pid: bool,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>)> {
    let decoding = PropertyDecodingV1::for_client(client);
    let original = ServicePropertyBookendV1::capture_inner(
        &client.conn,
        name,
        expected_main_pid,
        phase,
        discover_main_pid,
        decoding,
    )
    .await?;
    let properties = zbus::fdo::PropertiesProxy::builder(&client.conn)
        .destination(original.owner.clone())?
        .path(original.path)?
        .build()
        .await?;
    let service_values = read_properties(
        &properties,
        "org.freedesktop.systemd1.Service",
        service_properties,
        original.service.inner(),
        decoding,
    )
    .await?;
    let unit_values = read_properties(
        &properties,
        "org.freedesktop.systemd1.Unit",
        unit_properties,
        original.unit.inner(),
        decoding,
    )
    .await?;

    finish_service_property_bookend_v1(
        &original.bus,
        original.manager_name,
        &original.owner,
        &original.unit,
        &original.service,
        original.name.as_ref(),
        original.expected_main_pid,
        original.phase,
        &original.before,
        original.before_substate.as_deref(),
        decoding,
    )
    .await?;
    Ok((service_values, unit_values))
}

// Both service bookends and finite launch setup resolve the actual unique
// PID-1 owner through this original identity recipe. This creates no role grant.
pub(super) async fn capture_pid1_owner_v2(
    connection: &zbus::Connection,
) -> Result<(zbus::fdo::DBusProxy<'static>, zbus::names::BusName<'static>, zbus::names::OwnedUniqueName)> {
    let mut pending = BookendCaptureOriginalV2::default();
    capture_pid1_owner_into_v2(connection, &mut pending).await?;
    Ok((pending.bus.take().ok_or_else(retained::closed)?,
        pending.manager_name.take().ok_or_else(retained::closed)?,
        pending.owner.take().ok_or_else(retained::closed)?))
}

async fn capture_pid1_owner_into_v2(
    connection: &zbus::Connection, pending: &mut BookendCaptureOriginalV2,
) -> Result<()> {
    pending.bus = Some(zbus::fdo::DBusProxy::new(connection).await?);
    pending.manager_name = Some(zbus::names::BusName::try_from("org.freedesktop.systemd1")
        .map_err(|error| changed(&error.to_string()))?);
    let bus = pending.bus.as_ref().ok_or_else(retained::closed)?;
    let manager_name = pending.manager_name.as_ref().ok_or_else(retained::closed)?;
    pending.owner = Some(bus.get_name_owner(manager_name.clone()).await?);
    let owner_name = pending.owner.as_ref().ok_or_else(retained::closed)?.as_str().try_into()
        .map_err(|error: zbus::names::Error| changed(&error.to_string()))?;
    pending.owner_pid = Some(bus.get_connection_unix_process_id(owner_name).await?);
    if pending.owner_pid != Some(1) { return Err(changed("systemd bus owner is not PID 1")); }
    Ok(())
}

/// Borrows one connection and the exact original unique-PID-1 service proxies.
///
/// This is private readback machinery, not service or descriptor authority.
pub(crate) struct ServicePropertyBookendV1<'name> {
    // Match the meaningful legacy reverse-local disposal order. All proxies
    // share the original connection; this opens no second bus or client.
    before_substate: Option<String>,
    before: (String, String, u32, Vec<u8>),
    service: ServiceProxy<'static>,
    unit: UnitProxy<'static>,
    path: zbus::zvariant::OwnedObjectPath,
    _manager: ManagerProxy<'static>,
    owner: zbus::names::OwnedUniqueName,
    manager_name: zbus::names::BusName<'static>,
    bus: zbus::fdo::DBusProxy<'static>,
    name: Cow<'name, str>,
    expected_main_pid: u32,
    phase: ObservationPhase,
    decoding: PropertyDecodingV1,
}

impl<'name> ServicePropertyBookendV1<'name> {
    async fn capture(
        connection: &zbus::Connection,
        name: &'name str,
        expected_main_pid: u32,
        phase: ObservationPhase,
    ) -> Result<Self> {
        Self::capture_inner(
            connection, name, expected_main_pid, phase, false, PropertyDecodingV1::Ordinary,
        ).await
    }

    async fn capture_inner(
        connection: &zbus::Connection, name: &'name str, expected_main_pid: u32,
        phase: ObservationPhase, discover_main_pid: bool, decoding: PropertyDecodingV1,
    ) -> Result<Self> {
        Self::capture_inner_into(connection, Cow::Borrowed(name), expected_main_pid,
            phase, discover_main_pid, decoding, &mut BookendCaptureOriginalV2::default()).await
    }

    async fn capture_inner_into(
        connection: &zbus::Connection, name: Cow<'name, str>, mut expected_main_pid: u32,
        phase: ObservationPhase, discover_main_pid: bool, decoding: PropertyDecodingV1,
        pending: &mut BookendCaptureOriginalV2,
    ) -> Result<Self> {
        if !name.ends_with(".service") || name.contains('/') || name.contains('\0') {
            return Err(changed("service name is not an exact unit name"));
        }
        if expected_main_pid == 0 && !matches!(phase, ObservationPhase::StoppedNix | ObservationPhase::SuccessfulOneshot)
            && !discover_main_pid {
            return Err(changed("service main PID is absent"));
        }
        capture_pid1_owner_into_v2(connection, pending).await?;
        pending.manager = Some(ManagerProxy::builder(connection)
            .destination(pending.owner.as_ref().ok_or_else(retained::closed)?.clone())?
            .build().await?);
        pending.path = Some(pending.manager.as_ref().ok_or_else(retained::closed)?
            .get_unit(name.as_ref()).await?);
        pending.unit = Some(UnitProxy::builder(connection)
            .destination(pending.owner.as_ref().ok_or_else(retained::closed)?.clone())?
            .path(pending.path.as_ref().ok_or_else(retained::closed)?.clone())?
            .cache_properties(CacheProperties::No).build().await?);
        pending.service = Some(ServiceProxy::builder(connection)
            .destination(pending.owner.as_ref().ok_or_else(retained::closed)?.clone())?
            .path(pending.path.as_ref().ok_or_else(retained::closed)?.clone())?
            .cache_properties(CacheProperties::No).build().await?);
        let unit = pending.unit.as_ref().ok_or_else(retained::closed)?;
        let service = pending.service.as_ref().ok_or_else(retained::closed)?;
        pending.id = Some(decoding.get::<String>(unit.inner(), "Id").await?);
        pending.active = Some(decoding.get::<String>(unit.inner(), "ActiveState").await?);
        pending.pid = Some(decoding.get::<u32>(service.inner(), "MainPID").await?);
        pending.invocation = Some(decoding.get::<Vec<u8>>(unit.inner(), "InvocationID").await?);
        if matches!(phase, ObservationPhase::SuccessfulOneshot) && pending.pid != Some(0) {
            return Err(changed("successful oneshot still has a live main PID"));
        }
        if discover_main_pid {
            expected_main_pid = pending.pid.ok_or_else(retained::closed)?;
            if !phase.accepts_pid(pending.active.as_deref().ok_or_else(retained::closed)?, expected_main_pid) {
                return Err(changed("service main PID is absent"));
            }
        }
        pending.substate = match phase {
            ObservationPhase::Active | ObservationPhase::OptionalActive => None,
            ObservationPhase::StartingOrRunning | ObservationPhase::StoppedNix
            | ObservationPhase::SuccessfulOneshot | ObservationPhase::Configuration => {
                Some(decoding.get::<String>(unit.inner(), "SubState").await?)
            }
        };
        Ok(Self {
            before_substate: pending.substate.take(),
            before: (pending.id.take().ok_or_else(retained::closed)?,
                pending.active.take().ok_or_else(retained::closed)?,
                pending.pid.take().ok_or_else(retained::closed)?,
                pending.invocation.take().ok_or_else(retained::closed)?),
            service: pending.service.take().ok_or_else(retained::closed)?,
            unit: pending.unit.take().ok_or_else(retained::closed)?,
            path: pending.path.take().ok_or_else(retained::closed)?,
            _manager: pending.manager.take().ok_or_else(retained::closed)?,
            owner: pending.owner.take().ok_or_else(retained::closed)?,
            manager_name: pending.manager_name.take().ok_or_else(retained::closed)?,
            bus: pending.bus.take().ok_or_else(retained::closed)?,
            name, expected_main_pid, phase, decoding,
        })
    }

    /// Borrows the unique manager destination selected by the existing engine.
    pub(crate) fn destination(&self) -> &str {
        self.owner.as_str()
    }

    /// Borrows the exact original unit path, not a caller-selected locator.
    pub(crate) fn unit_path(&self) -> &zbus::zvariant::OwnedObjectPath {
        &self.path
    }

    /// Borrows only the genuine invocation coordinate for cross-sample DATA.
    pub(crate) fn invocation(&self) -> &[u8] {
        &self.before.3
    }

    pub(crate) async fn finish(&self) -> Result<()> {
        finish_service_property_bookend_v1(
            &self.bus,
            self.manager_name.clone(),
            &self.owner,
            &self.unit,
            &self.service,
            self.name.as_ref(),
            self.expected_main_pid,
            self.phase,
            &self.before,
            self.before_substate.as_deref(),
            self.decoding,
        )
        .await
    }
}

// Ordinary property reads move their original path into PropertiesProxy and
// their manager name into the final RPC exactly as before. The selected dump
// keeps those originals resident and borrows this same final-check engine.
async fn finish_service_property_bookend_v1(
    bus: &zbus::fdo::DBusProxy<'_>,
    manager_name: zbus::names::BusName<'_>,
    owner: &zbus::names::OwnedUniqueName,
    unit: &UnitProxy<'_>,
    service: &ServiceProxy<'_>,
    name: &str,
    expected_main_pid: u32,
    phase: ObservationPhase,
    before: &(String, String, u32, Vec<u8>),
    before_substate: Option<&str>,
    decoding: PropertyDecodingV1,
) -> Result<()> {
    finish_service_property_bookend_into_v2(bus, manager_name, owner, unit, service, name, expected_main_pid, phase,
        before, before_substate, decoding,
        &mut BookendAfterOriginalV2::default()).await
}

async fn finish_service_property_bookend_into_v2(
    bus: &zbus::fdo::DBusProxy<'_>,
    manager_name: zbus::names::BusName<'_>,
    owner: &zbus::names::OwnedUniqueName,
    unit: &UnitProxy<'_>,
    service: &ServiceProxy<'_>,
    name: &str,
    expected_main_pid: u32,
    phase: ObservationPhase,
    before: &(String, String, u32, Vec<u8>),
    before_substate: Option<&str>,
    decoding: PropertyDecodingV1,
    pending: &mut BookendAfterOriginalV2,
) -> Result<()> {
    pending.substate = match phase {
        ObservationPhase::Active | ObservationPhase::OptionalActive => None,
        ObservationPhase::StartingOrRunning | ObservationPhase::StoppedNix
            | ObservationPhase::SuccessfulOneshot | ObservationPhase::Configuration => {
            Some(decoding.get::<String>(unit.inner(), "SubState").await?)
        }
    };
    pending.id = Some(decoding.get::<String>(unit.inner(), "Id").await?);
    pending.active = Some(decoding.get::<String>(unit.inner(), "ActiveState").await?);
    pending.pid = Some(decoding.get::<u32>(service.inner(), "MainPID").await?);
    pending.invocation = Some(decoding.get::<Vec<u8>>(unit.inner(), "InvocationID").await?);
    if Some(before.0.as_str()) != pending.id.as_deref()
        || Some(before.1.as_str()) != pending.active.as_deref()
        || Some(before.2) != pending.pid || Some(before.3.as_slice()) != pending.invocation.as_deref()
        || before_substate != pending.substate.as_deref()
        || before.0 != name || !phase.accepts(&before.1, before_substate)
        || before.2 != expected_main_pid
        || !phase.accepts_pid(&before.1, before.2)
        || !phase.accepts_invocation(&before.1, &before.3) {
        return Err(changed("PID 1 service changed during property readback"));
    }
    pending.owner = Some(bus.get_name_owner(manager_name).await?);
    if pending.owner.as_ref() != Some(owner) {
        return Err(changed("PID 1 service changed during property readback"));
    }
    Ok(())
}

// The fixed Controller startup recipe discovers only a locator. The SAME
// unique-PID1 bookend binds that discovered MainPID before and after the read;
// the actual Controller separately checks its retained kernel objects.
pub(super) async fn observe_active_control_group(
    client: &SystemdClient,
    name: &'static str,
) -> Result<super::ServiceControlGroupObservation> {
    let original = ServicePropertyBookendV1::capture_inner(
        &client.conn, name, 0, ObservationPhase::Active, true,
        PropertyDecodingV1::for_client(client),
    ).await?;
    let control_group = original.decoding.get::<String>(
        original.service.inner(), "ControlGroup",
    ).await?;
    original.finish().await?;
    decode_control_group(name, &original.before, &original.before, control_group)
}

// Stable non-active service state is a successful absence observation. It
// preserves the existing caller's retry behavior without treating an inactive
// unit as a native failure that could be dropped and retried under a new loan.
// Active units use the SAME normal ControlGroup decode and authentic bookends.
pub(super) async fn observe_optional_active_control_group(
    client: &SystemdClient,
    name: &'static str,
) -> Result<Option<super::ServiceControlGroupObservation>> {
    let original = ServicePropertyBookendV1::capture_inner(
        &client.conn, name, 0, ObservationPhase::OptionalActive, true,
        PropertyDecodingV1::for_client(client),
    ).await?;
    if original.before.1 != "active" {
        original.finish().await?;
        return Ok(None);
    }
    let control_group = original.decoding.get::<String>(
        original.service.inner(), "ControlGroup",
    ).await?;
    original.finish().await?;
    decode_control_group(name, &original.before, &original.before, control_group).map(Some)
}

pub(super) fn decode_control_group(
    name: &str, before: &(String, String, u32, Vec<u8>),
    after: &(String, String, u32, Vec<u8>), control_group: String,
) -> Result<super::ServiceControlGroupObservation> {
    let (invocation_id, main_pid) = retained::validate_control_group_parts_v2(
        name, (&before.0, &before.1, before.2, &before.3),
        (&after.0, &after.1, after.2, &after.3), &control_group,
    )?;
    Ok(super::ServiceControlGroupObservation { control_group, main_pid, invocation_id })
}

// The selected Network native collector already bounds every property reply.
// The same service bookend recipe checks the actual same process and unit;
// only this closed name and concrete typed decoding disposition differ.
#[cfg(target_os = "linux")]
pub(crate) async fn capture_network_fd_store_bookend_v4(
    connection: &zbus::Connection,
) -> Result<ServicePropertyBookendV1<'static>> {
    capture_fixed_inventory_fd_store_bookend_v2(connection, FixedFdStoreRoleV2::Network).await
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) enum FixedFdStoreRoleV2 { Network, Mount }

#[cfg(target_os = "linux")]
impl FixedFdStoreRoleV2 {
    pub(crate) const fn unit(self) -> &'static str {
        match self { Self::Network => "aos-netd.service", Self::Mount => "aos-sandbox-mountd.service" }
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn capture_fixed_inventory_fd_store_bookend_v2(
    connection: &zbus::Connection, role: FixedFdStoreRoleV2,
) -> Result<ServicePropertyBookendV1<'static>> {
    ServicePropertyBookendV1::capture_inner(connection, role.unit(), std::process::id(),
        ObservationPhase::StartingOrRunning, false, PropertyDecodingV1::Fixed).await
}

pub(crate) async fn capture_mount_fd_store_bookend_v1(
    connection: &zbus::Connection,
) -> Result<ServicePropertyBookendV1<'static>> {
    ServicePropertyBookendV1::capture(
        connection,
        "aos-sandbox-mountd.service",
        std::process::id(),
        ObservationPhase::StartingOrRunning,
    )
    .await
}

impl ObservationPhase {
    fn accepts_invocation(self, state: &str, invocation: &[u8]) -> bool {
        // systemd's bus_property_get_id128 emits an empty ay for a null ID.
        // A never-started, inactive/dead owner has no invocation to authenticate.
        // The caller still compares both whole bookends and requires PID zero.
        if invocation.is_empty() {
            return matches!(self, Self::StoppedNix | Self::Configuration) && state == "inactive";
        }
        invocation.len() == 16
            && (matches!(self, Self::StoppedNix)
                || (matches!(self, Self::OptionalActive) && state != "active")
                || (matches!(self, Self::Configuration) && state == "inactive")
                || invocation.iter().any(|byte| *byte != 0))
    }

    fn accepts_pid(self, state: &str, pid: u32) -> bool {
        match self {
            Self::Configuration => {
                (state == "inactive" && pid == 0) || (state == "active" && pid != 0)
            }
            Self::StoppedNix | Self::SuccessfulOneshot => pid == 0,
            Self::OptionalActive => state != "active" || pid != 0,
            Self::Active | Self::StartingOrRunning => pid != 0,
        }
    }

    fn accepts(self, state: &str, substate: Option<&str>) -> bool {
        match self {
            Self::Active => state == "active",
            Self::OptionalActive => matches!(state,
                "active" | "inactive" | "activating" | "deactivating" | "failed"
                    | "reloading" | "maintenance" | "refreshing"),
            Self::StartingOrRunning => {
                matches!(
                    (state, substate),
                    ("activating", Some("start")) | ("active", Some("running"))
                )
            }
            Self::StoppedNix => matches!((state, substate), ("inactive", Some("dead"))),
            Self::SuccessfulOneshot => matches!((state, substate), ("active", Some("exited"))),
            Self::Configuration => matches!((state, substate),
                ("inactive", Some("dead")) | ("active", Some("running"))),
        }
    }
}

pub(super) async fn observe_stopped_nix(
    client: &SystemdClient,
) -> Result<[(Vec<OwnedValue>, Vec<OwnedValue>); 2]> {
    const SERVICE: &[&str] = &[
        "ControlGroup",
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
    ];
    const UNIT: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];

    let controller = observe(
        client,
        "aos-sandboxd.service",
        0,
        SERVICE,
        UNIT,
        ObservationPhase::StoppedNix,
    )
    .await?;
    let owner = observe(
        client,
        "aos-sandbox-nixd.service",
        0,
        SERVICE,
        UNIT,
        ObservationPhase::StoppedNix,
    )
    .await?;

    for (service, unit) in [&controller, &owner] {
        require_signatures(
            service,
            &["s", "a(sasbttttuii)", "a(sasbttttuii)", "a(sasbttttuii)"],
        )?;
        require_signatures(unit, &["s", "as", "b", "ay"])?;
    }
    Ok([controller, owner])
}

fn require_signatures(values: &[OwnedValue], signatures: &[&str]) -> Result<()> {
    if values.len() != signatures.len()
        || values.iter().zip(signatures).any(|(value, signature)| {
            value.value_signature().to_string() != *signature
        })
    {
        return Err(changed("stopped Nix property schema differs"));
    }
    Ok(())
}

async fn read_properties(
    proxy: &zbus::fdo::PropertiesProxy<'_>, interface: &str, names: &[&str],
    source: &zbus::Proxy<'_>, decoding: PropertyDecodingV1,
) -> Result<Vec<OwnedValue>> {
    let mut values = Vec::with_capacity(names.len());
    read_properties_into_v2(proxy, interface, names, source, decoding, &mut values).await?;
    Ok(values)
}

async fn read_properties_into_v2(
    proxy: &zbus::fdo::PropertiesProxy<'_>, interface: &str, names: &[&str],
    source: &zbus::Proxy<'_>, decoding: PropertyDecodingV1, values: &mut Vec<OwnedValue>,
) -> Result<()> {
    let interface = zbus::names::InterfaceName::try_from(interface)
        .map_err(|error| changed(&error.to_string()))?;
    for name in names {
        values.push(decoding.value(proxy, source, interface.clone(), name).await?);
    }
    Ok(())
}

pub(super) async fn observe_offline_nix(
    client: &SystemdClient,
    observation: &mut NixOfflineAbsenceObservationV5,
) -> Result<()> {
    const SERVICE: &[&str] = &[
        "ControlGroup", "ExecStart", "ExecStartPre", "ExecStartPost",
    ];
    const UNIT: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];
    const OWNER: &str = "aos-sandbox-nixd.service";

    if observation.absence.iter().any(Option::is_some) {
        return Err(changed("offline Nix absence observation was already attempted"));
    }
    observation.controller = Some(observe(
        client, "aos-sandboxd.service", 0, SERVICE, UNIT, ObservationPhase::StoppedNix,
    ).await?);
    let controller = observation.controller.as_ref()
        .ok_or_else(|| changed("original stopped Controller properties are absent"))?;
    require_signatures(
        &controller.0,
        &["s", "a(sasbttttuii)", "a(sasbttttuii)", "a(sasbttttuii)"],
    )?;
    require_signatures(&controller.1, &["s", "as", "b", "ay"])?;

    let bus = zbus::fdo::DBusProxy::new(&client.conn).await?;
    let manager_name = zbus::names::BusName::try_from("org.freedesktop.systemd1")
        .map_err(|error| changed(&error.to_string()))?;
    let owner = bus.get_name_owner(manager_name.clone()).await?;
    let owner_name = owner.as_str().try_into()
        .map_err(|error: zbus::names::Error| changed(&error.to_string()))?;
    if bus.get_connection_unix_process_id(owner_name).await? != 1 {
        return Err(changed("systemd bus owner is not PID 1"));
    }
    let manager = ManagerProxy::builder(&client.conn)
        .destination(owner.clone())?.build().await?;

    match manager.get_unit(OWNER).await {
        Ok(path) => {
            observation.owner_path = Some(path);
            observation.nix_owner = Some(observe(
                client, OWNER, 0, SERVICE, UNIT, ObservationPhase::StoppedNix,
            ).await?);
            let present = observation.nix_owner.as_ref()
                .ok_or_else(|| changed("original stopped Nix owner properties are absent"))?;
            require_signatures(
                &present.0,
                &["s", "a(sasbttttuii)", "a(sasbttttuii)", "a(sasbttttuii)"],
            )?;
            require_signatures(&present.1, &["s", "as", "b", "ay"])?;
            if bus.get_name_owner(manager_name).await? != owner {
                return Err(changed("PID 1 changed during offline Nix readback"));
            }
            Ok(())
        }
        Err(error) if exact_method_error(&error, "org.freedesktop.systemd1.NoSuchUnit") => {
            observation.absence[0] = Some(Error::Zbus(error));
            // Selected systemd propagates ENOENT as a method error, not a
            // successful string named `not-found`. Do not normalize other errors.
            let file_state = zbus::proxy::Builder::<zbus::Proxy<'_>>::new(&client.conn)
                .destination(owner.clone())?
                .path("/org/freedesktop/systemd1")?
                .interface("org.freedesktop.systemd1.Manager")?
                .cache_properties(CacheProperties::No)
                .build().await?
                .call_method("GetUnitFileState", &(OWNER,)).await;
            match file_state {
                Err(error) if exact_method_error(&error, "org.freedesktop.DBus.Error.FileNotFound") => {
                    observation.absence[1] = Some(Error::Zbus(error));
                }
                Err(error) => return Err(error.into()),
                Ok(reply) => {
                    observation.raw_reply = Some(reply);
                    return Err(changed("unloaded Nix owner has an installed unit file"));
                }
            }
            if bus.get_name_owner(manager_name.clone()).await? != owner {
                return Err(changed("PID 1 changed during offline Nix absence readback"));
            }
            let owner_name = owner.as_str().try_into()
                .map_err(|error: zbus::names::Error| changed(&error.to_string()))?;
            if bus.get_connection_unix_process_id(owner_name).await? != 1 {
                return Err(changed("original systemd bus owner is not PID 1"));
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn exact_method_error(error: &zbus::Error, expected: &'static str) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _) if name.as_str() == expected)
}

fn changed(message: &str) -> Error {
    Error::InvalidSandboxUnit(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::ObservationPhase;

    #[test]
    fn configuration_requires_a_stable_running_or_dead_unit_and_its_actual_pid() {
        let phase = ObservationPhase::Configuration;
        assert!(phase.accepts("inactive", Some("dead")));
        assert!(phase.accepts("active", Some("running")));
        assert!(phase.accepts_pid("inactive", 0));
        assert!(phase.accepts_pid("active", 42));
        assert!(!phase.accepts_pid("inactive", 42));
        assert!(!phase.accepts_pid("active", 0));
        for (state, substate) in [
            ("activating", "start"),
            ("deactivating", "stop"),
            ("active", "exited"),
            ("failed", "failed"),
            ("reloading", "reload"),
            ("inactive", "running"),
        ] {
            assert!(!phase.accepts(state, Some(substate)));
        }
        assert!(!phase.accepts("inactive", None));
    }

    #[test]
    fn configuration_null_invocation_cannot_describe_a_live_process() {
        let phase = ObservationPhase::Configuration;
        assert!(phase.accepts_invocation("inactive", &[]));
        assert!(phase.accepts_invocation("inactive", &[0; 16]));
        assert!(phase.accepts_invocation("inactive", &[1; 16]));
        assert!(phase.accepts_invocation("active", &[1; 16]));
        assert!(!phase.accepts_invocation("active", &[]));
        assert!(!phase.accepts_invocation("active", &[0; 16]));
        for len in [1, 15, 17] {
            assert!(!phase.accepts_invocation("inactive", &vec![1; len]));
            assert!(!phase.accepts_invocation("active", &vec![1; len]));
        }
    }

    #[test]
    fn successful_oneshot_is_distinct_from_running_starting_and_never_started() {
        let phase = ObservationPhase::SuccessfulOneshot;
        assert!(phase.accepts("active", Some("exited")));
        for (state, substate) in [
            ("active", Some("running")),
            ("activating", Some("start")),
            ("inactive", Some("dead")),
            ("failed", Some("failed")),
            ("active", None),
        ] {
            assert!(!phase.accepts(state, substate));
        }
        assert!(!ObservationPhase::StartingOrRunning.accepts("active", Some("exited")));
    }


    #[test]
    fn active_control_group_requires_the_same_nonzero_invocation_and_pid() {
        let before = ("aos-sandbox-hostd.service".to_owned(), "active".to_owned(), 42, vec![1; 16]);
        let path = "/system.slice/aos-sandbox-hostd.service".to_owned();
        let decoded = super::decode_control_group(&before.0, &before, &before, path.clone()).unwrap();
        assert_eq!(decoded.main_pid.get(), 42);

        let mut after = before.clone();
        after.2 += 1;
        assert!(super::decode_control_group(&before.0, &before, &after, path.clone()).is_err());
        after = before.clone();
        after.3[0] += 1;
        assert!(super::decode_control_group(&before.0, &before, &after, path).is_err());
    }

    #[test]
    fn active_control_group_refuses_noncanonical_locators() {
        let before = ("aos-sandbox-mountd.service".to_owned(), "active".to_owned(), 42, vec![1; 16]);
        for path in ["system.slice/unit.service", "/system.slice/../unit.service",
            "/system.slice//unit.service", "/system.slice/./unit.service"]
        {
            assert!(super::decode_control_group(&before.0, &before, &before, path.to_owned()).is_err());
        }
    }

    #[test]
    fn stopped_nix_phase_accepts_only_inactive_dead() {
        let stopped = ObservationPhase::StoppedNix;
        assert!(stopped.accepts("inactive", Some("dead")));

        for (state, substate) in [
            ("active", Some("running")),
            ("activating", Some("start")),
            ("deactivating", Some("stop")),
            ("failed", Some("failed")),
            ("inactive", None),
        ] {
            assert!(!stopped.accepts(state, substate));
        }
        assert!(!ObservationPhase::Active.accepts("inactive", Some("dead")));
        assert!(!ObservationPhase::StartingOrRunning.accepts("inactive", Some("dead")));
    }

    #[test]
    fn stopped_nix_readback_accepts_the_managers_null_invocation_encoding() {
        let stopped = ObservationPhase::StoppedNix;
        assert!(stopped.accepts_invocation("inactive", &[]));
        assert!(stopped.accepts_invocation("inactive", &[0; 16]));
        assert!(stopped.accepts_invocation("inactive", &[1; 16]));
        assert!(!stopped.accepts_invocation("active", &[]));

        for length in [1, 15, 17] {
            assert!(!stopped.accepts_invocation("inactive", &vec![1; length]));
        }
    }

    #[test]
    fn absent_stopped_invocation_cannot_authenticate_an_active_or_completed_service() {
        for phase in [
            ObservationPhase::Active,
            ObservationPhase::OptionalActive,
            ObservationPhase::StartingOrRunning,
            ObservationPhase::SuccessfulOneshot,
        ] {
            assert!(!phase.accepts_invocation("active", &[]));
            assert!(!phase.accepts_invocation("inactive", &[]));
            assert!(!phase.accepts_invocation("active", &[0; 16]));
            assert!(phase.accepts_invocation("active", &[1; 16]));
        }
        assert!(ObservationPhase::OptionalActive.accepts_invocation("inactive", &[0; 16]));
    }

    #[test]
    fn startup_property_phase_does_not_grant_other_activation_states() {
        let startup = ObservationPhase::StartingOrRunning;
        assert!(startup.accepts("activating", Some("start")));
        assert!(startup.accepts("active", Some("running")));
        for (state, substate) in [
            ("activating", "start-pre"),
            ("activating", "start-post"),
            ("activating", "auto-restart"),
            ("active", "exited"),
            ("deactivating", "stop-sigkill"),
            ("failed", "failed"),
        ] {
            assert!(!startup.accepts(state, Some(substate)));
        }
        assert!(!startup.accepts("active", None));
        assert!(ObservationPhase::Active.accepts("active", None));
    }
}
