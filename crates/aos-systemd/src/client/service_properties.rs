//! Shared unique-PID-1 property readback for active and startup service checks.
//!
//! This observation neither makes a notify service ready nor freezes PID 1's
//! policy. Consumers must validate retained kernel objects independently.

use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedValue;

use super::{Error, ManagerProxy, Result, ServiceProxy, SystemdClient, UnitProxy};

#[derive(Clone, Copy)]
pub(super) enum ObservationPhase {
    Active,
    StartingOrRunning,
}

pub(super) async fn observe(
    client: &SystemdClient,
    name: &str,
    expected_main_pid: u32,
    service_properties: &[&str],
    unit_properties: &[&str],
    phase: ObservationPhase,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>)> {
    if !name.ends_with(".service") || name.contains('/') || name.contains('\0') {
        return Err(changed("service name is not an exact unit name"));
    }
    if expected_main_pid == 0 {
        return Err(changed("service main PID is absent"));
    }

    let bus = zbus::fdo::DBusProxy::new(&client.conn).await?;
    let manager_name = zbus::names::BusName::try_from("org.freedesktop.systemd1")
        .map_err(|error| changed(&error.to_string()))?;
    let owner = bus.get_name_owner(manager_name.clone()).await?;
    let owner_name = owner
        .as_str()
        .try_into()
        .map_err(|error: zbus::names::Error| changed(&error.to_string()))?;
    if bus.get_connection_unix_process_id(owner_name).await? != 1 {
        return Err(changed("systemd bus owner is not PID 1"));
    }

    let manager = ManagerProxy::builder(&client.conn)
        .destination(owner.clone())?
        .build()
        .await?;
    let path = manager.get_unit(name).await?;
    let unit = UnitProxy::builder(&client.conn)
        .destination(owner.clone())?
        .path(path.clone())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let service = ServiceProxy::builder(&client.conn)
        .destination(owner.clone())?
        .path(path.clone())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let before = (
        unit.id().await?,
        unit.active_state().await?,
        service.main_pid().await?,
        unit.invocation_id().await?,
    );
    let before_substate = match phase {
        ObservationPhase::Active => None,
        ObservationPhase::StartingOrRunning => Some(unit.sub_state().await?),
    };

    let properties = zbus::fdo::PropertiesProxy::builder(&client.conn)
        .destination(owner.clone())?
        .path(path)?
        .build()
        .await?;
    let service_values = read_properties(
        &properties,
        "org.freedesktop.systemd1.Service",
        service_properties,
    )
    .await?;
    let unit_values = read_properties(
        &properties,
        "org.freedesktop.systemd1.Unit",
        unit_properties,
    )
    .await?;

    let after_substate = match phase {
        ObservationPhase::Active => None,
        ObservationPhase::StartingOrRunning => Some(unit.sub_state().await?),
    };
    let after = (
        unit.id().await?,
        unit.active_state().await?,
        service.main_pid().await?,
        unit.invocation_id().await?,
    );
    if before != after
        || before_substate != after_substate
        || before.0 != name
        || !phase.accepts(&before.1, before_substate.as_deref())
        || before.2 != expected_main_pid
        || before.3.len() != 16
        || before.3.iter().all(|byte| *byte == 0)
        || bus.get_name_owner(manager_name).await? != owner
    {
        return Err(changed("PID 1 service changed during property readback"));
    }
    Ok((service_values, unit_values))
}

impl ObservationPhase {
    fn accepts(self, state: &str, substate: Option<&str>) -> bool {
        match self {
            Self::Active => state == "active",
            Self::StartingOrRunning => {
                matches!(
                    (state, substate),
                    ("activating", Some("start")) | ("active", Some("running"))
                )
            }
        }
    }
}

async fn read_properties(
    proxy: &zbus::fdo::PropertiesProxy<'_>,
    interface: &str,
    names: &[&str],
) -> Result<Vec<OwnedValue>> {
    let interface = zbus::names::InterfaceName::try_from(interface)
        .map_err(|error| changed(&error.to_string()))?;
    let mut values = Vec::with_capacity(names.len());
    for name in names {
        values.push(proxy.get(interface.clone(), name).await?);
    }
    Ok(values)
}

fn changed(message: &str) -> Error {
    Error::InvalidSandboxUnit(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::ObservationPhase;

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
