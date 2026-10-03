//! Shared unique-PID-1 property readback for active and startup service checks.
//!
//! This observation neither makes a notify service ready nor freezes PID 1's
//! policy. Consumers must validate retained kernel objects independently.

use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedValue;

use super::{Error, ManagerProxy, NixOfflineAbsenceObservationV5, Result, ServiceProxy, SystemdClient, UnitProxy};

#[derive(Clone, Copy)]
pub(super) enum ObservationPhase {
    Active,
    StartingOrRunning,
    StoppedNix,
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
    if expected_main_pid == 0 && !matches!(phase, ObservationPhase::StoppedNix) {
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
        ObservationPhase::StartingOrRunning | ObservationPhase::StoppedNix => {
            Some(unit.sub_state().await?)
        }
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
        ObservationPhase::StartingOrRunning | ObservationPhase::StoppedNix => {
            Some(unit.sub_state().await?)
        }
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
        || (!matches!(phase, ObservationPhase::StoppedNix)
            && before.3.iter().all(|byte| *byte == 0))
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
            Self::StoppedNix => matches!((state, substate), ("inactive", Some("dead"))),
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
            let file_state = zbus::Proxy::builder(&client.conn)
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
