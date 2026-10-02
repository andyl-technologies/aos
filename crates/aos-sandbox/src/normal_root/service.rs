//! Genuine PID1 fixed-unit observations shared by Root and its Controller client.
//!
//! Property equality is point-in-time, not a policy freeze. Trusted deployment
//! administration and PID1 remain within the RFC boot/system-manager boundary.

use std::path::PathBuf;
use std::time::Duration;

use aos_systemd::{OwnedValue, SystemdClient, Value};

use crate::systemd_property_data;

use super::{
    NormalRootStartupErrorV1, PID1_FD_NAME, PROFILE_FD_NAME,
    profile::{CONTEXT, UNIT},
};

pub(super) const SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
];
const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];
const NIX_BARRIER_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "ExitType",
    "KillMode",
    "TimeoutStopUSec",
];
const PEER_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
];

const STORAGE_UNIT: &str = "aos-storaged.service";
const STORAGE_CGROUP: &str = "/aos.slice/aos-control.slice/aos-storaged.service";
const STORAGE_CONTEXT: &str = "system_u:system_r:aos_sandbox_storage_t";
const STORAGE_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "ExecStart",
];

#[derive(Debug, PartialEq)]
pub(super) struct ServiceObservationV1 {
    pub(super) fragment: PathBuf,
    pub(super) invocation: [u8; 16],
}

pub(super) fn observe(
    profile_path: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    observe_at(profile_path, std::process::id())
}

/// Observes only this process's fixed Storage unit through the same PID1 reader.
pub(super) fn observe_storage(
) -> Result<super::StorageWorkerParentDataV3, NormalRootStartupErrorV1> {
    let (service, unit) = read_properties(STORAGE_UNIT, std::process::id(), STORAGE_PROPERTIES)?;
    let [cgroup, open_files, extras, maximum, stored, context, bounding, ambient, nnp, start] =
        service.as_slice()
    else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(open_files) = &**open_files else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Structure(open_file)] = open_files.inner() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Str(path), Value::Str(name), Value::U64(1)] = open_file.fields() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(extras) = &**extras else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    if <&str>::try_from(cgroup).ok() != Some(STORAGE_CGROUP)
        || path.as_str() != "/proc/1/exe"
        || name.as_str() != "aos-method46-pid1-image"
        || !extras.is_empty()
        || extras.element_signature() != Value::from("").value_signature()
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || systemd_property_data::explicit_context(context) != Some(STORAGE_CONTEXT)
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let command = systemd_property_data::single_exec_start(start)
        .ok_or(NormalRootStartupErrorV1::Service)?;
    if command.pid != std::process::id()
        || command.path.len() > 4096
        || command.argv.len() != 12
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let executable = command.path.to_owned();
    let arguments = command
        .argv
        .iter()
        .map(|value| {
            let Value::Str(value) = value else {
                return Err(NormalRootStartupErrorV1::Service);
            };
            if value.len() > 4096 {
                return Err(NormalRootStartupErrorV1::Service);
            }
            Ok(value.as_str().to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observed = immutable_observation(decode_unit(&unit, STORAGE_UNIT)?)?;
    Ok(super::StorageWorkerParentDataV3 {
        fragment: observed.fragment,
        invocation: observed.invocation,
        executable,
        arguments,
    })
}

pub(super) fn observe_at(
    profile_path: &str,
    pid: u32,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let (service, unit) = read_properties(UNIT, pid, SERVICE_PROPERTIES)?;
    immutable_observation(decode(&service, &unit, profile_path)?)
}

pub(super) fn observe_peer(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::profile::NormalRootProfileV1,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let (values, unit) = read_properties(UNIT, pid, PEER_PROPERTIES)?;
    let common = values
        .get(..SERVICE_PROPERTIES.len())
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let launch = values
        .get(SERVICE_PROPERTIES.len()..)
        .ok_or(NormalRootStartupErrorV1::Service)?;
    require_peer_launch(launch, pid, profile)?;
    let profile_path = profile_path
        .to_str()
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    immutable_observation(decode(common, &unit, profile_path)?)
}

pub(super) fn require_peer_launch(
    launch: &[OwnedValue],
    pid: u32,
    profile: &super::profile::NormalRootProfileV1,
) -> Result<(), NormalRootStartupErrorV1> {
    let [start, pre, post] = launch else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    for empty in [pre, post] {
        let Value::Array(commands) = &**empty else {
            return Err(NormalRootStartupErrorV1::Service);
        };
        if !commands.is_empty() {
            return Err(NormalRootStartupErrorV1::Service);
        }
    }
    let command = systemd_property_data::single_exec_start(start)
        .ok_or(NormalRootStartupErrorV1::Service)?;

    let expected = std::iter::once(profile.executable.path.clone())
        .chain(profile.identities.map(|identity| identity.to_string()))
        .collect::<Vec<_>>();
    if command.path != profile.executable.path || command.pid != pid
        || command.argv.len() != expected.len()
        || command.argv.iter().zip(&expected).any(|(actual, expected)| {
            !matches!(actual, Value::Str(actual) if actual.as_str() == expected)
        })
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}

pub(super) fn read_properties(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    read_properties_with_recipe(unit_name, pid, properties, Pid1ConnectionRecipeV5::Legacy)
}

#[derive(Clone, Copy)]
pub(super) enum Pid1ConnectionRecipeV5 {
    Legacy,
    NixOfflineHardware,
}

pub(super) fn read_nix_offline_hardware_properties(
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    read_properties_with_recipe(
        "aos-sandbox-nix-floor-provision.service",
        std::process::id(),
        properties,
        Pid1ConnectionRecipeV5::NixOfflineHardware,
    )
}

fn read_properties_with_recipe(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
    recipe: Pid1ConnectionRecipeV5,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    std::thread::Builder::new()
        .name("normal-root-pid1-readback".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| NormalRootStartupErrorV1::Service)?;
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    let manager = match recipe {
                        Pid1ConnectionRecipeV5::Legacy => SystemdClient::connect().await,
                        Pid1ConnectionRecipeV5::NixOfflineHardware => {
                            SystemdClient::connect_nix_offline_hardware_observer().await
                        }
                    }
                        .map_err(|_| NormalRootStartupErrorV1::Service)?;
                    manager
                        .observe_pid1_service_startup_properties(
                            unit_name,
                            pid,
                            properties,
                            UNIT_PROPERTIES,
                        )
                        .await
                        .map_err(|_| NormalRootStartupErrorV1::Service)
                })
                .await
                .map_err(|_| NormalRootStartupErrorV1::Service)?
            })
        })
        .map_err(|_| NormalRootStartupErrorV1::Service)?
        .join()
        .map_err(|_| NormalRootStartupErrorV1::Service)?
}

pub(super) fn immutable_observation(
    mut observed: ServiceObservationV1,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    // Retain the immutable canonical target, not PID1's logical /etc symlink.
    observed.fragment =
        std::fs::canonicalize(&observed.fragment).map_err(|_| NormalRootStartupErrorV1::Service)?;
    super::profile::require_store_path(
        observed
            .fragment
            .to_str()
            .ok_or(NormalRootStartupErrorV1::Service)?,
    )?;
    Ok(observed)
}

// Only Nix floor-origin observations add the population crash-barrier fields.
// The ordinary Root/Controller flights retain their exact property list.
/// Reads the Nix barrier fields through the same authentic PID1 observer.
///
/// # Errors
///
/// Rejects failed original PID1 readback, wrong width or a barrier mismatch.
pub(super) fn read_nix_barrier_properties(
    unit_name: &'static str,
    pid: u32,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    let (mut properties, unit) = read_properties(unit_name, pid, NIX_BARRIER_PROPERTIES)?;
    if properties.len() != NIX_BARRIER_PROPERTIES.len() {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let barrier = properties.split_off(SERVICE_PROPERTIES.len());
    require_nix_barrier(&barrier)?;
    Ok((properties, unit))
}

fn require_nix_barrier(values: &[OwnedValue]) -> Result<(), NormalRootStartupErrorV1> {
    let [exit_type, kill_mode, timeout] = values else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    if <&str>::try_from(exit_type).ok() != Some("cgroup")
        || <&str>::try_from(kill_mode).ok() != Some("control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}

pub(super) fn decode(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let [
        cgroup,
        open_files,
        extras,
        maximum,
        stored,
        context,
        bounding,
        ambient,
        nnp,
    ] = service
    else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let context = systemd_property_data::explicit_context(context)
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let expected_cgroup = format!("/system.slice/{UNIT}");
    if <&str>::try_from(cgroup).ok() != Some(expected_cgroup.as_str())
        || context != CONTEXT
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || !exact_open_files(open_files, extras, profile_path)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    decode_unit(unit, UNIT)
}

pub(super) fn decode_unit(
    unit: &[OwnedValue],
    unit_name: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let [fragment, drop_ins, transient, invocation] = unit else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(drop_ins) = &**drop_ins else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(invocation) = &**invocation else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    if !drop_ins.is_empty()
        || drop_ins.element_signature() != Value::from("").value_signature()
        || bool::try_from(transient).ok() != Some(false)
        || invocation.len() != 16
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let id = systemd_property_data::nonzero_invocation_bytes(invocation.inner())
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let fragment = <&str>::try_from(fragment).map_err(|_| NormalRootStartupErrorV1::Service)?;
    if fragment.len() > 1024
        || !fragment.starts_with('/')
        || !fragment.ends_with(&format!("/{unit_name}"))
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(ServiceObservationV1 {
        fragment: fragment.into(),
        invocation: id,
    })
}

fn exact_open_files(open_files: &OwnedValue, extras: &OwnedValue, profile_path: &str) -> bool {
    systemd_property_data::exact_readonly_open_file_pair(
        open_files,
        extras,
        [("/proc/1/exe", PID1_FD_NAME), (profile_path, PROFILE_FD_NAME)],
    )
}

pub(super) fn require_same(
    previous: &ServiceObservationV1,
    current: &ServiceObservationV1,
) -> Result<(), NormalRootStartupErrorV1> {
    if previous != current {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}

#[cfg(test)]
mod nix_barrier_tests {
    use super::*;

    fn values(exit_type: &str, kill_mode: &str, timeout: u64) -> Vec<OwnedValue> {
        vec![
            OwnedValue::try_from(Value::from(exit_type.to_owned())).unwrap(),
            OwnedValue::try_from(Value::from(kill_mode.to_owned())).unwrap(),
            OwnedValue::from(timeout),
        ]
    }

    #[test]
    fn nix_barrier_appends_only_three_fields_to_the_ordinary_property_order() {
        assert_eq!(
            &NIX_BARRIER_PROPERTIES[..SERVICE_PROPERTIES.len()],
            SERVICE_PROPERTIES,
        );
        assert_eq!(
            &NIX_BARRIER_PROPERTIES[SERVICE_PROPERTIES.len()..],
            &["ExitType", "KillMode", "TimeoutStopUSec"],
        );
    }

    #[test]
    fn nix_barrier_requires_exact_population_and_unbounded_stop_properties() {
        assert!(require_nix_barrier(&values("cgroup", "control-group", u64::MAX)).is_ok());

        for candidate in [
            values("main", "control-group", u64::MAX),
            values("cgroup", "process", u64::MAX),
            values("cgroup", "control-group", u64::MAX - 1),
            values("cgroup", "control-group", 0),
        ] {
            assert!(require_nix_barrier(&candidate).is_err());
        }
        assert!(require_nix_barrier(&[]).is_err());
        let mut extra = values("cgroup", "control-group", u64::MAX);
        extra.push(OwnedValue::from(0_u64));
        assert!(require_nix_barrier(&extra).is_err());
    }
}
