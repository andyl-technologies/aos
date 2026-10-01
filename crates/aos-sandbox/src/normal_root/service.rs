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
    std::thread::Builder::new()
        .name("normal-root-pid1-readback".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| NormalRootStartupErrorV1::Service)?;
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    let manager = SystemdClient::connect()
                        .await
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
    let Value::Array(open_files) = &**open_files else {
        return false;
    };
    let Value::Array(extras) = &**extras else {
        return false;
    };
    if open_files.len() != 2
        || !extras.is_empty()
        || extras.element_signature() != Value::from("").value_signature()
    {
        return false;
    }
    let mut found = [false; 2];
    for entry in open_files.inner() {
        let Value::Structure(entry) = entry else {
            return false;
        };
        let [Value::Str(path), Value::Str(name), Value::U64(1)] = entry.fields() else {
            return false;
        };
        let slot = match (path.as_str(), name.as_str()) {
            ("/proc/1/exe", PID1_FD_NAME) => 0,
            (path, PROFILE_FD_NAME) if path == profile_path => 1,
            _ => return false,
        };
        if found[slot] {
            return false;
        }
        found[slot] = true;
    }
    found == [true; 2]
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
