//! Genuine PID1 fixed-unit observation reused from the shared systemd reader.
//!
//! Property equality is point-in-time, not a policy freeze. Trusted deployment
//! administration and PID1 remain within the RFC boot/system-manager boundary.

use std::path::PathBuf;
use std::time::Duration;

use aos_systemd::{OwnedValue, SystemdClient, Value};

use super::{
    NormalRootStartupErrorV1, PID1_FD_NAME, PROFILE_FD_NAME,
    profile::{CONTEXT, UNIT},
};

const SERVICE_PROPERTIES: &[&str] = &[
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

#[derive(Debug, PartialEq)]
pub(super) struct ServiceObservationV1 {
    pub(super) fragment: PathBuf,
    pub(super) invocation: [u8; 16],
}

pub(super) fn observe(
    profile_path: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let path = profile_path.to_owned();
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
                    let (service, unit) = manager
                        .observe_pid1_service_startup_properties(
                            UNIT,
                            std::process::id(),
                            SERVICE_PROPERTIES,
                            UNIT_PROPERTIES,
                        )
                        .await
                        .map_err(|_| NormalRootStartupErrorV1::Service)?;
                    let mut observed = decode(&service, &unit, &path)?;
                    // PID1 reports its logical /etc fragment pathname. Retain the
                    // actual immutable canonical target, not the symlink locator.
                    observed.fragment = std::fs::canonicalize(&observed.fragment)
                        .map_err(|_| NormalRootStartupErrorV1::Service)?;
                    super::profile::require_store_path(
                        observed
                            .fragment
                            .to_str()
                            .ok_or(NormalRootStartupErrorV1::Service)?,
                    )?;
                    Ok(observed)
                })
                .await
                .map_err(|_| NormalRootStartupErrorV1::Service)?
            })
        })
        .map_err(|_| NormalRootStartupErrorV1::Service)?
        .join()
        .map_err(|_| NormalRootStartupErrorV1::Service)?
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
    let [fragment, drop_ins, transient, invocation] = unit else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(drop_ins) = &**drop_ins else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(invocation) = &**invocation else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Structure(context) = &**context else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let expected_cgroup = format!("/system.slice/{UNIT}");
    if <&str>::try_from(cgroup).ok() != Some(expected_cgroup.as_str())
        || !drop_ins.is_empty()
        || drop_ins.element_signature() != Value::from("").value_signature()
        || bool::try_from(transient).ok() != Some(false)
        || invocation.len() != 16
        || context.as_str() != CONTEXT
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || !exact_open_files(open_files, extras, profile_path)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let mut id = [0; 16];
    for (slot, value) in id.iter_mut().zip(invocation.inner()) {
        *slot = u8::try_from(value).map_err(|_| NormalRootStartupErrorV1::Service)?;
    }
    if id == [0; 16] {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let fragment = <&str>::try_from(fragment).map_err(|_| NormalRootStartupErrorV1::Service)?;
    if fragment.len() > 1024
        || !fragment.starts_with('/')
        || !fragment.ends_with(&format!("/{UNIT}"))
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
