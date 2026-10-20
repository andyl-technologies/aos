//! Shares fixed Root delivery and peer comparison DATA without role authority.
//!
//! The complete actual archive and native receiver remain caller-owned. These
//! functions neither open a service connection nor admit Root, C, R or a writer.

use aos_systemd::{OwnedValue, Value};

use super::ControllerProfileErrorV1 as NormalRootStartupErrorV1;
use super::delivery::{ServiceObservationV1, SERVICE_PROPERTIES};
use super::property_data as systemd_property_data;
use super::schema::{UNIT, CONTEXT};

const PID1_FD_NAME: &str = "aos-normal-root-pid1-image";
const PROFILE_FD_NAME: &str = "aos-normal-root-profile";

/// Names the closed selected Root launch and actual producer property flight.
///
/// The first nine values share the existing fixed delivery decoder. Producer
/// epoch follows those values; the final three retain the exact launch recipe.
pub const SELECTED_RESOURCE_PEER_PROPERTIES_V1: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames", "FileDescriptorStoreMax",
    "NFileDescriptorStore", "SELinuxContext", "CapabilityBoundingSet", "AmbientCapabilities",
    "NoNewPrivileges", "AOSResourceProducerEpoch", "ExecStart", "ExecStartPre", "ExecStartPost",
];

/// Applies the existing fixed Root property comparison to readonly DATA.
///
/// # Errors
/// Refuses malformed properties, altered fixed roles, process or unit delivery.
pub fn decode(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_with_resource_pair(service, unit, profile_path, false)
}

fn decode_with_resource_pair(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
    resource_delivery: bool,
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
        || !(if resource_delivery {
            exact_resource_open_files(open_files, extras, profile_path)
        } else {
            exact_open_files(open_files, extras, profile_path)
        })
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    super::delivery::decode_unit(unit, UNIT)
}

fn exact_open_files(open_files: &OwnedValue, extras: &OwnedValue, profile_path: &str) -> bool {
    systemd_property_data::exact_readonly_open_file_pair(
        open_files,
        extras,
        [("/proc/1/exe", PID1_FD_NAME), (profile_path, PROFILE_FD_NAME)],
    )
}

fn exact_resource_open_files(open_files: &OwnedValue, extras: &OwnedValue, profile_path: &str) -> bool {
    let Value::Array(open_files) = &**open_files else {
        return false;
    };
    let Value::Array(extras) = &**extras else {
        return false;
    };
    extras.element_signature() == Value::from("").value_signature()
        && super::delivery::valid_resource_delivery_names(extras.inner(), true)
        && systemd_property_data::exact_readonly_open_file_entries(
            open_files.inner(),
            [("/proc/1/exe", PID1_FD_NAME), (profile_path, PROFILE_FD_NAME)],
        )
}

/// Applies the existing fixed Root property comparison to readonly DATA.
///
/// # Errors
/// Refuses malformed properties, altered fixed roles, process or unit delivery.
pub fn decode_root_resource(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
) -> Result<(ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1> {
    let (producer, common) = service.split_last().ok_or(NormalRootStartupErrorV1::Service)?;
    let observed = decode_with_resource_pair(common, unit, profile_path, true)?;
    Ok((observed, super::delivery::decode_resource_producer(producer)?))
}

/// Applies the existing fixed Root property comparison to readonly DATA.
///
/// # Errors
/// Refuses malformed properties, altered fixed roles, process or unit delivery.
pub fn decode_peer_properties(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_peer_properties_into(profile_path, pid, profile, values, unit, &mut None)
}

/// Applies the existing fixed Root property comparison to readonly DATA.
///
/// # Errors
/// Refuses malformed properties, altered fixed roles, process or unit delivery.
pub fn decode_peer_properties_into(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_peer_properties_for_delivery(profile_path, pid, profile, values, unit, canonical, false)
}

/// Decodes only the genuine selected Root's exact resource-delivery peer DATA.
///
/// The selected Root initial table has four fixed roles: PID1 image, measured
/// profile and the two original resource descriptors. This function requires
/// that exact existing resource pair; it never accepts an ordinary peer as a
/// fallback. Its caller still holds the real paid J/Root peer receiving owner.
///
/// # Errors
/// Refuses altered or missing selected resources, launch, unit or canonical DATA.
pub fn decode_selected_root_peer_properties_into(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_peer_properties_for_delivery(profile_path, pid, profile, values, unit, canonical, true)
}

/// Decodes the selected Root peer and the SAME actual PID1 producer epoch.
///
/// No producer or recipient comes from a decoded Hello. The owning receiver
/// retains this property flight and independently joins its kernel peer before
/// comparing these readonly fields to that Hello's untrusted correlation.
///
/// # Errors
/// Refuses a nonexact thirteen-value flight, zero producer or changed selected
/// delivery, launch, unit, canonical fragment or profile path.
pub fn decode_selected_root_peer_with_producer_into(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
) -> Result<(ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1> {
    if values.len() != SELECTED_RESOURCE_PEER_PROPERTIES_V1.len() {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let (common, remaining) = values.split_at(SERVICE_PROPERTIES.len());
    let (producer, launch) = remaining.split_first()
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let observed = decode_peer_property_parts(
        profile_path, pid, profile, common, launch, unit, canonical, true,
    )?;
    Ok((observed, super::delivery::decode_resource_producer(producer)?))
}

fn decode_peer_properties_for_delivery(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
    resource_delivery: bool,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let common = values
        .get(..SERVICE_PROPERTIES.len())
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let launch = values
        .get(SERVICE_PROPERTIES.len()..)
        .ok_or(NormalRootStartupErrorV1::Service)?;
    decode_peer_property_parts(
        profile_path, pid, profile, common, launch, unit, canonical, resource_delivery,
    )
}

fn decode_peer_property_parts(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
    common: &[OwnedValue],
    launch: &[OwnedValue],
    unit: &[OwnedValue],
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
    resource_delivery: bool,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    require_peer_launch(launch, pid, profile)?;
    let profile_path = profile_path
        .to_str()
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    super::delivery::immutable_observation_into(
        decode_with_resource_pair(common, unit, profile_path, resource_delivery)?, canonical,
    )
}

/// Applies the existing fixed Root property comparison to readonly DATA.
///
/// # Errors
/// Refuses malformed properties, altered fixed roles, process or unit delivery.
pub fn require_peer_launch(
    launch: &[OwnedValue],
    pid: u32,
    profile: &super::schema::NormalRootProfileV1,
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
        .chain(std::iter::once(profile.cache_signer_gid.to_string()))
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

/// Compares the fixed Root process credentials without granting peer authority.
///
/// # Errors
/// Rejects a different thread group, parent, UID or configured socket GID.
pub fn require_root_process_identity_data_v1(
    pid: std::num::NonZeroU32,
    gid: u32,
    info: &aos_sandbox_linux::pidfd::PidFdInfo,
) -> Result<(), NormalRootStartupErrorV1> {
    let credentials = info.credentials().ok_or(NormalRootStartupErrorV1::Service)?;
    if info.thread_group_id() != pid.get() || info.parent_pid() != 1
        || credentials.real_user_id() != 0 || credentials.effective_user_id() != 0
        || credentials.saved_user_id() != 0 || credentials.filesystem_user_id() != 0
        || credentials.real_group_id() != gid || credentials.effective_group_id() != gid
        || credentials.saved_group_id() != gid || credentials.filesystem_group_id() != gid
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}
