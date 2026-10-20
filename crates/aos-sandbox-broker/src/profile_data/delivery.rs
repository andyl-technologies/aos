//! Shares exact Controller delivery and fixed-unit comparison DATA.
//!
//! These pure shape predicates and canonical path observation never construct a
//! Controller original, profile or control loan. The actual receiving owner
//! retains the property flight, canonical Result and all independent posts.

use std::path::{Path, PathBuf};

use aos_systemd::{OwnedValue, Value};

use super::ControllerProfileErrorV1 as NormalRootStartupErrorV1;
use super::property_data as systemd_property_data;

/// Names the existing fixed controller unit comparison DATA.
#[doc(hidden)]
pub const CONTROLLER_UNIT: &str = "aos-sandboxd.service";

/// Names the existing fixed cgroup comparison DATA.
#[doc(hidden)]
pub const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";

/// Names the existing fixed context comparison DATA.
#[doc(hidden)]
pub const CONTEXT: &str = "system_u:system_r:aos_sandbox_controller_t";

/// Names the existing fixed profile name comparison DATA.
#[doc(hidden)]
pub const PROFILE_NAME: &str = "aos-normal-root-client-profile";

/// Names the existing fixed publisher name comparison DATA.
#[doc(hidden)]
pub const PUBLISHER_NAME: &str = "aos-sandboxd-publisher";

/// Names the existing fixed tpm image name comparison DATA.
#[doc(hidden)]
pub const TPM_IMAGE_NAME: &str = "aos-method46-pid1-image";

/// Names the existing fixed git source listener name comparison DATA.
#[doc(hidden)]
pub const GIT_SOURCE_LISTENER_NAME: &str = "aos-git-source-cut";

/// Names the existing fixed resource policy name comparison DATA.
#[doc(hidden)]
pub const RESOURCE_POLICY_NAME: &str = "aos-resource-image-policy-v1";

/// Names the existing fixed resource enrollment name comparison DATA.
#[doc(hidden)]
pub const RESOURCE_ENROLLMENT_NAME: &str = "aos-resource-pid1-enrollment-v1";

/// Names the existing fixed resource launch name comparison DATA.
#[doc(hidden)]
pub const RESOURCE_LAUNCH_NAME: &str = "aos-resource-controller-successor-v1";

/// Names the existing fixed nix profile name comparison DATA.
#[doc(hidden)]
pub const NIX_PROFILE_NAME: &str = "aos-nix-controller-profile";

/// Names the existing fixed nix pid1 name comparison DATA.
#[doc(hidden)]
pub const NIX_PID1_NAME: &str = "aos-nix-controller-pid1-image";

/// Names the exact original Controller service properties used by this recipe.
pub const SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames", "FileDescriptorStoreMax",
    "NFileDescriptorStore", "SELinuxContext", "CapabilityBoundingSet", "AmbientCapabilities",
    "NoNewPrivileges",
];

/// Names the exact unit property list used by the existing shared unit decoder.
pub const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];

/// Contains fixed-unit comparison DATA, never admission or a process handle.
#[derive(Debug, PartialEq)]
pub struct ServiceObservationV1 {
    /// Canonical fragment pathname observed from the actual PID1 flight.
    pub fragment: PathBuf,
    /// Exact nonzero invocation DATA observed from that same flight.
    pub invocation: [u8; 16],
}

/// Decodes the existing complete Controller delivery property DATA.
///
/// # Errors
/// Rejects altered unit/cgroup/subject/capability or descriptor-role shapes.
pub fn decode_delivery_with_resource_launch(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
    nix_profile: Option<&Path>,
    resource_delivery: bool,
    resource_launch: bool,
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
    ] = properties
    else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Structure(context) = &**context else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(files) = &**open_files else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(extras) = &**extras else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let expected_cgroup = format!("/{CGROUP}");
    if <&str>::try_from(cgroup).ok() != Some(expected_cgroup.as_str())
        || context.as_str() != CONTEXT
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || !valid_controller_launch_names(extras.inner(), resource_delivery, resource_launch)
        || extras.element_signature() != Value::from("").value_signature()
        || files.len() != 1 + usize::from(tpm_image) + 2 * usize::from(nix_profile.is_some())
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let mut found = [false; 4];
    for entry in files.inner() {
        let Value::Structure(entry) = entry else {
            return Err(NormalRootStartupErrorV1::Service);
        };
        let [Value::Str(path), Value::Str(name), Value::U64(1)] = entry.fields() else {
            return Err(NormalRootStartupErrorV1::Service);
        };
        let index = match (Path::new(path.as_str()), name.as_str()) {
            (path, PROFILE_NAME) if path == profile_path => 0,
            (path, TPM_IMAGE_NAME) if tpm_image && path == Path::new("/proc/1/exe") => 1,
            (path, NIX_PROFILE_NAME) if Some(path) == nix_profile => 2,
            (path, NIX_PID1_NAME)
                if nix_profile.is_some() && path == Path::new("/proc/1/exe") => 3,
            _ => return Err(NormalRootStartupErrorV1::Service),
        };
        if found[index] {
            return Err(NormalRootStartupErrorV1::Service);
        }
        found[index] = true;
    }
    if found != [true, tpm_image, nix_profile.is_some(), nix_profile.is_some()] {
        return Err(NormalRootStartupErrorV1::Service);
    }
    decode_unit(unit, CONTROLLER_UNIT)
}

/// Applies the existing exact valid backend names DATA predicate.
pub fn valid_backend_names(
    names: &[String],
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> bool {
    let nix_profile = names
        .iter()
        .filter(|name| name.as_str() == NIX_PROFILE_NAME)
        .count();
    let nix_pid1 = names
        .iter()
        .filter(|name| name.as_str() == NIX_PID1_NAME)
        .count();

    names.len() <= 9
        && names.iter().filter(|name| name.as_str() == RESOURCE_POLICY_NAME).count() <= 1
        && names.iter().filter(|name| name.as_str() == RESOURCE_POLICY_NAME).count()
            == names.iter().filter(|name| name.as_str() == RESOURCE_ENROLLMENT_NAME).count()
        && names.iter().filter(|name| name.as_str() == RESOURCE_LAUNCH_NAME).count() <= 1
        && (!names.iter().any(|name| name == RESOURCE_LAUNCH_NAME)
            || names.iter().any(|name| name == RESOURCE_POLICY_NAME))
        && nix_profile == usize::from(nix_enabled)
        && nix_profile == nix_pid1
        && names.iter().filter(|name| name.as_str() == GIT_SOURCE_LISTENER_NAME).count()
            == usize::from(git_source_cut)
        && names
            .iter()
            .filter(|name| name.as_str() == PUBLISHER_NAME)
            .count()
            == usize::from(publisher)
        && names
            .iter()
            .filter(|name| name.as_str() == TPM_IMAGE_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| name.as_str() == PROFILE_NAME)
            .count()
            <= 1
        && names.iter().all(|name| {
            matches!(
                name.as_str(),
                PUBLISHER_NAME | TPM_IMAGE_NAME | PROFILE_NAME
                    | NIX_PROFILE_NAME
                    | NIX_PID1_NAME
                    | GIT_SOURCE_LISTENER_NAME
                    | RESOURCE_POLICY_NAME | RESOURCE_ENROLLMENT_NAME | RESOURCE_LAUNCH_NAME
            )
        })
}

/// Applies the existing exact valid controller launch names DATA predicate.
pub fn valid_controller_launch_names(names: &[Value<'_>], selected: bool, launch: bool) -> bool {
    if !launch {
        return valid_resource_delivery_names(names, selected);
    }
    selected && matches!(names, [Value::Str(policy), Value::Str(enrollment), Value::Str(origin)]
        if policy.as_str() == RESOURCE_POLICY_NAME
            && enrollment.as_str() == RESOURCE_ENROLLMENT_NAME
            && origin.as_str() == RESOURCE_LAUNCH_NAME)
}

/// Applies the existing exact valid resource delivery names DATA predicate.
pub fn valid_resource_delivery_names(names: &[Value<'_>], selected: bool) -> bool {
    if !selected {
        return names.is_empty();
    }
    matches!(names, [Value::Str(policy), Value::Str(enrollment)]
        if policy.as_str() == RESOURCE_POLICY_NAME && enrollment.as_str() == RESOURCE_ENROLLMENT_NAME)
}

/// Applies the existing decode unit comparison recipe.
///
/// # Errors
/// Rejects malformed, unavailable or changed fixed-unit comparison DATA.
pub fn decode_unit(
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

/// Applies the existing immutable observation into comparison recipe.
///
/// # Errors
/// Rejects malformed, unavailable or changed fixed-unit comparison DATA.
pub fn immutable_observation_into(
    mut observed: ServiceObservationV1,
    canonical: &mut Option<std::io::Result<PathBuf>>,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    immutable_observation_in_place(&mut observed, canonical)?;
    Ok(observed)
}

/// Canonicalizes the actual observed fragment while retaining its Result.
///
/// This compares pathname DATA and grants no immutable-file or role admission.
///
/// # Errors
/// Refuses repeated observation, native canonicalization or a non-store path.
pub fn immutable_observation_in_place(
    observed: &mut ServiceObservationV1,
    canonical: &mut Option<std::io::Result<PathBuf>>,
) -> Result<(), NormalRootStartupErrorV1> {
    if canonical.is_some() { return Err(NormalRootStartupErrorV1::Service); }
    *canonical = Some(std::fs::canonicalize(&observed.fragment));
    observed.fragment = canonical.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(NormalRootStartupErrorV1::Service)?.clone();
    super::schema::require_store_path(
        observed
            .fragment
            .to_str()
            .ok_or(NormalRootStartupErrorV1::Service)?,
    )?;
    Ok(())
}

/// Applies the existing require same comparison recipe.
///
/// # Errors
/// Rejects malformed, unavailable or changed fixed-unit comparison DATA.
pub fn require_same(
    previous: &ServiceObservationV1,
    current: &ServiceObservationV1,
) -> Result<(), NormalRootStartupErrorV1> {
    if previous != current {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}


/// Decodes the same fixed nonzero resource-producer observation DATA.
///
/// # Errors
/// Refuses a non-byte array, wrong element signature or zero/foreign width.
pub fn decode_resource_producer(
    value: &OwnedValue,
) -> Result<[u8; 16], NormalRootStartupErrorV1> {
    let Value::Array(bytes) = &**value else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    if bytes.element_signature() != Value::from(0_u8).value_signature() {
        return Err(NormalRootStartupErrorV1::Service);
    }
    super::property_data::nonzero_invocation_bytes(bytes.inner())
        .ok_or(NormalRootStartupErrorV1::Service)
}
