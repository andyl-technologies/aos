//! Compares the fixed successful publisher's already-retained property DATA.

use aos_sandbox_broker::profile_data::runtime_deployment::{
    BootPreparationPublisherProfileDataV1, PUBLISHER_CONTEXT_V1, PUBLISHER_UNIT_V1,
};
use aos_sandbox_broker::profile_data::{property_data, schema::require_store_path};
use aos_systemd::{OwnedValue, ServicePropertiesReadOriginalV2, Value};

use super::BootPreparationPolicyErrorV1 as E;

pub(super) const SERVICE_V1: &[&str] = &[
    "Type",
    "RemainAfterExit",
    "ExecMainCode",
    "ExecMainStatus",
    "Result",
    "ExitType",
    "KillMode",
    "TimeoutStopUSec",
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "User",
    "Group",
    "UMask",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecCondition",
    "Restart",
];
pub(super) const UNIT_V1: &[&str] = &["FragmentPath", "DropInPaths", "Transient"];

// Fourteen existing unique-PID1 startup/oneshot bookend calls plus the exact
// fixed service/unit roster. Root owns the SAME manager's raw/typed quote.
pub(super) const CALLS_PER_SAMPLE_V1: usize = 14 + SERVICE_V1.len() + UNIT_V1.len();

pub(super) fn require_host_dependencies_v1(
    host: &ServicePropertiesReadOriginalV2,
) -> Result<(), E> {
    let Some([requires, after]) = host.unit_values_v2() else {
        return Err(E("actual Host Requires/After archive is absent"));
    };
    for property in [requires, after] {
        let Value::Array(names) = &**property else {
            return Err(E("Host dependency property differs"));
        };
        if !names
            .inner()
            .iter()
            .any(|name| matches!(name, Value::Str(name) if name.as_str() == PUBLISHER_UNIT_V1))
        {
            return Err(E(
                "Host does not require and follow the fixed boot publisher",
            ));
        }
    }
    Ok(())
}

/// Borrows only paths from the full same-invocation native property archive.
pub(super) fn require_publisher_v1<'a>(
    original: &'a ServicePropertiesReadOriginalV2,
    profile: &BootPreparationPublisherProfileDataV1,
) -> Result<(&'a str, &'a str), E> {
    let service = original
        .service_values_v2()
        .ok_or(E("publisher service archive absent"))?;
    let unit = original
        .unit_values_v2()
        .ok_or(E("publisher unit archive absent"))?;
    let [
        _,
        _,
        _,
        _,
        _,
        exit_type,
        kill,
        timeout,
        cgroup,
        open,
        extras,
        maximum,
        stored,
        context,
        bounding,
        ambient,
        nnp,
        user,
        group,
        umask,
        start,
        pre,
        post,
        reload,
        condition,
        restart,
    ] = service
    else {
        return Err(E("publisher fixed service roster differs"));
    };
    let [fragment, drop_ins, transient] = unit else {
        return Err(E("publisher unit roster differs"));
    };
    let text = |value: &'a OwnedValue| <&str>::try_from(value).ok();
    if text(exit_type) != Some("main")
        || text(kill) != Some("control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
        || text(cgroup)
            != Some("/aos.slice/aos-control.slice/aos-sandbox-runtime-publisher.service")
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || property_data::explicit_context(context) != Some(PUBLISHER_CONTEXT_V1)
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || text(user) != Some("root")
        || text(group) != Some("root")
        || u32::try_from(umask).ok() != Some(0o077)
        || text(restart) != Some("no")
        || bool::try_from(transient).ok() != Some(false)
        || !empty_array(drop_ins)
        || !empty_array(pre)
        || !empty_array(post)
        || !empty_array(reload)
        || !empty_array(condition)
    {
        return Err(E(
            "publisher loaded policy differs from its fixed normal contract",
        ));
    }
    let command =
        property_data::single_exec_start(start).ok_or(E("publisher command shape differs"))?;
    let [Value::Str(argv0), Value::Str(mode)] = command.argv else {
        return Err(E("publisher does not execute exactly the boot mode"));
    };
    if command.path != profile.publisher.executable.path
        || argv0.as_str() != profile.publisher.executable.path
        || mode.as_str() != "--boot-preparation-v1"
        || command.pid == 0
    {
        return Err(E(
            "publisher command differs from the signed immutable profile",
        ));
    }
    let Value::Array(entries) = &**open else {
        return Err(E("publisher OpenFile shape differs"));
    };
    let mut profile_path = None;
    for value in entries.inner() {
        if let Value::Structure(value) = value {
            if let [Value::Str(path), Value::Str(name), Value::U64(1)] = value.fields() {
                if name.as_str() == "aos-runtime-deployment-startup-profile" {
                    if profile_path.replace(path.as_str()).is_some() {
                        return Err(E("publisher profile role repeated"));
                    }
                }
            }
        }
    }
    let profile_path = profile_path.ok_or(E("publisher original profile role absent"))?;
    require_store_path(profile_path)
        .map_err(|_| E("publisher original profile path is not immutable"))?;
    if !property_data::exact_readonly_open_file_pair(
        open,
        extras,
        [
            (profile_path, "aos-runtime-deployment-startup-profile"),
            (
                &profile.publisher.pid1.path,
                "aos-runtime-deployment-pid1-image",
            ),
        ],
    ) {
        return Err(E("publisher original image/profile roles differ"));
    }
    let fragment = text(fragment).ok_or(E("publisher fragment path malformed"))?;
    require_store_path(fragment)
        .map_err(|_| E("publisher fragment is not an immutable store path"))?;
    if !fragment.ends_with("/aos-sandbox-runtime-publisher.service") {
        return Err(E("publisher fragment has a foreign fixed unit name"));
    }
    Ok((fragment, profile_path))
}

fn empty_array(value: &OwnedValue) -> bool {
    matches!(&**value, Value::Array(values) if values.is_empty())
}
