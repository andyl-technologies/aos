//! Compares the selected initial jobs' retained PID1 confinement properties.
//!
//! Both native samples use the systemd 261.2 vtable's exact types. Writable
//! paths name only the selected purpose's fixed journal directory. These unit
//! comparisons do not replace live kernel, MAC, device or writer observations.

use aos_systemd_client::{OwnedValue, Value};

use super::Method46InitialStartupClosedV1;

pub(super) fn require_confinement(
    values: &[OwnedValue],
    unit: &str,
) -> Result<(), Method46InitialStartupClosedV1> {
    let [
        system,
        home,
        network,
        devices,
        tmp,
        tmp_ex,
        tunables,
        modules,
        logs,
        cgroups,
        cgroups_ex,
        clock,
        proc,
        proc_subset,
        namespaces,
        families,
        realtime,
        suid,
        personality,
        wx,
        core,
        core_soft,
        umask,
        dynamic_user,
        private_users,
        user,
        group,
        device_policy,
        device_allow,
        write_paths,
        root_directory,
        root_image,
    ] = values.get(18..).ok_or(Method46InitialStartupClosedV1)?
    else {
        return Err(Method46InitialStartupClosedV1);
    };
    let directory = match unit {
        "aos-sandbox-controller-floor-initialize.service" => {
            "/var/lib/aos/sandboxd/broker-session/storage"
        }
        "aos-sandbox-storage-floor-initialize.service" => {
            "/var/lib/aos/sandbox-storage/broker-session"
        }
        _ => return Err(Method46InitialStartupClosedV1),
    };

    for (value, expected) in [
        (system, "strict"),
        (home, "yes"),
        (tmp_ex, "yes"),
        (cgroups_ex, "yes"),
        (proc, "default"),
        (proc_subset, "all"),
        (user, "root"),
        (group, "root"),
        (device_policy, "closed"),
        (root_directory, ""),
        (root_image, ""),
    ] {
        if <&str>::try_from(value).ok() != Some(expected) {
            return Err(Method46InitialStartupClosedV1);
        }
    }
    for value in [
        network,
        tmp,
        tunables,
        modules,
        logs,
        cgroups,
        clock,
        realtime,
        suid,
        personality,
        wx,
    ] {
        if bool::try_from(value).ok() != Some(true) {
            return Err(Method46InitialStartupClosedV1);
        }
    }
    // The fixed resource-manager device remains visible under a closed device
    // policy. User namespaces or dynamic identities cannot change journal DAC.
    for value in [devices, dynamic_user, private_users] {
        if bool::try_from(value).ok() != Some(false) {
            return Err(Method46InitialStartupClosedV1);
        }
    }
    if u64::try_from(namespaces).ok() != Some(0)
        || u64::try_from(core).ok() != Some(0)
        || u64::try_from(core_soft).ok() != Some(0)
        || u32::try_from(umask).ok() != Some(0o077)
    {
        return Err(Method46InitialStartupClosedV1);
    }

    if families.value_signature().to_string() != "(bas)" {
        return Err(Method46InitialStartupClosedV1);
    }
    let Value::Structure(families) = &**families else {
        return Err(Method46InitialStartupClosedV1);
    };
    let [Value::Bool(true), Value::Array(families)] = families.fields() else {
        return Err(Method46InitialStartupClosedV1);
    };
    if !matches!(families.inner(), [Value::Str(family)] if family.as_str() == "AF_UNIX") {
        return Err(Method46InitialStartupClosedV1);
    }

    if device_allow.value_signature().to_string() != "a(ss)" {
        return Err(Method46InitialStartupClosedV1);
    }
    let Value::Array(devices) = &**device_allow else {
        return Err(Method46InitialStartupClosedV1);
    };
    let [Value::Structure(device)] = devices.inner() else {
        return Err(Method46InitialStartupClosedV1);
    };
    if !matches!(device.fields(), [Value::Str(path), Value::Str(access)]
        if path.as_str() == "/dev/tpmrm0" && access.as_str() == "rw")
    {
        return Err(Method46InitialStartupClosedV1);
    }
    if !matches!(&**write_paths, Value::Array(paths)
        if matches!(paths.inner(), [Value::Str(path)] if path.as_str() == directory))
    {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_properties() -> Vec<OwnedValue> {
    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }
    vec![
        value("strict"),
        value("yes"),
        true.into(),
        false.into(),
        true.into(),
        value("yes"),
        true.into(),
        true.into(),
        true.into(),
        true.into(),
        value("yes"),
        true.into(),
        value("default"),
        value("all"),
        0_u64.into(),
        value((true, vec!["AF_UNIX"])),
        true.into(),
        true.into(),
        true.into(),
        true.into(),
        0_u64.into(),
        0_u64.into(),
        0o077_u32.into(),
        false.into(),
        false.into(),
        value("root"),
        value("root"),
        value("closed"),
        value(vec![("/dev/tpmrm0", "rw")]),
        value(vec!["/var/lib/aos/sandboxd/broker-session/storage"]),
        value(""),
        value(""),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER: &str = "aos-sandbox-controller-floor-initialize.service";
    const STORAGE: &str = "aos-sandbox-storage-floor-initialize.service";

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn properties() -> Vec<OwnedValue> {
        let mut values: Vec<OwnedValue> = (0..18).map(|_| false.into()).collect();
        values.extend(test_properties());
        values
    }

    #[test]
    fn initial_confinement_binds_the_writable_directory_to_the_fixed_purpose() {
        let mut values = properties();
        assert!(require_confinement(&values, CONTROLLER).is_ok());
        assert!(require_confinement(&values, STORAGE).is_err());
        assert!(require_confinement(&values, "foreign.service").is_err());

        values[18 + 29] = value(vec!["/var/lib/aos/sandbox-storage/broker-session"]);
        assert!(require_confinement(&values, STORAGE).is_ok());
        assert!(require_confinement(&values, CONTROLLER).is_err());
    }

    #[test]
    fn initial_confinement_refuses_relaxed_namespaces_devices_and_write_paths() {
        for (index, changed) in [
            (0, value("read-only")),
            (3, true.into()),
            (5, value("disconnected")),
            (10, value("private")),
            (12, value("invisible")),
            (13, value("pid")),
            (14, u64::MAX.into()),
            (15, value((false, vec!["AF_UNIX"]))),
            (15, value((true, vec!["AF_UNIX", "AF_INET"]))),
            (22, 0o022_u32.into()),
            (23, true.into()),
            (24, true.into()),
            (25, value("nobody")),
            (27, value("auto")),
            (28, value(vec![("/dev/tpmrm0", "rwm")])),
            (28, value(vec![("/dev/tpmrm0", "rw"), ("/dev/mem", "rw")])),
            (
                29,
                value(vec!["/var/lib/aos/sandboxd/broker-session/storage", "/tmp"]),
            ),
            (30, value("/other")),
            (31, value("/image")),
        ] {
            let mut values = properties();
            values[18 + index] = changed;
            assert!(require_confinement(&values, CONTROLLER).is_err(), "{index}");
        }
    }

    #[test]
    fn initial_confinement_requires_the_full_native_property_types() {
        for index in 18..super::super::service::PROPERTIES.len() {
            let mut values = properties();
            values[index] = 1_u8.into();
            assert!(require_confinement(&values, CONTROLLER).is_err(), "{index}");
        }
        let mut values = properties();
        values.pop();
        assert!(require_confinement(&values, CONTROLLER).is_err());
    }
}
