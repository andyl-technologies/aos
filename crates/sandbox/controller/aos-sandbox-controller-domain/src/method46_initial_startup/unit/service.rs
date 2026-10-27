//! Compares retained PID1 service properties for the fixed initial jobs.
//!
//! Both native samples retain their own values in the enclosing unit owner.
//! These predicates borrow those values without creating funding, credential,
//! writer or TPM authority. Remaining unit hardening and credential delivery
//! require separate admission before either manual producer can be installed.

use aos_systemd_client::{OwnedValue, Value};

use super::Method46InitialStartupClosedV1;
use crate::systemd_property_data::{explicit_context, single_exec_start};

pub(super) const PROPERTIES: &[&str] = &[
    "ControlGroup",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "SecureBits",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExitType",
    "KillMode",
    "TimeoutStopUSec",
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
    "ImportCredentialEx",
    "ProtectSystem",
    "ProtectHome",
    "PrivateNetwork",
    "PrivateDevices",
    "PrivateTmp",
    "PrivateTmpEx",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectControlGroupsEx",
    "ProtectClock",
    "ProtectProc",
    "ProcSubset",
    "RestrictNamespaces",
    "RestrictAddressFamilies",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "LimitCORE",
    "LimitCORESoft",
    "UMask",
    "DynamicUser",
    "PrivateUsers",
    "User",
    "Group",
    "DevicePolicy",
    "DeviceAllow",
    "ReadWritePaths",
    "RootDirectory",
    "RootImage",
];

pub(super) fn require_service(
    values: &[OwnedValue],
    unit: &str,
    context: &str,
    executable: &str,
    pid: u32,
) -> Result<(), Method46InitialStartupClosedV1> {
    if values.len() != PROPERTIES.len() {
        return Err(Method46InitialStartupClosedV1);
    }
    let [
        cgroup,
        subject,
        bounding,
        ambient,
        nnp,
        securebits,
        start,
        pre,
        post,
        exit_type,
        kill_mode,
        timeout,
        ..,
    ] = values
    else {
        return Err(Method46InitialStartupClosedV1);
    };

    // The two fixed jobs live in F. DAC override and chown support the existing
    // owners' protected files; ambient capabilities and setuid fixups stay off.
    if <&str>::try_from(cgroup)
        .ok()
        .and_then(|path| path.strip_prefix("/aoscomponents.slice/"))
        != Some(unit)
        || explicit_context(subject) != Some(context)
        || u64::try_from(bounding).ok() != Some(3)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || i32::try_from(securebits).ok() != Some(12)
        || <&str>::try_from(exit_type).ok() != Some("cgroup")
        || <&str>::try_from(kill_mode).ok() != Some("control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
    {
        return Err(Method46InitialStartupClosedV1);
    }

    // Initialization and recovery select from the actual durable state, never
    // an alternate argv mode or a caller-supplied journal/profile pathname.
    let command = single_exec_start(start).ok_or(Method46InitialStartupClosedV1)?;
    if command.path != executable
        || command.pid != pid
        || !matches!(command.argv, [Value::Str(argument)] if argument.as_str() == executable)
    {
        return Err(Method46InitialStartupClosedV1);
    }

    let Value::Array(commands) = &**start else {
        return Err(Method46InitialStartupClosedV1);
    };
    for hooks in [pre, post] {
        if !matches!(&**hooks, Value::Array(array)
            if array.is_empty() && array.element_signature() == commands.element_signature())
        {
            return Err(Method46InitialStartupClosedV1);
        }
    }

    super::confinement::require_confinement(values, unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: &str = "aos-sandbox-controller-floor-initialize.service";
    const CONTEXT: &str = "system_u:system_r:aos_method46_controller_initial_t";
    const EXE: &str = "/nix/store/immutable/bin/aos-sandbox-controller-floor-initialize";
    type Command = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn command() -> Command {
        (EXE.into(), vec![EXE.into()], false, 1, 2, 3, 4, 7, 0, 0)
    }

    fn properties() -> Vec<OwnedValue> {
        let mut values = vec![
            value(format!("/aoscomponents.slice/{UNIT}")),
            value((false, CONTEXT)),
            3_u64.into(),
            0_u64.into(),
            true.into(),
            12_i32.into(),
            value(vec![command()]),
            value(Vec::<Command>::new()),
            value(Vec::<Command>::new()),
            value("cgroup"),
            value("control-group"),
            u64::MAX.into(),
            value(Vec::<(String, String)>::new()),
            value(Vec::<(String, String)>::new()),
            value(Vec::<(String, Vec<u8>)>::new()),
            value(Vec::<(String, Vec<u8>)>::new()),
            value(Vec::<String>::new()),
            value(Vec::<(String, String)>::new()),
        ];
        values.extend(super::super::confinement::test_properties());
        values
    }

    #[test]
    fn initial_service_comparison_joins_the_selected_purpose_and_current_pid() {
        let values = properties();
        assert!(require_service(&values, UNIT, CONTEXT, EXE, 7).is_ok());

        for (unit, context, executable, pid) in [
            (
                "aos-sandbox-storage-floor-initialize.service",
                CONTEXT,
                EXE,
                7,
            ),
            (UNIT, "system_u:system_r:foreign_t", EXE, 7),
            (UNIT, CONTEXT, "/nix/store/other/bin/program", 7),
            (UNIT, CONTEXT, EXE, 8),
        ] {
            assert!(require_service(&values, unit, context, executable, pid).is_err());
        }
    }

    #[test]
    fn initial_service_comparison_rejects_changed_controls_and_command_shapes() {
        let changes = vec![
            (0, value(format!("/system.slice/{UNIT}"))),
            (1, value((true, CONTEXT))),
            (2, 7_u64.into()),
            (3, 1_u64.into()),
            (4, false.into()),
            (5, 0_i32.into()),
            (6, value(Vec::<Command>::new())),
            (7, value(vec![command()])),
            (7, value(Vec::<String>::new())),
            (8, value(vec![command()])),
            (8, value(Vec::<String>::new())),
            (9, value("main")),
            (10, value("process")),
            (11, 1_u64.into()),
        ];
        for (index, changed) in changes {
            let mut values = properties();
            values[index] = changed;
            assert!(
                require_service(&values, UNIT, CONTEXT, EXE, 7).is_err(),
                "{index}"
            );
        }

        let changed_commands: [Command; 2] = [
            (
                EXE.into(),
                vec![EXE.into(), "recover".into()],
                false,
                1,
                2,
                3,
                4,
                7,
                0,
                0,
            ),
            (EXE.into(), vec![EXE.into()], true, 1, 2, 3, 4, 7, 0, 0),
        ];
        for altered in changed_commands {
            let mut values = properties();
            values[6] = value(vec![altered]);
            assert!(require_service(&values, UNIT, CONTEXT, EXE, 7).is_err());
        }
    }

    #[test]
    fn initial_service_comparison_requires_the_complete_typed_roster() {
        let mut values = properties();
        values.pop();
        assert!(require_service(&values, UNIT, CONTEXT, EXE, 7).is_err());

        let mut values = properties();
        values.push(false.into());
        assert!(require_service(&values, UNIT, CONTEXT, EXE, 7).is_err());

        for index in 0..12 {
            let mut values = properties();
            values[index] = 1_u8.into();
            assert!(
                require_service(&values, UNIT, CONTEXT, EXE, 7).is_err(),
                "{index}"
            );
        }
    }
}
