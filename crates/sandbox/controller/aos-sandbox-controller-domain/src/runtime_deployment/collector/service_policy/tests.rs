//! UNRUN normalized-property DATA; no unit or collector owner is fabricated.

use super::*;

type ExecCommandV1 = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

fn value(value: impl Into<Value<'static>>) -> OwnedValue {
    OwnedValue::try_from(value.into()).expect("inert property value")
}

fn properties(profile: &str, executable: &str) -> (Vec<OwnedValue>, Vec<OwnedValue>) {
    let service = vec![
        value("cgroup"),
        value("control-group"),
        value(u64::MAX),
        value(CONTROL_GROUP),
        value(vec![
            ("/proc/1/exe".to_owned(), PID1_FD_NAME.to_owned(), 1_u64),
            (profile.to_owned(), PROFILE_FD_NAME.to_owned(), 1_u64),
        ]),
        value(Vec::<String>::new()),
        value(0_u32),
        value(0_u32),
        value((false, CONTEXT)),
        value(CAPABILITIES),
        value(0_u64),
        value(true),
        value("root"),
        value("root"),
        value(0o077_u32),
        value(vec![(
            executable.to_owned(),
            vec![executable.to_owned()],
            false,
            0_u64,
            0_u64,
            0_u64,
            0_u64,
            std::process::id(),
            0_i32,
            0_i32,
        )]),
        value(Vec::<ExecCommandV1>::new()),
        value(Vec::<ExecCommandV1>::new()),
    ];
    let unit = vec![
        value(format!("/nix/store/00000000000000000000000000000000-unit/{UNIT}")),
        value(Vec::<String>::new()),
        value(false),
        value(vec![1_u8; 16]),
        value(vec![SOCKET_UNIT.to_owned()]),
    ];

    (service, unit)
}

#[test]
fn unrun_collector_getters_require_exact_caps_mac_tuple_and_crash_custody() {
    let profile = "/nix/store/00000000000000000000000000000000-profile/profile.json";
    let executable = "/nix/store/00000000000000000000000000000000-collector/bin/aos-sandbox-installed-filter-collector";
    let (service, unit) = properties(profile, executable);
    assert!(decode(&service, &unit, profile, executable).is_ok());

    for (slot, substitute) in [
        (0, value("main")),
        (1, value("process")),
        (2, value(30_000_000_u64)),
        (3, value("/system.slice/aos-sandbox-installed-filter-collector.service")),
        (5, value(vec!["foreign".to_owned()])),
        (6, value(1_u32)),
        (7, value(1_u32)),
        (8, value(CONTEXT)),
        (8, value((true, CONTEXT))),
        (8, value((false, "system_u:system_r:aos_runtime_deployment_publisher_t:s0"))),
        (9, value(0_u64)),
        (9, value(CAPABILITIES | 1)),
        (10, value(CAPABILITIES)),
        (11, value(false)),
        (12, value("nobody")),
        (13, value("nobody")),
        (14, value(0_u32)),
        (16, value(Vec::<String>::new())),
        (17, value(Vec::<String>::new())),
    ] {
        let (mut service, unit) = properties(profile, executable);
        service[slot] = substitute;
        assert!(decode(&service, &unit, profile, executable).is_err(), "slot {slot}");
    }

    for (slot, substitute) in [
        (1, value(vec!["/etc/systemd/system/foreign.conf".to_owned()])),
        (2, value(true)),
        (3, value(vec![0_u8; 16])),
        (3, value(vec![1_u8; 15])),
        (4, value(vec!["foreign.socket".to_owned()])),
    ] {
        let (service, mut unit) = properties(profile, executable);
        unit[slot] = substitute;
        assert!(decode(&service, &unit, profile, executable).is_err(), "unit slot {slot}");
    }
}

#[test]
fn unrun_collector_open_files_require_original_role_flags_and_unique_entries() {
    let profile = "/nix/store/00000000000000000000000000000000-profile/profile.json";
    let extra = value(Vec::<String>::new());
    let entries = vec![
        ("/proc/1/exe".to_owned(), PID1_FD_NAME.to_owned(), 1_u64),
        (profile.to_owned(), PROFILE_FD_NAME.to_owned(), 1_u64),
    ];
    assert!(exact_open_files(&value(entries.clone()), &extra, profile));

    let mut duplicate = entries.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(!exact_open_files(&value(duplicate), &extra, profile));

    let mut wrong_flags = entries.clone();
    wrong_flags[0].2 = 3;
    assert!(!exact_open_files(&value(wrong_flags), &extra, profile));

    let mut wrong_role = entries.clone();
    wrong_role[1].1 = "aos-runtime-deployment-startup-profile".to_owned();
    assert!(!exact_open_files(&value(wrong_role), &extra, profile));
    assert!(!exact_open_files(&value(entries), &value(vec!["root".to_owned()]), profile));
}

#[test]
fn unrun_collector_exec_readback_requires_fixed_no_argument_original_process() {
    let executable = "/nix/store/00000000000000000000000000000000-collector/bin/aos-sandbox-installed-filter-collector";
    let command = (
        executable.to_owned(),
        vec![executable.to_owned()],
        false,
        0_u64,
        0_u64,
        0_u64,
        0_u64,
        std::process::id(),
        0_i32,
        0_i32,
    );
    assert!(exact_exec(&value(vec![command.clone()]), executable));

    let mut extra_argument = command.clone();
    extra_argument.1.push("--pid=1".to_owned());
    assert!(!exact_exec(&value(vec![extra_argument]), executable));

    let mut wrong_process = command.clone();
    wrong_process.7 = 0;
    assert!(!exact_exec(&value(vec![wrong_process]), executable));

    let mut optional = command.clone();
    optional.2 = true;
    assert!(!exact_exec(&value(vec![optional]), executable));
    assert!(!exact_exec(&value(vec![command.clone(), command]), executable));
}

#[test]
fn unrun_collector_unit_digest_normalizes_only_one_exact_self_reference() {
    let profile = "/nix/store/00000000000000000000000000000000-profile/profile.json";
    let prefix = "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE\n";
    let suffix = "NoNewPrivileges=yes\nExitType=cgroup\nKillMode=control-group\n";
    let actual = format!("{prefix}OpenFile={profile}:{PROFILE_FD_NAME}:read-only\n{suffix}");
    let expected = format!("{prefix}OpenFile={PROFILE_PLACEHOLDER}:{PROFILE_FD_NAME}:read-only\n{suffix}");
    assert_eq!(normalized_unit(actual.as_bytes(), profile).unwrap(), expected.as_bytes());

    for invalid in [
        actual.repeat(2),
        actual.replace("read-only", "graceful"),
        actual.replace(PROFILE_FD_NAME, "aos-runtime-deployment-startup-profile"),
        actual.replace(profile, "/nix/store/11111111111111111111111111111111-profile/profile.json"),
    ] {
        assert!(normalized_unit(invalid.as_bytes(), profile).is_err());
    }
    let changed = actual.replace("ExitType=cgroup", "ExitType=main");
    assert_ne!(normalized_unit(changed.as_bytes(), profile).unwrap(), expected.as_bytes());
    assert!(normalized_unit(&[], profile).is_err());
    assert!(normalized_unit(&vec![b' '; 64 * 1024 + 1], profile).is_err());
}
