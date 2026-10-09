//! Inert shared profile/property cuts and actual wrong-FD measurement regressions.
//!
//! These tests never create a production startup owner, authenticated PID1
//! launch, client proof or protected image. Installed positive startup is a
//! separate qualification obligation.

use aos_systemd::{OwnedValue, Value};
use serde_json::json;

use super::*;

const ROOT: &str = "/nix/store/00000000000000000000000000000000-aos-sandboxd-0.1.0";
const PROFILE: &str =
    "/nix/store/11111111111111111111111111111111-aos-normal-root-startup-profile-1/profile.json";

fn value(value: impl Into<Value<'static>>) -> OwnedValue {
    OwnedValue::try_from(value.into()).unwrap()
}

fn inert_profile() -> serde_json::Value {
    let pin = |path: String| json!({"path": path, "sha256": ([1_u8; 32].as_slice())});
    let executable = pin(format!("{ROOT}/bin/aos-sandbox-policy-authorityd"));
    let loader = pin(format!("{ROOT}/lib/ld.so"));
    json!({
        "format": "AOS_NORMAL_ROOT_STARTUP_1", "unit": UNIT, "context": CONTEXT,
        "identities": [811, 811, 0, 0], "executable": executable, "loader": loader,
        "pid1": pin(format!("{ROOT}/lib/systemd/systemd")),
        "runtime_files": [executable, loader], "closure_roots": [ROOT],
        "canonical_policy": pin("/nix/store/22222222222222222222222222222222-aos-selinux-kernel-policy-readback-1/policy.33".into()),
        "source_policy": pin(PROFILE.replace("profile.json", "source-policy.33")),
        "effective_matrix": pin(PROFILE.replace("profile.json", "effective-policy.tsv")),
        "unit_sha256": ([2_u8; 32].as_slice()),
    })
}

fn properties() -> (Vec<OwnedValue>, Vec<OwnedValue>) {
    let service = vec![
        value(format!("/system.slice/{UNIT}")),
        value(vec![
            ("/proc/1/exe".to_owned(), PID1_FD_NAME.to_owned(), 1_u64),
            (PROFILE.to_owned(), PROFILE_FD_NAME.to_owned(), 1_u64),
        ]),
        value(Vec::<String>::new()),
        OwnedValue::from(0_u32),
        OwnedValue::from(0_u32),
        value((false, CONTEXT)),
        OwnedValue::from(0_u64),
        OwnedValue::from(0_u64),
        OwnedValue::from(true),
    ];
    let unit = vec![
        value(format!("{ROOT}/{UNIT}")),
        value(Vec::<String>::new()),
        OwnedValue::from(false),
        value(vec![1_u8; 16]),
    ];
    (service, unit)
}

#[test]
fn normal_root_profile_rejects_legacy_tpm_or_duplicate_launch_roles() {
    assert!(valid_roles(&[]));
    assert!(valid_roles(&[PROFILE_FD_NAME.into(), PID1_FD_NAME.into()]));
    for names in [
        vec![PID1_FD_NAME.into()],
        vec![PROFILE_FD_NAME.into(); 2],
        vec!["aos-method46-pid1-image".into(), PROFILE_FD_NAME.into()],
        vec![
            PID1_FD_NAME.into(),
            PROFILE_FD_NAME.into(),
            "listener".into(),
        ],
    ] {
        assert!(!valid_roles(&names));
    }
}

#[test]
fn normal_root_profile_decoder_rejects_identity_image_and_closure_substitutions() {
    let bytes = serde_json::to_vec(&inert_profile()).unwrap();
    assert!(NormalRootProfileV1::decode(&bytes).is_ok());
    for (field, replacement) in [
        ("format", json!("AOS_METHOD46_TPM_PROFILE")),
        ("unit", json!("recovery.service")),
        ("context", json!("system_u:system_r:init_t:s0")),
        ("identities", json!([0, 811, 0, 0])),
        ("unit_sha256", json!([0_u8; 32].as_slice())),
        ("runtime_files", json!([])),
        ("closure_roots", json!(["/nix/store/foreign", ROOT])),
    ] {
        let mut profile = inert_profile();
        profile[field] = replacement;
        assert!(
            NormalRootProfileV1::decode(&serde_json::to_vec(&profile).unwrap()).is_err(),
            "{field}"
        );
    }
    for field in [
        "executable",
        "loader",
        "pid1",
        "canonical_policy",
        "effective_matrix",
    ] {
        let mut profile = inert_profile();
        profile[field]["path"] = json!(format!("{ROOT}/../foreign"));
        assert!(NormalRootProfileV1::decode(&serde_json::to_vec(&profile).unwrap()).is_err());
    }
    let mut profile = inert_profile();
    profile["runtime_files"][0]["sha256"] = json!([3_u8; 32].as_slice());
    assert!(NormalRootProfileV1::decode(&serde_json::to_vec(&profile).unwrap()).is_err());
}

#[test]
fn normal_root_profile_decoder_has_exact_bounds_and_fields() {
    let mut profile = inert_profile();
    profile["is_authority"] = json!(true);
    assert!(NormalRootProfileV1::decode(&serde_json::to_vec(&profile).unwrap()).is_err());
    assert!(NormalRootProfileV1::decode(&vec![b' '; profile::MAXIMUM_PROFILE_BYTES + 1]).is_err());
    let mut profile = inert_profile();
    profile["runtime_files"] = serde_json::Value::Array(vec![
        profile["executable"].clone();
        profile::MAXIMUM_RUNTIME_FILES + 1
    ]);
    assert!(NormalRootProfileV1::decode(&serde_json::to_vec(&profile).unwrap()).is_err());
    let bytes = serde_json::to_vec(&inert_profile()).unwrap();
    let duplicate = [
        b"{\"format\":\"AOS_NORMAL_ROOT_STARTUP_1\",".as_slice(),
        &bytes[1..],
    ]
    .concat();
    assert!(NormalRootProfileV1::decode(&duplicate).is_err());
}

#[test]
fn normal_root_unit_normalization_excludes_only_one_exact_self_reference() {
    let unit = format!(
        "[Service]\nExecStart={ROOT}/bin/aos-sandbox-policy-authorityd 811 811 0 0\nOpenFile={PROFILE}:aos-normal-root-profile:read-only\nNoNewPrivileges=true\n"
    );
    let normalized = profile::normalized_unit(unit.as_bytes(), PROFILE).unwrap();
    assert!(
        std::str::from_utf8(&normalized)
            .unwrap()
            .contains(profile::PROFILE_PLACEHOLDER)
    );
    let expected: [u8; 32] = Sha256::digest(&normalized).into();
    for changed in [
        unit.replace("811 811", "812 811"),
        unit.replace("true", "false"),
        format!("{unit}Environment=LD_PRELOAD=/tmp/inject.so\n"),
    ] {
        let actual: [u8; 32] =
            Sha256::digest(profile::normalized_unit(changed.as_bytes(), PROFILE).unwrap()).into();
        assert_ne!(actual, expected);
    }
    for bad in [
        unit.replace(":read-only", ":graceful"),
        format!("{unit}OpenFile={PROFILE}:aos-normal-root-profile:read-only\n"),
        unit.replace("OpenFile=", "# OpenFile="),
    ] {
        assert!(profile::normalized_unit(bad.as_bytes(), PROFILE).is_err());
    }
}

#[test]
fn normal_root_service_claims_reject_wrong_unit_context_fd_or_capabilities() {
    let (service, unit) = properties();
    assert!(service::decode(&service, &unit, PROFILE).is_ok());
    for (index, replacement) in [
        (0, value("/system.slice/recovery.service")),
        (
            1,
            value(vec![("/proc/1/exe", "aos-method46-pid1-image", 1_u64)]),
        ),
        (
            1,
            value(vec![
                ("/proc/1/exe".to_owned(), PID1_FD_NAME.to_owned(), 9_u64),
                (PROFILE.to_owned(), PROFILE_FD_NAME.to_owned(), 1_u64),
            ]),
        ),
        (2, value(vec!["other-fd".to_owned()])),
        (3, OwnedValue::from(1_u32)),
        (4, OwnedValue::from(1_u32)),
        (5, value((false, "system_u:system_r:init_t:s0"))),
        (5, value((true, CONTEXT))),
        (6, OwnedValue::from(1_u64)),
        (7, OwnedValue::from(1_u64)),
        (8, OwnedValue::from(false)),
    ] {
        let (mut service, unit) = properties();
        service[index] = replacement;
        assert!(
            service::decode(&service, &unit, PROFILE).is_err(),
            "property {index}"
        );
    }
    for (index, replacement) in [
        (0, value(format!("{ROOT}/recovery.service"))),
        (1, value(vec!["override.conf".to_owned()])),
        (2, OwnedValue::from(true)),
        (3, value(vec![0_u8; 16])),
        (3, value(vec![1_u8; 15])),
    ] {
        let (service, mut unit) = properties();
        unit[index] = replacement;
        assert!(service::decode(&service, &unit, PROFILE).is_err());
    }
}

#[test]
fn normal_root_service_currentness_rejects_changed_nonzero_invocation() {
    let (service, unit) = properties();
    let original = service::decode(&service, &unit, PROFILE).unwrap();
    let (service, mut unit) = properties();
    unit[3] = value(vec![2_u8; 16]);
    let changed = service::decode(&service, &unit, PROFILE).unwrap();
    assert!(service::require_same(&original, &original).is_ok());
    assert!(service::require_same(&original, &changed).is_err());
}

#[test]
fn normal_root_profile_and_service_reject_mls_suffixes() {
    assert_eq!(CONTEXT, "system_u:system_r:aos_sandbox_policy_authority_t");

    for suffix in [":s0", ":s0:c0", ":s0-s0:c0.c1"] {
        let context = format!("{CONTEXT}{suffix}");
        let mut profile = inert_profile();
        profile["context"] = json!(context.as_str());
        assert!(NormalRootProfileV1::decode(&serde_json::to_vec(&profile).unwrap()).is_err());

        let (mut properties, unit) = properties();
        properties[5] = value((false, context));
        assert!(service::decode(&properties, &unit, PROFILE).is_err());
    }
}

#[test]
fn normal_root_confinement_status_requires_exact_empty_capability_sets() {
    let status = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    assert!(require_status(status.as_bytes()).is_ok());
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(
            require_status(
                status
                    .replace(
                        &format!("{name}:\t0000000000000000"),
                        &format!("{name}:\t0000000000000001")
                    )
                    .as_bytes()
            )
            .is_err()
        );
    }
    assert!(
        require_status(
            status
                .replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")
                .as_bytes()
        )
        .is_err()
    );
    assert!(require_status(format!("{status}CapEff:\t0\n").as_bytes()).is_err());
}

#[test]
fn normal_root_actual_wrong_launch_file_cannot_be_adopted_as_image() {
    // Actual kernel FDs and proc-exe/name checks, not a synthetic positive
    // startup/config owner. These foreign test-local files grant no image pin.
    let file = tempfile::tempfile().unwrap();
    assert!(images::retain_profile(file.try_clone().unwrap()).is_err());
    let pin = profile::ImagePinV1 {
        path: format!("{ROOT}/bin/aos-sandbox-policy-authorityd"),
        sha256: [1; 32],
    };
    assert!(images::retain_pin(&pin, Some(file), true).is_err());
}

#[test]
fn controller_closed_table_preserves_existing_roles_and_one_selected_profile() {
    let names = |entries: &[&str]| {
        entries
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect::<Vec<_>>()
    };
    for entries in [
        vec![],
        vec!["aos-method46-pid1-image"],
        vec![client::PROFILE_NAME],
        vec!["aos-method46-pid1-image", client::PROFILE_NAME],
    ] {
        assert!(client::valid_names(&names(&entries), false));
        let mut publisher = entries;
        publisher.push("aos-sandboxd-publisher");
        assert!(client::valid_names(&names(&publisher), true));
    }
    for entries in [
        vec![client::PROFILE_NAME, client::PROFILE_NAME],
        vec!["aos-method46-pid1-image", "aos-method46-pid1-image"],
        vec!["aos-normal-root-pid1-image"],
        vec!["unknown"],
        vec!["aos-sandboxd-publisher"],
    ] {
        assert!(!client::valid_names(&names(&entries), false));
    }
    assert!(!client::valid_names(&names(&[client::PROFILE_NAME]), true));
}

fn controller_properties(tpm_image: bool) -> (Vec<OwnedValue>, Vec<OwnedValue>) {
    let (mut service, mut unit) = properties();
    service[0] = value("/aos.slice/aos-control.slice/aos-sandboxd.service");
    let mut files = vec![(PROFILE.to_owned(), client::PROFILE_NAME.to_owned(), 1_u64)];
    if tpm_image {
        files.push((
            "/proc/1/exe".to_owned(),
            "aos-method46-pid1-image".to_owned(),
            1,
        ));
    }
    service[1] = value(files);
    service[5] = value((false, "system_u:system_r:aos_sandbox_controller_t"));
    unit[0] = value(format!("{ROOT}/aos-sandboxd.service"));
    (service, unit)
}

#[test]
fn controller_profile_delivery_is_fixed_unit_invocation_and_original_role_bound() {
    for tpm in [false, true] {
        let (service, unit) = controller_properties(tpm);
        assert!(
            controller_peer::decode_delivery(&service, &unit, std::path::Path::new(PROFILE))
                .is_ok()
        );
        assert!(
            client::decode_delivery(&service, &unit, std::path::Path::new(PROFILE), tpm).is_ok()
        );
        assert!(
            client::decode_delivery(
                &service,
                &unit,
                std::path::Path::new("/other/profile.json"),
                tpm
            )
            .is_err()
        );
        assert!(
            client::decode_delivery(&service, &unit, std::path::Path::new(PROFILE), !tpm).is_err()
        );
    }
    let replacements = [
        (0, value("/system.slice/aos-sandboxd.service")),
        (
            1,
            value(vec![(
                PROFILE.to_owned(),
                PROFILE_FD_NAME.to_owned(),
                1_u64,
            )]),
        ),
        (
            1,
            value(vec![(
                PROFILE.to_owned(),
                client::PROFILE_NAME.to_owned(),
                0_u64,
            )]),
        ),
        (2, value(vec!["foreign".to_owned()])),
        (3, OwnedValue::from(1_u32)),
        (4, OwnedValue::from(1_u32)),
        (5, value((false, CONTEXT))),
        (6, OwnedValue::from(1_u64)),
        (7, OwnedValue::from(1_u64)),
        (8, OwnedValue::from(false)),
    ];
    for (index, replacement) in replacements {
        let (mut service, unit) = controller_properties(false);
        service[index] = replacement;
        assert!(
            controller_peer::decode_delivery(&service, &unit, std::path::Path::new(PROFILE))
                .is_err()
        );
        assert!(
            client::decode_delivery(&service, &unit, std::path::Path::new(PROFILE), false).is_err()
        );
    }
    for (index, replacement) in [
        (0, value(format!("{ROOT}/{UNIT}"))),
        (1, value(vec!["/run/mutable.conf".to_owned()])),
        (2, OwnedValue::from(true)),
        (3, value(vec![0_u8; 16])),
    ] {
        let (service, mut unit) = controller_properties(false);
        unit[index] = replacement;
        assert!(
            controller_peer::decode_delivery(&service, &unit, std::path::Path::new(PROFILE))
                .is_err()
        );
        assert!(
            client::decode_delivery(&service, &unit, std::path::Path::new(PROFILE), false).is_err()
        );
    }
}

#[test]
fn controller_profile_delivery_rejects_mls_suffixes() {
    assert_eq!(
        client::CONTEXT,
        "system_u:system_r:aos_sandbox_controller_t"
    );

    for tpm in [false, true] {
        for suffix in [":s0", ":s0:c0", ":s0-s0:c0.c1"] {
            let (mut properties, unit) = controller_properties(tpm);
            properties[5] = value((false, format!("{}{suffix}", client::CONTEXT)));

            assert!(
                client::decode_delivery(&properties, &unit, std::path::Path::new(PROFILE), tpm)
                    .is_err()
            );
            assert!(
                controller_peer::decode_delivery(&properties, &unit, std::path::Path::new(PROFILE))
                    .is_err()
            );
        }
    }
}

#[test]
fn original_controller_peer_infers_only_exact_existing_optional_pid1_role() {
    for files in [
        vec![
            (PROFILE.to_owned(), client::PROFILE_NAME.to_owned(), 1_u64),
            (
                "/proc/1/exe".to_owned(),
                "aos-method46-pid1-image".to_owned(),
                0,
            ),
        ],
        vec![
            (PROFILE.to_owned(), client::PROFILE_NAME.to_owned(), 1_u64),
            (
                "/other/exe".to_owned(),
                "aos-method46-pid1-image".to_owned(),
                1,
            ),
        ],
        vec![
            (PROFILE.to_owned(), client::PROFILE_NAME.to_owned(), 1_u64),
            (PROFILE.to_owned(), client::PROFILE_NAME.to_owned(), 1),
        ],
        vec![
            (PROFILE.to_owned(), client::PROFILE_NAME.to_owned(), 1_u64),
            (
                "/proc/1/exe".to_owned(),
                "aos-normal-root-pid1-image".to_owned(),
                1,
            ),
        ],
        Vec::new(),
    ] {
        let (mut properties, unit) = controller_properties(false);
        properties[1] = value(files);
        assert!(
            controller_peer::decode_delivery(&properties, &unit, std::path::Path::new(PROFILE))
                .is_err()
        );
    }
}

type InertCommand = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

fn peer_command(path: &str, argv: Vec<String>, ignore_failure: bool, pid: u32) -> InertCommand {
    (
        path.to_owned(),
        argv,
        ignore_failure,
        1_u64,
        2_u64,
        0_u64,
        0_u64,
        pid,
        0_i32,
        0_i32,
    )
}

#[test]
fn original_root_pid1_launch_requires_exact_image_argv_and_no_extra_commands() {
    let profile =
        NormalRootProfileV1::decode(&serde_json::to_vec(&inert_profile()).unwrap()).unwrap();
    let argv = vec![
        profile.executable.path.clone(),
        "811".into(),
        "811".into(),
        "0".into(),
        "0".into(),
    ];
    let empty = value(Vec::<InertCommand>::new());
    let start = |path: &str, args: Vec<String>, ignore_failure: bool, pid: u32| {
        value(vec![peer_command(path, args, ignore_failure, pid)])
    };
    let launch = vec![
        start(&profile.executable.path, argv.clone(), false, 22),
        empty.clone(),
        empty.clone(),
    ];
    assert!(service::require_peer_launch(&launch, 22, &profile).is_ok());

    let mut wrong_argv = argv.clone();
    wrong_argv[1] = "812".into();
    for replacement in [
        start("/other/root", argv.clone(), false, 22),
        start(&profile.executable.path, wrong_argv, false, 22),
        start(&profile.executable.path, argv.clone(), true, 22),
        start(&profile.executable.path, argv.clone(), false, 23),
        empty,
    ] {
        let mut changed = launch.clone();
        changed[0] = replacement;
        assert!(service::require_peer_launch(&changed, 22, &profile).is_err());
    }
    for index in [1, 2] {
        let mut changed = launch.clone();
        changed[index] = launch[0].clone();
        assert!(service::require_peer_launch(&changed, 22, &profile).is_err());
    }
    for malformed in [
        vec![],
        vec![launch[0].clone()],
        vec![launch[0].clone(), launch[1].clone()],
        vec![
            launch[0].clone(),
            launch[1].clone(),
            launch[2].clone(),
            launch[0].clone(),
        ],
    ] {
        assert!(service::require_peer_launch(&malformed, 22, &profile).is_err());
    }
}
