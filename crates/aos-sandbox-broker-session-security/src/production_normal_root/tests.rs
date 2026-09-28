//! Inert profile/property cuts and actual wrong-FD measurement regressions.
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
    let pin = |path: String| json!({"path": path, "sha256": [1_u8; 32].as_slice()});
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
        "unit_sha256": [2_u8; 32].as_slice(),
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
