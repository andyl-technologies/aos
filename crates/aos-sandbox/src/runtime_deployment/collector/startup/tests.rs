//! UNRUN pure collector-profile/confinement DATA; no startup owner is fabricated.

use serde_json::{Value, json};

use super::*;

fn profile() -> Value {
    let executable_root = "/nix/store/00000000000000000000000000000000-collector";
    let profile_root = "/nix/store/11111111111111111111111111111111-aos-installed-filter-collector-startup-profile-1";
    let specimen_package = "/nix/store/22222222222222222222222222222222-aos-sandbox-deployment-specimen-root-0.1.0";
    let helpers = "/nix/store/33333333333333333333333333333333-aos-installed-filter-collector-0.1.0";
    let systemd = "/nix/store/44444444444444444444444444444444-systemd-261.2";
    let pin = |path: String| json!({"path": path, "sha256": [1_u8; 32].as_slice()});
    let executable = pin(format!("{executable_root}/bin/aos-sandbox-installed-filter-collector"));
    let loader = pin(format!("{executable_root}/lib/ld.so"));
    let reader = pin(format!("{helpers}/libexec/aos-installed-filter-reader"));
    let network = pin(format!("{helpers}/libexec/aos-deployment-specimen-network"));
    let nspawn = pin(format!("{systemd}/bin/systemd-nspawn"));
    let init = pin(format!("{specimen_package}/root/usr/lib/systemd/systemd"));
    let root_pin = pin(format!("{specimen_package}/specimen-root.sha256"));
    let mut runtime = vec![executable.clone(), loader.clone(), reader.clone(), network.clone(),
        nspawn.clone(), init.clone(), root_pin.clone()];
    runtime.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));

    json!({
        "format": "AOS_INSTALLED_FILTER_COLLECTOR_STARTUP_1", "unit": UNIT, "context": CONTEXT,
        "executable": executable, "pid1": pin(format!("{systemd}/lib/systemd/systemd")),
        "loader": loader, "runtime_files": runtime,
        "closure_roots": [executable_root, specimen_package, helpers, systemd],
        "canonical_policy": pin("/nix/store/55555555555555555555555555555555-aos-selinux-kernel-policy-readback-1/policy.33".into()),
        "source_policy": pin(format!("{profile_root}/source-policy.33")),
        "effective_matrix": pin(format!("{profile_root}/effective-policy.tsv")),
        "unit_sha256": [2_u8; 32].as_slice(), "reader": reader, "network": network, "nspawn": nspawn,
        "specimen_root": format!("{specimen_package}/root"),
        "specimen_root_sha256": [3_u8; 32].as_slice(), "specimen_init": init,
        "specimen_root_digest_pin": root_pin,
    })
}

#[test]
fn unrun_collector_profile_is_closed_to_original_roles_and_fixed_helper_images() {
    let original = profile();
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&original).unwrap()).is_ok());
    for (field, replacement) in [
        ("unit", "aos-sandbox-runtime-publisher.service"),
        ("context", "system_u:system_r:aos_sandbox_host_t:s0"),
        ("format", "AOS_RUNTIME_DEPLOYMENT_STARTUP_1"),
    ] {
        let mut changed = original.clone();
        changed[field] = replacement.into();
        assert!(CollectorProfileV1::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut wrong_helper = original;
    wrong_helper["network"]["path"] = wrong_helper["reader"]["path"].clone();
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&wrong_helper).unwrap()).is_err());
}

#[test]
fn unrun_collector_root_and_complete_runtime_membership_cannot_be_substituted() {
    let original = profile();
    let mut wrong_root = original.clone();
    wrong_root["specimen_root"] = "/nix/store/22222222222222222222222222222222-runtime-root/root".into();
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&wrong_root).unwrap()).is_err());
    let mut absent_member = original.clone();
    absent_member["runtime_files"].as_array_mut().unwrap().pop();
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&absent_member).unwrap()).is_err());
    let mut wrong_pin = original;
    wrong_pin["specimen_root_digest_pin"]["sha256"] = json!([4_u8; 32].as_slice());
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&wrong_pin).unwrap()).is_err());
}

#[test]
fn unrun_unknown_profile_fields_duplicates_and_byte_bounds_refuse() {
    let mut unknown = profile();
    unknown["prepared"] = true.into();
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut duplicate = profile();
    let first = duplicate["runtime_files"][0].clone();
    duplicate["runtime_files"].as_array_mut().unwrap().insert(0, first);
    assert!(CollectorProfileV1::decode(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    assert!(CollectorProfileV1::decode(&[]).is_err());
    assert!(CollectorProfileV1::decode(&vec![b' '; PROFILE_BYTES + 1]).is_err());
}

#[test]
fn unrun_exact_two_capability_collector_is_not_empty_capability_host() {
    let status = format!(
        "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\n\
         CapPrm:\t{CAPABILITIES:016x}\nCapEff:\t{CAPABILITIES:016x}\n\
         CapBnd:\t{CAPABILITIES:016x}\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n"
    );
    assert!(require_status(status.as_bytes()).is_ok());
    for (original, replacement) in [
        (format!("CapEff:\t{CAPABILITIES:016x}"), "CapEff:\t0000000000000000".into()),
        ("NoNewPrivs:\t1".into(), "NoNewPrivs:\t0".into()),
        ("Seccomp:\t0".into(), "Seccomp:\t2".into()),
        ("Uid:\t0\t0\t0\t0".into(), "Uid:\t0\t1\t0\t0".into()),
    ] {
        assert!(require_status(status.replace(&original, &replacement).as_bytes()).is_err());
    }
    assert!(require_status(format!("{status}CapEff:\t{CAPABILITIES:016x}\n").as_bytes()).is_err());
}
