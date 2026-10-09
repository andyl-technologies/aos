//! Candidate installation and refusal regressions, without native qualification.

// crucible-lint: allow rust-allow -- bounded test fixtures and refusal oracles deliberately panic on failure.
#![allow(clippy::unwrap_used)]

use std::{fs, os::unix::fs::PermissionsExt};

use crucible_node_contract::{U64, canonical};

use super::*;

fn fixture_policy(directory: &std::path::Path) -> KvmCandidatePolicy {
    let artifacts = [
        (
            KvmCandidateArtifactRole::Qemu,
            "qemu",
            b"executable fixture".as_slice(),
        ),
        (
            KvmCandidateArtifactRole::QemuSource,
            "qemu-source",
            b"source evidence".as_slice(),
        ),
        (
            KvmCandidateArtifactRole::KernelSource,
            "kernel-source",
            b"kernel evidence".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(role, name, bytes)| {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        KvmCandidateArtifactPolicy {
            role,
            path,
            expected: canonical::content_ref(bytes, "application/octet-stream").unwrap(),
        }
    })
    .collect();
    KvmCandidatePolicy {
        format: "crucible.kvm-installed-candidate".into(),
        version: 1,
        architecture: KvmArchitecture::native().unwrap(),
        vcpus: U64::new(1),
        quantum_ps: U64::new(1_000_000),
        host_budget_ns: U64::new(1_000_000),
        artifacts,
    }
}

#[test]
fn local_policy_is_duplicate_strict_and_has_no_qualification_switch() {
    let directory = tempfile::tempdir().unwrap();
    let policy = fixture_policy(directory.path());
    let bytes = canonical::canonical_json(&serde_json::to_value(&policy).unwrap()).unwrap();
    assert!(KvmCandidatePolicy::from_json(&bytes).is_ok());

    let mut forged = serde_json::to_value(&policy).unwrap();
    forged["profile_qualified"] = serde_json::json!(true);
    assert!(KvmCandidatePolicy::from_json(&serde_json::to_vec(&forged).unwrap()).is_err());
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert!(KvmCandidatePolicy::from_json(duplicate.as_bytes()).is_err());
}

#[test]
fn local_policy_refuses_subnanosecond_grids_and_missing_source_rosters() {
    let directory = tempfile::tempdir().unwrap();
    let mut policy = fixture_policy(directory.path());
    policy.quantum_ps = U64::new(1001);
    assert!(policy.validate().is_err());
    policy.quantum_ps = U64::new(1000);
    policy.artifacts.pop();
    assert!(policy.validate().is_err());
}

#[test]
fn candidate_authentication_retains_pinned_original_files_and_rechecks_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let policy = fixture_policy(directory.path());
    let qemu = policy.artifacts[0].path.clone();
    let candidate = KvmInstalledCandidate::open(policy).unwrap();
    let original = directory.path().join("original-qemu");
    fs::rename(&qemu, &original).unwrap();
    fs::write(&qemu, b"replacement at same path").unwrap();
    assert!(candidate.artifacts[0].verify().is_ok());

    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&original, b"modified original").unwrap();
    assert!(matches!(
        candidate.prepare_quantized(),
        Err(KvmCandidateError::ArtifactIdentity {
            role: KvmCandidateArtifactRole::Qemu
        })
    ));
}

#[test]
fn candidate_refuses_symlink_and_changed_expected_source() {
    let directory = tempfile::tempdir().unwrap();
    let mut policy = fixture_policy(directory.path());
    policy.artifacts[1].expected =
        canonical::content_ref(b"other source bytes", "application/octet-stream").unwrap();
    assert!(matches!(
        KvmInstalledCandidate::open(policy),
        Err(KvmCandidateError::ArtifactIdentity {
            role: KvmCandidateArtifactRole::QemuSource
        })
    ));

    let symlink_directory = tempfile::tempdir().unwrap();
    let mut policy = fixture_policy(symlink_directory.path());
    let link = symlink_directory.path().join("qemu-link");
    std::os::unix::fs::symlink(&policy.artifacts[0].path, &link).unwrap();
    policy.artifacts[0].path = link;
    assert!(matches!(
        KvmInstalledCandidate::open(policy),
        Err(KvmCandidateError::ArtifactIo {
            role: KvmCandidateArtifactRole::Qemu,
            ..
        })
    ));
}

#[test]
fn quantized_candidate_uses_real_host_probe_and_never_promotes_partial_components() {
    let directory = tempfile::tempdir().unwrap();
    let candidate = KvmInstalledCandidate::open(fixture_policy(directory.path())).unwrap();
    let error = candidate.prepare_quantized().unwrap_err();
    // This tests the real availability/refusal path, not native run qualification.
    // No fake device or transport substitutes for an absent host KVM descriptor.
    match error {
        KvmCandidateError::Native(KvmProfileError::DeviceUnavailable { source }) => {
            assert!(matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ));
        }
        KvmCandidateError::Native(KvmProfileError::MissingMediation { .. }) => {}
        error => panic!("unexpected native candidate refusal: {error:?}"),
    }
}

#[test]
fn cross_architecture_candidate_never_falls_back_to_tcg() {
    let directory = tempfile::tempdir().unwrap();
    let mut policy = fixture_policy(directory.path());
    policy.architecture = match policy.architecture {
        KvmArchitecture::X86_64 => KvmArchitecture::Aarch64,
        KvmArchitecture::Aarch64 => KvmArchitecture::X86_64,
    };
    let candidate = KvmInstalledCandidate::open(policy).unwrap();
    assert!(matches!(
        candidate.prepare_quantized(),
        Err(KvmCandidateError::Native(
            KvmProfileError::UnsupportedArchitecture { .. }
        ))
    ));
}
