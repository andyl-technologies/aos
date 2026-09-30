//! Exact report substitutions, independent signatures and protected seed custody.

use super::*;

#[test]
fn public_verifier_is_hex_and_private_seed_is_a_distinct_format() {
    assert_eq!(
        files::public_key(format!("{}\n", "19".repeat(32)).as_bytes()).unwrap(),
        "19".repeat(32)
    );
    assert!(files::public_key(&[0x19; 32]).is_err());
    assert!(files::public_key("AB".repeat(32).as_bytes()).is_err());
}

mod fixtures;

#[test]
fn explicitly_reviewed_candidate_signs_only_with_independently_installed_key() {
    let fixture = fixtures::fixture();
    let candidate = fixture.directory.path().join("candidate.json");
    let output = fixture.directory.path().join("accepted.json");
    let reviewed = prepare_direct_upload_review(&fixture.selection, &candidate).unwrap();
    let hash = sign_direct_upload_review(
        &fixture.selection,
        &candidate,
        &reviewed,
        &fixture.private_key,
        &fixture.public_key,
        &output,
    )
    .unwrap();
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(hash, files::digest(&bytes));
    let artifact: aos_hub_core::direct_upload::DirectWorkerQualificationArtifact =
        serde_json::from_slice(&bytes).unwrap();
    artifact
        .verify(
            &artifact.deployment_id,
            &artifact.public_origin,
            &files::public_key(&std::fs::read(&fixture.public_key).unwrap()).unwrap(),
            now().unwrap(),
        )
        .unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("reviewer.seed"));
    assert!(sign_direct_upload_review(
        &fixture.selection,
        &candidate,
        &reviewed,
        &fixture.private_key,
        &fixture.public_key,
        &output
    )
    .is_err());
}

#[test]
fn changed_candidate_reports_profiles_and_keys_never_emit_a_signature() {
    for mutation in 0..5 {
        let fixture = fixtures::fixture();
        let candidate = fixture.directory.path().join("candidate.json");
        let output = fixture.directory.path().join("accepted.json");
        let reviewed = prepare_direct_upload_review(&fixture.selection, &candidate).unwrap();
        match mutation {
            0 => std::fs::write(&candidate, b"{}").unwrap(),
            1 => std::fs::write(&fixture.selection, b"{}").unwrap(),
            2 => std::fs::write(&fixture.private_key, [0x77; 32]).unwrap(),
            3 => std::fs::write(&fixture.public_key, "77".repeat(32)).unwrap(),
            4 => {
                let manifest: DirectReviewSelection =
                    serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
                std::fs::write(
                    fixture
                        .directory
                        .path()
                        .join(&manifest.documents.deployment_identity.path),
                    b"{}",
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let error = sign_direct_upload_review(
            &fixture.selection,
            &candidate,
            &reviewed,
            &fixture.private_key,
            &fixture.public_key,
            &output,
        )
        .unwrap_err()
        .to_string();
        assert!(!output.exists());
        assert!(!error.contains(fixture.directory.path().to_str().unwrap()));
        assert!(!error.contains(&"77".repeat(32)));
    }
}

#[cfg(unix)]
#[test]
fn raw_seed_custody_refuses_public_files_links_fifo_and_wrong_lengths() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    for mutation in 0..6 {
        let fixture = fixtures::fixture();
        let candidate = fixture.directory.path().join("candidate.json");
        let output = fixture.directory.path().join("accepted.json");
        let reviewed = prepare_direct_upload_review(&fixture.selection, &candidate).unwrap();
        let selected = fixture.directory.path().join("selected.seed");
        let selected = selected
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .to_path_buf();
        match mutation {
            0 => {
                std::fs::set_permissions(
                    &fixture.private_key,
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            1 => {
                symlink(
                    std::fs::canonicalize(&fixture.private_key).unwrap(),
                    &selected,
                )
                .unwrap();
            }
            2 => {
                std::fs::hard_link(&fixture.private_key, &selected).unwrap();
            }
            3 => {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &selected,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            4 => {
                std::fs::write(&fixture.private_key, [0x19; 31]).unwrap();
            }
            5 => {
                std::fs::write(&fixture.private_key, "19".repeat(32)).unwrap();
            }
            _ => unreachable!(),
        }
        let path = if matches!(mutation, 1..=3) {
            &selected
        } else {
            &fixture.private_key
        };
        assert!(sign_direct_upload_review(
            &fixture.selection,
            &candidate,
            &reviewed,
            path,
            &fixture.public_key,
            &output
        )
        .is_err());
        assert!(!output.exists());
    }
}

#[test]
fn unknown_selection_fields_and_self_declared_measurements_are_refused() {
    for mutation in 0..3 {
        let fixture = fixtures::fixture();
        let mut selection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
        match mutation {
            0 => selection["ready"] = serde_json::json!(true),
            1 => selection["runtimeBounds"]["maximumParallelObjects"] = serde_json::json!("5"),
            2 => selection["scriptVersion"] = serde_json::json!("other-script"),
            _ => unreachable!(),
        }
        std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();
        let output = fixture.directory.path().join("candidate.json");
        assert!(prepare_direct_upload_review(&fixture.selection, &output).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn retained_raw_reports_cannot_be_replaced_by_self_selected_summary_values() {
    for mutation in 0..3 {
        let fixture = fixtures::fixture();
        let mut selection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
        if mutation == 0 {
            selection["reports"]
                .as_array_mut()
                .unwrap()
                .retain(|report| report["kind"] != "mixed_load");
        } else {
            let report = selection["reports"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|report| report["kind"] == "metadata_queue")
                .unwrap();
            let path = fixture
                .directory
                .path()
                .join(report["file"]["path"].as_str().unwrap());
            let mut raw: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if mutation == 1 {
                raw["observations"]["samples"][0]["aggregateActive"] = serde_json::json!("5");
            } else {
                raw["observations"]["samples"] = serde_json::json!([]);
            }
            let bytes = serde_json::to_vec(&raw).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            report["file"]["sha256"] = serde_json::json!(files::digest(&bytes));
        }
        std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();
        let output = fixture.directory.path().join("candidate.json");
        assert!(prepare_direct_upload_review(&fixture.selection, &output).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn expired_attempt_raw_utc_must_match_the_authenticated_reply_not_latest_now() {
    let fixture = fixtures::fixture();
    let output = fixture.directory.path().join("candidate.json");
    prepare_direct_upload_review(&fixture.selection, &output).unwrap();

    let mut selection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
    let report = selection["reports"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|report| report["kind"] == "clock")
        .unwrap();
    let path = fixture
        .directory
        .path()
        .join(report["file"]["path"].as_str().unwrap());
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // The retained latest-now is 101 seconds; actual reply UTC is 100000 ms.
    raw["observations"]["expiredMutations"][0]["observedAtMillis"] = serde_json::json!("101000");
    let bytes = serde_json::to_vec(&raw).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    report["file"]["sha256"] = serde_json::json!(files::digest(&bytes));
    std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();

    let refused = fixture.directory.path().join("refused.json");
    assert!(prepare_direct_upload_review(&fixture.selection, &refused).is_err());
    assert!(!refused.exists());
}

#[test]
fn terminal_verification_replay_never_qualifies_from_ambient_isolate_dispatches() {
    fn substitute(value: &mut serde_json::Value, old: &str, new: &str) {
        match value {
            serde_json::Value::String(text) if text == old => *text = new.into(),
            serde_json::Value::Array(values) => {
                for value in values {
                    substitute(value, old, new);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values_mut() {
                    substitute(value, old, new);
                }
            }
            _ => {}
        }
    }

    for missing in [false, true] {
        let fixture = fixtures::fixture();
        let mut selection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
        let capture = selection["captureFiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|capture| {
                let path = fixture
                    .directory
                    .path()
                    .join(capture["path"].as_str().unwrap());
                let reply: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                reply["result"]["attempts"][0]["receipt"].is_object()
            })
            .unwrap();
        let path = fixture
            .directory
            .path()
            .join(capture["path"].as_str().unwrap());
        let old = capture["sha256"].as_str().unwrap().to_owned();
        let mut reply: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let receipt = &mut reply["result"]["attempts"][0]["receipt"];
        assert!(
            receipt["providerAfter"]["dispatches"].as_u64().unwrap()
                > receipt["attempt"]["providerBefore"]["dispatches"]
                    .as_u64()
                    .unwrap()
        );
        if missing {
            receipt
                .as_object_mut()
                .unwrap()
                .remove("verificationReplayed");
        } else {
            receipt["verificationReplayed"] = serde_json::json!(true);
        }
        let bytes = serde_json::to_vec(&reply).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let new = files::digest(&bytes);
        capture["sha256"] = serde_json::json!(new);

        for report in selection["reports"].as_array_mut().unwrap() {
            let path = fixture
                .directory
                .path()
                .join(report["file"]["path"].as_str().unwrap());
            let mut raw: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            substitute(&mut raw, &old, &new);
            let bytes = serde_json::to_vec(&raw).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            report["file"]["sha256"] = serde_json::json!(files::digest(&bytes));
        }
        std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();

        let output = fixture.directory.path().join("candidate.json");
        let error = prepare_direct_upload_review(&fixture.selection, &output).unwrap_err();
        assert!(error.to_string().contains("verification was replayed"));
        assert!(!output.exists());
    }
}

#[test]
fn public_endpoint_missing_authentication_400_does_not_qualify_as_disabled_public_refusal() {
    let fixture = fixtures::fixture();
    let mut selection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
    let selected = &mut selection["documents"]["privacy"];
    let path = fixture
        .directory
        .path()
        .join(selected["path"].as_str().unwrap());
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    document["publicReadRejectionStatus"] = serde_json::json!(400);
    let bytes = serde_json::to_vec(&document).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    selected["sha256"] = serde_json::json!(files::digest(&bytes));
    std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();
    assert!(prepare_direct_upload_review(
        &fixture.selection,
        &fixture.directory.path().join("candidate.json")
    )
    .is_err());
}

#[test]
fn actual_installed_component_hashes_and_sizes_are_checked_before_candidate_output() {
    for mutate in [false, true] {
        let fixture = fixtures::fixture();
        let mut selection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
        let mut components = Vec::new();
        let mut hashes = std::collections::BTreeMap::new();
        for name in [
            "source_nar",
            "distribution_nar",
            "wasm",
            "shim",
            "runtime_bindings",
        ] {
            let bytes = format!("explicit test-only observed {name} bytes");
            let path = fixture.directory.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            let hash = files::digest(bytes.as_bytes());
            hashes.insert(name, (hash.clone(), bytes.len()));
            components.push(serde_json::json!({"kind":name,"file":{"path":name,"sha256":hash}}));
        }
        selection["installedFiles"] = serde_json::json!(components);
        let report = serde_json::json!({"version":1,"executionKind":selection["executionKind"],"deploymentId":selection["deploymentId"],
            "publicOrigin":selection["publicOrigin"],"sourceDigest":selection["sourceDigest"],"scriptVersion":selection["scriptVersion"],
            "sourceNarSha256":hashes["source_nar"].0,"distributionNarSha256":hashes["distribution_nar"].0,
            "wasmSha256":hashes["wasm"].0,"wasmByteSize":(hashes["wasm"].1+usize::from(mutate)).to_string(),
            "shimSha256":hashes["shim"].0,"shimByteSize":hashes["shim"].1.to_string(),"runtimeBindingsSha256":hashes["runtime_bindings"].0,
            "runnerSha256":null,"runtimeExecutableSha256":null,"observedProcessExecutableSha256":null});
        let bytes = serde_json::to_vec(&report).unwrap();
        std::fs::write(fixture.directory.path().join("installation.json"), &bytes).unwrap();
        selection["documents"]["installation"] =
            serde_json::json!({"path":"installation.json","sha256":files::digest(&bytes)});
        std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();
        let output = fixture.directory.path().join("candidate.json");
        let prepared = prepare_direct_upload_review(&fixture.selection, &output);
        if mutate {
            assert!(prepared.is_err());
            assert!(!output.exists());
        } else {
            prepared.unwrap();
        }
    }
}

#[test]
fn provisioning_authority_never_erases_a_known_runtime_guard_bypass() {
    for missing_scope in [false, true] {
        let fixture = fixtures::fixture();
        let mut selection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.selection).unwrap()).unwrap();
        let report_index = selection["reports"]
            .as_array()
            .unwrap()
            .iter()
            .position(|report| report["kind"] == "privacy")
            .unwrap();
        let report_path = fixture.directory.path().join(
            selection["reports"][report_index]["file"]["path"]
                .as_str()
                .unwrap(),
        );
        let mut report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        let writer_hash = report["independentWriterReviewSha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let selected = selection["privacyFiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|file| file["sha256"] == writer_hash)
            .unwrap();
        let path = fixture
            .directory
            .path()
            .join(selected["path"].as_str().unwrap());
        let mut assessment: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if missing_scope {
            assessment["runtimeMutationApis"] = serde_json::json!([]);
        } else {
            assessment["runtimeMutationApis"][0]["guardCoverage"] =
                serde_json::json!("bypasses_guard");
        }
        let bytes = serde_json::to_vec(&assessment).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let hash = files::digest(&bytes);
        selected["sha256"] = serde_json::json!(hash);
        report["independentWriterReviewSha256"] = serde_json::json!(hash);
        let bytes = serde_json::to_vec(&report).unwrap();
        std::fs::write(&report_path, &bytes).unwrap();
        let hash = files::digest(&bytes);
        selection["reports"][report_index]["file"]["sha256"] = serde_json::json!(hash);
        let selected = &mut selection["documents"]["privacy"];
        let path = fixture
            .directory
            .path()
            .join(selected["path"].as_str().unwrap());
        let mut privacy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        privacy["observationSha256"] = serde_json::json!(hash);
        let bytes = serde_json::to_vec(&privacy).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        selected["sha256"] = serde_json::json!(files::digest(&bytes));
        std::fs::write(&fixture.selection, serde_json::to_vec(&selection).unwrap()).unwrap();
        let output = fixture.directory.path().join("candidate.json");
        assert!(prepare_direct_upload_review(&fixture.selection, &output).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn installed_clock_policy_commitment_uses_shared_encoder_without_claiming_measurements() {
    let output: serde_json::Value =
        serde_json::from_str(&direct_upload_review_clock_policy(2).unwrap()).unwrap();
    let policy: aos_hub_core::direct_upload::DirectClockPolicy =
        serde_json::from_value(output["policy"].clone()).unwrap();
    assert_eq!(policy.commitment().unwrap(), output["commitment"]);
    assert_eq!(output.as_object().unwrap().len(), 2);
    for uncertainty in [0, 30, u64::MAX] {
        assert!(direct_upload_review_clock_policy(uncertainty).is_err());
    }
}

#[test]
#[ignore = "requires AOS_DIRECT_REVIEW_TEST_BINARY pointing to the current source-built CLI"]
fn source_built_cli_prepares_reviews_signs_and_refuses_a_changed_candidate() {
    let binary = std::env::var_os("AOS_DIRECT_REVIEW_TEST_BINARY").unwrap();
    let fixture = fixtures::fixture();
    let candidate = fixture.directory.path().join("cli-candidate.json");
    let output = fixture.directory.path().join("cli-accepted.json");
    let prepared = std::process::Command::new(&binary)
        .env_remove("LD_LIBRARY_PATH")
        .arg("prepare")
        .arg("--selection-file")
        .arg(&fixture.selection)
        .arg("--output")
        .arg(&candidate)
        .output()
        .unwrap();
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let reviewed = String::from_utf8(prepared.stdout)
        .unwrap()
        .trim_end()
        .to_owned();
    assert_eq!(reviewed, files::digest(&std::fs::read(&candidate).unwrap()));
    let signed = std::process::Command::new(&binary)
        .env_remove("LD_LIBRARY_PATH")
        .arg("sign")
        .arg("--selection-file")
        .arg(&fixture.selection)
        .arg("--candidate-file")
        .arg(&candidate)
        .arg("--candidate-sha256")
        .arg(&reviewed)
        .arg("--reviewer-key-file")
        .arg(&fixture.private_key)
        .arg("--reviewer-public-key-file")
        .arg(&fixture.public_key)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(
        String::from_utf8(signed.stdout).unwrap().trim_end(),
        files::digest(&bytes)
    );
    let artifact: aos_hub_core::direct_upload::DirectWorkerQualificationArtifact =
        serde_json::from_slice(&bytes).unwrap();
    artifact
        .verify(
            &artifact.deployment_id,
            &artifact.public_origin,
            &files::public_key(&std::fs::read(&fixture.public_key).unwrap()).unwrap(),
            now().unwrap(),
        )
        .unwrap();
    let registry = std::process::Command::new(&binary)
        .env_remove("LD_LIBRARY_PATH")
        .arg("registry-key")
        .arg("--deployment-id")
        .arg(&artifact.deployment_id)
        .arg("--source-digest")
        .arg(&artifact.source_digest)
        .arg("--script-version")
        .arg(&artifact.script_version)
        .output()
        .unwrap();
    assert!(registry.status.success());
    assert_eq!(
        String::from_utf8(registry.stdout).unwrap().trim_end(),
        aos_hub_core::direct_upload::direct_worker_acceptance_key(
            &artifact.deployment_id,
            &artifact.source_digest,
            &artifact.script_version,
        )
        .unwrap(),
    );
    std::fs::write(&candidate, b"{}").unwrap();
    let refused = fixture.directory.path().join("cli-refused.json");
    let response = std::process::Command::new(binary)
        .env_remove("LD_LIBRARY_PATH")
        .arg("sign")
        .arg("--selection-file")
        .arg(&fixture.selection)
        .arg("--candidate-file")
        .arg(&candidate)
        .arg("--candidate-sha256")
        .arg(reviewed)
        .arg("--reviewer-key-file")
        .arg(&fixture.private_key)
        .arg("--reviewer-public-key-file")
        .arg(&fixture.public_key)
        .arg("--output")
        .arg(&refused)
        .output()
        .unwrap();
    assert!(!response.status.success());
    assert!(!refused.exists());
    assert!(response.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&response.stderr).contains("reviewer.seed"));
}
