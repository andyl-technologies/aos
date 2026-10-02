//! Controlled capture authentication/refusal tests; these do not qualify SDK work.

use std::{
    fs,
    path::{Path, PathBuf},
};

use aos_hub_core::storage_work::StorageWorkKey;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

use super::*;

struct PrivateDirectory {
    _retained: tempfile::TempDir,
    relative: PathBuf,
}

impl PrivateDirectory {
    fn path(&self) -> &Path {
        &self.relative
    }
}

fn private_directory() -> PrivateDirectory {
    let retained = tempfile::Builder::new()
        .prefix("oci-review-")
        .tempdir_in(".")
        .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(retained.path(), fs::Permissions::from_mode(0o700)).unwrap();

    // tempfile canonicalizes its path. Keep the actual directory but pass its
    // relative name so strict custody starts at this trusted working directory.
    let relative = Path::new(".").join(retained.path().file_name().unwrap());
    PrivateDirectory {
        _retained: retained,
        relative,
    }
}

fn input(directory: &Path, name: &str, bytes: &[u8]) -> ReviewedFile {
    let path = directory.join(name);
    files::write_new(&path, bytes).unwrap();
    ReviewedFile {
        path: PathBuf::from(name),
        sha256: files::digest(bytes),
    }
}

fn fixture(directory: &Path) -> OciSdkReviewSelection {
    let reference = input(directory, "unused.json", b"{}");
    let file = serde_json::to_value(&reference).unwrap();
    serde_json::from_value(json!({
        "version":1,"reviewerKeyId":"fixture-reviewer","reviewerPublicKey":file,
        "deploymentId":"fixture","publicOrigin":"https://worker.oci.test","nativeOrigin":"https://native.oci.test",
        "expectedSourceDigest":"11".repeat(32),"expectedScriptVersion":format!("emulated-{}","11".repeat(32)),
        "sourceStorePath":"/nix/store/test-source","distributionStorePath":"/nix/store/test-distribution",
        "sourceNarSha256":"22".repeat(32),"distributionNarSha256":"33".repeat(32),
        "issuedAt":200,"expiresAt":800,"clockPolicy":{"version":1,"mode":"bounded_utc","uncertaintySeconds":"2"},
        "maximumProviderRequests":2,"privateStagePolicyId":"fixture-only",
        "namespaceObservation":file,"nativeObservation":file,"nativeConfiguration":file,
        "anchorOriginal":file,"anchorReceipt":file,"clocks":[],"conformanceKeyFile":"control.key",
        "installed":{"nativeExecutable":file,"wasm":file,"shim":file,"configuration":file,"runner":file,
            "miniflareModule":file,"miniflareEntryWorker":file,"miniflareBucketWorker":file,
            "workerdExecutable":file,"nixExecutable":file}
    })).unwrap()
}

fn clock_fixture(directory: &Path) -> OciSdkReviewSelection {
    let mut selected = fixture(directory);
    let secret = "fixture-clock-key-only-0123456789abcdef";
    input(directory, "control.key", secret.as_bytes());
    let key = StorageWorkKey::new(secret).unwrap();
    for index in 0..2_u64 {
        let nonce = format!("{index:064x}");
        let request = serde_json::to_vec(&json!({"version":1,"runId":"44".repeat(32),"nonce":nonce,
            "sourceDigest":selected.expected_source_digest,"scriptVersion":selected.expected_script_version,
            "expiresAt":"190","action":{"kind":"clock"}})).unwrap();
        let request = input(directory, &format!("request-{index}.json"), &request);
        let observed = (180_000 + index).to_string();
        let reply = serde_json::to_vec(&json!({"version":1,"nonce":nonce,"requestSha256":request.sha256,
            "sourceDigest":selected.expected_source_digest,"scriptVersion":selected.expected_script_version,
            "observedAtMillis":observed,"result":{"kind":"clock","nonce":nonce,
                "observedAtMillis":observed,"uncertaintySeconds":"2"}})).unwrap();
        let signature = key
            .sign_body(
                &[
                    b"aos.direct-upload.qualification-reply.v1\0".as_slice(),
                    &reply,
                ]
                .concat(),
            )
            .unwrap();
        let reply = input(directory, &format!("reply-{index}.json"), &reply);
        let authentication = input(
            directory,
            &format!("auth-{index}.json"),
            &serde_json::to_vec(&json!({
                "status":200,"requestSha256":request.sha256,"responseSha256":reply.sha256,
                "sentAtMillis":"179999","receivedAtMillis":"180002","replySignature":signature
            }))
            .unwrap(),
        );
        selected.clocks.push(OciSdkClockCapture {
            request,
            reply,
            authentication,
        });
    }
    selected
}

fn replace_document(
    directory: &Path,
    reference: &mut ReviewedFile,
    change: impl FnOnce(&mut Value),
) {
    let mut value: Value =
        serde_json::from_slice(&fs::read(directory.join(&reference.path)).unwrap()).unwrap();
    change(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(directory.join(&reference.path), &bytes).unwrap();
    reference.sha256 = files::digest(&bytes);
}

#[test]
fn clock_authentication_uses_exact_actual_reply_and_both_reference_endpoints() {
    let directory = private_directory();
    let mut selected = clock_fixture(directory.path());

    let measurement = clock::assemble(directory.path(), &selected).unwrap();
    assert_eq!(measurement.samples.get(), 2);
    assert_eq!(measurement.maximum_observed_skew_millis.get(), 2);
    assert_eq!(measurement.expired_mutation_dispatches.get(), 0);

    replace_document(
        directory.path(),
        &mut selected.clocks[0].authentication,
        |value| value["replySignature"] = json!("00".repeat(32)),
    );
    assert!(clock::assemble(directory.path(), &selected).is_err());
}

#[test]
fn clock_refuses_relabelled_source_duplicate_nonce_and_reversed_brackets() {
    let directory = private_directory();
    let selected = clock_fixture(directory.path());
    let mut altered = selected.clone();
    altered.expected_source_digest = "99".repeat(32);
    assert!(clock::assemble(directory.path(), &altered).is_err());

    let mut altered = selected.clone();
    altered.clocks[1] = altered.clocks[0].clone();
    assert!(clock::assemble(directory.path(), &altered).is_err());

    let mut altered = selected;
    replace_document(
        directory.path(),
        &mut altered.clocks[0].authentication,
        |value| value["sentAtMillis"] = json!("180003"),
    );
    assert!(clock::assemble(directory.path(), &altered).is_err());
}

fn anchor_fixture(directory: &Path) -> OciSdkReviewSelection {
    let mut selected = fixture(directory);
    selected.namespace_observation =
        input(directory, "namespace.json", b"{\"controlledFixture\":1}");
    let namespace = fs::read(directory.join(&selected.namespace_observation.path)).unwrap();
    let payload = b"controlled anchor bytes; not an SDK observation";
    let run = "0123456789abcdef0123456789abcdef";
    let original = json!({"version":1,"issuedAt":"170","expiresAt":"190","runId":run,
        "namespaceObservationBase64":STANDARD.encode(&namespace),"namespaceObservationSha256":selected.namespace_observation.sha256,
        "payloadBase64":STANDARD.encode(payload),"payloadSha256":files::digest(payload),"payloadByteSize":payload.len().to_string()});
    selected.anchor_original = input(
        directory,
        "original.json",
        &serde_json::to_vec(&original).unwrap(),
    );
    let receipt = json!({"version":1,"status":"observed","runId":run,"originalSha256":selected.anchor_original.sha256,
        "namespaceObservationSha256":selected.namespace_observation.sha256,"completedAt":"1970-01-01T00:03:00.000Z",
        "anchor":{"object":{"key":format!(".aos-oci-sdk-qualification/{run}/anchor"),"provider_version":"controlled-fixture-version",
            "etag":"\"controlled-etag\"","size":payload.len()},"sha256":files::digest(payload)},"sdkInvocations":{"put":1,"get":1}});
    selected.anchor_receipt = input(
        directory,
        "receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
    selected
}

#[test]
fn anchor_requires_exact_namespace_original_positive_full_read_and_original_cutoff() {
    let directory = private_directory();
    let mut selected = anchor_fixture(directory.path());
    let (anchor, commitment) = anchor::assemble(directory.path(), &selected).unwrap();
    assert_eq!(
        anchor.object.provider_version.as_deref(),
        Some("controlled-fixture-version")
    );
    assert!(aos_hub_core::direct_upload::valid_direct_digest(
        &commitment
    ));

    replace_document(directory.path(), &mut selected.anchor_receipt, |value| {
        value["completedAt"] = json!("1970-01-01T00:03:10.000Z")
    });
    assert!(anchor::assemble(directory.path(), &selected).is_err());
}

#[test]
fn unknown_anchor_and_changed_full_read_hash_never_become_positive_evidence() {
    let directory = private_directory();
    let mut selected = anchor_fixture(directory.path());
    replace_document(directory.path(), &mut selected.anchor_receipt, |value| {
        value["status"] = json!("unknown")
    });
    assert!(anchor::assemble(directory.path(), &selected).is_err());
    replace_document(directory.path(), &mut selected.anchor_receipt, |value| {
        value["status"] = json!("observed");
        value["anchor"]["sha256"] = json!("ff".repeat(32));
    });
    assert!(anchor::assemble(directory.path(), &selected).is_err());
}

#[test]
fn private_custody_rejects_symlinks_public_modes_and_output_replacement() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = private_directory();
    let reference = input(directory.path(), "private.json", b"{}");
    assert!(files::selected_bytes(directory.path(), &reference).is_ok());
    assert!(files::write_new(&directory.path().join("private.json"), b"changed").is_err());
    symlink("private.json", directory.path().join("linked.json")).unwrap();
    assert!(files::private_bytes(&directory.path().join("linked.json"), 100).is_err());
    fs::set_permissions(
        directory.path().join("private.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(files::selected_bytes(directory.path(), &reference).is_err());
}

#[test]
fn actual_owned_native_process_observation_binds_current_elf_and_configuration() {
    let directory = private_directory();
    let executable = std::env::current_exe().unwrap();
    let report = directory.path().join("native.json");
    let configuration = directory.path().join("configuration.json");

    let hash =
        observe_oci_sdk_native(std::process::id(), &executable, &configuration, &report).unwrap();
    let native: observations::Native = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(hash, files::digest(&fs::read(&report).unwrap()));
    assert_eq!(native.process_id, std::process::id());
    assert_eq!(
        native.executable_sha256,
        files::hash_installed(&executable).unwrap().0
    );
    assert_eq!(
        native.configuration_sha256,
        files::digest(&fs::read(&configuration).unwrap())
    );
    assert!(observe_oci_sdk_native(
        std::process::id(),
        &configuration,
        &directory.path().join("other-config.json"),
        &directory.path().join("other-report.json")
    )
    .is_err());
}

#[test]
fn ephemeral_fixture_keys_are_new_and_separate_and_artifact_scope_is_closed() {
    let directory = private_directory();
    let seed = directory.path().join("seed");
    let public_file = directory.path().join("public");
    let public = create_oci_sdk_fixture_key(&seed, &public_file).unwrap();
    assert_eq!(fs::read(&seed).unwrap().len(), 32);
    assert_eq!(fs::read(&public_file).unwrap(), public.as_bytes());
    assert!(create_oci_sdk_fixture_key(&seed, &public_file).is_err());

    let (artifact, _) = aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_fixture();
    let mut value = serde_json::to_value(artifact).unwrap();
    value["evidence"]
        .as_object_mut()
        .unwrap()
        .remove("sdkObservationScope");
    assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["evidence"]["sdkObservationScope"] = json!("hosted");
    assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn nested_configuration_duplicates_and_invalid_utc_dates_fail_closed() {
    assert!(serde_json::from_slice::<super::json::UniqueJson>(
        br#"{"bindings":{"key":"first","key":"last"}}"#
    )
    .is_err());
    assert!(anchor::utc_millis("2026-02-29T00:00:00.000Z").is_err());
    assert_eq!(
        anchor::utc_millis("2000-02-29T00:00:00.000Z").unwrap(),
        951782400000
    );
}
