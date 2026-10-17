//! Bounded actual-byte, independent-signer and source-owned report regressions.

use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
};

use aos_hub_core::{
    db::Database,
    direct_upload::{DirectProtectedProfile, direct_worker_emulated_script_id},
    mirror_acceptance::external_controlled::{
        ControlledExternalMirrorExecution, ControlledExternalMirrorInstallation,
        ControlledExternalMirrorPurpose, require_distinct_external_mirror_reviewer,
    },
    storage_work::StorageWorkKey,
};
use serde_json::json;

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
        .prefix("mirror-review-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(".")
        .unwrap();

    // Retain the actual directory while starting custody at the trusted test
    // working directory, as the existing OCI review fixtures do.
    let relative = Path::new(".").join(retained.path().file_name().unwrap());
    PrivateDirectory {
        _retained: retained,
        relative,
    }
}

fn file(directory: &Path, name: &str, bytes: &[u8]) -> MirrorReviewFile {
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    MirrorReviewFile {
        path: PathBuf::from(name),
        sha256: files::digest(bytes),
        byte_size: bytes.len() as u64,
    }
}

fn selection() -> ExternalMirrorReviewSelection {
    let selected = json!({"path":"unused", "sha256":"11".repeat(32), "byteSize":1});
    let mut inputs = serde_json::Map::new();
    for name in [
        "prerequisiteArtifact",
        "prerequisiteReviewKeys",
        "artifactManifest",
        "workerInstallation",
        "wasm",
        "script",
        "runner",
        "runtimeExecutable",
        "nativeServingExecutable",
        "configuration",
        "namespace",
        "nativeObservation",
        "nativeInput",
        "nativeReadiness",
        "listExport",
        "providerReport",
        "providerConformanceExecutable",
        "nixStoreExecutable",
        "conformanceKey",
    ] {
        inputs.insert(name.into(), selected.clone());
    }
    inputs.insert("providerJournal".into(), json!("journal"));
    let source = "22".repeat(32);
    serde_json::from_value(json!({"version":1,"reviewerKeyId":"functional-reviewer", "reviewerPublicKey":selected,
        "deploymentId":"deployment-1", "publicOrigin":"https://localhost:4673", "sourceDigest":source,
        "scriptVersion":direct_worker_emulated_script_id(&source).unwrap(), "profileDigest":"33".repeat(32),
        "upstreamBase":"https://aos.andyl.org:4778/fleet-mirror/0123456789abcdef0123456789abcdef",
        "placementPrefix":".aos-mirror-qualification/0123456789abcdef0123456789abcdef/final",
        "maximumObjectBytes":1024, "issuedAt":100, "validUntil":200, "inputs":inputs,"clocks":[]})).unwrap()
}

#[test]
fn actual_private_file_hash_count_bound_and_symlink_are_checked() {
    let directory = private_directory();
    let mut selected = file(directory.path(), "actual.json", b"actual");
    assert_eq!(
        assembly::read(directory.path(), &selected, 6)
            .unwrap()
            .as_slice(),
        b"actual"
    );
    assert!(assembly::read(directory.path(), &selected, 5).is_err());
    selected.byte_size += 1;
    assert!(assembly::read(directory.path(), &selected, 7).is_err());
    selected.byte_size -= 1;
    fs::write(directory.path().join(&selected.path), b"foreign").unwrap();
    assert!(assembly::read(directory.path(), &selected, 7).is_err());
    fs::write(directory.path().join(&selected.path), b"actual").unwrap();
    assert_eq!(
        assembly::read(directory.path(), &selected, 6)
            .unwrap()
            .as_slice(),
        b"actual"
    );

    let link = directory.path().join("link");
    symlink(&selected.path, &link).unwrap();
    selected.path = PathBuf::from("link");
    assert!(assembly::read(directory.path(), &selected, 7).is_err());
}

#[test]
fn independent_keys_compare_decoded_bytes_and_outputs_do_not_overwrite() {
    let first = SigningKey::from_bytes(&[0x31; 32]);
    let public = hex::encode(first.verifying_key().to_bytes());
    assert!(require_distinct_external_mirror_reviewer(&public, &public.to_uppercase()).is_err());
    let other = hex::encode(
        SigningKey::from_bytes(&[0x32; 32])
            .verifying_key()
            .to_bytes(),
    );
    require_distinct_external_mirror_reviewer(&public, &other).unwrap();
    assert!(require_distinct_external_mirror_reviewer(&public, "not-a-key").is_err());

    let directory = private_directory();
    let output = directory.path().join("candidate.json");
    files::write_new(&output, b"first").unwrap();
    assert!(files::write_new(&output, b"replacement").is_err());
    assert_eq!(fs::read(output).unwrap(), b"first");
}

#[test]
fn namespace_requires_the_actual_external_classes_and_current_tuple() {
    let selected = selection();
    let mut namespace: observations::Namespace = serde_json::from_value(json!({
        "version":1,"observationScope":"selected_external_copy_namespace_readback","observedAt":"actual bracket",
        "runnerPid":100,"runnerStartTicks":"900", "configurationSha256":selected.inputs.configuration.sha256,
        "runnerSha256":selected.inputs.runner.sha256,"scriptSha256":selected.inputs.script.sha256,
        "isolationModuleSha256":"44".repeat(32),"miniflareModuleSha256":"55".repeat(32),
        "applicationWorkerName":"app","sourceWorkerName":"app","sourceTriggerExclusions":[],
        "persistenceRoot":"/private/actual", "participatingIsolateIdentity":null,
        "namespaces":[{"bindingName":"EXTERNAL_OBJECT_GUARD","className":"ExternalObjectGuard", "workerName":"app","namespaceKey":"guard","objectIds":[]},
            {"bindingName":"HYBRID_BINDING_STATE","className":"HybridBindingState", "workerName":"app","namespaceKey":"binding","objectIds":[]}]})).unwrap();
    installation::validate_namespace(&namespace, &selected).unwrap();
    namespace.configuration_sha256 = "66".repeat(32);
    assert!(installation::validate_namespace(&namespace, &selected).is_err());
    namespace.configuration_sha256 = selected.inputs.configuration.sha256.clone();
    namespace.namespaces[0].class_name = "HybridR2ObjectGuard".into();
    assert!(installation::validate_namespace(&namespace, &selected).is_err());
}

#[test]
fn clock_requires_distinct_exact_authenticated_originals() {
    let directory = private_directory();
    let mut selected = selection();
    let secret = "77".repeat(32);
    let key = StorageWorkKey::new(&secret).unwrap();
    selected.inputs.conformance_key = file(directory.path(), "key", secret.as_bytes());
    for index in 0..2 {
        let nonce = format!("{:064x}", index + 1);
        let request =
            serde_json::to_vec(&json!({"version":1,"runId":"88".repeat(32), "nonce":nonce,
            "sourceDigest":selected.source_digest,"scriptVersion":selected.script_version,
            "expiresAt":"110","action":{"kind":"clock"}}))
            .unwrap();
        let request = file(directory.path(), &format!("request-{index}"), &request);
        let reply = serde_json::to_vec(&json!({"version":1,"nonce":nonce,"requestSha256":request.sha256,
            "sourceDigest":selected.source_digest,"scriptVersion":selected.script_version,"observedAtMillis":"99500",
            "result":{"kind":"clock","nonce":nonce,"observedAtMillis":"99500","uncertaintySeconds":"1"}})).unwrap();
        let signature = key
            .sign_body(
                &[
                    b"aos.direct-upload.qualification-reply.v1\0".as_slice(),
                    reply.as_slice(),
                ]
                .concat(),
            )
            .unwrap();
        let reply = file(directory.path(), &format!("reply-{index}"), &reply);
        let authentication = serde_json::to_vec(&json!({"status":200,"requestSha256":request.sha256,
            "responseSha256":reply.sha256,"sentAtMillis":"99400","receivedAtMillis":"99600","replySignature":signature})).unwrap();
        let authentication = file(directory.path(), &format!("auth-{index}"), &authentication);
        selected.clocks.push(MirrorClockFiles {
            request,
            reply,
            authentication,
        });
    }
    clock::validate(directory.path(), &selected, 1).unwrap();
    let original = selected.clocks[1].clone();
    selected.clocks[1] = selected.clocks[0].clone();
    assert!(clock::validate(directory.path(), &selected, 1).is_err());
    selected.clocks[1] = original;
    fs::write(
        directory.path().join(&selected.clocks[0].reply.path),
        b"foreign reply",
    )
    .unwrap();
    assert!(clock::validate(directory.path(), &selected, 1).is_err());
}

async fn protected_profile() -> aos_hub_core::direct_upload::DirectProtectedExternalProfile {
    let db = Database::open_in_memory().await.unwrap();
    let org = db
        .create_org("mirror-review", "Mirror review")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let binding = db
        .create_topology_binding(
            Some(org),
            "mirror-review",
            &owner.stable_id,
            "Mirror review",
            "s3",
            None,
            Some("qualified-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("test-region"),
            Some("private"),
        )
        .await
        .unwrap();
    let binding = db.binding(binding).await.unwrap().unwrap();
    let (_, profile) = crate::direct_upload::authority::external_acceptance_fixture(
        "https://localhost:4673",
        100,
        200,
        &binding,
    );
    let DirectProtectedProfile::External {
        profile,
        runtime_qualification,
    } = profile
    else {
        panic!("External fixture required");
    };
    aos_hub_core::direct_upload::DirectProtectedExternalProfile::new(profile, runtime_qualification)
        .unwrap()
}

#[tokio::test]
async fn shared_signature_current_window_and_candidate_substitution_are_checked() {
    let selected = selection();
    let key = SigningKey::from_bytes(&[0x35; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let mut artifact = ControlledExternalMirrorArtifact {
        version: 1,
        purpose: ControlledExternalMirrorPurpose::FullAndPullThroughFunctionalProbeV1,
        execution: ControlledExternalMirrorExecution::EmulatedExternal,
        reviewer_key_id: selected.reviewer_key_id,
        deployment_id: selected.deployment_id,
        public_origin: selected.public_origin,
        source_digest: selected.source_digest,
        script_version: selected.script_version,
        protected_profile: protected_profile().await,
        direct_evidence_sha256: "99".repeat(32),
        external_domain_sha256: "aa".repeat(32),
        upstream_base: selected.upstream_base,
        placement_prefix: selected.placement_prefix,
        maximum_object_bytes: 1024,
        installation: ControlledExternalMirrorInstallation {
            artifact_manifest_sha256: "ab".repeat(32),
            wasm_sha256: "ac".repeat(32),
            script_sha256: "ad".repeat(32),
            native_executable_sha256: "ae".repeat(32),
            configuration_sha256: "af".repeat(32),
            namespace_observation_sha256: "ba".repeat(32),
            clock_observation_sha256: "bb".repeat(32),
            provider_contract_observation_sha256: "bc".repeat(32),
            prerequisite_artifact_sha256: "bd".repeat(32),
        },
        issued_at: 100,
        valid_until: 200,
        signature: String::new(),
    };
    let mut candidate = ExternalMirrorReviewCandidate {
        version: 1,
        selection_sha256: "be".repeat(32),
        trusted_public_key: public.clone(),
        artifact: artifact.clone(),
    };
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
    require_signature(&artifact, &candidate, &public, 150).unwrap();
    assert!(require_signature(&artifact, &candidate, &public, 200).is_err());
    candidate.artifact.installation.native_executable_sha256 = "cc".repeat(32);
    assert!(require_signature(&artifact, &candidate, &public, 150).is_err());
    candidate.artifact = artifact.clone();
    candidate.artifact.signature.clear();
    artifact.placement_prefix = "foreign".into();
    assert!(require_signature(&artifact, &candidate, &public, 150).is_err());
}

#[tokio::test]
async fn provider_projection_rejects_foreign_physical_profile_partial_contract_and_versioned_claim()
{
    let selected = selection();
    let protected = protected_profile().await;
    let mut domain = observations::Domain {
        list_cohort: protected.profile.read_cohort.clone(),
        issuer_installation: protected.profile.issuer_installation.clone(),
        profile: protected,
        provider_contract: observations::ProviderContract {
            observation_sha256: selected.inputs.provider_report.sha256.clone(),
            read_identity: observations::ReadIdentity::GuardedVersionless,
            maximum_conditional_read_bytes:
                aos_hub_core::storage_authority::lease::LeaseInteger::new(8 * 1024 * 1024).unwrap(),
            strong_conditional_read: true,
            private_incomplete_upload: true,
            completed_upload_rejects_late_parts: true,
            checksum_enforced: true,
            positive_complete_identity: true,
            positive_empty_put_identity: false,
        },
    };
    let mut projected: observations::ProviderProjection = serde_json::from_value(json!({
        "version":1,"report_sha256":selected.inputs.provider_report.sha256,"original_sha256":"de".repeat(32),
        "executable_sha256":selected.inputs.provider_conformance_executable.sha256,
        "endpoint":"https://s3.fleet.test", "bucket":"qualified-bucket",
        "private_staging_prefix":domain.profile.profile.staging_prefix,
        "private_policy":domain.profile.profile.private_stage_policy,"policy_review_sha256":"df".repeat(32),
        "provider_contract":{"contract_id":"aos.operator-s3.protected-copy.v1",
            "evidence_digest":selected.inputs.provider_report.sha256,
            "versioned_conditional_range_read":false,"versioned_multipart_complete":false,
            "private_incomplete_upload":true,"completed_upload_rejects_late_parts":true,
            "abort_closes_upload_id":true,"upload_part_checksum_enforced":true,"versioned_empty_put":false,
            "maximum_copy_read_range_bytes":"8388608",
            "protected_versionless":{"strong_conditional_range_read":true,"positive_multipart_complete":true}}})).unwrap();
    provider::validate_projection(&projected, &selected, &domain).unwrap();
    projected.bucket = "foreign-bucket".into();
    assert!(provider::validate_projection(&projected, &selected, &domain).is_err());
    projected.bucket = "qualified-bucket".into();
    projected
        .provider_contract
        .protected_versionless
        .positive_multipart_complete = false;
    assert!(provider::validate_projection(&projected, &selected, &domain).is_err());
    projected
        .provider_contract
        .protected_versionless
        .positive_multipart_complete = true;
    domain.provider_contract.read_identity = observations::ReadIdentity::Versioned;
    assert!(provider::validate_projection(&projected, &selected, &domain).is_err());
}

#[test]
fn installed_tuple_cannot_borrow_another_outputs_path_with_identical_bytes() {
    let directory = private_directory();
    let selected = file(directory.path(), "selected", b"same bytes");
    let mut recorded = observations::TupleFile {
        file: directory.path().join(&selected.path),
        sha256: selected.sha256.clone(),
        byte_size: selected.byte_size,
        store_path: "/nix/store/00000000000000000000000000000000-test".into(),
        deriver: "/nix/store/00000000000000000000000000000000-test.drv".into(),
    };
    installation::selected_installed(directory.path(), &selected, &recorded).unwrap();
    let other = file(directory.path(), "other", b"same bytes");
    recorded.file = directory.path().join(other.path);
    assert!(installation::selected_installed(directory.path(), &selected, &recorded).is_err());
}

#[test]
fn classic_store_alias_hashes_only_its_regular_sibling_and_refuses_redirects() {
    let directory = private_directory();
    let image = file(directory.path(), "nix", b"test-only regular tool image");
    let alias = directory.path().join("nix-store");
    symlink("nix", &alias).unwrap();
    let resolved = installation::store_observer_image(&alias).unwrap();
    assert_eq!(resolved, directory.path().join(image.path));
    assert_eq!(
        files::hash_installed(&resolved).unwrap(),
        (image.sha256, image.byte_size)
    );
    fs::remove_file(&alias).unwrap();
    symlink("../foreign-nix", &alias).unwrap();
    assert!(installation::store_observer_image(&alias).is_err());
    fs::remove_file(&alias).unwrap();
    symlink("nix", &alias).unwrap();
    fs::remove_file(&resolved).unwrap();
    symlink("nix-store", &resolved).unwrap();
    assert!(files::hash_installed(&installation::store_observer_image(&alias).unwrap()).is_err());
}
