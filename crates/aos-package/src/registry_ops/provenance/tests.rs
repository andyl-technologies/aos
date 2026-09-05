//! Tests for signed publication provenance artifacts and append-only transparency records.

use super::{
    PACKAGE_PROVENANCE_TRANSPARENCY_LOG, PackageProvenanceTransparencyLogEntry,
    append_package_provenance_transparency_log, bind_documentation_provenance,
    publish_provenance_artifact, publish_provenance_ref,
    read_package_provenance_transparency_log_state,
};
use crate::registry_ops::attestation::package_nar_root_digest;
use crate::registry_ops::git::{commit_registry_paths, git};
use crate::registry_ops::mac::PublishExposeManifest;
use crate::registry_ops::provenance::staged::validate_staged_package_provenance_transparency_log;
use crate::registry_ops::provenance::statement::package_provenance_transparency_entry_hash;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::test_support::{
    TEST_PROVENANCE_REGISTRY, init_test_transparency_repo, sample_transparency_provenance,
    sign_test_provenance_statement, signed_provenance_statement, test_provenance_signer,
    verity_expose_manifest, write_sample_package_toml, write_sample_provenance_artifact,
    write_sample_store_record,
};
use crate::registry_ops::uki::sha256_hex;
use crate::types::{AttestationMeta, DocumentationArtifactMeta, ExposeMeta, PermissionsMeta};
use anyhow::Result;
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use tempfile::TempDir;

#[test]
fn publish_provenance_artifact_binds_nar_manifest_measurement_and_source() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let source = StorePathInfo {
        path: "/nix/store/srcdrv-webapp-1.0.0.drv".into(),
        nar_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        nar_size: 4096,
        references: vec![],
        closure_size: 4096,
    };
    let root_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let manifest = verity_expose_manifest(root_hash);
    let manifest_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        root_hash,
        manifest_digest,
    );
    let expected_provenance =
        publish_provenance_ref("webapp", "x86_64-linux", &measurement).unwrap();

    let signer = test_provenance_signer();
    let artifact = publish_provenance_artifact(
        TEST_PROVENANCE_REGISTRY,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &manifest,
        manifest_digest,
        &signer.signer,
    )
    .unwrap()
    .expect("provenance artifact");

    assert_eq!(artifact.path, expected_provenance);
    assert!(artifact.path.contains("/x86_64-linux/"));
    let statement = signed_provenance_statement(&artifact);
    assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(statement["predicateType"], "https://slsa.dev/provenance/v1");
    assert_eq!(
        statement["subject"][0]["name"].as_str(),
        Some(info.path.as_str())
    );
    assert_eq!(
        statement["subject"][0]["digest"]["sha256"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        statement["subject"][1]["digest"]["sha256"],
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    );
    assert_eq!(
        statement["subject"][2]["digest"]["sha256"],
        measurement.trim_start_matches("sha256:")
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["root_digest"].as_str(),
        Some(root_hash)
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["root_hash"].as_str(),
        Some(root_hash)
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["provenance"].as_str(),
        Some(expected_provenance.as_str())
    );
    let expected_source_uri = format!("nix:{}", source.path);
    assert_eq!(
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"].as_str(),
        Some(expected_source_uri.as_str())
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["sha256"]
            .as_str(),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
}

#[test]
fn publish_provenance_artifact_binds_non_verity_root_digest() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let manifest = PublishExposeManifest {
        expose: ExposeMeta {
            target: "aos-pkg-webapp.target".into(),
            units: vec!["webapp.service".into()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        },
        permissions: PermissionsMeta::default(),
        mac: None,
        _kernel: None,
        _firewall: None,
        _confinement: None,
    };
    let manifest_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let expected_root_digest = package_nar_root_digest(&info.nar_hash);
    let measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        &expected_root_digest,
        manifest_digest,
    );

    let signer = test_provenance_signer();
    let artifact = publish_provenance_artifact(
        TEST_PROVENANCE_REGISTRY,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        None,
        &manifest,
        manifest_digest,
        &signer.signer,
    )
    .unwrap()
    .expect("provenance artifact");

    assert_eq!(artifact.attestation.root_hash, None);
    assert_eq!(artifact.attestation.root_hash_sig, None);
    assert_eq!(
        artifact.attestation.root_digest.as_deref(),
        Some(expected_root_digest.as_str())
    );
    assert_eq!(
        artifact.attestation.measurement.as_deref(),
        Some(measurement.as_str())
    );
    let statement = signed_provenance_statement(&artifact);
    let params = &statement["predicate"]["buildDefinition"]["externalParameters"];
    assert_eq!(
        params["root_digest"].as_str(),
        Some(expected_root_digest.as_str())
    );
    assert!(params.get("root_hash").is_none());
    assert!(params.get("root_hash_sig").is_none());
}

#[test]
fn publish_provenance_paths_are_platform_scoped() {
    let measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );

    let x86 = publish_provenance_ref("webapp", "x86_64-linux", &measurement).unwrap();
    let arm = publish_provenance_ref("webapp", "aarch64-linux", &measurement).unwrap();

    assert_ne!(x86, arm);
    assert!(x86.contains("/x86_64-linux/"));
    assert!(arm.contains("/aarch64-linux/"));
}

#[test]
fn documented_provenance_paths_change_with_the_documentation_nar() {
    let measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let attestation = AttestationMeta {
        root_digest: Some(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        ),
        measurement: Some(measurement),
        ..AttestationMeta::default()
    };
    let documentation = |nar_hash: &str| DocumentationArtifactMeta {
        format: aos_doc_model::DOCUMENT_FORMAT.to_string(),
        store_path: "/nix/store/0000000000000000000000000000000e-webapp-docs.json".to_string(),
        nar_hash: nar_hash.to_string(),
        nar_size: 512,
        document_sha256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .to_string(),
        document_size: 384,
        semantic_schema_sha256:
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        system_module_nar_hash: None,
        references: vec![],
    };

    let first = bind_documentation_provenance(
        attestation.clone(),
        "webapp",
        "x86_64-linux",
        &documentation("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    )
    .unwrap();
    let second = bind_documentation_provenance(
        attestation,
        "webapp",
        "x86_64-linux",
        &documentation("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    )
    .unwrap();

    assert_ne!(first.provenance, second.provenance);
    assert!(
        first
            .provenance
            .as_deref()
            .is_some_and(|path| path.ends_with(
                "-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.intoto.jsonl"
            ))
    );
    assert!(
        second
            .provenance
            .as_deref()
            .is_some_and(|path| path.ends_with(
                "-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.intoto.jsonl"
            ))
    );
}

#[test]
fn publish_provenance_ref_rejects_malformed_measurements() {
    assert!(publish_provenance_ref("webapp", "x86_64-linux", "not-a-digest").is_err());
    assert!(publish_provenance_ref("webapp", "x86_64-linux", "sha256:abcd").is_err());
    assert!(
        publish_provenance_ref(
            "webapp",
            "x86_64-linux",
            "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
        )
        .is_err()
    );
}

#[test]
fn publish_provenance_artifact_preserves_sri_nar_hashes_as_nix_digests() {
    let package_nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let source_nar_hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: package_nar_hash.into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let source = StorePathInfo {
        path: "/nix/store/srcdrv-webapp-1.0.0.drv".into(),
        nar_hash: source_nar_hash.into(),
        nar_size: 4096,
        references: vec![],
        closure_size: 4096,
    };
    let root_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let manifest = verity_expose_manifest(root_hash);
    let manifest_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    let signer = test_provenance_signer();
    let artifact = publish_provenance_artifact(
        TEST_PROVENANCE_REGISTRY,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &manifest,
        manifest_digest,
        &signer.signer,
    )
    .unwrap()
    .expect("provenance artifact");

    let statement = signed_provenance_statement(&artifact);
    assert_eq!(
        statement["subject"][0]["digest"]["nix:narHash"].as_str(),
        Some(package_nar_hash)
    );
    assert!(statement["subject"][0]["digest"].get("sha256").is_none());
    assert_eq!(
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]
            ["nix:narHash"]
            .as_str(),
        Some(source_nar_hash)
    );
    assert!(
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]
            .get("sha256")
            .is_none()
    );
}

#[test]
fn append_package_provenance_transparency_log_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(tmp.path(), &artifact);

    let log_path = append_package_provenance_transparency_log(
        tmp.path(),
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    append_package_provenance_transparency_log(
        tmp.path(),
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();

    assert_eq!(
        log_path,
        tmp.path().join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG)
    );
    let content = fs::read_to_string(&log_path).unwrap();
    let entries = content
        .lines()
        .map(|line| serde_json::from_str::<PackageProvenanceTransparencyLogEntry>(line))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body.sequence, 0);
    assert_eq!(entries[0].body.previous_entry_hash, None);
    assert_eq!(entries[0].body.package, "webapp");
    assert_eq!(entries[0].body.version, "1.0.0");
    assert_eq!(entries[0].body.platform, "x86_64-linux");
    assert_eq!(entries[0].body.store_path, info.path);
    assert_eq!(
        entries[0].body.root_digest.as_deref(),
        artifact.attestation.root_digest.as_deref()
    );
    assert_eq!(
        entries[0].body.root_hash.as_deref(),
        artifact.attestation.root_hash.as_deref()
    );
    assert_eq!(
        entries[0].body.statement.jsonl_sha256,
        format!("sha256:{}", sha256_hex(artifact.jsonl.as_bytes()))
    );
    assert_eq!(
        entries[0].entry_hash,
        package_provenance_transparency_entry_hash(&entries[0].body).unwrap()
    );
    assert_eq!(
        read_package_provenance_transparency_log_state(&log_path).unwrap(),
        (1, Some(entries[0].entry_hash.clone()))
    );
}

#[test]
fn append_package_provenance_transparency_log_rejects_corrupt_history() {
    let tmp = TempDir::new().unwrap();
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(tmp.path(), &artifact);
    let log_path = append_package_provenance_transparency_log(
        tmp.path(),
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let content = fs::read_to_string(&log_path).unwrap();
    let mut entry: PackageProvenanceTransparencyLogEntry =
        serde_json::from_str(content.trim()).unwrap();
    entry.entry_hash = format!("sha256:{}", "0".repeat(64));
    fs::write(
        &log_path,
        format!("{}\n", serde_json::to_string(&entry).unwrap()),
    )
    .unwrap();

    let err = append_package_provenance_transparency_log(
        tmp.path(),
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("hash mismatch"));
}

#[test]
fn append_package_provenance_transparency_log_rejects_broken_previous_link() {
    let tmp = TempDir::new().unwrap();
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(tmp.path(), &artifact);
    let log_path = append_package_provenance_transparency_log(
        tmp.path(),
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let (_, _, mut second_artifact) = sample_transparency_provenance();
    second_artifact.path = second_artifact
        .path
        .replace(".intoto.jsonl", "-second.intoto.jsonl");
    second_artifact.attestation.provenance = Some(second_artifact.path.clone());
    let second_provenance_path = write_sample_provenance_artifact(tmp.path(), &second_artifact);
    append_package_provenance_transparency_log(
        tmp.path(),
        "worker",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &second_artifact,
        &second_provenance_path,
    )
    .unwrap();
    let content = fs::read_to_string(&log_path).unwrap();
    let mut entries = content
        .lines()
        .map(|line| serde_json::from_str::<PackageProvenanceTransparencyLogEntry>(line))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    entries[1].body.previous_entry_hash = Some(format!("sha256:{}", "1".repeat(64)));
    entries[1].entry_hash = package_provenance_transparency_entry_hash(&entries[1].body).unwrap();
    let rewritten = entries
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    fs::write(&log_path, format!("{rewritten}\n")).unwrap();

    let err = read_package_provenance_transparency_log_state(&log_path).unwrap_err();

    assert!(format!("{err:#}").contains("previous hash mismatch"));
}

#[test]
fn append_package_provenance_transparency_log_rejects_head_rewrite() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    let log_path = append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();
    fs::write(&log_path, "").unwrap();

    let err = append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("does not extend committed HEAD"));
}

#[test]
fn validate_staged_package_provenance_transparency_log_rejects_statement_digest_mismatch() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    fs::write(&provenance_path, "{}\n").unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
        ],
    )
    .unwrap();

    let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

    assert!(format!("{err:#}").contains("digest mismatch"));
}

#[test]
fn commit_registry_paths_rejects_prestaged_bad_transparency_log() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    let log_path = append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    let content = fs::read_to_string(&log_path).unwrap();
    let mut entry: PackageProvenanceTransparencyLogEntry =
        serde_json::from_str(content.trim()).unwrap();
    entry.entry_hash = format!("sha256:{}", "0".repeat(64));
    fs::write(
        &log_path,
        format!("{}\n", serde_json::to_string(&entry).unwrap()),
    )
    .unwrap();
    git(&repo, &["add", PACKAGE_PROVENANCE_TRANSPARENCY_LOG]).unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("does not extend committed HEAD"));
}

#[test]
fn validate_staged_package_provenance_transparency_log_rejects_statement_body_mismatch() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    let log_path = append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let content = fs::read_to_string(&log_path).unwrap();
    let mut entry: PackageProvenanceTransparencyLogEntry =
        serde_json::from_str(content.trim()).unwrap();
    entry.body.package = "other".to_string();
    entry.entry_hash = package_provenance_transparency_entry_hash(&entry.body).unwrap();
    fs::write(
        &log_path,
        format!("{}\n", serde_json::to_string(&entry).unwrap()),
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
        ],
    )
    .unwrap();

    let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

    assert!(format!("{err:#}").contains("externalParameters.package mismatch"));
}

#[test]
fn validate_staged_package_provenance_transparency_log_rejects_manifest_measurement_mismatch() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    let log_path = append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let mut statement = signed_provenance_statement(&artifact);
    let subjects = statement
        .get_mut("subject")
        .and_then(Value::as_array_mut)
        .unwrap();
    let manifest_subject = subjects
        .iter_mut()
        .find(|subject| {
            subject.get("name").and_then(Value::as_str)
                == Some("aos:permissions-manifest:webapp:1.0.0:x86_64-linux")
        })
        .unwrap();
    manifest_subject["digest"]["sha256"] = Value::String("e".repeat(64));
    let statement_jsonl = sign_test_provenance_statement(&statement);
    fs::write(&provenance_path, &statement_jsonl).unwrap();

    let content = fs::read_to_string(&log_path).unwrap();
    let mut entry: PackageProvenanceTransparencyLogEntry =
        serde_json::from_str(content.trim()).unwrap();
    entry.body.statement.jsonl_sha256 =
        format!("sha256:{}", sha256_hex(statement_jsonl.as_bytes()));
    entry.entry_hash = package_provenance_transparency_entry_hash(&entry.body).unwrap();
    fs::write(
        &log_path,
        format!("{}\n", serde_json::to_string(&entry).unwrap()),
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
        ],
    )
    .unwrap();

    let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

    assert!(format!("{err:#}").contains("measurement does not match permissions manifest"));
}

#[test]
fn validate_staged_package_provenance_transparency_log_accepts_matching_package_toml() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    let store_record = write_sample_store_record(&repo, &info, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();

    validate_staged_package_provenance_transparency_log(&repo).unwrap();
}

#[test]
fn validate_staged_package_provenance_transparency_log_rejects_package_toml_mismatch() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let bad_measurement = format!("sha256:{}", "f".repeat(64));
    let package_toml =
        write_sample_package_toml(&repo, &info, &source, &artifact, Some(&bad_measurement));
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();

    let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

    assert!(format!("{err:#}").contains("measurement mismatch"));
}

#[test]
fn commit_registry_paths_rejects_new_provenanced_root_unlogged_store_bytes() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    let bad_nar_hash = format!("sha256:{}", "e".repeat(64));
    let store_record = write_sample_store_record(&repo, &info, Some(&bad_nar_hash));
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("blesses NAR"));
}

#[test]
fn commit_registry_paths_rejects_new_provenanced_root_without_store_record() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("store record"));
}

#[test]
fn validate_staged_package_provenance_transparency_log_rejects_duplicate_package_platform() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    fs::OpenOptions::new()
        .append(true)
        .open(&package_toml)
        .unwrap()
        .write_all(
            b"\n[[versions]]\n\
              version = \"1.0.0\"\n\
              \n\
              [versions.platforms.x86_64-linux]\n\
              store_path = \"/nix/store/abc123-webapp-1.0.0\"\n\
              closure_size = 1\n\
              source_drv = \"\"\n\
              source_nar_hash = \"\"\n",
        )
        .unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();

    let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

    assert!(format!("{err:#}").contains("duplicate webapp 1.0.0 x86_64-linux"));
}
