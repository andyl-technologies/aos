//! Shared fixtures for registry operation tests.

use crate::config::ApmConfig;
use crate::provenance::TrustedProvenanceKey;
#[cfg(test)]
use crate::provenance::sign_statement_dsse_jsonl;
use crate::registry::keys::{KeysToml, RevokedKey, RosterKey};
use crate::registry::store::{DepEdge, NarBytes, Realisation};
use crate::registry::{keys, store};
use crate::registry_ops::attestation::package_nar_root_digest;
use crate::registry_ops::git::git;
use crate::registry_ops::images::files::{
    open_stable_regular_file_with_links, sha256_open_file, verify_stable_regular_file,
};
use crate::registry_ops::images::{PublishedImage, inspect_published_image};
use crate::registry_ops::provenance::{
    LocalPackageProvenanceSigner, PublishProvenanceArtifact, publish_provenance_ref,
    publish_provenance_statement,
};
use crate::registry_ops::release::ReleaseTreeOptions;
use crate::registry_ops::store_paths::{RELEASE_POLICY_RELATIVE_PATH, StorePathInfo, extract_hash};
use crate::testutil;
use crate::types::{
    ApmSettings, AttestationMeta, ProfileScope, RegistryConfig, RegistryUploadAuthConfig,
    SigningKeySource,
};
use anyhow::{Context, Result};
use aos_cache::AuthOptions;
use aos_oci_types::{
    Annotations, CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA, CONTAINER_RELEASE_SCHEMA_VERSION,
    CONTAINER_SIGNATURE_INPUT_SCHEMA, ContainerEvidenceMappingQualification,
    ContainerEvidenceQualification, ContainerEvidenceQualificationCheck, ContainerNixProvenance,
    ContainerOciRelease, ContainerRelease, ContainerReleaseEvidence, ContainerReleaseIdentity,
    ContainerSignatureInput, ContainerSignatureInputEvidence, Descriptor, MediaType,
    NixDefinitionIdentity, NixOutputIdentity, Platform, Sha256Digest,
};
use serde_json::Value;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub(in crate::registry_ops) fn write_direct_image_output(
    container: &Path,
    format: &str,
    targets: serde_json::Value,
) -> StorePathInfo {
    let root = container.join("00000000000000000000000000000000-image-output");
    fs::create_dir_all(&root).unwrap();
    let extension = if format == "raw" { "img.zst" } else { format };
    let filename = format!("aos-test.{extension}");
    let image_path = root.join(&filename);
    let logical_path = container.join("logical.raw");
    fs::write(&logical_path, b"exact disk image bytes").unwrap();
    OpenOptions::new()
        .write(true)
        .open(&logical_path)
        .unwrap()
        .set_len(36 * 1024 * 1024)
        .unwrap();
    let (mut logical_file, logical_identity) =
        open_stable_regular_file_with_links(&logical_path, false).unwrap();
    let logical_sha256 = sha256_open_file(&mut logical_file, &logical_path).unwrap();
    verify_stable_regular_file(&logical_path, &logical_file, &logical_identity).unwrap();
    if format == "raw" {
        logical_file.seek(SeekFrom::Start(0)).unwrap();
        let image_file = fs::File::create(&image_path).unwrap();
        zstd::stream::copy_encode(logical_file, image_file, 1).unwrap();
    } else {
        fs::copy(&logical_path, &image_path).unwrap();
    }
    let (mut image_file, image_identity) =
        open_stable_regular_file_with_links(&image_path, false).unwrap();
    let sha256 = sha256_open_file(&mut image_file, &image_path).unwrap();
    verify_stable_regular_file(&image_path, &image_file, &image_identity).unwrap();
    let media_type = match format {
        "raw" => "application/vnd.aos.disk-image.raw+zstd",
        "qcow2" => "application/vnd.aos.disk-image.qcow2",
        "vmdk" => "application/x-vmdk",
        "vhd" => "application/vnd.aos.disk-image.vhd",
        other => panic!("unsupported fixture format {other}"),
    };
    let info = serde_json::json!({
        "schemaVersion": 2,
        "name": "test",
        "version": "2026.08",
        "architecture": "x86_64",
        "platform": "x86_64-linux",
        "format": format,
        "filename": filename,
        "mediaType": media_type,
        "compression": if format == "raw" { "zstd" } else { "none" },
        "byteSize": fs::metadata(&image_path).unwrap().len(),
        "sha256": &sha256,
        "logicalDiskSha256": &logical_sha256,
        "compatibleTargets": targets,
        "providerContract": {
            "schema": "aos.test-boot-artifacts/v1",
            "opaqueEvidence": {"provider-owned": true},
        },
    });
    fs::write(
        root.join("image-info.json"),
        serde_json::to_vec(&info).unwrap(),
    )
    .unwrap();
    StorePathInfo {
        path: root.display().to_string(),
        nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
        nar_size: 128,
        references: Vec::new(),
        closure_size: 128,
    }
}

pub(in crate::registry_ops) fn write_test_image_projections(
    payload: &StorePathInfo,
) -> Result<(StorePathInfo, StorePathInfo)> {
    let payload_path = Path::new(&payload.path);
    let container = payload_path.parent().unwrap();
    let producer: serde_json::Value =
        serde_json::from_slice(&fs::read(payload_path.join("image-info.json"))?)?;
    let filename = producer["filename"].as_str().unwrap();
    let disk_path = container.join("11111111111111111111111111111111-image-disk");
    let info_path = container.join("22222222222222222222222222222222-image-info");
    fs::copy(payload_path.join(filename), &disk_path)?;
    fs::copy(payload_path.join("image-info.json"), &info_path)?;
    let artifact = |path: &Path, marker: char| StorePathInfo {
        path: path.display().to_string(),
        nar_hash: format!("sha256:{}", marker.to_string().repeat(52)),
        nar_size: 256,
        references: Vec::new(),
        closure_size: 256,
    };
    let disk_store = artifact(&disk_path, '1');
    let info_store = artifact(&info_path, '2');
    Ok((disk_store, info_store))
}

pub(in crate::registry_ops) fn inspect_test_image(
    format: &str,
    payload: StorePathInfo,
    release: &str,
    platform: &str,
) -> Result<PublishedImage> {
    let (disk_store, info_store) = write_test_image_projections(&payload)?;
    inspect_published_image(
        format,
        payload,
        disk_store,
        info_store,
        "aos.test-boot-artifacts/v1",
        "test",
        release,
        platform,
    )
}

pub(in crate::registry_ops) fn rewrite_test_image_parent(
    store: &StorePathInfo,
    release: &str,
    platform: &str,
) {
    let path = Path::new(&store.path).join("image-info.json");
    let mut info: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    info["version"] = serde_json::json!(release);
    info["platform"] = serde_json::json!(platform);
    info["architecture"] = serde_json::json!(platform.split('-').next().unwrap_or_default());
    fs::write(path, serde_json::to_vec(&info).unwrap()).unwrap();
}
pub(in crate::registry_ops) fn test_release_options(tmp: &TempDir) -> ReleaseTreeOptions {
    ReleaseTreeOptions {
        version: semver::Version::parse("1.0.0").unwrap(),
        signing_key: tmp
            .path()
            .join("signing.key")
            .to_string_lossy()
            .into_owned(),
        tuf_signing_keys: Vec::new(),
        channel: None,
        init_channel: false,
        count: None,
        partitions: None,
        cache_dir: tmp.path().join("cache"),
        cache_key: None,
        cache_url: None,
        cache_url_explicit: false,
        cache_priority: 40,
        cache_priority_explicit: false,
        has_store_roots: false,
        no_skip: false,
        upload_urls: Vec::new(),
        upload_auth: AuthOptions::default(),
        dry_run: false,
        resume: false,
        jobs: None,
        store_publish: None,
        container_release: None,
        cache_max_age_days: 30,
    }
}

pub(in crate::registry_ops) fn container_release_inputs(
    version: &str,
) -> (ContainerRelease, ContainerSignatureInput) {
    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: u64::try_from(label.len()).expect("fixture size"),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    let mut manifest = descriptor(MediaType::OciImageManifest, "manifest");
    manifest.platform = Some(Platform::linux_amd64());
    let qualification = ContainerEvidenceQualification {
        schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
        mapping: ContainerEvidenceMappingQualification {
            complete: true,
            unknown_paths: Vec::new(),
        },
        corresponding_source: ContainerEvidenceQualificationCheck {
            complete: true,
            unknown_paths: Vec::new(),
        },
        licensing: ContainerEvidenceQualificationCheck {
            complete: true,
            unknown_paths: Vec::new(),
        },
        ready_for_verified_publication: true,
    };
    let release = ContainerRelease {
        schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
        media_type: MediaType::AosContainerRelease,
        identity: ContainerReleaseIdentity {
            release: version.to_string(),
            package: "aos".to_string(),
            package_version: "0.1.0".to_string(),
            image: "aos".to_string(),
        },
        oci: ContainerOciRelease {
            index: descriptor(MediaType::OciImageIndex, "index"),
            platform_manifests: vec![manifest],
        },
        nix: ContainerNixProvenance {
            definition: NixDefinitionIdentity {
                attribute: "containerImages.aos".to_string(),
                derivation_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv"
                    .to_string(),
            },
            output: NixOutputIdentity {
                name: "out".to_string(),
                store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container".to_string(),
            },
            closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
        },
        qualification: qualification.clone(),
        evidence: ContainerReleaseEvidence {
            abilities: evidence_descriptor(MediaType::AosContainerStaticAbilities, "abilities"),
            sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
            source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
            license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
            provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
            signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
        },
    };
    let input = ContainerSignatureInput {
        schema: CONTAINER_SIGNATURE_INPUT_SCHEMA.to_string(),
        identity: release.identity.clone(),
        oci: release.oci.clone(),
        nix: release.nix.clone(),
        evidence: ContainerSignatureInputEvidence {
            abilities: release.evidence.abilities.clone(),
            sbom: release.evidence.sbom.clone(),
            source: release.evidence.source.clone(),
            license: release.evidence.license.clone(),
            provenance: release.evidence.provenance.clone(),
        },
        qualification,
    };
    (release, input)
}

pub(in crate::registry_ops) fn release_policy_info(
    path: &Path,
    references: Vec<String>,
) -> StorePathInfo {
    StorePathInfo {
        path: path.to_string_lossy().into_owned(),
        nar_hash: String::new(),
        nar_size: 0,
        references,
        closure_size: 0,
    }
}

pub(in crate::registry_ops) fn write_internal_release_policy(path: &Path, identity: &str) {
    fs::create_dir_all(path.join("nix-support")).unwrap();
    fs::write(
        path.join(RELEASE_POLICY_RELATIVE_PATH),
        format!(
            "policy_version=1\nartifact_role=internal-component\nstandalone_release=false\nrelease_via=crucible\ncorresponding_source_required=true\ncorresponding_source_identity={identity}\n"
        ),
    )
    .unwrap();
}

pub(in crate::registry_ops) struct TestSigningFixture {
    pub(in crate::registry_ops) trusted_key: String,
    pub(in crate::registry_ops) private_key: PathBuf,
}

pub(in crate::registry_ops) fn test_registry_config(
    name: &str,
    upload_auth: Option<RegistryUploadAuthConfig>,
) -> RegistryConfig {
    RegistryConfig {
        name: name.into(),
        url: format!("https://registry.example.com/{name}"),
        priority: 500,
        enabled: true,
        commit: None,
        branch: None,
        channel: None,
        tag: None,
        version: None,
        pin: None,
        max_staleness_seconds: None,
        caches: Vec::new(),
        cache: Default::default(),
        upload_auth,
        signing_keys: Default::default(),
        signing: None,
    }
}

pub(in crate::registry_ops) fn test_config_with_signing_key(
    registry: &str,
    key_id: &str,
    private_key: &Path,
) -> ApmConfig {
    let mut registry_config = test_registry_config(registry, None);
    registry_config.signing_keys.insert(
        key_id.to_string(),
        SigningKeySource::Path(private_key.to_str().unwrap().to_string()),
    );
    ApmConfig {
        settings: ApmSettings::default(),
        registries: vec![(registry_config, None)],
        scope: ProfileScope::User,
    }
}

pub(in crate::registry_ops) struct TestProvenanceSigner {
    pub(in crate::registry_ops) _tmp: TempDir,
    pub(in crate::registry_ops) signer: LocalPackageProvenanceSigner,
    pub(in crate::registry_ops) trusted_key: String,
}

pub(in crate::registry_ops) const TEST_PROVENANCE_REGISTRY: &str = "test";

const TEST_PROVENANCE_KEY_ID: &str = "builder";

pub(in crate::registry_ops) fn test_provenance_signer() -> TestProvenanceSigner {
    let tmp = TempDir::new().unwrap();
    let key = write_seeded_signing_key(
        tmp.path(),
        TEST_PROVENANCE_REGISTRY,
        [42_u8; 32],
        TEST_PROVENANCE_KEY_ID,
    );
    TestProvenanceSigner {
        signer: LocalPackageProvenanceSigner {
            key_id: TEST_PROVENANCE_KEY_ID.to_string(),
            key_path: key.private_key.clone(),
            trusted_key: key.trusted_key.clone(),
        },
        trusted_key: key.trusted_key,
        _tmp: tmp,
    }
}

pub(in crate::registry_ops) fn signed_provenance_statement(
    artifact: &PublishProvenanceArtifact,
) -> serde_json::Value {
    let trusted = vec![TrustedProvenanceKey {
        key_id: TEST_PROVENANCE_KEY_ID.to_string(),
        key: test_provenance_signer().trusted_key,
        retired_before_sequence: None,
        package_contract_retired_before_sequence: None,
    }];
    let (statement, key_id) =
        crate::provenance::verify_statement_dsse_jsonl(&artifact.jsonl, &trusted).unwrap();
    assert_eq!(key_id, TEST_PROVENANCE_KEY_ID);
    statement
}

pub(in crate::registry_ops) fn sign_test_provenance_statement(statement: &Value) -> String {
    let signer = test_provenance_signer();
    sign_statement_dsse_jsonl(
        statement,
        TEST_PROVENANCE_KEY_ID,
        signer.signer.key_path.as_path(),
    )
    .unwrap()
}

pub(in crate::registry_ops) fn write_test_roster(
    dir: &Path,
    key_id: &str,
    trusted_key: &str,
    revoked: &[&str],
) -> Result<()> {
    let roster = KeysToml {
        active: vec![RosterKey {
            id: key_id.to_string(),
            key: trusted_key.to_string(),
        }],
        revoked: revoked
            .iter()
            .map(|id| RevokedKey {
                id: (*id).to_string(),
                key: None,
                provenance_before_sequence: None,
                package_contract_before_sequence: None,
                reason: Some("test".into()),
            })
            .collect(),
        ..KeysToml::default()
    };
    keys::write_keys_toml(dir, &roster)
}

pub(in crate::registry_ops) fn write_test_signing_key(
    root: &Path,
    registry: &str,
) -> TestSigningFixture {
    write_seeded_signing_key(root, registry, [9u8; 32], "registry_ed25519")
}

pub(in crate::registry_ops) fn write_seeded_signing_key(
    root: &Path,
    registry: &str,
    seed: [u8; 32],
    name: &str,
) -> TestSigningFixture {
    let signing_dir = root.join("signing");
    fs::create_dir_all(&signing_dir).unwrap();

    let keypair = crate::sshkey::Ed25519Keypair::from_seed(seed);
    let private_key = signing_dir.join(name);

    fs::write(&private_key, keypair.to_openssh_private_key(registry)).unwrap();
    restrict_private_key_permissions(&private_key).unwrap();

    TestSigningFixture {
        trusted_key: keypair.trust_key_line(registry),
        private_key,
    }
}

#[cfg(unix)]
fn restrict_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_private_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub(in crate::registry_ops) fn sample_transparency_provenance()
-> (StorePathInfo, StorePathInfo, PublishProvenanceArtifact) {
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
    let root_digest = package_nar_root_digest(&info.nar_hash);
    let binding_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        &root_digest,
        binding_digest,
    );
    let provenance = publish_provenance_ref("webapp", "x86_64-linux", &measurement).unwrap();
    let attestation = AttestationMeta {
        root_digest: Some(root_digest),
        provenance: Some(provenance.clone()),
        measurement: Some(measurement),
        ..AttestationMeta::default()
    };
    let signer = test_provenance_signer();
    let statement = publish_provenance_statement(
        TEST_PROVENANCE_REGISTRY,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        binding_digest,
        &attestation,
        &signer.signer.key_id,
    )
    .unwrap();
    let artifact = PublishProvenanceArtifact {
        path: provenance,
        jsonl: sign_statement_dsse_jsonl(
            &statement,
            TEST_PROVENANCE_KEY_ID,
            signer.signer.key_path.as_path(),
        )
        .unwrap(),
        attestation,
    };
    (info, source, artifact)
}

pub(in crate::registry_ops) fn write_sample_provenance_artifact(
    root: &Path,
    artifact: &PublishProvenanceArtifact,
) -> PathBuf {
    let path = root.join(&artifact.path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &artifact.jsonl).unwrap();
    path
}

pub(in crate::registry_ops) fn write_sample_store_record(
    root: &Path,
    info: &StorePathInfo,
    extra_nar_hash: Option<&str>,
) -> PathBuf {
    write_sample_store_record_with_deps(root, info, &[], extra_nar_hash)
}

pub(in crate::registry_ops) fn write_sample_store_record_with_deps(
    root: &Path,
    info: &StorePathInfo,
    deps: &[&str],
    extra_nar_hash: Option<&str>,
) -> PathBuf {
    let ia_hash = extract_hash(&info.path);
    let path = store::entry_path(root, ia_hash).unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let dep_edges = deps
        .iter()
        .map(|dep| DepEdge {
            dep_ia: extract_hash(dep).to_string(),
            dep_ca: None,
        })
        .collect::<Vec<_>>();
    let mut entry = store::StoreEntry {
        realisations: vec![Realisation {
            nar: NarBytes::from_hash(&info.nar_hash, info.nar_size).unwrap(),
            ca: None,
            deps: dep_edges,
        }],
    };
    if let Some(nar_hash) = extra_nar_hash {
        entry.realisations.push(Realisation {
            nar: NarBytes::from_hash(nar_hash, info.nar_size + 1).unwrap(),
            ca: Some(store::normalize_digest(nar_hash).unwrap()),
            deps: Vec::new(),
        });
    }
    fs::write(&path, store::serialize_entry(&entry)).unwrap();
    path
}

pub(in crate::registry_ops) fn write_sample_package_toml(
    root: &Path,
    info: &StorePathInfo,
    source: &StorePathInfo,
    artifact: &PublishProvenanceArtifact,
    measurement_override: Option<&str>,
) -> PathBuf {
    let path = root.join("packages").join("w").join("webapp.toml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let root_digest = artifact.attestation.root_digest.as_deref().unwrap();
    let root_hash = artifact.attestation.root_hash.as_deref().unwrap();
    let root_hash_sig = artifact.attestation.root_hash_sig.as_deref().unwrap();
    let provenance = artifact.attestation.provenance.as_deref().unwrap();
    let measurement = measurement_override
        .or(artifact.attestation.measurement.as_deref())
        .unwrap();
    fs::write(
        &path,
        format!(
            "[package]\n\
             name = \"webapp\"\n\
             description = \"\"\n\
             \n\
             [[versions]]\n\
             version = \"1.0.0\"\n\
             \n\
             [versions.platforms.x86_64-linux]\n\
             store_path = \"{}\"\n\
             closure_size = 1\n\
             source_drv = \"{}\"\n\
             source_nar_hash = \"{}\"\n\
             root_digest = \"{}\"\n\
             root_hash = \"{}\"\n\
             root_hash_sig = \"{}\"\n\
             provenance = \"{}\"\n\
             measurement = \"{}\"\n",
            info.path,
            source.path,
            source.nar_hash,
            root_digest,
            root_hash,
            root_hash_sig,
            provenance,
            measurement
        ),
    )
    .unwrap();
    path
}

pub(in crate::registry_ops) fn init_test_transparency_repo(repo: &Path) {
    git(
        repo,
        &["init", "--object-format=sha256", "--initial-branch=main"],
    )
    .unwrap();
    git(repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        format!("[registry]\nname = \"{TEST_PROVENANCE_REGISTRY}\"\n"),
    )
    .unwrap();
    let keypair = crate::sshkey::Ed25519Keypair::from_seed([42_u8; 32]);
    keys::write_keys_toml(
        repo,
        &KeysToml {
            active: vec![RosterKey {
                id: TEST_PROVENANCE_KEY_ID.to_string(),
                key: keypair.trust_key_line(TEST_PROVENANCE_REGISTRY),
            }],
            ..KeysToml::default()
        },
    )
    .unwrap();
}

/// Initialize a git repository with one commit at `dir`.
pub(in crate::registry_ops) fn init_authoring_clone(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    testutil::git(dir, &["init"]);
    fs::write(dir.join("registry.toml"), "[registry]\n").unwrap();
    testutil::git(dir, &["add", "."]);
    testutil::git(dir, &["commit", "-m", "init"]);
}
