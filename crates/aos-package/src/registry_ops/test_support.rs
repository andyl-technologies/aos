//! Shared fixtures for registry operation tests.

use crate::config::ApmConfig;
use crate::provenance::TrustedProvenanceKey;
#[cfg(test)]
use crate::provenance::sign_statement_dsse_jsonl;
use crate::registry::keys::{KeysToml, RevokedKey, RosterKey};
use crate::registry::store::{DepEdge, NarBytes, Realisation};
use crate::registry::{keys, store};
use crate::registry_ops::config_modules::DerivedOptionDeclaration;
use crate::registry_ops::git::git;
use crate::registry_ops::images::files::{
    open_stable_regular_file_with_links, sha256_open_file, verify_stable_regular_file,
};
use crate::registry_ops::images::{PublishedImage, inspect_published_image_with};
use crate::registry_ops::mac::{
    PublishExposeManifest, compile_publish_selinux_profile, expected_publish_selinux_profile,
    publish_selinux_identifier_for_label,
};
use crate::registry_ops::provenance::{
    LocalPackageProvenanceSigner, PublishProvenanceArtifact, publish_provenance_artifact,
};
use crate::registry_ops::release::ReleaseTreeOptions;
use crate::registry_ops::store_paths::{RELEASE_POLICY_RELATIVE_PATH, StorePathInfo, extract_hash};
use crate::registry_ops::uki::SbFacts;
use crate::testutil;
use crate::types::{
    ApmSettings, ConfigModuleMeta, ConfigOutputMeta, ExposeMeta, ModuleAbiCompat, OwnedRoot,
    PermissionsMeta, ProfileScope, RegistryConfig, RegistryUploadAuthConfig, SigningKeySource,
};
use anyhow::{Context, Result};
use aos_cache::AuthOptions;
use aos_doc_model::{OptionType, Visibility};
use aos_oci_types::{
    Annotations, CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA, CONTAINER_RELEASE_SCHEMA_VERSION,
    CONTAINER_SIGNATURE_INPUT_SCHEMA, ContainerEvidenceMappingQualification,
    ContainerEvidenceQualification, ContainerEvidenceQualificationCheck, ContainerNixProvenance,
    ContainerOciRelease, ContainerRelease, ContainerReleaseEvidence, ContainerReleaseIdentity,
    ContainerSignatureInput, ContainerSignatureInputEvidence, Descriptor, MediaType,
    NixDefinitionIdentity, NixOutputIdentity, Platform, Sha256Digest,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub(in crate::registry_ops) fn documentation_declaration(
    path: &str,
    visibility: Visibility,
) -> DerivedOptionDeclaration {
    DerivedOptionDeclaration {
        path: path.split('.').map(str::to_string).collect(),
        path_str: path.to_string(),
        type_sig: "boolean".to_string(),
        option_type: OptionType::Bool,
        description: "Fixture option.".to_string(),
        default: None,
        example: None,
        visibility,
        read_only: false,
        contributable: false,
        owner: "nginx".to_string(),
    }
}

pub(in crate::registry_ops) fn write_direct_image_output(
    container: &Path,
    format: &str,
    targets: serde_json::Value,
) -> StorePathInfo {
    let root = container.join("00000000000000000000000000000000-image-output");
    let uki_root = container.join("uki-output");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&uki_root).unwrap();
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
    let logical_size = fs::metadata(&logical_path).unwrap().len();
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
    let uki_filename = "aos-test.efi";
    let uki_path = uki_root.join(uki_filename);
    fs::write(&uki_path, b"unsigned fake UKI bytes").unwrap();
    let (mut uki_file, uki_identity) =
        open_stable_regular_file_with_links(&uki_path, false).unwrap();
    let uki_sha256 = sha256_open_file(&mut uki_file, &uki_path).unwrap();
    verify_stable_regular_file(&uki_path, &uki_file, &uki_identity).unwrap();
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
        "virtualSizeBytes": logical_size,
        "sha256": &sha256,
        "logicalDiskSha256": &logical_sha256,
        "rootfsSha256": "2".repeat(64),
        "artifactBudgetsMiB": {
            "root": 1,
            "verity": 1,
            "initrd": 1,
            "uki": 1,
            "esp": 34,
            "runtimeClosure": 1,
            "download": 64,
        },
        "compatibleTargets": targets,
        "partitionTable": "gpt",
        "kernelParams": "",
        "partitions": [{
            "number": 1,
            "label": "ESP",
            "type": "esp",
            "filesystem": "vfat",
            "sizeMiB": 34,
            "offsetBytes": 0,
            "sizeBytes": 34 * 1024 * 1024,
        }, {
            "number": 2,
            "label": "root-a",
            "type": "root",
            "filesystem": "fake",
            "sizeMiB": 1,
            "offsetBytes": 34 * 1024 * 1024,
            "sizeBytes": 1024 * 1024,
        }],
        "esp": {"uki": "EFI/Linux/aos-test.efi", "sdBoot": "EFI/systemd/systemd-bootx64.efi"},
        "uki": {
            "filename": uki_filename,
            "espPath": "EFI/Linux/aos-test.efi",
            "byteSize": uki_identity.len,
            "sha256": uki_sha256,
            "signed": false,
            "measured": false,
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
    let payload_path = Path::new(&payload.path);
    let uki_path = payload_path
        .parent()
        .unwrap()
        .join("uki-output/aos-test.efi");
    inspect_published_image_with(
        format,
        payload,
        disk_store,
        info_store,
        &uki_path,
        "test",
        release,
        platform,
        None,
        |_uki, _db_cert| Ok(SbFacts::default()),
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

pub(in crate::registry_ops) fn config_module_fixture() -> ConfigModuleMeta {
    ConfigModuleMeta {
        config_output: ConfigOutputMeta {
            store_path: "/nix/store/0000000000000000000000000000000a-firewall-config".to_string(),
            nar_hash: "sha256:cc".to_string(),
            nar_size: 2048,
            references: vec![],
        },
        evaluation_base_lib: None,
        dependency_outputs: BTreeMap::new(),
        module_abi_compat: ModuleAbiCompat { min: 1, max: 2 },
        declares: vec!["firewall.allowedTCPPorts".to_string()],
        declaration_schema: vec![],
        requires: vec![],
        owns_roots: vec![OwnedRoot {
            root: "firewall".to_string(),
            interface_abi: 1,
            contributable: vec!["allowedTCPPorts".to_string()],
        }],
        contributes: vec![],
        artifacts: Default::default(),
        provides_capabilities: vec!["system.capabilities.dns-resolver".to_string()],
    }
}

pub(in crate::registry_ops) fn config_module_fixture_with_base() -> ConfigModuleMeta {
    let mut module = config_module_fixture();
    module.config_output.nar_hash =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    module.evaluation_base_lib = Some(ConfigOutputMeta {
        store_path: "/nix/store/0000000000000000000000000000000c-base-lib".to_string(),
        nar_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        nar_size: 1,
        references: vec![],
    });
    module
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

pub(in crate::registry_ops) fn write_publish_selinux_artifacts(root: &Path, label: &str) {
    let module_name = publish_selinux_identifier_for_label(label);
    let source_text = expected_publish_selinux_profile(label);
    let compiled = compile_publish_selinux_profile(&source_text, &module_name).unwrap();
    let profile_path = root.join(format!("mac/selinux/{module_name}.pp"));
    fs::create_dir_all(profile_path.parent().unwrap()).unwrap();
    fs::write(&profile_path, compiled.profile).unwrap();
    fs::write(
        root.join(format!("mac/selinux/{module_name}.mod")),
        compiled.module,
    )
    .unwrap();
    fs::write(
        root.join(format!("mac/selinux/{module_name}.te")),
        source_text,
    )
    .unwrap();
}

pub(in crate::registry_ops) fn verity_expose_manifest(root_hash: &str) -> PublishExposeManifest {
    PublishExposeManifest {
        expose: ExposeMeta {
            target: "aos-pkg-webapp.target".into(),
            units: vec!["webapp.service".into()],
            images: vec![crate::types::SysrootImageEntry {
                format: "ext4-verity".into(),
                store_path: "/nix/store/imagehash111-webapp-root".into(),
                nar_hash: "sha256:image".into(),
                nar_size: 4096,
                delivery: crate::types::test_image_delivery("raw"),
                sb_signer_cert_sha256: None,
                sbat: Vec::new(),
                expected_pcr11: None,
                ukis: Vec::new(),
                recovery_ukis: Vec::new(),
                recovery_bundle: None,
                root_image: Some("root.img".into()),
                root_verity: Some("root.verity".into()),
                root_hash: Some(root_hash.into()),
                root_hash_sig: Some("root.roothash.p7s".into()),
            }],
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
    }
}

pub(in crate::registry_ops) fn synthetic_pe_section(
    name: &[u8],
    virtual_size: u32,
    raw: &[u8],
) -> Vec<u8> {
    assert!(name.len() <= 8);
    let pe_offset = 0x40_usize;
    let optional_size = 112_usize;
    let section_table = pe_offset + 4 + 20 + optional_size;
    let raw_offset = section_table + 40;
    let mut pe = vec![0_u8; raw_offset + raw.len()];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    pe[pe_offset..pe_offset + 4].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
    let coff = pe_offset + 4;
    pe[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
    pe[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
    pe[coff + 20..coff + 22].copy_from_slice(&0x020b_u16.to_le_bytes());
    pe[section_table..section_table + name.len()].copy_from_slice(name);
    pe[section_table + 8..section_table + 12].copy_from_slice(&virtual_size.to_le_bytes());
    pe[section_table + 16..section_table + 20].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    pe[section_table + 20..section_table + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
    pe[raw_offset..].copy_from_slice(raw);
    pe
}

/// Wrap a DER value in a SEQUENCE/SET/context tag with a short length.
pub(in crate::registry_ops) fn der_wrap(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 0x80, "test helper only handles short form");
    let mut out = vec![tag, value.len() as u8];
    out.extend_from_slice(value);
    out
}

pub(in crate::registry_ops) const SBCERT_A: &str =
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

pub(in crate::registry_ops) const SBCERT_B: &str =
    "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

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
    .unwrap();
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
