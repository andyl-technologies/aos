//! Authentication and retention regression tests.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use anyhow::Result;
use aos_ability_model::document::{PackageSubject, PlatformIdentity};
use aos_ability_model::{
    AbilityActivationMode, ArtifactReference, ImplementationKind, InterfaceDocument, LocalKey,
    PackageDocument, PackageImplementation, RequiredFeature, VersionedDocument, encode_canonical,
};
use aos_contract::Sha256Digest;
use base64::Engine as _;
use tempfile::TempDir;

use super::{
    AbilityPackageCoordinate, AbilityRetentionVerifier, CLOSURE_DIGEST_DOMAIN,
    VerifiedAbilityPackage, VerifiedAbilityPackageSet, VerifiedAbilityRetentionManifest,
    ability_provenance_statement, collect_distinct_artifacts, validate_ability_package_meta,
    validate_store_root, verify_ability_package,
};
use crate::provenance::{TrustedProvenanceKey, sign_statement_dsse_jsonl};
use crate::types::{
    AbilityArtifactRetentionMeta, AbilityClosureMemberMeta, AbilityPackageMeta, AttestationMeta,
    PackageMeta, PermissionsMeta,
};

const STORE_ROOT: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-ability-artifact";
const COMPANION_ROOT: &str = "/nix/store/123456789abcdfghijklmnpqrsvwxyz0-demo-abilities";
const REGISTRY: &str = "test-registry";
const KEY_ID: &str = "ability-builder";

#[test]
fn production_nix_companion_round_trips_through_native_contracts() {
    let Ok(companion) = std::env::var("AOS_TEST_ABILITY_PACKAGE_SMOKE") else {
        return;
    };
    let manifest_path = PathBuf::from(&companion).join("package.json");
    let manifest = fs::read(&manifest_path).unwrap();
    let package = super::decode_package_manifest(&manifest).unwrap();

    assert_eq!(encode_canonical(&package).unwrap(), manifest);
    assert_eq!(package.package.name.as_str(), "ability-package-smoke");
    assert!(package.package.source.store_path.ends_with(".drv"));
    assert_ne!(package.package.payload, package.package.source);
    assert_eq!(package.exports.len(), 1);
    assert_eq!(package.implementation.providers.len(), 1);
    let edge = package
        .requirements
        .iter()
        .find(|requirement| requirement.alias.as_str() == "canonical-edge")
        .unwrap();
    assert_eq!(edge.accepted_interfaces[0].abi.get(), u32::MAX);
    let sample =
        edge.fallback.as_ref().unwrap().outputs[&LocalKey::new("sample").unwrap()].as_json();
    assert_eq!(sample["label"], "café 東京 😀");
    assert_eq!(sample["maximum"], 9_007_199_254_740_991_i64);
    assert_eq!(sample["minimum"], -9_007_199_254_740_991_i64);

    let declaration = &package.exports[0];
    let provider = &package.implementation.providers[0];
    assert_eq!(declaration.interface, provider.interface);
    assert_eq!(
        declaration.implementation,
        provider.descriptor_digest().unwrap()
    );
    let compose = aos_ability_model::LocalKey::new("compose").unwrap();
    let transition = aos_ability_model::LocalKey::new("transition").unwrap();
    assert_eq!(package.module_entry_points[&compose], provider.artifact);
    assert_eq!(package.module_entry_points[&transition], provider.artifact);
    assert!(matches!(
        provider.implementation,
        ImplementationKind::PureComposition { .. }
    ));

    let interface_path = PathBuf::from(&companion)
        .join("interfaces")
        .join(format!("{}.json", declaration.interface.descriptor.hex()));
    let interface_bytes = fs::read(interface_path).unwrap();
    let interface = aos_ability_model::decode_canonical::<InterfaceDocument>(
        &interface_bytes,
        aos_ability_model::ABILITY_LIMITS_V1,
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(encode_canonical(&interface).unwrap(), interface_bytes);
    assert_eq!(interface.interface_key().unwrap(), declaration.interface);

    let package_digest = package.content_digest().unwrap();
    let activation_mode = package.activation_mode;
    let sealed = VerifiedAbilityPackage {
        artifacts: collect_distinct_artifacts(&package).unwrap(),
        package,
        manifest_sha256: Sha256Digest::of_bytes(&manifest),
        package_digest,
        package_name: "ability-package-smoke".to_string(),
        package_version: "1.0.0".to_string(),
        platform: "x86_64-linux".to_string(),
        activation_mode,
        retention: VerifiedAbilityRetentionManifest {
            companion_store_path: companion,
            companion_nar_hash: digest('8'),
            companion_nar_size: 1,
            companion_references: Vec::new(),
            artifacts: Vec::new(),
        },
    };
    let set = VerifiedAbilityPackageSet::from_verified(vec![sealed]).unwrap();
    let catalog = set.planning_catalog().unwrap();
    assert_eq!(catalog.packages().len(), 1);
    let _composer = catalog.composer();
}

struct TestFixture {
    _key_dir: TempDir,
    key_path: PathBuf,
    trusted_keys: Vec<TrustedProvenanceKey>,
    package_meta: PackageMeta,
    manifest_bytes: Vec<u8>,
    provenance_jsonl: String,
}

impl TestFixture {
    fn new() -> Self {
        let member = AbilityClosureMemberMeta {
            store_path: STORE_ROOT.to_string(),
            nar_hash: digest('2').to_string(),
            nar_size: 128,
            references: Vec::new(),
        };
        let closure = vec![member];
        let closure_digest = Sha256Digest::of_canonical(CLOSURE_DIGEST_DOMAIN, &closure).unwrap();
        let artifact = ArtifactReference {
            content: digest('1'),
            store_path: STORE_ROOT.to_string(),
            nar_hash: digest('2'),
            closure: closure_digest,
        };
        let package = PackageDocument {
            schema: PackageDocument::SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").unwrap()],
            activation_mode: AbilityActivationMode::ContractsOnly,
            package: PackageSubject {
                name: aos_ability_model::LocalKey::new("demo").unwrap(),
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: Vec::new(),
            exports: Vec::new(),
            requirements: Vec::new(),
            module_entry_points: BTreeMap::new(),
            implementation: PackageImplementation {
                providers: Vec::new(),
                handlers: BTreeMap::new(),
            },
            ownership: Vec::new(),
        };
        let manifest_bytes = encode_canonical(&package).unwrap();
        let ability = AbilityPackageMeta {
            store_path: COMPANION_ROOT.to_string(),
            nar_hash: digest('3').to_string(),
            nar_size: 256,
            references: Vec::new(),
            manifest_sha256: Sha256Digest::of_bytes(&manifest_bytes).to_string(),
            manifest_size: manifest_bytes.len() as u64,
            package_digest: package.content_digest().unwrap().to_string(),
            activation_mode: "contracts-only".to_string(),
            artifacts: vec![AbilityArtifactRetentionMeta {
                content: artifact.content.to_string(),
                store_path: artifact.store_path.clone(),
                nar_hash: artifact.nar_hash.to_string(),
                nar_size: 128,
                closure_digest: closure_digest.to_string(),
                closure,
            }],
            provenance: "provenance/demo.ability.intoto.jsonl".to_string(),
        };
        let package_meta = PackageMeta {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            description: "Demo".to_string(),
            homepage: None,
            license: "Apache-2.0".to_string(),
            maintainer: "Andyl, Inc.".to_string(),
            platform: "x86_64-linux".to_string(),
            store_path: STORE_ROOT.to_string(),
            nar_hash: digest('2').to_string(),
            nar_size: 128,
            references: Vec::new(),
            source_drv: String::new(),
            source_nar_hash: String::new(),
            closure_size: 128,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: None,
            requires_features: Vec::new(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            documentation: None,
            ability: Some(ability),
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: AttestationMeta::default(),
        };

        let key_dir = TempDir::new().unwrap();
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([73_u8; 32]);
        let key_path = key_dir.path().join("ability-builder");
        fs::write(&key_path, keypair.to_openssh_private_key(REGISTRY)).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let trusted_keys = vec![TrustedProvenanceKey {
            key_id: KEY_ID.to_string(),
            key: keypair.trust_key_line(REGISTRY),
            retired_before_sequence: None,
        }];
        let mut fixture = Self {
            _key_dir: key_dir,
            key_path,
            trusted_keys,
            package_meta,
            manifest_bytes,
            provenance_jsonl: String::new(),
        };
        fixture.resign();
        fixture
    }

    fn resign(&mut self) {
        let ability = self.package_meta.ability.as_ref().unwrap();
        let coordinate = AbilityPackageCoordinate {
            name: &self.package_meta.name,
            version: &self.package_meta.version,
            platform: &self.package_meta.platform,
            store_path: &self.package_meta.store_path,
            nar_hash: &self.package_meta.nar_hash,
        };
        let statement =
            ability_provenance_statement(&coordinate, ability, REGISTRY, KEY_ID).unwrap();
        self.provenance_jsonl =
            sign_statement_dsse_jsonl(&statement, KEY_ID, &self.key_path).unwrap();
    }
}

#[derive(Default)]
struct AcceptRetention {
    calls: Cell<u32>,
}

impl AbilityRetentionVerifier for AcceptRetention {
    fn verify_retention(&self, _retention: &VerifiedAbilityRetentionManifest) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

struct RejectRetention(&'static str);

impl AbilityRetentionVerifier for RejectRetention {
    fn verify_retention(&self, _retention: &VerifiedAbilityRetentionManifest) -> Result<()> {
        Err(anyhow::anyhow!(self.0))
    }
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

#[test]
fn signed_package_constructs_opaque_verified_value_after_retention() {
    let fixture = TestFixture::new();
    let retention = AcceptRetention::default();

    let verified = verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &retention,
    )
    .unwrap();

    assert_eq!(verified.package_name(), "demo");
    assert_eq!(verified.package_version(), "1.0.0");
    assert_eq!(verified.platform(), "x86_64-linux");
    assert_eq!(retention.calls.get(), 1);
}

#[test]
fn verified_package_set_deduplicates_equal_seals_and_checks_plan_inputs() {
    let fixture = TestFixture::new();
    let verified = verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap();
    let packages = VerifiedAbilityPackageSet::from_verified(vec![verified.clone(), verified])
        .expect("equal seals must coalesce");

    assert_eq!(packages.iter().len(), 1);
    let package = packages
        .get("demo", "1.0.0", "x86_64-linux")
        .expect("verified coordinate");
    let platform = PlatformIdentity {
        system: aos_ability_model::LocalKey::new("linux").unwrap(),
        architecture: aos_ability_model::LocalKey::new("x86_64").unwrap(),
    };
    packages
        .verify_plan_inputs(
            &platform,
            std::slice::from_ref(package.package()),
            package.artifacts(),
        )
        .expect("exact package documents and artifacts must be admitted");

    let wrong_platform = PlatformIdentity {
        system: aos_ability_model::LocalKey::new("linux").unwrap(),
        architecture: aos_ability_model::LocalKey::new("aarch64").unwrap(),
    };
    let error = packages
        .verify_plan_inputs(
            &wrong_platform,
            std::slice::from_ref(package.package()),
            package.artifacts(),
        )
        .expect_err("a plan for another platform must not reuse this package seal");
    assert!(error.to_string().contains("aarch64-linux"));
}

#[test]
fn verified_package_set_rejects_conflicting_coordinate_seals() {
    let fixture = TestFixture::new();
    let verified = verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap();
    let mut conflicting = verified.clone();
    conflicting.package_digest = digest('9');

    let error = VerifiedAbilityPackageSet::from_verified(vec![verified, conflicting])
        .expect_err("one coordinate must have one authenticated commitment");

    assert!(
        error
            .to_string()
            .contains("conflicting verified ability package")
    );
}

#[test]
fn verified_package_set_rechecks_every_live_retention_catalog() {
    let fixture = TestFixture::new();
    let verified = verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap();
    let packages = VerifiedAbilityPackageSet::from_verified(vec![verified]).unwrap();
    let retention = AcceptRetention::default();

    packages.verify_live_retention(&retention).unwrap();

    assert_eq!(retention.calls.get(), 1);
}

#[test]
fn signed_package_accepts_equivalent_primary_sri_nar_identity() {
    let mut fixture = TestFixture::new();
    fixture.package_meta.nar_hash = format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode([0x22_u8; 32])
    );
    fixture.resign();

    verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap();
}

#[test]
fn signed_package_accepts_equivalent_primary_nix_base32_nar_identity() {
    let mut fixture = TestFixture::new();
    fixture.package_meta.nar_hash =
        aos_core::nar::cache::normalize_sha256_nix32(&digest('2').to_string());
    fixture.resign();

    verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap();
}

#[test]
fn signed_package_rejects_untrusted_signer() {
    let mut fixture = TestFixture::new();
    let other_dir = TempDir::new().unwrap();
    let other_keypair = crate::sshkey::Ed25519Keypair::from_seed([91_u8; 32]);
    let other_path = other_dir.path().join("other-builder");
    fs::write(&other_path, other_keypair.to_openssh_private_key(REGISTRY)).unwrap();
    fs::set_permissions(&other_path, fs::Permissions::from_mode(0o600)).unwrap();
    let ability = fixture.package_meta.ability.as_ref().unwrap();
    let coordinate = AbilityPackageCoordinate {
        name: &fixture.package_meta.name,
        version: &fixture.package_meta.version,
        platform: &fixture.package_meta.platform,
        store_path: &fixture.package_meta.store_path,
        nar_hash: &fixture.package_meta.nar_hash,
    };
    let statement = ability_provenance_statement(&coordinate, ability, REGISTRY, "other").unwrap();
    fixture.provenance_jsonl = sign_statement_dsse_jsonl(&statement, "other", &other_path).unwrap();

    let error = verify_ability_package(
        &fixture.package_meta,
        &fixture.manifest_bytes,
        &fixture.provenance_jsonl,
        REGISTRY,
        &fixture.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("no valid signature from a trusted key"));
}

#[test]
fn signed_package_rejects_coordinate_and_payload_substitution() {
    let mut wrong_platform = TestFixture::new();
    wrong_platform.package_meta.platform = "aarch64-linux".to_string();
    let error = verify_ability_package(
        &wrong_platform.package_meta,
        &wrong_platform.manifest_bytes,
        &wrong_platform.provenance_jsonl,
        REGISTRY,
        &wrong_platform.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("does not exactly match"));

    let mut wrong_payload = TestFixture::new();
    wrong_payload.package_meta.store_path =
        "/nix/store/23456789abcdfghijklmnpqrsvwxyz01-other-payload".to_string();
    wrong_payload.package_meta.nar_hash = digest('4').to_string();
    wrong_payload.resign();
    let error = verify_ability_package(
        &wrong_payload.package_meta,
        &wrong_payload.manifest_bytes,
        &wrong_payload.provenance_jsonl,
        REGISTRY,
        &wrong_payload.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("manifest payload does not match"));
}

#[test]
fn signed_package_rejects_manifest_and_artifact_tampering() {
    let mut wrong_digest = TestFixture::new();
    wrong_digest
        .package_meta
        .ability
        .as_mut()
        .unwrap()
        .package_digest = digest('5').to_string();
    wrong_digest.resign();
    let error = verify_ability_package(
        &wrong_digest.package_meta,
        &wrong_digest.manifest_bytes,
        &wrong_digest.provenance_jsonl,
        REGISTRY,
        &wrong_digest.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("semantic digest"));

    let mut wrong_artifact = TestFixture::new();
    wrong_artifact
        .package_meta
        .ability
        .as_mut()
        .unwrap()
        .artifacts[0]
        .content = digest('6').to_string();
    wrong_artifact.resign();
    let error = verify_ability_package(
        &wrong_artifact.package_meta,
        &wrong_artifact.manifest_bytes,
        &wrong_artifact.provenance_jsonl,
        REGISTRY,
        &wrong_artifact.trusted_keys,
        &AcceptRetention::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("retention catalog does not match"));
}

#[test]
fn signed_package_propagates_live_store_failures() {
    for reason in [
        "ability closure member NAR mismatch",
        "ability store path is missing",
    ] {
        let fixture = TestFixture::new();
        let error = verify_ability_package(
            &fixture.package_meta,
            &fixture.manifest_bytes,
            &fixture.provenance_jsonl,
            REGISTRY,
            &fixture.trusted_keys,
            &RejectRetention(reason),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains(reason));
    }
}

#[test]
fn closure_rejects_edges_outside_authenticated_catalog() {
    let mut fixture = TestFixture::new();
    let ability = fixture.package_meta.ability.as_mut().unwrap();
    ability.artifacts[0].closure[0].references =
        vec!["3456789abcdfghijklmnpqrsvwxyz012".to_string()];
    ability.artifacts[0].closure_digest =
        Sha256Digest::of_canonical(CLOSURE_DIGEST_DOMAIN, &ability.artifacts[0].closure)
            .unwrap()
            .to_string();

    let error = validate_ability_package_meta(ability).unwrap_err();
    assert!(format!("{error:#}").contains("outside its signed closure"));
}

#[test]
fn exact_store_root_rejects_lexical_aliases() {
    validate_store_root(STORE_ROOT, "test store path").expect("canonical store root");

    for alias in [
        "/nix//store/0123456789abcdfghijklmnpqrsvwxyz-ability-artifact",
        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-ability-artifact/.",
        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-ability-artifact/",
    ] {
        let error = validate_store_root(alias, "test store path")
            .expect_err("lexical alias must be refused");
        assert!(
            error.to_string().contains("not an exact Nix store root"),
            "unexpected error for {alias}: {error:#}"
        );
    }
}
