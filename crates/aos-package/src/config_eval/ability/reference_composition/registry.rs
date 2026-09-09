//! Signed production-companion setup for reference composition tests.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{PackageDocument, VersionedDocument};
use aos_contract::Sha256Digest;
use serde::Deserialize;
use tempfile::TempDir;

use crate::ability_package::{
    AbilityPackageCoordinate, NativeAbilityRetentionVerifier, VerifiedAbilityPackageSet,
    ability_provenance_statement, activation_mode_name, canonical_nar_hash,
    collect_distinct_artifacts, decode_package_manifest, verify_ability_package,
};
use crate::provenance::{TrustedProvenanceKey, sign_statement_dsse_jsonl};
use crate::types::{
    AbilityArtifactRetentionMeta, AbilityClosureMemberMeta, AbilityPackageMeta, AttestationMeta,
    PackageMeta, PermissionsMeta,
};

const REGISTRY_NAME: &str = "reference-registry";
const KEY_ID: &str = "reference-ability-builder";

/// Retains exact decoded source inputs and their independently signed registry seals.
pub(super) struct ReferencePackageCatalog {
    source_packages: Vec<PackageDocument>,
    verified_packages: VerifiedAbilityPackageSet,
}

impl ReferencePackageCatalog {
    /// Loads every production companion named by the test environment.
    pub(super) fn from_environment() -> Result<Self> {
        let roots = std::env::var("AOS_TEST_ABILITY_REFERENCE_PACKAGES")
            .context("reading AOS_TEST_ABILITY_REFERENCE_PACKAGES")?;
        let roots = roots.split(':').map(PathBuf::from).collect::<Vec<_>>();
        ensure!(!roots.is_empty(), "reference companion catalog is empty");

        let signer = ReferenceSigner::new()?;
        let nix = nix_command()?;
        let mut source_packages = Vec::with_capacity(roots.len());
        let mut verified_packages = Vec::with_capacity(roots.len());
        for root in roots {
            let manifest = fs::read(root.join("package.json"))
                .with_context(|| format!("reading reference companion {}", root.display()))?;
            let package = decode_package_manifest(&manifest)
                .with_context(|| format!("decoding reference companion {}", root.display()))?;
            let package_meta = package_meta(&nix, &root, &manifest, &package)?;
            let provenance = signer.sign(&package_meta)?;
            let verified = verify_ability_package(
                &package_meta,
                &manifest,
                &provenance,
                REGISTRY_NAME,
                &signer.trusted_keys,
                &NativeAbilityRetentionVerifier::new(),
            )?;
            assert_identity_mutations_are_rejected(&signer, &package_meta, &manifest, &provenance)?;

            source_packages.push(package);
            verified_packages.push(verified);
        }
        source_packages.sort_by_key(|package| package.content_digest().unwrap());

        Ok(Self {
            source_packages,
            verified_packages: VerifiedAbilityPackageSet::from_verified(verified_packages)?,
        })
    }

    /// Returns package documents decoded directly from the realized companions.
    pub(super) fn source_packages(&self) -> &[PackageDocument] {
        &self.source_packages
    }

    /// Returns the sealed registry set admitted through provenance verification.
    pub(super) const fn verified_packages(&self) -> &VerifiedAbilityPackageSet {
        &self.verified_packages
    }
}

struct ReferenceSigner {
    _directory: TempDir,
    key_path: PathBuf,
    trusted_keys: Vec<TrustedProvenanceKey>,
}

impl ReferenceSigner {
    fn new() -> Result<Self> {
        let directory = TempDir::new().context("creating reference signing directory")?;
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([117_u8; 32]);
        let key_path = directory.path().join(KEY_ID);
        fs::write(&key_path, keypair.to_openssh_private_key(REGISTRY_NAME))?;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        let trusted_keys = vec![TrustedProvenanceKey {
            key_id: KEY_ID.to_string(),
            key: keypair.trust_key_line(REGISTRY_NAME),
            retired_before_sequence: None,
        }];

        Ok(Self {
            _directory: directory,
            key_path,
            trusted_keys,
        })
    }

    fn sign(&self, package: &PackageMeta) -> Result<String> {
        let ability = package
            .ability
            .as_ref()
            .context("reference package omitted ability metadata")?;
        let coordinate = AbilityPackageCoordinate {
            name: &package.name,
            version: &package.version,
            platform: &package.platform,
            store_path: &package.store_path,
            nar_hash: &package.nar_hash,
        };
        let statement = ability_provenance_statement(&coordinate, ability, REGISTRY_NAME, KEY_ID)?;
        sign_statement_dsse_jsonl(&statement, KEY_ID, &self.key_path)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PathInfo {
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
}

fn package_meta(
    nix: &Path,
    companion: &Path,
    manifest: &[u8],
    package: &PackageDocument,
) -> Result<PackageMeta> {
    let companion_path = companion
        .to_str()
        .context("reference companion path is not UTF-8")?;
    let companion_info = path_info(nix, companion_path, false)?
        .remove(companion_path)
        .context("Nix omitted the reference companion path")?;
    let payload_info = path_info(nix, &package.package.payload.store_path, false)?
        .remove(&package.package.payload.store_path)
        .context("Nix omitted the reference package payload")?;

    let mut artifacts = collect_distinct_artifacts(package)?
        .into_iter()
        .map(|artifact| artifact_retention(nix, artifact))
        .collect::<Result<Vec<_>>>()?;
    artifacts.sort_by(|left, right| left.content.cmp(&right.content));

    let ability = AbilityPackageMeta {
        store_path: companion_path.to_string(),
        nar_hash: canonical_nar_hash(&companion_info.nar_hash)?,
        nar_size: companion_info.nar_size,
        references: reference_hashes(&companion_info.references)?,
        manifest_sha256: Sha256Digest::of_bytes(manifest).to_string(),
        manifest_size: manifest.len() as u64,
        package_digest: package.content_digest()?.to_string(),
        activation_mode: activation_mode_name(package.activation_mode).to_string(),
        artifacts,
        provenance: format!("provenance/{}.ability.intoto.jsonl", package.package.name),
    };

    Ok(PackageMeta {
        name: package.package.name.as_str().to_string(),
        version: package.package.version.clone(),
        description: "Authenticated reference ability package".to_string(),
        homepage: None,
        license: "Apache-2.0".to_string(),
        maintainer: "Andyl, Inc.".to_string(),
        platform: "x86_64-linux".to_string(),
        store_path: package.package.payload.store_path.clone(),
        nar_hash: canonical_nar_hash(&payload_info.nar_hash)?,
        nar_size: payload_info.nar_size,
        references: reference_hashes(&payload_info.references)?,
        source_drv: String::new(),
        source_nar_hash: String::new(),
        closure_size: payload_info.nar_size,
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
    })
}

fn assert_identity_mutations_are_rejected(
    signer: &ReferenceSigner,
    package_meta: &PackageMeta,
    manifest: &[u8],
    provenance: &str,
) -> Result<()> {
    let mut altered_manifest = manifest.to_vec();
    altered_manifest.push(b' ');
    ensure!(
        verify_ability_package(
            package_meta,
            &altered_manifest,
            provenance,
            REGISTRY_NAME,
            &signer.trusted_keys,
            &NativeAbilityRetentionVerifier::new(),
        )
        .is_err(),
        "a changed production companion manifest passed exact-byte authentication"
    );

    let mut altered_primary = package_meta.clone();
    altered_primary.nar_hash = format!("sha256:{}", "0".repeat(64));
    let altered_provenance = signer.sign(&altered_primary)?;
    ensure!(
        verify_ability_package(
            &altered_primary,
            manifest,
            &altered_provenance,
            REGISTRY_NAME,
            &signer.trusted_keys,
            &NativeAbilityRetentionVerifier::new(),
        )
        .is_err(),
        "a signed wrong primary artifact identity passed package association"
    );
    Ok(())
}

fn artifact_retention(
    nix: &Path,
    artifact: aos_ability_model::ArtifactReference,
) -> Result<AbilityArtifactRetentionMeta> {
    let closure_info = path_info(nix, &artifact.store_path, true)?;
    let root_nar_size = closure_info
        .get(&artifact.store_path)
        .context("Nix omitted an ability artifact root")?
        .nar_size;
    let mut closure = closure_info
        .into_iter()
        .map(|(store_path, info)| {
            Ok(AbilityClosureMemberMeta {
                store_path,
                nar_hash: canonical_nar_hash(&info.nar_hash)?,
                nar_size: info.nar_size,
                references: reference_hashes(&info.references)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    closure.sort();
    let closure_digest = Sha256Digest::of_canonical("aos.ability.closure/v1", &closure)?;
    ensure!(
        closure_digest == artifact.closure,
        "production companion closure differs for {}: manifest {}, observed {}",
        artifact.store_path,
        artifact.closure,
        closure_digest
    );

    Ok(AbilityArtifactRetentionMeta {
        content: artifact.content.to_string(),
        store_path: artifact.store_path,
        nar_hash: artifact.nar_hash.to_string(),
        nar_size: root_nar_size,
        closure_digest: closure_digest.to_string(),
        closure,
    })
}

fn path_info(nix: &Path, store_path: &str, recursive: bool) -> Result<BTreeMap<String, PathInfo>> {
    let mut command = Command::new(nix);
    for (source, target) in [
        ("AOS_TEST_ABILITY_NIX_STORE_DIR", "NIX_STORE_DIR"),
        ("AOS_TEST_ABILITY_NIX_STATE_DIR", "NIX_STATE_DIR"),
        ("AOS_TEST_ABILITY_NIX_LOG_DIR", "NIX_LOG_DIR"),
        ("AOS_TEST_ABILITY_NIX_REMOTE", "NIX_REMOTE"),
    ] {
        if let Some(value) = std::env::var_os(source) {
            command.env(target, value);
        }
    }
    command.args([
        "--extra-experimental-features",
        "nix-command",
        "path-info",
        "--json",
    ]);
    if recursive {
        command.arg("--recursive");
    }
    let output = command
        .arg(store_path)
        .output()
        .with_context(|| format!("querying Nix path info for {store_path}"))?;
    if !output.status.success() {
        bail!(
            "Nix path-info failed for {store_path}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("decoding Nix path info for {store_path}"))
}

fn reference_hashes(references: &[String]) -> Result<Vec<String>> {
    let mut hashes = references
        .iter()
        .map(|reference| {
            let base = Path::new(reference)
                .file_name()
                .and_then(|name| name.to_str())
                .context("Nix reference is not a UTF-8 store path")?;
            let (hash, _) = base
                .split_once('-')
                .context("Nix reference has no store hash separator")?;
            ensure!(hash.len() == 32, "Nix reference has an invalid store hash");
            Ok(hash.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    hashes.sort();
    hashes.dedup();
    Ok(hashes)
}

fn nix_command() -> Result<PathBuf> {
    let instantiate =
        PathBuf::from(std::env::var("AOS_NIX_INSTANTIATE").context("reading AOS_NIX_INSTANTIATE")?);
    let parent = instantiate
        .parent()
        .context("AOS_NIX_INSTANTIATE has no binary directory")?;
    Ok(parent.join("nix"))
}
