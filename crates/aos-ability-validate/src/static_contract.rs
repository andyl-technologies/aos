//! Semantic validation for build-time OCI and boot ability contracts.
//!
//! Static contracts describe authenticated packages, exported implementations,
//! and obligations that remain unresolved until launch. They never carry
//! runtime grants; current runtime admission remains authoritative.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, ArtifactReference, InterfaceDocument, InterfaceKey, LocalKey,
    PackageDocument, RequirementDeclaration, RequirementStrength,
};
use aos_contract::Sha256Digest;
use serde::Deserialize;
use thiserror::Error;

const MAX_STATIC_ABILITY_CONTRACT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATIC_ABILITY_ITEMS: usize = 100_000;

/// Selects the artifact family whose static contract is being validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticAbilityArtifactClass {
    /// Describes an OCI application-container artifact.
    Container,
    /// Describes an initrd or host-stage boot artifact.
    Bootable,
}

/// Identifies the boot stage covered by a bootable static contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum StaticAbilityExecutionStage {
    /// Runs before the immutable root switch.
    Initrd,
    /// Runs under the normal host service manager.
    Host,
}

/// Identifies one exact OCI platform expected from a platform contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticAbilityPlatform {
    /// Names the operating-system family.
    pub os: String,
    /// Names the OCI architecture.
    pub architecture: String,
    /// Carries an optional OCI platform variant.
    pub variant: Option<String>,
}

/// Supplies artifact and platform expectations known by the invoking builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticAbilityContractExpectation {
    /// Selects the contract schema family.
    pub artifact_class: StaticAbilityArtifactClass,
    /// Requires the exact boot execution stage, or absence for containers.
    pub execution_stage: Option<StaticAbilityExecutionStage>,
    /// Requires one exact platform when set; aggregate contracts leave it unset.
    pub platform: Option<StaticAbilityPlatform>,
}

/// Retains summary information after static-contract semantic validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedStaticAbilityContract {
    platform_count: usize,
    packages: Vec<CheckedStaticAbilityPackage>,
}

impl CheckedStaticAbilityContract {
    /// Returns the number of distinct platform records in the contract.
    #[must_use]
    pub const fn platform_count(&self) -> usize {
        self.platform_count
    }

    /// Iterates the exact package selections retained by the checked contract.
    ///
    /// Artifact-backed validation also attaches the checked package document
    /// to each selection. Byte-only validation leaves it unavailable because
    /// the static document alone cannot prove the companion bytes.
    pub fn packages(&self) -> impl ExactSizeIterator<Item = &CheckedStaticAbilityPackage> {
        self.packages.iter()
    }
}

/// Retains one exact package selection from a checked static contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedStaticAbilityPackage {
    name: LocalKey,
    version: String,
    payload: ArtifactReference,
    manifest: CheckedStaticPackageManifest,
    package_document: Option<PackageDocument>,
    retained_interfaces: Vec<InterfaceDocument>,
}

impl CheckedStaticAbilityPackage {
    /// Returns the package's canonical local name.
    #[must_use]
    pub const fn name(&self) -> &LocalKey {
        &self.name
    }

    /// Returns the exact selected package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the exact selected payload artifact.
    #[must_use]
    pub const fn payload(&self) -> &ArtifactReference {
        &self.payload
    }

    /// Returns the exact package-manifest reference.
    #[must_use]
    pub const fn manifest(&self) -> &CheckedStaticPackageManifest {
        &self.manifest
    }

    /// Returns the artifact-backed package document when companion validation ran.
    #[must_use]
    pub const fn package_document(&self) -> Option<&PackageDocument> {
        self.package_document.as_ref()
    }

    /// Returns the artifact-validated retained interface catalog.
    ///
    /// Byte-only validation returns an empty slice. Artifact-backed callers
    /// can distinguish an ability-free package through [`Self::package_document`].
    #[must_use]
    pub fn retained_interfaces(&self) -> &[InterfaceDocument] {
        &self.retained_interfaces
    }
}

/// Identifies the exact package companion selected by a static contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedStaticPackageManifest {
    store_path: String,
    digest: Sha256Digest,
}

impl CheckedStaticPackageManifest {
    /// Returns the canonical store path of the package companion.
    #[must_use]
    pub fn store_path(&self) -> &str {
        &self.store_path
    }

    /// Returns the digest of the canonical package document bytes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Reports a canonical, schema, reference, or policy error in a static contract.
#[derive(Debug, Error)]
#[error("validating static ability contract")]
pub struct StaticAbilityContractValidationError {
    #[source]
    source: anyhow::Error,
}

/// Validates one canonical static ability contract against builder expectations.
///
/// # Errors
///
/// Returns an error for noncanonical or oversized JSON, an unexpected schema,
/// runtime grants, duplicate or noncanonically ordered records, dangling
/// package/ability references, malformed obligations, inconsistent
/// implementation availability, or disagreement with the expected artifact
/// stage and platform.
pub(crate) fn validate_static_ability_contract(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
) -> Result<CheckedStaticAbilityContract, StaticAbilityContractValidationError> {
    validate_static_ability_contract_document(bytes, expectation)
        .map(|contract| checked_static_ability_contract(contract, BTreeMap::new()))
        .map_err(|source| StaticAbilityContractValidationError { source })
}

/// Validates a static contract and its exact package companions from the store.
///
/// # Errors
///
/// Returns every byte-level static-contract error, and also fails when a
/// package manifest or retained interface is unavailable or invalid, the
/// manifest has a different digest, or the companion disagrees with a package,
/// exported ability, provider, or required-obligation record.
pub fn validate_static_ability_artifacts(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
) -> Result<CheckedStaticAbilityContract, StaticAbilityContractValidationError> {
    validate_static_ability_artifacts_with(bytes, expectation, read_package_artifacts)
        .map_err(|source| StaticAbilityContractValidationError { source })
}

/// Validates a static contract against companions beneath a mounted store root.
///
/// Contract references retain their canonical `/nix/store` identity. The
/// supplied root changes only where those exact store entries are read, which
/// allows immutable lower stores to use the same authenticated contract.
///
/// # Errors
///
/// Returns every static artifact validation error, and rejects malformed store
/// references or missing and changed companion files beneath `store_root`.
pub fn validate_static_ability_artifacts_at_store_root(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
    store_root: &Path,
) -> Result<CheckedStaticAbilityContract, StaticAbilityContractValidationError> {
    validate_static_ability_artifacts_with(bytes, expectation, |store_path| {
        read_package_artifacts_at_store_root(store_root, store_path)
    })
    .map_err(|source| StaticAbilityContractValidationError { source })
}

fn validate_static_ability_artifacts_with(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
    mut read_package: impl FnMut(&str) -> Result<StaticPackageArtifacts>,
) -> Result<CheckedStaticAbilityContract> {
    let contract = validate_static_ability_contract_document(bytes, expectation)?;
    let package_documents = validate_artifact_projections(&contract, &mut read_package)?;
    Ok(checked_static_ability_contract(contract, package_documents))
}

fn validate_static_ability_contract_document(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
) -> Result<StaticAbilityContract> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_STATIC_ABILITY_CONTRACT_BYTES,
        "static ability contract size is outside 1..={MAX_STATIC_ABILITY_CONTRACT_BYTES}"
    );
    aos_contract::canonical::require_canonical(bytes, "static ability contract")?;
    let contract: StaticAbilityContract =
        aos_contract::canonical::from_slice(bytes, "static ability contract")?;
    let expected_schema = match expectation.artifact_class {
        StaticAbilityArtifactClass::Container => "aos.container.static-abilities/v1",
        StaticAbilityArtifactClass::Bootable => "aos.boot.static-abilities/v1",
    };
    ensure!(
        contract.schema == expected_schema,
        "unexpected static ability schema"
    );
    ensure!(
        contract.runtime_grants.is_empty(),
        "static contracts cannot carry runtime grants"
    );
    ensure!(
        !contract.platforms.is_empty(),
        "static contract contains no platforms"
    );

    ensure_strict_order_by(
        &contract.platforms,
        compare_platform_records,
        "static contract platform records",
    )?;

    let mut platform_keys = BTreeSet::new();
    for platform in &contract.platforms {
        let key = (
            platform.platform.os.as_str(),
            platform.platform.architecture.as_str(),
            platform.platform.variant.as_deref(),
        );
        ensure!(
            platform_keys.insert(key),
            "static contract contains a duplicate platform"
        );
        validate_platform(platform, expectation)?;
    }
    if let Some(expected) = &expectation.platform {
        ensure!(
            contract.platforms.len() == 1,
            "platform contract must contain one platform"
        );
        let actual = &contract.platforms[0].platform;
        ensure!(
            actual.os == expected.os
                && actual.architecture == expected.architecture
                && actual.variant == expected.variant,
            "static ability contract has the wrong platform"
        );
    }

    Ok(contract)
}

fn checked_static_ability_contract(
    contract: StaticAbilityContract,
    package_documents: BTreeMap<(String, Sha256Digest), ArtifactBackedPackage>,
) -> CheckedStaticAbilityContract {
    let packages = contract
        .platforms
        .iter()
        .flat_map(|platform| &platform.packages)
        .map(|package| CheckedStaticAbilityPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            payload: package.payload.clone(),
            manifest: CheckedStaticPackageManifest {
                store_path: package.manifest.store_path.clone(),
                digest: package.manifest.digest,
            },
            package_document: package_documents
                .get(&manifest_key(&package.manifest))
                .map(|checked| checked.document.clone()),
            retained_interfaces: package_documents
                .get(&manifest_key(&package.manifest))
                .map_or_else(Vec::new, |checked| checked.interfaces.clone()),
        })
        .collect();

    CheckedStaticAbilityContract {
        platform_count: contract.platforms.len(),
        packages,
    }
}

#[derive(Clone)]
struct StaticPackageArtifacts {
    manifest: Vec<u8>,
    retained_interfaces: Vec<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq)]
struct ArtifactBackedPackage {
    document: PackageDocument,
    interfaces: Vec<InterfaceDocument>,
}

fn read_package_artifacts(store_path: &str) -> Result<StaticPackageArtifacts> {
    read_package_artifacts_from_path(Path::new(store_path))
}

fn read_package_artifacts_at_store_root(
    store_root: &Path,
    canonical_store_path: &str,
) -> Result<StaticPackageArtifacts> {
    validate_store_path(canonical_store_path)?;
    let store_entry = canonical_store_path
        .strip_prefix("/nix/store/")
        .context("validated static package path has no store prefix")?;

    read_package_artifacts_from_path(&store_root.join(store_entry))
}

fn read_package_artifacts_from_path(package_path: &Path) -> Result<StaticPackageArtifacts> {
    let manifest_path = package_path.join("package.json");
    let manifest = read_bounded_regular_file(&manifest_path, "static package manifest")?;
    let interface_directory = package_path.join("interfaces");
    let mut interface_paths = interface_directory
        .read_dir()
        .with_context(|| {
            format!(
                "reading static package interface directory {}",
                interface_directory.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    interface_paths.sort();
    interface_paths.retain(|path| path.extension() == Some(OsStr::new("json")));
    ensure!(
        u64::try_from(interface_paths.len())? <= ABILITY_LIMITS_V1.max_collection_items,
        "static package interface catalog contains excessive records"
    );
    let retained_interfaces = interface_paths
        .iter()
        .map(|path| read_bounded_regular_file(path, "static package interface"))
        .collect::<Result<Vec<_>>>()?;

    Ok(StaticPackageArtifacts {
        manifest,
        retained_interfaces,
    })
}

fn read_bounded_regular_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let path_metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    ensure!(
        path_metadata.file_type().is_file()
            && path_metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
        "{label} must be a bounded regular file: {}",
        path.display()
    );
    let file = File::open(path).with_context(|| format!("opening {label} {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    ensure!(
        opened_metadata.dev() == path_metadata.dev()
            && opened_metadata.ino() == path_metadata.ino()
            && opened_metadata.len() == path_metadata.len(),
        "{label} changed while being opened: {}",
        path.display()
    );

    let mut bytes = Vec::new();
    file.take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    let current_metadata = path
        .symlink_metadata()
        .with_context(|| format!("reinspecting {label} {}", path.display()))?;
    ensure!(
        u64::try_from(bytes.len())? == opened_metadata.len()
            && current_metadata.dev() == opened_metadata.dev()
            && current_metadata.ino() == opened_metadata.ino()
            && current_metadata.len() == opened_metadata.len(),
        "{label} changed while being read: {}",
        path.display()
    );
    Ok(bytes)
}

fn validate_artifact_projections(
    contract: &StaticAbilityContract,
    read_package: &mut impl FnMut(&str) -> Result<StaticPackageArtifacts>,
) -> Result<BTreeMap<(String, Sha256Digest), ArtifactBackedPackage>> {
    let mut package_documents = BTreeMap::new();

    for platform in &contract.platforms {
        for static_package in &platform.packages {
            let artifacts = read_package(&static_package.manifest.store_path)?;
            ensure!(
                Sha256Digest::of_bytes(&artifacts.manifest) == static_package.manifest.digest,
                "static package manifest byte digest differs from its contract record"
            );
            let checked_package = crate::package_contract::validate_package_contract(
                &artifacts.manifest,
                &artifacts.retained_interfaces,
            )
            .context("validating artifact-backed static package companion")?;

            validate_package_projection(platform, static_package, checked_package.package())?;
            let checked = ArtifactBackedPackage {
                document: checked_package.package().clone(),
                interfaces: checked_package
                    .retained_interfaces()
                    .into_values()
                    .cloned()
                    .collect(),
            };
            let manifest = manifest_key(&static_package.manifest);
            if let Some(previous) = package_documents.insert(manifest, checked.clone()) {
                ensure!(
                    previous == checked,
                    "static package manifest identity resolves to different package documents"
                );
            }
        }
    }
    Ok(package_documents)
}

fn validate_package_projection(
    platform: &StaticAbilityPlatformRecord,
    static_package: &StaticAbilityPackage,
    package: &PackageDocument,
) -> Result<()> {
    ensure!(
        static_package.name == package.package.name
            && static_package.version == package.package.version
            && static_package.payload == package.package.payload,
        "static package identity differs from its exact artifact-backed manifest"
    );

    let abilities = platform
        .abilities
        .iter()
        .filter(|ability| ability.package == static_package.manifest)
        .collect::<Vec<_>>();
    ensure!(
        abilities.len() == package.exports.len(),
        "static ability exports differ from their exact artifact-backed manifest"
    );

    let mut export_provider_descriptors = BTreeSet::new();
    let mut export_providers = Vec::new();
    for export in &package.exports {
        let ability = abilities
            .iter()
            .find(|ability| ability.export == export.name)
            .with_context(|| {
                format!(
                    "static ability export '{}' is absent from its artifact-backed manifest projection",
                    export.name.as_str()
                )
            })?;
        let provider = exact_export_provider(package, export)?;
        ensure!(
            ability.interface == export.interface
                && ability.implementation == export.implementation
                && ability.implementation_artifact == provider.artifact,
            "static exported ability identity differs from its exact artifact-backed provider"
        );
        if export_provider_descriptors.insert(export.implementation) {
            export_providers.push(provider);
        }
    }

    validate_requirement_projections(platform, static_package, package, &export_providers)?;
    Ok(())
}

fn validate_requirement_projections(
    platform: &StaticAbilityPlatformRecord,
    static_package: &StaticAbilityPackage,
    package: &PackageDocument,
    export_providers: &[&aos_ability_model::ProviderImplementation],
) -> Result<()> {
    let actual_requirements = platform
        .unresolved_launch_obligations
        .iter()
        .filter_map(|obligation| match obligation {
            StaticLaunchObligation::AbilityRequirement {
                consumer,
                requirement,
                ..
            } if consumer.package == static_package.manifest => {
                Some((consumer.ability.as_ref(), requirement))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let package_requirements = package
        .requirements
        .iter()
        .filter(|requirement| requirement.strength == RequirementStrength::Required)
        .map(|requirement| (None, requirement));
    let provider_requirements = export_providers.iter().flat_map(|provider| {
        provider
            .requirements
            .iter()
            .filter(|requirement| requirement.strength == RequirementStrength::Required)
            .map(|requirement| (Some(&provider.interface), requirement))
    });
    let expected_requirements = package_requirements
        .chain(provider_requirements)
        .collect::<Vec<_>>();

    ensure!(
        actual_requirements.len() == expected_requirements.len(),
        "static required launch obligations differ from their artifact-backed manifest"
    );
    for (expected_consumer, expected_requirement) in expected_requirements {
        let matching = actual_requirements
            .iter()
            .filter(|(consumer, requirement)| {
                *consumer == expected_consumer && requirement.alias == expected_requirement.alias
            });
        let matches = matching.collect::<Vec<_>>();
        ensure!(
            matches.len() == 1 && matches[0].1 == expected_requirement,
            "static required launch obligation differs from its exact artifact-backed requirement"
        );
    }
    Ok(())
}

fn exact_export_provider<'a>(
    package: &'a PackageDocument,
    export: &aos_ability_model::ExportDeclaration,
) -> Result<&'a aos_ability_model::ProviderImplementation> {
    let mut matching_provider = None;
    for provider in &package.implementation.providers {
        if provider.interface == export.interface
            && provider.descriptor_digest()? == export.implementation
        {
            ensure!(
                matching_provider.replace(provider).is_none(),
                "artifact-backed export has duplicate exact providers"
            );
        }
    }

    matching_provider.with_context(|| {
        format!(
            "artifact-backed export '{}' has no exact provider implementation",
            export.name.as_str()
        )
    })
}

fn validate_platform(
    stage: &StaticAbilityPlatformRecord,
    expectation: &StaticAbilityContractExpectation,
) -> Result<()> {
    match expectation.artifact_class {
        StaticAbilityArtifactClass::Container => ensure!(
            expectation.execution_stage.is_none() && stage.execution_stage.is_none(),
            "container static contracts cannot declare a boot execution stage"
        ),
        StaticAbilityArtifactClass::Bootable => ensure!(
            expectation.execution_stage.is_some()
                && stage.execution_stage == expectation.execution_stage,
            "boot static contract has the wrong execution stage"
        ),
    }
    ensure!(
        stage.packages.len() <= MAX_STATIC_ABILITY_ITEMS
            && stage.abilities.len() <= MAX_STATIC_ABILITY_ITEMS
            && stage.unresolved_launch_obligations.len() <= MAX_STATIC_ABILITY_ITEMS,
        "static ability contract contains excessive records"
    );

    ensure_strict_order_by(
        &stage.packages,
        |left, right| left.manifest.store_path.cmp(&right.manifest.store_path),
        "static contract package records",
    )?;

    let mut manifests = BTreeSet::new();
    for package in &stage.packages {
        ensure!(
            !package.name.as_str().is_empty() && !package.version.is_empty(),
            "static contract contains an empty package version"
        );
        validate_artifact_reference(&package.payload)?;
        validate_store_path(&package.manifest.store_path)?;
        ensure!(
            manifests.insert(manifest_key(&package.manifest)),
            "static contract contains a duplicate package manifest"
        );
    }

    ensure_strict_order_by(
        &stage.abilities,
        compare_ability_records,
        "static contract ability records",
    )?;

    let mut ability_exports = BTreeSet::new();
    let mut ability_records = BTreeSet::new();
    let mut ability_interfaces = BTreeSet::new();
    let mut ability_implementations = BTreeMap::new();
    for ability in &stage.abilities {
        let package = manifest_key(&ability.package);
        ensure!(
            manifests.contains(&package),
            "ability references an unknown package manifest"
        );
        validate_artifact_reference(&ability.implementation_artifact)?;
        let artifact = artifact_identity(&ability.implementation_artifact)?;
        ensure!(
            ability_exports.insert((package.clone(), ability.export.clone()))
                && ability_records.insert((
                    package.clone(),
                    ability.export.clone(),
                    ability.interface.clone(),
                    ability.implementation,
                    artifact,
                )),
            "static contract contains a duplicate ability record"
        );
        ability_interfaces.insert((package.clone(), ability.interface.clone()));
        let implementation_key = (package, ability.interface.clone(), artifact);
        if ability_implementations
            .insert(implementation_key, ability.availability)
            .is_some_and(|previous| previous != ability.availability)
        {
            bail!("shared ability implementation has inconsistent availability");
        }
    }

    ensure_strict_order_by(
        &stage.unresolved_launch_obligations,
        compare_launch_obligations,
        "static contract launch obligations",
    )?;

    let mut implementation_obligations = BTreeSet::new();
    for obligation in &stage.unresolved_launch_obligations {
        match obligation {
            StaticLaunchObligation::AbilityRequirement {
                consumer,
                requirement,
                disposition: StaticLaunchDisposition::ExternalLaunchObligation,
            } => {
                let package = manifest_key(&consumer.package);
                ensure!(
                    manifests.contains(&package)
                        && consumer.ability.as_ref().is_none_or(|interface| {
                            ability_interfaces.contains(&(package.clone(), interface.clone()))
                        }),
                    "ability requirement references an unknown consumer"
                );
                validate_requirement(requirement)?;
            }
            StaticLaunchObligation::ImplementationArtifact {
                consumer,
                artifact,
                disposition: StaticLaunchDisposition::ExternalLaunchObligation,
            } => {
                validate_artifact_reference(artifact)?;
                let key = (
                    manifest_key(&consumer.package),
                    consumer.ability.clone(),
                    artifact_identity(artifact)?,
                );
                ensure!(
                    ability_implementations.get(&key)
                        == Some(&StaticAbilityAvailability::UnresolvedAtLaunch)
                        && implementation_obligations.insert(key),
                    "implementation obligation differs from its unresolved ability"
                );
            }
        }
    }
    for (implementation, availability) in ability_implementations {
        ensure!(
            implementation_obligations.contains(&implementation)
                == (availability == StaticAbilityAvailability::UnresolvedAtLaunch),
            "ability availability differs from its implementation obligation"
        );
    }
    Ok(())
}

fn validate_artifact_reference(artifact: &ArtifactReference) -> Result<()> {
    validate_store_path(&artifact.store_path)
}

fn validate_store_path(path: &str) -> Result<()> {
    let Some(name) = path.strip_prefix("/nix/store/") else {
        bail!("static contract contains a non-store path");
    };
    let Some((hash, package)) = name.split_once('-') else {
        bail!("static contract contains a malformed store path");
    };
    ensure!(
        hash.len() == 32 && !package.is_empty() && !package.contains('/'),
        "static contract contains a malformed store path"
    );
    ensure!(
        hash.bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
        "static contract contains a malformed store hash"
    );
    Ok(())
}

fn artifact_identity(artifact: &ArtifactReference) -> Result<Sha256Digest> {
    let bytes = aos_contract::canonical::to_vec(artifact)
        .context("encoding static ability artifact identity")?;
    Ok(Sha256Digest::of_bytes(&bytes))
}

fn manifest_key(manifest: &StaticManifestReference) -> (String, Sha256Digest) {
    (manifest.store_path.clone(), manifest.digest)
}

fn validate_requirement(requirement: &RequirementDeclaration) -> Result<()> {
    ensure!(
        !requirement.accepted_interfaces.is_empty(),
        "ability requirement has no accepted interfaces"
    );
    ensure_strict_order(
        &requirement.accepted_interfaces,
        "ability requirement accepted interfaces",
    )?;
    ensure_strict_order(&requirement.methods, "ability requirement methods")?;
    ensure_strict_order(&requirement.guarantees, "ability requirement guarantees")?;

    let fallback_matches_strength = matches!(requirement.strength, RequirementStrength::Advisory)
        == requirement.fallback.is_some();
    ensure!(
        fallback_matches_strength,
        "ability requirement strength and fallback disagree"
    );
    Ok(())
}

fn ensure_strict_order<T: Ord>(values: &[T], label: &str) -> Result<()> {
    ensure_strict_order_by(values, Ord::cmp, label)
}

fn ensure_strict_order_by<T>(
    values: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
    label: &str,
) -> Result<()> {
    ensure!(
        values
            .windows(2)
            .all(|pair| compare(&pair[0], &pair[1]) == Ordering::Less),
        "{label} must be strictly sorted without duplicates"
    );
    Ok(())
}

// These keys mirror the `sort_by` expressions in the static-contract builder.
fn compare_platform_records(
    left: &StaticAbilityPlatformRecord,
    right: &StaticAbilityPlatformRecord,
) -> Ordering {
    (
        left.platform.os.as_str(),
        left.platform.architecture.as_str(),
        left.platform.variant.as_deref().unwrap_or_default(),
    )
        .cmp(&(
            right.platform.os.as_str(),
            right.platform.architecture.as_str(),
            right.platform.variant.as_deref().unwrap_or_default(),
        ))
}

fn compare_ability_records(left: &StaticAbility, right: &StaticAbility) -> Ordering {
    (
        left.package.store_path.as_str(),
        &left.interface,
        &left.export,
    )
        .cmp(&(
            right.package.store_path.as_str(),
            &right.interface,
            &right.export,
        ))
}

fn compare_launch_obligations(
    left: &StaticLaunchObligation,
    right: &StaticLaunchObligation,
) -> Ordering {
    launch_obligation_key(left).cmp(&launch_obligation_key(right))
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum StaticLaunchObligationKind {
    AbilityRequirement,
    ImplementationArtifact,
}

fn launch_obligation_key(
    obligation: &StaticLaunchObligation,
) -> (&str, &str, StaticLaunchObligationKind, &str, &str) {
    match obligation {
        StaticLaunchObligation::AbilityRequirement {
            consumer,
            requirement,
            ..
        } => (
            consumer.package.store_path.as_str(),
            consumer
                .ability
                .as_ref()
                .map_or("", |interface| interface.name.as_str()),
            StaticLaunchObligationKind::AbilityRequirement,
            requirement.alias.as_str(),
            "",
        ),
        StaticLaunchObligation::ImplementationArtifact {
            consumer, artifact, ..
        } => (
            consumer.package.store_path.as_str(),
            consumer.ability.name.as_str(),
            StaticLaunchObligationKind::ImplementationArtifact,
            "",
            artifact.store_path.as_str(),
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticAbilityContract {
    schema: String,
    platforms: Vec<StaticAbilityPlatformRecord>,
    runtime_grants: Vec<StaticRuntimeGrant>,
}

#[derive(Deserialize)]
enum StaticRuntimeGrant {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticAbilityPlatformRecord {
    platform: OciPlatform,
    #[serde(default)]
    execution_stage: Option<StaticAbilityExecutionStage>,
    packages: Vec<StaticAbilityPackage>,
    abilities: Vec<StaticAbility>,
    unresolved_launch_obligations: Vec<StaticLaunchObligation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OciPlatform {
    os: String,
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticAbilityPackage {
    name: LocalKey,
    version: String,
    payload: ArtifactReference,
    manifest: StaticManifestReference,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct StaticManifestReference {
    store_path: String,
    digest: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticAbility {
    package: StaticManifestReference,
    export: LocalKey,
    interface: InterfaceKey,
    implementation: Sha256Digest,
    implementation_artifact: ArtifactReference,
    availability: StaticAbilityAvailability,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum StaticAbilityAvailability {
    Baked,
    UnresolvedAtLaunch,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum StaticLaunchObligation {
    AbilityRequirement {
        consumer: StaticRequirementConsumer,
        requirement: RequirementDeclaration,
        disposition: StaticLaunchDisposition,
    },
    ImplementationArtifact {
        consumer: StaticAbilityConsumer,
        artifact: ArtifactReference,
        disposition: StaticLaunchDisposition,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticRequirementConsumer {
    package: StaticManifestReference,
    #[serde(default)]
    ability: Option<InterfaceKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticAbilityConsumer {
    package: StaticManifestReference,
    ability: InterfaceKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StaticLaunchDisposition {
    ExternalLaunchObligation,
}

#[cfg(test)]
#[path = "static_contract_tests.rs"]
mod tests;
