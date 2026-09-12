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
    ABILITY_LIMITS_V1, ArtifactReference, InterfaceKey, LocalKey, PackageDocument,
    RequirementDeclaration, RequirementStrength,
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
}

impl CheckedStaticAbilityContract {
    /// Returns the number of distinct platform records in the contract.
    #[must_use]
    pub const fn platform_count(&self) -> usize {
        self.platform_count
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
        .map(checked_static_ability_contract)
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

fn validate_static_ability_artifacts_with(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
    mut read_package: impl FnMut(&str) -> Result<StaticPackageArtifacts>,
) -> Result<CheckedStaticAbilityContract> {
    let contract = validate_static_ability_contract_document(bytes, expectation)?;
    validate_artifact_projections(&contract, &mut read_package)?;
    Ok(checked_static_ability_contract(contract))
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
) -> CheckedStaticAbilityContract {
    CheckedStaticAbilityContract {
        platform_count: contract.platforms.len(),
    }
}

#[derive(Clone)]
struct StaticPackageArtifacts {
    manifest: Vec<u8>,
    retained_interfaces: Vec<Vec<u8>>,
}

fn read_package_artifacts(store_path: &str) -> Result<StaticPackageArtifacts> {
    let manifest_path = Path::new(store_path).join("package.json");
    let manifest = read_bounded_regular_file(&manifest_path, "static package manifest")?;
    let interface_directory = Path::new(store_path).join("interfaces");
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
) -> Result<()> {
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
        }
    }
    Ok(())
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
mod tests {
    use super::*;
    use aos_ability_model::encode_canonical;
    use serde_json::{Value, json};

    const EMPTY_CONTAINER: &[u8] = br#"{"platforms":[{"abilities":[],"packages":[],"platform":{"architecture":"amd64","os":"linux"},"unresolved_launch_obligations":[]}],"runtime_grants":[],"schema":"aos.container.static-abilities/v1"}"#;

    fn expectation() -> StaticAbilityContractExpectation {
        StaticAbilityContractExpectation {
            artifact_class: StaticAbilityArtifactClass::Container,
            execution_stage: None,
            platform: Some(StaticAbilityPlatform {
                os: "linux".to_string(),
                architecture: "amd64".to_string(),
                variant: None,
            }),
        }
    }

    fn aggregate_expectation() -> StaticAbilityContractExpectation {
        StaticAbilityContractExpectation {
            artifact_class: StaticAbilityArtifactClass::Container,
            execution_stage: None,
            platform: None,
        }
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn artifact(store_path: &str, byte: char) -> Value {
        json!({
            "content": digest(byte),
            "store_path": store_path,
            "nar_hash": digest(byte),
            "closure": digest(byte),
        })
    }

    fn manifest(store_path: &str, byte: char) -> Value {
        json!({
            "store_path": store_path,
            "digest": digest(byte),
        })
    }

    fn interface(name: &str, byte: char) -> Value {
        json!({
            "name": name,
            "abi": 1,
            "descriptor": digest(byte),
        })
    }

    fn requirement(alias: &str) -> Value {
        json!({
            "alias": alias,
            "accepted_interfaces": [
                interface("aos.test.alpha", '1'),
                interface("aos.test.beta", '2'),
            ],
            "methods": ["apply", "remove"],
            "guarantees": [
                {"name": "aos.test.alpha", "version": 1, "descriptor": digest('3')},
                {"name": "aos.test.beta", "version": 1, "descriptor": digest('4')},
            ],
            "strength": "required",
            "fallback": null,
        })
    }

    fn populated_container_contract() -> Value {
        let package_a_path = "/nix/store/00000000000000000000000000000000-package-a";
        let package_b_path = "/nix/store/11111111111111111111111111111111-package-b";
        let provider_a_path = "/nix/store/22222222222222222222222222222222-provider-a";
        let provider_b_path = "/nix/store/33333333333333333333333333333333-provider-b";
        let package_a_manifest = manifest(package_a_path, '5');

        json!({
            "schema": "aos.container.static-abilities/v1",
            "platforms": [{
                "platform": {"os": "linux", "architecture": "amd64"},
                "packages": [
                    {
                        "name": "package-a",
                        "version": "1",
                        "payload": artifact(package_a_path, '6'),
                        "manifest": package_a_manifest,
                    },
                    {
                        "name": "package-b",
                        "version": "1",
                        "payload": artifact(package_b_path, '7'),
                        "manifest": manifest(package_b_path, '8'),
                    },
                ],
                "abilities": [
                    {
                        "package": package_a_manifest,
                        "export": "alpha",
                        "interface": interface("aos.test.alpha", '1'),
                        "implementation": digest('9'),
                        "implementation_artifact": artifact(provider_a_path, 'a'),
                        "availability": "baked",
                    },
                    {
                        "package": package_a_manifest,
                        "export": "beta",
                        "interface": interface("aos.test.beta", '2'),
                        "implementation": digest('b'),
                        "implementation_artifact": artifact(provider_b_path, 'c'),
                        "availability": "baked",
                    },
                ],
                "unresolved_launch_obligations": [
                    {
                        "kind": "ability-requirement",
                        "consumer": {"package": package_a_manifest},
                        "requirement": requirement("alpha"),
                        "disposition": "external-launch-obligation",
                    },
                    {
                        "kind": "ability-requirement",
                        "consumer": {"package": package_a_manifest},
                        "requirement": requirement("beta"),
                        "disposition": "external-launch-obligation",
                    },
                ],
            }],
            "runtime_grants": [],
        })
    }

    fn artifact_backed_container_contract() -> (Value, StaticPackageArtifacts) {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let mut package = fixture.binding_inputs.packages[0].clone();
        let accepted_interface = fixture.interfaces[0]
            .interface_key()
            .expect("fixture interface must have an exact key");
        package.requirements = vec![RequirementDeclaration {
            alias: LocalKey::new("package-required").expect("fixture alias must be valid"),
            accepted_interfaces: vec![accepted_interface.clone()],
            methods: Vec::new(),
            guarantees: Vec::new(),
            strength: RequirementStrength::Required,
            fallback: None,
        }];

        let provider = &mut package.implementation.providers[0];
        provider.requirements = vec![RequirementDeclaration {
            alias: LocalKey::new("provider-required").expect("fixture alias must be valid"),
            accepted_interfaces: vec![accepted_interface],
            methods: Vec::new(),
            guarantees: Vec::new(),
            strength: RequirementStrength::Required,
            fallback: None,
        }];
        let provider_interface = provider.interface.clone();
        let provider_descriptor = provider
            .descriptor_digest()
            .expect("fixture provider must have a descriptor");
        package
            .exports
            .iter_mut()
            .find(|export| export.interface == provider_interface)
            .expect("fixture provider must be exported")
            .implementation = provider_descriptor;

        let manifest_bytes = encode_canonical(&package)
            .expect("artifact-backed package fixture must encode canonically");
        let manifest_path = "/nix/store/44444444444444444444444444444444-package-manifest";
        let manifest_reference = json!({
            "store_path": manifest_path,
            "digest": Sha256Digest::of_bytes(&manifest_bytes),
        });
        let mut abilities = package
            .exports
            .iter()
            .map(|export| {
                let provider = package
                    .implementation
                    .providers
                    .iter()
                    .find(|provider| {
                        provider.interface == export.interface
                            && provider.descriptor_digest().ok() == Some(export.implementation)
                    })
                    .expect("fixture export must have an exact provider");
                (
                    (export.interface.clone(), export.name.clone()),
                    json!({
                        "package": manifest_reference,
                        "export": export.name,
                        "interface": export.interface,
                        "implementation": export.implementation,
                        "implementation_artifact": provider.artifact,
                        "availability": "baked",
                    }),
                )
            })
            .collect::<Vec<_>>();
        abilities.sort_by(|left, right| left.0.cmp(&right.0));
        let abilities = abilities
            .into_iter()
            .map(|(_, ability)| ability)
            .collect::<Vec<_>>();
        let exact_provider = package
            .implementation
            .providers
            .iter()
            .find(|provider| provider.interface == provider_interface)
            .expect("fixture provider must remain present");
        let obligations = vec![
            json!({
                "kind": "ability-requirement",
                "consumer": {"package": manifest_reference},
                "requirement": package.requirements[0],
                "disposition": "external-launch-obligation",
            }),
            json!({
                "kind": "ability-requirement",
                "consumer": {
                    "package": manifest_reference,
                    "ability": exact_provider.interface,
                },
                "requirement": exact_provider.requirements[0],
                "disposition": "external-launch-obligation",
            }),
        ];
        let contract = json!({
            "schema": "aos.container.static-abilities/v1",
            "platforms": [{
                "platform": {"os": "linux", "architecture": "amd64"},
                "packages": [{
                    "name": package.package.name,
                    "version": package.package.version,
                    "payload": package.package.payload,
                    "manifest": manifest_reference,
                }],
                "abilities": abilities,
                "unresolved_launch_obligations": obligations,
            }],
            "runtime_grants": [],
        });
        let retained_interfaces = fixture
            .interfaces
            .iter()
            .map(|interface| {
                encode_canonical(interface).expect("fixture interface must encode canonically")
            })
            .collect();

        (
            contract,
            StaticPackageArtifacts {
                manifest: manifest_bytes,
                retained_interfaces,
            },
        )
    }

    fn assert_artifact_contract_rejected(contract: &Value, artifacts: &StaticPackageArtifacts) {
        let bytes = aos_contract::canonical::to_vec(contract)
            .expect("static contract fixture must encode canonically");
        validate_static_ability_contract(&bytes, &aggregate_expectation())
            .expect("artifact mutation must remain a valid byte-level contract");

        validate_static_ability_artifacts_with(&bytes, &aggregate_expectation(), |store_path| {
            ensure!(
                store_path == "/nix/store/44444444444444444444444444444444-package-manifest",
                "unexpected fixture manifest path"
            );
            Ok(artifacts.clone())
        })
        .expect_err("artifact-backed identity mutation must fail closed");
    }

    fn set_manifest_digest(contract: &mut Value, digest: Value) {
        contract["platforms"][0]["packages"][0]["manifest"]["digest"] = digest.clone();
        contract["platforms"][0]["abilities"]
            .as_array_mut()
            .expect("fixture abilities must be an array")
            .iter_mut()
            .for_each(|ability| {
                ability["package"]["digest"] = digest.clone();
            });
        contract["platforms"][0]["unresolved_launch_obligations"]
            .as_array_mut()
            .expect("fixture obligations must be an array")
            .iter_mut()
            .for_each(|obligation| {
                obligation["consumer"]["package"]["digest"] = digest.clone();
            });
    }

    fn assert_contract_rejected(contract: &Value, expected_error: &str) {
        let bytes = aos_contract::canonical::to_vec(contract)
            .expect("static contract fixture must encode canonically");
        let error = validate_static_ability_contract(&bytes, &aggregate_expectation())
            .expect_err("noncanonical semantic order must fail closed");

        assert!(
            error.source.to_string().contains(expected_error),
            "unexpected validation error: {error:?}"
        );
    }

    #[test]
    fn accepts_a_canonical_empty_container_contract() {
        let checked = validate_static_ability_contract(EMPTY_CONTAINER, &expectation())
            .expect("canonical static contract must validate");
        assert_eq!(checked.platform_count(), 1);
    }

    #[test]
    fn rejects_a_runtime_grant_even_when_json_is_canonical() {
        let bytes = br#"{"platforms":[{"abilities":[],"packages":[],"platform":{"architecture":"amd64","os":"linux"},"unresolved_launch_obligations":[]}],"runtime_grants":[{}],"schema":"aos.container.static-abilities/v1"}"#;
        validate_static_ability_contract(bytes, &expectation())
            .expect_err("static runtime grants must fail closed");
    }

    #[test]
    fn accepts_strictly_ordered_static_contract_records() {
        let bytes = aos_contract::canonical::to_vec(&populated_container_contract())
            .expect("static contract fixture must encode canonically");

        validate_static_ability_contract(&bytes, &aggregate_expectation())
            .expect("strictly ordered static records must validate");
    }

    #[test]
    fn rejects_reordered_and_duplicate_static_contract_records() {
        for (field, expected_error) in [
            ("packages", "static contract package records"),
            ("abilities", "static contract ability records"),
            (
                "unresolved_launch_obligations",
                "static contract launch obligations",
            ),
        ] {
            let mut reordered = populated_container_contract();
            reordered["platforms"][0][field]
                .as_array_mut()
                .expect("fixture field must be an array")
                .reverse();
            assert_contract_rejected(&reordered, expected_error);

            let mut duplicated = populated_container_contract();
            let records = duplicated["platforms"][0][field]
                .as_array_mut()
                .expect("fixture field must be an array");
            records.insert(1, records[0].clone());
            assert_contract_rejected(&duplicated, expected_error);
        }
    }

    #[test]
    fn rejects_reordered_and_duplicate_platform_records() {
        let mut canonical = populated_container_contract();
        let mut arm64 = canonical["platforms"][0].clone();
        arm64["platform"]["architecture"] = json!("arm64");
        canonical["platforms"] = json!([canonical["platforms"][0].clone(), arm64]);

        let mut reordered = canonical.clone();
        reordered["platforms"]
            .as_array_mut()
            .expect("fixture platforms must be an array")
            .reverse();
        assert_contract_rejected(&reordered, "static contract platform records");

        let mut duplicated = canonical;
        let platforms = duplicated["platforms"]
            .as_array_mut()
            .expect("fixture platforms must be an array");
        platforms.insert(1, platforms[0].clone());
        assert_contract_rejected(&duplicated, "static contract platform records");
    }

    #[test]
    fn rejects_reordered_and_duplicate_requirement_members() {
        for (field, expected_error) in [
            (
                "accepted_interfaces",
                "ability requirement accepted interfaces",
            ),
            ("methods", "ability requirement methods"),
            ("guarantees", "ability requirement guarantees"),
        ] {
            let mut reordered = populated_container_contract();
            reordered["platforms"][0]["unresolved_launch_obligations"][0]["requirement"][field]
                .as_array_mut()
                .expect("fixture requirement member must be an array")
                .reverse();
            assert_contract_rejected(&reordered, expected_error);

            let mut duplicated = populated_container_contract();
            let members =
                duplicated["platforms"][0]["unresolved_launch_obligations"][0]["requirement"]
                    [field]
                    .as_array_mut()
                    .expect("fixture requirement member must be an array");
            members.insert(1, members[0].clone());
            assert_contract_rejected(&duplicated, expected_error);
        }
    }

    #[test]
    fn accepts_exact_artifact_backed_package_and_ability_projections() {
        let (contract, artifacts) = artifact_backed_container_contract();
        let bytes = aos_contract::canonical::to_vec(&contract)
            .expect("static contract fixture must encode canonically");

        validate_static_ability_artifacts_with(&bytes, &aggregate_expectation(), |_| {
            Ok(artifacts.clone())
        })
        .expect("exact artifact-backed projection must validate");
    }

    #[test]
    fn rejects_forged_artifact_backed_package_identities() {
        let (contract, artifacts) = artifact_backed_container_contract();

        let mut changed_name = contract.clone();
        changed_name["platforms"][0]["packages"][0]["name"] = json!("forged-package");
        assert_artifact_contract_rejected(&changed_name, &artifacts);

        let mut changed_version = contract.clone();
        changed_version["platforms"][0]["packages"][0]["version"] = json!("9.9.9");
        assert_artifact_contract_rejected(&changed_version, &artifacts);

        let mut changed_payload = contract.clone();
        changed_payload["platforms"][0]["packages"][0]["payload"]["content"] = json!(digest('0'));
        assert_artifact_contract_rejected(&changed_payload, &artifacts);

        let mut changed_manifest_digest = contract;
        set_manifest_digest(&mut changed_manifest_digest, json!(digest('0')));
        assert_artifact_contract_rejected(&changed_manifest_digest, &artifacts);
    }

    #[test]
    fn rejects_semantically_invalid_artifact_backed_package_companions() {
        let (mut contract, mut artifacts) = artifact_backed_container_contract();
        let mut package: Value = aos_contract::canonical::from_slice(
            &artifacts.manifest,
            "artifact-backed package fixture",
        )
        .expect("artifact-backed package fixture must decode");
        package["exports"][0]["implementation"] = json!(digest('0'));
        artifacts.manifest = aos_contract::canonical::to_vec(&package)
            .expect("mutated package fixture must encode canonically");
        set_manifest_digest(
            &mut contract,
            json!(Sha256Digest::of_bytes(&artifacts.manifest)),
        );

        assert_artifact_contract_rejected(&contract, &artifacts);
    }

    #[test]
    fn rejects_forged_artifact_backed_export_and_provider_identities() {
        let (contract, artifacts) = artifact_backed_container_contract();

        let mut changed_export = contract.clone();
        changed_export["platforms"][0]["abilities"][0]["export"] = json!("forged-export");
        assert_artifact_contract_rejected(&changed_export, &artifacts);

        let mut changed_interface = contract.clone();
        changed_interface["platforms"][0]["abilities"][0]["interface"]["descriptor"] =
            json!(digest('0'));
        let original_interface = contract["platforms"][0]["abilities"][0]["interface"].clone();
        changed_interface["platforms"][0]["unresolved_launch_obligations"]
            .as_array_mut()
            .expect("fixture obligations must be an array")
            .iter_mut()
            .filter(|obligation| obligation["consumer"].get("ability") == Some(&original_interface))
            .for_each(|obligation| {
                obligation["consumer"]["ability"]["descriptor"] = json!(digest('0'));
            });
        assert_artifact_contract_rejected(&changed_interface, &artifacts);

        let mut changed_implementation = contract.clone();
        changed_implementation["platforms"][0]["abilities"][0]["implementation"] =
            json!(digest('0'));
        assert_artifact_contract_rejected(&changed_implementation, &artifacts);

        let mut changed_provider_artifact = contract;
        changed_provider_artifact["platforms"][0]["abilities"][0]["implementation_artifact"]["content"] =
            json!(digest('0'));
        assert_artifact_contract_rejected(&changed_provider_artifact, &artifacts);
    }

    #[test]
    fn rejects_mutated_or_incomplete_artifact_backed_required_obligations() {
        let (contract, artifacts) = artifact_backed_container_contract();

        let mut changed_requirement = contract.clone();
        changed_requirement["platforms"][0]["unresolved_launch_obligations"][0]["requirement"]["methods"] =
            json!(["forged-method"]);
        assert_artifact_contract_rejected(&changed_requirement, &artifacts);

        let mut missing_requirement = contract;
        missing_requirement["platforms"][0]["unresolved_launch_obligations"]
            .as_array_mut()
            .expect("fixture obligations must be an array")
            .remove(0);
        assert_artifact_contract_rejected(&missing_requirement, &artifacts);
    }
}
