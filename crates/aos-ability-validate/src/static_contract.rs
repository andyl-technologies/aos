//! Semantic validation for build-time OCI and boot ability contracts.
//!
//! Static contracts describe authenticated packages, exported implementations,
//! and obligations that remain unresolved until launch. They never carry
//! runtime grants; current runtime admission remains authoritative.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
#[cfg(unix)]
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_ability_model::document::PlatformIdentity;
use aos_ability_model::{
    ArtifactReference, InterfaceDocument, InterfaceKey, LocalKey, PackageDocument,
    RequirementDeclaration, RequirementStrength,
};
use aos_contract::Sha256Digest;
use serde::Deserialize;
use thiserror::Error;

use crate::ResolvedPackageOutput;

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
    /// Identifies the exact AOS target without consulting the evaluator host.
    pub target: Option<PlatformIdentity>,
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
    platforms: Vec<StaticAbilityPlatform>,
    packages: Vec<CheckedStaticAbilityPackage>,
}

impl CheckedStaticAbilityContract {
    /// Returns the number of distinct platform records in the contract.
    #[must_use]
    pub const fn platform_count(&self) -> usize {
        self.platforms.len()
    }

    /// Returns the exact checked platform identities retained by the contract.
    #[must_use]
    pub fn platforms(&self) -> &[StaticAbilityPlatform] {
        &self.platforms
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
    resolved_outputs: Vec<ResolvedPackageOutput>,
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

    /// Returns the artifact-validated symbolic package output resolutions.
    #[must_use]
    pub fn resolved_outputs(&self) -> &[ResolvedPackageOutput] {
        &self.resolved_outputs
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
    pub(crate) source: anyhow::Error,
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

#[cfg(unix)]
pub(crate) fn validate_static_ability_artifacts_with(
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
            platform
                .target
                .as_ref()
                .map(|target| target.system.as_str()),
            platform
                .target
                .as_ref()
                .map(|target| target.architecture.as_str()),
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
                && actual.variant == expected.variant
                && expected
                    .target
                    .as_ref()
                    .is_none_or(|target| contract.platforms[0].target.as_ref() == Some(target)),
            "static ability contract has the wrong platform"
        );
    }

    Ok(contract)
}

fn checked_static_ability_contract(
    contract: StaticAbilityContract,
    package_documents: BTreeMap<(String, Sha256Digest), ArtifactBackedPackage>,
) -> CheckedStaticAbilityContract {
    let platforms = contract
        .platforms
        .iter()
        .map(|record| StaticAbilityPlatform {
            os: record.platform.os.clone(),
            architecture: record.platform.architecture.clone(),
            variant: record.platform.variant.clone(),
            target: record.target.clone(),
        })
        .collect();
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
            resolved_outputs: package_documents
                .get(&manifest_key(&package.manifest))
                .map_or_else(Vec::new, |checked| checked.resolved_outputs.clone()),
        })
        .collect();

    CheckedStaticAbilityContract {
        platforms,
        packages,
    }
}

#[derive(Clone)]
#[cfg(unix)]
pub(crate) struct StaticPackageArtifacts {
    pub(crate) manifest: Vec<u8>,
    pub(crate) resolved_outputs: Vec<u8>,
    pub(crate) retained_interfaces: Vec<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq)]
struct ArtifactBackedPackage {
    document: PackageDocument,
    interfaces: Vec<InterfaceDocument>,
    resolved_outputs: Vec<ResolvedPackageOutput>,
}

#[cfg(unix)]
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
            let resolved_outputs =
                validate_resolved_outputs(&artifacts.resolved_outputs, checked_package.package())?;

            validate_package_projection(platform, static_package, checked_package.package())?;
            let checked = ArtifactBackedPackage {
                document: checked_package.package().clone(),
                // The package's validated catalog includes method targets that
                // have no package-local alias. Stage consumers need those too.
                interfaces: checked_package
                    .validation_context()
                    .interface_catalog()
                    .values()
                    .cloned()
                    .collect(),
                resolved_outputs,
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

#[cfg(unix)]
fn validate_resolved_outputs(
    bytes: &[u8],
    package: &PackageDocument,
) -> Result<Vec<ResolvedPackageOutput>> {
    aos_contract::canonical::require_canonical(bytes, "resolved package output selectors")?;
    let outputs: Vec<ResolvedPackageOutput> =
        aos_contract::canonical::from_slice(bytes, "resolved package output selectors")?;
    ensure!(
        u64::try_from(outputs.len())? <= ABILITY_LIMITS_V1.max_collection_items,
        "resolved package output selector catalog contains excessive records"
    );
    ensure_strict_order_by(
        &outputs,
        |left, right| {
            (left.package.as_str(), left.output.as_str())
                .cmp(&(right.package.as_str(), right.output.as_str()))
        },
        "resolved package output selectors",
    )?;

    for output in &outputs {
        validate_artifact_reference(&output.artifact)?;
        ensure!(
            package
                .artifacts
                .iter()
                .any(|artifact| artifact.identity() == output.artifact.identity()),
            "resolved package output is absent from the authenticated package artifact catalog"
        );
    }
    Ok(outputs)
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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
            expectation.execution_stage.is_none()
                && stage.execution_stage.is_none()
                && stage.target.is_none(),
            "container static contracts cannot declare a boot execution stage or AOS target"
        ),
        StaticAbilityArtifactClass::Bootable => ensure!(
            expectation.execution_stage.is_some()
                && stage.execution_stage == expectation.execution_stage
                && stage.target.is_some(),
            "boot static contract has the wrong execution stage or omits its exact AOS target"
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

pub(crate) fn validate_store_path(path: &str) -> Result<()> {
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
        left.target
            .as_ref()
            .map_or("", |target| target.system.as_str()),
        left.target
            .as_ref()
            .map_or("", |target| target.architecture.as_str()),
    )
        .cmp(&(
            right.platform.os.as_str(),
            right.platform.architecture.as_str(),
            right.platform.variant.as_deref().unwrap_or_default(),
            right
                .target
                .as_ref()
                .map_or("", |target| target.system.as_str()),
            right
                .target
                .as_ref()
                .map_or("", |target| target.architecture.as_str()),
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
    target: Option<PlatformIdentity>,
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

#[cfg(all(test, unix))]
#[path = "static_contract_tests.rs"]
mod tests;
