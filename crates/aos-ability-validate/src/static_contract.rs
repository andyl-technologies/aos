//! Semantic validation for build-time OCI and boot ability contracts.
//!
//! Static contracts describe authenticated packages, exported implementations,
//! and obligations that remain unresolved until launch. They never carry
//! runtime grants; current runtime admission remains authoritative.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ArtifactReference, InterfaceKey, LocalKey, RequirementDeclaration, RequirementStrength,
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
    validate_static_ability_contract_inner(bytes, expectation)
        .map_err(|source| StaticAbilityContractValidationError { source })
}

fn validate_static_ability_contract_inner(
    bytes: &[u8],
    expectation: &StaticAbilityContractExpectation,
) -> Result<CheckedStaticAbilityContract> {
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

    Ok(CheckedStaticAbilityContract {
        platform_count: contract.platforms.len(),
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
}
