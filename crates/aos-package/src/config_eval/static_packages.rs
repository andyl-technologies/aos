//! Immutable-image package selection through the checked host ability contract.
//!
//! The image's static contract is the sole package inventory. Image package
//! pins retain a reference to that contract plus a package key; every later
//! resolution revalidates the exact contract and package companions rather
//! than copying a second catalog into the configuration manifest.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{InterfaceDocument, PackageDocument};
use aos_ability_validate::{
    CheckedStaticAbilityContract, ResolvedPackageOutput, StaticAbilityArtifactClass,
    StaticAbilityContractExpectation, StaticAbilityExecutionStage,
    validate_static_ability_artifacts_at_store_root,
};
use aos_contract::Sha256Digest;

use super::runtime::{ContractOrigin, LocalRuntimePackage};
use super::store_view::StoreViewLocator;

const INITRD_STORE_ROOT: &str = "/nix/store";
const STATIC_CONTRACT_FILE: &str = "contract.json";
const MAX_STATIC_CONTRACT_BYTES: u64 = 4 * 1024 * 1024;

/// Carries one package document and its exact checked companion identity.
pub(crate) struct ResolvedContract {
    pub(crate) document: PackageDocument,
    pub(crate) interfaces: Vec<InterfaceDocument>,
    pub(crate) resolved_outputs: Vec<ResolvedPackageOutput>,
    pub(crate) manifest_store_path: String,
    pub(crate) manifest_nar_hash: String,
    pub(crate) manifest_digest: Sha256Digest,
}

/// Loads image-local packages from the exact checked host static contract.
///
/// # Errors
///
/// Returns an error when the embedded contract link, artifact, package
/// companions, platform, or package identities are absent or invalid.
pub(super) fn load(store_view: &StoreViewLocator) -> Result<BTreeMap<String, LocalRuntimePackage>> {
    let (contract, checked) = checked_host_selection(store_view)?;
    let platform = runtime_platform(&checked)?;

    let mut packages = BTreeMap::new();
    for selected in checked.packages() {
        let document = selected
            .package_document()
            .context("checked static package has no artifact-backed document")?;
        let name = selected.name().as_str().to_string();
        ensure!(
            document.package.name == *selected.name()
                && document.package.version == selected.version()
                && document.package.payload == *selected.payload(),
            "checked static package selection differs from its package document"
        );
        require_immutable_artifact(store_view, &document.package.payload.store_path)?;

        let package = LocalRuntimePackage {
            version: selected.version().to_string(),
            platform: platform.clone(),
            store_path: selected.payload().store_path.clone(),
            nar_hash: selected.payload().nar_hash.to_string(),
            contract: Some(ContractOrigin::EmbeddedStatic {
                contract: contract.clone(),
                package: selected.name().clone(),
            }),
            closure: std::cell::RefCell::new(None),
        };
        ensure!(
            packages.insert(name.clone(), package).is_none(),
            "host static ability contract repeats package '{name}'"
        );
    }

    Ok(packages)
}

/// Derives immutable-image package measurements from the checked selection.
///
/// # Errors
///
/// Returns an error when the embedded static contract or one of its exact
/// package companions cannot be authenticated.
pub(crate) fn measurement_catalog(
    store_view: &StoreViewLocator,
) -> Result<Vec<crate::package_attestation::PackageMeasurementCatalogEntry>> {
    let (_, checked) = checked_host_selection(store_view)?;

    checked
        .packages()
        .map(|selected| {
            let root_digest = selected.payload().nar_hash.to_string();
            let manifest_digest = selected.manifest().digest().to_string();
            let measurement = crate::package_attestation::package_measurement_digest(
                selected.name().as_str(),
                selected.version(),
                &root_digest,
                &manifest_digest,
            );
            Ok(crate::package_attestation::PackageMeasurementCatalogEntry {
                name: selected.name().as_str().to_string(),
                version: selected.version().to_string(),
                root_digest,
                measurement,
            })
        })
        .collect()
}

/// Resolves one runtime pin to the same checked package-document view.
///
/// # Errors
///
/// Returns an error when registry publication metadata is invalid, or when an
/// embedded contract, package key, coordinate, or artifact identity changed.
pub(super) fn resolve(
    name: &str,
    version: &str,
    platform: &str,
    store_path: &str,
    nar_hash: &str,
    origin: &ContractOrigin,
    store_view: &StoreViewLocator,
) -> Result<ResolvedContract> {
    match origin {
        ContractOrigin::Registry { metadata } => {
            let coordinate = crate::package_contract::PackageContractCoordinate {
                name,
                version,
                platform,
                store_path,
                nar_hash,
            };
            let (document, interfaces) =
                crate::package_contract::resolve_pinned_package_document(coordinate, metadata)?;
            Ok(ResolvedContract {
                document,
                interfaces,
                resolved_outputs: metadata
                    .selectors
                    .iter()
                    .map(|selector| {
                        Ok(ResolvedPackageOutput {
                            package: aos_ability_model::LocalKey::new(&selector.package)?,
                            output: aos_ability_model::LocalKey::new(&selector.output)?,
                            artifact: crate::package_contract::artifact_reference(
                                &selector.artifact,
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                manifest_store_path: metadata.document.store_path.clone(),
                manifest_nar_hash: metadata.document.nar_hash.clone(),
                manifest_digest: Sha256Digest::parse(&metadata.document.document_sha256)?,
            })
        }
        ContractOrigin::EmbeddedStatic { contract, package } => {
            ensure!(
                package.as_str() == name,
                "embedded package key differs from runtime pin"
            );
            let current =
                crate::registry_ops::resolve_store_artifact_reference(&contract.store_path)?;
            ensure!(
                current == *contract,
                "embedded static contract artifact identity changed"
            );
            let lower_contract = store_view
                .read_path(Path::new(&contract.store_path))?
                .join(STATIC_CONTRACT_FILE);
            let bytes = read_contract(&lower_contract)?;
            let checked = validate_static_ability_artifacts_at_store_root(
                &bytes,
                &host_expectation(),
                &store_view.read_root,
            )?;
            ensure!(
                runtime_platform(&checked)? == platform,
                "embedded static package target differs from runtime pin"
            );
            let mut matching = checked
                .packages()
                .filter(|selected| selected.name() == package);
            let selected = matching
                .next()
                .with_context(|| format!("embedded static contract omits package '{name}'"))?;
            ensure!(
                matching.next().is_none(),
                "embedded static contract repeats package '{name}'"
            );
            ensure!(
                selected.version() == version
                    && selected.payload().store_path == store_path
                    && selected.payload().nar_hash.to_string() == nar_hash,
                "embedded static package coordinate differs from runtime pin"
            );
            let document = selected
                .package_document()
                .cloned()
                .context("embedded static package has no artifact-backed document")?;
            let manifest = crate::registry_ops::resolve_store_artifact_reference(
                selected.manifest().store_path(),
            )?;
            Ok(ResolvedContract {
                document,
                interfaces: selected.retained_interfaces().to_vec(),
                resolved_outputs: selected.resolved_outputs().to_vec(),
                manifest_store_path: selected.manifest().store_path().to_string(),
                manifest_nar_hash: manifest.nar_hash.to_string(),
                manifest_digest: selected.manifest().digest(),
            })
        }
    }
}

fn host_expectation() -> StaticAbilityContractExpectation {
    boot_expectation(StaticAbilityExecutionStage::Host)
}

fn boot_expectation(
    execution_stage: StaticAbilityExecutionStage,
) -> StaticAbilityContractExpectation {
    StaticAbilityContractExpectation {
        artifact_class: StaticAbilityArtifactClass::Bootable,
        execution_stage: Some(execution_stage),
        platform: None,
    }
}

/// Authenticates every package selected by an embedded initrd contract.
///
/// The static contract fixes package documents and companion identities. This
/// function additionally rechecks their live store objects before returning
/// the opaque runtime package set used by handler dispatch.
///
/// # Errors
///
/// Returns an error when the contract, package companion, interface catalog,
/// or any selected package artifact differs from the embedded selection.
pub(super) fn verified_initrd_packages(
    contract_bytes: &[u8],
) -> Result<crate::package_contract::VerifiedPackageContractSet> {
    let checked = validate_static_ability_artifacts_at_store_root(
        contract_bytes,
        &boot_expectation(StaticAbilityExecutionStage::Initrd),
        Path::new(INITRD_STORE_ROOT),
    )?;
    let platform = runtime_platform(&checked)?;
    let mut packages = Vec::with_capacity(checked.packages().len());

    for selected in checked.packages() {
        let document = selected
            .package_document()
            .cloned()
            .context("checked initrd package has no artifact-backed document")?;
        ensure!(
            document.package.name == *selected.name()
                && document.package.version == selected.version()
                && document.package.payload == *selected.payload(),
            "checked initrd package selection differs from its package document"
        );
        let manifest = crate::registry_ops::resolve_store_artifact_reference(
            selected.manifest().store_path(),
        )?;
        let resolved = ResolvedContract {
            document,
            interfaces: selected.retained_interfaces().to_vec(),
            resolved_outputs: selected.resolved_outputs().to_vec(),
            manifest_store_path: selected.manifest().store_path().to_string(),
            manifest_nar_hash: manifest.nar_hash.to_string(),
            manifest_digest: selected.manifest().digest(),
        };
        let coordinate = crate::package_contract::PackageContractCoordinate {
            name: selected.name().as_str(),
            version: selected.version(),
            platform: &platform,
            store_path: &selected.payload().store_path,
            nar_hash: &selected.payload().nar_hash.to_string(),
        };
        packages.push(crate::package_contract::verify_embedded_static_package(
            coordinate, resolved,
        )?);
    }

    crate::package_contract::VerifiedPackageContractSet::from_verified(packages)
}

fn runtime_platform(checked: &CheckedStaticAbilityContract) -> Result<String> {
    let [platform] = checked.platforms() else {
        anyhow::bail!("boot static ability contract must select one exact platform");
    };
    let target = platform
        .target
        .as_ref()
        .context("boot static ability contract omits its authenticated target platform")?;
    Ok(format!(
        "{}-{}",
        target.architecture.as_str(),
        target.system.as_str()
    ))
}

pub(crate) fn checked_host_selection(
    store_view: &StoreViewLocator,
) -> Result<(
    aos_ability_model::ArtifactReference,
    CheckedStaticAbilityContract,
)> {
    store_view.validate()?;
    let contract_root = contract_root(store_view)?;
    let contract = crate::registry_ops::resolve_store_artifact_reference(
        contract_root
            .to_str()
            .context("host static ability contract path is not UTF-8")?,
    )?;
    let contract_path = store_view.static_contract_read_path()?;
    let bytes = read_contract(&contract_path)?;
    let checked = validate_static_ability_artifacts_at_store_root(
        &bytes,
        &host_expectation(),
        &store_view.read_root,
    )?;

    Ok((contract, checked))
}

fn contract_root(store_view: &StoreViewLocator) -> Result<&Path> {
    let root = store_view
        .static_contract
        .parent()
        .context("host static contract has no artifact root")?;
    store_view.read_path(root)?;
    Ok(root)
}

fn require_immutable_artifact(store_view: &StoreViewLocator, path: &str) -> Result<PathBuf> {
    let lower = store_view.read_path(Path::new(path))?;
    ensure!(
        lower.exists(),
        "image package artifact {path} is absent from the immutable store"
    );
    Ok(lower)
}

fn read_contract(path: &Path) -> Result<Vec<u8>> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting static contract {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= MAX_STATIC_CONTRACT_BYTES,
        "static contract must be a bounded regular file: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("opening static contract {}", path.display()))?
        .take(MAX_STATIC_CONTRACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading static contract {}", path.display()))?;
    ensure!(
        u64::try_from(bytes.len())? == metadata.len(),
        "static contract changed while being read: {}",
        path.display()
    );
    Ok(bytes)
}
