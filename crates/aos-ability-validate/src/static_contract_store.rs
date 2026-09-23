//! Filesystem-backed companions for otherwise pure static ability validation.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ABILITY_LIMITS_V1;

use crate::static_contract::{
    CheckedStaticAbilityContract, StaticAbilityContractExpectation,
    StaticAbilityContractValidationError, StaticPackageArtifacts,
    validate_static_ability_artifacts_with, validate_store_path,
};

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
    let resolved_outputs_path = package_path.join("selectors.json");
    let resolved_outputs =
        read_bounded_regular_file(&resolved_outputs_path, "static package output selectors")?;
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
        resolved_outputs,
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
