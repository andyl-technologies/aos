//! Test-only decoder for a producer-emitted initrd stage contract.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use aos_image_finalizer::assembly::UNSIGNED_IMAGE_ASSEMBLY_V3;
use aos_image_finalizer::capture::capture_unsigned_assembly;
use aos_image_finalizer::initrd_contract::InitrdStageContractV1;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;

/// Decodes a canonical contract and binds it to exact archive bytes.
///
/// # Errors
///
/// Returns an error when the two paths are absent, either input is not a
/// single-link regular file, or the Rust contract reader rejects the canonical
/// document, stage semantics, archive size, or archive digest.
pub(super) fn verify(arguments: &[String]) -> Result<()> {
    if arguments.len() != 2 {
        bail!("usage: aos-release-fleet-fixture initrd-contract CONTRACT ARCHIVE");
    }
    let contract_path = Path::new(&arguments[0]);
    let archive_path = Path::new(&arguments[1]);
    let contract_metadata = contract_path
        .symlink_metadata()
        .with_context(|| format!("reading metadata for {}", contract_path.display()))?;
    let archive_metadata = archive_path
        .symlink_metadata()
        .with_context(|| format!("reading metadata for {}", archive_path.display()))?;
    ensure!(
        contract_metadata.is_file()
            && contract_metadata.nlink() == 1
            && archive_metadata.is_file()
            && archive_metadata.nlink() == 1,
        "initrd contract and archive must be single-link regular files"
    );

    let contract_bytes = fs::read(contract_path)
        .with_context(|| format!("reading initrd contract {}", contract_path.display()))?;
    canonical::require_canonical(&contract_bytes, "initrd stage contract")?;
    let contract: InitrdStageContractV1 =
        canonical::from_slice(&contract_bytes, "initrd stage contract")?;
    contract.validate()?;

    let archive = fs::read(archive_path)
        .with_context(|| format!("reading initrd archive {}", archive_path.display()))?;
    ensure!(
        contract.artifact.size_bytes == u64::try_from(archive.len())?
            && contract.artifact.sha256 == Sha256Digest::of_bytes(&archive),
        "initrd archive differs from its stage contract"
    );
    Ok(())
}

/// Captures and validates a complete producer-emitted unsigned assembly.
///
/// # Errors
///
/// Returns an error when the assembly is malformed, an input changes during
/// capture, the image is not schema v3, or the embedded initrd contract and
/// exact archive bytes disagree.
pub(super) fn verify_assembly(arguments: &[String]) -> Result<()> {
    if arguments.len() != 2 {
        bail!("usage: aos-release-fleet-fixture image-assembly-contract ROOT RELEASE_ID");
    }
    let assembly = capture_unsigned_assembly(Path::new(&arguments[0]), &arguments[1], |_| {
        Ok(format!("sha256:{}", "a".repeat(64)))
    })?;
    ensure!(
        assembly.schema_version == UNSIGNED_IMAGE_ASSEMBLY_V3 && assembly.initrd_contract.is_some(),
        "producer assembly lacks its version-3 initrd contract"
    );
    Ok(())
}
