//! Complete fail-closed image finalization orchestration.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;

use crate::assembly::{AssemblyFileKind, UnsignedImageAssemblyV1};
use crate::bundle::seal_image_artifacts;
use crate::disk::build_logical_disk;
use crate::finalize::prepare_filesystems;
use crate::formats::build_disk_formats;
use crate::input::{VerifiedInput, digest_regular_file, verified_tool};
use crate::request::ImageRequestAuthorizer;
use crate::result::{
    FINALIZED_IMAGE_SET_V1, FinalizedImageArtifactV1, FinalizedImageKind, FinalizedImageSetV1,
};
use crate::signer::ImageSigner;
use crate::tools::PinnedTool;
use crate::uki::build_signed_efi_artifacts;

const TOOL_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Complete finalized image-set output rooted in a private work directory.
#[derive(Debug)]
pub struct FinalizedImageOutputV1 {
    /// Directory containing the stable artifact paths and manifest.
    pub root: PathBuf,
    /// Canonical finalized image-set manifest.
    pub manifest: PathBuf,
    /// Validated in-memory form of the manifest.
    pub image_set: FinalizedImageSetV1,
}

/// Finalizes one captured public assembly into all production image artifacts.
///
/// The caller supplies the signer and authorization policy, while this
/// function owns stage ordering and makes no artifact visible in the returned
/// output directory until every signing and reconstruction check has passed.
/// `work` must not exist. It is created mode `0700` and should be placed on a
/// filesystem with enough capacity for the sparse logical disk and all four
/// downloadable encodings.
///
/// # Errors
///
/// Returns an error for an invalid assembly, an existing or non-absolute work
/// path, tool or input drift, unauthorized/invalid signing, reconstruction
/// failure, artifact budget overflow, or inability to durably seal the final
/// manifest.
pub async fn finalize_image_set(
    assembly_root: &Path,
    assembly: &UnsignedImageAssemblyV1,
    work: &Path,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    mut resolve_owner_nar_hash: impl FnMut(&str) -> Result<String>,
) -> Result<FinalizedImageOutputV1> {
    assembly.validate()?;
    if !work.is_absolute() || work.symlink_metadata().is_ok() {
        bail!("finalizer work path must be a new absolute path");
    }
    fs::create_dir(work)
        .with_context(|| format!("creating private finalizer work path {}", work.display()))?;
    fs::set_permissions(work, fs::Permissions::from_mode(0o700))?;

    let prepared_work = create_stage(work, "filesystem-stage")?;
    let prepared = prepare_filesystems(
        assembly_root,
        assembly,
        &prepared_work,
        signer,
        authorizer,
        &mut resolve_owner_nar_hash,
    )
    .await?;

    let efi_work = create_stage(work, "efi-stage")?;
    let efi = build_signed_efi_artifacts(
        assembly_root,
        assembly,
        &prepared,
        &efi_work,
        signer,
        authorizer,
        &mut resolve_owner_nar_hash,
    )
    .await?;

    let disk_work = create_stage(work, "disk-stage")?;
    let mkfs_vfat = pin_tool(
        assembly,
        "mkfs_vfat",
        &disk_work,
        &mut resolve_owner_nar_hash,
    )?;
    let mcopy = pin_tool(assembly, "mcopy", &disk_work, &mut resolve_owner_nar_hash)?;
    let sfdisk = pin_tool(assembly, "sfdisk", &disk_work, &mut resolve_owner_nar_hash)?;
    let disk = build_logical_disk(
        assembly, &prepared, &efi, &disk_work, &mkfs_vfat, &mcopy, &sfdisk,
    )
    .await?;

    let format_work = create_stage(work, "format-stage")?;
    let zstd = pin_tool(assembly, "zstd", &format_work, &mut resolve_owner_nar_hash)?;
    let qemu_img = pin_tool(
        assembly,
        "qemu_img",
        &format_work,
        &mut resolve_owner_nar_hash,
    )?;
    let formats = build_disk_formats(
        &disk.path,
        &format_work.join("output"),
        &format_work.join("scratch"),
        mebibytes(assembly.budgets.download_mib)?,
        &zstd,
        &qemu_img,
    )
    .await?;

    let bundle_work = create_stage(work, "bundle-stage")?;
    let tar = pin_tool(assembly, "tar", &bundle_work, &mut resolve_owner_nar_hash)?;
    let bundle_zstd = pin_tool(assembly, "zstd", &bundle_work, &mut resolve_owner_nar_hash)?;
    let openssl = pin_tool(
        assembly,
        "openssl",
        &bundle_work,
        &mut resolve_owner_nar_hash,
    )?;
    let bundle_inputs = bundle_work.join("inputs");
    fs::create_dir(&bundle_inputs)?;
    let secure_boot_certificate = bundle_inputs.join("secure-boot-db.crt");
    VerifiedInput::open(
        assembly_root,
        assembly,
        AssemblyFileKind::SecureBootCertificate,
    )?
    .copy_new(&secure_boot_certificate)?;
    let sealed = seal_image_artifacts(
        assembly_root,
        assembly,
        &prepared,
        &efi,
        &disk,
        &formats,
        &bundle_work,
        &secure_boot_certificate,
        &tar,
        &bundle_zstd,
        &openssl,
        signer,
        authorizer,
    )
    .await?;

    let final_root = work.join("finalized");
    let artifacts_root = final_root.join("artifacts");
    fs::create_dir(&final_root)?;
    fs::create_dir(&artifacts_root)?;
    let logical_digest = formats.logical_disk_sha256;
    let mut artifacts = Vec::new();
    for (id, kind, source, name, reconstruction) in [
        (
            "logical-disk",
            FinalizedImageKind::LogicalDisk,
            disk.path.as_path(),
            "aos.logical.raw",
            None,
        ),
        (
            "raw",
            FinalizedImageKind::Raw,
            formats.raw_zstd.as_path(),
            "aos.raw.zst",
            Some(logical_digest),
        ),
        (
            "qcow2",
            FinalizedImageKind::Qcow2,
            formats.qcow2.as_path(),
            "aos.qcow2",
            Some(logical_digest),
        ),
        (
            "vmdk",
            FinalizedImageKind::Vmdk,
            formats.vmdk.as_path(),
            "aos.vmdk",
            Some(logical_digest),
        ),
        (
            "vhd",
            FinalizedImageKind::Vhd,
            formats.vhd.as_path(),
            "aos.vhd",
            Some(logical_digest),
        ),
        (
            "uki-a",
            FinalizedImageKind::UkiA,
            efi.uki_a.as_path(),
            "aos-a.efi",
            None,
        ),
        (
            "uki-b",
            FinalizedImageKind::UkiB,
            efi.uki_b.as_path(),
            "aos-b.efi",
            None,
        ),
        (
            "recovery-uki-a",
            FinalizedImageKind::RecoveryUkiA,
            efi.recovery_uki_a.as_path(),
            "aos-recovery-a.efi",
            None,
        ),
        (
            "recovery-uki-b",
            FinalizedImageKind::RecoveryUkiB,
            efi.recovery_uki_b.as_path(),
            "aos-recovery-b.efi",
            None,
        ),
        (
            "recovery-bundle",
            FinalizedImageKind::RecoveryBundle,
            sealed.recovery_bundle.as_path(),
            "aos-recovery.tar.zst",
            None,
        ),
        (
            "metadata",
            FinalizedImageKind::Metadata,
            sealed.metadata.as_path(),
            "image-info.json",
            None,
        ),
    ] {
        let relative = BundlePath::parse(&format!("artifacts/{name}"))?;
        let destination = final_root.join(relative.as_str());
        fs::rename(source, &destination)
            .with_context(|| format!("installing finalized artifact {}", destination.display()))?;
        let (size_bytes, sha256) = digest_regular_file(&destination)?;
        artifacts.push(FinalizedImageArtifactV1 {
            id: id.to_owned(),
            kind,
            path: relative,
            size_bytes,
            sha256,
            reconstructed_logical_disk: reconstruction,
        });
    }
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));

    let mut signing_operations = prepared.signing_operations;
    signing_operations.extend(efi.signing_operations);
    signing_operations.push(sealed.signing_operation);
    let image_set = FinalizedImageSetV1 {
        schema_version: FINALIZED_IMAGE_SET_V1.to_owned(),
        assembly_digest: Sha256Digest::of_canonical(&assembly.schema_version, assembly)?,
        platform: assembly.platform,
        system_variant: assembly.system_variant.clone(),
        artifacts,
        signing_operations,
    };
    image_set.validate(assembly)?;
    write_new_synced(
        &final_root.join("unsigned-image-assembly.json"),
        &canonical::to_vec(assembly)?,
    )?;
    let manifest = final_root.join("finalized-image-set.json");
    write_new_synced(&manifest, &canonical::to_vec(&image_set)?)?;
    fs::File::open(&final_root)?.sync_all()?;

    Ok(FinalizedImageOutputV1 {
        root: final_root,
        manifest,
        image_set,
    })
}

fn create_stage(work: &Path, name: &str) -> Result<PathBuf> {
    let stage = work.join(name);
    fs::create_dir(&stage)?;
    Ok(stage)
}

fn pin_tool(
    assembly: &UnsignedImageAssemblyV1,
    id: &str,
    work: &Path,
    resolver: &mut impl FnMut(&str) -> Result<String>,
) -> Result<PinnedTool> {
    PinnedTool::from_verified(
        verified_tool(assembly, id, resolver)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn mebibytes(value: u64) -> Result<u64> {
    value
        .checked_mul(1024 * 1024)
        .context("byte budget overflow")
}
