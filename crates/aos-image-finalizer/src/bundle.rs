//! Final image metadata and signed recovery-bundle sealing.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use aos_release::signing::{
    SignatureAlgorithm, SignatureResponseV1, SignerRole, SigningContext, SigningOperation,
    verify_response_binding,
};
use base64::Engine as _;
use serde::Serialize;

use crate::assembly::{AssemblyFileKind, UnsignedImageAssemblyV1};
use crate::disk::{FinalDiskLayoutV1, LogicalDiskV1};
use crate::finalize::PreparedFilesystemsV1;
use crate::formats::DiskFormatsV1;
use crate::input::{VerifiedInput, digest_regular_file};
use crate::request::{ImageRequestAuthorizer, ImageSigningIntent, verify_intent};
use crate::signer::ImageSigner;
use crate::tools::PinnedTool;
use crate::uki::SignedEfiArtifactsV1;

const MAX_BUNDLE_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_TOOL_STDOUT_BYTES: u64 = 1024 * 1024;

/// Final metadata and downloadable signed recovery archive.
#[derive(Debug)]
pub struct SealedImageArtifactsV1 {
    /// Canonical final image metadata.
    pub metadata: PathBuf,
    /// Zstandard-compressed deterministic recovery tar archive.
    pub recovery_bundle: PathBuf,
    /// Canonical signed component manifest inside the archive.
    pub recovery_bundle_manifest: PathBuf,
    /// Raw signature over the component manifest.
    pub recovery_bundle_signature: PathBuf,
    /// Audited provider response for the bundle manifest.
    pub signing_operation: SignatureResponseV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ImageMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<aos_release::qualification::capabilities::ImageCapabilities>,
    schema_version: &'static str,
    assembly_digest: Sha256Digest,
    release_id: &'a str,
    version: &'a str,
    platform: Platform,
    system_variant: &'a str,
    sbat_generation: u64,
    secure_boot_certificate_sha256: Sha256Digest,
    root: RootMetadata,
    efi: EfiMetadata,
    disk: DiskMetadata<'a>,
    formats: Vec<ArtifactFact>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RootMetadata {
    filesystem_sha256: Sha256Digest,
    filesystem_size_bytes: u64,
    verity_sha256: Sha256Digest,
    verity_size_bytes: u64,
    root_hash: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EfiMetadata {
    normal_a: UkiMetadata,
    normal_b: UkiMetadata,
    recovery_a: ArtifactFact,
    recovery_b: ArtifactFact,
    bootloader: ArtifactFact,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UkiMetadata {
    artifact: ArtifactFact,
    expected_ready_pcr11: Sha256Digest,
    measurement: ArtifactFact,
    measurement_signature: ArtifactFact,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DiskMetadata<'a> {
    logical: ArtifactFact,
    disk_guid: &'a str,
    fat_volume_id: &'a str,
    layout: &'a FinalDiskLayoutV1,
    inactive_slot_state: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFact {
    id: String,
    path: String,
    size_bytes: u64,
    sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryBundleManifest<'a> {
    schema: &'static str,
    release: &'a str,
    platform: Platform,
    module_abi: u64,
    recovery_abi: u64,
    components: Vec<ArtifactFact>,
}

/// Writes canonical image metadata and seals a complete recovery archive.
///
/// # Errors
///
/// Returns an error for file identity drift, unsafe bundle paths, unauthorized
/// signing, invalid db-key signature, archive failure, or a download-budget
/// violation.
#[allow(clippy::too_many_arguments)]
pub async fn seal_image_artifacts(
    assembly_root: &Path,
    assembly: &UnsignedImageAssemblyV1,
    prepared: &PreparedFilesystemsV1,
    efi: &SignedEfiArtifactsV1,
    disk: &LogicalDiskV1,
    formats: &DiskFormatsV1,
    work: &Path,
    secure_boot_certificate: &Path,
    tar: &PinnedTool,
    zstd: &PinnedTool,
    openssl: &PinnedTool,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
) -> Result<SealedImageArtifactsV1> {
    let output = work.join("sealed-output");
    let bundle_tree = work.join("recovery-bundle-tree");
    let scratch = work.join("bundle-scratch");
    fs::create_dir(&output)?;
    fs::create_dir(&bundle_tree)?;
    fs::create_dir(&scratch)?;

    let metadata = output.join("image-info.json");
    let metadata_value = image_metadata(
        assembly,
        prepared,
        efi,
        disk,
        formats,
        secure_boot_certificate,
    )?;
    fs::write(&metadata, canonical::to_vec(&metadata_value)?)?;

    let mut components = Vec::new();
    for (id, source, relative) in [
        ("root-image", prepared.root_filesystem.as_path(), "root.img"),
        (
            "root-verity",
            prepared.verity.hash_tree.as_path(),
            "root.verity",
        ),
        (
            "root-hash",
            prepared.verity.root_hash_file.as_path(),
            "root.roothash",
        ),
        ("normal-uki-a", efi.uki_a.as_path(), "uki-a.efi"),
        ("normal-uki-b", efi.uki_b.as_path(), "uki-b.efi"),
        (
            "recovery-uki-a",
            efi.recovery_uki_a.as_path(),
            "recovery-a.efi",
        ),
        (
            "recovery-uki-b",
            efi.recovery_uki_b.as_path(),
            "recovery-b.efi",
        ),
        (
            "measurement-a",
            efi.measurement_a.measurement.as_path(),
            "uki-a.efi.measurement",
        ),
        (
            "measurement-a-signature",
            efi.measurement_a.signature.as_path(),
            "uki-a.efi.measurement.sig",
        ),
        (
            "measurement-b",
            efi.measurement_b.measurement.as_path(),
            "uki-b.efi.measurement",
        ),
        (
            "measurement-b-signature",
            efi.measurement_b.signature.as_path(),
            "uki-b.efi.measurement.sig",
        ),
        (
            "recovery-slot-manifest",
            efi.recovery_manifest.as_path(),
            "slot-manifest.json",
        ),
        (
            "recovery-slot-manifest-signature",
            efi.recovery_manifest_signature.as_path(),
            "slot-manifest.json.sig",
        ),
        ("image-metadata", metadata.as_path(), "image-info.json"),
    ] {
        let destination = bundle_tree.join(relative);
        copy_new(source, &destination)?;
        components.push(artifact_fact(id, relative, &destination)?);
    }
    let enrollment = bundle_tree.join("firmware-enrollment.tar");
    VerifiedInput::open(
        assembly_root,
        assembly,
        AssemblyFileKind::FirmwareEnrollment,
    )?
    .copy_new(&enrollment)?;
    components.push(artifact_fact(
        "firmware-enrollment",
        "firmware-enrollment.tar",
        &enrollment,
    )?);
    copy_new(
        secure_boot_certificate,
        &bundle_tree.join("secure-boot-db.crt"),
    )?;
    components.push(artifact_fact(
        "secure-boot-certificate",
        "secure-boot-db.crt",
        &bundle_tree.join("secure-boot-db.crt"),
    )?);
    components.sort_by(|left, right| left.id.cmp(&right.id));

    let bundle_manifest = output.join("recovery-bundle.json");
    let bundle_value = RecoveryBundleManifest {
        schema: "aos.recovery-bundle/v1",
        release: &assembly.version,
        platform: assembly.platform,
        module_abi: assembly.module_abi,
        recovery_abi: assembly.recovery_abi,
        components,
    };
    fs::write(&bundle_manifest, canonical::to_vec(&bundle_value)?)?;
    let (_, payload_digest) = digest_regular_file(&bundle_manifest)?;
    let intent = ImageSigningIntent {
        assembly_policy_id: &assembly.signer_roles.secure_boot,
        role: SignerRole::SecureBootDb,
        algorithm: SignatureAlgorithm::PublicKeySha256,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: "recovery-bundle".to_owned(),
        },
        payload_digest,
    };
    let request = authorizer.authorize(&intent)?;
    verify_intent(&request, &intent)?;
    let response = signer.sign_detached(&request, &bundle_manifest).await?;
    verify_response_binding(&request, &response)?;
    let (_, certificate_digest) = digest_regular_file(secure_boot_certificate)?;
    if response.output_digest.is_some()
        || response.verification_material_digest != certificate_digest
    {
        bail!("recovery bundle signer response differs from the db certificate");
    }
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.signature_base64)
        .context("decoding recovery bundle signature")?;
    if signature_bytes.is_empty() || signature_bytes.len() > MAX_BUNDLE_SIGNATURE_BYTES {
        bail!("recovery bundle signature is empty or oversized");
    }
    let bundle_signature = output.join("recovery-bundle.json.sig");
    fs::write(&bundle_signature, signature_bytes)?;
    crate::recovery::verify_manifest_signature(
        &bundle_manifest,
        &bundle_signature,
        secure_boot_certificate,
        &scratch,
        openssl,
    )
    .await?;
    copy_new(&bundle_manifest, &bundle_tree.join("recovery-bundle.json"))?;
    copy_new(
        &bundle_signature,
        &bundle_tree.join("recovery-bundle.json.sig"),
    )?;

    let archive = scratch.join("recovery-bundle.tar");
    let _ = tar
        .run(
            [
                "--sort=name",
                "--mtime=@0",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "-cf",
                path_text(&archive)?,
                "-C",
                path_text(&bundle_tree)?,
                ".",
            ],
            MAX_TOOL_STDOUT_BYTES,
        )
        .await?;
    let recovery_bundle = output.join("aos-recovery.tar.zst");
    let maximum = assembly
        .budgets
        .download_mib
        .checked_mul(1024 * 1024)
        .context("recovery bundle byte budget overflow")?;
    let _ = zstd
        .run_to_new_file(
            [
                "--ultra",
                "-22",
                "-T1",
                "-q",
                "-c",
                "--",
                path_text(&archive)?,
            ],
            None,
            &recovery_bundle,
            maximum,
        )
        .await?;
    Ok(SealedImageArtifactsV1 {
        metadata,
        recovery_bundle,
        recovery_bundle_manifest: bundle_manifest,
        recovery_bundle_signature: bundle_signature,
        signing_operation: response,
    })
}

fn image_metadata<'a>(
    assembly: &'a UnsignedImageAssemblyV1,
    prepared: &PreparedFilesystemsV1,
    efi: &SignedEfiArtifactsV1,
    disk: &'a LogicalDiskV1,
    formats: &DiskFormatsV1,
    secure_boot_certificate: &Path,
) -> Result<ImageMetadata<'a>> {
    Ok(ImageMetadata {
        schema_version: if prepared.capabilities.is_some() {
            "aos.image.metadata/v2"
        } else {
            "aos.image.metadata/v1"
        },
        capabilities: prepared.capabilities.clone(),
        assembly_digest: Sha256Digest::of_canonical(&assembly.schema_version, assembly)?,
        release_id: &assembly.release_id,
        version: &assembly.version,
        platform: assembly.platform,
        system_variant: &assembly.system_variant,
        sbat_generation: assembly.sbat_generation,
        secure_boot_certificate_sha256: digest_regular_file(secure_boot_certificate)?.1,
        root: RootMetadata {
            filesystem_sha256: digest_regular_file(&prepared.root_filesystem)?.1,
            filesystem_size_bytes: fs::metadata(&prepared.root_filesystem)?.len(),
            verity_sha256: digest_regular_file(&prepared.verity.hash_tree)?.1,
            verity_size_bytes: fs::metadata(&prepared.verity.hash_tree)?.len(),
            root_hash: prepared.verity.root_hash.clone(),
        },
        efi: EfiMetadata {
            normal_a: uki_metadata(
                "uki-a",
                &efi.uki_a,
                efi.pcr_a.expected_ready_pcr11,
                &efi.measurement_a.measurement,
                &efi.measurement_a.signature,
            )?,
            normal_b: uki_metadata(
                "uki-b",
                &efi.uki_b,
                efi.pcr_b.expected_ready_pcr11,
                &efi.measurement_b.measurement,
                &efi.measurement_b.signature,
            )?,
            recovery_a: artifact_fact("recovery-uki-a", "recovery-a.efi", &efi.recovery_uki_a)?,
            recovery_b: artifact_fact("recovery-uki-b", "recovery-b.efi", &efi.recovery_uki_b)?,
            bootloader: artifact_fact("bootloader", "systemd-boot.efi", &efi.bootloader)?,
        },
        disk: DiskMetadata {
            logical: artifact_fact("logical-disk", "image.logical.raw", &disk.path)?,
            disk_guid: &assembly.layout.disk_guid,
            fat_volume_id: &assembly.layout.fat_volume_id,
            layout: &disk.layout,
            inactive_slot_state: "zero-filled",
        },
        formats: vec![
            artifact_fact("raw", "aos.raw.zst", &formats.raw_zstd)?,
            artifact_fact("qcow2", "aos.qcow2", &formats.qcow2)?,
            artifact_fact("vmdk", "aos.vmdk", &formats.vmdk)?,
            artifact_fact("vhd", "aos.vhd", &formats.vhd)?,
        ],
    })
}

fn uki_metadata(
    id: &str,
    uki: &Path,
    expected_ready_pcr11: Sha256Digest,
    measurement: &Path,
    signature: &Path,
) -> Result<UkiMetadata> {
    Ok(UkiMetadata {
        artifact: artifact_fact(id, &format!("{id}.efi"), uki)?,
        expected_ready_pcr11,
        measurement: artifact_fact(
            &format!("{id}-measurement"),
            &format!("{id}.efi.measurement"),
            measurement,
        )?,
        measurement_signature: artifact_fact(
            &format!("{id}-measurement-signature"),
            &format!("{id}.efi.measurement.sig"),
            signature,
        )?,
    })
}

fn artifact_fact(id: &str, relative: &str, path: &Path) -> Result<ArtifactFact> {
    BundlePath::parse(relative)?;
    let (size_bytes, sha256) = digest_regular_file(path)?;
    Ok(ArtifactFact {
        id: id.to_owned(),
        path: relative.to_owned(),
        size_bytes,
        sha256,
    })
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let mut input = fs::File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("bundle finalizer path is not UTF-8"))
}
