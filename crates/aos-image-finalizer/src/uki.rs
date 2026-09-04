//! Normal/recovery UKI and bootloader construction with external signing.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::platform::Platform;
use aos_release::signing::{
    SignatureAlgorithm, SignatureResponseV1, SignerRole, SigningContext, SigningOperation,
    verify_response_binding,
};

use crate::assembly::{AssemblyFileKind, UnsignedImageAssemblyV1};
use crate::finalize::PreparedFilesystemsV1;
use crate::input::{VerifiedInput, digest_regular_file, verified_tool};
use crate::pcr::{
    PcrSections, SignedPcrPolicyV1, UkiMeasurementV1, sign_pcr_policy, sign_uki_measurement,
};
use crate::recovery::finalize_recovery;
use crate::request::{ImageRequestAuthorizer, ImageSigningIntent, verify_intent};
use crate::signer::ImageSigner;
use crate::tools::PinnedTool;

const TOOL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_TOOL_STDOUT_BYTES: u64 = 1024 * 1024;

/// Complete externally signed EFI artifact set for one Linux architecture.
#[derive(Debug)]
pub struct SignedEfiArtifactsV1 {
    /// Authenticode-signed systemd-boot.
    pub bootloader: PathBuf,
    /// Signed normal slot-A UKI with PCR policy.
    pub uki_a: PathBuf,
    /// Signed normal slot-B UKI with PCR policy.
    pub uki_b: PathBuf,
    /// Signed recovery slot-A UKI without normal PCR authorization.
    pub recovery_uki_a: PathBuf,
    /// Signed recovery slot-B UKI without normal PCR authorization.
    pub recovery_uki_b: PathBuf,
    /// Canonical db-signed recovery slot manifest.
    pub recovery_manifest: PathBuf,
    /// Raw detached signature over the recovery slot manifest.
    pub recovery_manifest_signature: PathBuf,
    /// Slot-A measured-boot evidence.
    pub pcr_a: SignedPcrPolicyV1,
    /// Slot-B measured-boot evidence.
    pub pcr_b: SignedPcrPolicyV1,
    /// Signed slot-A ready-phase measurement sidecar.
    pub measurement_a: UkiMeasurementV1,
    /// Signed slot-B ready-phase measurement sidecar.
    pub measurement_b: UkiMeasurementV1,
    /// Provider operations in deterministic execution order.
    pub signing_operations: Vec<SignatureResponseV1>,
}

/// Constructs normal/recovery UKIs and Authenticode-signs every EFI binary.
///
/// # Errors
///
/// Returns an error for assembly/tool drift, unsafe existing stage paths,
/// unauthorized requests, invalid PCR signatures, failed Authenticode public
/// verification, wrong PE architecture, or any artifact budget violation.
pub async fn build_signed_efi_artifacts(
    assembly_root: &Path,
    assembly: &UnsignedImageAssemblyV1,
    prepared: &PreparedFilesystemsV1,
    work: &Path,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    mut resolve_owner_nar_hash: impl FnMut(&str) -> Result<String>,
) -> Result<SignedEfiArtifactsV1> {
    assembly.validate()?;
    let ukify = PinnedTool::from_verified(
        verified_tool(assembly, "ukify", &mut resolve_owner_nar_hash)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )?;
    let measure = PinnedTool::from_verified(
        verified_tool(assembly, "systemd_measure", &mut resolve_owner_nar_hash)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )?;
    let openssl = PinnedTool::from_verified(
        verified_tool(assembly, "openssl", &mut resolve_owner_nar_hash)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )?;
    let sbverify = PinnedTool::from_verified(
        verified_tool(assembly, "sbverify", &mut resolve_owner_nar_hash)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )?;
    let objcopy = PinnedTool::from_verified(
        verified_tool(assembly, "objcopy", &mut resolve_owner_nar_hash)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )?;

    let inputs = work.join("efi-inputs");
    let output = work.join("efi-output");
    let scratch = work.join("efi-scratch");
    for directory in [&inputs, &output, &scratch] {
        fs::create_dir(directory)
            .with_context(|| format!("creating EFI stage {}", directory.display()))?;
    }
    let kernel = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::Kernel,
        &inputs.join("vmlinuz"),
    )?;
    let stub = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::UkiStub,
        &inputs.join("uki-stub.efi"),
    )?;
    let os_release = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::OsRelease,
        &inputs.join("os-release"),
    )?;
    let recovery_os_release_a = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::RecoveryOsReleaseA,
        &inputs.join("recovery-os-release-a"),
    )?;
    let recovery_os_release_b = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::RecoveryOsReleaseB,
        &inputs.join("recovery-os-release-b"),
    )?;
    let pcr_public_key = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::PcrPublicKey,
        &inputs.join("pcr-public.pem"),
    )?;
    let secure_boot_certificate = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::SecureBootCertificate,
        &inputs.join("secure-boot-db.crt"),
    )?;
    let unsigned_bootloader = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::Bootloader,
        &inputs.join("systemd-boot.efi"),
    )?;
    let sbat = inputs.join("aos.sbat");
    write_new(&sbat, sbat_policy(assembly)?.as_bytes())?;
    let cmdline_a = inputs.join("cmdline-a");
    let cmdline_b = inputs.join("cmdline-b");
    let recovery_cmdline = inputs.join("cmdline-recovery");
    write_new(&cmdline_a, prepared.command_lines.slot_a.as_bytes())?;
    write_new(&cmdline_b, prepared.command_lines.slot_b.as_bytes())?;
    write_new(
        &recovery_cmdline,
        prepared.command_lines.recovery.as_bytes(),
    )?;

    let uki_budget = mebibytes(assembly.budgets.uki_mib)?;
    let (uki_a, pcr_a, measurement_a, operations_a) = build_normal_uki(
        "uki-a",
        assembly,
        &kernel,
        &stub,
        &prepared.initrd,
        &os_release,
        &cmdline_a,
        &sbat,
        &pcr_public_key,
        &secure_boot_certificate,
        &output,
        &scratch,
        &ukify,
        &measure,
        &openssl,
        &sbverify,
        signer,
        authorizer,
        uki_budget,
    )
    .await?;
    verify_uki_sections(
        &objcopy,
        &uki_a,
        &[
            ("linux", &kernel),
            ("initrd", &prepared.initrd),
            ("osrel", &os_release),
            ("cmdline", &cmdline_a),
            ("sbat", &sbat),
            ("pcrpkey", &pcr_public_key),
            ("pcrsig", &pcr_a.signed_policy),
        ],
        &scratch.join("verify-uki-a"),
    )
    .await?;
    let (uki_b, pcr_b, measurement_b, operations_b) = build_normal_uki(
        "uki-b",
        assembly,
        &kernel,
        &stub,
        &prepared.initrd,
        &os_release,
        &cmdline_b,
        &sbat,
        &pcr_public_key,
        &secure_boot_certificate,
        &output,
        &scratch,
        &ukify,
        &measure,
        &openssl,
        &sbverify,
        signer,
        authorizer,
        uki_budget,
    )
    .await?;
    verify_uki_sections(
        &objcopy,
        &uki_b,
        &[
            ("linux", &kernel),
            ("initrd", &prepared.initrd),
            ("osrel", &os_release),
            ("cmdline", &cmdline_b),
            ("sbat", &sbat),
            ("pcrpkey", &pcr_public_key),
            ("pcrsig", &pcr_b.signed_policy),
        ],
        &scratch.join("verify-uki-b"),
    )
    .await?;
    let recovery = finalize_recovery(
        assembly,
        &uki_a,
        &uki_b,
        &prepared.verity.root_hash,
        &prepared.recovery_initrd_a,
        &prepared.recovery_initrd_b,
        &secure_boot_certificate,
        work,
        signer,
        authorizer,
        &mut resolve_owner_nar_hash,
    )
    .await?;
    let (recovery_uki_a, recovery_operation_a) = build_recovery_uki(
        "recovery-uki-a",
        assembly,
        &kernel,
        &stub,
        &recovery.initrd_a,
        &recovery_os_release_a,
        &recovery_cmdline,
        &sbat,
        &secure_boot_certificate,
        &output,
        &scratch,
        &ukify,
        &sbverify,
        signer,
        authorizer,
        uki_budget,
    )
    .await?;
    verify_uki_sections(
        &objcopy,
        &recovery_uki_a,
        &[
            ("linux", &kernel),
            ("initrd", &recovery.initrd_a),
            ("osrel", &recovery_os_release_a),
            ("cmdline", &recovery_cmdline),
            ("sbat", &sbat),
        ],
        &scratch.join("verify-recovery-a"),
    )
    .await?;
    verify_absent_section(
        &objcopy,
        &recovery_uki_a,
        "pcrsig",
        &scratch.join("verify-recovery-a-pcrsig"),
    )
    .await?;
    verify_absent_section(
        &objcopy,
        &recovery_uki_a,
        "pcrpkey",
        &scratch.join("verify-recovery-a-pcrpkey"),
    )
    .await?;
    let (recovery_uki_b, recovery_operation_b) = build_recovery_uki(
        "recovery-uki-b",
        assembly,
        &kernel,
        &stub,
        &recovery.initrd_b,
        &recovery_os_release_b,
        &recovery_cmdline,
        &sbat,
        &secure_boot_certificate,
        &output,
        &scratch,
        &ukify,
        &sbverify,
        signer,
        authorizer,
        uki_budget,
    )
    .await?;
    verify_uki_sections(
        &objcopy,
        &recovery_uki_b,
        &[
            ("linux", &kernel),
            ("initrd", &recovery.initrd_b),
            ("osrel", &recovery_os_release_b),
            ("cmdline", &recovery_cmdline),
            ("sbat", &sbat),
        ],
        &scratch.join("verify-recovery-b"),
    )
    .await?;
    verify_absent_section(
        &objcopy,
        &recovery_uki_b,
        "pcrsig",
        &scratch.join("verify-recovery-b-pcrsig"),
    )
    .await?;
    verify_absent_section(
        &objcopy,
        &recovery_uki_b,
        "pcrpkey",
        &scratch.join("verify-recovery-b-pcrpkey"),
    )
    .await?;
    let bootloader = output.join("systemd-boot.efi");
    let bootloader_operation = sign_pe(
        assembly,
        "bootloader",
        1,
        &unsigned_bootloader,
        &bootloader,
        &secure_boot_certificate,
        &sbverify,
        signer,
        authorizer,
        uki_budget,
    )
    .await?;

    let mut signing_operations = Vec::new();
    signing_operations.extend(operations_a);
    signing_operations.extend(operations_b);
    signing_operations.push(recovery.signing_operation);
    signing_operations.push(recovery_operation_a);
    signing_operations.push(recovery_operation_b);
    signing_operations.push(bootloader_operation);
    Ok(SignedEfiArtifactsV1 {
        bootloader,
        uki_a,
        uki_b,
        recovery_uki_a,
        recovery_uki_b,
        recovery_manifest: recovery.manifest,
        recovery_manifest_signature: recovery.signature,
        pcr_a,
        pcr_b,
        measurement_a,
        measurement_b,
        signing_operations,
    })
}

#[allow(clippy::too_many_arguments)]
async fn build_normal_uki(
    name: &str,
    assembly: &UnsignedImageAssemblyV1,
    kernel: &Path,
    stub: &Path,
    initrd: &Path,
    os_release: &Path,
    cmdline: &Path,
    sbat: &Path,
    pcr_public_key: &Path,
    certificate: &Path,
    output: &Path,
    scratch: &Path,
    ukify: &PinnedTool,
    measure: &PinnedTool,
    openssl: &PinnedTool,
    sbverify: &PinnedTool,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    maximum_bytes: u64,
) -> Result<(
    PathBuf,
    SignedPcrPolicyV1,
    UkiMeasurementV1,
    Vec<SignatureResponseV1>,
)> {
    let operation = scratch.join(name);
    fs::create_dir(&operation)?;
    let preliminary = operation.join("preliminary.efi");
    build_uki(
        ukify,
        stub,
        kernel,
        initrd,
        os_release,
        cmdline,
        sbat,
        Some(pcr_public_key),
        &preliminary,
        maximum_bytes,
    )
    .await?;
    let pcr = sign_pcr_policy(
        assembly,
        &PcrSections {
            linux: kernel,
            osrel: os_release,
            cmdline,
            initrd,
            sbat,
            pcrpkey: pcr_public_key,
        },
        &operation.join("pcr"),
        measure,
        openssl,
        signer,
        authorizer,
    )
    .await?;
    let with_pcr = operation.join("with-pcrsig.efi");
    let join = vec![
        OsString::from("build"),
        option_path("--join-pcrsig=", &preliminary),
        option_path("--pcrsig=@", &pcr.signed_policy),
        option_path("--output=", &with_pcr),
    ];
    let _ = ukify.run(join, MAX_TOOL_STDOUT_BYTES).await?;
    require_bounded_file(&with_pcr, maximum_bytes)?;
    let finalized = output.join(format!("{name}.efi"));
    let authenticode = sign_pe(
        assembly,
        "uki",
        assembly.sbat_generation,
        &with_pcr,
        &finalized,
        certificate,
        sbverify,
        signer,
        authorizer,
        maximum_bytes,
    )
    .await?;
    let measurement = sign_uki_measurement(
        assembly,
        &finalized,
        pcr.expected_ready_pcr11,
        pcr_public_key,
        &operation,
        openssl,
        signer,
        authorizer,
    )
    .await?;
    let operations = vec![
        pcr.signing_operation.clone(),
        authenticode,
        measurement.signing_operation.clone(),
    ];
    Ok((finalized, pcr, measurement, operations))
}

#[allow(clippy::too_many_arguments)]
async fn build_recovery_uki(
    name: &str,
    assembly: &UnsignedImageAssemblyV1,
    kernel: &Path,
    stub: &Path,
    initrd: &Path,
    os_release: &Path,
    cmdline: &Path,
    sbat: &Path,
    certificate: &Path,
    output: &Path,
    scratch: &Path,
    ukify: &PinnedTool,
    sbverify: &PinnedTool,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    maximum_bytes: u64,
) -> Result<(PathBuf, SignatureResponseV1)> {
    let operation = scratch.join(name);
    fs::create_dir(&operation)?;
    let unsigned = operation.join("unsigned.efi");
    build_uki(
        ukify,
        stub,
        kernel,
        initrd,
        os_release,
        cmdline,
        sbat,
        None,
        &unsigned,
        maximum_bytes,
    )
    .await?;
    let finalized = output.join(format!("{name}.efi"));
    let response = sign_pe(
        assembly,
        "recovery-uki",
        assembly.sbat_generation,
        &unsigned,
        &finalized,
        certificate,
        sbverify,
        signer,
        authorizer,
        maximum_bytes,
    )
    .await?;
    Ok((finalized, response))
}

#[allow(clippy::too_many_arguments)]
async fn build_uki(
    ukify: &PinnedTool,
    stub: &Path,
    kernel: &Path,
    initrd: &Path,
    os_release: &Path,
    cmdline: &Path,
    sbat: &Path,
    pcr_public_key: Option<&Path>,
    output: &Path,
    maximum_bytes: u64,
) -> Result<()> {
    let mut command = vec![
        OsString::from("build"),
        option_path("--stub=", stub),
        option_path("--linux=", kernel),
        option_path("--initrd=", initrd),
        option_path("--cmdline=@", cmdline),
        option_path("--os-release=@", os_release),
        option_path("--sbat=@", sbat),
    ];
    if let Some(public_key) = pcr_public_key {
        command.push(option_path("--pcrpkey=", public_key));
    }
    command.push(option_path("--output=", output));
    let _ = ukify.run(command, MAX_TOOL_STDOUT_BYTES).await?;
    require_bounded_file(output, maximum_bytes)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sign_pe(
    assembly: &UnsignedImageAssemblyV1,
    artifact_kind: &str,
    sbat_generation: u64,
    unsigned: &Path,
    signed: &Path,
    certificate: &Path,
    sbverify: &PinnedTool,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    maximum_bytes: u64,
) -> Result<SignatureResponseV1> {
    let (_, payload_digest) = digest_regular_file(unsigned)?;
    let intent = ImageSigningIntent {
        assembly_policy_id: &assembly.signer_roles.secure_boot,
        role: SignerRole::SecureBootDb,
        algorithm: SignatureAlgorithm::Authenticode,
        operation: SigningOperation::SignPe,
        context: SigningContext::Pe {
            platform: assembly.platform,
            system_variant: assembly.system_variant.clone(),
            pe_machine: pe_machine(assembly.platform)?.to_owned(),
            sbat_generation,
            artifact_kind: artifact_kind.to_owned(),
        },
        payload_digest,
    };
    let request = authorizer.authorize(&intent)?;
    verify_intent(&request, &intent)?;
    let response = signer
        .transform(&request, unsigned, signed, maximum_bytes)
        .await?;
    verify_response_binding(&request, &response)?;
    let (_, output_digest) = digest_regular_file(signed)?;
    let (_, certificate_digest) = digest_regular_file(certificate)?;
    if response.output_digest != Some(output_digest)
        || response.verification_material_digest != certificate_digest
    {
        bail!("Authenticode signer response differs from signed bytes or db certificate");
    }
    verify_pe_machine(signed, pe_machine(assembly.platform)?)?;
    let _ = sbverify
        .run(
            ["--cert", path_text(certificate)?, path_text(signed)?],
            MAX_TOOL_STDOUT_BYTES,
        )
        .await?;
    Ok(response)
}

async fn verify_uki_sections(
    objcopy: &PinnedTool,
    uki: &Path,
    expected: &[(&str, &PathBuf)],
    scratch: &Path,
) -> Result<()> {
    fs::create_dir(scratch)?;
    for (section, source) in expected {
        let extracted = scratch.join(section);
        extract_section(objcopy, uki, section, &extracted).await?;
        let expected = fs::read(source)?;
        let actual = fs::read(&extracted)?;
        if actual.len() < expected.len()
            || actual[..expected.len()] != expected
            || actual[expected.len()..].iter().any(|byte| *byte != 0)
        {
            bail!("final UKI section .{section} differs from its authorized input");
        }
    }
    Ok(())
}

async fn verify_absent_section(
    objcopy: &PinnedTool,
    uki: &Path,
    section: &str,
    scratch: &Path,
) -> Result<()> {
    fs::create_dir(scratch)?;
    let extracted = scratch.join(section);
    extract_section(objcopy, uki, section, &extracted).await?;
    if extracted
        .metadata()
        .is_ok_and(|metadata| metadata.len() != 0)
    {
        bail!("recovery UKI unexpectedly carries .{section}");
    }
    Ok(())
}

async fn extract_section(
    objcopy: &PinnedTool,
    uki: &Path,
    section: &str,
    output: &Path,
) -> Result<()> {
    let section = format!("--only-section=.{section}");
    let _ = objcopy
        .run(
            [
                OsString::from("-O"),
                OsString::from("binary"),
                OsString::from(section),
                uki.as_os_str().to_owned(),
                output.as_os_str().to_owned(),
            ],
            MAX_TOOL_STDOUT_BYTES,
        )
        .await?;
    Ok(())
}

fn verify_pe_machine(path: &Path, expected: &str) -> Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = fs::File::open(path)?;
    let mut dos = [0_u8; 64];
    file.read_exact(&mut dos)?;
    if &dos[..2] != b"MZ" {
        bail!("signed EFI artifact lacks a DOS header");
    }
    let offset = u64::from(u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]));
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0_u8; 6];
    file.read_exact(&mut header)?;
    if &header[..4] != b"PE\0\0" {
        bail!("signed EFI artifact lacks a PE header");
    }
    let actual = format!("{:04x}", u16::from_le_bytes([header[4], header[5]]));
    if actual != expected {
        bail!("signed EFI artifact has PE machine {actual}, expected {expected}");
    }
    Ok(())
}

fn sbat_policy(assembly: &UnsignedImageAssemblyV1) -> Result<String> {
    assembly.validate()?;
    Ok(format!(
        "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n{},{},{},{},{},{}\n",
        assembly.sbat.component,
        assembly.sbat_generation,
        assembly.sbat.vendor,
        assembly.sbat.package,
        assembly.version,
        assembly.sbat.url,
    ))
}

fn pe_machine(platform: Platform) -> Result<&'static str> {
    match platform {
        Platform::X86_64Linux => Ok("8664"),
        Platform::Aarch64Linux => Ok("aa64"),
        Platform::X86_64Darwin | Platform::Aarch64Darwin => {
            bail!("Darwin does not produce EFI images")
        }
    }
}

fn option_path(prefix: &str, path: &Path) -> OsString {
    let mut option = OsString::from(prefix);
    option.push(path);
    option
}

fn capture_copy(
    root: &Path,
    assembly: &UnsignedImageAssemblyV1,
    kind: AssemblyFileKind,
    destination: &Path,
) -> Result<PathBuf> {
    VerifiedInput::open(root, assembly, kind)?.copy_new(destination)?;
    Ok(destination.to_path_buf())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_bounded_file(path: &Path, maximum: u64) -> Result<u64> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("EFI output is empty, special, or exceeds its byte budget");
    }
    Ok(metadata.len())
}

fn mebibytes(value: u64) -> Result<u64> {
    value
        .checked_mul(1024 * 1024)
        .context("EFI artifact byte budget overflow")
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("EFI finalizer path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_values_cover_only_linux_image_targets() {
        assert!(matches!(pe_machine(Platform::X86_64Linux), Ok("8664")));
        assert!(matches!(pe_machine(Platform::Aarch64Linux), Ok("aa64")));
        assert!(pe_machine(Platform::Aarch64Darwin).is_err());
    }
}
