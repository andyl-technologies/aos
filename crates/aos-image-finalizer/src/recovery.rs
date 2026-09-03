//! Signed recovery-slot manifest construction and initrd injection.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::signing::{
    SignatureAlgorithm, SignatureResponseV1, SignerRole, SigningContext, SigningOperation,
    verify_response_binding,
};
use base64::Engine as _;
use serde::Serialize;

use crate::assembly::UnsignedImageAssemblyV1;
use crate::filesystem::{extract_initrd, rebuild_initrd};
use crate::input::{digest_regular_file, verified_tool};
use crate::request::{ImageRequestAuthorizer, ImageSigningIntent, verify_intent};
use crate::signer::ImageSigner;
use crate::tools::PinnedTool;

const TOOL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;

/// Signed manifest and recovery initrds that contain its exact bytes.
#[derive(Debug)]
pub struct FinalizedRecoveryV1 {
    /// Canonical recovery-slot manifest.
    pub manifest: PathBuf,
    /// Raw X.509-key signature over the manifest.
    pub signature: PathBuf,
    /// Rebuilt slot-A recovery initrd containing manifest and signature.
    pub initrd_a: PathBuf,
    /// Rebuilt slot-B recovery initrd containing manifest and signature.
    pub initrd_b: PathBuf,
    /// Audited detached-signature provider response.
    pub signing_operation: SignatureResponseV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryManifest<'a> {
    schema: &'static str,
    release: &'a str,
    #[serde(rename = "recoveryAbi")]
    recovery_abi: u64,
    slots: RecoverySlots,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoverySlots {
    #[serde(rename = "A")]
    a: RecoverySlot,
    #[serde(rename = "B")]
    b: RecoverySlot,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoverySlot {
    #[serde(rename = "rootData")]
    root_data: &'static str,
    #[serde(rename = "rootHashDevice")]
    root_hash_device: &'static str,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(rename = "ukiSha256")]
    uki_sha256: String,
}

/// Signs the exact normal-slot identities and injects them into both recoveries.
///
/// # Errors
///
/// Returns an error for tool drift, unauthorized signing, invalid detached
/// signature, recovery archive reconstruction failure, or an initrd budget
/// violation.
#[allow(clippy::too_many_arguments)]
pub async fn finalize_recovery(
    assembly: &UnsignedImageAssemblyV1,
    normal_uki_a: &Path,
    normal_uki_b: &Path,
    root_hash: &str,
    recovery_initrd_a: &Path,
    recovery_initrd_b: &Path,
    secure_boot_certificate: &Path,
    work: &Path,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    mut resolve_owner_nar_hash: impl FnMut(&str) -> Result<String>,
) -> Result<FinalizedRecoveryV1> {
    aos_release::digest::Sha256Digest::parse(&format!("sha256:{root_hash}"))?;
    let zstd_spec = verified_tool(assembly, "zstd", &mut resolve_owner_nar_hash)?;
    let cpio_spec = verified_tool(assembly, "cpio", &mut resolve_owner_nar_hash)?;
    let openssl = PinnedTool::from_verified(
        verified_tool(assembly, "openssl", &mut resolve_owner_nar_hash)?,
        work.to_path_buf(),
        TOOL_TIMEOUT,
    )?;
    let zstd = PinnedTool::from_verified(zstd_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let output = work.join("recovery-output");
    let scratch = work.join("recovery-scratch");
    fs::create_dir(&output)?;
    fs::create_dir(&scratch)?;

    let manifest_path = output.join("slot-manifest.json");
    let manifest = RecoveryManifest {
        schema: "aos.recovery-slot-manifest/v1",
        release: &assembly.version,
        recovery_abi: assembly.recovery_abi,
        slots: RecoverySlots {
            a: RecoverySlot {
                root_data: "/dev/disk/by-partlabel/root-a",
                root_hash_device: "/dev/disk/by-partlabel/root-a-hash",
                root_hash: root_hash.to_owned(),
                uki_sha256: digest_regular_file(normal_uki_a)?.1.hex(),
            },
            b: RecoverySlot {
                root_data: "/dev/disk/by-partlabel/root-b",
                root_hash_device: "/dev/disk/by-partlabel/root-b-hash",
                root_hash: root_hash.to_owned(),
                uki_sha256: digest_regular_file(normal_uki_b)?.1.hex(),
            },
        },
    };
    fs::write(&manifest_path, canonical::to_vec(&manifest)?)?;
    let (_, payload_digest) = digest_regular_file(&manifest_path)?;
    let intent = ImageSigningIntent {
        assembly_policy_id: &assembly.signer_roles.secure_boot,
        role: SignerRole::SecureBootDb,
        algorithm: SignatureAlgorithm::PublicKeySha256,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: "recovery-slot-manifest".to_owned(),
        },
        payload_digest,
    };
    let request = authorizer.authorize(&intent)?;
    verify_intent(&request, &intent)?;
    let response = signer.sign_detached(&request, &manifest_path).await?;
    verify_response_binding(&request, &response)?;
    let (_, certificate_digest) = digest_regular_file(secure_boot_certificate)?;
    if response.output_digest.is_some()
        || response.verification_material_digest != certificate_digest
    {
        bail!("recovery signer response differs from the db certificate");
    }
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&response.signature_base64)
        .context("decoding recovery manifest signature")?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        bail!("recovery manifest signature is empty or oversized");
    }
    let signature_path = output.join("slot-manifest.json.sig");
    fs::write(&signature_path, signature)?;
    verify_manifest_signature(
        &manifest_path,
        &signature_path,
        secure_boot_certificate,
        &scratch,
        &openssl,
    )
    .await?;

    let maximum_initrd_bytes = assembly
        .budgets
        .initrd_mib
        .checked_mul(1024 * 1024)
        .context("recovery initrd budget overflow")?;
    let initrd_a = output.join("recovery-a.img");
    let initrd_b = output.join("recovery-b.img");
    for (name, source, destination) in [
        ("a", recovery_initrd_a, &initrd_a),
        ("b", recovery_initrd_b, &initrd_b),
    ] {
        let operation = scratch.join(name);
        fs::create_dir(&operation)?;
        let tree = operation.join("tree");
        let extract_scratch = operation.join("extract");
        extract_initrd(
            &zstd,
            &cpio_spec,
            source,
            &tree,
            maximum_initrd_bytes,
            &extract_scratch,
        )
        .await?;
        let manifest_directory = tree.join("lib/aos/recovery");
        if !manifest_directory.is_dir() {
            bail!("recovery initrd lacks its fixed manifest directory");
        }
        if manifest_directory
            .join("slot-manifest.json")
            .symlink_metadata()
            .is_ok()
            || manifest_directory
                .join("slot-manifest.json.sig")
                .symlink_metadata()
                .is_ok()
        {
            bail!("unsigned recovery initrd unexpectedly contains release-time manifest data");
        }
        fs::copy(
            &manifest_path,
            manifest_directory.join("slot-manifest.json"),
        )?;
        fs::copy(
            &signature_path,
            manifest_directory.join("slot-manifest.json.sig"),
        )?;
        let rebuild_scratch = operation.join("rebuild");
        fs::create_dir(&rebuild_scratch)?;
        rebuild_initrd(
            &cpio_spec,
            &zstd,
            &tree,
            destination,
            maximum_initrd_bytes,
            &rebuild_scratch,
        )
        .await?;
    }
    Ok(FinalizedRecoveryV1 {
        manifest: manifest_path,
        signature: signature_path,
        initrd_a,
        initrd_b,
        signing_operation: response,
    })
}

async fn verify_manifest_signature(
    manifest: &Path,
    signature: &Path,
    certificate: &Path,
    scratch: &Path,
    openssl: &PinnedTool,
) -> Result<()> {
    let public_key = scratch.join("secure-boot-db-public.pem");
    let _ = openssl
        .run_to_new_file(
            ["x509", "-pubkey", "-noout", "-in", path_text(certificate)?],
            None,
            &public_key,
            1024 * 1024,
        )
        .await?;
    let _ = openssl
        .run(
            [
                "dgst",
                "-sha256",
                "-verify",
                path_text(&public_key)?,
                "-signature",
                path_text(signature)?,
                path_text(manifest)?,
            ],
            1024,
        )
        .await?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("recovery finalizer path is not UTF-8"))
}
