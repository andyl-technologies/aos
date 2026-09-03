//! Effectful sequencing for externally signed image construction.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::signing::{
    SignatureAlgorithm, SignatureResponseV1, SignerRole, SigningContext, SigningOperation,
    verify_response_binding,
};

use crate::assembly::{AssemblyFileKind, UnsignedImageAssemblyV1};
use crate::filesystem::{
    extract_erofs, extract_initrd, kernel_modules, rebuild_erofs, rebuild_initrd,
};
use crate::input::{VerifiedInput, digest_regular_file, verified_tool};
use crate::module_signature::verify_signed_module;
use crate::request::{ImageRequestAuthorizer, ImageSigningIntent, verify_intent};
use crate::signer::ImageSigner;
use crate::tools::PinnedTool;

const TOOL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MODULE_SIGNATURE_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;

/// Reconstructed module-bearing inputs ready for verity and UKI construction.
#[derive(Debug)]
pub struct PreparedFilesystemsV1 {
    /// Deterministically rebuilt signed EROFS root.
    pub root_filesystem: PathBuf,
    /// Deterministically rebuilt normal initrd.
    pub initrd: PathBuf,
    /// Deterministically rebuilt slot-A recovery initrd.
    pub recovery_initrd_a: PathBuf,
    /// Deterministically rebuilt slot-B recovery initrd.
    pub recovery_initrd_b: PathBuf,
    /// Audited provider responses for every signed module instance.
    pub signing_operations: Vec<SignatureResponseV1>,
}

/// Signs every module instance and deterministically rebuilds root and initrds.
///
/// `resolve_owner_nar_hash` must independently query the current NAR hash for
/// each exact executable owner. `work` must be a new private directory owned by
/// the caller; this function refuses any of its stage paths that already exist.
///
/// # Errors
///
/// Returns an error for assembly drift, tool-owner drift, unsafe filesystem
/// content, unauthorized signer requests, invalid provider responses, failed
/// cryptographic verification, nondeterministic reconstruction, or a budget
/// violation.
pub async fn prepare_filesystems(
    assembly_root: &Path,
    assembly: &UnsignedImageAssemblyV1,
    work: &Path,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
    mut resolve_owner_nar_hash: impl FnMut(&str) -> Result<String>,
) -> Result<PreparedFilesystemsV1> {
    assembly.validate()?;
    if !work.is_absolute() || !work.is_dir() {
        bail!("finalizer work path must be an existing absolute directory");
    }
    let fsck_erofs_spec = verified_tool(assembly, "fsck_erofs", &mut resolve_owner_nar_hash)?;
    let mkfs_erofs_spec = verified_tool(assembly, "mkfs_erofs", &mut resolve_owner_nar_hash)?;
    let zstd_spec = verified_tool(assembly, "zstd", &mut resolve_owner_nar_hash)?;
    let cpio_spec = verified_tool(assembly, "cpio", &mut resolve_owner_nar_hash)?;
    let openssl_spec = verified_tool(assembly, "openssl", &mut resolve_owner_nar_hash)?;

    let fsck_erofs = PinnedTool::from_verified(fsck_erofs_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let mkfs_erofs = PinnedTool::from_verified(mkfs_erofs_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let zstd = PinnedTool::from_verified(zstd_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let openssl = PinnedTool::from_verified(openssl_spec, work.to_path_buf(), TOOL_TIMEOUT)?;

    let input = work.join("captured-inputs");
    let trees = work.join("trees");
    let module_scratch = work.join("module-signing");
    let initrd_scratch = work.join("initrd-scratch");
    let output = work.join("prepared");
    for directory in [&input, &trees, &module_scratch, &initrd_scratch, &output] {
        fs::create_dir(directory)
            .with_context(|| format!("creating finalizer stage {}", directory.display()))?;
    }

    let root_input = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::RootFilesystem,
        &input.join("root.img"),
    )?;
    let initrd_input = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::Initrd,
        &input.join("initrd.img"),
    )?;
    let recovery_a_input = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::RecoveryInitrdA,
        &input.join("recovery-a.img"),
    )?;
    let recovery_b_input = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::RecoveryInitrdB,
        &input.join("recovery-b.img"),
    )?;
    let module_certificate = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::ModuleCertificate,
        &input.join("module-signing.crt"),
    )?;

    let root_tree = trees.join("root");
    let initrd_tree = trees.join("initrd");
    let recovery_a_tree = trees.join("recovery-a");
    let recovery_b_tree = trees.join("recovery-b");
    extract_erofs(&fsck_erofs, &root_input, &root_tree).await?;
    let initrd_budget = mebibytes(assembly.budgets.initrd_mib)?;
    extract_initrd(
        &zstd,
        &cpio_spec,
        &initrd_input,
        &initrd_tree,
        initrd_budget,
        &initrd_scratch.join("normal"),
    )
    .await?;
    extract_initrd(
        &zstd,
        &cpio_spec,
        &recovery_a_input,
        &recovery_a_tree,
        initrd_budget,
        &initrd_scratch.join("recovery-a"),
    )
    .await?;
    extract_initrd(
        &zstd,
        &cpio_spec,
        &recovery_b_input,
        &recovery_b_tree,
        initrd_budget,
        &initrd_scratch.join("recovery-b"),
    )
    .await?;

    let certificate_digest = digest_regular_file(&module_certificate)?.1;
    let mut signing_operations = Vec::new();
    for (scope, tree) in [
        ("root", &root_tree),
        ("initrd", &initrd_tree),
        ("recovery-a", &recovery_a_tree),
        ("recovery-b", &recovery_b_tree),
    ] {
        signing_operations.extend(
            sign_tree_modules(
                assembly,
                scope,
                tree,
                &module_certificate,
                certificate_digest,
                &openssl,
                &module_scratch,
                signer,
                authorizer,
            )
            .await?,
        );
    }

    let root_filesystem = output.join("root.img");
    rebuild_erofs(
        &mkfs_erofs,
        &fsck_erofs,
        &root_tree,
        &root_filesystem,
        &assembly.layout,
        mebibytes(assembly.budgets.root_mib)?,
    )
    .await?;
    let initrd = output.join("initrd.img");
    let recovery_initrd_a = output.join("recovery-a.img");
    let recovery_initrd_b = output.join("recovery-b.img");
    for (name, tree, destination) in [
        ("normal", &initrd_tree, &initrd),
        ("recovery-a", &recovery_a_tree, &recovery_initrd_a),
        ("recovery-b", &recovery_b_tree, &recovery_initrd_b),
    ] {
        let scratch = initrd_scratch.join(format!("rebuild-{name}"));
        fs::create_dir(&scratch)?;
        rebuild_initrd(
            &cpio_spec,
            &zstd,
            tree,
            destination,
            initrd_budget,
            &scratch,
        )
        .await?;
    }

    Ok(PreparedFilesystemsV1 {
        root_filesystem,
        initrd,
        recovery_initrd_a,
        recovery_initrd_b,
        signing_operations,
    })
}

#[allow(clippy::too_many_arguments)]
async fn sign_tree_modules(
    assembly: &UnsignedImageAssemblyV1,
    scope: &str,
    tree: &Path,
    certificate: &Path,
    certificate_digest: aos_release::digest::Sha256Digest,
    openssl: &PinnedTool,
    scratch: &Path,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
) -> Result<Vec<SignatureResponseV1>> {
    let modules = kernel_modules(tree)?;
    let mut responses = Vec::with_capacity(modules.len());
    for (index, module) in modules.into_iter().enumerate() {
        let relative = module.strip_prefix(tree)?;
        let module_id = format!("{scope}/{}", path_text(relative)?);
        let operation = scratch.join(format!("{scope}-{index:08}"));
        fs::create_dir(&operation)?;
        let unsigned = operation.join("unsigned.ko");
        fs::copy(&module, &unsigned)?;
        let (_, payload_digest) = digest_regular_file(&unsigned)?;
        let intent = ImageSigningIntent {
            assembly_policy_id: &assembly.signer_roles.module,
            role: SignerRole::KernelModule,
            algorithm: SignatureAlgorithm::KernelModule,
            operation: SigningOperation::SignKernelModule,
            context: SigningContext::KernelModule {
                platform: assembly.platform,
                system_variant: assembly.system_variant.clone(),
                kernel_release: assembly.kernel_release.clone(),
                module_id,
            },
            payload_digest,
        };
        let request = authorizer.authorize(&intent)?;
        verify_intent(&request, &intent)?;
        let signed = operation.join("signed.ko");
        let maximum = fs::metadata(&unsigned)?
            .len()
            .checked_add(MODULE_SIGNATURE_OVERHEAD_BYTES)
            .context("signed module budget overflow")?;
        let response = signer
            .transform(&request, &unsigned, &signed, maximum)
            .await?;
        verify_response_binding(&request, &response)?;
        let (_, signed_digest) = digest_regular_file(&signed)?;
        if response.output_digest != Some(signed_digest)
            || response.verification_material_digest != certificate_digest
        {
            bail!("module signer response differs from signed bytes or certificate");
        }
        verify_signed_module(&unsigned, &signed, certificate, openssl, &operation).await?;

        let mode = fs::symlink_metadata(&module)?.permissions().mode();
        fs::set_permissions(&signed, fs::Permissions::from_mode(mode))?;
        fs::rename(&signed, &module)?;
        responses.push(response);
    }
    Ok(responses)
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

fn mebibytes(value: u64) -> Result<u64> {
    value
        .checked_mul(1024 * 1024)
        .context("image byte budget overflow")
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("finalizer path is not UTF-8"))
}
