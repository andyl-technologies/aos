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

use crate::assembly::{AssemblyFileKind, ImageCommandLinesV1, UnsignedImageAssemblyV1};
use crate::filesystem::{
    extract_erofs, extract_initrd, kernel_modules, rebuild_erofs, rebuild_initrd,
};
use crate::input::{
    VerifiedInput, digest_regular_file, digest_regular_file_beneath, verified_tool,
};
use crate::module_signature::verify_signed_module;
use crate::request::{ImageRequestAuthorizer, ImageSigningIntent, verify_intent};
use crate::signer::ImageSigner;
use crate::tools::PinnedTool;
use crate::verity::{VerityOutputV1, bind_root_hash, build_verity};

const TOOL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MODULE_SIGNATURE_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;

/// Reconstructed module-bearing inputs ready for verity and UKI construction.
#[derive(Debug)]
pub struct PreparedFilesystemsV1 {
    /// Build-derived inventory of the final signed filesystem contents.
    pub capabilities: Option<aos_release::qualification::capabilities::ImageCapabilities>,
    /// Deterministically rebuilt signed EROFS root.
    pub root_filesystem: PathBuf,
    /// Deterministically rebuilt normal initrd.
    pub initrd: PathBuf,
    /// Deterministically rebuilt slot-A recovery initrd.
    pub recovery_initrd_a: PathBuf,
    /// Deterministically rebuilt slot-B recovery initrd.
    pub recovery_initrd_b: PathBuf,
    /// Deterministic verified dm-verity tree and root hash.
    pub verity: VerityOutputV1,
    /// Normal command lines rebound to the rebuilt root hash.
    pub command_lines: ImageCommandLinesV1,
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
    let veritysetup_spec = verified_tool(assembly, "veritysetup", &mut resolve_owner_nar_hash)?;

    let fsck_erofs = PinnedTool::from_verified(fsck_erofs_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let mkfs_erofs = PinnedTool::from_verified(mkfs_erofs_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let zstd = PinnedTool::from_verified(zstd_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let openssl = PinnedTool::from_verified(openssl_spec, work.to_path_buf(), TOOL_TIMEOUT)?;
    let veritysetup =
        PinnedTool::from_verified(veritysetup_spec, work.to_path_buf(), TOOL_TIMEOUT)?;

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

    if assembly.schema_version == crate::assembly::UNSIGNED_IMAGE_ASSEMBLY_V4 {
        verify_static_ability_contract_attachments(
            assembly_root,
            assembly,
            &input,
            &initrd_tree,
            &root_tree,
        )?;
    }

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
    let verity = build_verity(&veritysetup, &root_filesystem, &output, &assembly.layout).await?;
    let command_lines = ImageCommandLinesV1 {
        slot_a: bind_root_hash(&assembly.command_lines.slot_a, &verity.root_hash)?,
        slot_b: bind_root_hash(&assembly.command_lines.slot_b, &verity.root_hash)?,
        recovery: assembly.command_lines.recovery.clone(),
    };
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

    let capabilities = if matches!(
        assembly.schema_version.as_str(),
        crate::assembly::UNSIGNED_IMAGE_ASSEMBLY_V2
            | crate::assembly::UNSIGNED_IMAGE_ASSEMBLY_V3
            | crate::assembly::UNSIGNED_IMAGE_ASSEMBLY_V4
    ) {
        let config = input.join("kernel.config");
        capture_copy(
            assembly_root,
            assembly,
            AssemblyFileKind::KernelConfig,
            &config,
        )?;
        Some(crate::capabilities::capture(
            &assembly.kernel_release,
            &config,
            &root_tree,
            &initrd_tree,
            &recovery_a_tree,
            &recovery_b_tree,
        )?)
    } else {
        None
    };
    Ok(PreparedFilesystemsV1 {
        capabilities,
        root_filesystem,
        initrd,
        recovery_initrd_a,
        recovery_initrd_b,
        verity,
        command_lines,
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

/// Binds captured stage contracts to files inside extracted image trees.
///
/// The comparison opens every embedded path component without following
/// links. `captured_inputs` must exist and must not already contain either
/// captured contract filename.
///
/// # Errors
///
/// Returns an error when an assembly sidecar changed, an embedded contract is
/// absent or linked, a parent escapes its extracted tree, or the exact bytes
/// differ.
pub fn verify_static_ability_contract_attachments(
    assembly_root: &Path,
    assembly: &UnsignedImageAssemblyV1,
    captured_inputs: &Path,
    initrd_tree: &Path,
    root_tree: &Path,
) -> Result<()> {
    let initrd_contract = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::InitrdStaticAbilityContract,
        &captured_inputs.join("initrd-static-ability-contract.json"),
    )?;
    require_embedded_contract_matches(
        &initrd_contract,
        initrd_tree,
        Path::new("lib/aos/initrd/static-ability-contract.json"),
        "initrd static ability contract",
    )?;

    let host_contract = capture_copy(
        assembly_root,
        assembly,
        AssemblyFileKind::HostStaticAbilityContract,
        &captured_inputs.join("host-static-ability-contract.json"),
    )?;
    require_embedded_contract_matches(
        &host_contract,
        root_tree,
        Path::new("usr/lib/aos/host/static-ability-contract.json"),
        "host static ability contract",
    )?;
    Ok(())
}

fn require_embedded_contract_matches(
    captured: &Path,
    tree: &Path,
    embedded: &Path,
    label: &str,
) -> Result<()> {
    let captured_identity = digest_regular_file(captured)?;
    let embedded_identity = digest_regular_file_beneath(tree, embedded)?;
    if captured_identity != embedded_identity {
        bail!("captured {label} differs from the contract embedded in its filesystem");
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn rejects_a_sidecar_that_differs_from_the_embedded_contract() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let sidecar = temporary.path().join("sidecar.json");
        let tree = temporary.path().join("tree");
        let embedded = tree.join("lib/aos/initrd/static-ability-contract.json");
        fs::create_dir_all(
            embedded
                .parent()
                .context("fixture contract has no parent")?,
        )?;
        symlink(".", tree.join("usr"))?;
        fs::write(&sidecar, b"{\"stage\":\"initrd\"}")?;
        fs::write(&embedded, b"{\"stage\":\"initrd\"}")?;
        require_embedded_contract_matches(
            &sidecar,
            &tree,
            Path::new("lib/aos/initrd/static-ability-contract.json"),
            "test",
        )?;
        assert_eq!(
            fs::read(tree.join("usr/lib/aos/initrd/static-ability-contract.json"))?,
            fs::read(&sidecar)?,
        );

        fs::write(&sidecar, b"{\"stage\":\"host\"}")?;
        let error = require_embedded_contract_matches(
            &sidecar,
            &tree,
            Path::new("lib/aos/initrd/static-ability-contract.json"),
            "test",
        )
        .expect_err("a changed sidecar must not bind an unchanged filesystem");
        assert!(
            error
                .to_string()
                .contains("differs from the contract embedded")
        );
        Ok(())
    }
}
