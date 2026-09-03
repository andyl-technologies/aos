//! No-follow capture of a Nix-produced unsigned assembly.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use rustix::fs::{Mode, OFlags, open};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::assembly::{
    AssemblyFileKind, AssemblyFileV1, AssemblyToolV1, ImageBudgetsV1, ImageCommandLinesV1,
    ImageLayoutV1, ImageSignerRolesV1, UNSIGNED_IMAGE_ASSEMBLY_V1, UnsignedImageAssemblyV1,
};

const RECIPE_SCHEMA: &str = "aos.image.assembly-recipe/v1";
const MAX_RECIPE_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssemblyRecipeV1 {
    schema_version: String,
    release: String,
    platform: Platform,
    system_variant: String,
    kernel_release: String,
    module_abi: u64,
    recovery_abi: u64,
    sbat_generation: u64,
    command_lines: CommandLines,
    signer_roles: SignerRoles,
    layout: ImageLayoutV1,
    budgets: ImageBudgetsV1,
    tools: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandLines {
    slot_a: String,
    slot_b: String,
    recovery: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerRoles {
    secure_boot: String,
    module: String,
    pcr: String,
}

/// Captures one immutable assembly directory into its public contract.
///
/// `resolve_owner_nar_hash` receives each exact tool executable and must return
/// the independently queried NAR hash of its owning store output.
///
/// # Errors
///
/// Returns an error for a noncanonical or oversized recipe, a link or special
/// input, a changed file during capture, an unknown/missing tool identity, or
/// any invalid resulting assembly contract.
pub fn capture_unsigned_assembly(
    root: &Path,
    release_id: &str,
    mut resolve_owner_nar_hash: impl FnMut(&str) -> Result<String>,
) -> Result<UnsignedImageAssemblyV1> {
    let recipe_path = root.join("assembly-recipe.json");
    let recipe_bytes = capture_control_file(&recipe_path)?;
    canonical::require_canonical(&recipe_bytes, "image assembly recipe")?;
    let recipe: AssemblyRecipeV1 = canonical::from_slice(&recipe_bytes, "image assembly recipe")?;
    if recipe.schema_version != RECIPE_SCHEMA {
        bail!("unsupported image assembly recipe schema");
    }
    if [
        recipe.command_lines.slot_a.as_str(),
        recipe.command_lines.slot_b.as_str(),
        recipe.command_lines.recovery.as_str(),
        recipe.signer_roles.secure_boot.as_str(),
        recipe.signer_roles.module.as_str(),
        recipe.signer_roles.pcr.as_str(),
    ]
    .iter()
    .any(|value| value.is_empty())
    {
        bail!("image assembly recipe has an empty command line or signer role");
    }

    let specifications = [
        (
            "bootloader",
            AssemblyFileKind::Bootloader,
            "inputs/systemd-boot.efi",
        ),
        (
            "enrollment",
            AssemblyFileKind::FirmwareEnrollment,
            "inputs/firmware-enrollment.tar",
        ),
        ("initrd", AssemblyFileKind::Initrd, "inputs/initrd.img"),
        ("kernel", AssemblyFileKind::Kernel, "inputs/vmlinuz"),
        (
            "module-certificate",
            AssemblyFileKind::ModuleCertificate,
            "trust/module-signing.crt",
        ),
        (
            "os-release",
            AssemblyFileKind::OsRelease,
            "inputs/os-release",
        ),
        (
            "pcr-public-key",
            AssemblyFileKind::PcrPublicKey,
            "trust/pcr-public.pem",
        ),
        (
            "recovery-initrd-a",
            AssemblyFileKind::RecoveryInitrdA,
            "inputs/recovery-initrd-a.img",
        ),
        (
            "recovery-initrd-b",
            AssemblyFileKind::RecoveryInitrdB,
            "inputs/recovery-initrd-b.img",
        ),
        (
            "recovery-os-release-a",
            AssemblyFileKind::RecoveryOsReleaseA,
            "inputs/recovery-os-release-a",
        ),
        (
            "recovery-os-release-b",
            AssemblyFileKind::RecoveryOsReleaseB,
            "inputs/recovery-os-release-b",
        ),
        (
            "root-filesystem",
            AssemblyFileKind::RootFilesystem,
            "inputs/root.img",
        ),
        (
            "secure-boot-certificate",
            AssemblyFileKind::SecureBootCertificate,
            "trust/secure-boot-db.crt",
        ),
        ("uki-stub", AssemblyFileKind::UkiStub, "inputs/uki-stub.efi"),
        (
            "verity-root-hash",
            AssemblyFileKind::VerityRootHash,
            "inputs/root.roothash",
        ),
        (
            "verity-tree",
            AssemblyFileKind::VerityTree,
            "inputs/root.verity",
        ),
    ];
    let mut files = specifications
        .into_iter()
        .map(|(id, kind, relative)| {
            let path = BundlePath::parse(relative)?;
            let (size_bytes, sha256) = capture_regular_file(&root.join(relative))?;
            Ok(AssemblyFileV1 {
                id: id.to_owned(),
                kind,
                path,
                size_bytes,
                sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    files.sort_by(|left, right| left.id.cmp(&right.id));

    let tools = recipe
        .tools
        .into_iter()
        .map(|(id, executable)| {
            let owner_nar_hash = resolve_owner_nar_hash(&executable)
                .with_context(|| format!("resolving owner NAR hash for tool {id}"))?;
            Ok(AssemblyToolV1 {
                id,
                executable,
                owner_nar_hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let assembly = UnsignedImageAssemblyV1 {
        schema_version: UNSIGNED_IMAGE_ASSEMBLY_V1.to_owned(),
        release_id: release_id.to_owned(),
        version: recipe.release,
        platform: recipe.platform,
        system_variant: recipe.system_variant,
        kernel_release: recipe.kernel_release,
        module_abi: recipe.module_abi,
        recovery_abi: recipe.recovery_abi,
        sbat_generation: recipe.sbat_generation,
        command_lines: ImageCommandLinesV1 {
            slot_a: recipe.command_lines.slot_a,
            slot_b: recipe.command_lines.slot_b,
            recovery: recipe.command_lines.recovery,
        },
        signer_roles: ImageSignerRolesV1 {
            secure_boot: recipe.signer_roles.secure_boot,
            module: recipe.signer_roles.module,
            pcr: recipe.signer_roles.pcr,
        },
        layout: recipe.layout,
        budgets: recipe.budgets,
        files,
        tools,
    };
    assembly.validate()?;
    Ok(assembly)
}

fn capture_control_file(path: &Path) -> Result<Vec<u8>> {
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_RECIPE_BYTES {
        bail!("image assembly recipe must be a bounded single-link regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECIPE_BYTES + 1).read_to_end(&mut bytes)?;
    let current = path.symlink_metadata()?;
    if u64::try_from(bytes.len())? != metadata.len()
        || current.dev() != metadata.dev()
        || current.ino() != metadata.ino()
    {
        bail!("image assembly recipe changed during capture");
    }
    Ok(bytes)
}

fn capture_regular_file(path: &Path) -> Result<(u64, Sha256Digest)> {
    let mut file = open_regular_nofollow(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() == 0 {
        bail!("assembly input must be a nonempty single-link regular file");
    }
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("assembly input size overflow")?;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let current = path.symlink_metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || size != before.len()
        || current.dev() != before.dev()
        || current.ino() != before.ino()
    {
        bail!("assembly input changed during capture");
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((size, Sha256Digest::from_bytes(digest)))
}

fn open_regular_nofollow(path: &Path) -> Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening assembly input {}", path.display()))?;
    Ok(File::from(descriptor))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::*;

    fn fixture() -> Result<tempfile::TempDir> {
        let temporary = tempfile::tempdir()?;
        for relative in [
            "inputs/systemd-boot.efi",
            "inputs/firmware-enrollment.tar",
            "inputs/initrd.img",
            "inputs/recovery-initrd-a.img",
            "inputs/recovery-initrd-b.img",
            "inputs/recovery-os-release-a",
            "inputs/recovery-os-release-b",
            "inputs/vmlinuz",
            "trust/module-signing.crt",
            "inputs/os-release",
            "trust/pcr-public.pem",
            "inputs/root.img",
            "trust/secure-boot-db.crt",
            "inputs/uki-stub.efi",
            "inputs/root.roothash",
            "inputs/root.verity",
        ] {
            let path = temporary.path().join(relative);
            fs::create_dir_all(path.parent().context("fixture path has no parent")?)?;
            fs::write(path, relative.as_bytes())?;
        }
        let recipe = json!({
            "schema_version": RECIPE_SCHEMA,
            "release": "2026.9.0",
            "platform": "x86_64-linux",
            "system_variant": "production",
            "kernel_release": "6.18.33",
            "module_abi": 1,
            "recovery_abi": 1,
            "sbat_generation": 1,
            "command_lines": {"slot_a":"root=a","slot_b":"root=b","recovery":"recovery=1"},
            "signer_roles": {"secure_boot":"secure-boot-release","module":"module-release","pcr":"pcr-release"},
            "layout": {
              "sector_size":512,"alignment_sectors":2048,"esp_start_sector":2048,
              "esp_size_mib":384,"root_partition_mib":1024,"verity_partition_mib":16,
              "root_filesystem_type":"erofs","root_filesystem_uuid":"bdfb6fc9-0000-4000-8000-000000000001",
              "root_filesystem_label":"aos-root","erofs_compression_level":19,"esp_extra_free_mib":0,
              "verity_uuid":"00000000-0000-4000-8000-000000000007",
              "verity_salt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "disk_guid":"00000000-0000-0000-0000-000000000001",
              "partition_type_guids":{"esp":"C12A7328-F81F-11D2-BA4B-00A0C93EC93B","root":"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709","verity":"2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5"},
              "partition_guids":{"esp":"00000000-0000-0000-0000-000000000002","root_a":"00000000-0000-0000-0000-000000000003","root_a_hash":"00000000-0000-0000-0000-000000000004","root_b":"00000000-0000-0000-0000-000000000005","root_b_hash":"00000000-0000-0000-0000-000000000006"},
              "fat_volume_id":"ABCDEF01","efi_filenames":{"fallback":"BOOTX64.EFI","systemd_boot":"systemd-bootx64.efi","normal_uki":"aos-generation-0000000001+3.efi"}
            },
            "budgets":{"root_mib":512,"initrd_mib":128,"uki_mib":160,"download_mib":640},
            "tools": {"ukify":"/nix/store/00000000000000000000000000000000-systemd/bin/ukify"}
        });
        fs::write(
            temporary.path().join("assembly-recipe.json"),
            canonical::to_vec(&recipe)?,
        )?;
        Ok(temporary)
    }

    #[test]
    fn captures_complete_public_only_assembly() -> Result<()> {
        let temporary = fixture()?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        assert_eq!(assembly.files.len(), 16);
        assert_eq!(assembly.tools.len(), 1);
        Ok(())
    }

    #[test]
    fn rejects_a_link_substituted_for_an_input() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = fixture()?;
        let target = temporary.path().join("target");
        fs::write(&target, b"replacement")?;
        fs::remove_file(temporary.path().join("inputs/vmlinuz"))?;
        symlink(target, temporary.path().join("inputs/vmlinuz"))?;
        assert!(
            capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| Ok(format!(
                "sha256:{}",
                "a".repeat(64)
            )),)
            .is_err()
        );
        Ok(())
    }
}
