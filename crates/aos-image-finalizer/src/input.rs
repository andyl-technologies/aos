//! Point-of-use validation for captured assembly files and executables.
//!
//! The assembly manifest is an authorization boundary, not a promise that a
//! path will remain unchanged. Every consumer opens without following a final
//! symbolic link and checks exact bytes before using an input.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest as _, Sha256};

use crate::assembly::{AssemblyFileKind, AssemblyFileV1, AssemblyToolV1, UnsignedImageAssemblyV1};

/// One no-follow regular input whose identity has been checked.
pub struct VerifiedInput {
    path: PathBuf,
    file: File,
    metadata: std::fs::Metadata,
}

impl VerifiedInput {
    /// Opens and hashes the exact assembly file identified by `kind`.
    ///
    /// # Errors
    ///
    /// Returns an error when the kind is absent, the path escapes `root`, the
    /// file is linked or special, its bytes differ, or it changes during read.
    pub fn open(
        root: &Path,
        assembly: &UnsignedImageAssemblyV1,
        kind: AssemblyFileKind,
    ) -> Result<Self> {
        let specification = assembly_file(assembly, kind)?;
        let path = root.join(specification.path.as_str());
        let descriptor = open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening assembly input {}", path.display()))?;
        let mut file = File::from(descriptor);
        let metadata = file.metadata()?;
        let path_metadata = path.symlink_metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.dev() != path_metadata.dev()
            || metadata.ino() != path_metadata.ino()
            || metadata.len() != specification.size_bytes
        {
            bail!("assembly input is no longer the captured regular file");
        }

        let (size, digest) = hash_reader(&mut file)?;
        let after = file.metadata()?;
        if size != specification.size_bytes
            || digest != specification.sha256
            || !same_snapshot(&metadata, &after)
        {
            bail!("assembly input bytes changed after capture");
        }
        file.rewind()?;
        Ok(Self {
            path,
            file,
            metadata,
        })
    }

    /// Returns the exact validated source pathname.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the validated open descriptor for streaming reads.
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Copies exact bytes to a newly created output and verifies source
    /// stability after the copy.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination exists, an I/O operation fails,
    /// or the source path changes before the copy completes.
    pub fn copy_new(&self, destination: &Path) -> Result<()> {
        let mut source = self.file.try_clone()?;
        source.rewind()?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut output = options
            .open(destination)
            .with_context(|| format!("creating {}", destination.display()))?;
        std::io::copy(&mut source, &mut output)?;
        output.sync_all()?;
        self.verify_unchanged()
    }

    fn verify_unchanged(&self) -> Result<()> {
        let current = self.path.symlink_metadata()?;
        if !same_snapshot(&self.metadata, &current) {
            bail!("assembly input changed while it was consumed");
        }
        Ok(())
    }
}

/// Resolves one assembly-pinned executable and checks its current store owner.
///
/// # Errors
///
/// Returns an error when the id is absent, the executable is no longer a
/// regular non-writable file, or its independently resolved owner NAR hash no
/// longer equals the manifest.
pub fn verified_tool(
    assembly: &UnsignedImageAssemblyV1,
    id: &str,
    resolve_owner_nar_hash: impl FnOnce(&str) -> Result<String>,
) -> Result<PathBuf> {
    let tool = assembly_tool(assembly, id)?;
    validate_tool_file(tool)?;
    let current_hash = resolve_owner_nar_hash(&tool.executable)
        .with_context(|| format!("resolving current owner NAR hash for tool {id}"))?;
    if current_hash != tool.owner_nar_hash {
        bail!("assembly tool owner changed after capture");
    }
    Ok(PathBuf::from(&tool.executable))
}

fn assembly_file(
    assembly: &UnsignedImageAssemblyV1,
    kind: AssemblyFileKind,
) -> Result<&AssemblyFileV1> {
    assembly
        .files
        .iter()
        .find(|file| file.kind == kind)
        .ok_or_else(|| anyhow::anyhow!("assembly lacks required {kind:?} input"))
}

fn assembly_tool<'a>(
    assembly: &'a UnsignedImageAssemblyV1,
    id: &str,
) -> Result<&'a AssemblyToolV1> {
    assembly
        .tools
        .iter()
        .find(|tool| tool.id == id)
        .ok_or_else(|| anyhow::anyhow!("assembly lacks required {id} tool"))
}

fn validate_tool_file(tool: &AssemblyToolV1) -> Result<()> {
    let path = Path::new(&tool.executable);
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting assembly tool {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        bail!("assembly tool must be a single-link regular file without group/world writes");
    }
    Ok(())
}

fn hash_reader(reader: &mut File) -> Result<(u64, Sha256Digest)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("assembly input size overflow")?;
        hasher.update(&buffer[..count]);
    }
    Ok((size, Sha256Digest::from_bytes(hasher.finalize().into())))
}

fn same_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aos_release::artifact::BundlePath;
    use aos_release::platform::Platform;

    use super::*;
    use crate::assembly::{
        EfiFilenamesV1, ImageBudgetsV1, ImageCommandLinesV1, ImageLayoutV1, ImageSignerRolesV1,
        PartitionGuidsV1, PartitionTypeGuidsV1, UNSIGNED_IMAGE_ASSEMBLY_V1,
    };

    #[test]
    fn point_of_use_rejects_substitution() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        fs::write(temporary.path().join("kernel"), b"kernel")?;
        let assembly = fixture_assembly();
        assert!(VerifiedInput::open(temporary.path(), &assembly, AssemblyFileKind::Kernel).is_ok());
        fs::write(temporary.path().join("kernel"), b"changed")?;
        assert!(
            VerifiedInput::open(temporary.path(), &assembly, AssemblyFileKind::Kernel).is_err()
        );
        Ok(())
    }

    fn fixture_assembly() -> UnsignedImageAssemblyV1 {
        UnsignedImageAssemblyV1 {
            schema_version: UNSIGNED_IMAGE_ASSEMBLY_V1.to_owned(),
            release_id: "release-1".to_owned(),
            version: "2026.9.0".to_owned(),
            platform: Platform::X86_64Linux,
            system_variant: "production".to_owned(),
            kernel_release: "6.18.33".to_owned(),
            module_abi: 1,
            recovery_abi: 1,
            sbat_generation: 1,
            command_lines: ImageCommandLinesV1 {
                slot_a: "root=a".to_owned(),
                slot_b: "root=b".to_owned(),
                recovery: "recovery=1".to_owned(),
            },
            signer_roles: ImageSignerRolesV1 {
                secure_boot: "secure-boot-release".to_owned(),
                module: "kernel-module-release".to_owned(),
                pcr: "pcr-policy-release".to_owned(),
            },
            layout: ImageLayoutV1 {
                sector_size: 512,
                alignment_sectors: 2048,
                esp_start_sector: 2048,
                esp_size_mib: 384,
                root_partition_mib: 1024,
                verity_partition_mib: 16,
                root_filesystem_type: "erofs".to_owned(),
                root_filesystem_uuid: "bdfb6fc9-0000-4000-8000-000000000001".to_owned(),
                root_filesystem_label: "aos-root".to_owned(),
                erofs_compression_level: 19,
                verity_uuid: "00000000-0000-4000-8000-000000000007".to_owned(),
                verity_salt: "a".repeat(64),
                esp_extra_free_mib: 0,
                disk_guid: "00000000-0000-4000-8000-000000000001".to_owned(),
                partition_type_guids: PartitionTypeGuidsV1 {
                    esp: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B".to_owned(),
                    root: "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709".to_owned(),
                    verity: "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5".to_owned(),
                },
                partition_guids: PartitionGuidsV1 {
                    esp: "00000000-0000-0000-0000-000000000002".to_owned(),
                    root_a: "00000000-0000-0000-0000-000000000003".to_owned(),
                    root_a_hash: "00000000-0000-0000-0000-000000000004".to_owned(),
                    root_b: "00000000-0000-0000-0000-000000000005".to_owned(),
                    root_b_hash: "00000000-0000-0000-0000-000000000006".to_owned(),
                },
                fat_volume_id: "ABCDEF01".to_owned(),
                efi_filenames: EfiFilenamesV1 {
                    fallback: "BOOTX64.EFI".to_owned(),
                    systemd_boot: "systemd-bootx64.efi".to_owned(),
                    normal_uki: "aos-generation-0000000001+3.efi".to_owned(),
                },
            },
            budgets: ImageBudgetsV1 {
                root_mib: 512,
                initrd_mib: 128,
                uki_mib: 160,
                download_mib: 640,
            },
            files: vec![AssemblyFileV1 {
                id: "kernel".to_owned(),
                kind: AssemblyFileKind::Kernel,
                path: BundlePath::parse("kernel").unwrap_or_else(|error| panic!("{error}")),
                size_bytes: 6,
                sha256: Sha256Digest::of_bytes(b"kernel"),
            }],
            tools: Vec::new(),
        }
    }
}
