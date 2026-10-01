//! Point-of-use validation for captured assembly files and executables.
//!
//! The assembly manifest is an authorization boundary, not a promise that a
//! path will remain unchanged. Every consumer opens without following a final
//! symbolic link and checks exact bytes before using an input.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;
use rustix::fs::{Mode, OFlags, open, openat, readlinkat};
use sha2::{Digest as _, Sha256};

use crate::assembly::{AssemblyFileKind, AssemblyFileV1, AssemblyToolV1, UnsignedImageAssemblyV1};

/// Exact executable path and closed public environment verified from assembly.
#[derive(Clone, Debug)]
pub struct VerifiedTool {
    /// Absolute executable path in the Nix store.
    pub executable: PathBuf,
    /// Explicit environment retained by the public assembly recipe.
    pub environment: std::collections::BTreeMap<String, String>,
}

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
) -> Result<VerifiedTool> {
    let tool = assembly_tool(assembly, id)?;
    validate_tool_file(tool)?;
    let current_hash = resolve_owner_nar_hash(&tool.executable)
        .with_context(|| format!("resolving current owner NAR hash for tool {id}"))?;
    if current_hash != tool.owner_nar_hash {
        bail!("assembly tool owner changed after capture");
    }
    Ok(VerifiedTool {
        executable: PathBuf::from(&tool.executable),
        environment: tool.environment.clone(),
    })
}

/// Computes a point-in-time SHA-256 identity for one single-link regular file.
///
/// # Errors
///
/// Returns an error when the path is linked or special, I/O fails, or the file
/// changes while it is hashed.
pub fn digest_regular_file(path: &Path) -> Result<(u64, Sha256Digest)> {
    digest_file(path, true)
}

/// Hashes a regular file in a private reconstructed image tree.
///
/// Firmware and tool aliases can share an inode after filesystem extraction.
/// Symlinks and files that change during hashing remain rejected.
///
/// # Errors
/// Returns an error for special files, symlinks, I/O failures, or content changes
/// during hashing.
pub(crate) fn digest_image_tree_file(path: &Path) -> Result<(u64, Sha256Digest)> {
    digest_file(path, false)
}

fn digest_file(path: &Path, require_single_link: bool) -> Result<(u64, Sha256Digest)> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening regular file {}", path.display()))?;
    digest_opened_regular_file(File::from(descriptor), require_single_link)
}

/// Computes a SHA-256 identity while refusing links in every path component.
///
/// # Errors
///
/// Returns an error when `relative` is empty or nonrelative, any parent is not
/// a real directory beneath `root`, the leaf is linked or special, or the file
/// changes while it is hashed.
pub fn digest_regular_file_beneath(root: &Path, relative: &Path) -> Result<(u64, Sha256Digest)> {
    let root_descriptor = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening confined directory {}", root.display()))?;
    let mut directory = File::from(root_descriptor);
    let mut components = relative.components().peekable();
    if components.peek().is_none() {
        bail!("confined digest path must be a nonempty relative path");
    }

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            bail!("confined digest path must contain only normal components");
        };
        if components.peek().is_none() {
            let descriptor = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("opening confined file {}", relative.display()))?;
            return digest_opened_regular_file(File::from(descriptor), true);
        }

        let descriptor = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening confined parent for {}", relative.display()))?;
        directory = File::from(descriptor);
    }
    bail!("confined digest path has no file component")
}

/// Hashes a native document alias without resolving links on the host.
///
/// The fixed image bundle directory may link to its immutable store root.
/// Document aliases are then followed only inside the copied Nix store, with a
/// bounded chain and no linked store parents. Host paths are never resolved.
///
/// # Errors
/// Returns an error for unexpected linked parents, a non-store target, cyclic
/// or changed aliases, missing or special documents, or failed hashing.
pub(crate) fn digest_native_document_beneath(
    root: &Path,
    relative: &Path,
    store_directory: &Path,
) -> Result<(u64, Sha256Digest)> {
    digest_native_alias(root, relative, store_directory, 0, true)
}

fn digest_native_alias(
    root: &Path,
    relative: &Path,
    store_directory: &Path,
    depth: usize,
    allow_bundle: bool,
) -> Result<(u64, Sha256Digest)> {
    if depth >= 8 {
        bail!("native document alias chain exceeds its limit");
    }

    let mut directory = File::from(open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let mut components = relative.components().peekable();
    let mut traversed = PathBuf::new();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            bail!("native alias path is not normalized");
        };
        traversed.push(name);
        if components.peek().is_some() {
            let bundle_directory = allow_bundle
                && matches!(
                    traversed.to_str(),
                    Some(
                        "lib/aos/initrd/deployment"
                            | "usr/lib/aos/initrd/deployment"
                            | "usr/lib/aos/host/deployment"
                    )
                );
            if bundle_directory {
                match readlinkat(&directory, name, Vec::new()) {
                    Ok(target) => {
                        let target_text = target
                            .to_str()
                            .context("native bundle alias is not UTF-8")?;
                        aos_release::artifact::require_store_path(target_text, false)?;
                        let suffix = target_text
                            .strip_prefix("/nix/store/")
                            .context("native bundle alias escapes store")?;
                        let remaining: PathBuf = components.map(|part| part.as_os_str()).collect();
                        let identity = digest_native_alias(
                            root,
                            &store_directory.join(suffix).join(remaining),
                            store_directory,
                            depth + 1,
                            false,
                        )?;
                        if readlinkat(&directory, name, Vec::new())? != target {
                            bail!("native bundle alias changed while hashing");
                        }
                        return Ok(identity);
                    }
                    Err(rustix::io::Errno::INVAL) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            directory = File::from(openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            continue;
        }
        let target = match readlinkat(&directory, name, Vec::new()) {
            Ok(target) => target,
            Err(rustix::io::Errno::INVAL) => return digest_regular_file_beneath(root, relative),
            Err(error) => return Err(error.into()),
        };
        let target_text = target
            .to_str()
            .context("native document alias is not UTF-8")?;
        let suffix = target_text
            .strip_prefix("/nix/store/")
            .context("native document alias escapes store")?;
        let component = suffix
            .split('/')
            .next()
            .context("native document alias lacks root")?;
        aos_release::artifact::require_store_path(&format!("/nix/store/{component}"), false)?;
        let identity = digest_native_alias(
            root,
            &store_directory.join(suffix),
            store_directory,
            depth + 1,
            false,
        )?;
        if readlinkat(&directory, name, Vec::new())? != target {
            bail!("native document alias changed while hashing");
        }
        return Ok(identity);
    }
    bail!("native document alias path is empty")
}

fn digest_opened_regular_file(
    mut file: File,
    require_single_link: bool,
) -> Result<(u64, Sha256Digest)> {
    let before = file.metadata()?;
    if !before.is_file() {
        bail!("digest input must be a regular file");
    }
    if require_single_link && before.nlink() != 1 {
        bail!("digest input must be a single-link regular file");
    }
    let (size, digest) = hash_reader(&mut file)?;
    let after = file.metadata()?;
    if size != before.len() || !same_snapshot(&before, &after) {
        bail!("digest input changed while it was hashed");
    }
    Ok((size, digest))
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
    // Store outputs may contain hard-linked executable aliases. The owner NAR
    // hash is checked separately; writable permissions remain forbidden.
    if !metadata.file_type().is_file() || metadata.mode() & 0o022 != 0 {
        bail!("assembly tool must be a regular file without group/world writes");
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
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use aos_release::artifact::BundlePath;
    use aos_release::platform::Platform;

    use super::*;
    use crate::assembly::{
        EfiFilenamesV1, ImageBudgetsV1, ImageCommandLinesV1, ImageLayoutV1, ImageSignerRolesV1,
        PartitionGuidsV1, PartitionTypeGuidsV1, SbatPolicyV1, UNSIGNED_IMAGE_ASSEMBLY_V1,
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

    #[test]
    fn confined_digest_rejects_a_symlinked_parent() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let tree = temporary.path().join("tree");
        let outside = temporary.path().join("outside");
        fs::create_dir(&tree)?;
        fs::create_dir(&outside)?;
        fs::write(outside.join("contract.json"), b"contract")?;
        symlink(&outside, tree.join("usr"))?;

        assert!(
            digest_regular_file_beneath(&tree, Path::new("usr/contract.json")).is_err(),
            "a parent link must not escape the extracted tree"
        );
        Ok(())
    }

    #[test]
    fn confined_digest_rejects_a_fifo_without_blocking() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let tree = temporary.path().join("tree");
        fs::create_dir(&tree)?;
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            tree.join("contract.json"),
            Mode::RUSR | Mode::WUSR,
        )?;

        assert!(
            digest_regular_file_beneath(&tree, Path::new("contract.json")).is_err(),
            "a FIFO must be rejected as a special file"
        );
        Ok(())
    }

    #[test]
    fn image_tree_digest_accepts_hard_links_without_relaxing_document_checks() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let file = temporary.path().join("firmware");
        fs::write(&file, b"firmware")?;
        fs::hard_link(&file, temporary.path().join("firmware-alias"))?;

        assert!(super::digest_image_tree_file(&file).is_ok());
        assert!(super::digest_regular_file(&file).is_err());
        assert!(digest_regular_file_beneath(temporary.path(), Path::new("firmware")).is_err());
        Ok(())
    }

    #[test]
    fn tool_accepts_read_only_hard_links_but_rejects_writable_files() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let executable = temporary.path().join("objcopy");
        fs::write(&executable, b"tool")?;
        fs::hard_link(&executable, temporary.path().join("objcopy-alias"))?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;

        let tool = AssemblyToolV1 {
            id: "objcopy".to_owned(),
            executable: executable.to_string_lossy().into_owned(),
            owner_nar_hash: "sha256:example".to_owned(),
            environment: Default::default(),
        };
        assert_eq!(fs::metadata(&executable)?.nlink(), 2);
        assert!(validate_tool_file(&tool).is_ok());

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o777))?;
        assert!(validate_tool_file(&tool).is_err());

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        let alias = temporary.path().join("objcopy-symlink");
        symlink(&executable, &alias)?;
        let symlinked_tool = AssemblyToolV1 {
            executable: alias.to_string_lossy().into_owned(),
            ..tool
        };
        assert!(validate_tool_file(&symlinked_tool).is_err());
        Ok(())
    }

    #[test]
    fn native_alias_resolves_only_inside_extracted_store() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let tree = temporary.path();
        let store_root = "00000000000000000000000000000000-native-input";
        let document = tree
            .join("nix/store")
            .join(store_root)
            .join("transaction.json");
        std::fs::create_dir_all(document.parent().context("fixture lacks parent")?)?;
        std::fs::create_dir_all(tree.join("lib/aos/initrd/deployment"))?;
        std::fs::write(&document, b"native transaction bytes")?;
        let alias = tree.join("lib/aos/initrd/deployment/transaction.json");
        symlink(format!("/nix/store/{store_root}/transaction.json"), &alias)?;

        let identity = digest_native_document_beneath(
            tree,
            Path::new("lib/aos/initrd/deployment/transaction.json"),
            Path::new("nix/store"),
        )?;
        assert_eq!(identity, digest_regular_file(&document)?);

        std::fs::remove_file(&alias)?;
        symlink("/etc/passwd", &alias)?;
        assert!(
            digest_native_document_beneath(
                tree,
                Path::new("lib/aos/initrd/deployment/transaction.json"),
                Path::new("nix/store")
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn native_bundle_directory_preserves_immutable_alias_chains() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let tree = temporary.path();
        let bundle = "00000000000000000000000000000000-native-bundle";
        let payload = "11111111111111111111111111111111-native-document";
        let bundle_root = tree.join("nix/store").join(bundle);
        let payload_root = tree.join("nix/store").join(payload);
        std::fs::create_dir_all(&bundle_root)?;
        std::fs::create_dir_all(&payload_root)?;
        std::fs::create_dir_all(tree.join("lib/aos/initrd"))?;

        let document = payload_root.join("transaction.json");
        std::fs::write(&document, b"immutable native transaction")?;
        symlink(
            format!("/nix/store/{payload}/transaction.json"),
            bundle_root.join("transaction.json"),
        )?;
        let directory_alias = tree.join("lib/aos/initrd/deployment");
        symlink(format!("/nix/store/{bundle}"), &directory_alias)?;

        let relative = Path::new("lib/aos/initrd/deployment/transaction.json");
        assert_eq!(
            digest_native_document_beneath(tree, relative, Path::new("nix/store"))?,
            digest_regular_file(&document)?
        );

        std::fs::remove_file(&directory_alias)?;
        symlink("/etc", &directory_alias)?;
        assert!(digest_native_document_beneath(tree, relative, Path::new("nix/store")).is_err());
        Ok(())
    }

    #[test]
    fn native_bundle_document_cycle_fails_closed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let tree = temporary.path();
        let bundle = "00000000000000000000000000000000-native-bundle";
        let bundle_root = tree.join("nix/store").join(bundle);
        std::fs::create_dir_all(&bundle_root)?;
        std::fs::create_dir_all(tree.join("lib/aos/initrd"))?;
        symlink(
            format!("/nix/store/{bundle}/transaction.json"),
            bundle_root.join("transaction.json"),
        )?;
        symlink(
            format!("/nix/store/{bundle}"),
            tree.join("lib/aos/initrd/deployment"),
        )?;

        assert!(
            digest_native_document_beneath(
                tree,
                Path::new("lib/aos/initrd/deployment/transaction.json"),
                Path::new("nix/store"),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn native_alias_cannot_follow_a_linked_store_directory() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let tree = temporary.path();
        std::fs::create_dir_all(tree.join("lib/aos/initrd/deployment"))?;
        symlink(temporary.path(), tree.join("nix"))?;
        symlink(
            "/nix/store/00000000000000000000000000000000-input/transaction.json",
            tree.join("lib/aos/initrd/deployment/transaction.json"),
        )?;
        assert!(
            digest_native_document_beneath(
                tree,
                Path::new("lib/aos/initrd/deployment/transaction.json"),
                Path::new("nix/store")
            )
            .is_err()
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
            recovery_abi: 1,
            sbat_generation: 1,
            sbat: SbatPolicyV1 {
                component: "aos".to_owned(),
                vendor: "Andyl Inc.".to_owned(),
                package: "aos".to_owned(),
                url: "https://aos.dev".to_owned(),
            },
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
                converted_download_mib: None,
                recovery_bundle_mib: None,
            },
            initrd_contract: None,
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
