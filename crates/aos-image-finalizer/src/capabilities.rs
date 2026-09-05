//! Captures capabilities from resolved configuration and final signed trees.
//!
//! Image symlinks resolve inside the reconstructed image, including absolute
//! Nix store links. They never authorize reading the build host's filesystem.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::BundlePath;
use aos_release::digest::Sha256Digest;
use aos_release::qualification::capabilities::{
    CapabilityFile, ImageCapabilities, StageCapabilities,
};

use crate::input::digest_regular_file;

/// Captures actual kernel, module and firmware availability in final trees.
///
/// # Errors
/// Returns an error for malformed kernel configuration, missing built-in driver
/// metadata, ambiguous module names, unsafe links or unreadable input files.
pub fn capture(
    kernel_release: &str,
    kernel_config: &Path,
    runtime: &Path,
    initrd: &Path,
    recovery_a: &Path,
    recovery_b: &Path,
) -> Result<ImageCapabilities> {
    let config = fs::read(kernel_config)?;
    let mut kernel_options = BTreeMap::new();
    for line in std::str::from_utf8(&config)?.lines() {
        let entry = if let Some((key, value)) = line.split_once('=') {
            key.starts_with("CONFIG_").then_some((key, value))
        } else {
            line.strip_prefix("# ")
                .and_then(|line| line.strip_suffix(" is not set"))
                .filter(|key| key.starts_with("CONFIG_"))
                .map(|key| (key, "n"))
        };
        if let Some((key, value)) = entry {
            if value.is_empty()
                || kernel_options
                    .insert(key.to_owned(), value.to_owned())
                    .is_some()
            {
                bail!("resolved kernel configuration contains empty or duplicate values");
            }
        }
    }
    if kernel_options.is_empty() {
        bail!("resolved kernel configuration is empty");
    }
    let builtin = resolve(
        runtime,
        Path::new(&format!("lib/modules/{kernel_release}/modules.builtin")),
    )?;
    let mut builtin_drivers = BTreeSet::new();
    for path in fs::read_to_string(builtin)?.lines() {
        BundlePath::parse(path)?;
        builtin_drivers.insert(driver_name(Path::new(path))?);
    }
    let mut stages = BTreeMap::new();
    for (name, tree) in [
        ("runtime", runtime),
        ("initrd", initrd),
        ("recovery-a", recovery_a),
        ("recovery-b", recovery_b),
    ] {
        let module_root = PathBuf::from(format!("lib/modules/{kernel_release}"));
        let mut modules = BTreeMap::new();
        for (path, file) in files(tree, &module_root, true)? {
            if Path::new(&path)
                .extension()
                .is_some_and(|extension| extension == "ko")
            {
                let driver = driver_name(Path::new(&path))?;
                if modules.insert(driver.clone(), file).is_some() {
                    bail!("ambiguous module name {driver} in {name} stage");
                }
            }
        }
        let firmware = files(tree, Path::new("lib/firmware"), false)?;
        stages.insert(name.to_owned(), StageCapabilities { modules, firmware });
    }
    Ok(ImageCapabilities {
        schema_version: "aos.image.capabilities/v1".to_owned(),
        kernel_release: kernel_release.to_owned(),
        kernel_config_digest: Sha256Digest::of_bytes(config),
        kernel_options,
        builtin_drivers: builtin_drivers.into_iter().collect(),
        stages,
    })
}

fn driver_name(path: &Path) -> Result<String> {
    if path.extension().is_none_or(|extension| extension != "ko") {
        bail!("kernel driver inventory requires .ko entries");
    }
    Ok(path
        .file_stem()
        .and_then(|name| name.to_str())
        .context("non-UTF8 driver name")?
        .replace('-', "_"))
}

fn files(
    tree: &Path,
    directory: &Path,
    exclude_development_links: bool,
) -> Result<BTreeMap<String, CapabilityFile>> {
    let mut result = BTreeMap::new();
    let path = match resolve(tree, directory) {
        Ok(path) => path,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(result);
        }
        Err(error) => return Err(error),
    };
    walk(
        tree,
        &path,
        Path::new(""),
        exclude_development_links,
        &mut BTreeSet::new(),
        &mut result,
    )?;
    Ok(result)
}

fn walk(
    tree: &Path,
    directory: &Path,
    relative: &Path,
    exclude_development_links: bool,
    ancestors: &mut BTreeSet<PathBuf>,
    result: &mut BTreeMap<String, CapabilityFile>,
) -> Result<()> {
    if ancestors.len() >= 64 || !ancestors.insert(directory.to_path_buf()) {
        bail!("cyclic or excessively deep capability directory");
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        // Build/source links are development interfaces, not runtime modules.
        if exclude_development_links
            && matches!(entry.file_name().to_str(), Some("build" | "source"))
        {
            continue;
        }
        let next = relative.join(entry.file_name());
        let path = resolve(tree, entry.path().strip_prefix(tree)?)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            walk(tree, &path, &next, false, ancestors, result)?;
        } else if metadata.is_file() {
            let name = next
                .to_str()
                .context("non-UTF8 capability path")?
                .to_owned();
            let record = CapabilityFile {
                path: BundlePath::parse(&name)?,
                sha256: digest_regular_file(&path)?.1,
            };
            if result.len() >= 1_000_000 || result.insert(name, record).is_some() {
                bail!("oversized or duplicate capability inventory");
            }
        } else {
            bail!("capability inventory contains a special file");
        }
    }
    ancestors.remove(directory);
    Ok(())
}

/// Resolves links with the image root as `/`, rejecting traversal above it.
fn resolve(tree: &Path, relative: &Path) -> Result<PathBuf> {
    let mut remaining: VecDeque<_> = relative
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = remaining.pop_front() {
        match Path::new(&part).components().next() {
            Some(Component::RootDir) => resolved.clear(),
            Some(Component::CurDir) => {}
            Some(Component::ParentDir) => {
                if !resolved.pop() {
                    bail!("image capability link escapes its root");
                }
            }
            Some(Component::Normal(name)) => {
                let candidate = tree.join(&resolved).join(name);
                if fs::symlink_metadata(&candidate)?.file_type().is_symlink() {
                    links += 1;
                    if links > 40 {
                        bail!("excessive image capability symlink chain");
                    }
                    let target = fs::read_link(candidate)?;
                    for part in target.components().rev() {
                        remaining.push_front(part.as_os_str().to_owned());
                    }
                } else {
                    resolved.push(name);
                }
            }
            _ => bail!("invalid image capability path"),
        }
    }
    Ok(tree.join(resolved))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use aos_release::qualification::environment::{
        BootImplementation, BootStage, DeviceRequirement, EnvironmentProfile, Resources,
        SecurityState,
    };

    fn fixture() -> Result<tempfile::TempDir> {
        let temporary = tempfile::tempdir()?;
        fs::write(
            temporary.path().join("kernel.config"),
            "CONFIG_EFI=y\nCONFIG_VIRTIO_BLK=y\nCONFIG_VIRTIO_NET=m\n# CONFIG_UNUSED is not set\n",
        )?;
        for name in ["runtime", "initrd", "recovery-a", "recovery-b"] {
            let tree = temporary.path().join(name);
            let modules = tree.join("nix/store/synthetic-kernel/lib/modules/synthetic");
            fs::create_dir_all(&modules)?;
            fs::create_dir_all(tree.join("usr/lib/firmware"))?;
            symlink("usr/lib", tree.join("lib"))?;
            symlink(
                "/nix/store/synthetic-kernel/lib/modules",
                tree.join("usr/lib/modules"),
            )?;
            fs::write(modules.join("modules.builtin"), "kernel/virtio_blk.ko\n")?;
            fs::write(modules.join("virtio_net.ko"), b"final signed module bytes")?;
            fs::write(tree.join("usr/lib/firmware/network.bin"), b"firmware bytes")?;
            symlink(
                "network.bin",
                tree.join("usr/lib/firmware/network-alias.bin"),
            )?;
            symlink("/missing-development-output", modules.join("build"))?;
        }
        Ok(temporary)
    }

    fn collect(root: &Path) -> Result<ImageCapabilities> {
        capture(
            "synthetic",
            &root.join("kernel.config"),
            &root.join("runtime"),
            &root.join("initrd"),
            &root.join("recovery-a"),
            &root.join("recovery-b"),
        )
    }

    fn scope() -> EnvironmentProfile {
        EnvironmentProfile {
            layers: Vec::new(),
            boot: BootImplementation::SystemdBootUki,
            security: SecurityState::default(),
            resources: Resources {
                cpus: 1,
                memory_mib: 1,
                disk_mib: 1,
            },
            kernel_options: BTreeMap::from([("CONFIG_EFI".into(), "y".into())]),
            devices: vec![DeviceRequirement {
                driver: "virtio_net".into(),
                bus: None,
                vendor: None,
                product: None,
                revision: None,
                stage: BootStage::Recovery,
                firmware: vec!["network-alias.bin".into()],
            }],
        }
    }

    #[test]
    fn captures_final_bytes_through_image_local_store_and_firmware_links() -> Result<()> {
        let temporary = fixture()?;
        let capabilities = collect(temporary.path())?;
        capabilities.satisfies(&scope())?;
        assert_eq!(capabilities.kernel_options["CONFIG_UNUSED"], "n");
        assert_eq!(capabilities.builtin_drivers, ["virtio_blk"]);
        assert_eq!(
            capabilities.stages["initrd"].modules["virtio_net"].sha256,
            Sha256Digest::of_bytes("final signed module bytes")
        );
        assert_eq!(
            capabilities.stages["runtime"].firmware["network-alias.bin"].sha256,
            Sha256Digest::of_bytes("firmware bytes")
        );
        Ok(())
    }

    #[test]
    fn recovery_requires_driver_and_firmware_in_both_slots() -> Result<()> {
        let temporary = fixture()?;
        fs::remove_file(
            temporary
                .path()
                .join("recovery-b/nix/store/synthetic-kernel/lib/modules/synthetic/virtio_net.ko"),
        )?;
        assert!(collect(temporary.path())?.satisfies(&scope()).is_err());
        let mut capabilities = collect(temporary.path())?;
        capabilities.builtin_drivers.push("virtio_net".into());
        capabilities.satisfies(&scope())?;
        capabilities
            .stages
            .get_mut("recovery-b")
            .unwrap()
            .firmware
            .remove("network-alias.bin");
        assert!(capabilities.satisfies(&scope()).is_err());
        Ok(())
    }

    #[test]
    fn absolute_image_links_never_read_host_files_and_cycles_are_rejected() -> Result<()> {
        let temporary = fixture()?;
        let host = temporary.path().join("host-only-firmware");
        fs::write(&host, "must not be read through an image link")?;
        let link = temporary.path().join("initrd/usr/lib/firmware/host-link");
        symlink(&host, &link)?;
        assert!(collect(temporary.path()).is_err());
        fs::remove_file(&link)?;
        symlink(".", &link)?;
        assert!(collect(temporary.path()).is_err());
        Ok(())
    }

    #[test]
    fn configuration_changes_and_invalid_resolved_inputs_fail_closed() -> Result<()> {
        let temporary = fixture()?;
        fs::write(temporary.path().join("kernel.config"), "CONFIG_EFI=n\n")?;
        assert!(collect(temporary.path())?.satisfies(&scope()).is_err());
        fs::write(
            temporary.path().join("kernel.config"),
            "CONFIG_EFI=y\nCONFIG_EFI=n\n",
        )?;
        assert!(collect(temporary.path()).is_err());
        Ok(())
    }
}
