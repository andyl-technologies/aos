//! Architecture-specific guest boot assets and content-reference validation.

use std::fs;
use std::path::{Path, PathBuf};

use crucible::{ContentHash, NodeId};

use super::*;

/// Immutable boot artifacts selected for one guest architecture.
#[derive(Clone, Debug)]
pub(super) struct ProductionVmGuestAssets {
    pub(super) kernel: PathBuf,
    pub(super) root_image: PathBuf,
    pub(super) kernel_cmdline_prefix: Option<String>,
}

/// Exact configured guest paths selected for one replay architecture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionVmPortableReplayGuestAssetPaths {
    architecture: crucible::VmArchitecture,
    kernel: PathBuf,
    root_image: PathBuf,
    kernel_cmdline_prefix: Option<String>,
}

impl ProductionVmPortableReplayGuestAssetPaths {
    /// Returns the selected guest architecture.
    #[must_use]
    pub const fn architecture(&self) -> crucible::VmArchitecture {
        self.architecture
    }

    /// Returns the exact configured kernel path.
    #[must_use]
    pub fn kernel(&self) -> &Path {
        &self.kernel
    }

    /// Returns the exact configured immutable root-image path.
    #[must_use]
    pub fn root_image(&self) -> &Path {
        &self.root_image
    }

    /// Returns the effective package command-line prefix for this architecture.
    #[must_use]
    pub fn kernel_cmdline_prefix(&self) -> Option<&str> {
        self.kernel_cmdline_prefix.as_deref()
    }
}

/// Read-only exact guest deployment selected for a portable replay capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionVmPortableReplayAssetPaths {
    guest_assets: Vec<ProductionVmPortableReplayGuestAssetPaths>,
    initrd: Option<PathBuf>,
    root_image_format: ProductionRootImageFormat,
}

impl ProductionVmPortableReplayAssetPaths {
    /// Returns one sorted, unique asset set for each scenario architecture.
    #[must_use]
    pub fn guest_assets(&self) -> &[ProductionVmPortableReplayGuestAssetPaths] {
        &self.guest_assets
    }

    /// Returns the shared initrd path passed to every VM, when configured.
    #[must_use]
    pub fn initrd(&self) -> Option<&Path> {
        self.initrd.as_deref()
    }

    /// Returns the immutable root-image format passed to QEMU.
    #[must_use]
    pub const fn root_image_format(&self) -> ProductionRootImageFormat {
        self.root_image_format
    }
}

impl ProductionVmLifecycleConfig {
    /// Resolves and validates the exact guest files used by `scenario`.
    ///
    /// The projection owns path values but cannot modify lifecycle selection.
    /// Callers can copy these files into a path-free replay artifact before a
    /// private lifecycle and its deployment paths are released.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when an architecture has no configured
    /// assets or an authored kernel, root-image, or initrd reference differs
    /// from the selected file.
    pub fn portable_replay_asset_paths(
        &self,
        scenario: &crucible::ScenarioDefForm,
    ) -> Result<ProductionVmPortableReplayAssetPaths, LifecycleApiError> {
        let mut selected = std::collections::BTreeMap::new();
        for vm in scenario.world().vm_nodes() {
            let assets = self.guest_assets.get(&vm.arch).ok_or_else(|| {
                loop_factory_error(format!(
                    "production QEMU lifecycle has no boot artifacts for {:?}",
                    vm.arch
                ))
            })?;
            validate_guest_asset_references(vm, assets)?;
            match (vm.initrd, self.initrd.as_ref()) {
                (Some(expected), Some(path)) => {
                    validate_guest_asset_reference(&vm.id, "initrd", Some(expected), path)?;
                }
                (Some(_), None) => {
                    return Err(loop_factory_error(format!(
                        "QEMU node `{}` declares an initrd but no materialized initrd was configured",
                        vm.id.name
                    )));
                }
                (None, _) => {}
            }
            selected
                .entry(vm.arch)
                .or_insert_with(|| ProductionVmPortableReplayGuestAssetPaths {
                    architecture: vm.arch,
                    kernel: assets.kernel.clone(),
                    root_image: assets.root_image.clone(),
                    kernel_cmdline_prefix: production_kernel_cmdline_prefix(self, vm.arch, assets)
                        .map(ToOwned::to_owned),
                });
        }
        Ok(ProductionVmPortableReplayAssetPaths {
            guest_assets: selected.into_values().collect(),
            initrd: self.initrd.clone(),
            root_image_format: self.root_image_format,
        })
    }
}

/// Selects a command-line prefix without crossing guest architectures.
pub(super) fn production_kernel_cmdline_prefix<'a>(
    config: &'a ProductionVmLifecycleConfig,
    architecture: VmArchitecture,
    guest_assets: &'a ProductionVmGuestAssets,
) -> Option<&'a str> {
    guest_assets.kernel_cmdline_prefix.as_deref().or_else(|| {
        (architecture == config.native_guest_architecture)
            .then_some(config.kernel_cmdline_prefix.as_deref())
            .flatten()
    })
}

fn validate_guest_asset_reference(
    node: &NodeId,
    label: &'static str,
    expected: Option<crucible::ContentAddressedBlobRef>,
    path: &Path,
) -> Result<(), LifecycleApiError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let file = fs::File::open(path).map_err(|error| {
        loop_factory_error(format!(
            "read {label} for production node `{}` from {}: {error}",
            node.name,
            path.display()
        ))
    })?;
    let actual = ContentHash::from_reader(file).map_err(|error| {
        loop_factory_error(format!(
            "hash {label} for production node `{}` from {}: {error}",
            node.name,
            path.display()
        ))
    })?;
    if expected.hash() != actual {
        return Err(loop_factory_error(format!(
            "production node `{}` declares {label} {} but selected file {} hashes to blake3:{}",
            node.name,
            expected.to_uri(),
            path.display(),
            actual.to_hex()
        )));
    }
    Ok(())
}

pub(super) fn validate_guest_asset_references(
    vm: &crucible::WorldNode,
    guest_assets: &ProductionVmGuestAssets,
) -> Result<(), LifecycleApiError> {
    validate_guest_asset_reference(&vm.id, "kernel", vm.kernel, &guest_assets.kernel)?;
    validate_guest_asset_reference(
        &vm.id,
        "root image",
        vm.root_image,
        &guest_assets.root_image,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{
        ContentAddressedBlobRef, Plan, Properties, ReadyPoint, ScenarioDefForm, Seed,
        WhiteBoxPolicy, World, WorldNode,
    };

    fn test_node(kernel: &[u8], root_image: &[u8]) -> WorldNode {
        WorldNode {
            id: NodeId {
                name: String::from("debuggee"),
            },
            arch: VmArchitecture::X86_64,
            memory_mib: 256,
            cmdline: String::from("quiet"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
                kernel,
            ))),
            root_image: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
                root_image,
            ))),
            initrd: None,
        }
    }

    #[test]
    fn production_assets_must_match_declared_content_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let kernel = directory.path().join("kernel");
        let root_image = directory.path().join("root.img");
        fs::write(&kernel, b"kernel-bytes")?;
        fs::write(&root_image, b"root-image-bytes")?;
        let assets = ProductionVmGuestAssets {
            kernel,
            root_image,
            kernel_cmdline_prefix: None,
        };

        let matching = test_node(b"kernel-bytes", b"root-image-bytes");
        validate_guest_asset_references(&matching, &assets)?;

        let mismatched = test_node(b"different-kernel", b"root-image-bytes");
        let error = validate_guest_asset_references(&mismatched, &assets)
            .err()
            .ok_or("mismatched kernel reference unexpectedly passed")?;
        assert!(error.to_string().contains("declares kernel blake3:"));
        assert!(error.to_string().contains("hashes to blake3:"));
        Ok(())
    }

    #[test]
    fn portable_projection_selects_and_validates_exact_guest_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let kernel = directory.path().join("kernel");
        let root_image = directory.path().join("root.img");
        let initrd = directory.path().join("initrd");
        fs::write(&kernel, b"kernel-bytes")?;
        fs::write(&root_image, b"root-image-bytes")?;
        fs::write(&initrd, b"initrd-bytes")?;

        let mut node = test_node(b"kernel-bytes", b"root-image-bytes");
        node.initrd = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            b"initrd-bytes",
        )));
        let world = World::from_nodes(vec![node])?;
        let scenario = ScenarioDefForm::from_components(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(1),
        )?;
        let config = ProductionVmLifecycleConfig::new(
            "qemu",
            "plugin",
            &kernel,
            &root_image,
            directory.path().join("run"),
        )
        .with_initrd(&initrd)
        .with_root_image_format(ProductionRootImageFormat::Raw);
        let selected = config.portable_replay_asset_paths(&scenario)?;

        assert_eq!(selected.root_image_format(), ProductionRootImageFormat::Raw);
        assert_eq!(selected.initrd(), Some(initrd.as_path()));
        assert_eq!(selected.guest_assets().len(), 1);
        assert_eq!(selected.guest_assets()[0].kernel(), kernel.as_path());
        assert_eq!(
            selected.guest_assets()[0].root_image(),
            root_image.as_path()
        );

        fs::write(&initrd, b"changed-initrd")?;
        assert!(config.portable_replay_asset_paths(&scenario).is_err());
        Ok(())
    }
}
