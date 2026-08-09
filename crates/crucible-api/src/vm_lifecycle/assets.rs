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
    use crucible::{ContentAddressedBlobRef, ReadyPoint, WhiteBoxPolicy, WorldNode};

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
}
