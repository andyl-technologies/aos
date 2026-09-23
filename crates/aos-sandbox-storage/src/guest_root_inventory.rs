//! Protected Storage projection of physically published guest workspace roots.
//!
//! The source inventory has already been authenticated by the Storage runtime
//! and each row's root pin revalidated. This module adds only physical
//! publication evidence. It never treats a workspace marker as authority:
//! the expected proof is rebuilt from the current catalog row and a fixed
//! deployment-pinned AOS package template, then the complete tree is measured.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse;
use aos_sandbox_agent::guest_root_marker::read_guest_root_marker_v1;
use aos_sandbox_agent::guest_root_publication::{
    CONCRETE_GUEST_FEATURE_MASK_V1, GuestRootPublicationProofV1,
};
use aos_sandbox_agent::guest_root_tree::compare_guest_root_template_v1;
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES, ValidatedStorageWorkspace, decode_storage_resource_inventory_response,
};
use buffa::Message as _;

const PACKAGE_BINDING_FILE: &str = "package-binding";
const ROOT_TREE_DIGEST_FILE: &str = "root-tree-digest";
const ROOT_DIRECTORY: &str = "root";
const MARKER_FILE: &str = "etc/aos/sandbox-guest-root/publication-v1";
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;

/// Holds one exact, root-protected AOS package template selected by deployment.
#[derive(Clone, Debug)]
pub struct ProtectedGuestRootTemplateV1 {
    root: PathBuf,
    package_binding: [u8; 32],
    root_tree_digest: [u8; 32],
}

impl ProtectedGuestRootTemplateV1 {
    /// Opens and measures one fixed derivation output, not a request path.
    ///
    /// # Errors
    ///
    /// Returns [`GuestRootInventoryErrorV1`] if the output, binding file,
    /// ownership, mode, or complete template tree is not exact and protected.
    pub fn open(package_path: &Path) -> Result<Self, GuestRootInventoryErrorV1> {
        if !package_path.starts_with("/nix/store")
            || package_path == Path::new("/nix/store")
            || package_path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(GuestRootInventoryErrorV1::InvalidTemplate);
        }
        for ancestor in package_path
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            verify_protected_directory(ancestor)?;
        }
        let root = package_path.join(ROOT_DIRECTORY);
        verify_protected_directory(&root)?;

        let package_binding = read_protected_digest(&package_path.join(PACKAGE_BINDING_FILE))?;
        let expected_tree_digest =
            read_protected_digest(&package_path.join(ROOT_TREE_DIGEST_FILE))?;

        let root_tree_digest = compare_guest_root_template_v1(&root, &root)
            .map_err(|_| GuestRootInventoryErrorV1::InvalidTemplate)?;
        if root_tree_digest != expected_tree_digest {
            return Err(GuestRootInventoryErrorV1::InvalidTemplate);
        }
        Ok(Self {
            root,
            package_binding,
            root_tree_digest,
        })
    }

    /// Returns the independently pinned package-closure commitment.
    #[must_use]
    pub const fn package_binding(&self) -> &[u8; 32] {
        &self.package_binding
    }

    /// Returns the physically measured complete template tree commitment.
    #[must_use]
    pub const fn root_tree_digest(&self) -> &[u8; 32] {
        &self.root_tree_digest
    }

    /// Returns the protected template root used only by the fixed publisher.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn expected_proof(
        &self,
        workspace: &ValidatedStorageWorkspace,
    ) -> GuestRootPublicationProofV1 {
        GuestRootPublicationProofV1 {
            sandbox: *workspace.fence().sandbox_id(),
            incarnation: *workspace.fence().incarnation_id(),
            assignment_epoch: workspace.fence().assignment_epoch(),
            assignment_digest: *workspace.fence().assignment_digest(),
            creation_operation: *workspace.creation_operation_id(),
            workspace_handle: *workspace.workspace_handle(),
            dataset_guid: workspace.dataset_guid(),
            root_image_digest: *workspace.root_image().digest().as_bytes(),
            package_binding: self.package_binding,
            root_tree_digest: self.root_tree_digest,
            feature_mask: CONCRETE_GUEST_FEATURE_MASK_V1,
        }
    }
}

/// Adds exact physical AOSGRP01 proof to current authenticated inventory rows.
///
/// Missing marker means the workspace is not launch-ready. A present but
/// malformed, stale, or physically mismatched marker rejects the entire
/// snapshot; it cannot be silently treated as absence.
///
/// # Errors
///
/// Returns [`GuestRootInventoryErrorV1`] if input inventory is invalid, a
/// present marker or tree does not match, or the bounded output is invalid.
pub fn attach_guest_root_publication_readback_v1(
    inventory_bytes: &[u8],
    template: &ProtectedGuestRootTemplateV1,
) -> Result<Vec<u8>, GuestRootInventoryErrorV1> {
    let inventory =
        decode_storage_resource_inventory_response(inventory_bytes, MAXIMUM_RESPONSE_BYTES)
            .map_err(|_| GuestRootInventoryErrorV1::InvalidInventory)?;
    let mut response = InventoryStorageResourcesResponse::decode_from_slice(inventory_bytes)
        .map_err(|_| GuestRootInventoryErrorV1::InvalidInventory)?;
    if response.workspaces.len() != inventory.workspaces().len() {
        return Err(GuestRootInventoryErrorV1::InvalidInventory);
    }

    for (record, workspace) in response.workspaces.iter_mut().zip(inventory.workspaces()) {
        if !record.guest_root_publication_proof.is_empty() {
            return Err(GuestRootInventoryErrorV1::InvalidInventory);
        }
        let root = Path::new(workspace.root_directory());
        verify_workspace_root(root, workspace)?;
        let marker = root.join(MARKER_FILE);
        match fs::symlink_metadata(marker) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }

        let expected = template.expected_proof(workspace);
        read_guest_root_marker_v1(template.root(), root, expected)
            .map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?;
        verify_workspace_root(root, workspace)?;
        record.guest_root_publication_proof = expected
            .encode()
            .map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?
            .to_vec();
    }

    let encoded = response.encode_to_vec();
    decode_storage_resource_inventory_response(&encoded, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| GuestRootInventoryErrorV1::InvalidInventory)?;
    Ok(encoded)
}

fn verify_workspace_root(
    root: &Path,
    workspace: &ValidatedStorageWorkspace,
) -> Result<(), GuestRootInventoryErrorV1> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.dev() != workspace.root_device()
        || metadata.ino() != workspace.root_inode()
    {
        return Err(GuestRootInventoryErrorV1::InvalidPublication);
    }
    Ok(())
}

fn verify_protected_directory(path: &Path) -> Result<(), GuestRootInventoryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    Ok(())
}

fn read_protected_digest(path: &Path) -> Result<[u8; 32], GuestRootInventoryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)?;
    if file.metadata()?.ino() != metadata.ino() {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    let mut encoded = Vec::new();
    file.take(66).read_to_end(&mut encoded)?;
    if encoded.len() != 65 || encoded[64] != b'\n' {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded[..64].chunks_exact(2).enumerate() {
        digest[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    if digest == [0; 32] {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    Ok(digest)
}

fn hex_digit(byte: u8) -> Result<u8, GuestRootInventoryErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(GuestRootInventoryErrorV1::InvalidTemplate),
    }
}

/// Reports rejection at the protected template/inventory readback boundary.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootInventoryErrorV1 {
    /// The pinned template, its package binding, or its ownership is invalid.
    #[error("protected guest root template is invalid")]
    InvalidTemplate,
    /// The authenticated workspace inventory is invalid or already annotated.
    #[error("guest root inventory input or output is invalid")]
    InvalidInventory,
    /// A present publication marker or complete workspace tree is invalid.
    #[error("guest root physical publication is invalid")]
    InvalidPublication,
    /// A protected template or workspace filesystem operation failed.
    #[error("guest root physical readback failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_source_must_be_a_protected_store_output() {
        for path in [
            "/tmp/guest-template",
            "/nix/store",
            "/nix/store/../guest-template",
            "relative/guest-template",
        ] {
            assert!(matches!(
                ProtectedGuestRootTemplateV1::open(Path::new(path)),
                Err(GuestRootInventoryErrorV1::InvalidTemplate)
            ));
        }
    }

    #[test]
    fn package_binding_rejects_noncanonical_hex() {
        assert_eq!(hex_digit(b'a').ok(), Some(10));
        assert_eq!(hex_digit(b'9').ok(), Some(9));
        assert!(hex_digit(b'A').is_err());
        assert!(hex_digit(b'g').is_err());
    }
}
