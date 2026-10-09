//! Bounded portable member projection for canonical Nix recipe DATA.
//!
//! Names, original metadata, Tree-local hardlink labels, and Content descriptors
//! remain comparison DATA. This module opens no paths, retains no descriptors,
//! observes no physical store, and grants no recipe, readback, or effect authority.
//!
//! ```text
//! member = relative-name | Content(descriptor, metadata?, tree-local-hardlink?)
//!        | Directory(metadata) | Symlink(metadata, target)
//! ```

use std::collections::TryReserveError;

use aos_sandbox_core::model::{ContentLayout, Node};
use aos_sandbox_core::{
    CanonicalCborError, DecodeLimits, ObjectDescriptor, PortableMediaType, StreamingDirectory,
};

use super::{NixPreadmittedRecipeV2, NixStoreObjectV2};

/// Reports a pure projection refusal, never an effect or retry disposition.
#[derive(Debug, thiserror::Error)]
pub enum NixStoreProjectionErrorV2 {
    /// Retains the original canonical Directory decoding failure.
    #[error("original Directory decoding failed: {0}")]
    Directory(#[from] CanonicalCborError),
    /// Retains the original bounded allocation failure.
    #[error("bounded input allocation failed: {0}")]
    Allocation(#[from] TryReserveError),
    /// Rejects excessive members, encoded Content bytes, depth, or path length.
    #[error("local input count, byte or read bound exceeded")]
    Bound,
    /// Rejects missing portable records or conflicting member names.
    #[error("one staged basename has inconsistent descriptor or original bytes")]
    Conflict,
    /// Rejects a layout outside the selected Whole Content profile.
    #[error("local input layout is outside the admitted Whole Content profile")]
    UnsupportedLayout,
    /// Rejects a store object without its expected rooted path prefix.
    #[error("local input root, project, named inode or exact size changed")]
    Changed,
}

/// Checks one member's growth against the fixed portable count and byte bounds.
///
/// # Errors
///
/// Rejects arithmetic overflow or a count/Content-byte limit exceeded before
/// callers allocate or append the member.
pub fn checked_store_projection_growth_v2(
    count: usize,
    distinct_bytes: u64,
    encoded_size: u64,
) -> Result<u64, NixStoreProjectionErrorV2> {
    let next_count = count
        .checked_add(1)
        .ok_or(NixStoreProjectionErrorV2::Bound)?;
    let next_bytes = distinct_bytes
        .checked_add(encoded_size)
        .ok_or(NixStoreProjectionErrorV2::Bound)?;
    if next_count > super::NIX_MAXIMUM_OBJECTS_V2
        || encoded_size > super::NIX_MAXIMUM_OBJECT_BYTES_V2
        || next_bytes > super::NIX_MAXIMUM_OBJECT_BYTES_V2
    {
        return Err(NixStoreProjectionErrorV2::Bound);
    }
    Ok(next_bytes)
}

/// Projects names from portable recipe DATA without admitting its authority.
///
/// This is comparison DATA, not an opener or store admission. The same Core
/// Tree/Directory decoders enumerate original records. Recipe signature and
/// graph validation remain the caller's separate prerequisite; this projection
/// cannot stand in for them. Source custody and its allocation/error order stay
/// with the physical input owner.
///
/// # Errors
///
/// Rejects excessive count/bytes/depth/path lengths, unsupported layouts,
/// conflicting names, invalid Directory DATA, and allocation failures.
pub fn project_store_members_v2(
    recipe: &NixPreadmittedRecipeV2,
) -> Result<Vec<NixStoreMemberV2>, NixStoreProjectionErrorV2> {
    project_store_objects_v2(
        std::iter::once(&recipe.derivation).chain(&recipe.inputs),
        0,
        0,
    )
}

/// Projects selected predicted outputs through the same portable engine.
///
/// # Errors
///
/// Rejects empty outputs or any input/output union exceeding the same member
/// and byte bounds, invalid layouts, conflicting names, or allocation failures.
pub fn project_store_output_members_v2<'input>(
    recipe: &NixPreadmittedRecipeV2,
    mut inputs: impl Iterator<Item = &'input NixStoreMemberV2>,
) -> Result<Vec<NixStoreMemberV2>, NixStoreProjectionErrorV2> {
    if recipe.outputs.is_empty() {
        return Err(NixStoreProjectionErrorV2::Bound);
    }
    // Borrow the already-retained input graph rather than reconstructing a
    // second full union. Every output insertion shares its remaining count
    // and Content-byte headroom with those actual original input members.
    let (count, bytes) = inputs.try_fold((0_usize, 0_u64), |(count, bytes), member| {
        let content_bytes = match &member.kind {
            NixStoreMemberKindV2::Content { descriptor, .. } => descriptor.encoded_size(),
            _ => 0,
        };
        let bytes = checked_store_projection_growth_v2(count, bytes, content_bytes)?;
        Ok::<_, NixStoreProjectionErrorV2>((count + 1, bytes))
    })?;
    project_store_objects_v2(
        recipe.outputs.iter().map(|output| &output.object),
        count,
        bytes,
    )
}

fn project_store_objects_v2<'object>(
    objects: impl Iterator<Item = &'object NixStoreObjectV2>,
    retained_members: usize,
    retained_bytes: u64,
) -> Result<Vec<NixStoreMemberV2>, NixStoreProjectionErrorV2> {
    let mut members = Vec::new();
    let mut total_bytes = retained_bytes;
    for (object_index, object) in objects.enumerate() {
        let name = object
            .path
            .strip_prefix('/')
            .ok_or(NixStoreProjectionErrorV2::Changed)?;
        if object.portable.media_type().as_str() == PortableMediaType::Content.as_str() {
            push_store_member(
                &mut members,
                &mut total_bytes,
                retained_members,
                name,
                NixStoreMemberKindV2::Content {
                    descriptor: object.portable.clone(),
                    metadata: None,
                    hardlink: None,
                },
            )?;
        } else {
            let tree = object
                .portable_objects
                .iter()
                .find(|record| record.descriptor == object.portable)
                .ok_or(NixStoreProjectionErrorV2::Conflict)?;
            let tree = aos_sandbox_core::format::decode_tree(&tree.bytes, DecodeLimits::default())?;
            project_store_directory(
                object,
                object_index,
                tree.root(),
                name,
                0,
                &mut members,
                &mut total_bytes,
                retained_members,
            )?;
        }
    }
    members.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    if !members.windows(2).all(|pair| pair[0].name < pair[1].name) {
        return Err(NixStoreProjectionErrorV2::Conflict);
    }
    Ok(members)
}

/// Describes one bounded portable store member as comparison DATA.
pub struct NixStoreMemberV2 {
    /// Carries its exact relative store-member name.
    pub name: String,
    /// Carries the portable member kind and original metadata.
    pub kind: NixStoreMemberKindV2,
}

/// Describes portable Content, Directory, or Symlink DATA without store authority.
pub enum NixStoreMemberKindV2 {
    /// Describes one Whole Content member and its original metadata.
    Content {
        /// Carries the exact portable Content descriptor.
        descriptor: ObjectDescriptor,
        /// Carries Tree metadata, absent for a top-level Content object.
        metadata: Option<aos_sandbox_core::model::FilesystemMetadata>,
        /// Scopes a hardlink label to its original admitted Tree index.
        hardlink: Option<(usize, aos_sandbox_core::ObjectDigest)>,
    },
    /// Carries the original Directory metadata.
    Directory(aos_sandbox_core::model::FilesystemMetadata),
    /// Carries the original Symlink metadata and target DATA.
    Symlink(aos_sandbox_core::model::SymlinkNode),
}

fn push_store_member(
    members: &mut Vec<NixStoreMemberV2>,
    total_bytes: &mut u64,
    retained_members: usize,
    name: &str,
    kind: NixStoreMemberKindV2,
) -> Result<(), NixStoreProjectionErrorV2> {
    let bytes = match &kind {
        NixStoreMemberKindV2::Content { descriptor, .. } => descriptor.encoded_size(),
        _ => 0,
    };
    let count = retained_members
        .checked_add(members.len())
        .ok_or(NixStoreProjectionErrorV2::Bound)?;
    let next = checked_store_projection_growth_v2(count, *total_bytes, bytes)?;
    if name.is_empty() || name.len() > 4_096 {
        return Err(NixStoreProjectionErrorV2::Bound);
    }
    members.try_reserve_exact(1)?;
    let mut retained_name = String::new();
    retained_name.try_reserve_exact(name.len())?;
    retained_name.push_str(name);
    members.push(NixStoreMemberV2 {
        name: retained_name,
        kind,
    });
    *total_bytes = next;
    Ok(())
}

fn project_store_directory(
    object: &NixStoreObjectV2,
    object_index: usize,
    descriptor: &ObjectDescriptor,
    name: &str,
    depth: usize,
    members: &mut Vec<NixStoreMemberV2>,
    total_bytes: &mut u64,
    retained_members: usize,
) -> Result<(), NixStoreProjectionErrorV2> {
    if depth >= 64 {
        return Err(NixStoreProjectionErrorV2::Bound);
    }
    let record = object
        .portable_objects
        .iter()
        .find(|record| &record.descriptor == descriptor)
        .ok_or(NixStoreProjectionErrorV2::Conflict)?;
    let mut stream = StreamingDirectory::new(&record.bytes, DecodeLimits::default())?;
    push_store_member(
        members,
        total_bytes,
        retained_members,
        name,
        NixStoreMemberKindV2::Directory(stream.metadata().clone()),
    )?;

    while let Some(entry) = stream.next_entry()? {
        let leaf = std::str::from_utf8(entry.name.as_bytes())
            .map_err(|_| NixStoreProjectionErrorV2::UnsupportedLayout)?;
        let length = name
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(leaf.len()))
            .ok_or(NixStoreProjectionErrorV2::Bound)?;
        if length > 4_096 {
            return Err(NixStoreProjectionErrorV2::Bound);
        }
        let mut child = String::new();
        child.try_reserve_exact(length)?;
        child.push_str(name);
        child.push('/');
        child.push_str(leaf);
        match entry.node {
            Node::Directory(descriptor) => project_store_directory(
                object,
                object_index,
                &descriptor,
                &child,
                depth + 1,
                members,
                total_bytes,
                retained_members,
            )?,
            Node::File(file) => {
                let ContentLayout::Whole { content } = file.content else {
                    return Err(NixStoreProjectionErrorV2::UnsupportedLayout);
                };
                push_store_member(
                    members,
                    total_bytes,
                    retained_members,
                    &child,
                    NixStoreMemberKindV2::Content {
                        descriptor: content,
                        metadata: Some(file.metadata),
                        hardlink: file.hardlink_group.map(|group| (object_index, group)),
                    },
                )?;
            }
            Node::Symlink(link) => push_store_member(
                members,
                total_bytes,
                retained_members,
                &child,
                NixStoreMemberKindV2::Symlink(link),
            )?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{MediaType, ObjectDigest, descriptor_for_bytes};

    use super::*;

    fn content_object() -> NixStoreObjectV2 {
        NixStoreObjectV2 {
            path: format!("/nix/store/{}-input", "0".repeat(32)),
            portable: descriptor_for_bytes(
                MediaType::new(PortableMediaType::Content.as_str()).unwrap(),
                b"original",
            ),
            nar_sha256: ObjectDigest::from_bytes([3; 32]),
            nar_size: 64,
            references: Vec::new(),
            portable_objects: Vec::new(),
        }
    }

    #[test]
    fn portable_content_keeps_its_exact_descriptor_and_relative_name() {
        let object = content_object();

        let members = project_store_objects_v2(std::iter::once(&object), 0, 0).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, object.path.strip_prefix('/').unwrap());
        assert!(matches!(&members[0].kind,
            NixStoreMemberKindV2::Content { descriptor, metadata: None, hardlink: None }
            if descriptor == &object.portable));
    }

    #[test]
    fn a_duplicate_member_name_remains_a_conflict() {
        let object = content_object();

        let members = project_store_objects_v2([&object, &object].into_iter(), 0, 0);

        assert!(matches!(members, Err(NixStoreProjectionErrorV2::Conflict)));
    }

    #[test]
    fn retained_input_headroom_constrains_the_same_output_engine() {
        let object = content_object();

        let members = project_store_objects_v2(
            std::iter::once(&object),
            super::super::NIX_MAXIMUM_OBJECTS_V2,
            0,
        );

        assert!(matches!(members, Err(NixStoreProjectionErrorV2::Bound)));
    }

    #[test]
    fn growth_rejects_overflow_before_any_member_allocation() {
        for (count, bytes, size) in [(usize::MAX, 0, 0), (0, u64::MAX, 1)] {
            assert!(matches!(
                checked_store_projection_growth_v2(count, bytes, size),
                Err(NixStoreProjectionErrorV2::Bound)
            ));
        }
    }
}
