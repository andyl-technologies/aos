//! Borrowed content membership in a visible projected regular file.
//!
//! Source retention includes hidden files and structural objects. This narrower
//! proof joins one actual projected mapping to its authenticated file layout;
//! it establishes neither current consumer authority nor backing-FD custody.

use aos_sandbox_core::model::CacheDomain;
use aos_sandbox_core::{ObjectDescriptor, Revision, ViewId};

use super::{ProjectedNode, ProjectionError, ValidatedViewProjection};
use crate::{IndexContentView, IndexError, IndexNodeBodyView, IndexObjectDescriptorView};

/// Borrows an exact content object from one visible projected regular file.
///
/// Only an authenticated projection and its retained index can construct this
/// value. It identifies the first matching whole-file or sparse-extent range;
/// repeated references to an object need not be unique. It does not authorize
/// a consumer, establish current View or attachment state, acquire a Cache pin,
/// admit a physical descriptor, or prove a live worker or FUSE connection.
pub struct ValidatedViewProjectedFileObject<'projection, 'index, 'bytes> {
    projection: &'projection ValidatedViewProjection<'index, 'bytes>,
    projected: &'projection ProjectedNode,
    object: IndexObjectDescriptorView<'index>,
    logical_offset: u64,
    logical_size: u64,
}

impl<'projection, 'index, 'bytes> ValidatedViewProjectedFileObject<'projection, 'index, 'bytes> {
    /// Returns the exact projected mapping authenticated by this proof.
    #[must_use]
    pub const fn projected(&self) -> &ProjectedNode {
        self.projected
    }

    /// Returns the exact descriptor borrowed from the authenticated file layout.
    #[must_use]
    pub const fn object(&self) -> IndexObjectDescriptorView<'index> {
        self.object
    }

    /// Returns the first matching content range's logical start offset.
    #[must_use]
    pub const fn logical_offset(&self) -> u64 {
        self.logical_offset
    }

    /// Returns the matching content range's exact stored byte length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.object.encoded_size()
    }

    /// Returns the complete logical file size, including sparse holes.
    #[must_use]
    pub const fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// Returns the exact View descriptor that produced this mapping.
    #[must_use]
    pub const fn view_descriptor(&self) -> &ObjectDescriptor {
        self.projection.view_descriptor()
    }

    /// Returns the logical View identity and revision bound by the projection.
    #[must_use]
    pub const fn view_identity(&self) -> (ViewId, Revision) {
        self.projection.view_identity()
    }

    /// Returns the disclosure domain declared by the authenticated View.
    #[must_use]
    pub const fn disclosure(&self) -> CacheDomain {
        self.projection.view().disclosure()
    }
}

impl<'index, 'bytes> ValidatedViewProjection<'index, 'bytes> {
    /// Proves exact object membership in one visible projected regular file.
    ///
    /// The supplied mapping must resolve exactly in this projection. Hidden
    /// source dependencies, directories, symlinks, synthetic parents, sparse
    /// holes, and descriptors differing in media type, digest, or size cannot
    /// produce this proof. No whole-source scan or allocation is performed.
    /// Empty whole-file objects remain structural members, not authority for
    /// any read or descriptor handoff.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::UnresolvedPath`] for a foreign or stale
    /// projected mapping, or [`ProjectionError::Index`] if retained index
    /// semantics fail authentication or a checked extent invariant fails.
    pub fn prove_projected_file_object<'projection>(
        &'projection self,
        projected: &'projection ProjectedNode,
        object: &ObjectDescriptor,
    ) -> Result<
        Option<ValidatedViewProjectedFileObject<'projection, 'index, 'bytes>>,
        ProjectionError,
    > {
        let Some(source) = self.source_node(projected)? else {
            return Ok(None);
        };
        let index = self.index;
        let IndexNodeBodyView::File(file) = index.record_semantics(&source)?.body() else {
            return Ok(None);
        };

        let logical_size = file.logical_size();
        let matching = match file.content() {
            IndexContentView::Whole { content } => content.matches(object).then_some((content, 0)),
            IndexContentView::Sparse(sparse) => {
                let mut matching = None;
                for extent in sparse.extents() {
                    let extent = extent?;
                    let content = extent.content();
                    let end = extent
                        .offset()
                        .checked_add(extent.length())
                        .ok_or(IndexError::InvalidRecord)?;
                    if extent.length() == 0
                        || extent.length() != content.encoded_size()
                        || end > logical_size
                    {
                        return Err(IndexError::InvalidRecord.into());
                    }
                    if content.matches(object) {
                        matching = Some((content, extent.offset()));
                        break;
                    }
                }
                matching
            }
        };
        let Some((object, logical_offset)) = matching else {
            return Ok(None);
        };

        Ok(Some(ValidatedViewProjectedFileObject {
            projection: self,
            projected,
            object,
            logical_offset,
            logical_size,
        }))
    }
}

#[cfg(test)]
mod tests;
