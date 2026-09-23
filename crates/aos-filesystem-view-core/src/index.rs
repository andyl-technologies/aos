//! Architecture-neutral structural-index staging and validation.
//!
//! Format v1 is a little-endian derived cache with fixed-width point-lookup
//! and canonical directory tables:
//!
//! ```text
//! header = magic[8], version:u32, header-bytes:u32, compiler-abi[32],
//!          tree-digest[32], tree-size:u64, root-digest[32], root-size:u64,
//!          tree-features:u32, reserved:u32, record-count:u64,
//!          payload-bytes:u64, payload-sha256[32]
//! header-tail = records-bytes:u64, lookup-slots:u64, lookup-slot-bytes:u32,
//!               lookup-hash:u32, reserved:u64, directory-slots:u64,
//!               directory-slot-bytes:u32, reserved:u32, root-nlink:u64,
//!               reserved:u64
//! payload = record*, lookup-entry*, directory-entry*
//! lookup-entry = parent:u64, name-sha256[32], record-offset:u64, record-id:u64
//! directory-entry = parent:u64, record-offset:u64, record-id:u64, nlink:u64
//! record = record-bytes:u32, parent:u64, depth:u32, sibling-ordinal:u32,
//!          kind:u8, reserved[3],
//!          mode:u16, reserved:u16, uid:u32, gid:u32, mtime-sec:i64,
//!          mtime-nsec:u32, body...
//! ```
//!
//! Lookup entries are sorted canonically by parent, full domain-separated name
//! digest, and record ID. All variable fields are length-prefixed and the
//! validator rejects unknown tags, nonzero reserved bytes, non-canonical
//! tables, overflow, truncation, and trailing data.
//!
//! Builder working-byte limits account for fallible heap allocations. Header
//! encoding instead uses one fixed 248-byte stack object, which is part of the
//! compiler's constant stack budget and never scales with hostile input.
//! Structural ranges, point lookup, exact link counts, and allocation-free
//! borrowed semantic views are mandatory. FUSE cookie translation,
//! READDIRPLUS policy, and checked `u64`-to-`u32` protocol conversion belong to
//! later worker-facing increments.

use std::io::{Seek, SeekFrom, Write};

use aos_sandbox_core::model::{
    Acl, AclEntry, ContentLayout, Extent, FilesystemMetadata, SparseContent, Xattr,
};
use aos_sandbox_core::{
    DescriptorRole, InvalidPathName, MediaType, ObjectDescriptor, ObjectDigest, PathName,
    RelativePath, descriptor_for_bytes, hardlink_group_digest, validate_descriptor_role,
};
use sha2::{Digest, Sha256};

mod builder;
mod semantic;
mod validate;
mod view;
mod wire;

pub use builder::{IndexNode, IndexRecord, IndexStaging, StagedIndex};
pub use semantic::{
    IndexAclEntries, IndexAclRange, IndexContentView, IndexExtentRange, IndexExtentView,
    IndexExtents, IndexFileView, IndexNodeBodyView, IndexNodeSemantics, IndexObjectDescriptorView,
    IndexSparseContentView, IndexXattrRange, IndexXattrView, IndexXattrs,
};
pub use validate::{IndexCrosslinks, IndexError, IndexExpectation, validate_index};
pub use view::{
    DirectoryEntries, DirectoryEntryView, DirectoryRange, IndexNodeKind, IndexNodeView,
    IndexRecords, IndexSummary, ValidatedIndex,
};
pub use wire::INDEX_MEDIA_TYPE;

#[cfg(feature = "test-fixtures")]
pub use builder::StructuralIndexBuilder;
#[cfg(not(feature = "test-fixtures"))]
pub(crate) use builder::StructuralIndexBuilder;
#[allow(unused_imports)]
pub(crate) use builder::{FinishIndexResult, PushIndexResult};
pub(crate) use wire::{
    FEATURE_ABSOLUTE_SYMLINK, FEATURE_ACL, FEATURE_PARENT_SYMLINK, byte_vector_charge,
    record_encoded_len,
};

#[cfg(test)]
mod tests;
