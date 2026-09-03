//! Portable filesystem tree, directory, and delta values.
//!
//! The wire schema is defined by `portable-v1.cddl`. Constructors enforce
//! local invariants such as portable metadata, deterministic directory order,
//! normalized sparse extents, and byte-preserving symlink targets. Graph-wide
//! reachability, cycle, hard-link membership, and feature-closure checks are
//! performed by the bounded object-graph validator built on these values.

use serde::{Deserialize, Serialize};

use crate::{FeatureRef, ObjectDescriptor, ObjectDigest, PathName};

const MAX_XATTR_NAME_BYTES: usize = 255;
const MAX_XATTR_VALUE_BYTES: usize = 1_048_576;
const MAX_SYMLINK_BYTES: usize = 4_096;

/// Reports a locally invalid portable tree value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidTreeModel {
    /// Metadata contains bits outside the portable low twelve mode bits.
    #[error("portable mode contains bits outside the low twelve bits")]
    InvalidMode,
    /// A timestamp contains a nanosecond value outside one second.
    #[error("timestamp nanoseconds must be less than one billion")]
    InvalidNanoseconds,
    /// An extended attribute name or value exceeds its decoder ceiling.
    #[error("extended attribute exceeds its portable decoder ceiling")]
    XattrTooLarge,
    /// Extended attributes are not strictly ordered by byte name.
    #[error("extended attributes must be strictly ordered by byte name")]
    XattrsNotCanonical,
    /// An ACL contains an invalid qualifier or permission bitmap.
    #[error("ACL entry has an invalid qualifier or permission bitmap")]
    InvalidAclEntry,
    /// An ACL repeats a tag and qualifier identity.
    #[error("ACL entries must be unique")]
    DuplicateAclEntry,
    /// Directory entries are not strictly ordered by byte name.
    #[error("directory entries must be strictly ordered by byte name")]
    DirectoryNotCanonical,
    /// A symlink target is too large or contains NUL.
    #[error("symlink target must be at most 4096 bytes and exclude NUL")]
    InvalidSymlinkTarget,
    /// Sparse content uses an invalid extent range or ordering.
    #[error("sparse extents must be nonempty, non-touching, ordered, and within logical size")]
    InvalidSparseExtent,
    /// A descriptor size does not match the represented logical byte range.
    #[error("content descriptor size does not match the represented logical size")]
    ContentSizeMismatch,
    /// A full-range sparse extent must use the whole-content representation.
    #[error("a full-range extent is not a canonical sparse representation")]
    FullRangeSparseExtent,
    /// A set-valued collection is not strictly ordered or has duplicates.
    #[error("set-valued collection must be strictly ordered and unique")]
    SetNotCanonical,
}

/// Stores one byte-exact portable extended attribute.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "XattrWire")]
pub struct Xattr {
    name: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XattrWire {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl TryFrom<XattrWire> for Xattr {
    type Error = InvalidTreeModel;

    fn try_from(value: XattrWire) -> Result<Self, Self::Error> {
        Self::new(value.name, value.value)
    }
}

impl Xattr {
    /// Constructs a bounded extended attribute.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTreeModel::XattrTooLarge`] for an empty or oversized
    /// name, a name containing NUL, or an oversized value.
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Result<Self, InvalidTreeModel> {
        if name.is_empty()
            || name.len() > MAX_XATTR_NAME_BYTES
            || name.contains(&0)
            || value.len() > MAX_XATTR_VALUE_BYTES
        {
            return Err(InvalidTreeModel::XattrTooLarge);
        }
        Ok(Self { name, value })
    }

    /// Returns the uninterpreted attribute name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the uninterpreted attribute value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Stores one closed POSIX ACL entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case", tag = "tag", content = "entry")]
pub enum AclEntry {
    /// Carries the owning user's permission bitmap.
    UserObject(u8),
    /// Carries one named user's ID and permission bitmap.
    NamedUser { uid: u32, permissions: u8 },
    /// Carries the owning group's permission bitmap.
    GroupObject(u8),
    /// Carries one named group's ID and permission bitmap.
    NamedGroup { gid: u32, permissions: u8 },
    /// Carries the effective named-user/group mask.
    Mask(u8),
    /// Carries the other-user permission bitmap.
    Other(u8),
}

impl AclEntry {
    /// Validates that the permission bitmap contains only read/write/execute.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTreeModel::InvalidAclEntry`] for a bitmap above seven.
    pub fn validate(self) -> Result<Self, InvalidTreeModel> {
        let permissions = match self {
            Self::UserObject(value)
            | Self::GroupObject(value)
            | Self::Mask(value)
            | Self::Other(value) => value,
            Self::NamedUser { permissions, .. } | Self::NamedGroup { permissions, .. } => {
                permissions
            }
        };
        if permissions <= 0b111 {
            Ok(self)
        } else {
            Err(InvalidTreeModel::InvalidAclEntry)
        }
    }

    const fn identity(self) -> (u8, Option<u32>) {
        match self {
            Self::UserObject(_) => (0, None),
            Self::NamedUser { uid, .. } => (1, Some(uid)),
            Self::GroupObject(_) => (2, None),
            Self::NamedGroup { gid, .. } => (3, Some(gid)),
            Self::Mask(_) => (4, None),
            Self::Other(_) => (5, None),
        }
    }
}

/// Stores a unique, sorted portable POSIX ACL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Acl(Vec<AclEntry>);

impl Acl {
    /// Constructs an ACL from entries in canonical typed order.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid bitmap, duplicate identity, or
    /// non-increasing entry order.
    pub fn new(entries: Vec<AclEntry>) -> Result<Self, InvalidTreeModel> {
        let mut previous = None;
        for entry in &entries {
            entry.validate()?;
            let identity = entry.identity();
            if previous.is_some_and(|value| value >= identity) {
                return Err(if previous == Some(identity) {
                    InvalidTreeModel::DuplicateAclEntry
                } else {
                    InvalidTreeModel::SetNotCanonical
                });
            }
            previous = Some(identity);
        }
        Ok(Self(entries))
    }

    /// Returns the canonical ACL entries.
    #[must_use]
    pub fn entries(&self) -> &[AclEntry] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Acl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(Vec::<AclEntry>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Stores portable file or directory metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemMetadata {
    mode: u16,
    uid: u32,
    gid: u32,
    mtime_seconds: i64,
    mtime_nanos: u32,
    xattrs: Vec<Xattr>,
    acl: Option<Acl>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataWire {
    mode: u16,
    uid: u32,
    gid: u32,
    mtime_seconds: i64,
    mtime_nanos: u32,
    xattrs: Vec<Xattr>,
    acl: Option<Acl>,
}

impl<'de> Deserialize<'de> for FilesystemMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MetadataWire::deserialize(deserializer)?;
        Self::new(
            wire.mode,
            wire.uid,
            wire.gid,
            wire.mtime_seconds,
            wire.mtime_nanos,
            wire.xattrs,
            wire.acl,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl FilesystemMetadata {
    /// Constructs validated portable metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for high mode bits, invalid nanoseconds, or xattrs
    /// that are not strictly byte-name ordered.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: u16,
        uid: u32,
        gid: u32,
        mtime_seconds: i64,
        mtime_nanos: u32,
        xattrs: Vec<Xattr>,
        acl: Option<Acl>,
    ) -> Result<Self, InvalidTreeModel> {
        if mode > 0o7777 {
            return Err(InvalidTreeModel::InvalidMode);
        }
        if mtime_nanos >= 1_000_000_000 {
            return Err(InvalidTreeModel::InvalidNanoseconds);
        }
        if !strictly_increasing_by(&xattrs, |item| item.name()) {
            return Err(InvalidTreeModel::XattrsNotCanonical);
        }
        Ok(Self {
            mode,
            uid,
            gid,
            mtime_seconds,
            mtime_nanos,
            xattrs,
            acl,
        })
    }

    /// Returns the portable permission and special bits.
    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }

    /// Returns the guest-visible owner ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the guest-visible group ID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the normalized Unix modification-time seconds.
    #[must_use]
    pub const fn mtime_seconds(&self) -> i64 {
        self.mtime_seconds
    }

    /// Returns the normalized modification-time nanoseconds.
    #[must_use]
    pub const fn mtime_nanos(&self) -> u32 {
        self.mtime_nanos
    }

    /// Returns the canonical extended attributes.
    #[must_use]
    pub fn xattrs(&self) -> &[Xattr] {
        &self.xattrs
    }

    /// Returns the optional canonical POSIX ACL.
    #[must_use]
    pub const fn acl(&self) -> Option<&Acl> {
        self.acl.as_ref()
    }
}

/// Stores one immutable whole-file or normalized sparse content layout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ContentLayout {
    /// Stores all logical bytes in one raw-content object.
    Whole {
        /// Descriptor whose encoded size is the logical file size.
        content: ObjectDescriptor,
    },
    /// Stores maximal non-hole extents and leaves holes implicit.
    Sparse(SparseContent),
}

impl ContentLayout {
    /// Constructs a whole-file content layout.
    #[must_use]
    pub const fn whole(content: ObjectDescriptor) -> Self {
        Self::Whole { content }
    }

    /// Returns the logical size committed by the layout.
    #[must_use]
    pub fn logical_size(&self) -> u64 {
        match self {
            Self::Whole { content } => content.encoded_size(),
            Self::Sparse(content) => content.logical_size(),
        }
    }
}

/// Stores one maximal non-hole extent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Extent {
    offset: u64,
    length: u64,
    content: ObjectDescriptor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtentWire {
    offset: u64,
    length: u64,
    content: ObjectDescriptor,
}

impl<'de> Deserialize<'de> for Extent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ExtentWire::deserialize(deserializer)?;
        Self::new(wire.offset, wire.length, wire.content).map_err(serde::de::Error::custom)
    }
}

impl Extent {
    /// Constructs one extent with an exact-size content descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when length is zero, the range overflows, or the
    /// descriptor encoded size differs from the extent length.
    pub fn new(
        offset: u64,
        length: u64,
        content: ObjectDescriptor,
    ) -> Result<Self, InvalidTreeModel> {
        if length == 0 || offset.checked_add(length).is_none() {
            return Err(InvalidTreeModel::InvalidSparseExtent);
        }
        if content.encoded_size() != length {
            return Err(InvalidTreeModel::ContentSizeMismatch);
        }
        Ok(Self {
            offset,
            length,
            content,
        })
    }

    /// Returns the logical start offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the positive logical extent length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the exclusive logical end, known not to overflow.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }

    /// Returns the exact content descriptor.
    #[must_use]
    pub const fn content(&self) -> &ObjectDescriptor {
        &self.content
    }
}

/// Stores normalized sparse file content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SparseContent {
    logical_size: u64,
    extents: Vec<Extent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SparseContentWire {
    logical_size: u64,
    extents: Vec<Extent>,
}

impl<'de> Deserialize<'de> for SparseContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SparseContentWire::deserialize(deserializer)?;
        Self::new(wire.logical_size, wire.extents).map_err(serde::de::Error::custom)
    }
}

impl SparseContent {
    /// Constructs a normalized sparse layout.
    ///
    /// # Errors
    ///
    /// Returns an error unless extents are positive, strictly separated,
    /// inside the logical size, and do not encode the entire file as one run.
    pub fn new(logical_size: u64, extents: Vec<Extent>) -> Result<Self, InvalidTreeModel> {
        let mut prior_end = None;
        for extent in &extents {
            if extent.end() > logical_size || prior_end.is_some_and(|end| end >= extent.offset()) {
                return Err(InvalidTreeModel::InvalidSparseExtent);
            }
            prior_end = Some(extent.end());
        }
        if logical_size > 0
            && extents.len() == 1
            && extents[0].offset() == 0
            && extents[0].length() == logical_size
        {
            return Err(InvalidTreeModel::FullRangeSparseExtent);
        }
        Ok(Self {
            logical_size,
            extents,
        })
    }

    /// Returns the logical file size including holes.
    #[must_use]
    pub const fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// Returns the maximal non-hole extents.
    #[must_use]
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }
}

/// Stores a portable regular-file node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileNode {
    /// Portable file metadata.
    pub metadata: FilesystemMetadata,
    /// Exact logical content representation.
    pub content: ContentLayout,
    /// Optional tree-scoped hard-link group digest.
    pub hardlink_group: Option<ObjectDigest>,
}

/// Stores a portable symbolic-link node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymlinkNode {
    metadata: FilesystemMetadata,
    target: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SymlinkWire {
    metadata: FilesystemMetadata,
    target: Vec<u8>,
}

impl<'de> Deserialize<'de> for SymlinkNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SymlinkWire::deserialize(deserializer)?;
        Self::new(wire.metadata, wire.target).map_err(serde::de::Error::custom)
    }
}

impl SymlinkNode {
    /// Constructs a byte-preserving portable symbolic link.
    ///
    /// # Errors
    ///
    /// Returns an error if the target contains NUL or exceeds 4096 bytes.
    pub fn new(metadata: FilesystemMetadata, target: Vec<u8>) -> Result<Self, InvalidTreeModel> {
        if target.len() > MAX_SYMLINK_BYTES || target.contains(&0) {
            return Err(InvalidTreeModel::InvalidSymlinkTarget);
        }
        Ok(Self { metadata, target })
    }

    /// Returns the portable link metadata.
    #[must_use]
    pub const fn metadata(&self) -> &FilesystemMetadata {
        &self.metadata
    }

    /// Returns the uninterpreted symbolic-link target bytes.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.target
    }
}

/// Stores one closed portable filesystem node kind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "node")]
pub enum Node {
    /// A regular file with immutable content.
    File(FileNode),
    /// A directory referenced by its exact descriptor.
    Directory(ObjectDescriptor),
    /// A symbolic link preserving target bytes.
    Symlink(SymlinkNode),
}

/// Stores one name-to-node directory mapping.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    /// Byte-exact entry name.
    pub name: PathName,
    /// Closed portable node value.
    pub node: Node,
}

/// Stores one portable directory object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Directory {
    metadata: FilesystemMetadata,
    entries: Vec<DirectoryEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryWire {
    metadata: FilesystemMetadata,
    entries: Vec<DirectoryEntry>,
}

impl<'de> Deserialize<'de> for Directory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DirectoryWire::deserialize(deserializer)?;
        Self::new(wire.metadata, wire.entries).map_err(serde::de::Error::custom)
    }
}

impl Directory {
    /// Constructs a directory with strictly byte-name ordered entries.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTreeModel::DirectoryNotCanonical`] for duplicate or
    /// non-increasing entry names.
    pub fn new(
        metadata: FilesystemMetadata,
        entries: Vec<DirectoryEntry>,
    ) -> Result<Self, InvalidTreeModel> {
        if !strictly_increasing_by(&entries, |entry| entry.name.as_bytes()) {
            return Err(InvalidTreeModel::DirectoryNotCanonical);
        }
        Ok(Self { metadata, entries })
    }

    /// Returns the directory's own portable metadata.
    #[must_use]
    pub const fn metadata(&self) -> &FilesystemMetadata {
        &self.metadata
    }

    /// Returns the canonical directory entries.
    #[must_use]
    pub fn entries(&self) -> &[DirectoryEntry] {
        &self.entries
    }
}

/// Stores one portable tree root and its required feature closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Tree {
    root: ObjectDescriptor,
    required_features: Vec<FeatureRef>,
}

/// Stores a final-tree delta independent of mutation history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Delta {
    base: ObjectDescriptor,
    result: ObjectDescriptor,
    added_objects: Vec<ObjectDescriptor>,
    required_features: Vec<FeatureRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeWire {
    root: ObjectDescriptor,
    required_features: Vec<FeatureRef>,
}

impl<'de> Deserialize<'de> for Tree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TreeWire::deserialize(deserializer)?;
        Self::new(wire.root, wire.required_features).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaWire {
    base: ObjectDescriptor,
    result: ObjectDescriptor,
    added_objects: Vec<ObjectDescriptor>,
    required_features: Vec<FeatureRef>,
}

impl<'de> Deserialize<'de> for Delta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeltaWire::deserialize(deserializer)?;
        Self::new(
            wire.base,
            wire.result,
            wire.added_objects,
            wire.required_features,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Tree {
    /// Constructs a tree with a unique sorted feature set.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTreeModel::SetNotCanonical`] if required features are
    /// not strictly ordered.
    pub fn new(
        root: ObjectDescriptor,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidTreeModel> {
        validate_set(&required_features)?;
        Ok(Self {
            root,
            required_features,
        })
    }

    /// Returns the root directory descriptor.
    #[must_use]
    pub const fn root(&self) -> &ObjectDescriptor {
        &self.root
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

impl Delta {
    /// Constructs a final-tree delta with canonical set-valued collections.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTreeModel::SetNotCanonical`] for an unordered or
    /// duplicate descriptor or feature set.
    pub fn new(
        base: ObjectDescriptor,
        result: ObjectDescriptor,
        added_objects: Vec<ObjectDescriptor>,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidTreeModel> {
        validate_set(&added_objects)?;
        validate_set(&required_features)?;
        Ok(Self {
            base,
            result,
            added_objects,
            required_features,
        })
    }
}

fn validate_set<T: Ord>(values: &[T]) -> Result<(), InvalidTreeModel> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(InvalidTreeModel::SetNotCanonical)
    }
}

fn strictly_increasing_by<T, K: Ord + ?Sized>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediaType, ObjectDigest};

    fn descriptor(size: u64) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([7; 32]),
            size,
        )
    }

    fn metadata() -> FilesystemMetadata {
        FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
            .unwrap_or_else(|error| panic!("test metadata failed: {error}"))
    }

    #[test]
    fn sparse_extents_must_be_separated() {
        let left = Extent::new(0, 4, descriptor(4))
            .unwrap_or_else(|error| panic!("test extent failed: {error}"));
        let right = Extent::new(4, 2, descriptor(2))
            .unwrap_or_else(|error| panic!("test extent failed: {error}"));

        assert_eq!(
            SparseContent::new(8, vec![left, right]),
            Err(InvalidTreeModel::InvalidSparseExtent)
        );
    }

    #[test]
    fn all_hole_nonempty_file_is_canonical() {
        let sparse = SparseContent::new(4096, Vec::new())
            .unwrap_or_else(|error| panic!("test sparse layout failed: {error}"));

        assert_eq!(sparse.logical_size(), 4096);
        assert!(sparse.extents().is_empty());
    }

    #[test]
    fn directory_rejects_duplicate_byte_names() {
        let name = PathName::new(b"same".to_vec())
            .unwrap_or_else(|error| panic!("test name failed: {error}"));
        let entries = vec![
            DirectoryEntry {
                name: name.clone(),
                node: Node::Directory(descriptor(1)),
            },
            DirectoryEntry {
                name,
                node: Node::Directory(descriptor(1)),
            },
        ];

        assert_eq!(
            Directory::new(metadata(), entries),
            Err(InvalidTreeModel::DirectoryNotCanonical)
        );
    }

    #[test]
    fn symlink_preserves_non_utf8_bytes() {
        let node = SymlinkNode::new(metadata(), vec![0xff, b'/', b'x'])
            .unwrap_or_else(|error| panic!("test symlink failed: {error}"));

        assert_eq!(node.target(), &[0xff, b'/', b'x']);
    }

    #[test]
    fn acl_rejects_duplicate_qualifiers() {
        let entries = vec![
            AclEntry::NamedUser {
                uid: 1000,
                permissions: 4,
            },
            AclEntry::NamedUser {
                uid: 1000,
                permissions: 7,
            },
        ];

        assert!(Acl::new(entries).is_err());
    }

    #[test]
    fn xattrs_require_bytewise_order() {
        let attributes = vec![
            Xattr::new(b"user.z".to_vec(), Vec::new())
                .unwrap_or_else(|error| panic!("test xattr failed: {error}")),
            Xattr::new(b"user.a".to_vec(), Vec::new())
                .unwrap_or_else(|error| panic!("test xattr failed: {error}")),
        ];

        assert_eq!(
            FilesystemMetadata::new(0, 0, 0, 0, 0, attributes, None),
            Err(InvalidTreeModel::XattrsNotCanonical)
        );
    }

    #[test]
    fn sets_reject_duplicates() {
        let feature = FeatureRef::new("aos.test", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));

        assert_eq!(
            Tree::new(descriptor(1), vec![feature.clone(), feature]),
            Err(InvalidTreeModel::SetNotCanonical)
        );
    }
}
