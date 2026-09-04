//! Exact UID, GID, and POSIX ACL presentation translation.

use std::iter::FusedIterator;

use aos_sandbox_core::model::{Acl, AclEntry, FilesystemMetadata, Xattr};
use sha2::{Digest, Sha256};

use crate::{
    IndexAclEntries, IndexAclRange, IndexError, IndexNodeBodyView, IndexNodeKind, IndexNodeView,
    IndexXattrRange, ValidatedIndex,
};

/// Describes whether the target connection proved POSIX ACL conformance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclCapability {
    /// ACL metadata must be absent.
    Unsupported,
    /// Canonical ACL metadata may be translated and presented.
    Posix,
}

/// Maps one contiguous portable-ID range into a presentation range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdMapExtent {
    /// First portable ID.
    pub portable_start: u32,
    /// First ID interpreted by the FUSE connection.
    pub presented_start: u32,
    /// Positive number of IDs in the extent.
    pub length: u32,
}

/// Stores exact UID and GID maps for one presentation connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityMap {
    uid: Vec<IdMapExtent>,
    gid: Vec<IdMapExtent>,
}

/// Reports an invalid map or an identity that cannot be represented exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentityMapError {
    /// An extent is empty or either endpoint range overflows `u32`.
    #[error("identity-map extent is empty or overflows")]
    InvalidExtent,
    /// Portable ranges are not strictly ordered or presented ranges overlap.
    #[error("identity-map portable ranges are unordered or presented ranges overlap")]
    NonCanonicalMap,
    /// A portable owner or ACL qualifier has no exact mapping.
    #[error("portable identity has no exact presentation mapping")]
    UnmappedIdentity,
    /// ACL metadata is present without a proven ACL capability.
    #[error("POSIX ACL metadata is unsupported by this presentation")]
    AclUnsupported,
    /// Translated ACL construction failed.
    #[error("translated POSIX ACL is invalid")]
    InvalidAcl,
    /// ACL translation exceeds the caller's admitted entry ceiling.
    #[error("translated POSIX ACL exceeds its admitted entry ceiling")]
    AclLimitExceeded,
    /// The admitted ACL output allocation was refused.
    #[error("translated POSIX ACL allocation was refused")]
    AllocationRefused,
}

impl IdentityMap {
    /// Constructs canonical, injective UID and GID maps.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityMapError`] for empty or overflowing extents, portable
    /// ranges that are not strictly ordered, or presented ranges that overlap.
    /// Presented ranges may otherwise appear in any order.
    pub fn new(
        mut uid: Vec<IdMapExtent>,
        mut gid: Vec<IdMapExtent>,
    ) -> Result<Self, IdentityMapError> {
        validate_extents(&mut uid)?;
        validate_extents(&mut gid)?;
        Ok(Self { uid, gid })
    }

    /// Returns canonical UID extents.
    #[must_use]
    pub fn uid_extents(&self) -> &[IdMapExtent] {
        &self.uid
    }

    /// Returns canonical GID extents.
    #[must_use]
    pub fn gid_extents(&self) -> &[IdMapExtent] {
        &self.gid
    }

    /// Translates one portable UID without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityMapError::UnmappedIdentity`] when no UID extent covers
    /// `value`.
    pub fn translate_uid(&self, value: u32) -> Result<u32, IdentityMapError> {
        translate(&self.uid, value)
    }

    /// Translates one portable GID without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityMapError::UnmappedIdentity`] when no GID extent covers
    /// `value`.
    pub fn translate_gid(&self, value: u32) -> Result<u32, IdentityMapError> {
        translate(&self.gid, value)
    }
}

/// Binds an exact identity map to the target ACL capability profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationPlan {
    identity: IdentityMap,
    acl: AclCapability,
    digest: [u8; 32],
}

/// Bounds admission work for one prepared presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentationLimits {
    /// Maximum authenticated index records scanned before readiness.
    pub maximum_records: u64,
    /// Maximum aggregate ACL entries scanned before readiness.
    pub maximum_acl_entries: u64,
    /// Maximum aggregate retained UID and GID map capacity.
    pub maximum_identity_extents: usize,
}

impl PresentationLimits {
    /// Constructs explicit hard limits for presentation admission.
    #[must_use]
    pub const fn new(
        maximum_records: u64,
        maximum_acl_entries: u64,
        maximum_identity_extents: usize,
    ) -> Self {
        Self {
            maximum_records,
            maximum_acl_entries,
            maximum_identity_extents,
        }
    }
}

/// Reports failure to prepare or use exact worker-facing presentation state.
#[derive(Debug, thiserror::Error)]
pub enum PresentationError {
    /// Exact link counts are unavailable before structural-index V3.
    #[error("prepared presentation requires structural-index V3")]
    VersionUnsupported,
    /// Admission exceeded a caller-controlled record, ACL, or map ceiling.
    #[error("presentation exceeds its admitted {0} ceiling")]
    LimitExceeded(&'static str),
    /// A portable link count cannot be represented by the target FUSE ABI.
    #[error("portable link count exceeds the target FUSE ABI")]
    LinkCountOverflow,
    /// UID, GID, or ACL presentation is invalid for this plan.
    #[error("identity presentation failed: {0}")]
    Identity(#[from] IdentityMapError),
    /// The authenticated index could not be decoded or reauthenticated.
    #[error("structural-index presentation failed: {0}")]
    Index(#[from] IndexError),
}

/// Binds prevalidated presentation policy to one exact V3 index.
///
/// Construction scans every record without allocation. The cache identity
/// includes the exact index descriptor, identity/ACL plan, controller
/// generation, and presentation-policy digest. Connection-local proofs such as
/// the user-namespace descriptor, mount flags, and kernel ACL support remain
/// broker state and are deliberately not represented here.
///
/// ```compile_fail
/// use aos_filesystem_view::{PreparedPresentation, PresentedInodeAttributes};
///
/// fn attributes_cannot_escape(
///     prepared: PreparedPresentation<'_, '_, '_>,
/// ) -> PresentedInodeAttributes<'static> {
///     let root = prepared.index().root().unwrap();
///     prepared.present(&root).unwrap()
/// }
/// ```
pub struct PreparedPresentation<'index, 'bytes, 'plan> {
    index: &'index ValidatedIndex<'bytes>,
    plan: &'plan PresentationPlan,
    cache_identity: [u8; 32],
}

impl<'index, 'bytes, 'plan> PreparedPresentation<'index, 'bytes, 'plan> {
    /// Prevalidates every record for allocation-free worker presentation.
    ///
    /// `generation` and `policy_digest` are portable cache-partition inputs,
    /// not proof of any live FUSE connection property.
    ///
    /// # Errors
    ///
    /// Returns [`PresentationError`] for a non-V3 index, exceeded admission
    /// limit, unmapped owner or ACL qualifier, unsupported or reordered ACL,
    /// unrepresentable link count, or authenticated-index inconsistency.
    pub fn prepare(
        index: &'index ValidatedIndex<'bytes>,
        plan: &'plan PresentationPlan,
        generation: u64,
        policy_digest: [u8; 32],
        limits: PresentationLimits,
    ) -> Result<Self, PresentationError> {
        if !index.supports_directory_iteration() {
            return Err(PresentationError::VersionUnsupported);
        }
        if index.summary().records > limits.maximum_records {
            return Err(PresentationError::LimitExceeded("record"));
        }
        let map_extents = plan
            .identity
            .uid
            .capacity()
            .checked_add(plan.identity.gid.capacity())
            .ok_or(PresentationError::LimitExceeded("identity-map extent"))?;
        if map_extents > limits.maximum_identity_extents {
            return Err(PresentationError::LimitExceeded("identity-map extent"));
        }

        let mut acl_entries = 0_u64;
        for node in index.records() {
            let node = node?;
            plan.identity.translate_uid(node.uid())?;
            plan.identity.translate_gid(node.gid())?;
            u32::try_from(index.nlink(&node)?).map_err(|_| PresentationError::LinkCountOverflow)?;

            let semantics = index.record_semantics(&node)?;
            if let Some(acl) = semantics.acl() {
                if plan.acl == AclCapability::Unsupported {
                    return Err(IdentityMapError::AclUnsupported.into());
                }
                acl_entries = acl_entries
                    .checked_add(acl.len() as u64)
                    .ok_or(PresentationError::LimitExceeded("ACL entry"))?;
                if acl_entries > limits.maximum_acl_entries {
                    return Err(PresentationError::LimitExceeded("ACL entry"));
                }
                validate_presented_acl(acl, &plan.identity)?;
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(b"aos-filesystem-prepared-presentation-v1\0");
        let descriptor = index.descriptor();
        hasher.update((descriptor.media_type().as_str().len() as u64).to_be_bytes());
        hasher.update(descriptor.media_type().as_str().as_bytes());
        hasher.update(descriptor.digest().as_bytes());
        hasher.update(descriptor.encoded_size().to_be_bytes());
        hasher.update(plan.digest());
        hasher.update(generation.to_be_bytes());
        hasher.update(policy_digest);

        Ok(Self {
            index,
            plan,
            cache_identity: hasher.finalize().into(),
        })
    }

    /// Returns the exact validated index bound to this preparation.
    #[must_use]
    pub const fn index(&self) -> &'index ValidatedIndex<'bytes> {
        self.index
    }

    /// Returns the exact identity used to partition presentation caches.
    #[must_use]
    pub const fn cache_identity(&self) -> [u8; 32] {
        self.cache_identity
    }

    /// Presents one reauthenticated record without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`PresentationError::Index`] if `node` is foreign, substituted,
    /// or stale. Other errors indicate violation of the preparation invariant.
    pub fn present<'prepared>(
        &'prepared self,
        node: &IndexNodeView<'_>,
    ) -> Result<PresentedInodeAttributes<'prepared>, PresentationError> {
        let node = self.index.authenticate_node(node)?;
        let semantics = self.index.record_semantics(&node)?;
        let size = match semantics.body() {
            IndexNodeBodyView::File(file) => file.logical_size(),
            IndexNodeBodyView::Directory { .. } => 0,
            IndexNodeBodyView::Symlink { target } => target.len() as u64,
        };
        let acl = semantics.acl().map(|source| PresentedAclRange {
            source,
            identity: &self.plan.identity,
        });

        Ok(PresentedInodeAttributes {
            record_id: node.record_id(),
            kind: node.kind(),
            mode: node.mode(),
            uid: self.plan.identity.translate_uid(node.uid())?,
            gid: self.plan.identity.translate_gid(node.gid())?,
            nlink: u32::try_from(self.index.nlink(&node)?)
                .map_err(|_| PresentationError::LinkCountOverflow)?,
            size,
            mtime_seconds: node.mtime_seconds(),
            mtime_nanos: node.mtime_nanos(),
            xattrs: semantics.xattrs(),
            acl,
        })
    }
}

/// Borrows allocation-free attributes for one reauthenticated index record.
pub struct PresentedInodeAttributes<'a> {
    record_id: u64,
    kind: IndexNodeKind,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    mtime_seconds: i64,
    mtime_nanos: u32,
    xattrs: IndexXattrRange<'a>,
    acl: Option<PresentedAclRange<'a>>,
}

impl<'a> PresentedInodeAttributes<'a> {
    /// Returns the artifact-scoped record identifier.
    #[must_use]
    pub const fn record_id(&self) -> u64 {
        self.record_id
    }
    /// Returns the portable node kind.
    #[must_use]
    pub const fn kind(&self) -> IndexNodeKind {
        self.kind
    }
    /// Returns permission and special bits without a file-type encoding.
    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }
    /// Returns the translated owner UID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }
    /// Returns the translated owner GID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }
    /// Returns the target-ABI link count.
    #[must_use]
    pub const fn nlink(&self) -> u32 {
        self.nlink
    }
    /// Returns the logical file size, symlink target length, or zero for directories.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
    /// Returns normalized modification-time seconds.
    #[must_use]
    pub const fn mtime_seconds(&self) -> i64 {
        self.mtime_seconds
    }
    /// Returns normalized modification-time nanoseconds.
    #[must_use]
    pub const fn mtime_nanos(&self) -> u32 {
        self.mtime_nanos
    }
    /// Returns canonical borrowed extended attributes.
    #[must_use]
    pub const fn xattrs(&self) -> IndexXattrRange<'a> {
        self.xattrs
    }
    /// Returns the lazily translated canonical ACL when present.
    #[must_use]
    pub const fn acl(&self) -> Option<PresentedAclRange<'a>> {
        self.acl
    }
}

/// Borrows a canonical ACL whose named qualifiers are translated on iteration.
#[derive(Clone, Copy)]
pub struct PresentedAclRange<'a> {
    source: IndexAclRange<'a>,
    identity: &'a IdentityMap,
}

impl<'a> PresentedAclRange<'a> {
    /// Returns the exact entry count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.source.len()
    }
    /// Reports whether the ACL contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.source.is_empty()
    }
    /// Iterates translated entries without allocating.
    #[must_use]
    pub fn iter(self) -> PresentedAclEntries<'a> {
        PresentedAclEntries {
            source: self.source.iter(),
            identity: self.identity,
        }
    }
}

/// Iterates translated canonical POSIX ACL entries without allocating.
pub struct PresentedAclEntries<'a> {
    source: IndexAclEntries<'a>,
    identity: &'a IdentityMap,
}

impl Iterator for PresentedAclEntries<'_> {
    type Item = Result<AclEntry, PresentationError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.source.next().map(|entry| {
            let entry = entry?;
            Ok(translate_acl_entry(entry, self.identity)?)
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.source.size_hint()
    }
}

impl ExactSizeIterator for PresentedAclEntries<'_> {}
impl FusedIterator for PresentedAclEntries<'_> {}

/// Borrows immutable metadata while owning only translated ACL entries.
#[derive(Clone, Debug)]
pub struct PresentedMetadata<'a> {
    mode: u16,
    uid: u32,
    gid: u32,
    mtime_seconds: i64,
    mtime_nanos: u32,
    xattrs: &'a [Xattr],
    acl: Option<Acl>,
}

impl PresentedMetadata<'_> {
    /// Returns portable permission and special bits.
    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }
    /// Returns the exactly translated owner UID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }
    /// Returns the exactly translated owner GID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }
    /// Returns normalized modification-time seconds.
    #[must_use]
    pub const fn mtime_seconds(&self) -> i64 {
        self.mtime_seconds
    }
    /// Returns normalized modification-time nanoseconds.
    #[must_use]
    pub const fn mtime_nanos(&self) -> u32 {
        self.mtime_nanos
    }
    /// Borrows the source's immutable canonical extended attributes.
    #[must_use]
    pub const fn xattrs(&self) -> &[Xattr] {
        self.xattrs
    }
    /// Returns the translated canonical POSIX ACL.
    #[must_use]
    pub const fn acl(&self) -> Option<&Acl> {
        self.acl.as_ref()
    }
}

impl PresentationPlan {
    /// Constructs a presentation plan and its domain-separated identity.
    #[must_use]
    pub fn new(identity: IdentityMap, acl: AclCapability) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"aos-filesystem-presentation-v1\0");
        hash_extents(&mut hasher, b'u', identity.uid_extents());
        hash_extents(&mut hasher, b'g', identity.gid_extents());
        hasher.update([match acl {
            AclCapability::Unsupported => 0,
            AclCapability::Posix => 1,
        }]);
        Self {
            identity,
            acl,
            digest: hasher.finalize().into(),
        }
    }

    /// Returns the exact plan digest used to partition presentation caches.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Translates owners and every named ACL qualifier exactly.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityMapError`] if an owner or qualifier is unmapped, ACL
    /// support is absent, the ACL exceeds `maximum_acl_entries`, allocation is
    /// refused, or translated metadata cannot be represented.
    pub fn translate_metadata<'a>(
        &self,
        metadata: &'a FilesystemMetadata,
        maximum_acl_entries: usize,
    ) -> Result<PresentedMetadata<'a>, IdentityMapError> {
        let uid = self.identity.translate_uid(metadata.uid())?;
        let gid = self.identity.translate_gid(metadata.gid())?;
        let acl = match metadata.acl() {
            None => None,
            Some(_) if self.acl == AclCapability::Unsupported => {
                return Err(IdentityMapError::AclUnsupported);
            }
            Some(acl) => {
                if acl.entries().len() > maximum_acl_entries {
                    return Err(IdentityMapError::AclLimitExceeded);
                }
                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(acl.entries().len())
                    .map_err(|_| IdentityMapError::AllocationRefused)?;
                for entry in acl.entries() {
                    entries.push(match *entry {
                        AclEntry::NamedUser { uid, permissions } => AclEntry::NamedUser {
                            uid: self.identity.translate_uid(uid)?,
                            permissions,
                        },
                        AclEntry::NamedGroup { gid, permissions } => AclEntry::NamedGroup {
                            gid: self.identity.translate_gid(gid)?,
                            permissions,
                        },
                        other => other,
                    });
                }
                entries.sort_unstable();
                Some(Acl::new(entries).map_err(|_| IdentityMapError::InvalidAcl)?)
            }
        };

        Ok(PresentedMetadata {
            mode: metadata.mode(),
            uid,
            gid,
            mtime_seconds: metadata.mtime_seconds(),
            mtime_nanos: metadata.mtime_nanos(),
            xattrs: metadata.xattrs(),
            acl,
        })
    }
}

fn validate_extents(extents: &mut [IdMapExtent]) -> Result<(), IdentityMapError> {
    let mut portable_end = None;
    for extent in extents.iter() {
        if extent.length == 0 {
            return Err(IdentityMapError::InvalidExtent);
        }
        let portable = extent
            .portable_start
            .checked_add(extent.length - 1)
            .ok_or(IdentityMapError::InvalidExtent)?;
        extent
            .presented_start
            .checked_add(extent.length - 1)
            .ok_or(IdentityMapError::InvalidExtent)?;
        if portable_end.is_some_and(|end| end >= extent.portable_start) {
            return Err(IdentityMapError::NonCanonicalMap);
        }
        portable_end = Some(portable);
    }

    extents.sort_unstable_by_key(|extent| extent.presented_start);
    if extents.windows(2).any(|pair| {
        let left_end = pair[0].presented_start + pair[0].length - 1;
        left_end >= pair[1].presented_start
    }) {
        return Err(IdentityMapError::NonCanonicalMap);
    }

    extents.sort_unstable_by_key(|extent| extent.portable_start);
    Ok(())
}

fn translate_acl_entry(
    entry: AclEntry,
    identity: &IdentityMap,
) -> Result<AclEntry, IdentityMapError> {
    Ok(match entry {
        AclEntry::NamedUser { uid, permissions } => AclEntry::NamedUser {
            uid: identity.translate_uid(uid)?,
            permissions,
        },
        AclEntry::NamedGroup { gid, permissions } => AclEntry::NamedGroup {
            gid: identity.translate_gid(gid)?,
            permissions,
        },
        other => other,
    })
}

fn validate_presented_acl(
    acl: IndexAclRange<'_>,
    identity: &IdentityMap,
) -> Result<(), PresentationError> {
    let mut previous = None;
    for entry in acl {
        let entry = translate_acl_entry(entry?, identity)?;
        if previous.is_some_and(|prior| prior >= entry) {
            return Err(IdentityMapError::InvalidAcl.into());
        }
        previous = Some(entry);
    }
    Ok(())
}

fn translate(extents: &[IdMapExtent], value: u32) -> Result<u32, IdentityMapError> {
    let index = extents.partition_point(|extent| extent.portable_start <= value);
    let extent = index
        .checked_sub(1)
        .and_then(|position| extents.get(position))
        .ok_or(IdentityMapError::UnmappedIdentity)?;
    let offset = value - extent.portable_start;
    if offset >= extent.length {
        return Err(IdentityMapError::UnmappedIdentity);
    }
    extent
        .presented_start
        .checked_add(offset)
        .ok_or(IdentityMapError::InvalidExtent)
}

fn hash_extents(hasher: &mut Sha256, kind: u8, extents: &[IdMapExtent]) {
    hasher.update([kind]);
    hasher.update((extents.len() as u64).to_be_bytes());
    for extent in extents {
        hasher.update(extent.portable_start.to_be_bytes());
        hasher.update(extent.presented_start.to_be_bytes());
        hasher.update(extent.length.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_and_overlapping_destinations_fail_closed() {
        let map = IdentityMap::new(
            vec![IdMapExtent {
                portable_start: 10,
                presented_start: 100,
                length: 2,
            }],
            vec![IdMapExtent {
                portable_start: 20,
                presented_start: 200,
                length: 1,
            }],
        )
        .unwrap_or_else(|error| panic!("map should be valid: {error}"));
        assert_eq!(map.translate_uid(11), Ok(101));
        assert_eq!(
            map.translate_uid(12),
            Err(IdentityMapError::UnmappedIdentity)
        );

        assert_eq!(
            IdentityMap::new(
                vec![
                    IdMapExtent {
                        portable_start: 0,
                        presented_start: 10,
                        length: 2
                    },
                    IdMapExtent {
                        portable_start: 2,
                        presented_start: 11,
                        length: 2
                    },
                ],
                Vec::new(),
            ),
            Err(IdentityMapError::NonCanonicalMap)
        );
    }

    #[test]
    fn reverse_presented_ranges_are_restored_for_binary_translation() {
        let extents = (0_u32..1_024)
            .map(|portable_start| IdMapExtent {
                portable_start,
                presented_start: (1_023 - portable_start) * 2,
                length: 1,
            })
            .collect();
        let map = IdentityMap::new(extents, Vec::new())
            .unwrap_or_else(|error| panic!("reverse destination map failed: {error}"));

        assert!(
            map.uid_extents()
                .windows(2)
                .all(|pair| pair[0].portable_start < pair[1].portable_start)
        );
        assert_eq!(map.translate_uid(0), Ok(2_046));
        assert_eq!(map.translate_uid(511), Ok(1_024));
        assert_eq!(map.translate_uid(1_023), Ok(0));
    }

    #[test]
    fn unordered_portable_and_overlapping_presented_ranges_are_distinct_failures() {
        assert_eq!(
            IdentityMap::new(
                vec![
                    IdMapExtent {
                        portable_start: 2,
                        presented_start: 20,
                        length: 1,
                    },
                    IdMapExtent {
                        portable_start: 1,
                        presented_start: 10,
                        length: 1,
                    },
                ],
                Vec::new(),
            ),
            Err(IdentityMapError::NonCanonicalMap)
        );
        assert_eq!(
            IdentityMap::new(
                vec![
                    IdMapExtent {
                        portable_start: 0,
                        presented_start: 20,
                        length: 2,
                    },
                    IdMapExtent {
                        portable_start: 2,
                        presented_start: 21,
                        length: 1,
                    },
                ],
                Vec::new(),
            ),
            Err(IdentityMapError::NonCanonicalMap)
        );
    }

    #[test]
    fn named_acl_qualifiers_are_translated() {
        let map = IdentityMap::new(
            vec![IdMapExtent {
                portable_start: 0,
                presented_start: 1000,
                length: 20,
            }],
            vec![IdMapExtent {
                portable_start: 0,
                presented_start: 2000,
                length: 20,
            }],
        )
        .unwrap_or_else(|error| panic!("map should be valid: {error}"));
        let acl = Acl::new(vec![
            AclEntry::UserObject(7),
            AclEntry::NamedUser {
                uid: 4,
                permissions: 5,
            },
            AclEntry::GroupObject(5),
            AclEntry::NamedGroup {
                gid: 6,
                permissions: 4,
            },
            AclEntry::Mask(5),
            AclEntry::Other(0),
        ])
        .unwrap_or_else(|error| panic!("ACL should be valid: {error}"));
        let metadata = FilesystemMetadata::new(0o750, 1, 2, 0, 0, Vec::new(), Some(acl))
            .unwrap_or_else(|error| panic!("metadata should be valid: {error}"));
        let plan = PresentationPlan::new(map, AclCapability::Posix);
        assert!(matches!(
            plan.translate_metadata(&metadata, 5),
            Err(IdentityMapError::AclLimitExceeded)
        ));
        let translated = plan
            .translate_metadata(&metadata, 6)
            .unwrap_or_else(|error| panic!("translation should succeed: {error}"));
        assert_eq!(translated.uid(), 1001);
        assert_eq!(translated.gid(), 2002);
        assert!(matches!(
            translated.acl().and_then(|value| value.entries().get(1)),
            Some(AclEntry::NamedUser { uid: 1004, .. })
        ));
    }

    #[test]
    fn map_overflow_and_unmapped_acl_qualifier_fail_closed() {
        assert_eq!(
            IdentityMap::new(
                vec![IdMapExtent {
                    portable_start: 0,
                    presented_start: 0,
                    length: 0,
                }],
                Vec::new(),
            ),
            Err(IdentityMapError::InvalidExtent)
        );
        assert_eq!(
            IdentityMap::new(
                vec![IdMapExtent {
                    portable_start: u32::MAX,
                    presented_start: 0,
                    length: 2,
                }],
                Vec::new(),
            ),
            Err(IdentityMapError::InvalidExtent)
        );
        assert_eq!(
            IdentityMap::new(
                vec![IdMapExtent {
                    portable_start: 0,
                    presented_start: u32::MAX,
                    length: 2,
                }],
                Vec::new(),
            ),
            Err(IdentityMapError::InvalidExtent)
        );

        let map = IdentityMap::new(
            vec![IdMapExtent {
                portable_start: 0,
                presented_start: 1000,
                length: 2,
            }],
            vec![IdMapExtent {
                portable_start: 0,
                presented_start: 2000,
                length: 2,
            }],
        )
        .unwrap_or_else(|error| panic!("map should be valid: {error}"));
        let acl = Acl::new(vec![
            AclEntry::UserObject(7),
            AclEntry::NamedUser {
                uid: 9,
                permissions: 5,
            },
            AclEntry::GroupObject(5),
            AclEntry::Mask(5),
            AclEntry::Other(0),
        ])
        .unwrap_or_else(|error| panic!("ACL should be valid: {error}"));
        let metadata = FilesystemMetadata::new(0o750, 1, 1, 0, 0, Vec::new(), Some(acl))
            .unwrap_or_else(|error| panic!("metadata should be valid: {error}"));
        assert!(matches!(
            PresentationPlan::new(map, AclCapability::Posix).translate_metadata(&metadata, 5),
            Err(IdentityMapError::UnmappedIdentity)
        ));
    }

    #[test]
    fn unmapped_owner_fails_before_acl_output_admission() {
        let map = IdentityMap::new(
            vec![IdMapExtent {
                portable_start: 0,
                presented_start: 1000,
                length: 1,
            }],
            vec![IdMapExtent {
                portable_start: 0,
                presented_start: 2000,
                length: 1,
            }],
        )
        .unwrap_or_else(|error| panic!("map should be valid: {error}"));
        let acl = Acl::new(vec![
            AclEntry::UserObject(7),
            AclEntry::GroupObject(5),
            AclEntry::Other(0),
        ])
        .unwrap_or_else(|error| panic!("ACL should be valid: {error}"));
        let metadata = FilesystemMetadata::new(0o750, 1, 0, 0, 0, Vec::new(), Some(acl))
            .unwrap_or_else(|error| panic!("metadata should be valid: {error}"));

        assert!(matches!(
            PresentationPlan::new(map, AclCapability::Posix).translate_metadata(&metadata, 0),
            Err(IdentityMapError::UnmappedIdentity)
        ));
    }
}
