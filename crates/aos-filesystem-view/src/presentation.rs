//! Exact UID, GID, and POSIX ACL presentation translation.

use aos_sandbox_core::model::{Acl, AclEntry, FilesystemMetadata, Xattr};
use sha2::{Digest, Sha256};

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
    /// Portable or presented ranges overlap or are not strictly ordered.
    #[error("identity-map extents overlap or are not canonical")]
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
    /// Returns [`IdentityMapError`] for empty, overflowing, unordered, or
    /// overlapping portable or presentation ranges.
    pub fn new(uid: Vec<IdMapExtent>, gid: Vec<IdMapExtent>) -> Result<Self, IdentityMapError> {
        validate_extents(&uid)?;
        validate_extents(&gid)?;
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

    fn uid(&self, value: u32) -> Result<u32, IdentityMapError> {
        translate(&self.uid, value)
    }

    fn gid(&self, value: u32) -> Result<u32, IdentityMapError> {
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
        let uid = self.identity.uid(metadata.uid())?;
        let gid = self.identity.gid(metadata.gid())?;
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
                            uid: self.identity.uid(uid)?,
                            permissions,
                        },
                        AclEntry::NamedGroup { gid, permissions } => AclEntry::NamedGroup {
                            gid: self.identity.gid(gid)?,
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

fn validate_extents(extents: &[IdMapExtent]) -> Result<(), IdentityMapError> {
    let mut portable_end = None;
    let mut presented_ranges = Vec::with_capacity(extents.len());
    for extent in extents {
        if extent.length == 0 {
            return Err(IdentityMapError::InvalidExtent);
        }
        let portable = extent
            .portable_start
            .checked_add(extent.length - 1)
            .ok_or(IdentityMapError::InvalidExtent)?;
        let presented = extent
            .presented_start
            .checked_add(extent.length - 1)
            .ok_or(IdentityMapError::InvalidExtent)?;
        if portable_end.is_some_and(|end| end >= extent.portable_start) {
            return Err(IdentityMapError::NonCanonicalMap);
        }
        portable_end = Some(portable);
        presented_ranges.push((extent.presented_start, presented));
    }
    presented_ranges.sort_unstable();
    if presented_ranges
        .windows(2)
        .any(|pair| pair[0].1 >= pair[1].0)
    {
        return Err(IdentityMapError::NonCanonicalMap);
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
        assert_eq!(map.uid(11), Ok(101));
        assert_eq!(map.uid(12), Err(IdentityMapError::UnmappedIdentity));

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
