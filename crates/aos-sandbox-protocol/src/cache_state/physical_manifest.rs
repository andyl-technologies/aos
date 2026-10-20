//! Shares the existing physical Cache manifest and quota-limit DATA recipes.
//!
//! The compile-time recipe preserves each invocation's private model/error
//! types and allocation/error/Drop frontiers. It performs no native I/O,
//! callback, capability verification, role admission, signing or effect.
//!
//! ```text
//! AOSCOO01 | version:u32be=3 | generation:u64be | disk-count:u32be |
//! complete disk entries | negative-count:u32be | negative entries | SHA256:32
//! ```

use aos_sandbox_core::ObjectDigest;
#[doc(hidden)]
pub use sha2::{Digest, Sha256};

/// Identifies the canonical physical manifest magic.
pub const CACHE_PHYSICAL_MANIFEST_MAGIC_V1: &[u8; 8] = b"AOSCOO01";
/// Identifies the established complete physical manifest version.
pub const CACHE_PHYSICAL_MANIFEST_VERSION_V1: u32 = 3;
/// Bounds the existing canonical physical manifest byte representation.
pub const CACHE_PHYSICAL_MANIFEST_MAXIMUM_BYTES_V1: usize = 16 * 1024 * 1024;

/// Rejects invalid physical identifier comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid physical Cache identifier DATA")]
pub struct CachePhysicalIdentifierDataErrorV1;

/// Validates only nonzero physical pin bytes, without issuing a pin.
///
/// # Errors
/// Rejects the all-zero reserved identifier.
pub fn validate_owner_pin_bytes_v1(
    bytes: [u8; 16],
) -> Result<[u8; 16], CachePhysicalIdentifierDataErrorV1> {
    if bytes == [0; 16] {
        return Err(CachePhysicalIdentifierDataErrorV1);
    }
    Ok(bytes)
}

/// Validates only a nonzero lookup commitment without read/disclosure authority.
///
/// # Errors
/// Rejects the all-zero reserved commitment.
pub fn validate_negative_key_digest_v1(
    digest: ObjectDigest,
) -> Result<ObjectDigest, CachePhysicalIdentifierDataErrorV1> {
    if digest.as_bytes() == &[0; 32] {
        return Err(CachePhysicalIdentifierDataErrorV1);
    }
    Ok(digest)
}

/// Commits the seven existing physical limit fields without granting capacity.
///
/// Callers preserve their own checked usize-to-u64 conversion and error types
/// before passing fields in memory/disk/low-water/positive/negative/pins/bytes
/// order. This digest authenticates neither protected quotas nor a live owner.
#[must_use]
pub fn cache_physical_limit_fields_digest_v1(fields: [u64; 7]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.cache-owner.limits.v1\0");
    for value in fields {
        digest.update(value.to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Expands the one physical manifest/limit DATA engine for private models.
///
/// Identifiers name only each invocation's existing error, limit, row and fixed
/// identifier DATA types. They cannot supply a callback, payer, key or native
/// original. Native consumers keep their old types/error variants and the same
/// map construction, validation and disposal schedule; the private signer uses
/// the same source with its own nonauthorizing decoded DATA models.
#[doc(hidden)]
#[macro_export]
macro_rules! define_cache_physical_manifest_data_recipe_v1 {
    ($error:ident, $limits:ident, $object_key:ident, $disk_entry:ident,
     $negative_key:ident, $negative_entry:ident, $pin_id:ident) => {
        impl $limits {
            /// Derives one node-global physical owner envelope from protected quotas.
            ///
            /// The caller supplies only the separate heap-tier ceiling. Physical bytes,
            /// resident entries, and pin obligations come from the complete protected
            /// partition set. The negative cache is advisory and shares the resident
            /// entry ceiling; it cannot expand correctness authority.
            ///
            /// # Errors
            ///
            /// Returns the invocation's `InvalidLimits` error for absent, duplicate,
            /// cross-node, invalid, or unrepresentable partition quotas.
            pub fn from_node_quotas(
                maximum_memory_bytes: u64,
                quotas: impl IntoIterator<Item = $crate::cache_state::NodeCacheQuotaV1>,
            ) -> Result<Self, $error> {
                let mut partitions = ::std::collections::BTreeSet::new();
                let mut node = None;
                let mut maximum_disk_bytes = 0_u64;
                let mut disk_low_water_bytes = 0_u64;
                let mut maximum_positive_entries = 0_u64;
                let mut maximum_pins = 0_u64;
                let mut maximum_pinned_bytes = 0_u64;

                for quota in quotas {
                    quota
                        .validate()
                        .map_err(|_| $error::InvalidLimits)?;
                    if !partitions.insert(*quota.partition.digest().as_bytes())
                        || node.is_some_and(|current| current != *quota.partition.node().as_bytes())
                    {
                        return Err($error::InvalidLimits);
                    }
                    node = Some(*quota.partition.node().as_bytes());

                    let partition_pins = quota
                        .maximum_logical_pins
                        .checked_add(quota.maximum_source_retentions)
                        .and_then(|count| count.checked_add(quota.maximum_kernel_references))
                        .and_then(|count| count.checked_add(quota.maximum_backing_registrations))
                        .ok_or($error::InvalidLimits)?;
                    maximum_disk_bytes = maximum_disk_bytes
                        .checked_add(quota.maximum_physical_bytes)
                        .ok_or($error::InvalidLimits)?;
                    disk_low_water_bytes = disk_low_water_bytes
                        .checked_add(quota.low_water_bytes)
                        .ok_or($error::InvalidLimits)?;
                    maximum_positive_entries = maximum_positive_entries
                        .checked_add(quota.maximum_resident_objects)
                        .ok_or($error::InvalidLimits)?;
                    maximum_pins = maximum_pins
                        .checked_add(partition_pins)
                        .ok_or($error::InvalidLimits)?;
                    // Each pin charges its object's bytes independently. Saturation
                    // keeps the owner bound representable without rejecting valid
                    // large protected quotas; checked runtime accounting still fails
                    // before u64 overflow.
                    maximum_pinned_bytes = maximum_pinned_bytes
                        .saturating_add(quota.maximum_physical_bytes.saturating_mul(partition_pins));
                }

                if partitions.is_empty() {
                    return Err($error::InvalidLimits);
                }
                Self {
                    maximum_memory_bytes,
                    maximum_disk_bytes,
                    disk_low_water_bytes,
                    maximum_positive_entries: usize::try_from(maximum_positive_entries)
                        .map_err(|_| $error::InvalidLimits)?,
                    maximum_negative_entries: usize::try_from(maximum_positive_entries)
                        .map_err(|_| $error::InvalidLimits)?,
                    maximum_pins: usize::try_from(maximum_pins)
                        .map_err(|_| $error::InvalidLimits)?,
                    maximum_pinned_bytes,
                }
                .validate()
            }

            /// Matches the entire physical envelope to protected node quotas.
            pub(crate) fn matches_node_quotas(self, quotas: &[$crate::cache_state::NodeCacheQuotaV1]) -> bool {
                Self::from_node_quotas(self.maximum_memory_bytes, quotas.iter().copied())
                    .is_ok_and(|derived| derived == self)
            }

            fn validate(self) -> Result<Self, $error> {
                if self.maximum_memory_bytes == 0
                    || self.maximum_disk_bytes == 0
                    || self.disk_low_water_bytes > self.maximum_disk_bytes
                    || self.maximum_positive_entries == 0
                    || self.maximum_negative_entries == 0
                    || self.maximum_pins == 0
                    || self.maximum_pinned_bytes == 0
                {
                    return Err($error::InvalidLimits);
                }
                Ok(self)
            }
        }

        fn encode_manifest(
            generation: u64,
            disk: &::std::collections::BTreeMap<$object_key, $disk_entry>,
            negatives: &::std::collections::BTreeMap<$negative_key, $negative_entry>,
        ) -> Result<Vec<u8>, $error> {
            use $crate::cache_state::physical_manifest::Digest as _;
            let mut bytes = Vec::new();
            bytes.extend_from_slice($crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_MAGIC_V1);
            bytes.extend_from_slice(&$crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_VERSION_V1.to_be_bytes());
            bytes.extend_from_slice(&generation.to_be_bytes());
            put_u32(&mut bytes, disk.len())?;
            for (key, entry) in disk {
                bytes.extend_from_slice(key.partition.as_bytes());
                put_descriptor(&mut bytes, &key.descriptor)?;
                put_string(&mut bytes, &entry.file_name)?;
                put_string(&mut bytes, entry.staging_name.as_deref().unwrap_or(""))?;
                put_string(&mut bytes, entry.deleting_name.as_deref().unwrap_or(""))?;
                bytes.extend_from_slice(&entry.bytes.to_be_bytes());
                bytes.extend_from_slice(&entry.device.to_be_bytes());
                bytes.extend_from_slice(&entry.inode.to_be_bytes());
                bytes.extend_from_slice(&entry.verity);
                bytes.extend_from_slice(entry.canonical_name.as_bytes());
                bytes.extend_from_slice(entry.root_custody.as_bytes());
                bytes.extend_from_slice(&entry.last_used.to_be_bytes());
                put_u32(&mut bytes, entry.pins.len())?;
                for pin in &entry.pins {
                    bytes.extend_from_slice(pin.as_bytes());
                }
            }
            put_u32(&mut bytes, negatives.len())?;
            for (key, entry) in negatives {
                bytes.extend_from_slice(key.digest().as_bytes());
                bytes.extend_from_slice(&entry.valid_until.to_be_bytes());
                bytes.extend_from_slice(&entry.last_used.to_be_bytes());
            }
            let checksum: [u8; 32] = $crate::cache_state::physical_manifest::Sha256::digest(&bytes).into();
            bytes.extend_from_slice(&checksum);
            if bytes.len() > $crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_MAXIMUM_BYTES_V1 {
                return Err($error::CapacityExhausted);
            }
            Ok(bytes)
        }

        fn decode_manifest(
            bytes: &[u8],
            limits: $limits,
        ) -> Result<
            (
                u64,
                ::std::collections::BTreeMap<$object_key, $disk_entry>,
                ::std::collections::BTreeMap<$negative_key, $negative_entry>,
            ),
            $error,
        > {
            use $crate::cache_state::physical_manifest::Digest as _;
            if bytes.len() < 56 || bytes.len() > $crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_MAXIMUM_BYTES_V1 {
                return Err($error::InvalidManifest);
            }
            let (payload, checksum) = bytes.split_at(bytes.len() - 32);
            if $crate::cache_state::physical_manifest::Sha256::digest(payload).as_slice() != checksum {
                return Err($error::InvalidManifest);
            }
            let mut cursor = ::aos_sandbox_core::bounded_codec::BoundedReader::new(payload, manifest_read_error);
            if cursor.bytes(8)? != $crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_MAGIC_V1 || cursor.u32()? != $crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_VERSION_V1 {
                return Err($error::InvalidManifest);
            }
            let generation = cursor.u64()?;
            if generation == 0 {
                return Err($error::InvalidManifest);
            }
            let count = cursor.u32()? as usize;
            if count > limits.maximum_positive_entries {
                return Err($error::CapacityExhausted);
            }
            let mut disk = ::std::collections::BTreeMap::new();
            for _ in 0..count {
                let key = $object_key {
                    partition: ::aos_sandbox_core::ObjectDigest::from_bytes(cursor.array()?),
                    descriptor: read_manifest_descriptor(&mut cursor)?,
                };
                let file_name = read_manifest_string(&mut cursor)?;
                validate_basename(&file_name)?;
                let staging_name = match read_manifest_string(&mut cursor)? {
                    name if name.is_empty() => None,
                    name => {
                        validate_basename(&name)?;
                        Some(name)
                    }
                };
                let deleting_name = match read_manifest_string(&mut cursor)? {
                    name if name.is_empty() => None,
                    name => {
                        validate_basename(&name)?;
                        Some(name)
                    }
                };
                if staging_name.is_some() && deleting_name.is_some() {
                    return Err($error::InvalidManifest);
                }
                let bytes = cursor.u64()?;
                let device = cursor.u64()?;
                let inode = cursor.u64()?;
                let verity = cursor.array()?;
                let canonical_name = ::aos_sandbox_core::ObjectDigest::from_bytes(cursor.array()?);
                let root_custody = ::aos_sandbox_core::ObjectDigest::from_bytes(cursor.array()?);
                let last_used = cursor.u64()?;
                let pin_count = cursor.u32()? as usize;
                if bytes == 0
                    || device == 0
                    || inode == 0
                    || verity == [0; 32]
                    || canonical_name.as_bytes() == &[0; 32]
                    || root_custody.as_bytes() == &[0; 32]
                    || last_used == 0
                    || pin_count > limits.maximum_pins
                {
                    return Err($error::InvalidManifest);
                }
                let mut pins = ::std::collections::BTreeSet::new();
                for _ in 0..pin_count {
                    if !pins.insert($pin_id::from_bytes(cursor.array()?)?) {
                        return Err($error::InvalidManifest);
                    }
                }
                if disk
                    .insert(
                        key,
                        $disk_entry {
                            file_name,
                            staging_name,
                            deleting_name,
                            bytes,
                            device,
                            inode,
                            verity,
                            canonical_name,
                            root_custody,
                            last_used,
                            pins,
                        },
                    )
                    .is_some()
                {
                    return Err($error::InvalidManifest);
                }
            }
            let negative_count = cursor.u32()? as usize;
            if negative_count > limits.maximum_negative_entries {
                return Err($error::CapacityExhausted);
            }
            let mut negatives = ::std::collections::BTreeMap::new();
            for _ in 0..negative_count {
                let key = $negative_key::from_digest(::aos_sandbox_core::ObjectDigest::from_bytes(cursor.array()?))
                    .map_err(|_| $error::InvalidManifest)?;
                let entry = $negative_entry {
                    valid_until: cursor.u64()?,
                    last_used: cursor.u64()?,
                };
                if entry.valid_until == 0 || entry.last_used == 0 || negatives.insert(key, entry).is_some()
                {
                    return Err($error::InvalidManifest);
                }
            }
            cursor.finish()?;
            Ok((generation, disk, negatives))
        }

        fn decode_generation(bytes: &[u8]) -> Result<u64, $error> {
            if bytes.len() < 20
                || &bytes[..8] != $crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_MAGIC_V1
                || bytes[8..12] != $crate::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_VERSION_V1.to_be_bytes()
            {
                return Err($error::InvalidManifest);
            }
            Ok(u64::from_be_bytes(
                bytes[12..20]
                    .try_into()
                    .map_err(|_| $error::InvalidManifest)?,
            ))
        }

        fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), $error> {
            bytes.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| $error::CapacityExhausted)?
                    .to_be_bytes(),
            );
            Ok(())
        }

        fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), $error> {
            let length = u16::try_from(value.len()).map_err(|_| $error::InvalidManifest)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
            Ok(())
        }

        fn put_descriptor(
            bytes: &mut Vec<u8>,
            descriptor: &::aos_sandbox_core::ObjectDescriptor,
        ) -> Result<(), $error> {
            put_string(bytes, descriptor.media_type().as_str())?;
            bytes.extend_from_slice(descriptor.digest().as_bytes());
            bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
            Ok(())
        }

        fn validate_basename(name: &str) -> Result<(), $error> {
            let bytes = name.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 255
                || bytes == b"."
                || bytes == b".."
                || bytes.contains(&b'/')
                || bytes.contains(&0)
                || ::std::path::Path::new(name).is_absolute()
                || ::std::path::Path::new(name).components().count() != 1
            {
                return Err($error::UnsafeName);
            }
            Ok(())
        }

        fn manifest_read_error(_: ::aos_sandbox_core::bounded_codec::ReadError) -> $error {
            $error::InvalidManifest
        }

        fn read_manifest_string(
            cursor: &mut ::aos_sandbox_core::bounded_codec::BoundedReader<'_, $error>,
        ) -> Result<String, $error> {
            let length = cursor.u16()? as usize;
            let value = std::str::from_utf8(cursor.bytes(length)?)
                .map_err(|_| $error::InvalidManifest)?;
            Ok(value.to_owned())
        }

        fn read_manifest_descriptor(
            cursor: &mut ::aos_sandbox_core::bounded_codec::BoundedReader<'_, $error>,
        ) -> Result<::aos_sandbox_core::ObjectDescriptor, $error> {
            let media = ::aos_sandbox_core::MediaType::new(read_manifest_string(cursor)?)
                .map_err(|_| $error::InvalidManifest)?;
            Ok(::aos_sandbox_core::ObjectDescriptor::new(
                media,
                ::aos_sandbox_core::ObjectDigest::from_bytes(cursor.array()?),
                cursor.u64()?,
            ))
        }
    };
}

/// Instantiates the canonical object-view manifest DATA without native authority.
pub mod view_data;
