//! Encodes canonical bucket probe, generation, and tombstone records.
//!
//! ```text
//! CAPABILITIES = {1: 1, 2: true, 3: true, 4: true, 5: false,
//!                 6: 1, 7: timestamp, 8: store-profile, 10: []}
//! MANIFEST = {1: generation, 2: [shard-entry], 3: timestamp, 4: cycle,
//!             5: [pack-inventory-entry]}
//! Tombstone = {1: pack-id, 2: cycle, 3: timestamp, 4: removed-entries, 5: epoch}
//! ```

use crate::cbor::{self, Decoder};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// Reports malformed, noncanonical, or unsupported durable records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    /// The deterministic CBOR encoding failed validation.
    Cbor(cbor::Error),
    /// Fields violate the registered schema or supported layout version.
    Schema,
}

impl From<cbor::Error> for RecordError {
    fn from(value: cbor::Error) -> Self {
        Self::Cbor(value)
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(f),
            Self::Schema => f.write_str("invalid bucket record"),
        }
    }
}

impl core::error::Error for RecordError {}

/// Binds a store to its immutable identity and chunk profiles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreProfile {
    /// The registered identity profile name.
    pub identity: String,
    /// The digest algorithm name.
    pub algorithm: String,
    /// The registered chunk profile name.
    pub chunk: String,
    /// The seed from which the chunk profile's gear table is derived.
    pub seed: [u8; 32],
}

/// Records the capabilities established by an opening backend's probes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BucketCapabilities {
    /// The supported durable layout version.
    pub layout_version: u64,
    /// Whether a colliding create-if-absent failed as required.
    pub create_if_absent: bool,
    /// Whether a stale complete-value condition failed as required.
    pub compare_and_swap: bool,
    /// Whether exact ranged reads were verified.
    pub ranges: bool,
    /// Whether presigned read URLs are available.
    pub presign: bool,
    /// Whether verified multiwriter safety is available.
    pub multi_writer: bool,
    /// The probe's Unix timestamp in seconds.
    pub probed_at: u64,
    /// The persistent identity and chunk profile binding.
    pub profile: StoreProfile,
    /// The authoritative published index generation, absent for an empty catalog.
    pub generation: Option<u64>,
    /// Complete sorted, unique registered ref names; absence means unknown completeness.
    /// Names remain after losing publication attempts or ref deletion.
    pub ref_names: Option<Vec<String>>,
}

impl BucketCapabilities {
    /// Encodes the complete canonical probe record.
    ///
    /// # Errors
    /// Returns [`RecordError::Schema`] for an unsupported layout version or an
    /// unsorted, duplicate, or unregistered ref inventory.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        if self.layout_version != 1 {
            return Err(RecordError::Schema);
        }

        if let Some(names) = &self.ref_names {
            validate_ref_names(names)?;
        }
        let mut bytes = Vec::new();
        cbor::write_map(
            &mut bytes,
            8 + usize::from(self.generation.is_some()) + usize::from(self.ref_names.is_some()),
        );
        uint_field(&mut bytes, 1, self.layout_version);
        for (key, value) in [
            (2, self.create_if_absent),
            (3, self.compare_and_swap),
            (4, self.ranges),
            (5, self.presign),
        ] {
            cbor::write_uint(&mut bytes, key);
            bytes.push(if value { 0xf5 } else { 0xf4 });
        }
        uint_field(&mut bytes, 6, if self.multi_writer { 1 } else { 2 });
        uint_field(&mut bytes, 7, self.probed_at);
        cbor::write_uint(&mut bytes, 8);
        cbor::write_map(&mut bytes, 4);
        for (key, value) in [
            (1, &self.profile.identity),
            (2, &self.profile.algorithm),
            (3, &self.profile.chunk),
        ] {
            cbor::write_uint(&mut bytes, key);
            cbor::write_text(&mut bytes, value);
        }
        cbor::write_uint(&mut bytes, 4);
        cbor::write_bytes(&mut bytes, &self.profile.seed);
        if let Some(generation) = self.generation {
            uint_field(&mut bytes, 9, generation);
        }
        if let Some(names) = &self.ref_names {
            cbor::write_uint(&mut bytes, 10);
            cbor::write_array(&mut bytes, names.len());
            for name in names {
                cbor::write_text(&mut bytes, name);
            }
        }
        Ok(bytes)
    }

    /// Decodes and validates a supported probe record and profile binding.
    ///
    /// # Errors
    /// Rejects unsupported versions, missing profile binding, invalid fields,
    /// noncanonical encoding, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes);
        let fields = decoder.map(10)?;
        if !(8..=10).contains(&fields) {
            return Err(RecordError::Schema);
        }
        key(&mut decoder, 1)?;
        let layout_version = decoder.uint()?;
        if layout_version != 1 {
            return Err(RecordError::Schema);
        }
        key(&mut decoder, 2)?;
        let create_if_absent = boolean(&mut decoder)?;
        key(&mut decoder, 3)?;
        let compare_and_swap = boolean(&mut decoder)?;
        key(&mut decoder, 4)?;
        let ranges = boolean(&mut decoder)?;
        key(&mut decoder, 5)?;
        let presign = boolean(&mut decoder)?;
        key(&mut decoder, 6)?;
        let multi_writer = match decoder.uint()? {
            1 => true,
            2 => false,
            _ => return Err(RecordError::Schema),
        };
        key(&mut decoder, 7)?;
        let probed_at = decoder.uint()?;

        key(&mut decoder, 8)?;
        if decoder.map(4)? != 4 {
            return Err(RecordError::Schema);
        }
        key(&mut decoder, 1)?;
        let identity = decoder.text(decoder.remaining().len())?.to_string();
        key(&mut decoder, 2)?;
        let algorithm = decoder.text(decoder.remaining().len())?.to_string();
        key(&mut decoder, 3)?;
        let chunk = decoder.text(decoder.remaining().len())?.to_string();
        key(&mut decoder, 4)?;
        let seed = digest(&mut decoder)?;
        let mut generation = None;
        let mut ref_names = None;
        let mut previous_key = 8;
        for _ in 8..fields {
            let field = decoder.uint()?;
            if field <= previous_key {
                return Err(RecordError::Schema);
            }
            previous_key = field;
            match field {
                9 => generation = Some(decoder.uint()?),
                10 => {
                    let count = decoder.array(decoder.remaining().len())?;
                    let mut names = Vec::with_capacity(count);
                    for _ in 0..count {
                        names.push(decoder.text(decoder.remaining().len())?.to_string());
                    }
                    validate_ref_names(&names)?;
                    ref_names = Some(names);
                }
                _ => return Err(RecordError::Schema),
            }
        }
        decoder.finish()?;

        Ok(Self {
            layout_version,
            create_if_absent,
            compare_and_swap,
            ranges,
            presign,
            multi_writer,
            probed_at,
            generation,
            ref_names,
            profile: StoreProfile {
                identity,
                algorithm,
                chunk,
                seed,
            },
        })
    }
}

fn validate_ref_names(names: &[String]) -> Result<(), RecordError> {
    if names
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(RecordError::Schema);
    }
    for name in names {
        if !name.starts_with("refs/") || super::keys::BucketKey::parse(name).is_err() {
            return Err(RecordError::Schema);
        }
    }
    Ok(())
}

/// Identifies one shard and the optional filter belonging to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationShard {
    /// The shard number within the generation.
    pub shard: u64,
    /// The domain-separated identity of its index bytes.
    pub index_hash: [u8; 32],
    /// The exact encoded index size.
    pub index_size: u64,
    /// The filter's identity and size, when this generation has a filter.
    pub filter: Option<([u8; 32], u64)>,
}

/// Describes a published pack and its matching detached index container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackInventoryEntry {
    /// The opaque UUID identifying both registered container keys.
    pub pack_id: [u8; 16],
    /// The identity digest of the complete sealed pack bytes.
    pub pack_hash: [u8; 32],
    /// The exact encoded size of the sealed pack.
    pub pack_size: u64,
    /// The identity digest of the header-prefixed detached index bytes.
    pub index_hash: [u8; 32],
    /// The exact encoded size of the detached index.
    pub index_size: u64,
}

/// Describes the complete immutable content of one index generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationManifest {
    /// The generation named by the enclosing key.
    pub generation: u64,
    /// All shards, in strictly increasing shard order.
    pub shards: Vec<GenerationShard>,
    /// The publication's Unix timestamp in seconds.
    pub written_at: u64,
    /// The collection cycle producing the generation.
    pub cycle: u64,
    /// The optional authoritative container inventory, ordered by unique pack ID.
    pub inventory: Option<Vec<PackInventoryEntry>>,
}

impl GenerationManifest {
    /// Encodes a complete generation manifest as canonical CBOR.
    ///
    /// # Errors
    /// Returns [`RecordError::Schema`] for repeated or unordered shards or
    /// container inventory entries.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        if self
            .shards
            .windows(2)
            .any(|pair| pair[0].shard >= pair[1].shard)
        {
            return Err(RecordError::Schema);
        }

        if self.inventory.as_ref().is_some_and(|entries| {
            entries
                .windows(2)
                .any(|pair| pair[0].pack_id >= pair[1].pack_id)
        }) {
            return Err(RecordError::Schema);
        }

        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 4 + usize::from(self.inventory.is_some()));
        uint_field(&mut bytes, 1, self.generation);
        cbor::write_uint(&mut bytes, 2);
        cbor::write_array(&mut bytes, self.shards.len());
        for shard in &self.shards {
            cbor::write_array(&mut bytes, if shard.filter.is_some() { 5 } else { 3 });
            cbor::write_uint(&mut bytes, shard.shard);
            cbor::write_bytes(&mut bytes, &shard.index_hash);
            cbor::write_uint(&mut bytes, shard.index_size);
            if let Some((hash, size)) = shard.filter {
                cbor::write_bytes(&mut bytes, &hash);
                cbor::write_uint(&mut bytes, size);
            }
        }
        uint_field(&mut bytes, 3, self.written_at);
        uint_field(&mut bytes, 4, self.cycle);
        if let Some(entries) = &self.inventory {
            cbor::write_uint(&mut bytes, 5);
            cbor::write_array(&mut bytes, entries.len());
            for entry in entries {
                cbor::write_array(&mut bytes, 5);
                cbor::write_bytes(&mut bytes, &entry.pack_id);
                cbor::write_bytes(&mut bytes, &entry.pack_hash);
                cbor::write_uint(&mut bytes, entry.pack_size);
                cbor::write_bytes(&mut bytes, &entry.index_hash);
                cbor::write_uint(&mut bytes, entry.index_size);
            }
        }
        Ok(bytes)
    }

    /// Decodes a canonical generation manifest.
    ///
    /// # Errors
    /// Rejects malformed fields, duplicate or unordered shards, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes);
        let fields = decoder.map(5)?;
        if !matches!(fields, 4 | 5) {
            return Err(RecordError::Schema);
        }
        key(&mut decoder, 1)?;
        let generation = decoder.uint()?;
        key(&mut decoder, 2)?;
        let count = decoder.array(decoder.remaining().len())?;
        let mut shards = Vec::with_capacity(count);
        for _ in 0..count {
            let length = decoder.array(5)?;
            if !matches!(length, 3 | 5) {
                return Err(RecordError::Schema);
            }
            let shard = decoder.uint()?;
            if shards
                .last()
                .is_some_and(|last: &GenerationShard| last.shard >= shard)
            {
                return Err(RecordError::Schema);
            }
            let index_hash = digest(&mut decoder)?;
            let index_size = decoder.uint()?;
            let filter = if length == 5 {
                Some((digest(&mut decoder)?, decoder.uint()?))
            } else {
                None
            };
            shards.push(GenerationShard {
                shard,
                index_hash,
                index_size,
                filter,
            });
        }
        key(&mut decoder, 3)?;
        let written_at = decoder.uint()?;
        key(&mut decoder, 4)?;
        let cycle = decoder.uint()?;
        let inventory = if fields == 5 {
            key(&mut decoder, 5)?;
            let count = decoder.array(decoder.remaining().len())?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                if decoder.array(5)? != 5 {
                    return Err(RecordError::Schema);
                }
                let pack_id = decoder
                    .bytes(16)?
                    .try_into()
                    .map_err(|_| RecordError::Schema)?;
                if entries
                    .last()
                    .is_some_and(|prior: &PackInventoryEntry| prior.pack_id >= pack_id)
                {
                    return Err(RecordError::Schema);
                }
                let pack_hash = digest(&mut decoder)?;
                let pack_size = decoder.uint()?;
                let index_hash = digest(&mut decoder)?;
                let index_size = decoder.uint()?;
                entries.push(PackInventoryEntry {
                    pack_id,
                    pack_hash,
                    pack_size,
                    index_hash,
                    index_size,
                });
            }
            Some(entries)
        } else {
            None
        };
        decoder.finish()?;

        Ok(Self {
            generation,
            shards,
            written_at,
            cycle,
            inventory,
        })
    }
}

/// Removes one pack from service without deleting its retained bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tombstone {
    /// The sealed pack's opaque UUID bytes.
    pub pack_id: [u8; 16],
    /// The collection cycle removing the pack.
    pub cycle: u64,
    /// The removal's Unix timestamp in seconds.
    pub tombstoned_at: u64,
    /// The number of removed index entries.
    pub removed_entries: u64,
    /// The collector fencing epoch authorizing removal.
    pub epoch: u64,
}

impl Tombstone {
    /// Encodes the canonical tombstone record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 5);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_bytes(&mut bytes, &self.pack_id);
        uint_field(&mut bytes, 2, self.cycle);
        uint_field(&mut bytes, 3, self.tombstoned_at);
        uint_field(&mut bytes, 4, self.removed_entries);
        uint_field(&mut bytes, 5, self.epoch);
        bytes
    }

    /// Decodes a canonical tombstone record.
    ///
    /// # Errors
    /// Rejects invalid pack IDs, fields, CBOR, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.map(5)? != 5 {
            return Err(RecordError::Schema);
        }
        key(&mut decoder, 1)?;
        let pack_id = decoder
            .bytes(16)?
            .try_into()
            .map_err(|_| RecordError::Schema)?;
        key(&mut decoder, 2)?;
        let cycle = decoder.uint()?;
        key(&mut decoder, 3)?;
        let tombstoned_at = decoder.uint()?;
        key(&mut decoder, 4)?;
        let removed_entries = decoder.uint()?;
        key(&mut decoder, 5)?;
        let epoch = decoder.uint()?;
        decoder.finish()?;

        Ok(Self {
            pack_id,
            cycle,
            tombstoned_at,
            removed_entries,
            epoch,
        })
    }
}

fn uint_field(bytes: &mut Vec<u8>, key: u64, value: u64) {
    cbor::write_uint(bytes, key);
    cbor::write_uint(bytes, value);
}

fn key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), RecordError> {
    if decoder.uint()? == expected {
        Ok(())
    } else {
        Err(RecordError::Schema)
    }
}

fn digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], RecordError> {
    decoder
        .bytes(32)?
        .try_into()
        .map_err(|_| RecordError::Schema)
}

fn boolean(decoder: &mut Decoder<'_>) -> Result<bool, RecordError> {
    match decoder.simple()? {
        0xf4 => Ok(false),
        0xf5 => Ok(true),
        _ => Err(RecordError::Schema),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn durable_records_reject_noncanonical_unknown_and_trailing_fields() {
        let record = BucketCapabilities {
            layout_version: 1,
            create_if_absent: true,
            compare_and_swap: true,
            ranges: true,
            presign: false,
            multi_writer: true,
            probed_at: 7,
            generation: Some(8),
            ref_names: Some(alloc::vec!["refs/heads/_/main".into()]),
            profile: StoreProfile {
                identity: "terrane-v1".into(),
                algorithm: "blake3".into(),
                chunk: "cdc-1m".into(),
                seed: [3; 32],
            },
        };
        let encoded = record.encode().unwrap();
        assert_eq!(BucketCapabilities::decode(&encoded).unwrap(), record);

        let mut noncanonical = encoded.clone();
        noncanonical.splice(2..3, [0x18, 1]);
        assert!(BucketCapabilities::decode(&noncanonical).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(BucketCapabilities::decode(&trailing).is_err());
        let mut unknown = encoded;
        unknown[1] = 0;
        assert!(BucketCapabilities::decode(&unknown).is_err());
    }

    #[test]
    fn capability_inventory_distinguishes_complete_empty_from_legacy_unknown() {
        let mut record = BucketCapabilities {
            layout_version: 1,
            create_if_absent: true,
            compare_and_swap: true,
            ranges: true,
            presign: false,
            multi_writer: true,
            probed_at: 1,
            generation: None,
            ref_names: Some(Vec::new()),
            profile: StoreProfile {
                identity: "terrane-v1".into(),
                algorithm: "blake3".into(),
                chunk: "cdc-1m".into(),
                seed: [0; 32],
            },
        };
        let complete = record.encode().unwrap();
        assert_eq!(
            BucketCapabilities::decode(&complete).unwrap().ref_names,
            Some(Vec::new())
        );
        record.ref_names = None;
        let unknown = record.encode().unwrap();
        assert_ne!(complete, unknown);
        assert_eq!(
            BucketCapabilities::decode(&unknown).unwrap().ref_names,
            None
        );
        for names in [
            alloc::vec!["refs/heads/_/b".into(), "refs/heads/_/a".into()],
            alloc::vec!["refs/heads/_/a".into(), "refs/heads/_/a".into()],
            alloc::vec!["CAPABILITIES".into()],
            alloc::vec!["refs/unknown/_/a".into()],
        ] {
            record.ref_names = Some(names);
            assert!(record.encode().is_err());
        }
        let mut nullable = complete;
        nullable.pop();
        nullable.push(0xf6);
        assert!(BucketCapabilities::decode(&nullable).is_err());
    }

    #[test]
    fn generation_manifest_binds_all_shards_and_optional_filters() {
        let mut manifest = GenerationManifest {
            generation: 2,
            inventory: None,
            shards: alloc::vec![
                GenerationShard {
                    shard: 0,
                    index_hash: [1; 32],
                    index_size: 77,
                    filter: None
                },
                GenerationShard {
                    shard: 3,
                    index_hash: [2; 32],
                    index_size: 78,
                    filter: Some(([4; 32], 40))
                },
            ],
            written_at: 9,
            cycle: 1,
        };
        assert_eq!(
            GenerationManifest::decode(&manifest.encode().unwrap()).unwrap(),
            manifest
        );
        manifest.shards.reverse();
        assert!(manifest.encode().is_err());

        let tombstone = Tombstone {
            pack_id: [5; 16],
            cycle: 1,
            tombstoned_at: 10,
            removed_entries: 7,
            epoch: 3,
        };
        assert_eq!(Tombstone::decode(&tombstone.encode()).unwrap(), tombstone);
    }
}
