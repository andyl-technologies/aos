//! Canonical root, base-record, and pack-table formats of the packed index.
//!
//! ```text
//! PackIndexV2 =
//!   "crucible.content-store.pack-index.v2\0"
//!   configuration[32]
//!   backend_instance[32]
//!   generation_u64
//!   last_repack_tag_u8            # 0 None, 1 Some
//!   [last_repack_plan_id[32]]     # present exactly when the tag is 1
//!   base_digest[32]
//!   base_record_count_u64
//!   pack_table_digest[32]
//!   pack_table_record_count_u64
//!   journal_committed_length_u64  # header plus committed records
//!   journal_record_count_u64
//!   journal_chain[32]
//!   logical_object_count_u64
//!   logical_bytes_u64
//!   referenced_pack_count_u64
//!   referenced_physical_bytes_u64
//!   root_checksum[32]             # BLAKE3("crucible.content-store.pack-index.v2" || preceding bytes)
//!
//! PackIndexBaseV2 record (85 bytes, sorted by content ID) =
//!   content_id[37] pack_id[32] absolute_body_offset_u64 logical_length_u64
//!
//! PackTableV1 record (48 bytes, sorted by pack ID) =
//!   pack_id[32] live_entry_count_u64 pack_physical_bytes_u64
//! ```
//!
//! The root's totals always equal the base overlaid by its committed journal
//! prefix; [`IndexTotals::after`] advances them by exactly one journal record.

use super::format::{
    CONTENT_ID_BYTES, PackedCursor, decode_content_id, encode_content_id, validate_index_entry,
};
use super::journal::{JOURNAL_RECORD_BYTES, JournalOperation, JournalRecord, journal_header};
use super::sorted_file::{SortedFileFormat, SortedRecord};
use super::{
    ContentId, IndexEntry, MAX_PACK_BYTES, MAX_PACK_ENTRIES, PackId, PackedRepackPlanId, StoreError,
};

const ROOT_MAGIC: &[u8] = b"crucible.content-store.pack-index.v2\0";
const ROOT_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.pack-index.v2";
const ROOT_DIGEST_DOMAIN: &[u8] = b"crucible.content-store.pack-index-digest.v2";

/// Returns the digest that a repack plan binds for one exact root.
pub(super) fn root_digest(root_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_DIGEST_DOMAIN);
    hasher.update(root_bytes);
    *hasher.finalize().as_bytes()
}

/// Checked logical and physical totals committed by one root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct IndexTotals {
    pub(super) logical_objects: u64,
    pub(super) logical_bytes: u64,
    pub(super) packs: u64,
    pub(super) physical_bytes: u64,
}

impl IndexTotals {
    /// Returns totals after `record` moved its pack to `pack_state`.
    pub(super) fn after(
        self,
        record: &JournalRecord,
        pack_state: PackState,
    ) -> Result<Self, StoreError> {
        let length = record.entry.length;
        let physical = record.pack_physical_bytes;
        let overflow = || StoreError::Quota;
        let underflow = || StoreError::Incompatible;
        let mut next = self;
        match record.operation {
            JournalOperation::Put => {
                next.logical_objects = next.logical_objects.checked_add(1).ok_or_else(overflow)?;
                next.logical_bytes = next
                    .logical_bytes
                    .checked_add(length)
                    .ok_or_else(overflow)?;
                if pack_state.live_entries == 1 {
                    next.packs = next.packs.checked_add(1).ok_or_else(overflow)?;
                    next.physical_bytes = next
                        .physical_bytes
                        .checked_add(physical)
                        .ok_or_else(overflow)?;
                }
            }
            JournalOperation::Delete => {
                next.logical_objects = next.logical_objects.checked_sub(1).ok_or_else(underflow)?;
                next.logical_bytes = next
                    .logical_bytes
                    .checked_sub(length)
                    .ok_or_else(underflow)?;
                if pack_state.live_entries == 0 {
                    next.packs = next.packs.checked_sub(1).ok_or_else(underflow)?;
                    next.physical_bytes = next
                        .physical_bytes
                        .checked_sub(physical)
                        .ok_or_else(underflow)?;
                }
            }
        }
        Ok(next)
    }
}

/// Live entries and exact file length of one referenced pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PackState {
    pub(super) live_entries: u64,
    pub(super) physical_bytes: u64,
}

/// One base record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IndexRecord {
    pub(super) id: ContentId,
    pub(super) entry: IndexEntry,
}

impl SortedRecord for IndexRecord {
    type Key = ContentId;

    const FORMAT: SortedFileFormat = SortedFileFormat {
        magic: b"crucible.content-store.pack-index-base.v2\0",
        block_domain: b"crucible.content-store.pack-index-base-block.v2",
        trailer_domain: b"crucible.content-store.pack-index-base-trailer.v2",
        digest_domain: b"crucible.content-store.pack-index-base-digest.v2",
        record_width: CONTENT_ID_BYTES + 32 + 8 + 8,
        block_records: 48,
    };

    fn key(&self) -> ContentId {
        self.id
    }

    fn encode(&self, output: &mut [u8]) {
        let mut id = [0_u8; CONTENT_ID_BYTES];
        encode_content_id(self.id, &mut id);
        output[..37].copy_from_slice(&id);
        output[37..69].copy_from_slice(&self.entry.pack.0);
        output[69..77].copy_from_slice(&self.entry.offset.to_be_bytes());
        output[77..85].copy_from_slice(&self.entry.length.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let id = decode_content_id(bytes.get(..37).ok_or(StoreError::Incompatible)?)?;
        let mut cursor = PackedCursor::new(bytes.get(37..).ok_or(StoreError::Incompatible)?);
        let entry = IndexEntry {
            pack: PackId(cursor.array_32()?),
            offset: cursor.u64()?,
            length: cursor.u64()?,
        };
        if !cursor.is_empty() {
            return Err(StoreError::Incompatible);
        }
        validate_index_entry(entry)?;
        Ok(Self { id, entry })
    }
}

/// One pack-table record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PackRecord {
    pub(super) pack: PackId,
    pub(super) state: PackState,
}

impl SortedRecord for PackRecord {
    type Key = PackId;

    const FORMAT: SortedFileFormat = SortedFileFormat {
        magic: b"crucible.content-store.pack-table.v1\0",
        block_domain: b"crucible.content-store.pack-table-block.v1",
        trailer_domain: b"crucible.content-store.pack-table-trailer.v1",
        digest_domain: b"crucible.content-store.pack-table-digest.v1",
        record_width: 32 + 8 + 8,
        block_records: 85,
    };

    fn key(&self) -> PackId {
        self.pack
    }

    fn encode(&self, output: &mut [u8]) {
        output[..32].copy_from_slice(&self.pack.0);
        output[32..40].copy_from_slice(&self.state.live_entries.to_be_bytes());
        output[40..48].copy_from_slice(&self.state.physical_bytes.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut cursor = PackedCursor::new(bytes);
        let record = Self {
            pack: PackId(cursor.array_32()?),
            state: PackState {
                live_entries: cursor.u64()?,
                physical_bytes: cursor.u64()?,
            },
        };
        if !cursor.is_empty()
            || !(1..=MAX_PACK_ENTRIES as u64).contains(&record.state.live_entries)
            || !(1..=MAX_PACK_BYTES).contains(&record.state.physical_bytes)
        {
            return Err(StoreError::Incompatible);
        }
        Ok(record)
    }
}

/// Decoded authoritative root record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct IndexRoot {
    pub(super) instance: [u8; 32],
    pub(super) generation: u64,
    pub(super) last_repack_plan: Option<PackedRepackPlanId>,
    pub(super) base_digest: [u8; 32],
    pub(super) base_records: u64,
    pub(super) pack_table_digest: [u8; 32],
    pub(super) pack_table_records: u64,
    pub(super) journal_length: u64,
    pub(super) journal_records: u64,
    pub(super) journal_chain: [u8; 32],
    pub(super) totals: IndexTotals,
}

impl IndexRoot {
    pub(super) fn encode(&self, configuration: [u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(400);
        bytes.extend_from_slice(ROOT_MAGIC);
        bytes.extend_from_slice(&configuration);
        bytes.extend_from_slice(&self.instance);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        match self.last_repack_plan {
            None => bytes.push(0),
            Some(plan) => {
                bytes.push(1);
                bytes.extend_from_slice(&plan.0);
            }
        }
        bytes.extend_from_slice(&self.base_digest);
        bytes.extend_from_slice(&self.base_records.to_be_bytes());
        bytes.extend_from_slice(&self.pack_table_digest);
        bytes.extend_from_slice(&self.pack_table_records.to_be_bytes());
        bytes.extend_from_slice(&self.journal_length.to_be_bytes());
        bytes.extend_from_slice(&self.journal_records.to_be_bytes());
        bytes.extend_from_slice(&self.journal_chain);
        bytes.extend_from_slice(&self.totals.logical_objects.to_be_bytes());
        bytes.extend_from_slice(&self.totals.logical_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.totals.packs.to_be_bytes());
        bytes.extend_from_slice(&self.totals.physical_bytes.to_be_bytes());
        let mut hasher = blake3::Hasher::new();
        hasher.update(ROOT_CHECKSUM_DOMAIN);
        hasher.update(&bytes);
        bytes.extend_from_slice(hasher.finalize().as_bytes());
        bytes
    }

    pub(super) fn decode(bytes: &[u8], configuration: [u8; 32]) -> Result<Self, StoreError> {
        let (payload, checksum) = bytes
            .split_at_checked(
                bytes
                    .len()
                    .checked_sub(32)
                    .ok_or(StoreError::Incompatible)?,
            )
            .ok_or(StoreError::Incompatible)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(ROOT_CHECKSUM_DOMAIN);
        hasher.update(payload);
        if hasher.finalize().as_bytes() != checksum {
            return Err(StoreError::Incompatible);
        }

        let mut cursor = PackedCursor::new(payload);
        if cursor.fixed(ROOT_MAGIC.len())? != ROOT_MAGIC || cursor.array_32()? != configuration {
            return Err(StoreError::Incompatible);
        }
        let instance = cursor.array_32()?;
        let generation = cursor.u64()?;
        let last_repack_plan = match cursor.u8()? {
            0 => None,
            1 => Some(PackedRepackPlanId(cursor.array_32()?)),
            _ => return Err(StoreError::Incompatible),
        };
        let root = Self {
            instance,
            generation,
            last_repack_plan,
            base_digest: cursor.array_32()?,
            base_records: cursor.u64()?,
            pack_table_digest: cursor.array_32()?,
            pack_table_records: cursor.u64()?,
            journal_length: cursor.u64()?,
            journal_records: cursor.u64()?,
            journal_chain: cursor.array_32()?,
            totals: IndexTotals {
                logical_objects: cursor.u64()?,
                logical_bytes: cursor.u64()?,
                packs: cursor.u64()?,
                physical_bytes: cursor.u64()?,
            },
        };
        let journal_records_length = root
            .journal_records
            .checked_mul(JOURNAL_RECORD_BYTES as u64)
            .ok_or(StoreError::Incompatible)?;
        if !cursor.is_empty()
            || root.journal_length.checked_sub(journal_records_length)
                != Some(journal_header_length())
        {
            return Err(StoreError::Incompatible);
        }
        Ok(root)
    }
}

fn journal_header_length() -> u64 {
    journal_header([0; 32], [0; 32], [0; 32]).len() as u64
}
