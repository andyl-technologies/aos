//! Fixed-width Packed placement pages and their committed root descriptor.
//!
//! Physical fields use explicit big-endian bytes rather than native layouts.
//! A root commits either a small inline leaf or immutable arena pages:
//!
//! ```text
//! root = header | inline-leaf-or-page-reference | checksum
//! leaf = page-header | (full-key, value)* | checksum
//! branch = page-header | (upper-key, page-reference)* | checksum
//! ```

use super::*;

pub(super) const PAGE_BYTES: usize = 8_192;
pub(super) const MAX_ROWS: usize = 64;
pub(super) const MIN_ROWS: usize = 16;
pub(super) const MAX_HEIGHT: usize = 16;
pub(super) const KEY_BYTES: usize = 38;
pub(super) const VALUE_BYTES: usize = 48;
pub(super) const LEAF_ROW_BYTES: usize = KEY_BYTES + VALUE_BYTES;
pub(super) const REFERENCE_BYTES: usize = 53;
pub(super) const BRANCH_ROW_BYTES: usize = KEY_BYTES + REFERENCE_BYTES;
pub(super) const PAGE_HEADER_BYTES: usize = 28;
pub(super) const ROOT_HEADER_BYTES: usize = 207;

const ROOT_MAGIC: &[u8; 16] = b"CRUCPIDXROOT0002";
const PAGE_MAGIC: &[u8; 16] = b"CRUCPIDXPAGE0002";
const ROOT_DOMAIN: &[u8] = b"crucible.content-store.packed-root.v2";
const PAGE_DOMAIN: &[u8] = b"crucible.content-store.packed-page.v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key(pub(super) [u8; KEY_BYTES]);

impl Key {
    pub(super) fn object(id: ContentId) -> Self {
        let mut bytes = [0; KEY_BYTES];
        bytes[1] = kind_code(id.kind());
        bytes[2..6].copy_from_slice(&id.schema_version().to_be_bytes());
        bytes[6..].copy_from_slice(&id.digest());
        Self(bytes)
    }

    pub(super) fn pack(pack: PackId) -> Self {
        let mut bytes = [0; KEY_BYTES];
        bytes[0] = 1;
        bytes[1..33].copy_from_slice(&pack.0);
        Self(bytes)
    }

    pub(super) fn id(self) -> Result<ContentId, StoreError> {
        if self.0[0] != 0 {
            return Err(StoreError::Incompatible);
        }
        Ok(ContentId {
            kind: decode_kind(self.0[1])?,
            schema_version: u32::from_be_bytes(array(&self.0[2..6])?),
            digest: array(&self.0[6..])?,
        })
    }

    pub(super) fn pack_id(self) -> Result<PackId, StoreError> {
        if self.0[0] != 1 || self.0[33..] != [0; 5] {
            return Err(StoreError::Incompatible);
        }
        Ok(PackId(array(&self.0[1..33])?))
    }

    fn validate(self) -> Result<(), StoreError> {
        match self.0[0] {
            0 => self.id().map(|_| ()),
            1 => self.pack_id().map(|_| ()),
            _ => Err(StoreError::Incompatible),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PackRecord {
    pub(super) physical_bytes: u64,
    pub(super) objects: u64,
    pub(super) logical_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Value(pub(super) [u8; VALUE_BYTES]);

impl Value {
    pub(super) fn validate_for(self, key: Key) -> Result<(), StoreError> {
        key.validate()?;
        if key.0[0] == 0 {
            let entry = self.entry()?;
            entry
                .offset
                .checked_add(entry.length)
                .filter(|end| *end <= MAX_PACK_BYTES)
                .ok_or(StoreError::Incompatible)?;
        } else {
            let record = self.pack_record()?;
            if record.objects == 0 || record.physical_bytes > MAX_PACK_BYTES {
                return Err(StoreError::Incompatible);
            }
        }
        Ok(())
    }

    pub(super) fn object(entry: IndexEntry) -> Self {
        let mut bytes = [0; VALUE_BYTES];
        bytes[..32].copy_from_slice(&entry.pack.0);
        bytes[32..40].copy_from_slice(&entry.offset.to_be_bytes());
        bytes[40..].copy_from_slice(&entry.length.to_be_bytes());
        Self(bytes)
    }

    pub(super) fn entry(self) -> Result<IndexEntry, StoreError> {
        Ok(IndexEntry {
            pack: PackId(array(&self.0[..32])?),
            offset: u64::from_be_bytes(array(&self.0[32..40])?),
            length: u64::from_be_bytes(array(&self.0[40..])?),
        })
    }

    pub(super) fn pack(record: PackRecord) -> Self {
        let mut bytes = [0; VALUE_BYTES];
        bytes[..8].copy_from_slice(&record.physical_bytes.to_be_bytes());
        bytes[8..16].copy_from_slice(&record.objects.to_be_bytes());
        bytes[16..24].copy_from_slice(&record.logical_bytes.to_be_bytes());
        Self(bytes)
    }

    pub(super) fn pack_record(self) -> Result<PackRecord, StoreError> {
        if self.0[24..] != [0; 24] {
            return Err(StoreError::Incompatible);
        }
        Ok(PackRecord {
            physical_bytes: u64::from_be_bytes(array(&self.0[..8])?),
            objects: u64::from_be_bytes(array(&self.0[8..16])?),
            logical_bytes: u64::from_be_bytes(array(&self.0[16..24])?),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PageReference {
    pub(super) offset: u64,
    pub(super) length: u32,
    pub(super) digest: [u8; 32],
    pub(super) records: u64,
    pub(super) height: u8,
}

impl PageReference {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != REFERENCE_BYTES {
            return Err(StoreError::Incompatible);
        }
        Ok(Self {
            offset: u64::from_be_bytes(array(&bytes[..8])?),
            length: u32::from_be_bytes(array(&bytes[8..12])?),
            digest: array(&bytes[12..44])?,
            records: u64::from_be_bytes(array(&bytes[44..52])?),
            height: bytes[52],
        })
    }

    pub(super) fn append(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.offset.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.records.to_be_bytes());
        bytes.push(self.height);
    }

    pub(super) fn validate(self, committed_bytes: u64) -> Result<(), StoreError> {
        if self.length as usize > PAGE_BYTES
            || (self.length as usize) < PAGE_HEADER_BYTES + 32
            || self.height as usize >= MAX_HEIGHT
            || self.records == 0
            || self
                .offset
                .checked_add(self.length as u64)
                .is_none_or(|end| end > committed_bytes)
        {
            return Err(StoreError::Incompatible);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) instance: [u8; 32],
    pub(super) generation: u64,
    pub(super) last_repack_plan: Option<PackedRepackPlanId>,
    pub(super) arena: Option<[u8; 32]>,
    pub(super) committed_bytes: u64,
    pub(super) count: u64,
    pub(super) logical_bytes: u64,
    pub(super) packs: u64,
    pub(super) physical_bytes: u64,
    pub(super) records: u64,
    pub(super) height: u8,
}

impl Header {
    pub(super) fn empty(instance: [u8; 32]) -> Self {
        Self {
            instance,
            generation: 0,
            last_repack_plan: None,
            arena: None,
            committed_bytes: 0,
            count: 0,
            logical_bytes: 0,
            packs: 0,
            physical_bytes: 0,
            records: 0,
            height: 0,
        }
    }

    pub(super) fn require_version(bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.len() < ROOT_MAGIC.len() {
            return Err(StoreError::Incompatible);
        }
        if &bytes[..ROOT_MAGIC.len()] != ROOT_MAGIC {
            return Err(StoreError::Unsupported {
                capability: "packed-index-version",
            });
        }
        Ok(())
    }

    pub(super) fn decode(bytes: &[u8], configuration: [u8; 32]) -> Result<Self, StoreError> {
        Self::require_version(bytes)?;
        if bytes.len() < ROOT_HEADER_BYTES + REFERENCE_BYTES + 32 || bytes.len() > PAGE_BYTES {
            return Err(StoreError::Incompatible);
        }
        verify_checksum(ROOT_DOMAIN, bytes)?;
        if bytes[16..48] != configuration {
            return Err(StoreError::Incompatible);
        }
        let optional = |tag, value: &[u8]| -> Result<Option<[u8; 32]>, StoreError> {
            match tag {
                0 if value == [0; 32] => Ok(None),
                1 => Ok(Some(array(value)?)),
                _ => Err(StoreError::Incompatible),
            }
        };
        let header = Self {
            instance: array(&bytes[48..80])?,
            generation: u64::from_be_bytes(array(&bytes[80..88])?),
            last_repack_plan: optional(bytes[88], &bytes[89..121])?.map(PackedRepackPlanId),
            arena: optional(bytes[121], &bytes[122..154])?,
            committed_bytes: number(bytes, 154)?,
            count: number(bytes, 162)?,
            logical_bytes: number(bytes, 170)?,
            packs: number(bytes, 178)?,
            physical_bytes: number(bytes, 186)?,
            records: number(bytes, 194)?,
            height: bytes[202],
        };
        let body_length = u32::from_be_bytes(array(&bytes[203..207])?) as usize;
        if header.height as usize >= MAX_HEIGHT
            || header.count.checked_add(header.packs) != Some(header.records)
            || ROOT_HEADER_BYTES
                .checked_add(body_length)
                .and_then(|n| n.checked_add(32))
                != Some(bytes.len())
        {
            return Err(StoreError::Incompatible);
        }
        let body = &bytes[ROOT_HEADER_BYTES..bytes.len() - 32];
        match header.arena {
            None => {
                let node = Node::parse(body, true)?;
                if node.height != 0
                    || node.records != header.records
                    || header.committed_bytes != 0
                    || header.height != 0
                {
                    return Err(StoreError::Incompatible);
                }
            }
            Some(_) => {
                let reference = PageReference::decode(body)?;
                reference.validate(header.committed_bytes)?;
                if reference.height != header.height || reference.records != header.records {
                    return Err(StoreError::Incompatible);
                }
            }
        }
        Ok(header)
    }

    pub(super) fn append(
        self,
        configuration: [u8; 32],
        body: &[u8],
        bytes: &mut Vec<u8>,
    ) -> Result<(), StoreError> {
        bytes.clear();
        if ROOT_HEADER_BYTES + body.len() + 32 > bytes.capacity() {
            return Err(StoreError::Quota);
        }
        bytes.extend_from_slice(ROOT_MAGIC);
        bytes.extend_from_slice(&configuration);
        bytes.extend_from_slice(&self.instance);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.push(u8::from(self.last_repack_plan.is_some()));
        bytes.extend_from_slice(&self.last_repack_plan.map_or([0; 32], |p| p.0));
        bytes.push(u8::from(self.arena.is_some()));
        bytes.extend_from_slice(&self.arena.unwrap_or([0; 32]));
        for number in [
            self.committed_bytes,
            self.count,
            self.logical_bytes,
            self.packs,
            self.physical_bytes,
            self.records,
        ] {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
        bytes.push(self.height);
        bytes.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| StoreError::Quota)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(body);
        append_checksum(ROOT_DOMAIN, bytes);
        Ok(())
    }
}

pub(super) struct Node<'a> {
    bytes: &'a [u8],
    pub(super) height: u8,
    pub(super) count: usize,
    pub(super) records: u64,
}

impl<'a> Node<'a> {
    pub(super) fn parse(bytes: &'a [u8], root: bool) -> Result<Self, StoreError> {
        Self::parse_inner(bytes, root, false)
    }

    pub(super) fn parse_pending(bytes: &'a [u8]) -> Result<Self, StoreError> {
        Self::parse_inner(bytes, true, true)
    }

    fn parse_inner(bytes: &'a [u8], root: bool, pending: bool) -> Result<Self, StoreError> {
        if bytes.len() < PAGE_HEADER_BYTES + 32
            || bytes.len() > PAGE_BYTES
            || &bytes[..16] != PAGE_MAGIC
        {
            return Err(StoreError::Incompatible);
        }
        verify_checksum(PAGE_DOMAIN, bytes)?;
        let height = bytes[17];
        let count = u16::from_be_bytes(array(&bytes[18..20])?) as usize;
        let row_bytes = if height == 0 {
            LEAF_ROW_BYTES
        } else {
            BRANCH_ROW_BYTES
        };
        if height as usize >= MAX_HEIGHT
            || bytes[16] != u8::from(height != 0)
            || count > MAX_ROWS
            || (!root && count < MIN_ROWS)
            || (height != 0 && count < if pending { 1 } else { 2 })
            || PAGE_HEADER_BYTES + count * row_bytes + 32 != bytes.len()
        {
            return Err(StoreError::Incompatible);
        }
        let records = number(bytes, 20)?;
        let node = Self {
            bytes,
            height,
            count,
            records,
        };
        let mut prior = None;
        let mut observed = 0_u64;
        for slot in 0..count {
            let key = node.key(slot)?;
            key.validate()?;
            if prior.is_some_and(|p| p >= key) {
                return Err(StoreError::Incompatible);
            }
            prior = Some(key);
            if height == 0 {
                node.value(slot)?.validate_for(key)?;
                observed = observed.checked_add(1).ok_or(StoreError::Quota)?;
            } else {
                let child = node.child(slot)?;
                if child.height.checked_add(1) != Some(height)
                    || child.records == 0
                    || child.length as usize > PAGE_BYTES
                {
                    return Err(StoreError::Incompatible);
                }
                observed = observed
                    .checked_add(child.records)
                    .ok_or(StoreError::Quota)?;
            }
        }
        if observed != records {
            return Err(StoreError::Incompatible);
        }
        Ok(node)
    }

    pub(super) fn key(&self, slot: usize) -> Result<Key, StoreError> {
        Ok(Key(array(
            self.row(slot)?
                .get(..KEY_BYTES)
                .ok_or(StoreError::Incompatible)?,
        )?))
    }

    pub(super) fn value(&self, slot: usize) -> Result<Value, StoreError> {
        if self.height != 0 {
            return Err(StoreError::Incompatible);
        }
        Ok(Value(array(&self.row(slot)?[KEY_BYTES..])?))
    }

    pub(super) fn child(&self, slot: usize) -> Result<PageReference, StoreError> {
        if self.height == 0 {
            return Err(StoreError::Incompatible);
        }
        PageReference::decode(&self.row(slot)?[KEY_BYTES..])
    }

    pub(super) fn row(&self, slot: usize) -> Result<&'a [u8], StoreError> {
        if slot >= self.count {
            return Err(StoreError::Incompatible);
        }
        let width = if self.height == 0 {
            LEAF_ROW_BYTES
        } else {
            BRANCH_ROW_BYTES
        };
        self.bytes
            .get(PAGE_HEADER_BYTES + slot * width..PAGE_HEADER_BYTES + (slot + 1) * width)
            .ok_or(StoreError::Incompatible)
    }

    pub(super) fn payload(&self) -> &'a [u8] {
        &self.bytes[PAGE_HEADER_BYTES..self.bytes.len() - 32]
    }

    pub(super) fn validate_children_before(&self, offset: u64) -> Result<(), StoreError> {
        if self.height == 0 {
            return Ok(());
        }
        for slot in 0..self.count {
            self.child(slot)?.validate(offset)?;
        }
        Ok(())
    }

    pub(super) fn position(&self, key: Key) -> Result<usize, StoreError> {
        for slot in 0..self.count {
            if self.key(slot)? >= key {
                return Ok(slot);
            }
        }
        Ok(self.count)
    }
}

pub(super) fn begin_node(bytes: &mut Vec<u8>, height: u8) {
    bytes.clear();
    bytes.extend_from_slice(PAGE_MAGIC);
    bytes.push(u8::from(height != 0));
    bytes.push(height);
    bytes.extend_from_slice(&[0; 10]);
}

pub(super) fn finish_node(
    bytes: &mut Vec<u8>,
    count: usize,
    records: u64,
) -> Result<(), StoreError> {
    if count > MAX_ROWS || bytes.len() + 32 > bytes.capacity() {
        return Err(StoreError::Quota);
    }
    bytes[18..20].copy_from_slice(
        &u16::try_from(count)
            .map_err(|_| StoreError::Quota)?
            .to_be_bytes(),
    );
    bytes[20..28].copy_from_slice(&records.to_be_bytes());
    append_checksum(PAGE_DOMAIN, bytes);
    Ok(())
}

pub(super) fn page_digest(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    array(
        bytes
            .get(
                bytes
                    .len()
                    .checked_sub(32)
                    .ok_or(StoreError::Incompatible)?..,
            )
            .ok_or(StoreError::Incompatible)?,
    )
}

fn number(bytes: &[u8], offset: usize) -> Result<u64, StoreError> {
    Ok(u64::from_be_bytes(array(
        bytes
            .get(offset..offset + 8)
            .ok_or(StoreError::Incompatible)?,
    )?))
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Incompatible)
}

fn append_checksum(domain: &[u8], bytes: &mut Vec<u8>) {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(bytes);
    bytes.extend_from_slice(hash.finalize().as_bytes());
}

fn verify_checksum(domain: &[u8], bytes: &[u8]) -> Result<(), StoreError> {
    let split = bytes
        .len()
        .checked_sub(32)
        .ok_or(StoreError::Incompatible)?;
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(&bytes[..split]);
    if hash.finalize().as_bytes() != &bytes[split..] {
        return Err(StoreError::Incompatible);
    }
    Ok(())
}

fn kind_code(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::CampaignFact => 0,
        ObjectKind::CampaignSnapshot => 1,
        ObjectKind::MerkleNode => 2,
        ObjectKind::Scenario => 3,
        ObjectKind::Configuration => 4,
        ObjectKind::Policy => 5,
        ObjectKind::ExactManifest => 6,
        ObjectKind::RamExtent => 7,
        ObjectKind::RamTree => 8,
        ObjectKind::DiskExtent => 9,
        ObjectKind::DeviceState => 10,
        ObjectKind::Observation => 11,
        ObjectKind::Finding => 12,
        ObjectKind::Projection => 13,
        ObjectKind::Trace => 14,
    }
}

fn decode_kind(code: u8) -> Result<ObjectKind, StoreError> {
    match code {
        0 => Ok(ObjectKind::CampaignFact),
        1 => Ok(ObjectKind::CampaignSnapshot),
        2 => Ok(ObjectKind::MerkleNode),
        3 => Ok(ObjectKind::Scenario),
        4 => Ok(ObjectKind::Configuration),
        5 => Ok(ObjectKind::Policy),
        6 => Ok(ObjectKind::ExactManifest),
        7 => Ok(ObjectKind::RamExtent),
        8 => Ok(ObjectKind::RamTree),
        9 => Ok(ObjectKind::DiskExtent),
        10 => Ok(ObjectKind::DeviceState),
        11 => Ok(ObjectKind::Observation),
        12 => Ok(ObjectKind::Finding),
        13 => Ok(ObjectKind::Projection),
        14 => Ok(ObjectKind::Trace),
        _ => Err(StoreError::Incompatible),
    }
}
