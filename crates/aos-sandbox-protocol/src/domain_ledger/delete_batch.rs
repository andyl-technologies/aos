//! Borrowed, non-authorizing Delete batch, tombstone and collection DATA.
//!
//! The one codec is shared by native Controller CAS and Source replay:
//!
//! ```text
//! AOSDEL01 | header608 | W | R | C | E36 | P17 | checksum32
//! AOSDTS01 | pending tombstone128 | checksum32
//! AOSDCG01 | collection96 | checksum32
//! AOSDHF01 | native handoff128 | checksum32
//! ```
//!
//! Canonical bytes describe dependencies; neither a checksum nor a decoded
//! inventory authenticates a current graph, an owner, a floor or retirement.

use aos_sandbox_core::{OperationId, ProjectId};
use sha2::{Digest as _, Sha256};

use super::lifecycle_model::{
    LifecycleDependencyEdgeV1, LifecycleModelError, LifecycleResourceV1,
    canonical_dependency_postorder_is_complete,
};

pub const BATCH_PREFIX: &[u8] = b"aos.delete.batch.v1\0";
pub const TOMBSTONE_PREFIX: &[u8] = b"aos.delete.tombstone.v1\0";
pub(crate) const COLLECTION_PREFIX: &[u8] = b"aos.delete.collection.v1\0";
pub const HANDOFF_PREFIX: &[u8] = b"aos.delete.handoff.v1\0";

const BATCH_DOMAIN: &[u8] = b"aos.sandbox.delete.batch.v1\0";
const TOMBSTONE_DOMAIN: &[u8] = b"aos.sandbox.delete.tombstone.v1\0";
const COLLECTION_DOMAIN: &[u8] = b"aos.sandbox.delete.collection.v1\0";
const HANDOFF_DOMAIN: &[u8] = b"aos.sandbox.delete.handoff.v1\0";

const MAXIMUM_ROWS: usize = 4096;
const MAXIMUM_BYTES: usize = 2 * 1024 * 1024 - 1032;
const HEADER_BYTES: usize = 608;

/// Retains bounded canonical batch bytes without claiming their provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleDeleteBatchV1 {
    bytes: Vec<u8>,
    project: ProjectId,
    operation: OperationId,
}

impl LifecycleDeleteBatchV1 {
    /// Copies a structurally validated batch after all wire bounds are checked.
    ///
    /// # Errors
    ///
    /// Rejects malformed/noncanonical DATA or a failed checked allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        Self::from_view(DeleteBatchViewV1::decode(bytes)?)
    }

    fn from_view(view: DeleteBatchViewV1<'_>) -> Result<Self, LifecycleModelError> {
        let bytes = view.bytes();
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            project: view.project(),
            operation: view.operation(),
        })
    }

    /// Borrows the complete original canonical representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn project(&self) -> ProjectId {
        self.project
    }

    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    pub fn view(&self) -> Result<DeleteBatchViewV1<'_>, LifecycleModelError> {
        DeleteBatchViewV1::decode(&self.bytes)
    }
}

/// Retains the canonical selected Source auxiliary payload as DATA only.
///
/// A decoded native proof is not currentness. A protected producer must join it
/// to the same original native writer; groundwork supplies no such admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleDeleteBatchRecordV1 {
    state: u8,
    batch: LifecycleDeleteBatchV1,
    native_proof: [u8; 64],
}

impl LifecycleDeleteBatchRecordV1 {
    /// Decodes the exact bounded payload with its state-dependent proof shape.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical length, batch, reserved bytes or proof fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        if bytes.len() < 72 || !matches!(bytes[0], 1..=3) || !zero(&bytes[1..4]) {
            return Err(corrupt());
        }
        let length = number32(&bytes[4..8])? as usize;
        if length.checked_add(72) != Some(bytes.len()) {
            return Err(corrupt());
        }
        let view = DeleteBatchViewV1::decode(&bytes[8..8 + length])?;
        let proof = &bytes[8 + length..];
        match bytes[0] {
            1 if !zero(proof) => return Err(corrupt()),
            2 | 3 => {
                if zero(&proof[..16])
                    || zero(&proof[16..48])
                    || raw64(&proof[48..56]) == 0
                    || raw64(&proof[48..56]) == u64::MAX
                    || raw64(&proof[56..64]) == 0
                    || (proof[..16] == view.transaction()) != (bytes[0] == 2)
                {
                    return Err(corrupt());
                }
            }
            _ => {}
        }
        let mut native_proof = [0; 64];
        native_proof.copy_from_slice(proof);
        Ok(Self {
            state: bytes[0],
            batch: LifecycleDeleteBatchV1::from_view(view)?,
            native_proof,
        })
    }

    /// Encodes the same canonical payload without modifying its proof or epoch.
    ///
    /// # Errors
    ///
    /// Returns an allocation error before copying bounded payload bytes.
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleModelError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.encoded_length())
            .map_err(|_| LifecycleModelError::Allocation)?;
        bytes.extend_from_slice(&[self.state, 0, 0, 0]);
        bytes.extend_from_slice(&(self.batch.as_bytes().len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.batch.as_bytes());
        bytes.extend_from_slice(&self.native_proof);
        Ok(bytes)
    }

    /// Borrows the immutable selected batch DATA.
    #[must_use]
    pub const fn batch(&self) -> &LifecycleDeleteBatchV1 {
        &self.batch
    }

    /// Returns Planned(1), ControllerCommitted(2), or ControllerCancelled(3).
    #[must_use]
    pub const fn state(&self) -> u8 {
        self.state
    }

    /// Borrows exact original native proof bytes, not an append permission.
    #[must_use]
    pub const fn native_proof(&self) -> &[u8; 64] {
        &self.native_proof
    }

    pub fn encoded_length(&self) -> usize {
        72 + self.batch.as_bytes().len()
    }

    pub fn can_follow(&self, before: &Self) -> bool {
        self.batch == before.batch
            && (self == before || (before.state == 1 && matches!(self.state, 2 | 3)))
    }
}

/// Borrows one completely checked canonical batch; it carries no authority.
#[derive(Clone, Copy, Debug)]
pub struct DeleteBatchViewV1<'bytes> {
    bytes: &'bytes [u8],
    sections: [&'bytes [u8]; 5],
    counts: [usize; 5],
}

impl<'bytes> DeleteBatchViewV1<'bytes> {
    pub fn decode(bytes: &'bytes [u8]) -> Result<Self, LifecycleModelError> {
        if bytes.len() < 640
            || bytes.len() > MAXIMUM_BYTES
            || &bytes[..8] != b"AOSDEL01"
            || bytes[8..10] != [0, 1]
            || bytes[10] > 3
            || bytes[11] != 0
            || number32(&bytes[12..16])? as usize != bytes.len()
            || !zero(&bytes[81..88])
            || !zero(&bytes[316..320])
            || zero(&bytes[16..32])
            || zero(&bytes[32..48])
            || zero(&bytes[48..64])
            || bytes[64] != 1
            || resource(&bytes[64..81]).is_err()
            || bytes[104..296].chunks_exact(32).any(zero)
        {
            return Err(corrupt());
        }
        checksum(bytes, BATCH_DOMAIN)?;

        let mut counts = [0; 5];
        for (index, count) in counts.iter_mut().enumerate() {
            *count = number32(&bytes[296 + index * 4..300 + index * 4])? as usize;
            if *count > MAXIMUM_ROWS {
                return Err(corrupt());
            }
        }
        if counts[0] == 0
            || counts[4] != counts[0]
            || counts[..3]
                .iter()
                .try_fold(0_usize, |n, c| n.checked_add(*c))
                .is_none_or(|n| n > MAXIMUM_ROWS)
        {
            return Err(corrupt());
        }
        for (index, descriptor) in bytes[320..608].chunks_exact(48).enumerate() {
            if descriptor[0] as usize != index + 1
                || !zero(&descriptor[1..4])
                || number64(&descriptor[4..12])? == u64::MAX
                || number32(&descriptor[12..16])? as usize > MAXIMUM_ROWS
                || zero(&descriptor[16..48])
            {
                return Err(corrupt());
            }
        }

        // Section slicing checks every count and variable key before graph
        // allocation. The iterator below only traverses these validated slices.
        let body_end = bytes.len() - 32;
        let mut offset = HEADER_BYTES;
        let mut sections = [&bytes[0..0]; 5];
        for index in 0..5 {
            let start = offset;
            for _ in 0..counts[index] {
                let fixed = match index {
                    0 | 2 => 100,
                    1 => 56,
                    3 => 36,
                    _ => 17,
                };
                let fixed_end = offset
                    .checked_add(fixed)
                    .filter(|end| *end <= body_end)
                    .ok_or_else(corrupt)?;
                let key_length = if index < 3 {
                    let length = number16(&bytes[offset + 18..offset + 20])? as usize;
                    if length == 0 || length > 1024 {
                        return Err(corrupt());
                    }
                    length
                } else {
                    0
                };
                offset = fixed_end
                    .checked_add(key_length)
                    .filter(|end| *end <= body_end)
                    .ok_or_else(corrupt)?;
            }
            sections[index] = &bytes[start..offset];
        }
        if offset != body_end {
            return Err(corrupt());
        }
        let view = Self {
            bytes,
            sections,
            counts,
        };
        view.validate_rows()?;
        if view.graph_digest() != bytes[264..296] {
            return Err(corrupt());
        }
        Ok(view)
    }

    pub fn project(self) -> ProjectId {
        ProjectId::from_bytes(array16(&self.bytes[16..32]))
    }

    pub fn operation(self) -> OperationId {
        OperationId::from_bytes(array16(&self.bytes[32..48]))
    }

    pub fn transaction(self) -> [u8; 16] {
        array16(&self.bytes[48..64])
    }

    pub fn before_sequence(self) -> u64 {
        raw64(&self.bytes[88..96])
    }

    pub fn request_digest(self) -> [u8; 32] {
        array32(&self.bytes[104..136])
    }

    pub fn graph_plan(self) -> [u8; 32] {
        array32(&self.bytes[264..296])
    }

    pub fn flags(self) -> u8 {
        self.bytes[10]
    }

    pub fn root(self) -> Result<LifecycleResourceV1, LifecycleModelError> {
        resource(&self.bytes[64..81])
    }

    pub(crate) fn checksum(self) -> [u8; 32] {
        array32(&self.bytes[self.bytes.len() - 32..])
    }

    pub fn bytes(self) -> &'bytes [u8] {
        self.bytes
    }

    pub fn count(self, section: usize) -> usize {
        self.counts[section]
    }

    pub fn rows(self, section: usize) -> DeleteRowsV1<'bytes> {
        DeleteRowsV1 {
            remaining: self.sections[section],
            section,
        }
    }

    fn validate_rows(self) -> Result<(), LifecycleModelError> {
        for section in 0..3 {
            let mut previous = None;
            for row in self.rows(section) {
                resource(&row[..17])?;
                let namespace = if section == 2 { 1 } else { row[17] };
                let key = row_key(row, section);
                if namespace == 0
                    || namespace > 76
                    || previous.is_some_and(|last| last >= (namespace, key))
                {
                    return Err(corrupt());
                }
                previous = Some((namespace, key));
                match section {
                    0 => {
                        if row[17] != 1
                            || !matches!(row[0], 1..=5)
                            || !successor(raw64(&row[20..28]), raw64(&row[60..68]))
                            || zero(&row[28..60])
                            || zero(&row[68..100])
                            || self
                                .rows(0)
                                .filter(|other| other[..17] == row[..17])
                                .count()
                                != 1
                            || self
                                .rows(1)
                                .any(|other| other[17] == row[17] && row_key(other, 1) == key)
                        {
                            return Err(corrupt());
                        }
                    }
                    1 => {
                        if row[20] > 1
                            || !zero(&row[21..24])
                            || zero(&row[24..56]) != (row[20] == 0)
                        {
                            return Err(corrupt());
                        }
                    }
                    _ => {
                        if !matches!(row[17], 1..=6)
                            || !successor(raw64(&row[20..28]), raw64(&row[60..68]))
                            || zero(&row[28..60])
                            || zero(&row[68..100])
                            || key != collection_key(self.project(), &row[..17], row[17]).as_slice()
                        {
                            return Err(corrupt());
                        }
                    }
                }
            }
        }

        let mut edges = Vec::new();
        edges
            .try_reserve_exact(self.counts[3])
            .map_err(|_| LifecycleModelError::Allocation)?;
        let mut previous = None;
        for row in self.rows(3) {
            let left = resource(&row[..17])?;
            let right = resource(&row[17..34])?;
            if !matches!(row[34], 1..=6)
                || row[35] != 0
                || previous.is_some_and(|last| last >= row)
                || !self.contains_resource(&row[..17])
                || !self.contains_resource(&row[17..34])
            {
                return Err(corrupt());
            }
            previous = Some(row);
            if self.is_written(&row[..17]) && self.is_written(&row[17..34]) {
                edges.push(LifecycleDependencyEdgeV1::new(left, right)?);
            }
        }
        let mut postorder = Vec::new();
        postorder
            .try_reserve_exact(self.counts[4])
            .map_err(|_| LifecycleModelError::Allocation)?;
        for row in self.rows(4) {
            let value = resource(row)?;
            if !self.is_written(row) || postorder.contains(&value) {
                return Err(corrupt());
            }
            postorder.push(value);
        }
        if postorder.last().copied() != Some(self.root()?)
            || !canonical_dependency_postorder_is_complete(&edges, &postorder)
        {
            return Err(corrupt());
        }
        Ok(())
    }

    fn is_written(self, value: &[u8]) -> bool {
        self.rows(0).any(|row| &row[..17] == value)
    }

    fn contains_resource(self, value: &[u8]) -> bool {
        self.is_written(value) || self.rows(1).any(|row| &row[..17] == value)
    }

    fn graph_digest(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.delete.graph-plan.v1\0");
        digest.update(&self.bytes[16..32]);
        digest.update(&self.bytes[10..11]);
        digest.update(&self.bytes[64..81]);
        digest.update(&self.bytes[88..104]);
        digest.update(&self.bytes[168..264]);
        digest.update(&self.bytes[320..608]);
        digest.update(&self.bytes[296..316]);
        for section in 0..5 {
            for row in self.rows(section) {
                if section == 0 || section == 2 {
                    digest.update(&row[..60]);
                    digest.update(row_key(row, section));
                } else {
                    digest.update(row);
                }
            }
        }
        digest.finalize().into()
    }
}

pub struct DeleteRowsV1<'bytes> {
    remaining: &'bytes [u8],
    section: usize,
}

impl<'bytes> Iterator for DeleteRowsV1<'bytes> {
    type Item = &'bytes [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let fixed = match self.section {
            0 | 2 => 100,
            1 => 56,
            3 => 36,
            _ => 17,
        };
        let key = if self.section < 3 {
            usize::from(u16::from_be_bytes([self.remaining[18], self.remaining[19]]))
        } else {
            0
        };
        let (row, remaining) = self.remaining.split_at(fixed + key);
        self.remaining = remaining;
        Some(row)
    }
}

pub fn row_key(row: &[u8], section: usize) -> &[u8] {
    &row[if section == 1 { 56 } else { 100 }..]
}

pub fn batch_key(project: ProjectId, operation: OperationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(52);
    key.extend_from_slice(BATCH_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(operation.as_bytes());
    key
}

pub fn tombstone_key(project: ProjectId, value: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(57);
    key.extend_from_slice(TOMBSTONE_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(value);
    key
}

pub(crate) fn collection_key(project: ProjectId, owner: &[u8], class: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(59);
    key.extend_from_slice(COLLECTION_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(owner);
    key.push(class);
    key
}

pub fn handoff_key(project: ProjectId, operation: OperationId) -> [u8; 54] {
    let mut key = [0; 54];
    key[..22].copy_from_slice(HANDOFF_PREFIX);
    key[22..38].copy_from_slice(project.as_bytes());
    key[38..].copy_from_slice(operation.as_bytes());
    key
}

/// Validates retained handoff DATA without authenticating its Source reference.
pub fn validate_handoff(
    bytes: &[u8],
    batch: DeleteBatchViewV1<'_>,
) -> Result<(), LifecycleModelError> {
    if bytes.len() != 160
        || &bytes[..8] != b"AOSDHF01"
        || bytes[8..11] != [0, 1, 1]
        || !zero(&bytes[11..16])
        || bytes[16..32] != batch.project().as_bytes()[..]
        || bytes[32..48] != batch.operation().as_bytes()[..]
        || bytes[48..64] != batch.transaction()
        || bytes[64..96] != batch.checksum()
        || zero(&bytes[96..128])
    {
        return Err(corrupt());
    }
    checksum(bytes, HANDOFF_DOMAIN)
}

pub fn tombstone(batch: DeleteBatchViewV1<'_>, row: &[u8]) -> [u8; 160] {
    let mut bytes = [0; 160];
    bytes[..8].copy_from_slice(b"AOSDTS01");
    bytes[9] = 1;
    bytes[10] = 1;
    bytes[12..28].copy_from_slice(batch.project().as_bytes());
    bytes[28..44].copy_from_slice(batch.operation().as_bytes());
    bytes[44..60].copy_from_slice(&batch.transaction());
    bytes[60..77].copy_from_slice(&row[..17]);
    bytes[80..88].copy_from_slice(&row[20..28]);
    bytes[88..96].copy_from_slice(&row[60..68]);
    bytes[96..128].copy_from_slice(&row[28..60]);
    seal(&mut bytes, TOMBSTONE_DOMAIN);
    bytes
}

pub(crate) fn validate_tombstone(bytes: &[u8]) -> Result<(), LifecycleModelError> {
    if bytes.len() != 160
        || &bytes[..8] != b"AOSDTS01"
        || bytes[8..12] != [0, 1, 1, 0]
        || zero(&bytes[12..28])
        || zero(&bytes[28..44])
        || zero(&bytes[44..60])
        || !zero(&bytes[77..80])
        || resource(&bytes[60..77]).is_err()
        || !successor(raw64(&bytes[80..88]), raw64(&bytes[88..96]))
        || zero(&bytes[96..128])
    {
        return Err(corrupt());
    }
    checksum(bytes, TOMBSTONE_DOMAIN)
}

pub fn collection(project: ProjectId, row: &[u8], after: bool) -> [u8; 128] {
    let mut bytes = [0; 128];
    bytes[..8].copy_from_slice(b"AOSDCG01");
    bytes[9] = 1;
    bytes[10] = row[17];
    bytes[16..32].copy_from_slice(project.as_bytes());
    bytes[32..49].copy_from_slice(&row[..17]);
    let start = if after { 60 } else { 20 };
    bytes[56..96].copy_from_slice(&row[start..start + 40]);
    seal(&mut bytes, COLLECTION_DOMAIN);
    bytes
}

pub(crate) fn validate_collection(bytes: &[u8]) -> Result<(), LifecycleModelError> {
    if bytes.len() != 128
        || &bytes[..8] != b"AOSDCG01"
        || bytes[8..10] != [0, 1]
        || !matches!(bytes[10], 1..=6)
        || !zero(&bytes[11..16])
        || zero(&bytes[16..32])
        || resource(&bytes[32..49]).is_err()
        || !zero(&bytes[49..56])
        || raw64(&bytes[56..64]) == 0
        || raw64(&bytes[56..64]) == u64::MAX
        || zero(&bytes[64..96])
    {
        return Err(corrupt());
    }
    checksum(bytes, COLLECTION_DOMAIN)
}

/// Borrows one existing canonical member without asserting complete membership.
pub(crate) struct DeleteCollectionMemberV1<'bytes> {
    pub(crate) owner: u8,
    pub(crate) namespace: u8,
    pub(crate) key: &'bytes [u8],
    pub(crate) value: &'bytes [u8],
}

pub(crate) fn collection_root(
    project: ProjectId,
    owner: LifecycleResourceV1,
    class: u8,
    members: &[DeleteCollectionMemberV1<'_>],
) -> Result<[u8; 32], LifecycleModelError> {
    if !matches!(class, 1..=6) || members.len() > MAXIMUM_ROWS {
        return Err(corrupt());
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.delete.collection-members.v1\0");
    digest.update(project.as_bytes());
    digest.update([owner.code()]);
    digest.update(owner.as_bytes());
    digest.update([class]);
    digest.update((members.len() as u32).to_be_bytes());
    let mut previous = None;
    for member in members {
        let identity = (member.owner, member.namespace, member.key);
        if !matches!(member.owner, 1..=8)
            || member.namespace == 0
            || member.namespace > 76
            || member.key.is_empty()
            || member.key.len() > 1024
            || previous.is_some_and(|last| last >= identity)
            || matches!(member.namespace, 2..=4)
            || member.key.starts_with(BATCH_PREFIX)
            || member.key.starts_with(COLLECTION_PREFIX)
            || member.key.starts_with(HANDOFF_PREFIX)
        {
            return Err(corrupt());
        }
        // Actual logical tombstone overlays are membership DATA. Excluding
        // them would lose the before/after collection join; metadata and the
        // collection's own commitment remain excluded to avoid hash cycles.
        previous = Some(identity);
        digest.update([member.owner, member.namespace]);
        digest.update((member.key.len() as u16).to_be_bytes());
        digest.update(member.key);
        digest.update(Sha256::digest(member.value));
    }
    Ok(digest.finalize().into())
}

pub fn reserved_key(key: &[u8]) -> bool {
    key.starts_with(BATCH_PREFIX)
        || key.starts_with(TOMBSTONE_PREFIX)
        || key.starts_with(COLLECTION_PREFIX)
        || key.starts_with(HANDOFF_PREFIX)
}

pub fn native_value_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn raw64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(bytes);
    u64::from_be_bytes(value)
}

fn successor(before: u64, after: u64) -> bool {
    before != 0 && after != u64::MAX && before.checked_add(1) == Some(after)
}

pub(crate) fn resource(bytes: &[u8]) -> Result<LifecycleResourceV1, LifecycleModelError> {
    if bytes.len() != 17 {
        return Err(corrupt());
    }
    LifecycleResourceV1::from_code(bytes[0], array16(&bytes[1..17]))
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn corrupt() -> LifecycleModelError {
    LifecycleModelError::CorruptEncoding
}

fn array16(bytes: &[u8]) -> [u8; 16] {
    let mut value = [0; 16];
    value.copy_from_slice(bytes);
    value
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(bytes);
    value
}

fn number16(bytes: &[u8]) -> Result<u16, LifecycleModelError> {
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| corrupt())?))
}

fn number32(bytes: &[u8]) -> Result<u32, LifecycleModelError> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| corrupt())?))
}

fn number64(bytes: &[u8]) -> Result<u64, LifecycleModelError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| corrupt())?))
}

fn checksum(bytes: &[u8], domain: &[u8]) -> Result<(), LifecycleModelError> {
    let end = bytes.len() - 32;
    if Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..end])
        .finalize()[..]
        != bytes[end..]
    {
        return Err(corrupt());
    }
    Ok(())
}

fn seal(bytes: &mut [u8], domain: &[u8]) {
    let end = bytes.len() - 32;
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..end])
        .finalize();
    bytes[end..].copy_from_slice(&digest);
}

#[cfg(any(test, feature = "test-fixtures"))]
mod fixture;
#[cfg(any(test, feature = "test-fixtures"))]
pub use fixture::fixture_batch_v1;

#[cfg(test)]
mod tests;
