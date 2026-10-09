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

use super::{LifecycleDependencyEdgeV1, LifecycleModelError, LifecycleResourceV1};

pub(crate) const BATCH_PREFIX: &[u8] = b"aos.delete.batch.v1\0";
pub(crate) const TOMBSTONE_PREFIX: &[u8] = b"aos.delete.tombstone.v1\0";
pub(crate) const COLLECTION_PREFIX: &[u8] = b"aos.delete.collection.v1\0";
pub(crate) const HANDOFF_PREFIX: &[u8] = b"aos.delete.handoff.v1\0";
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
        owned.try_reserve_exact(bytes.len())
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

    pub(crate) const fn project(&self) -> ProjectId { self.project }

    pub(crate) const fn operation(&self) -> OperationId { self.operation }

    pub(crate) fn view(&self) -> Result<DeleteBatchViewV1<'_>, LifecycleModelError> {
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
                if zero(&proof[..16]) || zero(&proof[16..48])
                    || raw64(&proof[48..56]) == 0 || raw64(&proof[48..56]) == u64::MAX
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
        bytes.try_reserve_exact(self.encoded_length())
            .map_err(|_| LifecycleModelError::Allocation)?;
        bytes.extend_from_slice(&[self.state, 0, 0, 0]);
        bytes.extend_from_slice(&(self.batch.as_bytes().len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.batch.as_bytes());
        bytes.extend_from_slice(&self.native_proof);
        Ok(bytes)
    }

    /// Borrows the immutable selected batch DATA.
    #[must_use]
    pub const fn batch(&self) -> &LifecycleDeleteBatchV1 { &self.batch }

    /// Returns Planned(1), ControllerCommitted(2), or ControllerCancelled(3).
    #[must_use]
    pub const fn state(&self) -> u8 { self.state }

    /// Borrows exact original native proof bytes, not an append permission.
    #[must_use]
    pub const fn native_proof(&self) -> &[u8; 64] { &self.native_proof }

    pub(crate) fn encoded_length(&self) -> usize { 72 + self.batch.as_bytes().len() }

    pub(crate) fn can_follow(&self, before: &Self) -> bool {
        self.batch == before.batch && (self == before
            || (before.state == 1 && matches!(self.state, 2 | 3)))
    }
}

/// Borrows one completely checked canonical batch; it carries no authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DeleteBatchViewV1<'bytes> {
    bytes: &'bytes [u8],
    sections: [&'bytes [u8]; 5],
    counts: [usize; 5],
}

impl<'bytes> DeleteBatchViewV1<'bytes> {
    pub(crate) fn decode(bytes: &'bytes [u8]) -> Result<Self, LifecycleModelError> {
        if bytes.len() < 640 || bytes.len() > MAXIMUM_BYTES
            || &bytes[..8] != b"AOSDEL01" || bytes[8..10] != [0, 1]
            || bytes[10] > 3 || bytes[11] != 0
            || number32(&bytes[12..16])? as usize != bytes.len()
            || !zero(&bytes[81..88]) || !zero(&bytes[316..320])
            || zero(&bytes[16..32]) || zero(&bytes[32..48]) || zero(&bytes[48..64])
            || bytes[64] != 1 || resource(&bytes[64..81]).is_err()
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
        if counts[0] == 0 || counts[4] != counts[0]
            || counts[..3].iter().try_fold(0_usize, |n, c| n.checked_add(*c))
                .is_none_or(|n| n > MAXIMUM_ROWS)
        {
            return Err(corrupt());
        }
        for (index, descriptor) in bytes[320..608].chunks_exact(48).enumerate() {
            if descriptor[0] as usize != index + 1 || !zero(&descriptor[1..4])
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
                let fixed = match index { 0 | 2 => 100, 1 => 56, 3 => 36, _ => 17 };
                let fixed_end = offset.checked_add(fixed).filter(|end| *end <= body_end)
                    .ok_or_else(corrupt)?;
                let key_length = if index < 3 {
                    let length = number16(&bytes[offset + 18..offset + 20])? as usize;
                    if length == 0 || length > 1024 { return Err(corrupt()); }
                    length
                } else { 0 };
                offset = fixed_end.checked_add(key_length).filter(|end| *end <= body_end)
                    .ok_or_else(corrupt)?;
            }
            sections[index] = &bytes[start..offset];
        }
        if offset != body_end { return Err(corrupt()); }
        let view = Self { bytes, sections, counts };
        view.validate_rows()?;
        if view.graph_digest() != bytes[264..296] { return Err(corrupt()); }
        Ok(view)
    }

    pub(crate) fn project(self) -> ProjectId { ProjectId::from_bytes(array16(&self.bytes[16..32])) }

    pub(crate) fn operation(self) -> OperationId { OperationId::from_bytes(array16(&self.bytes[32..48])) }

    pub(crate) fn transaction(self) -> [u8; 16] { array16(&self.bytes[48..64]) }

    pub(crate) fn before_sequence(self) -> u64 { raw64(&self.bytes[88..96]) }

    pub(crate) fn request_digest(self) -> [u8; 32] { array32(&self.bytes[104..136]) }

    pub(crate) fn graph_plan(self) -> [u8; 32] { array32(&self.bytes[264..296]) }

    pub(crate) fn flags(self) -> u8 { self.bytes[10] }

    pub(crate) fn root(self) -> Result<LifecycleResourceV1, LifecycleModelError> { resource(&self.bytes[64..81]) }

    pub(crate) fn checksum(self) -> [u8; 32] { array32(&self.bytes[self.bytes.len() - 32..]) }

    pub(crate) fn bytes(self) -> &'bytes [u8] { self.bytes }

    pub(crate) fn count(self, section: usize) -> usize { self.counts[section] }

    pub(crate) fn rows(self, section: usize) -> DeleteRowsV1<'bytes> {
        DeleteRowsV1 { remaining: self.sections[section], section }
    }

    fn validate_rows(self) -> Result<(), LifecycleModelError> {
        for section in 0..3 {
            let mut previous = None;
            for row in self.rows(section) {
                resource(&row[..17])?;
                let namespace = if section == 2 { 1 } else { row[17] };
                let key = row_key(row, section);
                if namespace == 0 || namespace > 76
                    || previous.is_some_and(|last| last >= (namespace, key))
                {
                    return Err(corrupt());
                }
                previous = Some((namespace, key));
                match section {
                    0 => {
                        if row[17] != 1 || !matches!(row[0], 1..=5)
                            || !successor(raw64(&row[20..28]), raw64(&row[60..68]))
                            || zero(&row[28..60]) || zero(&row[68..100])
                            || self.rows(0).filter(|other| other[..17] == row[..17]).count() != 1
                            || self.rows(1).any(|other| other[17] == row[17] && row_key(other, 1) == key)
                        {
                            return Err(corrupt());
                        }
                    }
                    1 => {
                        if row[20] > 1 || !zero(&row[21..24])
                            || zero(&row[24..56]) != (row[20] == 0)
                        {
                            return Err(corrupt());
                        }
                    }
                    _ => {
                        if !matches!(row[17], 1..=6)
                            || !successor(raw64(&row[20..28]), raw64(&row[60..68]))
                            || zero(&row[28..60]) || zero(&row[68..100])
                            || key != collection_key(self.project(), &row[..17], row[17]).as_slice()
                        {
                            return Err(corrupt());
                        }
                    }
                }
            }
        }

        let mut edges = Vec::new();
        edges.try_reserve_exact(self.counts[3])
            .map_err(|_| LifecycleModelError::Allocation)?;
        let mut previous = None;
        for row in self.rows(3) {
            let left = resource(&row[..17])?;
            let right = resource(&row[17..34])?;
            if !matches!(row[34], 1..=6) || row[35] != 0
                || previous.is_some_and(|last| last >= row)
                || !self.contains_resource(&row[..17]) || !self.contains_resource(&row[17..34])
            {
                return Err(corrupt());
            }
            previous = Some(row);
            if self.is_written(&row[..17]) && self.is_written(&row[17..34]) {
                edges.push(LifecycleDependencyEdgeV1::new(left, right)?);
            }
        }
        let mut postorder = Vec::new();
        postorder.try_reserve_exact(self.counts[4])
            .map_err(|_| LifecycleModelError::Allocation)?;
        for row in self.rows(4) {
            let value = resource(row)?;
            if !self.is_written(row) || postorder.contains(&value) {
                return Err(corrupt());
            }
            postorder.push(value);
        }
        if postorder.last().copied() != Some(self.root()?)
            || !super::semantic::canonical_dependency_postorder_is_complete(&edges, &postorder)
        {
            return Err(corrupt());
        }
        Ok(())
    }

    fn is_written(self, value: &[u8]) -> bool { self.rows(0).any(|row| &row[..17] == value) }

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

pub(crate) struct DeleteRowsV1<'bytes> {
    remaining: &'bytes [u8],
    section: usize,
}

impl<'bytes> Iterator for DeleteRowsV1<'bytes> {
    type Item = &'bytes [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() { return None; }
        let fixed = match self.section { 0 | 2 => 100, 1 => 56, 3 => 36, _ => 17 };
        let key = if self.section < 3 {
            usize::from(u16::from_be_bytes([self.remaining[18], self.remaining[19]]))
        } else { 0 };
        let (row, remaining) = self.remaining.split_at(fixed + key);
        self.remaining = remaining;
        Some(row)
    }
}

pub(crate) fn row_key(row: &[u8], section: usize) -> &[u8] {
    &row[if section == 1 { 56 } else { 100 }..]
}

pub(crate) fn batch_key(project: ProjectId, operation: OperationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(52);
    key.extend_from_slice(BATCH_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(operation.as_bytes());
    key
}

pub(crate) fn tombstone_key(project: ProjectId, value: &[u8]) -> Vec<u8> {
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

pub(crate) fn handoff_key(project: ProjectId, operation: OperationId) -> [u8; 54] {
    let mut key = [0; 54];
    key[..22].copy_from_slice(HANDOFF_PREFIX);
    key[22..38].copy_from_slice(project.as_bytes());
    key[38..].copy_from_slice(operation.as_bytes());
    key
}

/// Validates retained handoff DATA without authenticating its Source reference.
pub(crate) fn validate_handoff(
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

pub(crate) fn tombstone(batch: DeleteBatchViewV1<'_>, row: &[u8]) -> [u8; 160] {
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
    if bytes.len() != 160 || &bytes[..8] != b"AOSDTS01" || bytes[8..12] != [0, 1, 1, 0]
        || zero(&bytes[12..28]) || zero(&bytes[28..44]) || zero(&bytes[44..60])
        || !zero(&bytes[77..80]) || resource(&bytes[60..77]).is_err()
        || !successor(raw64(&bytes[80..88]), raw64(&bytes[88..96])) || zero(&bytes[96..128])
    { return Err(corrupt()); }
    checksum(bytes, TOMBSTONE_DOMAIN)
}

pub(crate) fn collection(project: ProjectId, row: &[u8], after: bool) -> [u8; 128] {
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
    if bytes.len() != 128 || &bytes[..8] != b"AOSDCG01" || bytes[8..10] != [0, 1]
        || !matches!(bytes[10], 1..=6) || !zero(&bytes[11..16])
        || zero(&bytes[16..32]) || resource(&bytes[32..49]).is_err() || !zero(&bytes[49..56])
        || raw64(&bytes[56..64]) == 0 || raw64(&bytes[56..64]) == u64::MAX
        || zero(&bytes[64..96])
    { return Err(corrupt()); }
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
    if !matches!(class, 1..=6) || members.len() > MAXIMUM_ROWS { return Err(corrupt()); }
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
        if !matches!(member.owner, 1..=8) || member.namespace == 0 || member.namespace > 76
            || member.key.is_empty() || member.key.len() > 1024
            || previous.is_some_and(|last| last >= identity)
            || matches!(member.namespace, 2..=4)
            || member.key.starts_with(BATCH_PREFIX)
            || member.key.starts_with(COLLECTION_PREFIX)
            || member.key.starts_with(HANDOFF_PREFIX)
        { return Err(corrupt()); }
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

pub(crate) fn reserved_key(key: &[u8]) -> bool {
    key.starts_with(BATCH_PREFIX) || key.starts_with(TOMBSTONE_PREFIX)
        || key.starts_with(COLLECTION_PREFIX) || key.starts_with(HANDOFF_PREFIX)
}

pub(crate) fn native_value_digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

pub(crate) fn raw64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(bytes);
    u64::from_be_bytes(value)
}

fn successor(before: u64, after: u64) -> bool {
    before != 0 && after != u64::MAX && before.checked_add(1) == Some(after)
}

pub(crate) fn resource(bytes: &[u8]) -> Result<LifecycleResourceV1, LifecycleModelError> {
    if bytes.len() != 17 { return Err(corrupt()); }
    LifecycleResourceV1::from_code(bytes[0], array16(&bytes[1..17]))
}

fn zero(bytes: &[u8]) -> bool { bytes.iter().all(|byte| *byte == 0) }

fn corrupt() -> LifecycleModelError { LifecycleModelError::CorruptEncoding }

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
    if Sha256::new().chain_update(domain).chain_update(&bytes[..end]).finalize()[..] != bytes[end..] {
        return Err(corrupt());
    }
    Ok(())
}

fn seal(bytes: &mut [u8], domain: &[u8]) {
    let end = bytes.len() - 32;
    let digest = Sha256::new().chain_update(domain).chain_update(&bytes[..end]).finalize();
    bytes[end..].copy_from_slice(&digest);
}

/// Supplies purely synthetic canonical DATA to the selected codec tests.
#[cfg(test)]
pub(crate) fn fixture_batch_v1(key: &[u8], before: &[u8], sequence: u64) -> Vec<u8> {
    let length = 640 + 100 + key.len() + 17;
    let mut bytes = vec![0; length];
    bytes[..8].copy_from_slice(b"AOSDEL01");
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&(length as u32).to_be_bytes());
    bytes[16..32].fill(4);
    bytes[32..48].fill(5);
    bytes[48..64].fill(6);
    bytes[64] = 1;
    bytes[65..81].fill(7);
    bytes[88..96].copy_from_slice(&sequence.to_be_bytes());
    bytes[96..104].copy_from_slice(&1_u64.to_be_bytes());
    bytes[104..264].fill(8);
    bytes[296..300].copy_from_slice(&1_u32.to_be_bytes());
    bytes[312..316].copy_from_slice(&1_u32.to_be_bytes());
    for (index, row) in bytes[320..608].chunks_exact_mut(48).enumerate() {
        row[0] = index as u8 + 1;
        row[4..12].copy_from_slice(&1_u64.to_be_bytes());
        row[16..48].fill(10 + index as u8);
    }
    let write_end = 708 + key.len();
    bytes[608] = 1;
    bytes[609..625].fill(7);
    bytes[625] = 1;
    bytes[626..628].copy_from_slice(&(key.len() as u16).to_be_bytes());
    bytes[628..636].copy_from_slice(&1_u64.to_be_bytes());
    bytes[636..668].copy_from_slice(&native_value_digest(before));
    bytes[668..676].copy_from_slice(&2_u64.to_be_bytes());
    bytes[708..write_end].copy_from_slice(key);
    bytes[write_end] = 1;
    bytes[write_end + 1..write_end + 17].fill(7);

    let (graph, after) = {
        let empty = &bytes[0..0];
        let view = DeleteBatchViewV1 {
            bytes: &bytes,
            sections: [&bytes[608..write_end], empty, empty, empty, &bytes[write_end..write_end + 17]],
            counts: [1, 0, 0, 0, 1],
        };
        (view.graph_digest(), native_value_digest(&tombstone(view, &bytes[608..write_end])))
    };
    bytes[264..296].copy_from_slice(&graph);
    bytes[676..708].copy_from_slice(&after);
    seal(&mut bytes, BATCH_DOMAIN);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{DesiredGeneration, ObjectDigest, PrincipalId, ResourceId, Revision, SandboxId};
    use super::super::*;

    // These fixtures exercise codecs and replay only. The test-only private
    // verifier inputs are synthetic DATA, not genuine protected owner custody.
    fn selected_operation() -> LifecycleOperationV1 {
        let sandbox = SandboxId::from_bytes([7; 16]);
        let resource = LifecycleResourceV1::Sandbox(sandbox);
        let state = LifecycleResourceStateDigestV1::commit(b"before");
        let fence = DesiredStateFenceV1::new(
            resource, DesiredGeneration::new(1), Revision::new(1), state,
        ).unwrap();
        let step = LifecycleStepV1::unbound(
            0, LifecycleStepClassV1::PostCommitForward, LifecycleStepDomainV1::Controller,
            LifecycleStepRequestDigestV1::commit(b"pending Delete"), None,
        ).unwrap();

        LifecycleOperationV1::new(
            OperationId::from_bytes([5; 16]), PrincipalId::from_bytes([3; 16]),
            ProjectId::from_bytes([4; 16]), LifecycleIdempotencyDigestV1::commit(b"key"),
            LifecycleIntentV1::DeleteSandbox { sandbox, fence }, LifecycleTimeV1::new(1).unwrap(),
            Revision::new(1), vec![ResourceExpectationV1::present(resource, Revision::new(1), state).unwrap()],
            vec![step], LifecyclePhaseV1::Accepted, 0, 0, None, None, None, None, None, None,
        ).unwrap().select_delete_batch_layout().unwrap()
    }

    fn planned_record() -> LifecycleDeleteBatchRecordV1 {
        let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
        let mut payload = vec![1, 0, 0, 0];
        payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&bytes);
        payload.extend_from_slice(&[0; 64]);
        LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap()
    }

    fn planned_join(
        verification: &LifecycleReplayVerificationV1,
    ) -> Vec<LifecycleAuxiliaryRecordV1> {
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();
        let digest = super::super::format::record_digest(&encoded).unwrap();
        let project = operation.project();
        let id = operation.operation_id();
        let join = ResourceId::from_bytes([52; 16]);
        let revision = Revision::new(1);
        let operation_member = LifecycleAuxiliaryRecordV1::proposal(
            project, id, revision, digest, ResourceId::from_bytes([50; 16]), revision, None,
            LifecycleAuxiliaryPayloadV1::Operation(operation), join, None, verification,
        ).unwrap();
        let batch_member = LifecycleAuxiliaryRecordV1::proposal(
            project, id, revision, digest, ResourceId::from_bytes([51; 16]), revision, None,
            LifecycleAuxiliaryPayloadV1::DeleteBatch(planned_record()), join, None, verification,
        ).unwrap();

        bind_lifecycle_atomic_join_v1(vec![operation_member, batch_member]).unwrap()
    }

    // Rebuild proposal DATA without reusing the immutable bound member set.
    fn unbound_fixture_member(
        record: &LifecycleAuxiliaryRecordV1,
        verification: &LifecycleReplayVerificationV1,
    ) -> LifecycleAuxiliaryRecordV1 {
        LifecycleAuxiliaryRecordV1::proposal(
            record.project(),
            record.operation(),
            record.operation_revision(),
            record.operation_record(),
            record.lineage(),
            record.revision(),
            record.predecessor(),
            record.payload().clone(),
            record.atomic_join(),
            record.replay_floor(),
            verification,
        )
        .unwrap()
    }

    fn operation_digest(operation: &LifecycleOperationV1) -> LifecycleRecordDigestV1 {
        let encoded = super::super::format::encode_retained_operation_record(operation).unwrap();
        super::super::format::record_digest(&encoded).unwrap()
    }

    fn bound_successor(operation: &LifecycleOperationV1) -> LifecycleOperationV1 {
        let step = operation.steps()[0]
            .bind(
                LifecycleStepBodyDigestV1::commit(b"bound Delete body"),
                LifecycleStepPlanDigestV1::commit(b"bound Delete plan"),
                None,
                None,
            )
            .unwrap();

        operation
            .successor(
                operation_digest(operation), LifecyclePhaseV1::Accepted, 0, 0,
                vec![step], None, None, None, None, None,
            )
            .unwrap()
            .select_delete_batch_layout()
            .unwrap()
    }

    fn checkpoint_operation(
        operation: &LifecycleOperationV1,
        caller: PrincipalId,
        idempotency: LifecycleIdempotencyDigestV1,
        accepted_at: LifecycleTimeV1,
        revision: Revision,
        predecessor: Option<LifecycleRecordDigestV1>,
        selected: bool,
    ) -> LifecycleOperationV1 {
        let copied = LifecycleOperationV1::new(
            operation.operation_id(),
            caller,
            operation.project(),
            idempotency,
            operation.intent().clone(),
            accepted_at,
            revision,
            operation.expectations().to_vec(),
            operation.steps().to_vec(),
            operation.phase(),
            operation.forward_progress(),
            operation.compensation_progress(),
            operation.method_semantic_commit().cloned(),
            operation.failure(),
            operation.retry(),
            operation.terminal_result(),
            operation.finished_at(),
            predecessor,
        )
        .unwrap();

        if selected {
            copied.select_delete_batch_layout().unwrap()
        } else {
            copied
        }
    }

    fn checkpoint_successor_join(
        before: &[LifecycleAuxiliaryRecordV1],
        operation: LifecycleOperationV1,
        join: u8,
        include_batch: bool,
        verification: &LifecycleReplayVerificationV1,
    ) -> Vec<LifecycleAuxiliaryRecordV1> {
        let previous = &before[0];
        let digest = operation_digest(&operation);
        let operation_member = LifecycleAuxiliaryRecordV1::proposal(
            operation.project(),
            operation.operation_id(),
            operation.record_revision(),
            digest,
            previous.lineage(),
            previous.revision().checked_next().unwrap(),
            Some(previous.complete_digest()),
            LifecycleAuxiliaryPayloadV1::Operation(operation),
            ResourceId::from_bytes([join; 16]),
            None,
            verification,
        )
        .unwrap();
        let mut records = vec![operation_member];

        if include_batch {
            let previous = &before[1];
            records.push(LifecycleAuxiliaryRecordV1::proposal(
                previous.project(),
                previous.operation(),
                records[0].operation_revision(),
                digest,
                previous.lineage(),
                previous.revision().checked_next().unwrap(),
                Some(previous.complete_digest()),
                previous.payload().clone(),
                ResourceId::from_bytes([join; 16]),
                None,
                verification,
            ).unwrap());
        }

        bind_lifecycle_atomic_join_v1(records).unwrap()
    }

    #[test]
    fn bounded_batch_and_pending_tombstone_round_trip() {
        let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
        let batch = LifecycleDeleteBatchV1::from_bytes(&bytes).unwrap();
        let view = batch.view().unwrap();
        let row = view.rows(0).next().unwrap();
        let pending = tombstone(view, row);

        assert_eq!(batch.as_bytes(), bytes);
        assert_eq!(view.count(4), 1);
        assert!(validate_tombstone(&pending).is_ok());
        assert_eq!(native_value_digest(&pending), row[68..100]);
    }

    #[test]
    fn batch_rejects_reserved_counts_lengths_and_resealed_generation() {
        let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
        for (offset, value) in [(11, 1), (299, 2), (675, 3)] {
            let mut wrong = bytes.clone();
            wrong[offset] = value;
            seal(&mut wrong, BATCH_DOMAIN);
            assert!(DeleteBatchViewV1::decode(&wrong).is_err());
        }
        assert!(DeleteBatchViewV1::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(DeleteBatchViewV1::decode(&trailing).is_err());
    }

    #[test]
    fn selected_outcome_has_exact_state_dependent_native_data() {
        let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
        let mut payload = vec![1, 0, 0, 0];
        payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&bytes);
        payload.extend_from_slice(&[0; 64]);
        let planned = LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap();

        assert_eq!(planned.encode().unwrap(), payload);
        payload[0] = 2;
        assert!(LifecycleDeleteBatchRecordV1::from_bytes(&payload).is_err());
        let start = payload.len() - 64;
        payload[start..start + 16].fill(6);
        payload[start + 16..start + 48].fill(9);
        payload[start + 48..start + 56].copy_from_slice(&9_u64.to_be_bytes());
        payload[start + 56..].copy_from_slice(&1000_u64.to_be_bytes());
        let committed = LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap();
        assert!(committed.can_follow(&planned));
        assert!(!planned.can_follow(&committed));
        payload[start] = 7;
        assert!(LifecycleDeleteBatchRecordV1::from_bytes(&payload).is_err());
    }

    #[test]
    fn handoff_is_exact_non_authorizing_dependency_data() {
        let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
        let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
        let mut marker = [0; 160];
        marker[..8].copy_from_slice(b"AOSDHF01");
        marker[9] = 1;
        marker[10] = 1;
        marker[16..32].copy_from_slice(batch.project().as_bytes());
        marker[32..48].copy_from_slice(batch.operation().as_bytes());
        marker[48..64].copy_from_slice(&batch.transaction());
        marker[64..96].copy_from_slice(&batch.checksum());
        marker[96..128].fill(21);
        seal(&mut marker, HANDOFF_DOMAIN);

        assert!(validate_handoff(&marker, batch).is_ok());
        assert_eq!(handoff_key(batch.project(), batch.operation()).len(), 54);
        for offset in [10, 11, 16, 48, 64, 96] {
            let mut wrong = marker;
            wrong[offset] = if offset == 11 { 1 } else { 0 };
            if offset == 96 { wrong[96..128].fill(0); }
            seal(&mut wrong, HANDOFF_DOMAIN);
            assert!(validate_handoff(&wrong, batch).is_err());
        }
    }

    #[test]
    fn canonical_ready_order_does_not_accept_caller_tie_order() {
        let first = LifecycleResourceV1::Sandbox(aos_sandbox_core::SandboxId::from_bytes([1; 16]));
        let second = LifecycleResourceV1::Sandbox(aos_sandbox_core::SandboxId::from_bytes([2; 16]));
        let root = LifecycleResourceV1::Sandbox(aos_sandbox_core::SandboxId::from_bytes([3; 16]));
        let edges = [
            LifecycleDependencyEdgeV1::new(first, root).unwrap(),
            LifecycleDependencyEdgeV1::new(second, root).unwrap(),
        ];

        assert!(super::super::semantic::canonical_dependency_postorder_is_complete(&edges, &[first, second, root]));
        assert!(!super::super::semantic::canonical_dependency_postorder_is_complete(&edges, &[second, first, root]));
    }

    #[test]
    fn selected_operation_is_version_separated_before_semantic_commit() {
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();

        assert_eq!(&encoded[..10], b"AOSLIF04\0\x04");
        assert_eq!(decode_operation_record_v1(&encoded).unwrap(), operation);
        assert!(encode_operation_record_v1(&operation).is_err());
    }

    #[test]
    fn planned_auxiliary_join_replays_exactly_and_keeps_original_dependencies() {
        let authority = ObjectDigest::from_bytes([40; 32]);
        let initial = LifecycleReplayVerificationV1::from_verified_authority(authority, vec![], vec![]).unwrap();
        let records = planned_join(&initial);
        let encoded: Vec<_> = records.iter().map(|record| encode_lifecycle_auxiliary_record_v1(record).unwrap()).collect();
        let mut accepted: Vec<_> = records.iter().map(LifecycleAuxiliaryRecordV1::complete_digest).collect();
        accepted.sort();
        let verification = LifecycleReplayVerificationV1::from_verified_authority(authority, accepted, vec![]).unwrap();

        let history = LifecycleAuxiliaryHistoryV1::replay(encoded.iter().map(Vec::as_slice), &verification).unwrap();
        assert_eq!(history.operations().operation(OperationId::from_bytes([5; 16])), Some(&selected_operation()));
        assert!(encoded.iter().all(|bytes| &bytes[..10] == b"AOSLIFA5\0\x03"));
        assert!(history.operations().checkpoint().is_err());
        assert!(LifecycleAuxiliaryHistoryV1::replay(encoded[1..].iter().map(Vec::as_slice), &verification).is_err());
    }

    #[test]
    fn selected_generic_cancellation_and_orphan_operation_refuse() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let records = planned_join(&verification);
        let mut history = LifecycleAuxiliaryHistoryV1::under_verification(&verification);
        history.apply_atomic_join(&records).unwrap();
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();
        let digest = super::super::format::record_digest(&encoded).unwrap();
        let request = LifecycleCancelRequestV1::new(
            operation.caller(), operation.project(), operation.operation_id(), Revision::new(1),
            digest, LifecycleCancelIdempotencyDigestV1::commit(b"cancel"), LifecycleTimeV1::new(2).unwrap(),
        ).unwrap();

        assert!(history.admit_cancellation(
            request, ResourceId::from_bytes([50; 16]), ResourceId::from_bytes([53; 16]),
            ResourceId::from_bytes([54; 16]), &verification,
        ).is_err());
        let orphan = bind_lifecycle_atomic_join_v1(vec![
            unbound_fixture_member(&records[0], &verification),
        ]).unwrap();
        assert!(LifecycleAuxiliaryHistoryV1::under_verification(&verification).apply_atomic_join(&orphan).is_err());
        assert_eq!(history.operations().operation(operation.operation_id()), Some(&operation));
    }

    #[test]
    fn old_auxiliary_payload_api_cannot_encode_selected_batch_or_operation() {
        assert!(encode_lifecycle_auxiliary_payload_v1(&LifecycleAuxiliaryPayloadV1::DeleteBatch(planned_record())).is_err());
        assert!(encode_lifecycle_auxiliary_payload_v1(&LifecycleAuxiliaryPayloadV1::Operation(selected_operation())).is_err());
    }

    #[test]
    fn committed_native_data_cannot_replace_missing_source_planned_history() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let mut payload = planned_record().encode().unwrap();
        payload[0] = 2;
        let start = payload.len() - 64;
        payload[start..start + 16].fill(6);
        payload[start + 16..start + 48].fill(9);
        payload[start + 48..start + 56].copy_from_slice(&9_u64.to_be_bytes());
        payload[start + 56..].copy_from_slice(&1000_u64.to_be_bytes());
        let committed = LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap();
        let mut records = planned_join(&verification);
        let before = records.pop().unwrap();
        records[0] = unbound_fixture_member(&records[0], &verification);
        let member = LifecycleAuxiliaryRecordV1::proposal(
            before.project(), before.operation(), before.operation_revision(), before.operation_record(),
            before.lineage(), before.revision(), before.predecessor(),
            LifecycleAuxiliaryPayloadV1::DeleteBatch(committed), before.atomic_join(),
            before.replay_floor(), &verification,
        ).unwrap();
        records.push(member);
        let records = bind_lifecycle_atomic_join_v1(records).unwrap();

        assert!(LifecycleAuxiliaryHistoryV1::under_verification(&verification).apply_atomic_join(&records).is_err());
    }

    #[test]
    fn collection_fold_keeps_tombstone_data_but_excludes_native_metadata_and_own_hash() {
        let project = ProjectId::from_bytes([4; 16]);
        let owner = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let key = tombstone_key(project, &[1; 17]);
        let members = [DeleteCollectionMemberV1 {
            owner: 7, namespace: 1, key: &key, value: b"complete pending overlay",
        }];
        let populated = collection_root(project, owner, 1, &members).unwrap();

        assert_ne!(populated, collection_root(project, owner, 1, &[]).unwrap());
        for namespace in 2..=4 {
            assert!(collection_root(project, owner, 1, &[DeleteCollectionMemberV1 {
                owner: 7, namespace, key: b"metadata", value: b"value",
            }]).is_err());
        }
        assert!(collection_root(project, owner, 1, &[DeleteCollectionMemberV1 {
            owner: 7, namespace: 1, key: COLLECTION_PREFIX, value: b"own root",
        }]).is_err());
    }

    #[test]
    fn selected_checkpoint_replays_bound_successor_and_exact_repeated_member() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let mut records = planned_join(&verification);
        let operation = bound_successor(&selected_operation());
        let successor = checkpoint_successor_join(&records, operation.clone(), 53, true, &verification);
        let repeated = checkpoint_successor_join(&successor, operation.clone(), 54, true, &verification);
        records.extend(successor);
        records.extend(repeated);

        let history = LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
            .unwrap();

        assert_eq!(
            history.operations().operation_record(operation.operation_id()),
            Some((&operation, operation_digest(&operation))),
        );
    }

    #[test]
    fn selected_checkpoint_rejects_changed_admission_fields() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let operation = bound_successor(&selected_operation());
        let mutations = [
            (
                PrincipalId::from_bytes([9; 16]),
                operation.idempotency(),
                operation.accepted_at(),
            ),
            (
                operation.caller(),
                LifecycleIdempotencyDigestV1::commit(b"another key"),
                operation.accepted_at(),
            ),
            (
                operation.caller(),
                operation.idempotency(),
                LifecycleTimeV1::new(2).unwrap(),
            ),
        ];

        for (caller, idempotency, accepted_at) in mutations {
            let changed = checkpoint_operation(
                &operation, caller, idempotency, accepted_at,
                operation.record_revision(), operation.predecessor_digest(), true,
            );
            let mut records = planned_join(&verification);
            let successor = checkpoint_successor_join(&records, changed, 53, true, &verification);
            records.extend(successor);

            assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
                .is_err());
        }
    }

    #[test]
    fn selected_checkpoint_rejects_disconnected_or_skipped_operation_predecessor() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let operation = bound_successor(&selected_operation());
        for (revision, predecessor) in [
            (Revision::new(3), operation.predecessor_digest()),
            (operation.record_revision(), Some(operation_digest(&operation))),
        ] {
            let changed = checkpoint_operation(
                &operation, operation.caller(), operation.idempotency(),
                operation.accepted_at(), revision, predecessor, true,
            );
            let mut records = planned_join(&verification);
            let successor = checkpoint_successor_join(&records, changed, 53, true, &verification);
            records.extend(successor);

            assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
                .is_err());
        }
    }

    #[test]
    fn selected_checkpoint_does_not_ignore_later_operation_only_member() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let operation = bound_successor(&selected_operation());
        let changed = checkpoint_operation(
            &operation, PrincipalId::from_bytes([9; 16]),
            operation.idempotency(), operation.accepted_at(), operation.record_revision(),
            operation.predecessor_digest(), true,
        );
        let mut records = planned_join(&verification);
        let successor = checkpoint_successor_join(&records, changed, 53, false, &verification);
        assert_eq!(
            (successor[0].declared_members(), successor[0].declared_count()),
            (0x01, 1),
        );
        records.extend(successor);

        assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
            .is_err());
    }

    #[test]
    fn ordinary_checkpoint_keeps_latest_only_baseline_without_selected_records() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let selected = bound_successor(&selected_operation());
        let operation = checkpoint_operation(
            &selected, selected.caller(), selected.idempotency(), selected.accepted_at(),
            selected.record_revision(), selected.predecessor_digest(), false,
        );
        let digest = operation_digest(&operation);
        let record = LifecycleAuxiliaryRecordV1::proposal(
            operation.project(),
            operation.operation_id(),
            operation.record_revision(),
            digest,
            ResourceId::from_bytes([50; 16]),
            Revision::new(1),
            None,
            LifecycleAuxiliaryPayloadV1::Operation(operation.clone()),
            ResourceId::from_bytes([52; 16]),
            None,
            &verification,
        )
        .unwrap();
        let records = bind_lifecycle_atomic_join_v1(vec![record]).unwrap();

        let history = LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
            .unwrap();

        assert_eq!(
            history.operations().operation_record(operation.operation_id()),
            Some((&operation, digest)),
        );
    }
}
