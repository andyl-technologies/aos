//! Owns the complete non-authorizing Delete batch and auxiliary DATA grammar.
//!
//! Native Controller CAS and Source replay share this canonical codec:
//!
//! ```text
//! AOSDEL01 | historical header608 | W | R | C | E36 | P17 | checksum32
//! AOSDEL02 | named-cut header608  | W | R | C | E36 | P17 | companions418 | checksum32
//! AOSDTS01 | pending tombstone128 | checksum32
//! AOSDCG01 | collection96 | checksum32
//! AOSDHF01 | native handoff128 | checksum32
//! ```
//!
//! Canonical bytes describe dependencies; neither a checksum nor a decoded
//! inventory authenticates a current graph, an owner, a floor or retirement.

use aos_sandbox_model::{OperationId, ProjectId};
use sha2::{Digest as _, Sha256};

mod companions;
pub mod capability_retention;
mod dependency_class;
pub use dependency_class::DeleteDependencyClassDataV2;
mod encoding;
mod native_commit;
mod native_boundary;
pub mod new_use;
pub use native_boundary::{DeleteBatchNativeBoundaryDataV2, DeleteBatchOwnerCutDataV2};
pub use native_commit::encode_native_commit_data_v1;
pub use encoding::{
    DeleteBatchCollectionDataV1, DeleteBatchDependencyDataV1, DeleteBatchEncodingDataV1,
    DeleteBatchOwnerCutDataV1, DeleteBatchReadDataV1, DeleteBatchWriteDataV1,
    DeleteBatchCommitmentsDataV2,
};

use super::lifecycle_model::{
    LifecycleDependencyEdgeV1, LifecycleModelError, LifecycleResourceV1,
    canonical_dependency_postorder_is_complete,
};

/// Prefixes the historical Delete batch key family.
pub const BATCH_PREFIX: &[u8] = b"aos.delete.batch.v1\0";
/// Prefixes the historical pending-tombstone key family.
pub const TOMBSTONE_PREFIX: &[u8] = b"aos.delete.tombstone.v1\0";
pub(crate) const COLLECTION_PREFIX: &[u8] = b"aos.delete.collection.v1\0";
/// Prefixes the historical Delete handoff key family.
pub const HANDOFF_PREFIX: &[u8] = b"aos.delete.handoff.v1\0";

const BATCH_DOMAIN: &[u8] = b"aos.sandbox.delete.batch.v1\0";
const BATCH_DOMAIN_V2: &[u8] = b"aos.sandbox.delete.batch.v2\0";
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

    /// Returns the project recorded in the canonical batch DATA.
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the operation recorded in the canonical batch DATA.
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Borrows a completely checked view of the retained canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an encoding/model error for invalid retained DATA or an allocation
    /// error when checked graph allocation fails.
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
    /// Returns an allocation error when checked graph reservation or batch copying fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        let view = LifecycleDeleteBatchRecordViewDataV3::decode(bytes)?;
        Ok(Self { state: view.state, batch: LifecycleDeleteBatchV1::from_view(view.batch)?,
            native_proof: *view.native_proof })
    }

    /// Builds state2 acceptance DATA through the sole existing payload codec.
    ///
    /// The original state1 history and actual same-writer native COMMIT must
    /// still be authenticated by the caller. This pure constructor grants no
    /// append, cleanup or physical-retirement permission.
    ///
    /// # Errors
    /// Refuses a non-Planned predecessor, wrong transaction/proof shape or a
    /// canonical payload/checked allocation failure.
    pub fn controller_committed_data_v3(&self, native: &[u8; 64])
        -> Result<Self, LifecycleModelError> {
        if self.state != 1 { return Err(corrupt()); }
        let candidate = Self { state: 2, batch: self.batch.clone(), native_proof: *native };
        Self::from_bytes(&candidate.encode()?)
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

    /// Returns the exact state/proof payload length.
    pub fn encoded_length(&self) -> usize {
        72 + self.batch.as_bytes().len()
    }

    /// Checks exact repetition or a planned record's terminal successor with the same batch.
    pub fn can_follow(&self, before: &Self) -> bool {
        self.batch == before.batch
            && (self == before || (before.state == 1 && matches!(self.state, 2 | 3)))
    }
}

/// Borrows canonical state/proof payload DATA without copying the selected batch.
///
/// Batch graph validation has the same bounded transient cost as the owned decoder;
/// this view grants no acceptance, native owner or cleanup authority.
#[derive(Clone, Copy, Debug)]
pub struct LifecycleDeleteBatchRecordViewDataV3<'bytes> {
    /// Canonical Planned(1), ControllerCommitted(2), or ControllerCancelled(3).
    pub state: u8,
    /// Complete structurally checked immutable batch.
    pub batch: DeleteBatchViewV1<'bytes>,
    /// Borrowed native proof; its provenance remains the caller's obligation.
    pub native_proof: &'bytes [u8; 64],
}

impl<'bytes> LifecycleDeleteBatchRecordViewDataV3<'bytes> {
    /// Borrows the sole canonical state/proof payload decoder.
    ///
    /// # Errors
    /// Rejects malformed state, reserved bytes, extent, graph or proof shape.
    pub fn decode(bytes: &'bytes [u8]) -> Result<Self, LifecycleModelError> {
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
        Ok(Self { state: bytes[0], batch: view,
            native_proof: proof.try_into().map_err(|_| corrupt())? })
    }
}

/// Borrows one completely checked canonical batch; it carries no authority.
#[derive(Clone, Copy, Debug)]
pub struct DeleteBatchViewV1<'bytes> {
    bytes: &'bytes [u8],
    sections: [&'bytes [u8]; 5],
    counts: [usize; 5],
    companions: &'bytes [u8],
}

impl<'bytes> DeleteBatchViewV1<'bytes> {
    /// Checks the sole canonical batch codec's complete encoded extent bound.
    ///
    /// This performs no decoding, allocation or provenance validation.
    #[must_use]
    pub const fn encoded_length_is_bounded_v1(bytes: usize) -> bool {
        bytes >= HEADER_BYTES + 32 && bytes <= MAXIMUM_BYTES
    }

    /// Bounds this decoder's transient graph backing before receiving bytes.
    ///
    /// The checked actual encoded length bounds edge and postorder cardinality;
    /// the existing row ceiling further limits each. Both graph vectors and the
    /// sole canonical topological check's map/set may coexist. This byte-only
    /// DATA does not pay, allocate, create namespace entries or accept a batch.
    #[must_use]
    pub fn decode_receiving_bytes_v1(bytes: usize) -> Option<usize> {
        if !Self::encoded_length_is_bounded_v1(bytes) { return None; }
        let edges = (bytes / 36).min(MAXIMUM_ROWS);
        let vertices = (bytes / 17).min(MAXIMUM_ROWS);
        let map = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<LifecycleResourceV1, usize>(vertices)?;
        let set = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<LifecycleResourceV1, ()>(vertices)?;
        edges.checked_mul(std::mem::size_of::<LifecycleDependencyEdgeV1>())?
            .checked_add(vertices.checked_mul(std::mem::size_of::<LifecycleResourceV1>())?)?
            .checked_add(map)?.checked_add(set)?
            .checked_add(3 * std::mem::size_of::<Self>())?
            .checked_add(std::mem::size_of::<std::collections::BTreeMap<LifecycleResourceV1, usize>>())?
            .checked_add(std::mem::size_of::<std::collections::BTreeSet<LifecycleResourceV1>>())?
            .checked_add(2 * std::mem::size_of::<Vec<LifecycleResourceV1>>())?
            .checked_add(companions::receiving_bytes_v2()?)?
            .checked_add(std::mem::size_of::<[DeleteBatchOwnerCutDataV2; 6]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<DeleteBatchOwnerCutDataV2>().checked_mul(3)?)
    }

    /// Bounds a batch decoder nested inside an actual enclosing encoded value.
    ///
    /// A batch cannot exceed either its containing slice or this same parser's
    /// existing wire ceiling. This performs no parsing or allocation.
    #[must_use]
    pub fn nested_decode_receiving_bytes_v1(enclosing_bytes: usize) -> Option<usize> {
        let bytes = enclosing_bytes.min(MAXIMUM_BYTES);
        if Self::encoded_length_is_bounded_v1(bytes) {
            Self::decode_receiving_bytes_v1(bytes)
        } else {
            Some(0)
        }
    }

    /// Bounds the actual map/set vertex names of a nested canonical graph check.
    ///
    /// Control fields and scalar values are not namespace entries.
    #[must_use]
    pub fn nested_decode_metadata_entries_v1(enclosing_bytes: usize) -> Option<usize> {
        (enclosing_bytes.min(MAXIMUM_BYTES) / 17).min(MAXIMUM_ROWS).checked_mul(2)
    }

    /// Checks and borrows the complete bounded five-section batch grammar.
    ///
    /// # Errors
    ///
    /// Returns an encoding/model error for malformed or noncanonical DATA, or
    /// an allocation error when checked graph allocation fails.
    pub fn decode(bytes: &'bytes [u8]) -> Result<Self, LifecycleModelError> {
        if !Self::encoded_length_is_bounded_v1(bytes.len())
            || !matches!((&bytes[..8], &bytes[8..10]),
                (b"AOSDEL01", [0, 1]) | (b"AOSDEL02", [0, 2]))
            || bytes[10] > 3
            || bytes[11] != 0
            || number32(&bytes[12..16])? as usize != bytes.len()
            || !zero(&bytes[81..88])
            || (bytes[9] == 1 && !zero(&bytes[316..320]))
            || zero(&bytes[16..32])
            || zero(&bytes[32..48])
            || zero(&bytes[48..64])
            || bytes[64] != 1
            || resource(&bytes[64..81]).is_err()
            || bytes[104..296].chunks_exact(32).any(zero)
            || (bytes[9] == 2 && matches!(raw64(&bytes[96..104]), 0 | u64::MAX))
        {
            return Err(corrupt());
        }
        let domain = if bytes[9] == 2 { BATCH_DOMAIN_V2 } else { BATCH_DOMAIN };
        checksum(bytes, domain)?;

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
                || (bytes[9] == 1 && !zero(&descriptor[1..4]))
                || number64(&descriptor[4..12])? == u64::MAX
                || number32(&descriptor[12..16])? as usize > MAXIMUM_ROWS
                || zero(&descriptor[16..48])
            {
                return Err(corrupt());
            }
            if bytes[9] == 2 {
                DeleteBatchOwnerCutDataV2::decode_descriptor_v2((index + 1) as u8, descriptor)?;
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
        let companion_count = number32(&bytes[316..320])? as usize;
        if companion_count > MAXIMUM_ROWS / 2
            || offset.checked_add(companion_count.checked_mul(
                super::provisioning_resources::PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2)
                .ok_or_else(corrupt)?) != Some(body_end)
        {
            return Err(corrupt());
        }
        let companions = &bytes[offset..body_end];
        let view = Self {
            bytes,
            sections,
            counts,
            companions,
        };
        view.validate_companions_v2()?;
        view.validate_rows()?;
        if view.graph_digest() != bytes[264..296] {
            return Err(corrupt());
        }
        Ok(view)
    }

    /// Returns the explicit canonical DATA version without granting admission.
    pub const fn version(self) -> u8 {
        self.bytes[9]
    }

    /// Borrows named V2 commitments; historical V1 has no such interpretation.
    ///
    /// These digests remain comparison DATA. The actual producer and consumer
    /// must recompute their complete canonical preimages from retained owners.
    pub fn named_commitments_v2(self) -> Option<DeleteBatchCommitmentsDataV2> {
        (self.version() == 2).then(|| DeleteBatchCommitmentsDataV2 {
            authorization: array32(&self.bytes[136..168]),
            source: array32(&self.bytes[168..200]),
            controller: array32(&self.bytes[200..232]),
            initial_six: array32(&self.bytes[232..264]),
        })
    }

    /// Returns the project recorded in the canonical batch DATA.
    pub fn project(self) -> ProjectId {
        ProjectId::from_bytes(array16(&self.bytes[16..32]))
    }

    /// Returns the operation recorded in the canonical batch DATA.
    pub fn operation(self) -> OperationId {
        OperationId::from_bytes(array16(&self.bytes[32..48]))
    }

    /// Returns the historical transaction identity without authenticating it.
    pub fn transaction(self) -> [u8; 16] {
        array16(&self.bytes[48..64])
    }

    /// Returns the retained predecessor sequence without selecting current state.
    pub fn before_sequence(self) -> u64 {
        raw64(&self.bytes[88..96])
    }

    /// Returns V2's actual pre-Planned Source NEXT comparison coordinate.
    ///
    /// Historical V1's unrelated field has no V2 interpretation.
    #[must_use]
    pub fn source_predecessor_next_sequence_v2(self) -> Option<u64> {
        (self.version() == 2).then(|| raw64(&self.bytes[96..104]))
    }

    /// Returns the retained request commitment.
    pub fn request_digest(self) -> [u8; 32] {
        array32(&self.bytes[104..136])
    }

    /// Returns the complete retained graph-plan commitment.
    pub fn graph_plan(self) -> [u8; 32] {
        array32(&self.bytes[264..296])
    }

    /// Returns the established cascade/force DATA bits.
    pub fn flags(self) -> u8 {
        self.bytes[10]
    }

    /// Decodes the retained typed root resource.
    ///
    /// # Errors
    ///
    /// Returns an encoding error for invalid root DATA; checked view construction
    /// already excludes that condition.
    pub fn root(self) -> Result<LifecycleResourceV1, LifecycleModelError> {
        resource(&self.bytes[64..81])
    }

    /// Returns the selected root's exact next desired generation as DATA.
    ///
    /// # Errors
    /// Refuses a noncurrent batch or an absent canonical root write row.
    pub fn root_successor_generation_data_v2(self) -> Result<u64, LifecycleModelError> {
        if self.version() != 2 { return Err(corrupt()); }
        let row = self.rows(0).find(|row| row[..17] == self.bytes[64..81])
            .ok_or_else(corrupt)?;
        Ok(raw64(&row[60..68]))
    }

    /// Encodes canonical postorder overlays, collection successors and handoff.
    ///
    /// The caller pays the concrete output/model bound before entering this
    /// pure recipe and authenticates the original Source COMMIT independently.
    /// No output record supplies append permission or destructive authority.
    ///
    /// # Errors
    /// Refuses a historical batch, missing write row, malformed Source native
    /// reference, checked output overflow or failed allocation.
    pub fn admission_local_records_data_v2(
        self,
        source_pending_native: &[u8; 64],
    ) -> Result<Vec<super::transaction::JournalRecord>, LifecycleModelError> {
        use super::transaction::JournalRecord;
        use aos_sandbox_model::RecordNamespace;

        if self.version() != 2 { return Err(corrupt()); }
        let count = self.count(0).checked_add(self.count(2))
            .and_then(|count| count.checked_add(1)).ok_or_else(corrupt)?;
        let mut records = Vec::new();
        records.try_reserve_exact(count).map_err(|_| LifecycleModelError::Allocation)?;
        for resource in self.rows(4) {
            let row = self.rows(0).find(|row| &row[..17] == resource).ok_or_else(corrupt)?;
            records.push(JournalRecord::put(RecordNamespace::DesiredState,
                tombstone_key(self.project(), resource), tombstone(self, row).to_vec()));
        }
        for row in self.rows(2) {
            records.push(JournalRecord::put(RecordNamespace::DesiredState,
                row_key(row, 2).to_vec(), collection(self.project(), row, true).to_vec()));
        }
        records.push(JournalRecord::put(RecordNamespace::DesiredState,
            handoff_key(self.project(), self.operation()).to_vec(),
            encode_handoff_from_source_pending_data_v2(self, source_pending_native)?.to_vec()));
        Ok(records)
    }

    /// Compares the original public Delete request with this complete batch.
    ///
    /// An omitted expected plan remains omitted; when supplied it must equal
    /// the selected graph. This compares DATA and grants no admission or effect.
    ///
    /// # Errors
    ///
    /// Refuses a different root, flags, expected plan, or a non-cascade request
    /// whose complete write set contains more than one resource.
    pub fn require_public_request_v2(
        self,
        request: &aos_sandbox_api::aos::sandbox::v1::DeleteSandboxRequest,
    ) -> Result<(), LifecycleModelError> {
        let LifecycleResourceV1::Sandbox(root) = self.root()? else {
            return Err(corrupt());
        };
        if self.version() != 2 || request.sandbox_id.as_slice() != root.as_bytes()
            || self.flags() != (u8::from(request.cascade) | (u8::from(request.force) << 1))
            || (!request.cascade && self.count(0) != 1)
            || (!request.expected_plan_digest.is_empty()
                && request.expected_plan_digest.as_slice() != self.graph_plan())
        {
            return Err(corrupt());
        }
        Ok(())
    }

    /// Borrows the selected resource order through the sole resource decoder.
    ///
    /// Checked construction already verifies complete canonical dependency
    /// postorder. This exposes passive selection DATA without allocating or
    /// constructing a pending fence, current graph or destructive permission.
    pub fn postorder_resources_data_v2(self) -> impl Iterator<Item =
        Result<LifecycleResourceV1, LifecycleModelError>> + 'bytes
    {
        self.rows(4).map(resource)
    }

    pub(crate) fn checksum(self) -> [u8; 32] {
        array32(&self.bytes[self.bytes.len() - 32..])
    }

    /// Borrows the complete original canonical representation.
    pub fn bytes(self) -> &'bytes [u8] {
        self.bytes
    }

    /// Returns the checked row count for one of the five sections.
    ///
    /// # Panics
    ///
    /// Panics when `section` is greater than four.
    pub fn count(self, section: usize) -> usize {
        self.counts[section]
    }

    /// Borrows the checked rows of one of the five sections.
    ///
    /// # Panics
    ///
    /// Panics when `section` is greater than four.
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
                            || !(matches!(row[0], 1..=5)
                                || (self.version() == 2 && row[0] == 9
                                    && self.companion_for_resource_v2(&row[..17]).is_some()))
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
            let class_valid = if self.version() == 2 {
                DeleteDependencyClassDataV2::from_endpoints_v2(row[34], left, right).is_ok()
                    && (row[34] != 7 || self.is_companion_edge_v2(row))
            } else {
                matches!(row[34], 1..=6)
            };
            if !class_valid
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
        if self.version() == 2 {
            digest.update(b"aos.sandbox.delete.graph-plan.v2\0");
        } else {
            digest.update(b"aos.sandbox.delete.graph-plan.v1\0");
        }
        digest.update(&self.bytes[16..32]);
        digest.update(&self.bytes[10..11]);
        digest.update(&self.bytes[64..81]);
        digest.update(&self.bytes[88..104]);
        // The request and authorization commit the caller's expected graph.
        // Including either here would make that precondition self-referential.
        // The whole batch checksum still commits both exact header fields.
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
        if !self.companions.is_empty() {
            digest.update(&self.bytes[316..320]);
            digest.update(self.companions);
        }
        digest.finalize().into()
    }
}

/// Traverses only slices established by a completely checked batch view.
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

/// Borrows the variable key from a checked W, R or C row.
///
/// # Panics
///
/// Panics for fewer than 56 bytes when `section == 1`, otherwise fewer than
/// 100 bytes. Callers retain the checked row/section pairing.
pub fn row_key(row: &[u8], section: usize) -> &[u8] {
    &row[if section == 1 { 56 } else { 100 }..]
}

/// Builds the established project/operation batch key.
pub fn batch_key(project: ProjectId, operation: OperationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(52);
    key.extend_from_slice(BATCH_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(operation.as_bytes());
    key
}

/// Builds the pending-overlay key using the supplied resource encoding.
///
/// Canonical callers supply exactly 17 resource bytes; this helper does not
/// validate that DATA or authenticate its owner.
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

/// Builds the fixed project/operation handoff key.
pub fn handoff_key(project: ProjectId, operation: OperationId) -> [u8; 54] {
    let mut key = [0; 54];
    key[..22].copy_from_slice(HANDOFF_PREFIX);
    key[22..38].copy_from_slice(project.as_bytes());
    key[38..].copy_from_slice(operation.as_bytes());
    key
}

/// Encodes the retained Source pending COMMIT reference as handoff DATA.
///
/// The producer must obtain `source_pending_native` from its genuine held
/// Source owner and compare that same original during append/readback. Neither
/// the reference nor this canonical encoding authenticates that owner.
///
/// # Errors
///
/// Rejects a malformed native COMMIT shape or an invalid resulting handoff.
pub fn encode_handoff_from_source_pending_data_v2(
    batch: DeleteBatchViewV1<'_>,
    source_pending_native: &[u8; 64],
) -> Result<[u8; 160], LifecycleModelError> {
    if zero(&source_pending_native[..16]) || zero(&source_pending_native[16..48])
        || matches!(raw64(&source_pending_native[48..56]), 0 | u64::MAX)
        || raw64(&source_pending_native[56..64]) == 0
    {
        return Err(corrupt());
    }
    let mut bytes = [0; 160];
    bytes[..8].copy_from_slice(b"AOSDHF01");
    bytes[9] = 1;
    bytes[10] = 1;
    bytes[16..32].copy_from_slice(batch.project().as_bytes());
    bytes[32..48].copy_from_slice(batch.operation().as_bytes());
    bytes[48..64].copy_from_slice(&batch.transaction());
    bytes[64..96].copy_from_slice(&batch.checksum());
    bytes[96..128].copy_from_slice(&source_pending_handoff_commitment_data_v2(source_pending_native));
    seal(&mut bytes, HANDOFF_DOMAIN);
    validate_handoff(&bytes, batch)?;
    Ok(bytes)
}

/// Commits exact native Source pending coordinates for a handoff comparison.
///
/// The domain names the existing non-authorizing handoff reference's concrete
/// producer. No decoded bytes or digest create Source custody or authority.
pub fn source_pending_handoff_commitment_data_v2(native: &[u8; 64]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.delete.source-pending-handoff.v2\0");
    hash.update(native);
    hash.finalize().into()
}

/// Validates retained handoff DATA without authenticating its Source reference.
///
/// # Errors
///
/// Returns an encoding error for malformed handoff shape, mismatched retained
/// batch context, reserved fields or checksum.
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

/// Encodes pending-tombstone DATA from a retained batch and checked W row.
///
/// The caller supplies the checked write row; this helper does not validate it.
///
/// # Panics
///
/// Panics when `row` contains fewer than 68 bytes.
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

/// Encodes the predecessor or successor collection DATA from a checked C row.
///
/// The caller supplies the checked collection row; this helper does not validate it.
///
/// # Panics
///
/// Panics for fewer than 60 bytes when `after` is false, or fewer than 100 bytes
/// when `after` is true.
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

/// Recognizes the four established reserved Delete key prefixes.
pub fn reserved_key(key: &[u8]) -> bool {
    key.starts_with(BATCH_PREFIX)
        || key.starts_with(TOMBSTONE_PREFIX)
        || key.starts_with(COLLECTION_PREFIX)
        || key.starts_with(HANDOFF_PREFIX)
}

/// Hashes the complete supplied value DATA with SHA-256.
pub fn native_value_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Reads one fixed-width big-endian unsigned integer.
///
/// # Panics
///
/// Panics unless `bytes` contains exactly eight bytes.
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
