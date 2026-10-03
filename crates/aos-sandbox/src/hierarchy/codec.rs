//! Canonical bounded codecs for inert hierarchy snapshots and history records.
//!
//! The formats are deliberately private source-model formats. They are fixed,
//! big-endian, reject trailing bytes and reserved values, and carry independent
//! domain-separated SHA-256 commitments.

use aos_sandbox_core::{
    AttachmentId, DesiredGeneration, IncarnationId, ObjectDigest, OperationId, ProjectId, Revision,
    SandboxId, SnapshotId,
};
use sha2::{Digest as _, Sha256};

use super::graph::{MAXIMUM_TREE_TOMBSTONES, SandboxTreeV1};
use super::history::{
    CompactedHierarchyHistoryV1, HierarchyHistoryCheckpointV1, HierarchyHistoryError,
    HierarchyHistoryRecordV1, HierarchyHistorySubjectV1, HierarchyHistoryV1,
    HierarchyTransitionKindV1, MAXIMUM_HIERARCHY_HISTORY_RECORDS,
};
use super::model::{MAXIMUM_TREE_SANDBOXES, SandboxTreeRecordV1, TreeLimitsV1};

const TREE_MAGIC: &[u8; 8] = b"AOSHTR01";
const HISTORY_MAGIC: &[u8; 8] = b"AOSHHI01";
const HISTORY_LOG_MAGIC: &[u8; 8] = b"AOSHLG01";
const COMPACTED_HISTORY_MAGIC: &[u8; 8] = b"AOSHCG01";
const TREE_HEADER_BYTES: usize = 72;
const TREE_RECORD_BYTES: usize = 58;
const HISTORY_RECORD_BYTES: usize = 262;
const HISTORY_LOG_HEADER_BYTES: usize = 32;
const COMPACTED_HISTORY_HEADER_BYTES: usize = 176;
const RESOURCE_STATE_BYTES: usize = 50;
const FORMAT_VERSION: u16 = 1;
/// Maximum encoded hierarchy snapshot bytes.
pub const MAXIMUM_HIERARCHY_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

/// Encodes one validated project tree canonically.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] if a host-sized count cannot be represented,
/// checked encoded size exceeds the ceiling, or allocation fails.
pub fn encode_tree_v1(tree: &SandboxTreeV1) -> Result<Vec<u8>, HierarchyCodecError> {
    let count = tree.records().len();
    let tombstone_count = tree.tombstones().len();
    let encoded_len = TREE_RECORD_BYTES
        .checked_mul(count)
        .and_then(|bytes| {
            16_usize
                .checked_mul(tombstone_count)
                .and_then(|tombstone_bytes| bytes.checked_add(tombstone_bytes))
        })
        .and_then(|bytes| bytes.checked_add(TREE_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if encoded_len > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES {
        return Err(HierarchyCodecError::Capacity);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_len)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    bytes.extend_from_slice(TREE_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(tree.project().as_bytes());
    bytes.extend_from_slice(&tree.tree_generation().get().to_be_bytes());
    let limits = tree.limits();
    for limit in [
        limits.maximum_project_roots(),
        limits.maximum_project_sandboxes(),
        limits.maximum_project_live_sandboxes(),
        limits.maximum_depth(),
        limits.maximum_children_per_parent(),
        limits.maximum_descendants(),
        limits.maximum_live_descendants(),
    ] {
        bytes.extend_from_slice(&to_u32(limit)?.to_be_bytes());
    }
    bytes.extend_from_slice(&to_u32(count)?.to_be_bytes());
    bytes.extend_from_slice(&to_u32(tombstone_count)?.to_be_bytes());
    for record in tree.records() {
        bytes.extend_from_slice(record.sandbox().as_bytes());
        match record.parent() {
            Some(parent) => {
                bytes.push(1);
                bytes.extend_from_slice(parent.as_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 16]);
            }
        }
        bytes.extend_from_slice(&record.desired_generation().get().to_be_bytes());
        match record.incarnation() {
            Some(incarnation) => {
                bytes.push(1);
                bytes.extend_from_slice(incarnation.as_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 16]);
            }
        }
    }
    for tombstone in tree.tombstones() {
        bytes.extend_from_slice(tombstone.as_bytes());
    }
    if bytes.len() != encoded_len {
        return Err(HierarchyCodecError::CorruptEncoding);
    }
    Ok(bytes)
}

/// Decodes and fully revalidates one canonical project tree.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] for invalid framing, reserved values,
/// trailing bytes, size overflow, or any invalid tree invariant.
pub fn decode_tree_v1(bytes: &[u8]) -> Result<SandboxTreeV1, HierarchyCodecError> {
    if bytes.len() < TREE_HEADER_BYTES || bytes.len() > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *TREE_MAGIC
        || u16::from_be_bytes(cursor.take::<2>()?) != FORMAT_VERSION
        || cursor.take::<2>()? != [0; 2]
    {
        return Err(HierarchyCodecError::InvalidHeader);
    }
    let project = ProjectId::from_bytes(cursor.take::<16>()?);
    let tree_generation = Revision::new(u64::from_be_bytes(cursor.take::<8>()?));
    let limits = TreeLimitsV1::new(
        cursor.take_u32()? as usize,
        cursor.take_u32()? as usize,
        cursor.take_u32()? as usize,
        cursor.take_u32()? as usize,
        cursor.take_u32()? as usize,
        cursor.take_u32()? as usize,
        cursor.take_u32()? as usize,
    )
    .map_err(|_| HierarchyCodecError::InvalidTree)?;
    let count = cursor.take_u32()? as usize;
    let tombstone_count = cursor.take_u32()? as usize;
    if count > MAXIMUM_TREE_SANDBOXES {
        return Err(HierarchyCodecError::Capacity);
    }
    if tombstone_count > MAXIMUM_TREE_TOMBSTONES {
        return Err(HierarchyCodecError::Capacity);
    }
    let expected = TREE_RECORD_BYTES
        .checked_mul(count)
        .and_then(|bytes| {
            16_usize
                .checked_mul(tombstone_count)
                .and_then(|tombstone_bytes| bytes.checked_add(tombstone_bytes))
        })
        .and_then(|size| size.checked_add(TREE_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if expected != bytes.len() {
        return Err(HierarchyCodecError::InvalidLength);
    }

    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    for _ in 0..count {
        let sandbox = SandboxId::from_bytes(cursor.take::<16>()?);
        let parent_present = cursor.take::<1>()?[0];
        let parent_bytes = cursor.take::<16>()?;
        let parent = match parent_present {
            0 if parent_bytes == [0; 16] => None,
            1 if parent_bytes != [0; 16] => Some(SandboxId::from_bytes(parent_bytes)),
            _ => return Err(HierarchyCodecError::CorruptEncoding),
        };
        let desired_generation = DesiredGeneration::new(u64::from_be_bytes(cursor.take::<8>()?));
        let incarnation_present = cursor.take::<1>()?[0];
        let incarnation_bytes = cursor.take::<16>()?;
        let incarnation = match incarnation_present {
            0 if incarnation_bytes == [0; 16] => None,
            1 if incarnation_bytes != [0; 16] => Some(IncarnationId::from_bytes(incarnation_bytes)),
            _ => return Err(HierarchyCodecError::CorruptEncoding),
        };
        records.push(
            SandboxTreeRecordV1::new(project, sandbox, parent, desired_generation, incarnation)
                .map_err(|_| HierarchyCodecError::InvalidTree)?,
        );
    }
    let mut tombstones = Vec::new();
    tombstones
        .try_reserve_exact(tombstone_count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    for _ in 0..tombstone_count {
        tombstones.push(SandboxId::from_bytes(cursor.take::<16>()?));
    }
    if !cursor.is_empty() {
        return Err(HierarchyCodecError::InvalidLength);
    }
    SandboxTreeV1::from_records_and_tombstones(
        project,
        tree_generation,
        limits,
        records,
        tombstones,
    )
    .map_err(|_| HierarchyCodecError::InvalidTree)
}

/// Returns the canonical tree snapshot commitment.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] if canonical encoding cannot be produced.
pub fn tree_commitment_v1(tree: &SandboxTreeV1) -> Result<ObjectDigest, HierarchyCodecError> {
    let bytes = encode_tree_v1(tree)?;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-tree.v1\0");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Encodes one fixed-size hierarchy history record.
///
/// # Errors
///
/// Returns [`HierarchyCodecError::CorruptEncoding`] only if the fixed schema
/// implementation produces an unexpected length.
pub fn encode_history_record_v1(
    record: HierarchyHistoryRecordV1,
) -> Result<[u8; HISTORY_RECORD_BYTES], HierarchyCodecError> {
    let mut bytes = [0_u8; HISTORY_RECORD_BYTES];
    let mut offset = 0;
    write(&mut bytes, &mut offset, HISTORY_MAGIC)?;
    write(&mut bytes, &mut offset, &FORMAT_VERSION.to_be_bytes())?;
    write(&mut bytes, &mut offset, &[record.transition() as u8])?;
    write(&mut bytes, &mut offset, &[record.subject().tag()])?;
    write(&mut bytes, &mut offset, record.project().as_bytes())?;
    write(&mut bytes, &mut offset, &record.sequence().to_be_bytes())?;
    write(&mut bytes, &mut offset, &record.subject().bytes())?;
    write(&mut bytes, &mut offset, record.operation().as_bytes())?;
    write(&mut bytes, &mut offset, record.idempotency_key().as_bytes())?;
    write(
        &mut bytes,
        &mut offset,
        record.request_commitment().as_bytes(),
    )?;
    match record.prior_resource_commitment() {
        Some(commitment) => {
            write(&mut bytes, &mut offset, &[1])?;
            write(&mut bytes, &mut offset, commitment.as_bytes())?;
        }
        None => {
            write(&mut bytes, &mut offset, &[0])?;
            write(&mut bytes, &mut offset, &[0; 32])?;
        }
    }
    match record.predecessor() {
        Some(predecessor) => {
            write(&mut bytes, &mut offset, &[1])?;
            write(&mut bytes, &mut offset, predecessor.as_bytes())?;
        }
        None => {
            write(&mut bytes, &mut offset, &[0])?;
            write(&mut bytes, &mut offset, &[0; 32])?;
        }
    }
    write(
        &mut bytes,
        &mut offset,
        record.result_commitment().as_bytes(),
    )?;
    write(
        &mut bytes,
        &mut offset,
        record.record_commitment().as_bytes(),
    )?;
    if offset != HISTORY_RECORD_BYTES {
        return Err(HierarchyCodecError::CorruptEncoding);
    }
    Ok(bytes)
}

/// Decodes and verifies one fixed-size hierarchy history record.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] for invalid framing, tags, sentinels, or
/// record commitment.
pub fn decode_history_record_v1(
    bytes: &[u8],
) -> Result<HierarchyHistoryRecordV1, HierarchyCodecError> {
    if bytes.len() != HISTORY_RECORD_BYTES {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *HISTORY_MAGIC
        || u16::from_be_bytes(cursor.take::<2>()?) != FORMAT_VERSION
    {
        return Err(HierarchyCodecError::InvalidHeader);
    }
    let transition = HierarchyTransitionKindV1::from_byte(cursor.take::<1>()?[0])
        .map_err(HierarchyCodecError::History)?;
    let subject_tag = cursor.take::<1>()?[0];
    let project = ProjectId::from_bytes(cursor.take::<16>()?);
    let sequence = u64::from_be_bytes(cursor.take::<8>()?);
    let subject_bytes = cursor.take::<16>()?;
    let subject = match subject_tag {
        0 => HierarchyHistorySubjectV1::Project(ProjectId::from_bytes(subject_bytes)),
        1 => HierarchyHistorySubjectV1::Sandbox(SandboxId::from_bytes(subject_bytes)),
        2 => HierarchyHistorySubjectV1::Attachment(AttachmentId::from_bytes(subject_bytes)),
        3 => HierarchyHistorySubjectV1::Snapshot(SnapshotId::from_bytes(subject_bytes)),
        _ => return Err(HierarchyCodecError::CorruptEncoding),
    };
    let operation = OperationId::from_bytes(cursor.take::<16>()?);
    let idempotency_key = ObjectDigest::from_bytes(cursor.take::<32>()?);
    let request_commitment = ObjectDigest::from_bytes(cursor.take::<32>()?);
    let resource_head_present = cursor.take::<1>()?[0];
    let resource_head_bytes = cursor.take::<32>()?;
    let prior_resource_commitment = match resource_head_present {
        0 if resource_head_bytes == [0; 32] => None,
        1 if resource_head_bytes != [0; 32] => Some(ObjectDigest::from_bytes(resource_head_bytes)),
        _ => return Err(HierarchyCodecError::CorruptEncoding),
    };
    let predecessor_present = cursor.take::<1>()?[0];
    let predecessor_bytes = cursor.take::<32>()?;
    let predecessor = match predecessor_present {
        0 if predecessor_bytes == [0; 32] => None,
        1 if predecessor_bytes != [0; 32] => Some(ObjectDigest::from_bytes(predecessor_bytes)),
        _ => return Err(HierarchyCodecError::CorruptEncoding),
    };
    let result_commitment = ObjectDigest::from_bytes(cursor.take::<32>()?);
    let record_commitment = ObjectDigest::from_bytes(cursor.take::<32>()?);
    HierarchyHistoryRecordV1::from_decoded_parts(
        project,
        sequence,
        subject,
        transition,
        operation,
        idempotency_key,
        request_commitment,
        prior_resource_commitment,
        predecessor,
        result_commitment,
        record_commitment,
    )
    .map_err(HierarchyCodecError::History)
}

/// Encodes a complete validated project history canonically.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] when checked length or allocation exceeds
/// the bounded source-model format.
pub fn encode_history_v1(history: &HierarchyHistoryV1) -> Result<Vec<u8>, HierarchyCodecError> {
    let encoded_len = HISTORY_RECORD_BYTES
        .checked_mul(history.records().len())
        .and_then(|bytes| bytes.checked_add(HISTORY_LOG_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if encoded_len > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES {
        return Err(HierarchyCodecError::Capacity);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_len)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    bytes.extend_from_slice(HISTORY_LOG_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(history.project().as_bytes());
    bytes.extend_from_slice(&to_u32(history.records().len())?.to_be_bytes());
    for record in history.records() {
        bytes.extend_from_slice(&encode_history_record_v1(*record)?);
    }
    if bytes.len() != encoded_len {
        return Err(HierarchyCodecError::CorruptEncoding);
    }
    Ok(bytes)
}

/// Decodes and validates a complete project history.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] for framing, count, record, chain, or
/// idempotency conflicts.
pub fn decode_history_v1(bytes: &[u8]) -> Result<HierarchyHistoryV1, HierarchyCodecError> {
    if bytes.len() < HISTORY_LOG_HEADER_BYTES || bytes.len() > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *HISTORY_LOG_MAGIC
        || u16::from_be_bytes(cursor.take::<2>()?) != FORMAT_VERSION
        || cursor.take::<2>()? != [0; 2]
    {
        return Err(HierarchyCodecError::InvalidHeader);
    }
    let project = ProjectId::from_bytes(cursor.take::<16>()?);
    let count = cursor.take_u32()? as usize;
    if count > MAXIMUM_HIERARCHY_HISTORY_RECORDS {
        return Err(HierarchyCodecError::Capacity);
    }
    let expected = HISTORY_RECORD_BYTES
        .checked_mul(count)
        .and_then(|bytes| bytes.checked_add(HISTORY_LOG_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if expected != bytes.len() {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    for _ in 0..count {
        let record_bytes = cursor.take_slice(HISTORY_RECORD_BYTES)?;
        records.push(decode_history_record_v1(record_bytes)?);
    }
    HierarchyHistoryV1::from_records(project, records).map_err(HierarchyCodecError::History)
}

/// Returns the canonical complete history commitment.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] if canonical history encoding fails.
pub fn history_commitment_v1(
    history: &HierarchyHistoryV1,
) -> Result<ObjectDigest, HierarchyCodecError> {
    let bytes = encode_history_v1(history)?;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-history.v1\0");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Encodes a protected history floor, summaries, and retained suffix canonically.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] for checked size or allocation exhaustion.
pub fn encode_compacted_history_v1(
    history: &CompactedHierarchyHistoryV1,
) -> Result<Vec<u8>, HierarchyCodecError> {
    let state_count = history.floor_states().len();
    let retired_count = history.retired_idempotency_keys().len();
    let suffix_count = history.suffix().len();
    let encoded_len = RESOURCE_STATE_BYTES
        .checked_mul(state_count)
        .and_then(|bytes| {
            32_usize
                .checked_mul(retired_count)
                .and_then(|keys| bytes.checked_add(keys))
        })
        .and_then(|bytes| {
            HISTORY_RECORD_BYTES
                .checked_mul(suffix_count)
                .and_then(|records| bytes.checked_add(records))
        })
        .and_then(|bytes| bytes.checked_add(COMPACTED_HISTORY_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if encoded_len > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES {
        return Err(HierarchyCodecError::Capacity);
    }
    let checkpoint = history.checkpoint();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_len)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    bytes.extend_from_slice(COMPACTED_HISTORY_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(checkpoint.project().as_bytes());
    bytes.extend_from_slice(&checkpoint.through_sequence().to_be_bytes());
    bytes.extend_from_slice(checkpoint.through_record_commitment().as_bytes());
    bytes.extend_from_slice(checkpoint.state_commitment().as_bytes());
    bytes.extend_from_slice(checkpoint.checkpoint_commitment().as_bytes());
    bytes.extend_from_slice(checkpoint.protected_checkpoint_commitment().as_bytes());
    bytes.extend_from_slice(&to_u32(state_count)?.to_be_bytes());
    bytes.extend_from_slice(&to_u32(retired_count)?.to_be_bytes());
    bytes.extend_from_slice(&to_u32(suffix_count)?.to_be_bytes());
    for (subject, transition) in history.floor_states() {
        bytes.push(subject.tag());
        bytes.push(*transition as u8);
        bytes.extend_from_slice(&subject.bytes());
        let head = history
            .floor_heads()
            .get(subject)
            .ok_or(HierarchyCodecError::CorruptEncoding)?;
        bytes.extend_from_slice(head.as_bytes());
    }
    for key in history.retired_idempotency_keys() {
        bytes.extend_from_slice(key.as_bytes());
    }
    for record in history.suffix() {
        bytes.extend_from_slice(&encode_history_record_v1(*record)?);
    }
    if bytes.len() != encoded_len {
        return Err(HierarchyCodecError::CorruptEncoding);
    }
    Ok(bytes)
}

/// Decodes a compacted history against an independently verified protected floor.
///
/// # Errors
///
/// Returns [`HierarchyCodecError`] for framing, bound, checkpoint, summary,
/// resource-transition, idempotency, or suffix-chain conflicts.
pub fn decode_compacted_history_v1(
    bytes: &[u8],
    verified_checkpoint: HierarchyHistoryCheckpointV1,
) -> Result<CompactedHierarchyHistoryV1, HierarchyCodecError> {
    if bytes.len() < COMPACTED_HISTORY_HEADER_BYTES
        || bytes.len() > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES
    {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *COMPACTED_HISTORY_MAGIC
        || u16::from_be_bytes(cursor.take::<2>()?) != FORMAT_VERSION
        || cursor.take::<2>()? != [0; 2]
        || ProjectId::from_bytes(cursor.take::<16>()?) != verified_checkpoint.project()
        || u64::from_be_bytes(cursor.take::<8>()?) != verified_checkpoint.through_sequence()
        || ObjectDigest::from_bytes(cursor.take::<32>()?)
            != verified_checkpoint.through_record_commitment()
        || ObjectDigest::from_bytes(cursor.take::<32>()?) != verified_checkpoint.state_commitment()
        || ObjectDigest::from_bytes(cursor.take::<32>()?)
            != verified_checkpoint.checkpoint_commitment()
        || ObjectDigest::from_bytes(cursor.take::<32>()?)
            != verified_checkpoint.protected_checkpoint_commitment()
    {
        return Err(HierarchyCodecError::InvalidHeader);
    }
    let state_count = cursor.take_u32()? as usize;
    let retired_count = cursor.take_u32()? as usize;
    let suffix_count = cursor.take_u32()? as usize;
    let retained_units = state_count
        .checked_add(suffix_count)
        .ok_or(HierarchyCodecError::Capacity)?;
    if retained_units > MAXIMUM_HIERARCHY_HISTORY_RECORDS
        || retired_count > MAXIMUM_HIERARCHY_HISTORY_RECORDS
    {
        return Err(HierarchyCodecError::Capacity);
    }
    let expected = RESOURCE_STATE_BYTES
        .checked_mul(state_count)
        .and_then(|size| {
            32_usize
                .checked_mul(retired_count)
                .and_then(|keys| size.checked_add(keys))
        })
        .and_then(|size| {
            HISTORY_RECORD_BYTES
                .checked_mul(suffix_count)
                .and_then(|records| size.checked_add(records))
        })
        .and_then(|size| size.checked_add(COMPACTED_HISTORY_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if expected != bytes.len() {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut floor_states = Vec::new();
    floor_states
        .try_reserve_exact(state_count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    let mut floor_heads = Vec::new();
    floor_heads
        .try_reserve_exact(state_count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    for _ in 0..state_count {
        let subject_tag = cursor.take::<1>()?[0];
        let transition = HierarchyTransitionKindV1::from_byte(cursor.take::<1>()?[0])?;
        let identity = cursor.take::<16>()?;
        let subject = decode_subject(subject_tag, identity)?;
        let resource_head = ObjectDigest::from_bytes(cursor.take::<32>()?);
        floor_states.push((subject, transition));
        floor_heads.push((subject, resource_head));
    }
    let mut retired_keys = Vec::new();
    retired_keys
        .try_reserve_exact(retired_count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    for _ in 0..retired_count {
        retired_keys.push(ObjectDigest::from_bytes(cursor.take::<32>()?));
    }
    let mut suffix = Vec::new();
    suffix
        .try_reserve_exact(suffix_count)
        .map_err(|_| HierarchyCodecError::Capacity)?;
    for _ in 0..suffix_count {
        suffix.push(decode_history_record_v1(
            cursor.take_slice(HISTORY_RECORD_BYTES)?,
        )?);
    }
    CompactedHierarchyHistoryV1::recover(
        verified_checkpoint,
        floor_states,
        floor_heads,
        retired_keys,
        suffix,
    )
    .map_err(HierarchyCodecError::History)
}

fn decode_subject(
    tag: u8,
    bytes: [u8; 16],
) -> Result<HierarchyHistorySubjectV1, HierarchyCodecError> {
    match tag {
        0 => Ok(HierarchyHistorySubjectV1::Project(ProjectId::from_bytes(
            bytes,
        ))),
        1 => Ok(HierarchyHistorySubjectV1::Sandbox(SandboxId::from_bytes(
            bytes,
        ))),
        2 => Ok(HierarchyHistorySubjectV1::Attachment(
            AttachmentId::from_bytes(bytes),
        )),
        3 => Ok(HierarchyHistorySubjectV1::Snapshot(SnapshotId::from_bytes(
            bytes,
        ))),
        _ => Err(HierarchyCodecError::CorruptEncoding),
    }
}

fn to_u32(value: usize) -> Result<u32, HierarchyCodecError> {
    u32::try_from(value).map_err(|_| HierarchyCodecError::Capacity)
}

fn write<const N: usize>(
    output: &mut [u8; HISTORY_RECORD_BYTES],
    offset: &mut usize,
    value: &[u8; N],
) -> Result<(), HierarchyCodecError> {
    let end = offset.checked_add(N).ok_or(HierarchyCodecError::Capacity)?;
    let destination = output
        .get_mut(*offset..end)
        .ok_or(HierarchyCodecError::CorruptEncoding)?;
    destination.copy_from_slice(value);
    *offset = end;
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], HierarchyCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(HierarchyCodecError::Capacity)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(HierarchyCodecError::InvalidLength)?;
        let mut value = [0; N];
        value.copy_from_slice(source);
        self.offset = end;
        Ok(value)
    }

    fn take_u32(&mut self) -> Result<u32, HierarchyCodecError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], HierarchyCodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HierarchyCodecError::Capacity)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(HierarchyCodecError::InvalidLength)?;
        self.offset = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Reports invalid, excessive, or noncanonical hierarchy encoding.
#[derive(Debug, thiserror::Error)]
pub enum HierarchyCodecError {
    /// Encoded input has invalid magic, version, or reserved bytes.
    #[error("hierarchy encoding header is invalid")]
    InvalidHeader,
    /// Encoded input length is inconsistent or has trailing bytes.
    #[error("hierarchy encoding length is invalid")]
    InvalidLength,
    /// Encoded fields violate the fixed schema.
    #[error("hierarchy encoding is corrupt")]
    CorruptEncoding,
    /// Decoded graph violates a hierarchy invariant.
    #[error("decoded hierarchy tree is invalid")]
    InvalidTree,
    /// Checked size or allocation capacity is exhausted.
    #[error("hierarchy encoding capacity is exhausted")]
    Capacity,
    /// History record validation failed.
    #[error(transparent)]
    History(#[from] HierarchyHistoryError),
}
