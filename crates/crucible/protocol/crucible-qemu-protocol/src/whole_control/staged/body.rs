//! Complete stage inventories, native receipts, commits and execution references.
//!
//! These codecs retain full payload and common evidence bytes. Shape and digest
//! checks supply correlation only. The source-issued queue reservation and its
//! original allocation are separately retained by the installed native provider.
//!
//! ```text
//! stage: header128, stage_operation[N], batch[B], node[I], common[C], inventory[Q]
//! receipt256: scope, epoch, stage, body/plan/inventory hashes, actual counts,
//!             cutoff, reservation digest and native stage cut
//! commit128: scope, epoch, stage, cut, original body and receipt hashes
//! references: count:u32, reserved0:u32, entry64[count]
//! All integers are big endian; all reserved fields are zero.
//! ```

use super::{STAGE_HEADER_BYTES, STAGE_RECEIPT_BYTES};
use crate::whole_control::{
    WHOLE_ACK_BYTES, WHOLE_BODY_MAX_BYTES, WholeControlError, domain_digest,
    inventory::WholeInventory, put_u32, put_u64, read_u32, read_u64,
};

/// Borrows one complete original staged batch and its queue inventory.
#[derive(Clone, Debug)]
pub struct StageInventory<'a> {
    body: &'a [u8],
    /// Correlates the original constructor's process-protocol scope.
    pub scope: [u8; 32],
    /// Correlates the authentic native retained world incarnation.
    pub native_epoch: u64,
    /// Selects a separately indexed original input stage.
    pub stage_sequence: u64,
    /// Names the complete original common stage operation.
    pub stage_operation: &'a str,
    /// Names the complete original common batch.
    pub batch: &'a str,
    /// Names the batch's original common destination node.
    pub node: &'a str,
    /// Retains the batch's original physical cutoff in picoseconds.
    pub cutoff_ps: u64,
    /// Retains the batch's original causal cutoff coordinate.
    pub cutoff_microstep: u64,
    /// Retains the original common canonical inventory digest.
    pub common_inventory_digest: [u8; 32],
    /// Borrows complete original batch, owner, provenance and lineage evidence.
    pub common_batch: &'a [u8],
    /// Borrows every complete original input queue record and payload.
    pub queue_inventory: WholeInventory<'a>,
}

impl<'a> StageInventory<'a> {
    /// Checks a whole original stage before exposing its input records.
    ///
    /// # Errors
    /// Rejects truncated or trailing bytes, invalid identities, unsupported
    /// coordinates, reserved fields, malformed queue inventory or empty evidence.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        if !(STAGE_HEADER_BYTES..=WHOLE_BODY_MAX_BYTES as usize).contains(&body.len())
            || read_u32(body, 0) != 1
            || read_u32(body, 4) as usize != body.len()
            || body[8..40] == [0; 32]
            || read_u64(body, 40) == 0
            || read_u64(body, 48) == 0
            || read_u16(body, 62) != 0
            || body[80..88] != [0; 8]
            || read_u64(body, 64) > i64::MAX as u64
            || !read_u64(body, 64).is_multiple_of(50)
            || body[88..120] == [0; 32]
        {
            return Err(WholeControlError::Body);
        }
        let lengths = [56, 58, 60].map(|offset| read_u16(body, offset) as usize);
        let common_len = read_u32(body, 124) as usize;
        let inventory_len = read_u32(body, 120) as usize;
        let extent = lengths
            .into_iter()
            .try_fold(STAGE_HEADER_BYTES, |total, length| {
                total.checked_add(length)
            })
            .and_then(|total| total.checked_add(common_len))
            .and_then(|total| total.checked_add(inventory_len));
        if lengths.iter().any(|length| !(1..=128).contains(length))
            || common_len == 0
            || extent != Some(body.len())
        {
            return Err(WholeControlError::Body);
        }
        let mut offset = STAGE_HEADER_BYTES;
        let stage_operation = take_identifier(body, &mut offset, lengths[0])?;
        let batch = take_identifier(body, &mut offset, lengths[1])?;
        let node = take_identifier(body, &mut offset, lengths[2])?;
        let common_batch = &body[offset..offset + common_len];
        let queue_inventory = WholeInventory::decode(&body[offset + common_len..], true)?;
        if queue_inventory.records().any(|record| record.node != node) {
            return Err(WholeControlError::Correlation);
        }

        Ok(Self {
            body,
            scope: array32(body, 8),
            native_epoch: read_u64(body, 40),
            stage_sequence: read_u64(body, 48),
            stage_operation,
            batch,
            node,
            cutoff_ps: read_u64(body, 64),
            cutoff_microstep: read_u64(body, 72),
            common_inventory_digest: array32(body, 88),
            common_batch,
            queue_inventory,
        })
    }

    /// Borrows the complete same original body, including all input payloads.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Commits the entire immutable original stage body.
    pub fn digest(&self) -> [u8; 32] {
        domain_digest(b"crucible.qemu.whole.stage.v2\0", self.body)
    }

    /// Counts actual full native payload bytes independently of wire overhead.
    ///
    /// # Errors
    /// Rejects arithmetic overflow rather than saturating accepted input credit.
    pub fn payload_byte_count(&self) -> Result<u64, WholeControlError> {
        self.queue_inventory
            .records()
            .try_fold(0u64, |total, record| {
                total
                    .checked_add(record.payload.len() as u64)
                    .ok_or(WholeControlError::Budget)
            })
    }
}

/// Supplies full original input bytes to the bounded stage encoder.
pub struct StageInventoryParts<'a> {
    /// Correlates the authentic constructor scope.
    pub scope: [u8; 32],
    /// Correlates the authentic native world epoch.
    pub native_epoch: u64,
    /// Selects the original separately indexed stage slot.
    pub stage_sequence: u64,
    /// Names the common stage operation.
    pub stage_operation: &'a str,
    /// Names the common batch.
    pub batch: &'a str,
    /// Names the common destination node.
    pub node: &'a str,
    /// Retains the original physical cutoff.
    pub cutoff_ps: u64,
    /// Retains the original causal cutoff.
    pub cutoff_microstep: u64,
    /// Retains the original common inventory commitment.
    pub common_inventory_digest: [u8; 32],
    /// Supplies complete original common batch and evidence bytes.
    pub common_batch: &'a [u8],
    /// Supplies complete original encoded queue inventory and payloads.
    pub queue_inventory: &'a [u8],
}

impl StageInventoryParts<'_> {
    /// Encodes an entire stage into exact caller-owned preallocated backing.
    ///
    /// # Errors
    /// Rejects malformed source data, lengths or insufficient backing. Any
    /// partially written refused backing must remain in its caller's journal.
    pub fn encode_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        let parts = [
            self.stage_operation.as_bytes(),
            self.batch.as_bytes(),
            self.node.as_bytes(),
            self.common_batch,
            self.queue_inventory,
        ];
        let extent = parts.iter().try_fold(STAGE_HEADER_BYTES, |total, part| {
            total.checked_add(part.len())
        });
        if extent != Some(body.len())
            || body.len() > WHOLE_BODY_MAX_BYTES as usize
            || parts[..3]
                .iter()
                .any(|part| !(1..=128).contains(&part.len()))
        {
            return Err(WholeControlError::Body);
        }
        body.fill(0);
        put_u32(body, 0, 1);
        put_u32(body, 4, body.len() as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(body, 40, self.native_epoch);
        put_u64(body, 48, self.stage_sequence);
        for (index, part) in parts[..3].iter().enumerate() {
            put_u16(body, 56 + 2 * index, part.len() as u16);
        }
        put_u64(body, 64, self.cutoff_ps);
        put_u64(body, 72, self.cutoff_microstep);
        body[88..120].copy_from_slice(&self.common_inventory_digest);
        put_u32(body, 120, self.queue_inventory.len() as u32);
        put_u32(body, 124, self.common_batch.len() as u32);
        let mut offset = STAGE_HEADER_BYTES;
        for part in parts {
            body[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        StageInventory::decode(body)?;
        Ok(())
    }
}

/// Retains one complete native receipt for an actual original queue reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageReceipt {
    /// Correlates the original world scope.
    pub scope: [u8; 32],
    /// Correlates the original native world epoch.
    pub native_epoch: u64,
    /// Correlates the original independently indexed stage.
    pub stage_sequence: u64,
    /// Commits the complete original stage body.
    pub stage_body_digest: [u8; 32],
    /// Retains the original common canonical inventory commitment.
    pub common_inventory_digest: [u8; 32],
    /// Commits the complete same original source-issued queue plan.
    pub queue_plan_digest: [u8; 32],
    /// Counts actual accepted input queue records.
    pub accepted_records: u64,
    /// Counts actual accepted native payload bytes without encoded overhead.
    pub accepted_payload_bytes: u64,
    /// Retains the original physical cutoff.
    pub cutoff_ps: u64,
    /// Retains the original causal cutoff.
    pub cutoff_microstep: u64,
    /// Commits the actual original native queue reservation.
    pub reservation_digest: [u8; 32],
    /// Retains the native source-issued monotonic stage cut.
    pub stage_cut: u64,
}

impl StageReceipt {
    /// Decodes a full receipt without treating its bytes as source authority.
    ///
    /// # Errors
    /// Rejects malformed extents, reserved fields, zero correlations or cutoff.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != STAGE_RECEIPT_BYTES
            || read_u32(body, 0) != 1
            || read_u32(body, 4) != STAGE_RECEIPT_BYTES as u32
            || body[184..192] != [0; 8]
            || body[232..256] != [0; 24]
        {
            return Err(WholeControlError::Body);
        }
        let receipt = Self {
            scope: array32(body, 8),
            native_epoch: read_u64(body, 40),
            stage_sequence: read_u64(body, 48),
            stage_body_digest: array32(body, 56),
            common_inventory_digest: array32(body, 88),
            queue_plan_digest: array32(body, 120),
            accepted_records: read_u64(body, 152),
            accepted_payload_bytes: read_u64(body, 160),
            cutoff_ps: read_u64(body, 168),
            cutoff_microstep: read_u64(body, 176),
            reservation_digest: array32(body, 192),
            stage_cut: read_u64(body, 224),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Encodes an already source-issued receipt into its exact portable layout.
    ///
    /// # Errors
    /// Rejects invalid receipt correlations or coordinates. Encoding does not
    /// create a queue reservation, stage admission or native preparation proof.
    pub fn encode(&self) -> Result<[u8; STAGE_RECEIPT_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; STAGE_RECEIPT_BYTES];
        put_u32(&mut body, 0, 1);
        put_u32(&mut body, 4, STAGE_RECEIPT_BYTES as u32);
        for (offset, digest) in [
            (8, self.scope),
            (56, self.stage_body_digest),
            (88, self.common_inventory_digest),
            (120, self.queue_plan_digest),
            (192, self.reservation_digest),
        ] {
            body[offset..offset + 32].copy_from_slice(&digest);
        }
        for (offset, value) in [
            (40, self.native_epoch),
            (48, self.stage_sequence),
            (152, self.accepted_records),
            (160, self.accepted_payload_bytes),
            (168, self.cutoff_ps),
            (176, self.cutoff_microstep),
            (224, self.stage_cut),
        ] {
            put_u64(&mut body, offset, value);
        }
        Ok(body)
    }

    /// Correlates every original stage byte and actual payload count.
    ///
    /// # Errors
    /// Rejects a receipt for another stage, plan, cutoff, body or actual count.
    /// Callers additionally authenticate the same original source allocation.
    pub fn validate_against(
        &self,
        stage: &StageInventory<'_>,
        queue_plan_digest: [u8; 32],
    ) -> Result<(), WholeControlError> {
        self.validate()?;
        if self.scope != stage.scope
            || self.native_epoch != stage.native_epoch
            || self.stage_sequence != stage.stage_sequence
            || self.stage_cut != stage.stage_sequence
            || self.stage_body_digest != stage.digest()
            || self.common_inventory_digest != stage.common_inventory_digest
            || self.queue_plan_digest != queue_plan_digest
            || self.accepted_records != u64::from(stage.queue_inventory.record_count())
            || self.accepted_payload_bytes != stage.payload_byte_count()?
            || self.cutoff_ps != stage.cutoff_ps
            || self.cutoff_microstep != stage.cutoff_microstep
        {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    /// Commits the entire source-issued receipt for the original stage commit.
    ///
    /// # Errors
    /// Rejects invalid receipt data before hashing.
    pub fn digest(&self) -> Result<[u8; 32], WholeControlError> {
        Ok(domain_digest(
            b"crucible.qemu.whole.stage-receipt.v2\0",
            &self.encode()?,
        ))
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        if [
            self.scope,
            self.stage_body_digest,
            self.common_inventory_digest,
            self.queue_plan_digest,
            self.reservation_digest,
        ]
        .contains(&[0; 32])
            || self.native_epoch == 0
            || self.stage_sequence == 0
            || self.stage_cut != self.stage_sequence
            || self.cutoff_ps > i64::MAX as u64
            || !self.cutoff_ps.is_multiple_of(50)
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Retains the exact complete original stage commit and its consumed echo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageCommit {
    /// Correlates the original scope.
    pub scope: [u8; 32],
    /// Correlates the original native epoch.
    pub native_epoch: u64,
    /// Correlates the original stage.
    pub stage_sequence: u64,
    /// Retains the native-issued original stage cut.
    pub stage_cut: u64,
    /// Commits the complete same original stage body.
    pub stage_body_digest: [u8; 32],
    /// Commits the complete same original native stage receipt.
    pub stage_receipt_digest: [u8; 32],
}

impl StageCommit {
    /// Builds a portable commit for a correlated original source receipt.
    ///
    /// # Errors
    /// Rejects malformed or uncorrelated stage and receipt bytes.
    pub fn for_receipt(
        stage: &StageInventory<'_>,
        receipt: &StageReceipt,
        queue_plan_digest: [u8; 32],
    ) -> Result<Self, WholeControlError> {
        receipt.validate_against(stage, queue_plan_digest)?;
        Ok(Self {
            scope: receipt.scope,
            native_epoch: receipt.native_epoch,
            stage_sequence: receipt.stage_sequence,
            stage_cut: receipt.stage_cut,
            stage_body_digest: receipt.stage_body_digest,
            stage_receipt_digest: receipt.digest()?,
        })
    }

    /// Encodes the exact stage commit or consumed acknowledgement body.
    ///
    /// # Errors
    /// Rejects zero correlations or a cut outside its original stage slot.
    pub fn encode(&self) -> Result<[u8; WHOLE_ACK_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; WHOLE_ACK_BYTES];
        put_u32(&mut body, 0, 1);
        put_u32(&mut body, 4, WHOLE_ACK_BYTES as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(&mut body, 40, self.native_epoch);
        put_u64(&mut body, 48, self.stage_sequence);
        put_u64(&mut body, 56, self.stage_cut);
        body[64..96].copy_from_slice(&self.stage_body_digest);
        body[96..128].copy_from_slice(&self.stage_receipt_digest);
        Ok(body)
    }

    /// Checks one entire original stage commit or consumed echo body.
    ///
    /// # Errors
    /// Rejects malformed extents, zero correlations or an invalid stage cut.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != WHOLE_ACK_BYTES
            || read_u32(body, 0) != 1
            || read_u32(body, 4) != WHOLE_ACK_BYTES as u32
        {
            return Err(WholeControlError::Body);
        }
        let commit = Self {
            scope: array32(body, 8),
            native_epoch: read_u64(body, 40),
            stage_sequence: read_u64(body, 48),
            stage_cut: read_u64(body, 56),
            stage_body_digest: array32(body, 64),
            stage_receipt_digest: array32(body, 96),
        };
        commit.validate()?;
        Ok(commit)
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.native_epoch == 0
            || self.stage_sequence == 0
            || self.stage_cut != self.stage_sequence
            || self.stage_body_digest == [0; 32]
            || self.stage_receipt_digest == [0; 32]
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Borrows a compute reference to the same retained committed stage records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageReference {
    /// Selects an original committed stage slot.
    pub stage_sequence: u64,
    /// Correlates the original source-issued stage cut.
    pub stage_cut: u64,
    /// Commits the entire same original stage body.
    pub stage_body_digest: [u8; 32],
    /// Selects the first retained record consumed by this compute operation.
    pub first_record: u32,
    /// Counts the contiguous retained records consumed by this operation.
    pub record_count: u32,
}

/// Borrows a complete checked execution-reference body without allocation.
pub struct StageReferences<'a> {
    body: &'a [u8],
}

impl<'a> StageReferences<'a> {
    /// Checks every reference before exposing any execution input.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, reserved fields, zero correlations
    /// or overflowing ranges. Native admission additionally rejects absent,
    /// uncommitted, already consumed or overlapping original staged records.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        if body.len() < 8
            || body.len() > WHOLE_BODY_MAX_BYTES as usize
            || read_u32(body, 4) != 0
            || (read_u32(body, 0) as usize).checked_mul(64) != Some(body.len() - 8)
        {
            return Err(WholeControlError::Body);
        }
        for record in body[8..].as_chunks::<64>().0 {
            decode_reference(record)?;
        }
        Ok(Self { body })
    }

    /// Iterates every checked original stage reference without allocation.
    pub fn records(&self) -> impl Iterator<Item = StageReference> + 'a {
        self.body[8..]
            .as_chunks::<64>()
            .0
            .iter()
            .filter_map(|record| decode_reference(record).ok())
    }
}

fn decode_reference(body: &[u8]) -> Result<StageReference, WholeControlError> {
    let reference = StageReference {
        stage_sequence: read_u64(body, 0),
        stage_cut: read_u64(body, 8),
        stage_body_digest: array32(body, 16),
        first_record: read_u32(body, 48),
        record_count: read_u32(body, 52),
    };
    if reference.stage_sequence == 0
        || reference.stage_cut != reference.stage_sequence
        || reference.stage_body_digest == [0; 32]
        || reference.record_count == 0
        || reference
            .first_record
            .checked_add(reference.record_count)
            .is_none()
        || read_u64(body, 56) != 0
    {
        return Err(WholeControlError::Body);
    }
    Ok(reference)
}

fn take_identifier<'a>(
    body: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a str, WholeControlError> {
    let value = std::str::from_utf8(&body[*offset..*offset + length])
        .map_err(|_| WholeControlError::Body)?;
    *offset += length;
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(WholeControlError::Body);
    }
    Ok(value)
}

fn array32(body: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&body[offset..offset + 32]);
    value
}

fn put_u16(body: &mut [u8], offset: usize, value: u16) {
    body[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn read_u16(body: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([body[offset], body[offset + 1]])
}
