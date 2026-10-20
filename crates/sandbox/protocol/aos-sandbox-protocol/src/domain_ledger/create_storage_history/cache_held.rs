//! Encodes the new Cache Held comparison body and its exact native receipt.
//!
//! ```text
//! AOSXKH01 | association192 | Source-Held-checksum32 |
//! Bootstrap64 | Hold64 | State64 | Authority64 | Clock64 |
//! physical128 | selected-partition32 | selected-head32 | quota32 |
//! disk-count8 | negative-count8 | pin-count8 | clock-floor8
//! coordinate = protected-names48 | NEXT8 | durable-end8
//! receipt = record948 | head40 | Hold-names48 | Hold-after-NEXT8 | Hold-after-end8
//! ```
//!
//! Every field is historical DATA. Only the actual initialized Native Cache
//! loan can hold the writers, clock, gate and physical owner through use. A
//! decoded row does not grant authority, custody, a payer or a fresh deadline.

use super::super::protected_names::ProtectedJournalNamesV1;
use super::{HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1,
    PhaseV1, RECORD_OVERHEAD_BYTES, RecordEnvelopeV1, nonzero, reader};
use super::association::AcceptedAssociationDataV1;

/// Checks the fresh independent Cache signature and exact current coordinates.
pub mod current_proof;

/// Holds the exact fixed Cache Held body extent.
pub const CACHE_HELD_BODY_BYTES_V1: usize = 808;
/// Holds the exact Cache Held envelope extent.
pub const CACHE_HELD_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + CACHE_HELD_BODY_BYTES_V1;
/// Holds the exact postappend Cache Held receipt extent.
pub const CACHE_HELD_RECEIPT_BYTES_V1: usize = CACHE_HELD_RECORD_BYTES_V1 + HEAD_BYTES + 48 + 8 + 8;

/// Describes one actual held writer's preappend comparison coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheJournalDataV1 {
    /// The fixed original directory, writer and lock identities.
    pub names: ProtectedJournalNamesV1,
    /// The next original native sequence before the Cache Held append.
    pub next: u64,
    /// The original durable native byte end before that append.
    pub end: u64,
}

impl CacheJournalDataV1 {
    fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            next: input.u64()?, end: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn encode(self) -> Result<[u8; 64], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; 64];
        bytes[..48].copy_from_slice(&self.names.to_bytes());
        bytes[48..56].copy_from_slice(&self.next.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.end.to_be_bytes());
        Ok(bytes)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        ProtectedJournalNamesV1::from_bytes(&self.names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if self.next == 0 { return Err(HistoryErrorV1::Malformed); }
        Ok(())
    }
}

/// Describes the original held physical owner's fixed identities and head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePhysicalDataV1 {
    /// The fixed physical root's device and inode.
    pub root: (u64, u64),
    /// The physical root's original owner UID.
    pub uid: u32,
    /// The original root's permission mode, exactly 0700.
    pub mode: u32,
    /// The retained flock file's device and inode.
    pub lock: (u64, u64),
    /// The manifest's device/inode, both zero only for an absent genesis file.
    pub manifest: (u64, u64),
    /// The previously validated original manifest generation.
    pub generation: u64,
    /// The complete original physical manifest head, zero only at genesis.
    pub digest: [u8; 32],
    /// The existing physical-owner limits digest.
    pub limits: [u8; 32],
}

impl CachePhysicalDataV1 {
    /// Encodes the same complete physical comparison through its sole codec.
    ///
    /// This is historical DATA, not a held physical/currentness capability.
    ///
    /// # Errors
    /// Refuses the established invalid physical name/genesis/manifest/limit shape.
    pub fn canonical_comparison_bytes_v1(self) -> Result<[u8; 128], HistoryErrorV1> {
        self.encode()
    }

    fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            root: (input.u64()?, input.u64()?), uid: input.u32()?, mode: input.u32()?,
            lock: (input.u64()?, input.u64()?), manifest: (input.u64()?, input.u64()?),
            generation: input.u64()?, digest: input.array()?, limits: input.array()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn encode(self) -> Result<[u8; 128], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; 128];
        bytes[..8].copy_from_slice(&self.root.0.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.root.1.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.uid.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.mode.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.lock.0.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.lock.1.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.manifest.0.to_be_bytes());
        bytes[48..56].copy_from_slice(&self.manifest.1.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.generation.to_be_bytes());
        bytes[64..96].copy_from_slice(&self.digest);
        bytes[96..128].copy_from_slice(&self.limits);
        Ok(bytes)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        let genesis = self.generation == 0 && self.digest == [0; 32] && self.manifest == (0, 0);
        let committed = self.generation != 0 && self.digest != [0; 32]
            && self.manifest.0 == self.root.0 && self.manifest.1 != 0
            && self.manifest.1 != self.root.1 && self.manifest.1 != self.lock.1;
        if self.root.0 == 0 || self.root.1 == 0 || self.uid == 0 || self.mode != 0o700
            || self.lock.0 != self.root.0 || self.lock.1 == 0 || self.lock.1 == self.root.1
            || (!genesis && !committed) || self.limits == [0; 32]
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}

/// Describes the exact new Cache Held body without granting a live original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheHeldBodyDataV1 {
    /// The same accepted association carried by the actual Source Held row.
    pub association: AcceptedAssociationDataV1,
    /// The checksum of that exact complete Source Held envelope.
    pub source_held: [u8; 32],
    /// The same original immutable Controller Cache bootstrap writer.
    pub bootstrap: CacheJournalDataV1,
    /// The actual hold writer receiving the new record/head pair.
    pub hold: CacheJournalDataV1,
    /// The same original Cache State writer.
    pub state: CacheJournalDataV1,
    /// The same original protected replay-authority writer.
    pub authority: CacheJournalDataV1,
    /// The frozen original clock-floor writer.
    pub clock: CacheJournalDataV1,
    /// The actual held physical original's identity and complete durable head.
    pub physical: CachePhysicalDataV1,
    /// The uniquely selected protected project partition digest.
    pub selected_partition: [u8; 32],
    /// The existing protected project-physical head digest.
    pub selected_head: [u8; 32],
    /// The existing canonical complete-node-quota commitment.
    pub quota: [u8; 32],
    /// The actual complete physical manifest's durable disk entry count.
    pub disk_count: u64,
    /// The same complete manifest's retained negative entry count.
    pub negative_count: u64,
    /// The same physical original's durable pin count.
    pub pin_count: u64,
    /// The actual frozen monotone wall-clock floor in Unix seconds.
    pub clock_floor: u64,
}

impl CacheHeldBodyDataV1 {
    /// Decodes the exact body without allocation or original-owner admission.
    ///
    /// # Errors
    /// Rejects nonexact extent, wrong magic, invalid coordinates or association.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXKH01" { return Err(HistoryErrorV1::Malformed); }
        let value = Self {
            association: AcceptedAssociationDataV1::decode(input.bytes(192)?)?,
            source_held: input.array()?,
            bootstrap: CacheJournalDataV1::decode(input.bytes(64)?)?,
            hold: CacheJournalDataV1::decode(input.bytes(64)?)?,
            state: CacheJournalDataV1::decode(input.bytes(64)?)?,
            authority: CacheJournalDataV1::decode(input.bytes(64)?)?,
            clock: CacheJournalDataV1::decode(input.bytes(64)?)?,
            physical: CachePhysicalDataV1::decode(input.bytes(128)?)?,
            selected_partition: input.array()?, selected_head: input.array()?, quota: input.array()?,
            disk_count: input.u64()?, negative_count: input.u64()?, pin_count: input.u64()?,
            clock_floor: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes one exact fixed body without allocation.
    ///
    /// # Errors
    /// Rejects an invalid association, writer or physical comparison field.
    pub fn encode(self) -> Result<[u8; CACHE_HELD_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; CACHE_HELD_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXKH01");
        bytes[8..200].copy_from_slice(&self.association.encode()?);
        bytes[200..232].copy_from_slice(&self.source_held);
        bytes[232..296].copy_from_slice(&self.bootstrap.encode()?);
        bytes[296..360].copy_from_slice(&self.hold.encode()?);
        bytes[360..424].copy_from_slice(&self.state.encode()?);
        bytes[424..488].copy_from_slice(&self.authority.encode()?);
        bytes[488..552].copy_from_slice(&self.clock.encode()?);
        bytes[552..680].copy_from_slice(&self.physical.encode()?);
        bytes[680..712].copy_from_slice(&self.selected_partition);
        bytes[712..744].copy_from_slice(&self.selected_head);
        bytes[744..776].copy_from_slice(&self.quota);
        bytes[776..784].copy_from_slice(&self.disk_count.to_be_bytes());
        bytes[784..792].copy_from_slice(&self.negative_count.to_be_bytes());
        bytes[792..800].copy_from_slice(&self.pin_count.to_be_bytes());
        bytes[800..808].copy_from_slice(&self.clock_floor.to_be_bytes());
        Ok(bytes)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.association.validate()?;
        nonzero(&self.source_held)?;
        for journal in [self.bootstrap, self.hold, self.state, self.authority, self.clock] {
            journal.validate()?;
        }
        if self.hold.next.checked_add(4).is_none() { return Err(HistoryErrorV1::Extent); }
        self.physical.validate()?;
        nonzero(&self.selected_partition)?;
        nonzero(&self.selected_head)?;
        nonzero(&self.quota)?;
        if self.physical.generation == 0
            && (self.disk_count != 0 || self.negative_count != 0 || self.pin_count != 0)
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

/// Borrows the complete Cache Held row beside its postappend native positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheHeldReceiptDataV1<'record> {
    /// The complete original Held envelope, without a copy of its body.
    pub record: &'record [u8; CACHE_HELD_RECORD_BYTES_V1],
    /// The exact latest head atomically appended beside this record.
    pub latest_head: [u8; HEAD_BYTES],
    /// The same HOLD writer's unchanged original physical names.
    pub hold_names: ProtectedJournalNamesV1,
    /// The actual returned/read-back HOLD NEXT after the pair.
    pub hold_after_next: u64,
    /// The actual returned/read-back durable HOLD byte end.
    pub hold_after_end: u64,
}

impl<'record> CacheHeldReceiptDataV1<'record> {
    /// Borrows one exact fixed receipt under the expected original lane.
    ///
    /// # Errors
    /// Rejects extent, body, head, lane or native-coordinate inconsistency.
    /// Successful parsing authenticates no live writer or returned append.
    pub fn decode(bytes: &'record [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            record: input.bytes(CACHE_HELD_RECORD_BYTES_V1)?.try_into()
                .map_err(|_| HistoryErrorV1::Extent)?,
            latest_head: input.array()?,
            hold_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            hold_after_next: input.u64()?, hold_after_end: input.u64()?,
        };
        input.finish()?;
        value.body(lane)?;
        Ok(value)
    }

    /// Returns the exact checked body as comparison DATA.
    ///
    /// # Errors
    /// Rejects a substituted row/head, a predecessor on the first Held phase,
    /// a different seed/name or an impossible four-frame returned position.
    pub fn body(self, lane: [u8; 16]) -> Result<CacheHeldBodyDataV1, HistoryErrorV1> {
        let key = KeyV1::new(lane, OwnerV1::Cache, 1)?;
        let record = RecordEnvelopeV1::decode(self.record, key, PhaseV1::new(OwnerV1::Cache, 1)?)?;
        let body = CacheHeldBodyDataV1::decode(record.body())?;
        let latest = KeyV1::new(lane, OwnerV1::Cache, 0)?;
        LatestHeadV1::decode(&self.latest_head, latest)?.check_record(latest, record)?;
        if record.coordinates().predecessor != [0; 32]
            || record.coordinates().correlation != body.association.seed
            || self.hold_names != body.hold.names
            || body.hold.next.checked_add(4) != Some(self.hold_after_next)
            || self.hold_after_end <= body.hold.end
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }

    /// Compares the exact Source Held row association and checksum as DATA.
    ///
    /// # Errors
    /// Rejects a different accepted association, seed or Source Held envelope.
    /// Both original writers still need independent Native verification.
    pub fn compare_source(
        self,
        lane: [u8; 16],
        source: super::source_held::SourceHeldReceiptDataV1<'_>,
    ) -> Result<(), HistoryErrorV1> {
        let body = self.body(lane)?;
        let source_body = source.body(lane)?;
        let source_record = RecordEnvelopeV1::decode(source.record,
            KeyV1::new(lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)?;
        if body.association != source_body.association()
            || body.source_held != source_record.checksum()
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Encodes the exact checked receipt into fixed caller-owned storage.
    ///
    /// # Errors
    /// Rejects the same row, head and native-coordinate errors as `body`.
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; CACHE_HELD_RECEIPT_BYTES_V1], HistoryErrorV1> {
        self.body(lane)?;
        let mut bytes = [0; CACHE_HELD_RECEIPT_BYTES_V1];
        let record_end = CACHE_HELD_RECORD_BYTES_V1;
        let head_end = record_end + HEAD_BYTES;
        let names_end = head_end + 48;
        bytes[..record_end].copy_from_slice(self.record);
        bytes[record_end..head_end].copy_from_slice(&self.latest_head);
        bytes[head_end..names_end].copy_from_slice(&self.hold_names.to_bytes());
        bytes[names_end..names_end + 8].copy_from_slice(&self.hold_after_next.to_be_bytes());
        bytes[names_end + 8..].copy_from_slice(&self.hold_after_end.to_be_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::RecordCoordinatesV1;

    pub(super) fn body() -> CacheHeldBodyDataV1 {
        let coordinate = CacheJournalDataV1 {
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            next: 1, end: 0,
        };
        CacheHeldBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [1; 16], project: [2; 16], sandbox: [3; 16],
                accepted_request: [4; 32], coissuance_binding: [5; 32], seed: [6; 32],
                controller_nonce: [7; 16], boot: [8; 16], started: 9, cutoff: 10,
            },
            source_held: [11; 32], bootstrap: coordinate, hold: coordinate, state: coordinate,
            authority: coordinate, clock: coordinate,
            physical: CachePhysicalDataV1 {
                root: (12, 13), uid: 1000, mode: 0o700, lock: (12, 14), manifest: (0, 0),
                generation: 0, digest: [0; 32], limits: [15; 32],
            },
            selected_partition: [16; 32], selected_head: [17; 32], quota: [18; 32],
            disk_count: 0, negative_count: 0, pin_count: 0, clock_floor: 19,
        }
    }

    pub(super) fn record(body: CacheHeldBodyDataV1, lane: [u8; 16])
        -> ([u8; CACHE_HELD_RECORD_BYTES_V1], [u8; HEAD_BYTES])
    {
        let mut record = [0; CACHE_HELD_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Cache, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Cache, 1).unwrap(), predecessor: [0; 32],
            correlation: body.association.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        (record, LatestHeadV1::new(1, checksum).unwrap().encode())
    }

    #[test]
    fn cache_body_round_trips_the_complete_fixed_layout_and_genesis_relation() {
        let original = body();
        let encoded = original.encode().unwrap();

        assert_eq!(encoded.len(), 808);
        assert_eq!(CacheHeldBodyDataV1::decode(&encoded).unwrap(), original);
        assert!(CacheHeldBodyDataV1::decode(&encoded[..807]).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(CacheHeldBodyDataV1::decode(&trailing).is_err());

        let mut changed = original;
        changed.pin_count = 1;
        assert_eq!(changed.encode(), Err(HistoryErrorV1::Correlation));
        changed.physical.generation = 1;
        changed.physical.digest = [20; 32];
        changed.physical.manifest = (12, 21);
        assert!(changed.encode().is_ok());
        changed.physical.manifest = changed.physical.lock;
        assert!(changed.encode().is_err());
    }

    #[test]
    fn borrowed_receipt_rejects_substitution_checksum_and_native_position_changes() {
        let original = body();
        let lane = [22; 16];
        let (record, latest_head) = record(original, lane);
        let receipt = CacheHeldReceiptDataV1 {
            record: &record, latest_head, hold_names: original.hold.names,
            hold_after_next: 5, hold_after_end: 1000,
        };
        let bytes = receipt.encode(lane).unwrap();
        let decoded = CacheHeldReceiptDataV1::decode(&bytes, lane).unwrap();

        assert_eq!(bytes.len(), 1052);
        assert_eq!(decoded.body(lane).unwrap(), original);
        assert_eq!(decoded.record.as_ptr(), bytes.as_ptr());
        assert!(CacheHeldReceiptDataV1::decode(&bytes, [23; 16]).is_err());
        assert!(CacheHeldReceiptDataV1::decode(&bytes[..1051], lane).is_err());
        let mut changed = bytes;
        changed[108] ^= 1;
        assert!(CacheHeldReceiptDataV1::decode(&changed, lane).is_err());
        let mut changed = bytes;
        changed[CACHE_HELD_RECORD_BYTES_V1 + 8] ^= 1;
        assert!(CacheHeldReceiptDataV1::decode(&changed, lane).is_err());
        let mut changed = bytes;
        changed[CACHE_HELD_RECEIPT_BYTES_V1 - 16..CACHE_HELD_RECEIPT_BYTES_V1 - 8]
            .copy_from_slice(&6_u64.to_be_bytes());
        assert!(CacheHeldReceiptDataV1::decode(&changed, lane).is_err());
    }
}
