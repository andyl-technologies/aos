//! Encodes the fresh Delete Root opening and original challenge DATA.
//!
//! ```text
//! open208 = AOSDRQ02 | version2/reserved | project/operation | whole-batch-digest |
//!           batch-bytes | original-C17-paired-clock | original-expiry | Source-native64
//! challenge224 = AOSDRH02 | version2/reserved | digest(open208) |
//!                fresh-Root-paired-clock | Source-Delete-query128
//! ```
//!
//! Complete canonical AOSDEL02 bytes follow the opening. No old unnamed batch
//! commitment receives a new meaning. Decoding establishes no C17, six-owner
//! cut, Root floor, publication, terminal state or lifecycle permission.

use super::super::{delete_batch::{DeleteBatchViewV1, DeleteBatchCommitmentsDataV2}, lifecycle_model::LifecycleModelError};
use super::source_current::{
    SOURCE_DELETE_CURRENT_MAXIMUM_DURATION_NANOSECONDS_V1, SourceDeleteCurrentDataErrorV1,
    SourceDeleteCurrentQueryDataV1, source_delete_current_batch_digest_v1,
};
use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

/// Selects only the fresh Delete Root entrance.
pub const DELETE_ROOT_OPEN_MAGIC_V2: &[u8; 8] = b"AOSDRQ02";
/// Selects its corresponding fresh Root challenge.
pub const DELETE_ROOT_CHALLENGE_MAGIC_V2: &[u8; 8] = b"AOSDRH02";
/// Gives the exact opening extent preceding the complete batch.
pub const DELETE_ROOT_OPEN_BYTES_V2: usize = 208;
/// Gives the complete fresh challenge extent.
pub const DELETE_ROOT_CHALLENGE_BYTES_V2: usize = 224;

/// Identifies a passive framing, association or original-clock refusal.
#[derive(Debug, thiserror::Error)]
pub enum DeleteRootWireErrorV2 {
    /// Fixed framing, extent or an identity is invalid.
    #[error("Delete Root exchange framing is noncanonical")]
    Format,
    /// Original authorization or the fresh bounded horizon is invalid.
    #[error("Delete Root exchange is outside its original authorization horizon")]
    Clock,
    /// Complete batch or challenge association differs.
    #[error("Delete Root exchange differs from its opening")]
    Association,
    /// The sole complete batch parser rejected the bytes.
    #[error(transparent)]
    Batch(#[from] LifecycleModelError),
    /// The canonical Source-purpose codec or digest rejected its DATA.
    #[error(transparent)]
    Source(#[from] SourceDeleteCurrentDataErrorV1),
}

/// Carries named original C17 and Source pending comparison coordinates.
///
/// The private Controller producer derives these from its same live intrinsic
/// pending fence. A decoded opening remains untrusted comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootOpenDataV2 {
    /// Identifies the actual batch project.
    pub project: [u8; 16],
    /// Identifies the actual operation and pending transaction.
    pub operation: [u8; 16],
    /// Commits every canonical batch byte under the Source D domain.
    pub batch: [u8; 32],
    /// Gives the exact complete batch extent without allocating it.
    pub batch_bytes: u64,
    /// Records the same C17 decision's original paired sample.
    pub authorization_clock: RawPairedClockSample,
    /// Gives the minimum actual capability/policy expiration.
    pub authorization_expires: i64,
    /// Describes the actual Source pending transaction/digest/COMMIT/end.
    pub source_pending: [u8; 64],
}

impl DeleteRootOpenDataV2 {

    /// Decodes only the complete authorization-bearing V2 exchange.
    ///
    /// # Errors
    /// Rejects another version or the same malformed fixed DATA.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        header_v2(bytes, DELETE_ROOT_OPEN_BYTES_V2, DELETE_ROOT_OPEN_MAGIC_V2)?;
        let value = Self {
            project: array(bytes, 16)?,
            operation: array(bytes, 32)?,
            batch: array(bytes, 48)?,
            batch_bytes: u64::from_be_bytes(array(bytes, 80)?),
            authorization_clock: decode_clock(bytes, 88)?,
            authorization_expires: i64::from_be_bytes(array(bytes, 136)?),
            source_pending: array(bytes, 144)?,
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Encodes the explicit authorization-bearing V2 fields into fixed storage.
    ///
    /// # Errors
    /// Rejects the same malformed fixed DATA as decoding.
    pub fn encode_v2(self) -> Result<[u8; DELETE_ROOT_OPEN_BYTES_V2], DeleteRootWireErrorV2> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_OPEN_BYTES_V2];
        encode_header_v2(&mut bytes, DELETE_ROOT_OPEN_MAGIC_V2);
        bytes[16..32].copy_from_slice(&self.project);
        bytes[32..48].copy_from_slice(&self.operation);
        bytes[48..80].copy_from_slice(&self.batch);
        bytes[80..88].copy_from_slice(&self.batch_bytes.to_be_bytes());
        encode_clock(&mut bytes, 88, self.authorization_clock);
        bytes[136..144].copy_from_slice(&self.authorization_expires.to_be_bytes());
        bytes[144..].copy_from_slice(&self.source_pending);
        Ok(bytes)
    }

    /// Commits all explicit V2 opening bytes under the named V2 domain.
    ///
    /// # Errors
    /// Rejects a malformed opening.
    pub fn digest_v2(self) -> Result<[u8; 32], DeleteRootWireErrorV2> {
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.delete-root.open.v2\0")
            .chain_update(self.encode_v2()?)
            .finalize()
            .into())
    }

    /// Checks the complete canonical batch against this exact opening.
    ///
    /// The caller pays the sole parser's transient graph peak before entry.
    ///
    /// # Errors
    /// Preserves parser refusal or reports a changed complete association.
    pub fn require_batch_v2(self, bytes: &[u8]) -> Result<(), DeleteRootWireErrorV2> {
        self.require_batch_inventory_cuts_v2(bytes).map(|_| ())
    }

    /// Returns the named cuts, six descriptors and Source NEXT from one parse.
    ///
    /// These borrowed-input projections remain passive comparison DATA.
    ///
    /// # Errors
    /// Rejects the same changed V2 batch or any invalid typed native boundary.
    pub fn require_batch_inventory_cuts_v2(self, bytes: &[u8]) -> Result<
        (DeleteBatchCommitmentsDataV2, [super::super::delete_batch::DeleteBatchOwnerCutDataV2; 6], u64),
        DeleteRootWireErrorV2,
    > {
        self.require_canonical()?;
        let batch = DeleteBatchViewV1::decode(bytes)?;
        // This Root exchange requires explicitly named V2 cuts.
        // Another batch schema cannot enter the actual Root flight.
        if batch.version() != 2
            || usize::try_from(self.batch_bytes).ok() != Some(bytes.len())
            || batch.project().as_bytes() != &self.project
            || batch.operation().as_bytes() != &self.operation
            || source_delete_current_batch_digest_v1(bytes)? != self.batch
        {
            return Err(DeleteRootWireErrorV2::Association);
        }
        let named = batch.named_commitments_v2().ok_or(DeleteRootWireErrorV2::Association)?;
        let owners = [batch.native_owner_cut_v2(1)?, batch.native_owner_cut_v2(2)?,
            batch.native_owner_cut_v2(3)?, batch.native_owner_cut_v2(4)?,
            batch.native_owner_cut_v2(5)?, batch.native_owner_cut_v2(6)?];
        let source_next = batch.source_predecessor_next_sequence_v2()
            .ok_or(DeleteRootWireErrorV2::Association)?;
        Ok((named, owners, source_next))
    }

    /// Clamps a fresh Root sample to original expiry and the fresh D horizon.
    ///
    /// This compares raw DATA. Root independently captures its actual sample
    /// and joins the original decision to its genuine C17/current owner.
    ///
    /// # Errors
    /// Rejects rollback, drift, changed boot/provenance, expiration or overflow.
    pub fn cutoff_for_root_sample_v1(
        self,
        root: RawPairedClockSample,
    ) -> Result<u64, DeleteRootWireErrorV2> {
        self.require_canonical()?;
        authorization_cutoff_for_root_sample_v1(self.authorization_clock, self.authorization_expires, root)
    }

    fn require_canonical(self) -> Result<(), DeleteRootWireErrorV2> {
        let bytes = usize::try_from(self.batch_bytes).map_err(|_| DeleteRootWireErrorV2::Format)?;
        let sequence = u64::from_be_bytes(array(&self.source_pending, 48)?);
        let end = u64::from_be_bytes(array(&self.source_pending, 56)?);
        if self.project == [0; 16]
            || self.operation == [0; 16]
            || self.batch == [0; 32]
            || !DeleteBatchViewV1::encoded_length_is_bounded_v1(bytes)
            || self.source_pending[..16] != self.operation
            || self.source_pending[16..48] == [0; 32]
            || sequence == 0
            || sequence == u64::MAX
            || end == 0
        {
            return Err(DeleteRootWireErrorV2::Format);
        }
        if self.authorization_clock.boottime_nanoseconds() == 0
            || self
                .authorization_clock
                .conservative_expiry_deadline_data_v1(self.authorization_expires)
                .is_none()
        {
            return Err(DeleteRootWireErrorV2::Clock);
        }
        Ok(())
    }
}

/// Carries the fresh actual Root sample and exact independent Source query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootChallengeDataV2 {
    /// Commits the full original opening, including horizon and native64.
    pub open: [u8; 32],
    /// Records the actual retained Root kernel paired sample.
    pub clock: RawPairedClockSample,
    /// Records the actual nonce, whole batch and clamped cutoff.
    pub source: SourceDeleteCurrentQueryDataV1,
}

impl DeleteRootChallengeDataV2 {

    /// Decodes only the complete authorization-bearing V2 exchange.
    ///
    /// # Errors
    /// Rejects another version or the same malformed fixed DATA.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        header_v2(
            bytes,
            DELETE_ROOT_CHALLENGE_BYTES_V2,
            DELETE_ROOT_CHALLENGE_MAGIC_V2,
        )?;
        let value = Self {
            open: array(bytes, 16)?,
            clock: decode_clock(bytes, 48)?,
            source: SourceDeleteCurrentQueryDataV1::decode(&bytes[96..])?,
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Encodes the explicit authorization-bearing V2 fields into fixed storage.
    ///
    /// # Errors
    /// Rejects the same malformed fixed DATA as decoding.
    pub fn encode_v2(self) -> Result<[u8; DELETE_ROOT_CHALLENGE_BYTES_V2], DeleteRootWireErrorV2> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_CHALLENGE_BYTES_V2];
        encode_header_v2(&mut bytes, DELETE_ROOT_CHALLENGE_MAGIC_V2);
        bytes[16..48].copy_from_slice(&self.open);
        encode_clock(&mut bytes, 48, self.clock);
        bytes[96..].copy_from_slice(&self.source.encode()?);
        Ok(bytes)
    }

    /// Compares the exact V2 opening and both original nonrenewable horizons.
    ///
    /// # Errors
    /// Rejects another opening, batch or deadline.
    pub fn require_open_v2(self, open: DeleteRootOpenDataV2) -> Result<(), DeleteRootWireErrorV2> {
        self.require_canonical()?;
        if self.open != open.digest_v2()?
            || self.source.project != open.project
            || self.source.operation != open.operation
            || self.source.batch != open.batch
            || self.source.cutoff != open.cutoff_for_root_sample_v1(self.clock)?
        {
            return Err(DeleteRootWireErrorV2::Association);
        }
        Ok(())
    }

    /// Commits the complete V2 challenge for actual authorization-bearing flights.
    ///
    /// # Errors
    /// Rejects malformed fixed comparison DATA.
    pub fn digest_v2(self) -> Result<[u8; 32], DeleteRootWireErrorV2> {
        Ok(Sha256::new().chain_update(b"aos.sandbox.delete-root.challenge.v2\0").chain_update(self.encode_v2()?).finalize().into())
    }

    fn require_canonical(self) -> Result<(), DeleteRootWireErrorV2> {
        self.source.encode()?;
        if self.open == [0; 32]
            || self.source.boot != self.clock.host_boot_id()
            || self.source.started != self.clock.boottime_nanoseconds()
        {
            return Err(DeleteRootWireErrorV2::Association);
        }
        Ok(())
    }
}

pub(super) fn authorization_cutoff_for_root_sample_v1(
    authorization_clock: RawPairedClockSample, authorization_expires: i64,
    root: RawPairedClockSample,
) -> Result<u64, DeleteRootWireErrorV2> {
        authorization_clock
            .validate_later_sample(root)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        if root.wall_seconds() >= authorization_expires {
            return Err(DeleteRootWireErrorV2::Clock);
        }
        let original = authorization_clock
            .conservative_expiry_deadline_data_v1(authorization_expires)
            .ok_or(DeleteRootWireErrorV2::Clock)?;
        let fresh = root
            .boottime_nanoseconds()
            .checked_add(SOURCE_DELETE_CURRENT_MAXIMUM_DURATION_NANOSECONDS_V1)
            .ok_or(DeleteRootWireErrorV2::Clock)?;
        let cutoff = original.min(fresh);
        if root.boottime_nanoseconds() >= cutoff {
            return Err(DeleteRootWireErrorV2::Clock);
        }
        Ok(cutoff)

}

// The Source-current purpose and fixed namespace subformats retain their
// actual V1 headers. The unshipped outer Root V1 exchanges have no decoder.
pub(super) fn header(bytes: &[u8], expected: usize, magic: &[u8; 8]) -> Result<(), DeleteRootWireErrorV2> {
    header_exact(bytes, expected, magic, 1)
}

pub(super) fn header_v2(bytes: &[u8], expected: usize, magic: &[u8; 8]) -> Result<(), DeleteRootWireErrorV2> {
    header_exact(bytes, expected, magic, 2)
}

pub(super) fn header_v3(bytes: &[u8], expected: usize, magic: &[u8; 8]) -> Result<(), DeleteRootWireErrorV2> {
    header_exact(bytes, expected, magic, 3)
}

fn header_exact(bytes: &[u8], expected: usize, magic: &[u8; 8], version: u16) -> Result<(), DeleteRootWireErrorV2> {
    if bytes.len() != expected || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..10] != version.to_be_bytes() || bytes[10..16] != [0; 6] {
        return Err(DeleteRootWireErrorV2::Format);
    }
    Ok(())
}

pub(super) fn encode_header(bytes: &mut [u8], magic: &[u8; 8]) {
    encode_header_exact(bytes, magic, 1);
}

pub(super) fn encode_header_v2(bytes: &mut [u8], magic: &[u8; 8]) {
    encode_header_exact(bytes, magic, 2);
}

pub(super) fn encode_header_v3(bytes: &mut [u8], magic: &[u8; 8]) {
    encode_header_exact(bytes, magic, 3);
}

fn encode_header_exact(bytes: &mut [u8], magic: &[u8; 8], version: u16) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&version.to_be_bytes());
}

pub(super) fn decode_clock(
    bytes: &[u8],
    offset: usize,
) -> Result<RawPairedClockSample, DeleteRootWireErrorV2> {
    let provenance = RawClockProvenance::new_untrusted(array(bytes, offset)?)
        .map_err(|_| DeleteRootWireErrorV2::Clock)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        array(bytes, offset + 16)?,
        i64::from_be_bytes(array(bytes, offset + 32)?),
        u64::from_be_bytes(array(bytes, offset + 40)?),
    )
    .map_err(|_| DeleteRootWireErrorV2::Clock)
}

pub(super) fn encode_clock(bytes: &mut [u8], offset: usize, clock: RawPairedClockSample) {
    bytes[offset..offset + 16].copy_from_slice(&clock.provenance().as_bytes());
    bytes[offset + 16..offset + 32].copy_from_slice(&clock.host_boot_id());
    bytes[offset + 32..offset + 40].copy_from_slice(&clock.wall_seconds().to_be_bytes());
    bytes[offset + 40..offset + 48].copy_from_slice(&clock.boottime_nanoseconds().to_be_bytes());
}

pub(super) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DeleteRootWireErrorV2> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(DeleteRootWireErrorV2::Format)?)
        .ok_or(DeleteRootWireErrorV2::Format)?
        .try_into()
        .map_err(|_| DeleteRootWireErrorV2::Format)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(wall: i64, boot_seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            boot_seconds * 1_000_000_000,
        )
        .unwrap()
    }

    fn open(expires: i64) -> DeleteRootOpenDataV2 {
        let mut native = [3; 64];
        native[..16].copy_from_slice(&[4; 16]);
        native[48..56].copy_from_slice(&7_u64.to_be_bytes());
        native[56..].copy_from_slice(&4096_u64.to_be_bytes());
        // This tests fixed framing only: no canonical batch or live owner is
        // constructed from these synthetic comparison coordinates.
        DeleteRootOpenDataV2 {
            project: [5; 16],
            operation: [4; 16],
            batch: [6; 32],
            batch_bytes: 640,
            authorization_clock: sample(100, 10),
            authorization_expires: expires,
            source_pending: native,
        }
    }

    fn challenge(open: DeleteRootOpenDataV2) -> DeleteRootChallengeDataV2 {
        let clock = sample(101, 11);
        DeleteRootChallengeDataV2 {
            open: open.digest_v2().unwrap(),
            clock,
            source: SourceDeleteCurrentQueryDataV1 {
                nonce: [7; 16],
                project: open.project,
                operation: open.operation,
                batch: open.batch,
                boot: clock.host_boot_id(),
                started: clock.boottime_nanoseconds(),
                cutoff: open.cutoff_for_root_sample_v1(clock).unwrap(),
            },
        }
    }

    #[test]
    fn fixed_open_roundtrip_keeps_original_horizon_and_whole_native64() {
        let original = open(500);
        assert_eq!(
            DeleteRootOpenDataV2::decode_v2(&original.encode_v2().unwrap()).unwrap(),
            original
        );
        let mut changed = original;
        changed.source_pending[20] ^= 1;
        assert_ne!(original.digest_v2().unwrap(), changed.digest_v2().unwrap());
        changed = original;
        changed.authorization_expires -= 1;
        assert_ne!(original.digest_v2().unwrap(), changed.digest_v2().unwrap());
    }

    #[test]
    fn original_expiry_clamps_the_new_root_horizon_without_renewal() {
        let original = open(104);
        let challenge = challenge(original);
        assert_eq!(challenge.source.cutoff, 13_000_000_000);
        assert!(challenge.require_open_v2(original).is_ok());
        assert!(original.cutoff_for_root_sample_v1(sample(103, 13)).is_err());
        assert!(
            open(102)
                .cutoff_for_root_sample_v1(sample(101, 11))
                .is_err()
        );
    }

    #[test]
    fn independent_fresh_window_is_also_bounded() {
        let original = open(500);
        let challenge = challenge(original);
        assert_eq!(challenge.source.cutoff, 76_000_000_000);
        assert_eq!(
            DeleteRootChallengeDataV2::decode_v2(&challenge.encode_v2().unwrap()).unwrap(),
            challenge
        );
        let mut renewed = challenge;
        renewed.source.cutoff += 1;
        assert!(renewed.encode_v2().is_err());
    }

    #[test]
    fn changed_native_horizon_and_boot_cannot_reuse_a_challenge() {
        let original = open(500);
        let challenge = challenge(original);
        let mut changed = original;
        changed.source_pending[16] ^= 1;
        assert!(challenge.require_open_v2(changed).is_err());
        changed = original;
        changed.authorization_expires -= 1;
        assert!(challenge.require_open_v2(changed).is_err());
        let foreign = RawPairedClockSample::new_untrusted(
            original.authorization_clock.provenance(),
            [9; 16],
            101,
            11_000_000_000,
        )
        .unwrap();
        assert!(original.cutoff_for_root_sample_v1(foreign).is_err());
    }

    #[test]
    fn framing_rejects_old_purpose_reserved_bytes_and_unbounded_extent() {
        let original = open(500).encode_v2().unwrap();
        for index in [0, 8, 10, 15] {
            let mut changed = original;
            changed[index] ^= 1;
            assert!(DeleteRootOpenDataV2::decode_v2(&changed).is_err());
        }
        assert!(DeleteRootOpenDataV2::decode_v2(&original[..original.len() - 1]).is_err());
        let mut changed = original;
        changed[80..88].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(DeleteRootOpenDataV2::decode_v2(&changed).is_err());
    }

    #[test]
    fn opening_decoder_refuses_retired_headers_without_a_legacy_encoder() {
        let value = open(500);
        let current = value.encode_v2().unwrap();
        assert_eq!(DeleteRootOpenDataV2::decode_v2(&current).unwrap(), value);
        let mut retired = current;
        retired[..8].copy_from_slice(b"AOSDRQ01");
        retired[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(DeleteRootOpenDataV2::decode_v2(&retired).is_err());
        let mut retired_challenge = challenge(value).encode_v2().unwrap();
        retired_challenge[..8].copy_from_slice(b"AOSDRH01");
        retired_challenge[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(DeleteRootChallengeDataV2::decode_v2(&retired_challenge).is_err());
        for index in [0, 7, 8, 9, 10, 15] {
            let mut changed = current;
            changed[index] ^= 1;
            assert!(DeleteRootOpenDataV2::decode_v2(&changed).is_err());
        }
        assert!(DeleteRootOpenDataV2::decode_v2(&current[..current.len() - 1]).is_err());
    }

    #[test]
    fn production_root_rejects_unsupported_batch_and_accepts_explicit_v2_data() {
        use aos_sandbox_model::{OperationId, ProjectId, SandboxId};
        use crate::domain_ledger::delete_batch::{
            DeleteBatchCommitmentsDataV2, DeleteBatchEncodingDataV1,
            DeleteBatchOwnerCutDataV1, DeleteBatchWriteDataV1,
            LifecycleDeleteBatchV1, fixture_batch_v1,
        };
        use crate::domain_ledger::lifecycle_model::LifecycleResourceV1;
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let writes = [DeleteBatchWriteDataV1 {
            resource: root, key: b"projection", before_generation: 1, before_digest: [9; 32],
        }];
        let postorder = [root];
        let data = DeleteBatchEncodingDataV1 {
            project: ProjectId::from_bytes([4; 16]), operation: OperationId::from_bytes([5; 16]),
            transaction: [6; 16], root, flags: 0, before_sequence: 1, authority_epoch: 1,
            commitments: [[8; 32]; 5],
            owners: std::array::from_fn(|index| DeleteBatchOwnerCutDataV1 {
                sequence: 1, count: 0, digest: [10 + index as u8; 32],
            }),
            writes: &writes, reads: &[], collections: &[], dependencies: &[], postorder: &postorder,
        };
        let current = LifecycleDeleteBatchV1::from_encoding_data_v2(&data,
            DeleteBatchCommitmentsDataV2 { authorization: [21; 32], source: [22; 32],
                controller: [23; 32], initial_six: [24; 32] }, 41).unwrap();
        let unsupported = fixture_batch_v1(b"projection", b"retained before", 1);
        assert!(DeleteBatchViewV1::decode(&unsupported).is_ok());

        let mut opening = open(500);
        opening.project = [4; 16];
        opening.operation = [5; 16];
        opening.source_pending[..16].copy_from_slice(&opening.operation);
        opening.batch_bytes = unsupported.len() as u64;
        opening.batch = source_delete_current_batch_digest_v1(&unsupported).unwrap();
        assert!(matches!(opening.require_batch_v2(&unsupported), Err(DeleteRootWireErrorV2::Association)));

        opening.batch_bytes = current.as_bytes().len() as u64;
        opening.batch = source_delete_current_batch_digest_v1(current.as_bytes()).unwrap();
        assert!(opening.require_batch_v2(current.as_bytes()).is_ok());
    }

}
