//! Frames the post-ACK fresh-six comparison on the same original Delete stream.
//!
//! ```text
//! fresh456 = AOSDFI02/version2/reserved | open32/challenge32/initial-ACK32 |
//!   current-Controller-cut32 | owner48[6] | fresh-Cache-nonce16/cutoff8
//! preparatory192 = AOSDPA03/version3/reserved | open32/challenge32/fresh-frame32 |
//!   exact-draft-and-signature32 | actual-Root-paired-clock48
//! ```
//!
//! These are comparison DATA. The initial ACK permits only fresh queries, and
//! an approval decoded here is never an acceptance, native owner or effect
//! lender. Each actual endpoint retains its independently verified native,
//! signed-Session and original-horizon conjunction around these bytes.

mod transfer;
pub use transfer::{DELETE_ROOT_FRESH_TRANSFER_BYTES_V2, DeleteRootFreshTransferDataV2};
mod preparatory_approval;
pub use preparatory_approval::{DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3, DeleteRootPreparatoryApprovalDataV3};

use super::initial_inventory::DeleteRootInitialAckDataV3;
use super::inventory_cuts::fresh_six_cut_data_v2;
use super::transport::{
    DeleteRootChallengeDataV2, DeleteRootOpenDataV2, DeleteRootWireErrorV2,
    array, decode_clock, encode_clock, encode_header_v2, header_v2,
};
use super::super::delete_batch::DeleteBatchOwnerCutDataV2;
use aos_sandbox_model::RawPairedClockSample;
use sha2::{Digest as _, Sha256};

/// Gives the exact post-ACK fresh comparison frame extent.
pub const DELETE_ROOT_FRESH_FRAME_BYTES_V2: usize = 456;


/// Carries all six fresh comparison descriptors and their original association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootFreshFrameDataV2 {
    /// Commits the complete original pending opening.
    pub open: [u8; 32],
    /// Commits its same original Root challenge.
    pub challenge: [u8; 32],
    /// Commits the actual completed initial-verification ACK bytes.
    pub initial_ack: [u8; 32],
    /// Commits the separately framed complete current Controller cut.
    pub controller: [u8; 32],
    /// Gives the fixed Runtime/Mount/Storage/Network/Cache/Transfer order.
    pub owners: [DeleteBatchOwnerCutDataV2; 6],
    /// Gives the actual fresh Cache request nonce, equal to the D challenge.
    pub cache_nonce: [u8; 16],
    /// Gives its actual unchanged, nonrenewed absolute cutoff.
    pub cache_cutoff: u64,
}

impl DeleteRootFreshFrameDataV2 {
    /// Encodes each typed descriptor through the sole owner48 codec.
    ///
    /// # Errors
    /// Refuses missing identities or malformed role/boundary combinations.
    pub fn encode_v2(self) -> Result<[u8; DELETE_ROOT_FRESH_FRAME_BYTES_V2], DeleteRootWireErrorV2> {
        self.require_canonical_v2()?;
        let mut bytes = [0; DELETE_ROOT_FRESH_FRAME_BYTES_V2];
        encode_header_v2(&mut bytes, b"AOSDFI02");
        bytes[16..48].copy_from_slice(&self.open);
        bytes[48..80].copy_from_slice(&self.challenge);
        bytes[80..112].copy_from_slice(&self.initial_ack);
        bytes[112..144].copy_from_slice(&self.controller);
        for (index, cut) in self.owners.iter().enumerate() {
            let start = 144 + 48 * index;
            bytes[start..start + 48].copy_from_slice(
                &cut.canonical_descriptor_data_v2((index + 1) as u8)?,
            );
        }
        bytes[432..448].copy_from_slice(&self.cache_nonce);
        bytes[448..].copy_from_slice(&self.cache_cutoff.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one fresh-comparison purpose and no trailing bytes.
    ///
    /// # Errors
    /// Refuses another version, reserved bytes or a malformed typed descriptor.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        header_v2(bytes, DELETE_ROOT_FRESH_FRAME_BYTES_V2, b"AOSDFI02")?;
        let owner = |index: usize| {
            let start = 144 + 48 * index;
            DeleteBatchOwnerCutDataV2::decode_descriptor_v2(
                (index + 1) as u8, &bytes[start..start + 48],
            ).map_err(DeleteRootWireErrorV2::from)
        };
        let value = Self {
            open: array(bytes, 16)?,
            challenge: array(bytes, 48)?,
            initial_ack: array(bytes, 80)?,
            controller: array(bytes, 112)?,
            owners: [owner(0)?, owner(1)?, owner(2)?, owner(3)?, owner(4)?, owner(5)?],
            cache_nonce: array(bytes, 432)?,
            cache_cutoff: u64::from_be_bytes(array(bytes, 448)?),
        };
        value.require_canonical_v2()?;
        Ok(value)
    }

    /// Compares the same opening, challenge, completed ACK and current C frame.
    ///
    /// The actual receiver separately verifies every fresh descriptor from its
    /// own native reader. This check does not adopt the transmitted descriptors.
    ///
    /// # Errors
    /// Refuses mixed flights, changed current C bytes or renewed query bounds.
    pub fn require_exchange_v2(
        self,
        open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2,
        initial: DeleteRootInitialAckDataV3,
        controller: super::controller_cut::DeleteRootControllerCutDataV3,
    ) -> Result<(), DeleteRootWireErrorV2> {
        self.require_canonical_v2()?;
        challenge.require_open_v2(open)?;
        controller.require_challenge_v2(challenge)
            .map_err(|_| DeleteRootWireErrorV2::Association)?;
        let initial_bytes = initial.encode_v3()?;
        if self.open != open.digest_v2()?
            || self.challenge != challenge.digest_v2()?
            || initial.open != self.open
            || initial.challenge != self.challenge
            || self.initial_ack != initial_ack_commitment_data_v2(&initial_bytes)
            || self.controller != controller.digest_v3()
                .map_err(|_| DeleteRootWireErrorV2::Association)?
            || self.cache_nonce != challenge.source.nonce
            || self.cache_cutoff > challenge.source.cutoff
        {
            return Err(DeleteRootWireErrorV2::Association);
        }
        challenge.clock.validate_later_sample(initial.clock)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        Ok(())
    }

    /// Commits the complete fresh frame, including each native boundary type.
    ///
    /// # Errors
    /// Refuses the same malformed DATA as the encoder.
    pub fn digest_v2(self) -> Result<[u8; 32], DeleteRootWireErrorV2> {
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.delete-root.fresh-frame.v2\0")
            .chain_update(self.encode_v2()?).finalize().into())
    }

    fn require_canonical_v2(self) -> Result<(), DeleteRootWireErrorV2> {
        if [self.open, self.challenge, self.initial_ack, self.controller]
            .into_iter().any(|digest| digest == [0; 32])
            || self.cache_nonce == [0; 16] || self.cache_cutoff == 0
        {
            return Err(DeleteRootWireErrorV2::Format);
        }
        fresh_six_cut_data_v2(&self.owners)?;
        Ok(())
    }
}

/// Commits the exact ACK192 bytes without giving them accepting semantics.
#[must_use]
pub fn initial_ack_commitment_data_v2(bytes: &[u8; 192]) -> [u8; 32] {
    Sha256::new().chain_update(b"aos.sandbox.delete-root.initial-ack.v2\0")
        .chain_update(bytes).finalize().into()
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::delete_batch::DeleteBatchNativeBoundaryDataV2;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16], 100 + boot as i64, boot * 1_000_000_000).unwrap()
    }

    fn frame() -> DeleteRootFreshFrameDataV2 {
        // Explicit passive boundary fixtures cannot construct a native loan.
        let mut owners = std::array::from_fn(|index| DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: index as u64 + 1 },
            count: 0, digest: [index as u8 + 1; 32],
        });
        owners[5].boundary = DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: 100 };
        DeleteRootFreshFrameDataV2 {
            open: [3; 32], challenge: [4; 32], initial_ack: [5; 32], controller: [6; 32],
            owners, cache_nonce: [7; 16], cache_cutoff: 20_000_000_000,
        }
    }

    #[test]
    fn fresh_frame_preserves_all_six_typed_boundaries_and_has_no_initial_ack_alias() {
        let data = frame();
        let bytes = data.encode_v2().unwrap();
        assert_eq!(DeleteRootFreshFrameDataV2::decode_v2(&bytes).unwrap(), data);
        let initial = super::super::inventory_cuts::initial_six_cut_data_v2(&data.owners).unwrap();
        assert_ne!(fresh_six_cut_data_v2(&data.owners).unwrap(), initial);
        let mut wrong = data;
        wrong.owners.swap(0, 5);
        assert!(wrong.encode_v2().is_err());
        let mut wrong = bytes;
        wrong[144 + 2] = 1;
        assert!(DeleteRootFreshFrameDataV2::decode_v2(&wrong).is_err());
        let mut wrong = bytes;
        wrong[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(DeleteRootFreshFrameDataV2::decode_v2(&wrong).is_err());
        assert!(DeleteRootFreshFrameDataV2::decode_v2(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn preparatory_approval_binds_actual_signed_draft_and_refuses_old_final_purpose() {
        let frame = frame();
        use super::super::resource_exchange::{DeleteRootResourceContextDataV2,
            DeleteRootResourceDraftDataV2, DeleteRootResourceSignedDataV2};
        let context = DeleteRootResourceContextDataV2 {
            open: frame.open, challenge: frame.challenge, frame: frame.digest_v2().unwrap(),
            fresh_six: fresh_six_cut_data_v2(&frame.owners).unwrap(), lease: [9; 32],
            policy_expires_seconds: 1000, clock: sample(9),
        }.encode_v2().unwrap();
        let draft = DeleteRootResourceDraftDataV2 { context: &context, canonical_plan: b"plan",
            canonical_statement: b"statement", deadline_free_body: b"body" };
        let digest = draft.digest_v2().unwrap();
        let signed = DeleteRootResourceSignedDataV2 { draft: &digest, canonical_signature: &[10; 64] };
        let value = DeleteRootPreparatoryApprovalDataV3 {
            open: frame.open, challenge: frame.challenge, frame: frame.digest_v2().unwrap(),
            preparation: signed.acceptance_commitment_v2(draft).unwrap(), clock: sample(10),
        };
        let encoded = value.encode_v3().unwrap();
        assert_eq!(DeleteRootPreparatoryApprovalDataV3::decode_v3(&encoded).unwrap(), value);
        assert!(value.require_resources_v3(frame, draft, signed).is_ok());
        let other = DeleteRootResourceSignedDataV2 { canonical_signature: &[11; 64], ..signed };
        assert!(value.require_resources_v3(frame, draft, other).is_err());
        let other = DeleteRootResourceDraftDataV2 { deadline_free_body: b"changed", ..draft };
        assert!(value.require_resources_v3(frame, other, signed).is_err());
        assert!(DeleteRootInitialAckDataV3::decode_v3(&encoded).is_err());
        let initial = DeleteRootInitialAckDataV3 {
            open: value.open, challenge: value.challenge, frame: [7; 32],
            initial_six: [8; 32], clock: sample(9),
        };
        assert!(DeleteRootPreparatoryApprovalDataV3::decode_v3(&initial.encode_v3().unwrap()).is_err());
        let mut old = encoded;
        old[..8].copy_from_slice(b"AOSDFA02");
        old[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert!(DeleteRootPreparatoryApprovalDataV3::decode_v3(&old).is_err());
        let mut wrong = encoded;
        wrong[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert!(DeleteRootPreparatoryApprovalDataV3::decode_v3(&wrong).is_err());
        let mut wrong = encoded;
        wrong[10] = 1;
        assert!(DeleteRootPreparatoryApprovalDataV3::decode_v3(&wrong).is_err());
    }
}
