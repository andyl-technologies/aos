//! Frames the fresh Root-owned namespace and Ownership observation before six cuts.
//!
//! ```text
//! transfer1424 = AOSDFO02/version2/reserved | open32/challenge32/initial-ACK32 |
//!   canonical-namespace-Ownership-trust-observation1312
//! ```
//!
//! The embedded preimage uses the sole existing namespace, process and public
//! trust codecs. Its original fields name this pending D exchange, rather than
//! a historical planning exchange. These bytes authenticate no native owner.

use super::initial_ack_commitment_data_v2;
use super::super::{
    initial_inventory::DeleteRootInitialAckDataV3,
    planning::{DeleteRootPlanningDataErrorV3, DeleteRootPlanningObservationDataV2},
    transport::{DeleteRootChallengeDataV2, DeleteRootOpenDataV2, DeleteRootWireErrorV2,
        array, encode_header_v2, header_v2},
};
use crate::domain_ledger::delete_batch::{
    DeleteBatchNativeBoundaryDataV2, DeleteBatchOwnerCutDataV2,
};
use sha2::{Digest as _, Sha256};

/// Gives the exact finite post-ACK namespace observation extent.
pub const DELETE_ROOT_FRESH_TRANSFER_BYTES_V2: usize = 1424;

/// Carries the complete fresh namespace, active Ownership and configured trust DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootFreshTransferDataV2 {
    /// Commits the original pending Delete opening.
    pub open: [u8; 32],
    /// Commits its same original Root challenge.
    pub challenge: [u8; 32],
    /// Commits the actual completed ready-to-query acknowledgement.
    pub initial_ack: [u8; 32],
    /// Carries every independently observed native and trust preimage.
    pub observation: DeleteRootPlanningObservationDataV2,
}

impl DeleteRootFreshTransferDataV2 {
    /// Encodes the new purpose around the existing complete preimage codec.
    ///
    /// # Errors
    /// Refuses absent/mixed identities or a noncanonical native/trust preimage.
    pub fn encode_v2(self) -> Result<[u8; DELETE_ROOT_FRESH_TRANSFER_BYTES_V2], DeleteRootPlanningDataErrorV3> {
        self.require_canonical_v2()?;
        let mut bytes = [0; DELETE_ROOT_FRESH_TRANSFER_BYTES_V2];
        encode_header_v2(&mut bytes, b"AOSDFO02");
        bytes[16..48].copy_from_slice(&self.open);
        bytes[48..80].copy_from_slice(&self.challenge);
        bytes[80..112].copy_from_slice(&self.initial_ack);
        bytes[112..].copy_from_slice(&self.observation.encode()?);
        Ok(bytes)
    }

    /// Decodes exactly this post-ACK purpose without accepting planning bytes.
    ///
    /// # Errors
    /// Refuses another purpose/version, reserved fields, trailing bytes or a
    /// noncanonical or mixed complete namespace/process/trust preimage.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, DeleteRootPlanningDataErrorV3> {
        header_v2(bytes, DELETE_ROOT_FRESH_TRANSFER_BYTES_V2, b"AOSDFO02")?;
        let value = Self {
            open: array(bytes, 16)?,
            challenge: array(bytes, 48)?,
            initial_ack: array(bytes, 80)?,
            observation: DeleteRootPlanningObservationDataV2::decode(&bytes[112..])?,
        };
        value.require_canonical_v2()?;
        Ok(value)
    }

    /// Joins the exact pending D originals and the unchanged accepted horizon.
    ///
    /// This is comparison only. Each endpoint must separately retain the actual
    /// native namespace/Ownership original and its Runtime default-local join.
    ///
    /// # Errors
    /// Refuses a substituted ACK, mixed original, regressed clock or expired
    /// original capability/cutoff. No deadline is renewed by this observation.
    pub fn require_exchange_v2(self, open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2, initial: DeleteRootInitialAckDataV3,
    ) -> Result<(), DeleteRootPlanningDataErrorV3> {
        self.require_canonical_v2()?;
        challenge.require_open_v2(open)?;
        if self.open != open.digest_v2()? || self.challenge != challenge.digest_v2()?
            || initial.open != self.open || initial.challenge != self.challenge
            || self.initial_ack != initial_ack_commitment_data_v2(&initial.encode_v3()?)
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        challenge.clock.validate_later_sample(initial.clock)
            .and_then(|()| initial.clock.validate_later_sample(self.observation.native.clock))
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        if self.observation.native.clock.boottime_nanoseconds() >= challenge.source.cutoff
            || self.observation.native.clock.wall_seconds() >= open.authorization_expires
        {
            return Err(DeleteRootWireErrorV2::Clock.into());
        }
        Ok(())
    }

    /// Derives the sixth comparison descriptor from this complete fresh preimage.
    ///
    /// # Errors
    /// Refuses the same noncanonical DATA as the encoder. This returns no
    /// permission, native observation, absence capability or ownership grant.
    pub fn owner_cut_data_v2(self) -> Result<DeleteBatchOwnerCutDataV2, DeleteRootPlanningDataErrorV3> {
        let bytes = self.encode_v2()?;
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.delete.transfer-default-local-fresh-cut.v2\0")
            .chain_update(bytes).finalize().into();
        Ok(DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence {
                directory_inode: self.observation.native.namespace.directories[0].file.inode,
            },
            count: 0,
            digest,
        })
    }

    fn require_canonical_v2(self) -> Result<(), DeleteRootPlanningDataErrorV3> {
        if [self.open, self.challenge, self.initial_ack].into_iter().any(|id| id == [0; 32])
            || self.observation.native.open != self.open
            || self.observation.native.challenge != self.challenge
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        self.observation.encode()?;
        Ok(())
    }
}
