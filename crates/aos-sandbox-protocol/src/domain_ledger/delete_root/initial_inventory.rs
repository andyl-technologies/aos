//! Encodes the complete historical initial-six comparison and its fresh ACK.
//!
//! ```text
//! initial2808 = AOSDRI03/version3/reserved | pending-open32/challenge32 |
//!   planning-open1264/planning-challenge128/Root-observation1312 | Cache-nonce16/cutoff8
//! ack192 = AOSDIA03/version3/reserved | pending-open32/challenge32 |
//!   initial-frame32/initial-six32 | fresh-Root-paired-clock48
//! ```
//!
//! These fixed DATA codecs supply no live native, Session, C17, default-local
//! or fresh-query ownership. Actual receivers independently verify their own
//! files, keys, models and original horizons before lending any private loan.

use super::planning::{
    DELETE_ROOT_PLANNING_OPEN_BYTES_V3, DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3,
    DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2, DeleteRootPlanningChallengeDataV3, DeleteRootPlanningDataErrorV3,
    DeleteRootPlanningObservationDataV2, DeleteRootPlanningOpenDataV3,
};
use super::transport::{
    DeleteRootChallengeDataV2, DeleteRootOpenDataV2, DeleteRootWireErrorV2, header_v3, encode_header_v3, array,
    decode_clock, encode_clock,
};
use aos_sandbox_core::RawPairedClockSample;
use sha2::{Digest as _, Sha256};

/// Gives the exact complete initial comparison frame size.
pub const DELETE_ROOT_INITIAL_FRAME_BYTES_V3: usize = 80 + DELETE_ROOT_PLANNING_OPEN_BYTES_V3
    + DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3 + DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2 + 16 + 8;
const PLANNING_CHALLENGE_OFFSET: usize = 80 + DELETE_ROOT_PLANNING_OPEN_BYTES_V3;
const PLANNING_OBSERVATION_OFFSET: usize = PLANNING_CHALLENGE_OFFSET + DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3;
const CACHE_NONCE_OFFSET: usize = PLANNING_OBSERVATION_OFFSET + DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2;
const CACHE_CUTOFF_OFFSET: usize = CACHE_NONCE_OFFSET + 16;
/// Gives the exact initial-verification ACK size.
pub const DELETE_ROOT_INITIAL_ACK_BYTES_V3: usize = 192;

/// Preserves strict framing or the original complete planning codec refusal.
#[derive(Debug, thiserror::Error)]
pub enum DeleteRootInitialDataErrorV3 {
    /// The current frame or original pending association differs.
    #[error(transparent)]
    Wire(#[from] DeleteRootWireErrorV2),
    /// The complete historical planning exchange is invalid.
    #[error(transparent)]
    Planning(#[from] DeleteRootPlanningDataErrorV3),
}

/// Bounds the same codec's two co-live complete decoded planning model peaks.
///
/// Three receiving/move copies of each actual typed tuple cover its complete
/// Claim, native namespace, Ownership, trust and paired-clock representation.
/// This supplies MemoryBytes only, not namespace or authority.
#[must_use]
pub fn initial_comparison_decoding_bytes_v3() -> Option<usize> {
    std::mem::size_of::<(
        DeleteRootPlanningOpenDataV3,
        DeleteRootPlanningChallengeDataV3,
        DeleteRootPlanningObservationDataV2,
    )>()
    .checked_mul(6)
}

/// Contains every original historical planning and Cache correlation byte.
#[derive(Clone, Copy)]
pub struct DeleteRootInitialFrameDataV3 {
    /// Commits the actual current version2 pending opening.
    pub open: [u8; 32],
    /// Commits its actual fresh version2 Root challenge.
    pub challenge: [u8; 32],
    /// Contains the complete original authorized planning opening.
    pub planning_open: [u8; DELETE_ROOT_PLANNING_OPEN_BYTES_V3],
    /// Contains its original independently sampled Root challenge.
    pub planning_challenge: [u8; DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3],
    /// Contains the complete native namespace, process and public trust preimages.
    pub planning_observation: [u8; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2],
    /// Gives the historical Cache query's actual original nonce.
    pub cache_nonce: [u8; 16],
    /// Gives that historical Cache query's immutable original cutoff.
    pub cache_cutoff: u64,
}

impl DeleteRootInitialFrameDataV3 {
    /// Encodes the complete comparison without allocating or issuing a grant.
    ///
    /// # Errors
    /// Refuses missing associations or malformed complete planning preimages.
    pub fn encode_v3(
        self,
    ) -> Result<[u8; DELETE_ROOT_INITIAL_FRAME_BYTES_V3], DeleteRootInitialDataErrorV3> {
        self.planning_v3()?;
        let mut bytes = [0; DELETE_ROOT_INITIAL_FRAME_BYTES_V3];
        encode_header_v3(&mut bytes, b"AOSDRI03");
        bytes[16..48].copy_from_slice(&self.open);
        bytes[48..80].copy_from_slice(&self.challenge);
        bytes[80..PLANNING_CHALLENGE_OFFSET].copy_from_slice(&self.planning_open);
        bytes[PLANNING_CHALLENGE_OFFSET..PLANNING_OBSERVATION_OFFSET].copy_from_slice(&self.planning_challenge);
        bytes[PLANNING_OBSERVATION_OFFSET..CACHE_NONCE_OFFSET].copy_from_slice(&self.planning_observation);
        bytes[CACHE_NONCE_OFFSET..CACHE_CUTOFF_OFFSET].copy_from_slice(&self.cache_nonce);
        bytes[CACHE_CUTOFF_OFFSET..].copy_from_slice(&self.cache_cutoff.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only the explicit complete version3 comparison frame.
    ///
    /// # Errors
    /// Refuses other purposes/versions, reserved bytes or invalid nested DATA.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootInitialDataErrorV3> {
        header_v3(bytes, DELETE_ROOT_INITIAL_FRAME_BYTES_V3, b"AOSDRI03")?;
        let value = Self {
            open: array(bytes, 16)?,
            challenge: array(bytes, 48)?,
            planning_open: array(bytes, 80)?,
            planning_challenge: array(bytes, PLANNING_CHALLENGE_OFFSET)?,
            planning_observation: array(bytes, PLANNING_OBSERVATION_OFFSET)?,
            cache_nonce: array(bytes, CACHE_NONCE_OFFSET)?,
            cache_cutoff: u64::from_be_bytes(array(bytes, CACHE_CUTOFF_OFFSET)?),
        };
        value.planning_v3()?;
        Ok(value)
    }

    /// Decodes and compares the whole original planning exchange through its sole codecs.
    ///
    /// # Errors
    /// Refuses any malformed nested frame, mixed original or missing query binding.
    pub fn planning_v3(
        self,
    ) -> Result<
        (
            DeleteRootPlanningOpenDataV3,
            DeleteRootPlanningChallengeDataV3,
            DeleteRootPlanningObservationDataV2,
        ),
        DeleteRootInitialDataErrorV3,
    > {
        if self.open == [0; 32]
            || self.challenge == [0; 32]
            || self.cache_nonce == [0; 16]
            || self.cache_cutoff == 0
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        let open = DeleteRootPlanningOpenDataV3::decode_v3(&self.planning_open)?;
        let challenge = DeleteRootPlanningChallengeDataV3::decode_v3(&self.planning_challenge)?;
        let observation = DeleteRootPlanningObservationDataV2::decode(&self.planning_observation)?;
        observation.require_exchange_v2(open, challenge)?;
        Ok((open, challenge, observation))
    }

    /// Compares current and historical original clock/project associations.
    ///
    /// Historical nonces and cutoff remain historical; they are never renewed.
    ///
    /// # Errors
    /// Refuses another current pending flight, authorization or historical boot.
    pub fn require_exchange_v3(
        self,
        open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2,
    ) -> Result<(), DeleteRootInitialDataErrorV3> {
        challenge.require_open_v2(open)?;
        let (planning, _, observation) = self.planning_v3()?;
        if self.open != open.digest_v2()?
            || self.challenge != challenge.digest_v2()?
            || planning.project != open.project
            || planning.authorization_clock != open.authorization_clock
            || planning.authorization_expires != open.authorization_expires
            || self.cache_cutoff > challenge.source.cutoff
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        observation
            .native
            .clock
            .validate_later_sample(challenge.clock)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        Ok(())
    }

    /// Commits every original initial comparison byte under its versioned domain.
    ///
    /// # Errors
    /// Refuses the same malformed DATA as encoding.
    pub fn digest_v3(self) -> Result<[u8; 32], DeleteRootInitialDataErrorV3> {
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.delete-root.initial-frame.v3\0")
            .chain_update(self.encode_v3()?)
            .finalize()
            .into())
    }
}

/// Contains only the actual completed receiver's comparison acknowledgement DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootInitialAckDataV3 {
    /// Commits the exact current pending opening.
    pub open: [u8; 32],
    /// Commits its exact current Root challenge.
    pub challenge: [u8; 32],
    /// Commits all complete initial preimages received on this same connection.
    pub frame: [u8; 32],
    /// Gives the independently recomputed six-descriptor aggregate.
    pub initial_six: [u8; 32],
    /// Gives the actual final Root comparison sample under the original horizon.
    pub clock: RawPairedClockSample,
}

impl DeleteRootInitialAckDataV3 {
    /// Encodes the exact nonauthorizing acknowledgement DATA.
    ///
    /// # Errors
    /// Refuses a missing complete association.
    pub fn encode_v3(
        self,
    ) -> Result<[u8; DELETE_ROOT_INITIAL_ACK_BYTES_V3], DeleteRootWireErrorV2> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_INITIAL_ACK_BYTES_V3];
        encode_header_v3(&mut bytes, b"AOSDIA03");
        bytes[16..48].copy_from_slice(&self.open);
        bytes[48..80].copy_from_slice(&self.challenge);
        bytes[80..112].copy_from_slice(&self.frame);
        bytes[112..144].copy_from_slice(&self.initial_six);
        encode_clock(&mut bytes, 144, self.clock);
        Ok(bytes)
    }

    /// Decodes only the explicit initial-verification acknowledgement purpose.
    ///
    /// # Errors
    /// Refuses framing, reserved bytes, invalid clock or missing associations.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        header_v3(bytes, DELETE_ROOT_INITIAL_ACK_BYTES_V3, b"AOSDIA03")?;
        let value = Self {
            open: array(bytes, 16)?,
            challenge: array(bytes, 48)?,
            frame: array(bytes, 80)?,
            initial_six: array(bytes, 112)?,
            clock: decode_clock(bytes, 144)?,
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Compares every complete association and the original fresh Root horizon.
    ///
    /// The caller must separately hold its actual native/C17/Session originals.
    ///
    /// # Errors
    /// Refuses another frame, aggregate, flight, boot, rolled-back clock or expiry.
    pub fn require_exchange_v3(
        self,
        frame: DeleteRootInitialFrameDataV3,
        open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2,
        expected_initial_six: [u8; 32],
    ) -> Result<(), DeleteRootInitialDataErrorV3> {
        self.require_canonical()?;
        frame.require_exchange_v3(open, challenge)?;
        if self.open != open.digest_v2()?
            || self.challenge != challenge.digest_v2()?
            || self.frame != frame.digest_v3()?
            || self.initial_six != expected_initial_six
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        challenge
            .clock
            .validate_later_sample(self.clock)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        if self.clock.wall_seconds() >= open.authorization_expires
            || self.clock.boottime_nanoseconds() >= challenge.source.cutoff
        {
            return Err(DeleteRootWireErrorV2::Clock.into());
        }
        Ok(())
    }

    fn require_canonical(self) -> Result<(), DeleteRootWireErrorV2> {
        if [self.open, self.challenge, self.frame, self.initial_six].contains(&[0; 32]) {
            return Err(DeleteRootWireErrorV2::Format);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    #[test]
    fn ack_has_an_explicit_version_and_never_adopts_another_purpose() {
        // Passive fixtures exercise DATA only, not native or query ownership.
        let value = DeleteRootInitialAckDataV3 {
            open: [1; 32],
            challenge: [2; 32],
            frame: [3; 32],
            initial_six: [4; 32],
            clock: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted([5; 16]).unwrap(),
                [6; 16],
                100,
                10_000_000_000,
            )
            .unwrap(),
        };
        let bytes = value.encode_v3().unwrap();
        assert_eq!(
            DeleteRootInitialAckDataV3::decode_v3(&bytes).unwrap(),
            value
        );
        assert!(DeleteRootInitialAckDataV3::decode_v3(&bytes[..191]).is_err());

        for index in [0, 7, 8, 9, 10, 15] {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(DeleteRootInitialAckDataV3::decode_v3(&changed).is_err());
        }
        for offset in [16, 48, 80, 112] {
            let mut changed = bytes;
            changed[offset..offset + 32].fill(0);
            assert!(DeleteRootInitialAckDataV3::decode_v3(&changed).is_err());
        }
        assert!(DeleteRootInitialFrameDataV3::decode_v3(&bytes).is_err());
    }
}
