//! Encodes the trust-bearing planning observation without granting its producer.
//!
//! ```text
//! observation1312 = native784(version2) | trust528
//! trust528 = AOSDOT02/version2/reserved | open32/challenge32/native-digest32 |
//!   policy-digest32/size8/scope16/key-generation8/key-fingerprint32 |
//!   key-id-length1/key-id255/public-key32 | checksum32
//! ```
//!
//! Policy media, signature purpose and key usage are exactly TrustPolicy and
//! OwnershipLease. The genuine native caller supplies protected provenance;
//! decoding this complete public preimage supplies no native or lease grant.

use super::super::transport::{DeleteRootWireErrorV2, array, header_v2, encode_header_v2};
use super::{
    DeleteRootPlanningChallengeDataV3, DeleteRootPlanningDataErrorV3,
    DeleteRootPlanningNativeDataV2, DeleteRootPlanningOpenDataV3,
};
use aos_sandbox_model::{KeyUsage, PortableMediaType};
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;
use sha2::{Digest as _, Sha256};

/// Gives the complete strict V2 planning observation extent.
pub const DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2: usize = 1312;
const TRUST_DOMAIN: &[u8] = b"aos.sandbox.delete-root.planning-ownership-trust.v2\0";
const NATIVE_DOMAIN: &[u8] = b"aos.sandbox.delete-root.planning-native-observation.v2\0";

/// Carries the complete canonical public trust preimage from a protected reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningTrustDataV2 {
    payload: [u8; 384],
}

impl DeleteRootPlanningTrustDataV2 {
    /// Projects the actual verifier's public configuration through one recipe.
    ///
    /// This compares its independently stored authority to the anchor's exact
    /// authority. It constructs DATA only and admits no protected provenance.
    ///
    /// # Errors
    /// Rejects mismatched authorities, another policy media/usage or invalid DATA.
    pub fn from_verifier_comparison_v2(
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<Self, DeleteRootPlanningDataErrorV3> {
        let view = verifier.trust_anchor_comparison_v1();
        let authority = view.authority();
        if verifier.authority() != authority
            || authority.usage() != KeyUsage::OwnershipLease
            || view.policy_descriptor().media_type().as_str()
                != PortableMediaType::TrustPolicy.as_str()
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        let mut payload = [0; 384];
        payload[..32].copy_from_slice(view.policy_descriptor().digest().as_bytes());
        payload[32..40].copy_from_slice(&view.policy_descriptor().encoded_size().to_be_bytes());
        payload[40..56].copy_from_slice(view.trust_scope().as_bytes());
        payload[56..64].copy_from_slice(&authority.generation().to_be_bytes());
        payload[64..96].copy_from_slice(authority.public_key_sha256().as_bytes());
        let id = authority.stable_key_id().as_str().as_bytes();
        payload[96] = u8::try_from(id.len()).map_err(|_| DeleteRootWireErrorV2::Format)?;
        payload[97..97 + id.len()].copy_from_slice(id);
        payload[352..].copy_from_slice(view.public_key());
        let value = Self { payload };
        value.require_canonical()?;
        Ok(value)
    }

    /// Borrows every canonical public comparison byte in its documented order.
    #[must_use]
    pub fn canonical_preimage_v2(&self) -> &[u8; 384] {
        &self.payload
    }

    /// Compares the complete observed public configuration to a held verifier.
    ///
    /// # Errors
    /// Rejects any configuration byte or independent verifier-authority mismatch.
    pub fn require_verifier_comparison_v2(
        self,
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<(), DeleteRootPlanningDataErrorV3> {
        if self != Self::from_verifier_comparison_v2(verifier)? {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(())
    }

    fn require_canonical(self) -> Result<(), DeleteRootPlanningDataErrorV3> {
        let id_length = usize::from(self.payload[96]);
        let policy_bytes = u64::from_be_bytes(array(&self.payload, 32)?);
        if self.payload[..32] == [0; 32]
            || !(1..=65536).contains(&policy_bytes)
            || self.payload[40..56] == [0; 16]
            || self.payload[56..64] == [0; 8]
            || id_length == 0
            || self.payload[97 + id_length..352]
                .iter()
                .any(|byte| *byte != 0)
            || std::str::from_utf8(&self.payload[97..97 + id_length]).is_err()
            || self.payload[64..96] != Sha256::digest(&self.payload[352..])[..]
        {
            return Err(DeleteRootWireErrorV2::Format.into());
        }
        Ok(())
    }
}

/// Carries the native namespace/process observation and its whole public trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningObservationDataV2 {
    /// Contains the original complete native namespace/process preimages.
    pub native: DeleteRootPlanningNativeDataV2,
    /// Contains the independently read bootstrap's canonical public trust.
    pub trust: DeleteRootPlanningTrustDataV2,
}

impl DeleteRootPlanningObservationDataV2 {
    /// Encodes the strict V2 exchange with all full preimages and associations.
    ///
    /// # Errors
    /// Rejects malformed native or public trust DATA.
    pub fn encode(
        self,
    ) -> Result<[u8; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2], DeleteRootPlanningDataErrorV3>
    {
        self.trust.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2];
        bytes[..784].copy_from_slice(&self.native.encode_v2()?);
        let native_digest = native_digest(&bytes[..784]);
        let tail = &mut bytes[784..];
        encode_header_v2(tail, b"AOSDOT02");
        tail[16..48].copy_from_slice(&self.native.open);
        tail[48..80].copy_from_slice(&self.native.challenge);
        tail[80..112].copy_from_slice(&native_digest);
        tail[112..496].copy_from_slice(&self.trust.payload);
        let checksum = trust_digest(&tail[..496]);
        tail[496..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes only explicit V2 and recomputes every named full-preimage binding.
    ///
    /// # Errors
    /// Rejects V1, truncation, malformed trust, checksums or mixed observations.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeleteRootPlanningDataErrorV3> {
        if bytes.len() != DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2 {
            return Err(DeleteRootWireErrorV2::Format.into());
        }
        let native =
            DeleteRootPlanningNativeDataV2::decode_v2(&bytes[..784])?;
        let tail = &bytes[784..];
        header_v2(tail, 528, b"AOSDOT02")?;
        if tail[16..48] != native.open
            || tail[48..80] != native.challenge
            || tail[80..112] != native_digest(&bytes[..784])
            || tail[496..] != trust_digest(&tail[..496])
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        let trust = DeleteRootPlanningTrustDataV2 {
            payload: array(tail, 112)?,
        };
        trust.require_canonical()?;
        Ok(Self { native, trust })
    }

    /// Compares both exact V3 planning originals and their immutable final horizon.
    ///
    /// # Errors
    /// Rejects other originals, clock rollback or expiry.
    pub fn require_exchange_v2(
        self,
        open: DeleteRootPlanningOpenDataV3,
        challenge: DeleteRootPlanningChallengeDataV3,
    ) -> Result<(), DeleteRootPlanningDataErrorV3> {
        challenge.require_open_v3(open)?;
        self.trust.require_canonical()?;
        self.native.require_canonical()?;
        if self.native.open != open.digest_v3()?
            || self.native.challenge != challenge.digest_v3()?
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        challenge
            .clock
            .validate_later_sample(self.native.clock)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        if self.native.clock.boottime_nanoseconds() >= challenge.cutoff
            || self.native.clock.wall_seconds() >= open.authorization_expires
        {
            return Err(DeleteRootWireErrorV2::Clock.into());
        }
        Ok(())
    }
}

fn native_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(NATIVE_DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn trust_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(TRUST_DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::super::{
        DeleteRootPlanningDirectoryDataV1, DeleteRootPlanningFileDataV1,
        DeleteRootPlanningNamespaceDataV1, DeleteRootPlanningOwnershipDataV1,
    };
    use super::*;
    use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};

    fn observation() -> DeleteRootPlanningObservationDataV2 {
        let file = DeleteRootPlanningFileDataV1 {
            device: 1,
            inode: 2,
            uid: 0,
            gid: 0,
            mode: 0o100600,
            links: 1,
            bytes: 128,
        };
        let directory = DeleteRootPlanningDirectoryDataV1 {
            file: DeleteRootPlanningFileDataV1 {
                inode: 3,
                mode: 0o40700,
                links: 2,
                ..file
            },
            mount: 9,
        };
        let native = DeleteRootPlanningNativeDataV2 {
            open: [3; 32],
            challenge: [4; 32],
            clock: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted([1; 16]).unwrap(),
                [2; 16],
                100,
                10_000_000_000,
            )
            .unwrap(),
            namespace: DeleteRootPlanningNamespaceDataV1 {
                directories: [directory; 2],
                local: [[file; 3]; 3],
            },
            ownership: DeleteRootPlanningOwnershipDataV1 {
                pid: 42,
                invocation: [5; 16],
                cgroup: 6,
                unit: [7; 32],
                executable: [8; 32],
            },
        };
        let mut payload = [0; 384];
        payload[..32].fill(11);
        payload[32..40].copy_from_slice(&128_u64.to_be_bytes());
        payload[40..56].fill(12);
        payload[56..64].copy_from_slice(&1_u64.to_be_bytes());
        payload[352..].fill(13);
        let fingerprint: [u8; 32] = Sha256::digest(&payload[352..]).into();
        payload[64..96].copy_from_slice(&fingerprint);
        payload[96] = 255;
        payload[97..352].fill(b'k');
        DeleteRootPlanningObservationDataV2 {
            native,
            trust: DeleteRootPlanningTrustDataV2 { payload },
        }
    }

    #[test]
    fn v2_binds_every_native_trust_and_association_byte() {
        let value = observation();
        let bytes = value.encode().unwrap();
        assert_eq!(
            DeleteRootPlanningObservationDataV2::decode(&bytes).unwrap(),
            value
        );
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                DeleteRootPlanningObservationDataV2::decode(&changed).is_err(),
                "byte {index}"
            );
        }
        assert!(
            DeleteRootPlanningObservationDataV2::decode(&value.native.encode_v2().unwrap()).is_err()
        );
        let mut retired = bytes;
        retired[7] = b'1';
        retired[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(DeleteRootPlanningObservationDataV2::decode(&retired).is_err());
    }

    #[test]
    fn resealed_trust_still_rejects_key_fingerprint_and_noncanonical_padding() {
        let mut value = observation();
        value.trust.payload[64] ^= 1;
        assert!(value.encode().is_err());
        let mut value = observation();
        value.trust.payload[96] = 1;
        assert!(value.encode().is_err());
    }

    fn fresh_transfer_fixture() -> (
        super::super::super::transport::DeleteRootOpenDataV2,
        super::super::super::transport::DeleteRootChallengeDataV2,
        super::super::super::initial_inventory::DeleteRootInitialAckDataV3,
        super::super::super::final_inventory::DeleteRootFreshTransferDataV2,
    ) {
        use super::super::super::{transport::{DeleteRootOpenDataV2, DeleteRootChallengeDataV2},
            source_current::SourceDeleteCurrentQueryDataV1, initial_inventory::DeleteRootInitialAckDataV3,
            final_inventory::{DeleteRootFreshTransferDataV2, initial_ack_commitment_data_v2}};
        let sample = |wall, boot| RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16], wall, boot,
        ).unwrap();
        let mut pending = [3; 64];
        pending[..16].fill(4);
        pending[48..56].copy_from_slice(&7u64.to_be_bytes());
        pending[56..].copy_from_slice(&4096u64.to_be_bytes());
        let open = DeleteRootOpenDataV2 {
            project: [5; 16], operation: [4; 16], batch: [6; 32], batch_bytes: 640,
            authorization_clock: sample(98, 8_000_000_000), authorization_expires: 500,
            source_pending: pending,
        };
        let clock = sample(99, 9_000_000_000);
        let challenge = DeleteRootChallengeDataV2 {
            open: open.digest_v2().unwrap(), clock,
            source: SourceDeleteCurrentQueryDataV1 {
                nonce: [7; 16], project: open.project, operation: open.operation, batch: open.batch,
                boot: clock.host_boot_id(), started: clock.boottime_nanoseconds(),
                cutoff: open.cutoff_for_root_sample_v1(clock).unwrap(),
            },
        };
        let initial = DeleteRootInitialAckDataV3 {
            open: open.digest_v2().unwrap(), challenge: challenge.digest_v2().unwrap(),
            frame: [8; 32], initial_six: [9; 32], clock: sample(100, 10_000_000_000),
        };
        let mut observation = observation();
        observation.native.open = initial.open;
        observation.native.challenge = initial.challenge;
        observation.native.clock = sample(101, 11_000_000_000);
        let data = DeleteRootFreshTransferDataV2 {
            open: initial.open, challenge: initial.challenge,
            initial_ack: initial_ack_commitment_data_v2(&initial.encode_v3().unwrap()), observation,
        };
        (open, challenge, initial, data)
    }

    #[test]
    fn fresh_transfer_has_a_distinct_purpose_and_keeps_the_sole_complete_preimage() {
        use super::super::super::final_inventory::DeleteRootFreshTransferDataV2;
        let (open, challenge, initial, data) = fresh_transfer_fixture();
        data.require_exchange_v2(open, challenge, initial).unwrap();
        let encoded = data.encode_v2().unwrap();
        assert_eq!(DeleteRootFreshTransferDataV2::decode_v2(&encoded).unwrap(), data);
        assert_eq!(&encoded[112..], &data.observation.encode().unwrap());
        assert!(DeleteRootFreshTransferDataV2::decode_v2(&data.observation.encode().unwrap()).is_err());
        assert!(DeleteRootPlanningObservationDataV2::decode(&encoded).is_err());
        for index in 8..16 {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert!(DeleteRootFreshTransferDataV2::decode_v2(&changed).is_err());
        }
        let mut changed = encoded;
        changed[16] ^= 1;
        assert!(DeleteRootFreshTransferDataV2::decode_v2(&changed).is_err());
    }

    #[test]
    fn fresh_transfer_rejects_old_ack_rollback_and_the_original_exact_cutoff() {
        let (open, challenge, initial, data) = fresh_transfer_fixture();
        let original = data.owner_cut_data_v2().unwrap();
        let mut wrong = data;
        wrong.initial_ack[0] ^= 1;
        assert!(wrong.require_exchange_v2(open, challenge, initial).is_err());
        assert_ne!(wrong.owner_cut_data_v2().unwrap(), original);
        let mut wrong = data;
        wrong.observation.native.clock = challenge.clock;
        assert!(wrong.require_exchange_v2(open, challenge, initial).is_err());
        let mut wrong = data;
        wrong.observation.native.clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16],
            104, challenge.source.cutoff,
        ).unwrap();
        assert!(wrong.require_exchange_v2(open, challenge, initial).is_err());
        let mut changed = data;
        changed.observation.native.ownership.invocation[0] ^= 1;
        assert_ne!(changed.owner_cut_data_v2().unwrap(), original);
    }

}
