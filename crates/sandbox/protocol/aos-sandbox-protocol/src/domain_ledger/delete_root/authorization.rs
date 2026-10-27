//! Encodes the complete versioned Delete authorization witness DATA.
//!
//! ```text
//! header208 = AOSDRA02/version2/reserved | Open32/Challenge32 |
//!   project16/caller16/capability16/input-bytes8/channel32 |
//!   capability-not-before8/expires8/policy-not-before8/expires8/authorized-wall8
//! body = complete-canonical-input | sha256(domain | header208 | input)
//! ```
//!
//! The real C17 caller lends its retained protected decision and input. Root
//! independently rereads the same Controller prefix and recomputes every named
//! authorization field. This codec creates no decision, TLS session or grant.

use super::transport::{
    DeleteRootChallengeDataV2, DeleteRootOpenDataV2, DeleteRootWireErrorV2, header_v2, encode_header_v2, array,
};
use sha2::{Digest as _, Sha256};

/// Gives the strict fixed authorization header size.
pub const DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2: usize = 208;
/// Gives the existing canonical Delete envelope's actual parser bound.
pub const DELETE_ROOT_AUTHORIZATION_INPUT_MAXIMUM_BYTES_V2: usize = 14 + 64 * 1024;
/// Gives the complete witness's trailing checksum extent.
pub const DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2: usize = 32;

/// Contains every fixed authorization field, without a protected decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootAuthorizationFieldsV2 {
    /// Commits the exact version2 opening.
    pub open: [u8; 32],
    /// Commits the exact independently sampled version2 Root challenge.
    pub challenge: [u8; 32],
    /// Names the actual authenticated project.
    pub project: [u8; 16],
    /// Names the original authenticated principal.
    pub caller: [u8; 16],
    /// Names the exact capability read from Root's own Controller prefix.
    pub capability: [u8; 16],
    /// Bounds the complete canonical input that follows this fixed header.
    pub input_bytes: u64,
    /// Records the actual capability's original authenticated channel binding.
    pub channel: [u8; 32],
    /// Records the capability's inclusive lease start.
    pub capability_not_before: i64,
    /// Records the capability's exclusive lease end.
    pub capability_expires: i64,
    /// Records the current policy's inclusive lease start.
    pub policy_not_before: i64,
    /// Records the current policy's exclusive lease end.
    pub policy_expires: i64,
    /// Records the original protected authorization wall time.
    pub authorized_wall: i64,
}

impl DeleteRootAuthorizationFieldsV2 {
    /// Encodes only the strict bounded comparison header.
    ///
    /// # Errors
    /// Rejects missing identities, invalid lengths or contradictory original leases.
    pub fn encode_v2(
        self,
    ) -> Result<[u8; DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2], DeleteRootWireErrorV2> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2];
        encode_header_v2(&mut bytes, b"AOSDRA02");
        bytes[16..48].copy_from_slice(&self.open);
        bytes[48..80].copy_from_slice(&self.challenge);
        bytes[80..96].copy_from_slice(&self.project);
        bytes[96..112].copy_from_slice(&self.caller);
        bytes[112..128].copy_from_slice(&self.capability);
        bytes[128..136].copy_from_slice(&self.input_bytes.to_be_bytes());
        bytes[136..168].copy_from_slice(&self.channel);
        bytes[168..176].copy_from_slice(&self.capability_not_before.to_be_bytes());
        bytes[176..184].copy_from_slice(&self.capability_expires.to_be_bytes());
        bytes[184..192].copy_from_slice(&self.policy_not_before.to_be_bytes());
        bytes[192..200].copy_from_slice(&self.policy_expires.to_be_bytes());
        bytes[200..208].copy_from_slice(&self.authorized_wall.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only the strict version2 fixed header, before body allocation.
    ///
    /// # Errors
    /// Rejects other versions and the same invalid DATA as encoding.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        header_v2(
            bytes,
            DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2,
            b"AOSDRA02",
        )?;
        let value = Self {
            open: array(bytes, 16)?,
            challenge: array(bytes, 48)?,
            project: array(bytes, 80)?,
            caller: array(bytes, 96)?,
            capability: array(bytes, 112)?,
            input_bytes: u64::from_be_bytes(array(bytes, 128)?),
            channel: array(bytes, 136)?,
            capability_not_before: i64::from_be_bytes(array(bytes, 168)?),
            capability_expires: i64::from_be_bytes(array(bytes, 176)?),
            policy_not_before: i64::from_be_bytes(array(bytes, 184)?),
            policy_expires: i64::from_be_bytes(array(bytes, 192)?),
            authorized_wall: i64::from_be_bytes(array(bytes, 200)?),
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Compares both originals and the exact original authorization horizon.
    ///
    /// # Errors
    /// Rejects another opening/challenge/project, wall sample or lease cutoff.
    pub fn require_exchange_v2(
        self,
        open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2,
    ) -> Result<(), DeleteRootWireErrorV2> {
        self.require_canonical()?;
        challenge.require_open_v2(open)?;
        if self.open != open.digest_v2()?
            || self.challenge != challenge.digest_v2()?
            || self.project != open.project
            || self.authorized_wall != open.authorization_clock.wall_seconds()
            || self.capability_expires.min(self.policy_expires) != open.authorization_expires
        {
            return Err(DeleteRootWireErrorV2::Association);
        }
        Ok(())
    }

    fn require_canonical(self) -> Result<(), DeleteRootWireErrorV2> {
        let length =
            usize::try_from(self.input_bytes).map_err(|_| DeleteRootWireErrorV2::Format)?;
        if self.open == [0; 32]
            || self.challenge == [0; 32]
            || self.project == [0; 16]
            || self.caller == [0; 16]
            || self.capability == [0; 16]
            || self.channel == [0; 32]
            || !(1..=DELETE_ROOT_AUTHORIZATION_INPUT_MAXIMUM_BYTES_V2).contains(&length)
            || self.authorized_wall < self.capability_not_before
            || self.authorized_wall >= self.capability_expires
            || self.authorized_wall < self.policy_not_before
            || self.authorized_wall >= self.policy_expires
        {
            return Err(DeleteRootWireErrorV2::Format);
        }
        Ok(())
    }
}

/// Commits the exact header and whole canonical input without allocating.
#[must_use]
pub fn authorization_witness_checksum_data_v2(
    header: &[u8; DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2],
    input: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.delete-root.authorization-witness.v2\0")
        .chain_update(header)
        .chain_update(input)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1;
    use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};

    fn sample(wall: i64, boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            boot * 1_000_000_000,
        )
        .unwrap()
    }

    fn exchange() -> (
        DeleteRootOpenDataV2,
        DeleteRootChallengeDataV2,
        DeleteRootAuthorizationFieldsV2,
    ) {
        let mut native = [3; 64];
        native[..16].copy_from_slice(&[4; 16]);
        native[48..56].copy_from_slice(&7_u64.to_be_bytes());
        native[56..].copy_from_slice(&4096_u64.to_be_bytes());
        let open = DeleteRootOpenDataV2 {
            project: [5; 16],
            operation: [4; 16],
            batch: [6; 32],
            batch_bytes: 640,
            authorization_clock: sample(100, 10),
            authorization_expires: 104,
            source_pending: native,
        };
        let clock = sample(101, 11);
        let challenge = DeleteRootChallengeDataV2 {
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
        };
        let fields = DeleteRootAuthorizationFieldsV2 {
            open: open.digest_v2().unwrap(),
            challenge: challenge.digest_v2().unwrap(),
            project: open.project,
            caller: [8; 16],
            capability: [9; 16],
            input_bytes: 3,
            channel: [10; 32],
            capability_not_before: 90,
            capability_expires: 105,
            policy_not_before: 95,
            policy_expires: 104,
            authorized_wall: 100,
        };
        (open, challenge, fields)
    }

    #[test]
    fn explicit_v2_preserves_complete_authorization_association() {
        let (open, challenge, fields) = exchange();
        assert_eq!(
            DeleteRootOpenDataV2::decode_v2(&open.encode_v2().unwrap()).unwrap(),
            open
        );
        assert_eq!(
            DeleteRootChallengeDataV2::decode_v2(&challenge.encode_v2().unwrap()).unwrap(),
            challenge
        );
        assert!(fields.require_exchange_v2(open, challenge).is_ok());
    }

    #[test]
    fn complete_witness_checksum_binds_every_header_and_input_byte() {
        let (_, _, fields) = exchange();
        let header = fields.encode_v2().unwrap();
        assert_eq!(
            DeleteRootAuthorizationFieldsV2::decode_v2(&header).unwrap(),
            fields
        );
        let input = [11, 12, 13];
        let checksum = authorization_witness_checksum_data_v2(&header, &input);
        for index in 0..header.len() {
            let mut changed = header;
            changed[index] ^= 1;
            assert_ne!(
                checksum,
                authorization_witness_checksum_data_v2(&changed, &input),
                "header {index}"
            );
        }
        for index in 0..input.len() {
            let mut changed = input;
            changed[index] ^= 1;
            assert_ne!(
                checksum,
                authorization_witness_checksum_data_v2(&header, &changed),
                "input {index}"
            );
        }
    }

    #[test]
    fn witness_cannot_renew_either_original_lease_or_switch_exchange() {
        let (open, challenge, fields) = exchange();
        let mut changed = fields;
        changed.policy_expires += 1;
        assert!(changed.require_exchange_v2(open, challenge).is_err());
        changed = fields;
        changed.authorized_wall += 1;
        assert!(changed.require_exchange_v2(open, challenge).is_err());
        changed = fields;
        changed.open[0] ^= 1;
        assert!(changed.require_exchange_v2(open, challenge).is_err());
        changed = fields;
        changed.input_bytes = (DELETE_ROOT_AUTHORIZATION_INPUT_MAXIMUM_BYTES_V2 as u64) + 1;
        assert!(changed.encode_v2().is_err());
        let mut header = fields.encode_v2().unwrap();
        header[7] = b'1';
        assert!(DeleteRootAuthorizationFieldsV2::decode_v2(&header).is_err());
        header = fields.encode_v2().unwrap();
        header[15] = 1;
        assert!(DeleteRootAuthorizationFieldsV2::decode_v2(&header).is_err());
    }
}
