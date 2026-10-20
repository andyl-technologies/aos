//! Encodes the distinct authorized-before-Planned Root comparison DATA.
//!
//! ```text
//! open1264 = AOSDRP03 | version3/reserved | project16/caller16/input32 |
//!   original-clock48/expiry8 | original-C-nonce16/cutoff8 |
//!   C-NEXT8/end8 | Source-NEXT8/end8 | canonical-funding-union1072
//! challenge128 = AOSDPC03 | version3/reserved | digest(open1264) |
//!   fresh-Root-clock48 | fresh-Root-nonce16 | clamped-cutoff8 | reserved8
//! ```
//!
//! Only the funding-bearing V3 opening/challenge and complete trust-bearing
//! observation1312 are accepted by this planning exchange.
//! Retired unshipped Root V1/V2 headers are refused without reinterpretation.
//!
//! These fields describe a genuine producer's cuts but cannot create one.
//! In particular there is no pending-native64, candidate batch, floor or
//! six-owner grant; the later pending/preaccept exchange remains independent.

mod observation;
mod trust;
pub use trust::{DeleteRootPlanningObservationDataV2, DeleteRootPlanningTrustDataV2, DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2};
pub use observation::{
    DELETE_ROOT_PLANNING_NATIVE_BYTES_V2, DeleteRootPlanningDirectoryDataV1,
    DeleteRootPlanningFileDataV1, DeleteRootPlanningNamespaceDataV1,
    DeleteRootPlanningNativeDataV2, DeleteRootPlanningOwnershipDataV1,
};

use aos_sandbox_core::RawPairedClockSample;
use sha2::{Digest as _, Sha256};

use super::super::resource_bank::{
    OPERATION_INTAKE_FUNDING_BYTES_V1, OperationIntakeFundingDataV1, ResourceBankDataError,
};
use super::transport::{
    DeleteRootWireErrorV2, array, authorization_cutoff_for_root_sample_v1, decode_clock,
    encode_clock, header_v3, encode_header_v3,
};

/// Selects only the planning entrance's fresh Root challenge.
pub const DELETE_ROOT_PLANNING_CHALLENGE_MAGIC_V3: &[u8; 8] = b"AOSDPC03";
/// Gives the complete planning opening's fixed byte extent.
pub const DELETE_ROOT_PLANNING_OPEN_BYTES_V3: usize = 192 + OPERATION_INTAKE_FUNDING_BYTES_V1;
/// Gives the complete planning challenge's fixed byte extent.
pub const DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3: usize = 128;

/// Selects the trust-bearing authorized planning opening.
pub const DELETE_ROOT_PLANNING_OPEN_MAGIC_V3: &[u8; 8] = b"AOSDRP03";

/// Reports malformed planning DATA without classifying native role ownership.
#[derive(Debug, thiserror::Error)]
pub enum DeleteRootPlanningDataErrorV3 {
    /// Framing, clock or fixed comparison DATA is invalid.
    #[error(transparent)]
    Wire(#[from] DeleteRootWireErrorV2),
    /// The sole canonical C17 funding codec rejected its DATA.
    #[error(transparent)]
    Funding(#[from] ResourceBankDataError),
}

/// Carries only the authorized C17/Source predecessor planning comparisons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningOpenDataV3 {
    /// Identifies the actual authorized project.
    pub project: [u8; 16],
    /// Identifies the original authenticated caller.
    pub caller: [u8; 16],
    /// Commits the entire canonical authorized input under its planning domain.
    pub input: [u8; 32],
    /// Records the same original authorization's genuine paired clock.
    pub authorization_clock: RawPairedClockSample,
    /// Gives that authorization's minimum capability/policy expiry.
    pub authorization_expires: i64,
    /// Names this query's actual retained Controller entropy original.
    pub controller_nonce: [u8; 16],
    /// Gives its immutable original five-second/authorization-clamped cutoff.
    pub controller_cutoff: u64,
    /// Gives the actual continuously held Controller native NEXT.
    pub controller_next: u64,
    /// Gives that Controller coordinator's actual durable native end.
    pub controller_end: u64,
    /// Gives the same held Source predecessor's native NEXT.
    pub source_next: u64,
    /// Gives that held Source predecessor's durable native end.
    pub source_end: u64,
    /// Carries the complete initial reservation or actual recovered C17 debit.
    pub funding: OperationIntakeFundingDataV1,
}

impl DeleteRootPlanningOpenDataV3 {

    /// Decodes only the explicit funding-bearing V3 exchange.
    ///
    /// # Errors
    /// Rejects other versions and the same malformed comparison fields.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootPlanningDataErrorV3> {
        header_v3(
            bytes,
            DELETE_ROOT_PLANNING_OPEN_BYTES_V3,
            DELETE_ROOT_PLANNING_OPEN_MAGIC_V3,
        )?;
        let value = Self {
            project: array(bytes, 16)?,
            caller: array(bytes, 32)?,
            input: array(bytes, 48)?,
            authorization_clock: decode_clock(bytes, 80)?,
            authorization_expires: i64::from_be_bytes(array(bytes, 128)?),
            controller_nonce: array(bytes, 136)?,
            controller_cutoff: u64::from_be_bytes(array(bytes, 152)?),
            controller_next: u64::from_be_bytes(array(bytes, 160)?),
            controller_end: u64::from_be_bytes(array(bytes, 168)?),
            source_next: u64::from_be_bytes(array(bytes, 176)?),
            source_end: u64::from_be_bytes(array(bytes, 184)?),
            funding: OperationIntakeFundingDataV1::decode_v1(&bytes[192..])?,
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Encodes the explicit funding-bearing V3 exchange into fixed storage.
    ///
    /// # Errors
    /// Rejects the same malformed comparison fields as decoding.
    pub fn encode_v3(self) -> Result<[u8; DELETE_ROOT_PLANNING_OPEN_BYTES_V3], DeleteRootPlanningDataErrorV3> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_PLANNING_OPEN_BYTES_V3];
        encode_header_v3(&mut bytes, DELETE_ROOT_PLANNING_OPEN_MAGIC_V3);
        bytes[16..32].copy_from_slice(&self.project);
        bytes[32..48].copy_from_slice(&self.caller);
        bytes[48..80].copy_from_slice(&self.input);
        encode_clock(&mut bytes, 80, self.authorization_clock);
        bytes[128..136].copy_from_slice(&self.authorization_expires.to_be_bytes());
        bytes[136..152].copy_from_slice(&self.controller_nonce);
        bytes[152..160].copy_from_slice(&self.controller_cutoff.to_be_bytes());
        bytes[160..168].copy_from_slice(&self.controller_next.to_be_bytes());
        bytes[168..176].copy_from_slice(&self.controller_end.to_be_bytes());
        bytes[176..184].copy_from_slice(&self.source_next.to_be_bytes());
        bytes[184..192].copy_from_slice(&self.source_end.to_be_bytes());
        bytes[192..].copy_from_slice(&self.funding.encode_v1()?);
        Ok(bytes)
    }

    /// Clamps an independently sampled Root clock to both original horizons.
    ///
    /// The genuine Controller caller separately derives its nonce cutoff from
    /// the shared real five-second nonce owner. This DATA method cannot supply
    /// entropy, authenticate its producer, or renew that original's deadline.
    ///
    /// # Errors
    /// Rejects boot/clock rollback, expiry, elapsed original cutoff or overflow.
    pub fn cutoff_for_root_sample_v1(
        self,
        root: RawPairedClockSample,
    ) -> Result<u64, DeleteRootPlanningDataErrorV3> {
        self.require_canonical()?;
        let cutoff = authorization_cutoff_for_root_sample_v1(
            self.authorization_clock,
            self.authorization_expires,
            root,
        )?
        .min(self.controller_cutoff);
        if root.boottime_nanoseconds() >= cutoff {
            return Err(DeleteRootWireErrorV2::Clock.into());
        }
        Ok(cutoff)
    }

    /// Commits the explicit V3 bytes under their distinct versioned domain.
    ///
    /// # Errors
    /// Rejects malformed comparison DATA.
    pub fn digest_v3(self) -> Result<[u8; 32], DeleteRootPlanningDataErrorV3> {
        Ok(Sha256::new().chain_update(b"aos.sandbox.delete-root.planning-open.v3\0")
            .chain_update(self.encode_v3()?).finalize().into())
    }

    fn require_canonical(self) -> Result<(), DeleteRootPlanningDataErrorV3> {
        self.funding.require_delete_data_v1()?;
        let expiry = self
            .authorization_clock
            .conservative_expiry_deadline_data_v1(self.authorization_expires)
            .ok_or(DeleteRootWireErrorV2::Clock)?;
        if self.project == [0; 16]
            || self.caller == [0; 16]
            || self.input == [0; 32]
            || self.controller_nonce == [0; 16]
            || self.authorization_clock.boottime_nanoseconds() == 0
            || self.controller_cutoff <= self.authorization_clock.boottime_nanoseconds()
            || self.controller_cutoff > expiry
            || self.controller_next == 0
            || self.controller_next == u64::MAX
            || self.controller_end == 0
            || self.source_next == 0
            || self.source_next == u64::MAX
            || self.source_end == 0
        {
            return Err(DeleteRootWireErrorV2::Format.into());
        }
        self.funding.encode_v1()?;
        Ok(())
    }
}

/// Carries the actual Root nonce/paired sample for this one planning opening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningChallengeDataV3 {
    /// Commits all authorized planning opening fields and the complete C17 cut.
    pub open: [u8; 32],
    /// Records the independently retained Root paired clock sample.
    pub clock: RawPairedClockSample,
    /// Records that Root flight's actual fresh nonce.
    pub nonce: [u8; 16],
    /// Gives the minimum original Controller, authorization and Root horizon.
    pub cutoff: u64,
}

impl DeleteRootPlanningChallengeDataV3 {

    /// Decodes only the explicit funding-bearing V3 exchange.
    ///
    /// # Errors
    /// Rejects other versions and the same malformed comparison fields.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootPlanningDataErrorV3> {
        header_v3(
            bytes,
            DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3,
            DELETE_ROOT_PLANNING_CHALLENGE_MAGIC_V3,
        )?;
        if bytes[120..] != [0; 8] {
            return Err(DeleteRootWireErrorV2::Format.into());
        }
        let value = Self {
            open: array(bytes, 16)?,
            clock: decode_clock(bytes, 48)?,
            nonce: array(bytes, 96)?,
            cutoff: u64::from_be_bytes(array(bytes, 112)?),
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Encodes the explicit funding-bearing V3 exchange into fixed storage.
    ///
    /// # Errors
    /// Rejects the same malformed comparison fields as decoding.
    pub fn encode_v3(self) -> Result<[u8; DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3], DeleteRootPlanningDataErrorV3> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3];
        encode_header_v3(&mut bytes, DELETE_ROOT_PLANNING_CHALLENGE_MAGIC_V3);
        bytes[16..48].copy_from_slice(&self.open);
        encode_clock(&mut bytes, 48, self.clock);
        bytes[96..112].copy_from_slice(&self.nonce);
        bytes[112..120].copy_from_slice(&self.cutoff.to_be_bytes());
        Ok(bytes)
    }

    /// Commits the explicit V3 bytes under their distinct versioned domain.
    ///
    /// # Errors
    /// Rejects malformed comparison DATA.
    pub fn digest_v3(self) -> Result<[u8; 32], DeleteRootPlanningDataErrorV3> {
        Ok(Sha256::new().chain_update(b"aos.sandbox.delete-root.planning-challenge.v3\0")
            .chain_update(self.encode_v3()?).finalize().into())
    }

    /// Binds V3 to the exact opening and its original nonrenewable horizon.
    ///
    /// # Errors
    /// Rejects another opening or an extended original horizon.
    pub fn require_open_v3(self, open: DeleteRootPlanningOpenDataV3) -> Result<(), DeleteRootPlanningDataErrorV3> {
        self.require_canonical()?;
        if self.open != open.digest_v3()? || self.cutoff != open.cutoff_for_root_sample_v1(self.clock)? {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(())
    }

    fn require_canonical(self) -> Result<(), DeleteRootPlanningDataErrorV3> {
        if self.open == [0; 32]
            || self.nonce == [0; 16]
            || self.clock.boottime_nanoseconds() == 0
            || self.clock.boottime_nanoseconds() >= self.cutoff
        {
            return Err(DeleteRootWireErrorV2::Format.into());
        }
        Ok(())
    }
}
