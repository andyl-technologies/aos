//! Encodes the named Controller/C17 cut for one fresh Delete Root challenge.
//!
//! ```text
//! controller1136 = AOSDRC03 | version3/reserved | digest(challenge224) |
//!                 canonical-funding-union1072 | ControllerNEXT8 | durableEnd8
//! ```
//!
//! This is untrusted comparison DATA. Root independently reads its fixed
//! Controller view and full Bank/semantic history; no decoder creates C17,
//! a native owner, a six-domain conjunction or accepted lifecycle state.

use super::super::resource_bank::{
    OPERATION_INTAKE_FUNDING_BYTES_V1, OperationIntakeFundingDataV1, ResourceBankDataError,
};
use super::transport::{DeleteRootChallengeDataV2, DeleteRootWireErrorV2, header_v3, encode_header_v3};

/// Gives the exact versioned Controller/C17 frame extent.
pub const DELETE_ROOT_CONTROLLER_CUT_BYTES_V3: usize = 16 + 32 + OPERATION_INTAKE_FUNDING_BYTES_V1 + 8 + 8;
const MAGIC: &[u8; 8] = b"AOSDRC03";

/// Identifies a fixed framing or full-cut comparison refusal.
#[derive(Debug, thiserror::Error)]
pub enum DeleteRootControllerCutErrorV3 {
    /// The fixed framing, extent or native position is invalid.
    #[error("Delete Root Controller cut is noncanonical")]
    Format,
    /// The exact Root challenge or captured Controller cut differs.
    #[error("Delete Root Controller cut differs from the same fresh flight")]
    Association,
    /// The existing canonical funding codec rejected its DATA.
    #[error(transparent)]
    Funding(#[from] ResourceBankDataError),
    /// The complete canonical Root challenge is invalid.
    #[error(transparent)]
    Challenge(#[from] DeleteRootWireErrorV2),
}

/// Carries the complete C17 funding and actual held Controller native position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootControllerCutDataV3 {
    /// Commits all original Challenge224 fields under their named D domain.
    pub challenge: [u8; 32],
    /// Retains the entire actual C17 canonical funding, not a selected subset.
    pub funding: OperationIntakeFundingDataV1,
    /// Gives the actual same held Controller NEXT.
    pub next: u64,
    /// Gives that Controller coordinator's actual durable native end.
    pub end: u64,
}

impl DeleteRootControllerCutDataV3 {

    /// Decodes only the explicit authorization-bearing V3 Controller cut.
    ///
    /// # Errors
    /// Rejects another version and the same malformed OperationIntakeFundingDataV1/native DATA.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootControllerCutErrorV3> {
        header_v3(bytes, DELETE_ROOT_CONTROLLER_CUT_BYTES_V3, MAGIC)
            .map_err(|_| DeleteRootControllerCutErrorV3::Format)?;
        let value = Self {
            challenge: bytes[16..48]
                .try_into()
                .map_err(|_| DeleteRootControllerCutErrorV3::Format)?,
            funding: OperationIntakeFundingDataV1::decode_v1(&bytes[48..48 + OPERATION_INTAKE_FUNDING_BYTES_V1])?,
            next: u64::from_be_bytes(
                bytes[48 + OPERATION_INTAKE_FUNDING_BYTES_V1..56 + OPERATION_INTAKE_FUNDING_BYTES_V1]
                    .try_into()
                    .map_err(|_| DeleteRootControllerCutErrorV3::Format)?,
            ),
            end: u64::from_be_bytes(
                bytes[56 + OPERATION_INTAKE_FUNDING_BYTES_V1..]
                    .try_into()
                    .map_err(|_| DeleteRootControllerCutErrorV3::Format)?,
            ),
        };
        value.require_canonical()?;
        Ok(value)
    }

    /// Encodes every V3 comparison field without constructing its native owner.
    ///
    /// # Errors
    /// Rejects malformed OperationIntakeFundingDataV1 or native position DATA.
    pub fn encode_v3(self) -> Result<[u8; DELETE_ROOT_CONTROLLER_CUT_BYTES_V3], DeleteRootControllerCutErrorV3> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_CONTROLLER_CUT_BYTES_V3];
        encode_header_v3(&mut bytes, MAGIC);
        bytes[16..48].copy_from_slice(&self.challenge);
        bytes[48..48 + OPERATION_INTAKE_FUNDING_BYTES_V1].copy_from_slice(&self.funding.encode_v1()?);
        bytes[48 + OPERATION_INTAKE_FUNDING_BYTES_V1..56 + OPERATION_INTAKE_FUNDING_BYTES_V1].copy_from_slice(&self.next.to_be_bytes());
        bytes[56 + OPERATION_INTAKE_FUNDING_BYTES_V1..].copy_from_slice(&self.end.to_be_bytes());
        Ok(bytes)
    }

    /// Compares the actual complete V2 challenge under its explicit domain.
    ///
    /// # Errors
    /// Rejects another challenge or malformed native comparison DATA.
    pub fn require_challenge_v2(self, challenge: DeleteRootChallengeDataV2)
        -> Result<(), DeleteRootControllerCutErrorV3> {
        self.require_canonical()?;
        if self.challenge != challenge.digest_v2()? {
            return Err(DeleteRootControllerCutErrorV3::Association);
        }
        Ok(())
    }

    /// Commits all canonical funding and actual Controller native coordinates.
    ///
    /// This digest is comparison DATA and never adopts a C17 or current writer.
    ///
    /// # Errors
    /// Refuses the same malformed funding or native coordinates as encoding.
    pub fn digest_v3(self) -> Result<[u8; 32], DeleteRootControllerCutErrorV3> {
        use sha2::{Digest as _, Sha256};
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.delete-root.controller-cut.v3\0")
            .chain_update(self.encode_v3()?).finalize().into())
    }

    fn require_canonical(self) -> Result<(), DeleteRootControllerCutErrorV3> {
        self.funding.require_delete_data_v1()?;
        if self.challenge == [0; 32]
            || self.next == 0
            || self.next == u64::MAX
            || self.end == 0
        {
            return Err(DeleteRootControllerCutErrorV3::Format);
        }
        Ok(())
    }
}
