//! Encodes the closed initial-claim or recovered-subdivision comparison union.
//!
//! ```text
//! AOSOIF02 | kind1 | purpose1 | payloadLength2 | reserved4 | payload1056
//! initial: exact Claim531 followed by 525 zero bytes
//! recovered: exact AOSRFS02 debit row1056
//! ```
//!
//! Decoding supplies no native funding, enrolled owner or Root grant. Actual
//! consumers require their private issuer and independently held complete C.

use super::*;

/// Specifies the canonical closed funding-witness extent.
pub const OPERATION_INTAKE_FUNDING_BYTES_V1: usize = 16 + RECOVERED_OPERATION_FUNDING_BYTES_V1;

/// Keeps initial reservation and actual recovered subdivision DATA distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationIntakeFundingDataV1 {
    /// Carries the complete literal historical reserved Claim531.
    InitialReservedClaim(Claim),
    /// Carries the complete actual-debit comparison row from protected C.
    RecoveredBaseline(RecoveredOperationFundingDataV1),
}

impl OperationIntakeFundingDataV1 {
    /// Returns the unchanged shared-bank enrollment comparison identity.
    pub const fn enrollment_v1(self) -> EnrollmentIdentity {
        match self {
            Self::InitialReservedClaim(claim) => claim.enrollment,
            Self::RecoveredBaseline(row) => row.enrollment,
        }
    }

    /// Returns the actual successor recipient only for recovered subdivision.
    pub const fn recovered_recipient_v1(self) -> Option<[u8; 16]> {
        match self {
            Self::InitialReservedClaim(_) => None,
            Self::RecoveredBaseline(row) => Some(row.recipient),
        }
    }

    /// Requires exactly the Delete purpose without adopting either DATA kind.
    ///
    /// # Errors
    /// Refuses another role, malformed debit or non-reserved initial claim.
    pub fn require_delete_data_v1(self) -> Result<(), ResourceBankDataError> {
        if self.purpose_v1()? != RecoveredOperationFundingPurposeV1::Delete {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }

    /// Returns the closed purpose after canonical comparison validation.
    ///
    /// # Errors
    /// Refuses an unrelated or non-reserved claim, or malformed debit record.
    pub fn purpose_v1(self) -> Result<RecoveredOperationFundingPurposeV1, ResourceBankDataError> {
        match self {
            Self::InitialReservedClaim(claim) => {
                claim.encode()?;
                if claim.state != ClaimState::Reserved {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                match claim.purpose {
                    ClaimPurpose::DeleteOperationIntake => Ok(RecoveredOperationFundingPurposeV1::Delete),
                    ClaimPurpose::ExecutionOperationIntake => Ok(RecoveredOperationFundingPurposeV1::Execution),
                    _ => Err(ResourceBankDataError::CorruptLedger),
                }
            }
            Self::RecoveredBaseline(row) => {
                row.encode_v1()?;
                Ok(row.purpose)
            }
        }
    }

    /// Encodes the exact kind, closed purpose, inner codec and required padding.
    ///
    /// # Errors
    /// Refuses malformed, unrelated or non-reserved funding comparison DATA.
    pub fn encode_v1(self) -> Result<[u8; OPERATION_INTAKE_FUNDING_BYTES_V1], ResourceBankDataError> {
        let purpose = self.purpose_v1()?;
        let mut bytes = [0; OPERATION_INTAKE_FUNDING_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSOIF02");
        bytes[9] = match purpose {
            RecoveredOperationFundingPurposeV1::Delete => 17,
            RecoveredOperationFundingPurposeV1::Execution => 18,
        };
        let length = match self {
            Self::InitialReservedClaim(claim) => {
                bytes[8] = 0;
                bytes[16..16 + CLAIM_BYTES_V1].copy_from_slice(&claim.encode()?);
                CLAIM_BYTES_V1
            }
            Self::RecoveredBaseline(row) => {
                bytes[8] = 1;
                bytes[16..].copy_from_slice(&row.encode_v1()?);
                RECOVERED_OPERATION_FUNDING_BYTES_V1
            }
        };
        bytes[10..12].copy_from_slice(&(length as u16).to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only the canonical explicit union, never an old claim as a row.
    ///
    /// # Errors
    /// Refuses width, kind, role, padding, reserved bits or inner codec failure.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        if bytes.len() != OPERATION_INTAKE_FUNDING_BYTES_V1 || &bytes[..8] != b"AOSOIF02"
            || bytes[12..16].iter().any(|byte| *byte != 0) {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let value = match bytes[8] {
            0 if u16::from_be_bytes([bytes[10], bytes[11]]) as usize == CLAIM_BYTES_V1
                && bytes[16 + CLAIM_BYTES_V1..].iter().all(|byte| *byte == 0) =>
                Self::InitialReservedClaim(Claim::decode(&bytes[16..16 + CLAIM_BYTES_V1])?),
            1 if u16::from_be_bytes([bytes[10], bytes[11]]) as usize == RECOVERED_OPERATION_FUNDING_BYTES_V1 =>
                Self::RecoveredBaseline(RecoveredOperationFundingDataV1::decode_v1(&bytes[16..])?),
            _ => return Err(ResourceBankDataError::CorruptLedger),
        };
        if value.encode_v1()?.as_slice() != bytes {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(value)
    }

    /// Compares the actual complete protected funding row and full shared bank.
    ///
    /// # Errors
    /// Refuses absent, different, partial or foreign funding and corrupt replay.
    pub fn require_bank_record_v1(self, state: &State) -> Result<(), ResourceBankDataError> {
        self.purpose_v1()?;
        if replay::validate(state)? != Some(self.enrollment_v1()) {
            return Err(ResourceBankDataError::Conflict);
        }
        match self {
            Self::InitialReservedClaim(claim) => {
                // Preserved predecessor claims remain readable history after
                // succession. They cannot fund the new recipient's ordinary D/X.
                if recipient::recipient_incarnation(state, claim.enrollment)?
                    .is_some_and(|recipient| recipient.generation() != 0)
                {
                    return Err(ResourceBankDataError::Conflict);
                }
                require_exact_claim_record_v1(state, claim)
            }
            Self::RecoveredBaseline(row) => recovered_funding::require_pair_replayed_v1(state, row),
        }
    }

    /// Commits funding and the actual C boundary under their explicit kind.
    ///
    /// Initial Claim531 uses the unchanged existing preimage. The recovered
    /// branch has a distinct domain and commits the complete actual debit row.
    ///
    /// # Errors
    /// Refuses malformed funding comparison DATA before hashing.
    pub fn controller_funding_cut_data_v3(self, next: u64, end: u64) -> Result<[u8; 32], ResourceBankDataError> {
        use sha2::{Digest as _, Sha256};
        self.require_delete_data_v1()?;
        Ok(match self {
            Self::InitialReservedClaim(claim) => super::super::delete_root::named_cuts::
                controller_cut_from_encoded_claim_data_v2(&claim.encode()?, next, end),
            Self::RecoveredBaseline(row) => Sha256::new()
                .chain_update(b"aos.sandbox.delete.controller-recovered-funding-cut.v1\0")
                .chain_update(row.encode_v1()?).chain_update(next.to_be_bytes()).chain_update(end.to_be_bytes())
                .finalize().into(),
        })
    }
}
