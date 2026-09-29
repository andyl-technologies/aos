//! Stable unsigned owning-journal disposition and settlement identities.
//!
//! ```text
//! Root722 = AOSNDA01 | version1 | disposition | observation | reserved[4] |
//!           original_scope[224] | Source_artifact[32] | descriptor[32] | witnesses[418]
//! Store488 = AOSNSA01 | version1 | disposition | interest_active=1 | reserved[4] |
//!            full_scope[224] | Root_ID[32] | existing_unsigned_acceptance[216]
//! Provider336 = AOSNPA01 | version1 | disposition | interest_active=1 | reserved[4] |
//!               full_scope[224] | Root_ID[32] | Store_ID[32] | Source_artifact[32]
//! S104 = disposition | interest_active=1 | reserved[6] | Root_ID | Store_ID | Provider_ID
//! ```
//!
//! These claims do not commit an owner transition or prove custody. Their stable
//! unsigned IDs deliberately exclude hot frame signatures and recovery nonces.

use aos_sandbox_core::ObjectDigest;

use crate::StorageNativeAcceptanceV3;

use super::codec::{Reader, digest, invalid, nonzero};
use super::witness::{
    NativeHeldByteWitnessV1, ROOT_NATIVE_WITNESS_FAMILIES_V1, decode_records, encode_records,
};
use super::{NativeHeldControlKindV1, NativeHeldScopeV1, Result};

/// Pins the exact width of the unsigned Root disposition assertion.
pub const ROOT_NATIVE_DISPOSITION_ASSERTION_BYTES_V1: usize = 722;
/// Pins the exact width of the unsigned Storage settlement assertion.
pub const STORAGE_NATIVE_SETTLEMENT_ASSERTION_BYTES_V1: usize = 488;
/// Pins the exact width of the unsigned Provider settlement assertion.
pub const PROVIDER_NATIVE_SETTLEMENT_ASSERTION_BYTES_V1: usize = 336;
/// Pins the exact width of the stable terminal identity tuple.
pub const NATIVE_HELD_SETTLEMENT_BYTES_V1: usize = 104;

const ROOT_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.root-disposition.v1\0";
const STORAGE_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.storage-settlement.v1\0";
const PROVIDER_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.provider-settlement.v1\0";

/// Names the irreversible owning-journal outcome, not live effect permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldDispositionV1 {
    /// Root genuinely accepted its original FD locally; manager crossing is closed.
    Accepted = 1,
    /// Root irrevocably closed the original flight without a custody claim.
    Closed = 2,
}

impl NativeHeldDispositionV1 {
    pub(super) fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Closed),
            _ => Err(invalid("disposition")),
        }
    }
}

/// Distinguishes Root's unchanged partial preparation from observed Source bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RootNativeObservationV1 {
    /// The two Source-only scope fields remain original immutable zeroes.
    PreparedOnly = 1,
    /// Root observed the actual full ProviderHeld scope and Source artifact.
    ProviderHeldObserved = 2,
}

/// Claims one canonical unsigned Root journal disposition and exact companions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeDispositionAssertionV1 {
    /// Names Accepted or irreversible Closed.
    pub disposition: NativeHeldDispositionV1,
    /// Fixes whether Root observed the full Source offer.
    pub observation: RootNativeObservationV1,
    /// Retains exact original full or five-known-field scope.
    pub scope: NativeHeldScopeV1,
    /// Uses the existing canonical Source response artifact; zero only partial Closed.
    pub source_artifact: ObjectDigest,
    /// Uses the original complete descriptor commitment; zero for every Closed.
    pub descriptor_commitment: ObjectDigest,
    /// Lists exact session/attempt/acquisition/head byte claims in canonical order.
    pub records: [NativeHeldByteWitnessV1; 4],
}

impl RootNativeDispositionAssertionV1 {
    /// Encodes the stable unsigned assertion, independently of any hot archive.
    ///
    /// # Errors
    ///
    /// Rejects partial Accepted, nonzero Closed custody, sentinel positive fields
    /// or substituted companion witness families.
    pub fn to_canonical_bytes(&self) -> Result<[u8; ROOT_NATIVE_DISPOSITION_ASSERTION_BYTES_V1]> {
        match (self.disposition, self.observation) {
            (NativeHeldDispositionV1::Accepted, RootNativeObservationV1::ProviderHeldObserved) => {
                self.scope.validate_full()?;
                if !nonzero(self.source_artifact)
                    || !nonzero(self.descriptor_commitment)
                    || self.records.iter().any(|record| !nonzero(record.digest()))
                {
                    return Err(invalid("Accepted original observation"));
                }
            }
            (NativeHeldDispositionV1::Closed, RootNativeObservationV1::PreparedOnly) => {
                self.scope.validate_root_only()?;
                if nonzero(self.source_artifact) || nonzero(self.descriptor_commitment) {
                    return Err(invalid("partial Closed fields"));
                }
            }
            (NativeHeldDispositionV1::Closed, RootNativeObservationV1::ProviderHeldObserved) => {
                self.scope.validate_full()?;
                if !nonzero(self.source_artifact) || nonzero(self.descriptor_commitment) {
                    return Err(invalid("observed Closed fields"));
                }
            }
            _ => return Err(invalid("partial Accepted")),
        }
        // Only the acquisition can be absent in a valid original Root prefix.
        if [0, 1, 3]
            .iter()
            .any(|index| !nonzero(self.records[*index].digest()))
        {
            return Err(invalid("mandatory Root companion"));
        }
        let mut bytes = b"AOSNDA01".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(self.disposition as u8);
        bytes.push(self.observation as u8);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.scope.to_canonical_bytes());
        bytes.extend_from_slice(self.source_artifact.as_bytes());
        bytes.extend_from_slice(self.descriptor_commitment.as_bytes());
        encode_records(&mut bytes, &self.records, &ROOT_NATIVE_WITNESS_FAMILIES_V1)?;
        bytes
            .try_into()
            .map_err(|_| invalid("Root assertion width"))
    }

    /// Decodes exact stable bytes without manufacturing journal readback.
    ///
    /// # Errors
    ///
    /// Rejects every width, reserved-byte, scope, disposition or witness mismatch.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ROOT_NATIVE_DISPOSITION_ASSERTION_BYTES_V1 {
            return Err(invalid("Root assertion width"));
        }
        let mut reader = Reader::new(bytes);
        reader.header(b"AOSNDA01")?;
        let disposition = NativeHeldDispositionV1::from_byte(reader.u8()?)?;
        let observation = match reader.u8()? {
            1 => RootNativeObservationV1::PreparedOnly,
            2 => RootNativeObservationV1::ProviderHeldObserved,
            _ => return Err(invalid("Root observation")),
        };
        reader.zeros(4)?;
        let value = Self {
            disposition,
            observation,
            scope: NativeHeldScopeV1::decode(&mut reader)?,
            source_artifact: reader.digest()?,
            descriptor_commitment: reader.digest()?,
            records: decode_records(&mut reader, ROOT_NATIVE_WITNESS_FAMILIES_V1)?,
        };
        reader.finish()?;
        if value.to_canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("Root assertion canonical bytes"));
        }
        Ok(value)
    }

    /// Computes the stable disposition identity over the entire unsigned assertion.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed assertion fields as canonical encoding.
    pub fn digest(&self) -> Result<ObjectDigest> {
        Ok(digest(ROOT_DOMAIN, &self.to_canonical_bytes()?))
    }
}

/// Claims genuine retained Storage settlement while keeping its interest active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeSettlementAssertionV1 {
    /// Retains the immutable owning Root disposition class.
    pub disposition: NativeHeldDispositionV1,
    /// Retains the exact full original Requested scope.
    pub scope: NativeHeldScopeV1,
    /// Uses the stable unsigned Root assertion ID, never its hot frame hash.
    pub root_disposition: ObjectDigest,
    /// Reuses the exact original existing unsigned216-byte acceptance codec.
    pub acceptance: StorageNativeAcceptanceV3,
}

impl StorageNativeSettlementAssertionV1 {
    /// Encodes stable settlement metadata, never interest retirement or custody.
    ///
    /// # Errors
    ///
    /// Rejects incomplete scope, a sentinel Root ID or changed native request binding.
    pub fn to_canonical_bytes(&self) -> Result<[u8; STORAGE_NATIVE_SETTLEMENT_ASSERTION_BYTES_V1]> {
        self.scope.validate_full()?;
        if !nonzero(self.root_disposition)
            || self.acceptance.request_digest() != self.scope.original_native_request
        {
            return Err(invalid("Storage assertion original join"));
        }
        let mut bytes = settlement_header(b"AOSNSA01", self.disposition);
        bytes.extend_from_slice(&self.scope.to_canonical_bytes());
        bytes.extend_from_slice(self.root_disposition.as_bytes());
        bytes.extend_from_slice(&self.acceptance.to_canonical_bytes());
        bytes
            .try_into()
            .map_err(|_| invalid("Storage assertion width"))
    }

    /// Decodes the exact unsigned assertion without reconstructing acceptance authority.
    ///
    /// # Errors
    ///
    /// Rejects wrong version/width, retired interest claims or inconsistent original bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != STORAGE_NATIVE_SETTLEMENT_ASSERTION_BYTES_V1 {
            return Err(invalid("Storage assertion width"));
        }
        let mut reader = Reader::new(bytes);
        let disposition = read_settlement_header(&mut reader, b"AOSNSA01")?;
        let value = Self {
            disposition,
            scope: NativeHeldScopeV1::decode(&mut reader)?,
            root_disposition: reader.digest()?,
            acceptance: StorageNativeAcceptanceV3::from_canonical_bytes(reader.bytes(216)?)
                .map_err(|_| invalid("original unsigned acceptance"))?,
        };
        reader.finish()?;
        if value.to_canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("Storage assertion canonical bytes"));
        }
        Ok(value)
    }

    /// Computes the stable Storage identity, independent of query nonce or signature.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed assertion fields as canonical encoding.
    pub fn digest(&self) -> Result<ObjectDigest> {
        Ok(digest(STORAGE_DOMAIN, &self.to_canonical_bytes()?))
    }
}

/// Claims exact retained Source settlement, never a new positive outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderNativeSettlementAssertionV1 {
    /// Retains the immutable owning Root disposition class.
    pub disposition: NativeHeldDispositionV1,
    /// Retains the exact full original Requested scope.
    pub scope: NativeHeldScopeV1,
    /// Uses the stable unsigned owning Root disposition ID.
    pub root_disposition: ObjectDigest,
    /// Uses the actual verified original Storage settlement assertion ID.
    pub storage_settlement: ObjectDigest,
    /// Retains the Source artifact; zero is legal only Closed before Complete.
    pub source_artifact: ObjectDigest,
}

impl ProviderNativeSettlementAssertionV1 {
    /// Encodes stable Source settlement without fabricating skipped Complete rows.
    ///
    /// # Errors
    ///
    /// Rejects incomplete scope, absent owner IDs or an Accepted zero artifact.
    pub fn to_canonical_bytes(
        &self,
    ) -> Result<[u8; PROVIDER_NATIVE_SETTLEMENT_ASSERTION_BYTES_V1]> {
        self.scope.validate_full()?;
        if !nonzero(self.root_disposition)
            || !nonzero(self.storage_settlement)
            || (self.disposition == NativeHeldDispositionV1::Accepted
                && !nonzero(self.source_artifact))
        {
            return Err(invalid("Provider settlement IDs"));
        }
        let mut bytes = settlement_header(b"AOSNPA01", self.disposition);
        bytes.extend_from_slice(&self.scope.to_canonical_bytes());
        for digest in [
            self.root_disposition,
            self.storage_settlement,
            self.source_artifact,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes
            .try_into()
            .map_err(|_| invalid("Provider assertion width"))
    }

    /// Decodes stable bytes without producing Source admission or signing custody.
    ///
    /// # Errors
    ///
    /// Rejects width/version/interest or original-scope and settlement-ID mismatches.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PROVIDER_NATIVE_SETTLEMENT_ASSERTION_BYTES_V1 {
            return Err(invalid("Provider assertion width"));
        }
        let mut reader = Reader::new(bytes);
        let disposition = read_settlement_header(&mut reader, b"AOSNPA01")?;
        let value = Self {
            disposition,
            scope: NativeHeldScopeV1::decode(&mut reader)?,
            root_disposition: reader.digest()?,
            storage_settlement: reader.digest()?,
            source_artifact: reader.digest()?,
        };
        reader.finish()?;
        if value.to_canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("Provider assertion canonical bytes"));
        }
        Ok(value)
    }

    /// Computes the stable Provider identity, excluding every control signature.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed assertion fields as canonical encoding.
    pub fn digest(&self) -> Result<ObjectDigest> {
        Ok(digest(PROVIDER_DOMAIN, &self.to_canonical_bytes()?))
    }
}

/// Retains stable disposition/settlement IDs while consumer interest stays active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHeldSettlementV1 {
    /// Retains the irreversible Root disposition class.
    pub disposition: NativeHeldDispositionV1,
    /// Uses the owning journal's stable unsigned Root disposition identity.
    pub root_disposition: ObjectDigest,
    /// Uses the stable original Storage assertion identity.
    pub storage_settlement: ObjectDigest,
    /// Uses the stable Source assertion identity; zero only in Storage kind6.
    pub provider_settlement: ObjectDigest,
}

impl NativeHeldSettlementV1 {
    /// Encodes a nonauthorizing active-interest tuple with exact stable IDs.
    ///
    /// # Errors
    ///
    /// Rejects sentinel Root or Storage settlement identities.
    pub fn to_canonical_bytes(&self) -> Result<[u8; NATIVE_HELD_SETTLEMENT_BYTES_V1]> {
        if !nonzero(self.root_disposition) || !nonzero(self.storage_settlement) {
            return Err(invalid("settlement IDs"));
        }
        let mut bytes = [0; NATIVE_HELD_SETTLEMENT_BYTES_V1];
        bytes[0] = self.disposition as u8;
        bytes[1] = 1;
        bytes[8..40].copy_from_slice(self.root_disposition.as_bytes());
        bytes[40..72].copy_from_slice(self.storage_settlement.as_bytes());
        bytes[72..104].copy_from_slice(self.provider_settlement.as_bytes());
        Ok(bytes)
    }

    /// Decodes exact tuple bytes without interpreting them as interest retirement.
    ///
    /// # Errors
    ///
    /// Rejects width, reserved fields, retired-interest markers or sentinel IDs.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NATIVE_HELD_SETTLEMENT_BYTES_V1 {
            return Err(invalid("settlement width"));
        }
        let mut reader = Reader::new(bytes);
        let disposition = NativeHeldDispositionV1::from_byte(reader.u8()?)?;
        if reader.u8()? != 1 {
            return Err(invalid("interest-active marker"));
        }
        reader.zeros(6)?;
        let value = Self {
            disposition,
            root_disposition: reader.digest()?,
            storage_settlement: reader.digest()?,
            provider_settlement: reader.digest()?,
        };
        reader.finish()?;
        value.to_canonical_bytes()?;
        Ok(value)
    }

    /// Checks the Provider-ID presence fixed by kind6 versus kinds7/13.
    ///
    /// # Errors
    ///
    /// Rejects an unrelated kind or wrong Provider identity presence.
    pub fn validate_for_kind(&self, kind: NativeHeldControlKindV1) -> Result<()> {
        self.to_canonical_bytes()?;
        let required = match kind {
            NativeHeldControlKindV1::StorageSettled => false,
            NativeHeldControlKindV1::ProviderSettled
            | NativeHeldControlKindV1::RootTerminalRecorded => true,
            _ => return Err(invalid("settlement control kind")),
        };
        if nonzero(self.provider_settlement) != required {
            return Err(invalid("Provider settlement presence"));
        }
        Ok(())
    }
}

fn settlement_header(magic: &[u8; 8], disposition: NativeHeldDispositionV1) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[disposition as u8, 1, 0, 0, 0, 0]);
    bytes
}

fn read_settlement_header(
    reader: &mut Reader<'_>,
    magic: &[u8; 8],
) -> Result<NativeHeldDispositionV1> {
    reader.header(magic)?;
    let disposition = NativeHeldDispositionV1::from_byte(reader.u8()?)?;
    if reader.u8()? != 1 {
        return Err(invalid("interest-active marker"));
    }
    reader.zeros(4)?;
    Ok(disposition)
}
