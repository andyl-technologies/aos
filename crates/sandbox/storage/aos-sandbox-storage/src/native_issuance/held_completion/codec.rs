//! Explicit held-v2 framing alongside the unchanged legacy-v1 codec.

use super::{
    HEADER_BYTES, MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2, NativeHeldCompletionSuffixV1,
    NativeIssuanceRowV1, Result, StorageHeldIssuanceRowV2, StorageIssuanceValueV1, invalid,
};

const MAGIC: &[u8; 8] = b"AOSNSI02";

impl StorageHeldIssuanceRowV2 {
    /// Encodes the original legacy fields followed by the one canonical suffix.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent original fields/prefixes or the complete value bound.
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.encode_fields()
    }

    // Historical-prefix reconstruction must not recursively validate its own W.
    pub(super) fn encode_fields(&self) -> Result<Vec<u8>> {
        let mut bytes = self.original.encode()?;
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&self.suffix.to_canonical_bytes()?);
        if bytes.len() > MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2 {
            return Err(invalid("held issuance value bound"));
        }
        Ok(bytes)
    }

    /// Decodes only explicit v2 and preserves every original signed request byte.
    ///
    /// # Errors
    ///
    /// Rejects malformed nested values, lengths, tails, prefixes and size limits.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2
            || bytes.len() < HEADER_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(2_u16.to_be_bytes().as_slice())
        {
            return Err(invalid("held issuance version/length"));
        }
        let request_length = u32::from_be_bytes(super::super::array(bytes, 80)?) as usize;
        let acceptance_length = u32::from_be_bytes(super::super::array(bytes, 84)?) as usize;
        let suffix_start = HEADER_BYTES
            .checked_add(request_length)
            .and_then(|length| length.checked_add(acceptance_length))
            .ok_or_else(|| invalid("held issuance lengths"))?;
        if suffix_start > super::super::MAXIMUM_VALUE_BYTES || suffix_start >= bytes.len() {
            return Err(invalid("held issuance original framing"));
        }
        let mut legacy = bytes
            .get(..suffix_start)
            .ok_or_else(|| invalid("held issuance truncated original"))?
            .to_vec();
        legacy[..8].copy_from_slice(super::super::MAGIC);
        legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
        let original = NativeIssuanceRowV1::decode(&legacy)?;
        let suffix = NativeHeldCompletionSuffixV1::from_canonical_bytes(&bytes[suffix_start..])?;
        let value = Self { original, suffix };
        value.validate()?;
        if value.to_canonical_bytes()? != bytes {
            return Err(invalid("held issuance canonical bytes"));
        }
        Ok(value)
    }
}

impl StorageIssuanceValueV1 {
    /// Selects the exact on-disk version; legacy bytes are never made held data.
    ///
    /// # Errors
    ///
    /// Rejects unknown, cross-version, malformed or noncanonical records.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes.get(..8) {
            Some(magic) if magic == super::super::MAGIC => {
                Ok(Self::Legacy(NativeIssuanceRowV1::decode(bytes)?))
            }
            Some(magic) if magic == MAGIC => Ok(Self::Held(
                StorageHeldIssuanceRowV2::from_canonical_bytes(bytes)?,
            )),
            _ => Err(invalid("issuance value magic")),
        }
    }

    /// Returns exact version-specific bytes without rewriting a legacy value.
    ///
    /// # Errors
    ///
    /// Rejects invalid version-specific data or its unchanged encoding bound.
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Legacy(row) => Ok(row.encode()?),
            Self::Held(row) => row.to_canonical_bytes(),
        }
    }

    pub(super) fn original(&self) -> &NativeIssuanceRowV1 {
        match self {
            Self::Legacy(row) => row,
            Self::Held(row) => &row.original,
        }
    }
}
