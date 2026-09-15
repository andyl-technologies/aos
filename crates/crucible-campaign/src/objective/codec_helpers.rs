//! Canonical objective scalar and schema helpers.

use super::*;

pub(super) fn canonical_magnitude_bytes(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

pub(super) fn validate_magnitude(
    bytes: &[u8],
    reason: &'static str,
) -> Result<(), CampaignCodecError> {
    if bytes.is_empty()
        || bytes.len() > MAX_FIXED_REWARD_MAGNITUDE_BYTES
        || bytes.len() > 1 && bytes[0] == 0
    {
        Err(CampaignCodecError::InvalidValue { reason })
    } else {
        Ok(())
    }
}

pub(super) fn require_schema(actual: u32) -> Result<(), CampaignCodecError> {
    if actual == RECORD_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported objective record schema version",
        })
    }
}
