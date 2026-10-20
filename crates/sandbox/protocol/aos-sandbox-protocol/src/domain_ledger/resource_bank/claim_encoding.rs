//! Encodes borrowed canonical claim DATA without issuing or adopting a claim.

use super::{CLAIM_BYTES_V1, Claim, ResourceBankDataError};

impl Claim {
    /// Encodes the complete claim using the sole existing canonical codec.
    ///
    /// Encoded history supplies no financial, native or operation authority.
    ///
    /// # Errors
    /// Rejects the same noncanonical fields as the existing claim codec.
    pub fn encode(&self) -> Result<[u8; CLAIM_BYTES_V1], ResourceBankDataError> {
        super::codec::encode_claim(*self)
    }
}
