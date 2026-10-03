//! Root-only canonical verification projection for the first terminal Source10.
//!
//! ```text
//! AOSNVE01 | version1 | reserved[6] | trust_generation:u64be | trust_digest[32] |
//! revocation_generation:u64be | revocation_digest[32] | verified_at:i64be |
//! signer_JSON_length:u32be | exact_SignerSnapshotV2_JSON[<=2048]
//! ```
//!
//! This serialized projection is not independently owned protected trust. The
//! actual receiver must capture it under its real trust/revocation writer before
//! retaining terminal10. Validation authenticates bytes against the projection;
//! it cannot establish that the projection was eligible at an actual readback.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::frame::{
    NativeHeldSignerV1, SignedNativeHeldControlV1,
};
use aos_sandbox_source_provider_protocol::{SourceProviderKeyUsageV1, SourceProviderSigningKeyV1};
use sha2::{Digest as _, Sha256};

use super::codec::Reader;
use crate::mount_source_acquisition_state::{
    Result, SignerRoleV2, SignerSnapshotV2, format::state_error,
};

/// Bounds the entire Root-specific terminal verifier projection.
pub const MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1: usize = 2_156;

/// Retains the exact historical verification claims for one current Provider10.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeTerminalVerifierV1 {
    /// Names the independently owned trust cut captured by the actual receiver.
    pub trust_generation: u64,
    /// Commits that cut's exact protected trust projection.
    pub trust_digest: ObjectDigest,
    /// Names the receiver's corresponding independently owned revocation cut.
    pub revocation_generation: u64,
    /// Commits the captured protected revocation projection.
    pub revocation_digest: ObjectDigest,
    /// Retains the actual verification time, never a new effect deadline.
    pub verified_at_seconds: i64,
    /// Reuses the actual canonical Mount signer snapshot type.
    pub signer: SignerSnapshotV2,
}

impl RootNativeTerminalVerifierV1 {
    /// Encodes the fixed verifier projection with canonical bounded signer JSON.
    ///
    /// # Errors
    ///
    /// Rejects sentinel cuts, wrong role, ineligible signer intervals or oversize JSON.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.signer_reference()?;
        let signer = serde_json::to_vec(&self.signer)
            .map_err(|_| state_error("native Root verifier JSON"))?;
        if signer.len() > 2_048 {
            return Err(state_error("native Root verifier signer limit"));
        }

        let mut bytes = b"AOSNVE01".to_vec();
        bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&self.trust_generation.to_be_bytes());
        bytes.extend_from_slice(self.trust_digest.as_bytes());
        bytes.extend_from_slice(&self.revocation_generation.to_be_bytes());
        bytes.extend_from_slice(self.revocation_digest.as_bytes());
        bytes.extend_from_slice(&self.verified_at_seconds.to_be_bytes());
        bytes.extend_from_slice(&(signer.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&signer);
        Ok(bytes)
    }

    /// Decodes the exact native verifier version and canonical signer projection.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, invalid role/cuts, noncanonical JSON or trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1 {
            return Err(state_error("native Root verifier limit"));
        }
        let mut reader = Reader::new(bytes);
        reader.header(b"AOSNVE01")?;
        let trust_generation = u64::from_be_bytes(reader.array()?);
        let trust_digest = ObjectDigest::from_bytes(reader.array()?);
        let revocation_generation = u64::from_be_bytes(reader.array()?);
        let revocation_digest = ObjectDigest::from_bytes(reader.array()?);
        let verified_at_seconds = i64::from_be_bytes(reader.array()?);
        let length = reader.u32()?;
        if length > 2_048 {
            return Err(state_error("native Root verifier signer limit"));
        }
        let signer = serde_json::from_slice(reader.bytes(length)?)
            .map_err(|_| state_error("native Root verifier signer JSON"))?;
        reader.finish()?;
        let value = Self {
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            verified_at_seconds,
            signer,
        };
        if value.to_canonical_bytes()? != bytes {
            return Err(state_error("native Root verifier canonical bytes"));
        }
        Ok(value)
    }

    pub(super) fn verify_terminal(
        &self,
        control: &SignedNativeHeldControlV1,
        provider: [u8; 16],
    ) -> Result<()> {
        let expected = self.signer_reference()?;
        if expected.authority_id() != provider {
            return Err(state_error("native Root verifier provider subject"));
        }
        control
            .verify_signature_claim(
                &NativeHeldSignerV1::SourceProvider(expected),
                &self.signer.public_key,
            )
            .map_err(|_| state_error("native Root current Provider terminal signature"))
    }

    fn signer_reference(&self) -> Result<SourceProviderSigningKeyV1> {
        let signer = &self.signer;
        if self.trust_generation == 0
            || self.revocation_generation == 0
            || self.trust_digest.as_bytes() == &[0; 32]
            || self.revocation_digest.as_bytes() == &[0; 32]
            || signer.role != SignerRoleV2::ProviderOutcome
            || signer.superseded_by_key_generation != 0
            || signer.public_key == [0; 32]
            || <[u8; 32]>::from(Sha256::digest(signer.public_key)) != signer.public_key_fingerprint
            || self.verified_at_seconds < signer.authority_valid_from_seconds
            || self.verified_at_seconds >= signer.authority_valid_until_seconds
            || self.verified_at_seconds < signer.key_valid_from_seconds
            || self.verified_at_seconds >= signer.key_valid_until_seconds
        {
            return Err(state_error("native Root terminal verifier projection"));
        }
        SourceProviderSigningKeyV1::new(
            signer.authority_id,
            signer.authority_generation,
            ObjectDigest::from_bytes(signer.authority_digest),
            signer.key_id,
            signer.key_generation,
            ObjectDigest::from_bytes(signer.public_key_fingerprint),
            SourceProviderKeyUsageV1::ProviderOutcome,
        )
        .map_err(|_| state_error("native Root terminal signer reference"))
    }
}
