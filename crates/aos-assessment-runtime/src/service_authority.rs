//! Secret-free receipts for explicitly reviewed recurring service authority.
//!
//! A receipt describes a coordinator-owned review. It cannot authenticate a
//! request, create a credential, or authorize work when imported by a client.

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::{decode, encoded};

/// Describes one finite review of an existing service-account credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceAuthorityV1 {
    /// Exact receipt discriminator.
    pub schema: String,
    /// Stable service principal commitment, independent of its recyclable ID.
    pub actor_ref: Sha256Digest,
    /// Commitment to the exact existing credential generation, never its secret.
    pub credential_ref: Sha256Digest,
    /// Stable commitment to the authenticated principal that applied the review.
    pub reviewer_ref: Sha256Digest,
    /// Exclusive review deadline, also bounded by the current credential expiry.
    pub expires_at: Timestamp,
}

impl ServiceAuthorityV1 {
    /// Encodes a closed receipt without exposing retained credential metadata.
    ///
    /// # Errors
    /// Returns an error for an unsupported schema or excessive content.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-service-authority/v1",
            "invalid assessment service authority receipt"
        );
        encoded(self)
    }

    /// Decodes the same descriptive receipt used by local and hosted clients.
    ///
    /// # Errors
    /// Returns an error for unknown fields, nulls, limits or an invalid schema.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment service authority receipt")?;
        value.to_bytes()?;
        Ok(value)
    }
}

/// Checks the canonical spelling of an existing credential-generation identity.
///
/// This syntax check performs no authentication or lookup. The coordinator
/// independently verifies the referenced credential and its current grants.
///
/// # Errors
/// Returns an error unless the value is a lowercase RFC 4122 version-four UUID.
pub fn validate_service_credential_id(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(bytes.len() == 36, "invalid service credential identity");
    for (index, byte) in bytes.iter().copied().enumerate() {
        ensure!(
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            },
            "invalid service credential identity"
        );
    }
    ensure!(
        bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
        "invalid service credential identity"
    );
    Ok(())
}

/// Computes the public commitment to one canonical credential generation.
///
/// The commitment is descriptive and cannot be exchanged for authentication.
///
/// # Errors
/// Returns an error for a noncanonical identity or canonical encoding failure.
pub fn service_credential_ref(value: &str) -> Result<Sha256Digest> {
    validate_service_credential_id(value)?;
    Sha256Digest::of_canonical("aos.assessment-service-credential/v1", &value)
}
