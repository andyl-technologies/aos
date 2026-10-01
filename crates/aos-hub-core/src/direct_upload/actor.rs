//! Immutable authenticated actor incarnations and retained numeric-slot fences.
//!
//! Numeric database IDs address a permanent broker reservation, while the UUID
//! determines the public principal namespace. SQL restore/reset never authorizes
//! replacement of an already reserved actor slot.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{valid_direct_identity, WireInteger};

/// Closed authenticated account kind, resolved by Native rather than the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectActorKind {
    /// Retained human account identity.
    User,
    /// Retained service-account identity.
    ServiceAccount,
}

/// Protected actor slot that must be permanently reserved before business work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectActorSlot {
    /// Exact authenticated account kind.
    pub kind: DirectActorKind,
    /// Positive signed-64-bit database slot; never a permanent public identity.
    pub numeric_id: WireInteger,
    /// Server-created canonical lowercase UUIDv4 account incarnation.
    pub incarnation: String,
}

impl DirectActorSlot {
    /// Checks the canonical retained account slot without proving its provenance.
    ///
    /// # Errors
    /// Returns an error for a nonpositive/overflowing slot or noncanonical UUIDv4.
    pub fn validate(&self) -> Result<()> {
        let bytes = self.incarnation.as_bytes();
        let uuid = bytes.len() == 36
            && bytes.iter().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
                }
            })
            && bytes.get(14) == Some(&b'4')
            && bytes
                .get(19)
                .is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'));
        ensure!(
            (1..=i64::MAX as u64).contains(&self.numeric_id.get()) && uuid,
            "invalid direct authenticated actor slot"
        );
        Ok(())
    }

    /// Derives the public principal commitment, excluding the recyclable slot.
    ///
    /// The byte format is the domain followed by three u32-length-framed UTF-8
    /// strings: deployment, account-kind spelling, and canonical UUIDv4.
    ///
    /// # Errors
    /// Returns an error for an invalid actor or deployment namespace.
    pub fn principal_id(&self, deployment: &str) -> Result<String> {
        self.validate()?;
        ensure!(
            valid_direct_identity(deployment),
            "invalid direct actor deployment"
        );
        let mut digest = Sha256::new();
        digest.update(b"aos.direct-upload.principal.v1\0");
        let kind = match self.kind {
            DirectActorKind::User => "user",
            DirectActorKind::ServiceAccount => "service_account",
        };
        for value in [deployment, kind, self.incarnation.as_str()] {
            digest.update((value.len() as u32).to_be_bytes());
            digest.update(value.as_bytes());
        }
        Ok(hex::encode(digest.finalize()))
    }
}
