//! Shares the fixed accepted-operation association used by Held bodies.
//!
//! This comparison DATA records the original accepted Create and cutoff. It
//! cannot reconstruct the intake, renew the cutoff or authorize a transition.
//!
//! ```text
//! operation16 | project16 | sandbox16 | accepted-request32 | coissuance32 |
//! seed32 | Controller-nonce16 | boot16 | started8 | cutoff8
//! ```

use super::{HistoryErrorV1, nonzero, reader};

/// Holds the exact accepted-operation association extent without a body magic.
pub const ASSOCIATION_BYTES_V1: usize = 192;

/// Carries the original accepted Create association as passive comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedAssociationDataV1 {
    /// The accepted operation, distinct from a Spec publication operation.
    pub operation: [u8; 16],
    /// The accepted project's identity.
    pub project: [u8; 16],
    /// The accepted sandbox projection's identity.
    pub sandbox: [u8; 16],
    /// The existing scope's digest of the exact accepted canonical request.
    pub accepted_request: [u8; 32],
    /// The retained original native coissuance association commitment.
    pub coissuance_binding: [u8; 32],
    /// The commitment of the complete Controller Intent association.
    pub seed: [u8; 32],
    /// The original once-generated and persisted Controller nonce.
    pub controller_nonce: [u8; 16],
    /// The original continuation clock's host boot identity.
    pub boot: [u8; 16],
    /// The original paired BOOTTIME sample in nanoseconds.
    pub started: u64,
    /// The same immutable cutoff, never a renewed deadline.
    pub cutoff: u64,
}

impl AcceptedAssociationDataV1 {
    /// Decodes the exact fixed association without allocating or granting use.
    ///
    /// # Errors
    /// Rejects a nonexact extent, zero association or nonincreasing cutoff.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self::read(&mut input)?;
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    // Reads complete fields first; the Source adapter preserves its existing
    // subsequent names/NEXT validation before its final cutoff comparison.
    pub(super) fn read(
        input: &mut aos_sandbox_model::bounded_codec::BoundedReader<'_, HistoryErrorV1>,
    ) -> Result<Self, HistoryErrorV1> {
        Ok(Self {
            operation: input.array()?, project: input.array()?, sandbox: input.array()?,
            accepted_request: input.array()?, coissuance_binding: input.array()?,
            seed: input.array()?, controller_nonce: input.array()?, boot: input.array()?,
            started: input.u64()?, cutoff: input.u64()?,
        })
    }

    /// Encodes the exact fixed association without allocation.
    ///
    /// # Errors
    /// Rejects zero identities or a nonincreasing original cutoff.
    pub fn encode(self) -> Result<[u8; ASSOCIATION_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; ASSOCIATION_BYTES_V1];
        bytes[..16].copy_from_slice(&self.operation);
        bytes[16..32].copy_from_slice(&self.project);
        bytes[32..48].copy_from_slice(&self.sandbox);
        bytes[48..80].copy_from_slice(&self.accepted_request);
        bytes[80..112].copy_from_slice(&self.coissuance_binding);
        bytes[112..144].copy_from_slice(&self.seed);
        bytes[144..160].copy_from_slice(&self.controller_nonce);
        bytes[160..176].copy_from_slice(&self.boot);
        bytes[176..184].copy_from_slice(&self.started.to_be_bytes());
        bytes[184..192].copy_from_slice(&self.cutoff.to_be_bytes());
        Ok(bytes)
    }

    pub(super) fn validate_identities(self) -> Result<(), HistoryErrorV1> {
        nonzero(&self.operation)?;
        nonzero(&self.project)?;
        nonzero(&self.sandbox)?;
        nonzero(&self.accepted_request)?;
        nonzero(&self.coissuance_binding)?;
        nonzero(&self.seed)?;
        nonzero(&self.controller_nonce)?;
        nonzero(&self.boot)?;
        Ok(())
    }

    pub(super) fn validate(self) -> Result<(), HistoryErrorV1> {
        self.validate_identities()?;
        if self.cutoff <= self.started {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}
