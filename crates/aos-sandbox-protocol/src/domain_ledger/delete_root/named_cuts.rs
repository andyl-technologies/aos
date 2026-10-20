//! Shares the exact V2 named-cut preimages without granting their provenance.
//!
//! ```text
//! authorization = H(domain | project16 | caller16 | input-length8 | input |
//!   protected-revision32 | channel32 | capability-validity16 |
//!   policy-validity16 | authorized-wall8)
//! Controller = H(domain | complete-canonical-C17-Claim531 | NEXT8 | end8)
//! protected-revision = existing RevisionDigest(domain | exact-coordinates176)
//! ```
//!
//! These kernels hash supplied comparison DATA. Each actual consumer must
//! retain its native currentness, complete canonical input and protected
//! decision or independently read records. A digest constructs no decision,
//! journal owner, six-domain proof or accepting lifecycle state.

use crate::domain_ledger::resource_bank::CLAIM_BYTES_V1;
use crate::public_api::model::AuthorizationRevisionDigestV1;
use aos_sandbox_core::{CapabilityRecord, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

/// Carries the full retained authorization preimage as borrowed historical DATA.
#[derive(Clone, Copy)]
pub struct DeleteAuthorizationCutDataV2<'input> {
    /// Identifies the authenticated project.
    pub project: [u8; 16],
    /// Identifies the authenticated caller.
    pub caller: [u8; 16],
    /// Borrows the complete canonical public mutation input.
    pub input: &'input [u8],
    /// Commits the complete protected capability/policy/time-floor revision.
    pub revision: [u8; 32],
    /// Binds the actual authorized capability to its original channel.
    pub channel: [u8; 32],
    /// Records the actual capability's inclusive start.
    pub capability_not_before: i64,
    /// Records the actual capability's exclusive end.
    pub capability_expires: i64,
    /// Records the actual policy's inclusive start.
    pub policy_not_before: i64,
    /// Records the actual policy's exclusive end.
    pub policy_expires: i64,
    /// Records the protected wall instant used by the real decision.
    pub authorized_wall: i64,
}

impl DeleteAuthorizationCutDataV2<'_> {
    /// Commits every original preimage field under the sole named V2 recipe.
    #[must_use]
    pub fn digest_v2(self) -> [u8; 32] {
        // Every supported Rust target has at most a64-bit address space. The
        // original recipe's input-length encoding is therefore lossless.
        const {
            assert!(usize::BITS <= u64::BITS);
        }
        Sha256::new()
            .chain_update(b"aos.sandbox.delete.authorization-cut.v2\0")
            .chain_update(self.project)
            .chain_update(self.caller)
            .chain_update((self.input.len() as u64).to_be_bytes())
            .chain_update(self.input)
            .chain_update(self.revision)
            .chain_update(self.channel)
            .chain_update(self.capability_not_before.to_be_bytes())
            .chain_update(self.capability_expires.to_be_bytes())
            .chain_update(self.policy_not_before.to_be_bytes())
            .chain_update(self.policy_expires.to_be_bytes())
            .chain_update(self.authorized_wall.to_be_bytes())
            .finalize()
            .into()
    }
}

/// Commits a complete canonical Claim and its actual native boundary.
///
/// This does not decode or admit supplied Claim bytes. Genuine callers encode
/// their already validated Claim through the existing sole codec first.
#[must_use]
pub fn controller_cut_from_encoded_claim_data_v2(
    claim: &[u8; CLAIM_BYTES_V1],
    next: u64,
    end: u64,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.delete.controller-cut.v2\0")
        .chain_update(claim)
        .chain_update(next.to_be_bytes())
        .chain_update(end.to_be_bytes())
        .finalize()
        .into()
}

/// Commits the original exact176-byte protected authorization revision recipe.
///
/// The supplied capability is comparison DATA; this performs no live grant,
/// revocation, policy, TLS or protected time-floor admission.
#[must_use]
pub fn protected_authorization_revision_data_v2(
    capability: &CapabilityRecord,
    controller_generation: u64,
    policy_generation: u64,
    time_floor_generation: u64,
    time_floor_clock: RawPairedClockSample,
    time_floor_digest: &[u8; 32],
) -> AuthorizationRevisionDigestV1 {
    let claims = capability.claims();
    let mut exact_revision = [0_u8; 176];
    exact_revision[..16].copy_from_slice(claims.id.as_bytes());
    exact_revision[16..32].copy_from_slice(claims.revocation_scope.as_bytes());
    exact_revision[32..40].copy_from_slice(&claims.revocation_generation.get().to_be_bytes());
    exact_revision[40..72].copy_from_slice(claims.policy_digest.as_bytes());
    exact_revision[72..80].copy_from_slice(&controller_generation.to_be_bytes());
    exact_revision[80..88].copy_from_slice(&policy_generation.to_be_bytes());
    exact_revision[88..96].copy_from_slice(&time_floor_generation.to_be_bytes());
    exact_revision[96..112].copy_from_slice(&time_floor_clock.provenance().as_bytes());
    exact_revision[112..128].copy_from_slice(&time_floor_clock.host_boot_id());
    exact_revision[128..136].copy_from_slice(&time_floor_clock.wall_seconds().to_be_bytes());
    exact_revision[136..144]
        .copy_from_slice(&time_floor_clock.boottime_nanoseconds().to_be_bytes());
    exact_revision[144..].copy_from_slice(time_floor_digest);
    AuthorizationRevisionDigestV1::commit(&exact_revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_named_preimages_match_the_existing_v2_vectors() {
        let authorization = DeleteAuthorizationCutDataV2 {
            project: [1; 16],
            caller: [2; 16],
            input: b"request",
            revision: [3; 32],
            channel: [4; 32],
            capability_not_before: 10,
            capability_expires: 20,
            policy_not_before: 11,
            policy_expires: 19,
            authorized_wall: 12,
        };
        assert_eq!(
            authorization.digest_v2(),
            [
                0xc0, 0x3e, 0xdd, 0xcc, 0xc1, 0x0b, 0x57, 0x80, 0x8a, 0x75, 0xac, 0x5d, 0xfb, 0x38,
                0x2c, 0x36, 0x20, 0xf8, 0xa8, 0xa4, 0xee, 0xc1, 0x07, 0x3d, 0xbd, 0xf5, 0xed, 0x98,
                0x12, 0xae, 0xb7, 0x71
            ]
        );
        assert_eq!(
            controller_cut_from_encoded_claim_data_v2(&[7; CLAIM_BYTES_V1], 8, 9),
            [
                0x90, 0x3b, 0x9b, 0x4d, 0x79, 0xa7, 0x99, 0x74, 0xe5, 0x5d, 0xc7, 0xa1, 0xea, 0x7c,
                0x64, 0xd2, 0x52, 0x44, 0x18, 0xc0, 0x10, 0x06, 0xc9, 0xa4, 0xe2, 0x11, 0xb7, 0xa2,
                0xde, 0x55, 0x2a, 0x5e
            ]
        );
    }
}

/// Commits the whole actual authorized input for the original planning query.
///
/// This is a passive byte commitment, not a protected authorization decision.
#[must_use]
pub fn planning_authorized_input_cut_data_v2(input: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"aos.sandbox.delete.planning-authorized-input.v1\0")
        .chain_update(input).finalize().into()
}
