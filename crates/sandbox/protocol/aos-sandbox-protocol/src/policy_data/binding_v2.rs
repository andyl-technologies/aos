//! Owns canonical Root binding-chain, hold and qualified-proof DATA.
//!
//! These existing wire/row codecs validate comparison DATA only. Actual native
//! Authority owns its complete protected rows, admission, currentness and
//! independently owed posts. No decoded head, hold or proof adopts a writer,
//! grants publication, authorizes an effect or permits release.

#[cfg(test)]
mod tests;

mod chain;
mod hold;
mod proof;
mod record;

pub use chain::{
    RootBindingChainDataV2, current_hold_v1, current_root_binding_chain_v2,
    root_binding_chain_receiving_bytes_v2,
};
pub use hold::RootBindingHoldV1;
pub use proof::{PROOF_KEY_PREFIX, RootQualifiedProofV1, proof_key};
pub use record::{
    BINDING_V2_BODY_BYTES, BINDING_V2_CHECKSUM_DOMAIN, CLOSED_POLICY_BINDING_BYTES_V2,
    ClosedCreateProposalFieldViewV2, ClosedPolicyRootBindingV2, closed_policy_binding_digest_v2,
    decode_closed_policy_binding_v2,
};

/// Preserves the existing fixed malformed/unauthenticated comparison category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the Root binding comparison DATA is malformed or inconsistent")]
pub enum BindingDataErrorV1 {
    /// The original canonical record or complete chain comparison refused.
    UnauthenticatedCandidate,
}

/// Names the existing canonical binding row prefix.
pub const BINDING_V2_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v2\0";
/// Names the original retired binding prefix, denied by the closed chain.
pub const POLICY_BINDING_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v1\0";
/// Names the original closed-binding head pointer.
pub const ROOT_BINDING_HEAD_KEY: &[u8] = b"\0aos-policy-compiler-binding-head-v2\0";
/// Names the original held/released row.
pub const HOLD_KEY: &[u8] = b"\0aos-policy-compiler-binding-hold-v1\0";
/// Names the retired ACK row denied by complete chain validation.
pub const RETIRED_EFFECT_ACK_KEY: &[u8] = b"\0aos-policy-compiler-root-effect-ack-v1\0";
/// Names the retired challenge row denied by complete chain validation.
pub const RETIRED_EFFECT_CHALLENGE_KEY: &[u8] =
    b"\0aos-policy-compiler-root-effect-ack-challenge-v1\0";
/// Retains the original maximum number of closed binding records.
pub const MAXIMUM_POLICY_BINDINGS: usize = 4_096;

/// Derives the existing issuer comparison identifier from actual selected IDs.
///
/// The UID/GID and returned bytes are DATA. Native Authority independently
/// authenticates the original selected identity; this hash grants no role.
#[must_use]
pub fn root_policy_issuer_owner_v2(controller_uid: u32, controller_gid: u32) -> [u8; 16] {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.policy-controller-owner.v2\0")
        .chain_update(controller_uid.to_be_bytes())
        .chain_update(controller_gid.to_be_bytes())
        .finalize();
    let mut issuer_owner = [0; 16];
    issuer_owner.copy_from_slice(&digest[..16]);
    issuer_owner
}
