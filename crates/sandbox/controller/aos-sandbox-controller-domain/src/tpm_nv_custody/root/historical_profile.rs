//! Private shape DATA for independently checked historical Root comparisons.
//!
//! These declarations preserve the original verifier's comparison fields.
//! They neither load provisioned pins nor select a live production profile;
//! no constructor, credential loader or current-floor owner is exposed here.

use super::super::NvCustodyEndpointV1;

/// Scalar format claims are private and never construct a live floor token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PurposeProfileV1 {
    pub(super) endpoint: NvCustodyEndpointV1,
    pub(super) node: [u8; 16],
    pub(super) epoch: [u8; 16],
    pub(super) stable_endpoint: [u8; 32],
    pub(super) domain_binding: [u8; 32],
    pub(super) nv_name: [u8; 34],
    pub(super) salt_name: [u8; 34],
    pub(super) genesis: [u8; 32],
    pub(super) role_pins: Option<[[u8; 32]; 3]>,
    pub(super) scope: [u8; 32],
}

/// Retains exact fixed public role observations, never a live-floor permit.
pub(super) struct RootRolePinsV1 {
    pub(super) keys: [[u8; 32]; 3],
    pub(super) assignments: [[u8; 32]; 3],
    pub(super) digests: [[u8; 32]; 3],
}
