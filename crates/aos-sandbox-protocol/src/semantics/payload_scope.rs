//! Canonical signed authority semantics for payload-scope descriptor acquisition.
//!
//! Fixed-width network-order fields bind the complete assignment, runtime
//! target, method, and returned descriptor roles. Response metadata and kernel
//! identities are deliberately absent: the broker observes them after admission.
//!
//! ```text
//! domain || method:u16 || sandbox:16 || incarnation:16 || epoch:u64
//!        || desired:u64 || assignment_digest:32 || runtime_handle:32
//!        || descriptor_count:u16 || roles:[u16;2]
//! ```

use super::host::HostSemanticError;
use crate::payload_scope::ValidatedPayloadScopeRequest;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
};

const DOMAIN: &[u8] = b"aos.sandbox.host.payload-scope.v1\0";

/// Binds one descriptor-acquisition request to an exact HostObserve grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalPayloadScopeSemanticsV1 {
    commitment: BrokerArgumentCommitment,
    target: BrokerGrantTarget,
}

impl CanonicalPayloadScopeSemanticsV1 {
    /// Returns the exact signed argument commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }
    /// Returns the separately granted observation verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        BrokerVerb::HostObserve
    }
    /// Returns the exact runtime-resource target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Commits the complete fixed payload-scope authority meaning.
///
/// # Errors
///
/// Returns an error if the runtime handle is not a valid resource target.
pub fn canonical_payload_scope_semantics_v1(
    request: &ValidatedPayloadScopeRequest,
) -> Result<CanonicalPayloadScopeSemanticsV1, HostSemanticError> {
    let target = BrokerResourceHandle::from_bytes(*request.runtime_handle())
        .map_err(|_| HostSemanticError::InvalidTarget)?;
    let fence = request.fence();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 120);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&12_u16.to_be_bytes());
    bytes.extend_from_slice(fence.sandbox_id());
    bytes.extend_from_slice(fence.incarnation_id());
    bytes.extend_from_slice(&fence.assignment_epoch().to_be_bytes());
    bytes.extend_from_slice(&fence.desired_generation().to_be_bytes());
    bytes.extend_from_slice(fence.assignment_digest());
    bytes.extend_from_slice(request.runtime_handle());
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&8_u16.to_be_bytes());
    bytes.extend_from_slice(&9_u16.to_be_bytes());
    Ok(CanonicalPayloadScopeSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
        target: BrokerGrantTarget::Resource(target),
    })
}
