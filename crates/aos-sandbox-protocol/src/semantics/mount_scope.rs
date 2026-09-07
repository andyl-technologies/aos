//! Canonical Host authority for RootMount-only exact-scope acquisition.
//!
//! All integers use network byte order. A distinct domain and method prevent a
//! controller payload-observation grant from authorizing root/namespace export.
//!
//! ```text
//! domain || method:u16 || sandbox:16 || incarnation:16 || epoch:u64
//!        || desired:u64 || assignment_digest:32 || runtime_handle:32
//!        || payload_scope_handle:32 || audience:u16 || descriptor_count:u16
//!        || roles:[u16;5]
//! ```

use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
};

use super::host::HostSemanticError;
use crate::mount_scope::ValidatedMountScopeRequest;

const DOMAIN: &[u8] = b"aos.sandbox.host.mount-scope.v1\0";

/// Binds exact retained scope acquisition to a distinct signed HostObserve grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalMountScopeSemanticsV1 {
    commitment: BrokerArgumentCommitment,
    target: BrokerGrantTarget,
}

impl CanonicalMountScopeSemanticsV1 {
    /// Returns the exact signed argument commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the observation verb without authorizing any Mount effect.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        BrokerVerb::HostObserve
    }

    /// Returns the exact runtime resource target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Commits the complete exact-scope RootMount acquisition request.
///
/// # Errors
///
/// Rejects a runtime handle that cannot form a resource grant target.
pub fn canonical_mount_scope_semantics_v1(
    request: &ValidatedMountScopeRequest,
) -> Result<CanonicalMountScopeSemanticsV1, HostSemanticError> {
    let target = BrokerResourceHandle::from_bytes(*request.runtime_handle())
        .map_err(|_| HostSemanticError::InvalidTarget)?;

    let fence = request.fence();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 160);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&13_u16.to_be_bytes());

    bytes.extend_from_slice(fence.sandbox_id());
    bytes.extend_from_slice(fence.incarnation_id());
    bytes.extend_from_slice(&fence.assignment_epoch().to_be_bytes());
    bytes.extend_from_slice(&fence.desired_generation().to_be_bytes());
    bytes.extend_from_slice(fence.assignment_digest());

    bytes.extend_from_slice(request.runtime_handle());
    bytes.extend_from_slice(request.payload_scope_handle());

    bytes.extend_from_slice(&5_u16.to_be_bytes());
    bytes.extend_from_slice(&5_u16.to_be_bytes());
    for role in [8_u16, 9, 2, 1, 6] {
        bytes.extend_from_slice(&role.to_be_bytes());
    }

    Ok(CanonicalMountScopeSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
        target: BrokerGrantTarget::Resource(target),
    })
}
