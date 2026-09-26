//! Exact project cache-domain binding against the current publisher policy.
//!
//! The policy compiler supplies canonical binding bytes. This verifier
//! reconstructs the sole publisher-owned project binding from a protected
//! current revision while its journal remains borrowed by the caller.

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::{MediaType, ObjectDescriptor, PortableMediaType, ProjectId};

use crate::policy_compiler::{CacheDomainBindingV1, CacheDomainVerifierV1};

use super::PublisherPolicyStore;

const BINDING_DOMAIN: &[u8] = b"aos.sandbox.cache-domain-binding.v2";

/// Verifies the exact current project binding held by a protected publisher journal.
///
/// Private and trust-domain disclosure require different owners and always fail
/// through this verifier. A caller needing an atomic cross-owner decision must
/// keep the publisher journal claim through that decision.
pub struct PublisherProjectCacheDomainVerifierV1<'store, 'journal> {
    store: &'store PublisherPolicyStore<'journal>,
    project: ProjectId,
}

impl<'store, 'journal> PublisherProjectCacheDomainVerifierV1<'store, 'journal> {
    /// Binds verification to one project under the caller's protected journal claim.
    #[must_use]
    pub const fn new(store: &'store PublisherPolicyStore<'journal>, project: ProjectId) -> Self {
        Self { store, project }
    }
}

impl CacheDomainVerifierV1 for PublisherProjectCacheDomainVerifierV1<'_, '_> {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool {
        let Ok(Some(head)) = self.store.project_cache_domain_head(self.project) else {
            return false;
        };
        let Ok(payload) =
            serde_json::to_vec(&(head.domain(), CacheDomainBindingV1::Project(self.project)))
        else {
            return false;
        };

        // Match the compiler's length-prefixed canonical object encoding. The
        // value is constructed from fixed protected identities, never parsed
        // from caller-supplied bytes.
        let mut expected = Vec::with_capacity(16 + BINDING_DOMAIN.len() + payload.len());
        expected.extend_from_slice(&(BINDING_DOMAIN.len() as u64).to_be_bytes());
        expected.extend_from_slice(BINDING_DOMAIN);
        expected.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        expected.extend_from_slice(&payload);
        if canonical_bytes != expected.as_slice() {
            return false;
        }

        let Ok(media_type) = MediaType::new(PortableMediaType::Content.as_str()) else {
            return false;
        };
        descriptor_for_bytes(media_type, &expected) == *descriptor
    }
}
