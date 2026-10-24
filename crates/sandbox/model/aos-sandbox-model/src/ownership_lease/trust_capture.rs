//! Keeps protected-configuration DATA during the shared trust-anchor checks.

use super::*;
use crate::format::{TrustPolicyDecodeCaptureV1, decode_trust_policy_retaining_v1};
use crate::model::TrustPolicy;
use std::mem::size_of;

/// Reports an unavailable retained anchor without moving its original error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained ownership trust anchor construction is closed")]
pub struct OwnershipLeaseTrustAnchorClosedV1;

/// Retains the raw, parsed and descriptor prefixes of one anchor construction.
#[must_use = "retain this destination beside the genuine protected credential owner"]
pub struct OwnershipLeaseTrustAnchorConstructionV1 {
    canonical: Option<Vec<u8>>,
    descriptor: Option<ObjectDescriptor>,
    scope: Option<TrustScopeId>,
    authority: Option<KeyReference>,
    public_key: Option<[u8; 32]>,
    parser: TrustPolicyDecodeCaptureV1,
    policy: Option<TrustPolicy>,
    computed: Option<ObjectDescriptor>,
    anchor: Option<OwnershipLeaseTrustAnchor>,
    completion: Option<Result<(), OwnershipLeaseVerificationError>>,
    entered: bool,
    closed: bool,
    taken: bool,
}

impl OwnershipLeaseTrustAnchorConstructionV1 {
    /// Creates an inert owner without parsing or authenticating input DATA.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            canonical: None,
            descriptor: None,
            scope: None,
            authority: None,
            public_key: None,
            parser: TrustPolicyDecodeCaptureV1::new(),
            policy: None,
            computed: None,
            anchor: None,
            completion: None,
            entered: false,
            closed: false,
            taken: false,
        }
    }

    /// Borrows the actual canonical decoder cause before a coarser anchor error.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.parser.cause()
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }

    /// Moves a fully checked anchor once, preserving every failed prefix.
    #[must_use]
    pub fn take_anchor_once(&mut self) -> Option<OwnershipLeaseTrustAnchor> {
        if self.taken || self.closed || !matches!(self.completion, Some(Ok(()))) {
            return None;
        }
        self.taken = true;
        self.anchor.take()
    }

    /// Bounds the concrete construction and resident inline representations.
    #[must_use]
    pub const fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)
    }

    /// Counts this owner's fixed destinations, excluding nested parser entries.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize { 13 }

    pub(super) fn construct_once(
        &mut self, canonical: Vec<u8>, descriptor: ObjectDescriptor,
        scope: TrustScopeId, authority: KeyReference, public_key: [u8; 32], limits: DecodeLimits,
    ) -> Result<(), OwnershipLeaseTrustAnchorClosedV1> {
        if self.entered {
            self.closed = true;
            return Err(OwnershipLeaseTrustAnchorClosedV1);
        }
        self.entered = true;
        self.canonical = Some(canonical);
        self.descriptor = Some(descriptor);
        self.scope = Some(scope);
        self.authority = Some(authority);
        self.public_key = Some(public_key);
        self.completion = Some(match construct(self, limits, true) {
            Ok(anchor) => {
                self.anchor = Some(anchor);
                Ok(())
            }
            Err(cause) => Err(cause),
        });
        if matches!(self.completion, Some(Ok(()))) { Ok(()) }
        else { Err(OwnershipLeaseTrustAnchorClosedV1) }
    }
}

impl Default for OwnershipLeaseTrustAnchorConstructionV1 {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn ordinary(
    canonical: Vec<u8>, descriptor: ObjectDescriptor, scope: TrustScopeId,
    authority: KeyReference, public_key: [u8; 32], limits: DecodeLimits,
) -> Result<OwnershipLeaseTrustAnchor, OwnershipLeaseVerificationError> {
    let mut work = OwnershipLeaseTrustAnchorConstructionV1::new();
    work.canonical = Some(canonical);
    work.descriptor = Some(descriptor);
    work.scope = Some(scope);
    work.authority = Some(authority);
    work.public_key = Some(public_key);
    construct(&mut work, limits, false)
}

fn construct(
    work: &mut OwnershipLeaseTrustAnchorConstructionV1,
    limits: DecodeLimits, retained: bool,
) -> Result<OwnershipLeaseTrustAnchor, OwnershipLeaseVerificationError> {
    use sha2::{Digest as _, Sha256};
    let invalid = || OwnershipLeaseVerificationError::InvalidTrustAnchor;
    let canonical = work.canonical.as_ref().ok_or_else(invalid)?;
    work.policy = Some(if retained {
        decode_trust_policy_retaining_v1(canonical, limits, &mut work.parser)
            .map_err(|_| invalid())?;
        work.parser.take_policy_once().ok_or_else(invalid)?
    } else {
        decode_trust_policy(canonical, limits)?
    });
    let policy = work.policy.as_ref().ok_or_else(invalid)?;
    crate::validate_required_features(policy.required_features())?;
    let descriptor = work.descriptor.as_ref().ok_or_else(invalid)?;
    crate::validate_descriptor_role(crate::DescriptorRole::SignatureVerificationPolicy, descriptor)?;
    work.computed = Some(descriptor_for_bytes(descriptor.media_type().clone(), canonical));
    let authority = work.authority.as_ref().ok_or_else(invalid)?;
    let public_key = work.public_key.ok_or_else(invalid)?;
    if work.computed.as_ref() != Some(descriptor)
        || Some(policy.trust_scope()) != work.scope
        || policy.purpose() != SignaturePurpose::OwnershipLease
        || !policy.allowed_keys().contains(authority)
        || authority.usage() != KeyUsage::OwnershipLease
        || authority.generation() == 0
        || authority.public_key_sha256() != ObjectDigest::from_bytes(Sha256::digest(public_key).into())
    {
        return Err(invalid());
    }
    Ok(OwnershipLeaseTrustAnchor {
        canonical_policy: work.canonical.take().ok_or_else(invalid)?,
        policy_descriptor: work.descriptor.take().ok_or_else(invalid)?,
        trust_scope: work.scope.ok_or_else(invalid)?,
        authority: work.authority.take().ok_or_else(invalid)?,
        public_key,
    })
}

#[cfg(test)]
mod tests;
