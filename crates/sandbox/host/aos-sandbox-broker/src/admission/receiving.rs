//! Passive representation of the existing signed admission engine.
//!
//! This module reads only held artifact extents and protected anchor layouts.
//! The caller pays the returned DATA through its genuine role receiver before
//! entering ordinary admission; neither this supplier nor its inputs grant IO.

use aos_sandbox_model::format::{authorization_capture, canonical_validation_receiving_memory_v4};
use aos_sandbox_model::{AccountingError, ResourceDimension, ResourceVector};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::{BrokerAuthority, VerifiedBrokerAdmission, artifact_limits};

impl BrokerAuthority {
    /// Bounds signed admission against these actual artifacts and pinned anchors.
    ///
    /// Includes both detached signature decoders, plan/lease constructors,
    /// protected-policy verification, signature messages and admission return
    /// carriers. Packet ownership and audience-specific semantics are priced by
    /// their existing receiving owners. No parser or encoder runs here.
    ///
    /// # Errors
    /// Returns a Memory arithmetic error when compiled layout arithmetic wraps.
    pub fn signed_admission_receiving_demand_v4(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    ) -> Result<ResourceVector, AccountingError> {
        public_verification_receiving_demand_v2(&self.plan_anchor, &self.lease_anchor, artifacts)
    }
}

pub(super) fn public_verification_receiving_demand_v2(
    plan_anchor: &aos_sandbox_model::BrokerPlanTrustAnchor,
    lease_anchor: &aos_sandbox_model::OwnershipLeaseTrustAnchor,
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
) -> Result<ResourceVector, AccountingError> {
    use std::mem::size_of;
    let overflow = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MemoryBytes,
    };
    let plan = artifacts.broker_plan().len();
    let plan_signature = artifacts.broker_plan_signature().len();
    let lease = artifacts.ownership_lease().len();
    let lease_signature = artifacts.ownership_lease_signature().len();
    let plan_pair = plan.checked_add(plan_signature).ok_or_else(overflow)?;
    let lease_pair = lease.checked_add(lease_signature).ok_or_else(overflow)?;

    // Immediate delegation preserves the canonical decoder's aggregate
    // grant/feature bounds and the actual protected policy's vector/text
    // layout. The lease verifier supplier includes its two signature lanes;
    // retaining that complete shared bound avoids guessing a smaller crypto
    // capture from a different caller's disposition.
    let plan_bytes = plan_anchor
        .verification_receiving_bytes_v1(plan_pair)
        .ok_or_else(overflow)?;
    let lease_verification =
        aos_sandbox_model::ownership_lease::retained::verification_dynamic_bytes_v2(
            lease_anchor,
            lease_pair,
        )
        .ok_or_else(overflow)?;
    let lease_models = usize::try_from(
        authorization_capture::authorization_artifact_dynamic_footprint_v1(lease_pair)
            .ok_or_else(overflow)?
            .0,
    )
    .map_err(|_| overflow())?;
    let mut memory = plan_bytes
        .checked_add(lease_verification)
        .and_then(|bytes| bytes.checked_add(lease_models))
        .and_then(|bytes| bytes.checked_add(size_of::<VerifiedBrokerAdmission>().checked_mul(2)?))
        .and_then(|bytes| {
            bytes.checked_add(
                size_of::<authorization_capture::SignatureDecodeCaptureV1>().checked_mul(4)?,
            )
        })
        .ok_or_else(overflow)?;

    let plan_limit = super::MAXIMUM_BROKER_PLAN_BYTES;
    let signature_limit = super::MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES;
    let lease_limit = super::MAXIMUM_OWNERSHIP_LEASE_BYTES;
    for (bytes, limit) in [
        (plan, plan_limit),
        (plan_signature, signature_limit),
        (lease, lease_limit),
        (lease_signature, signature_limit),
    ] {
        memory = memory
            .checked_add(
                canonical_validation_receiving_memory_v4(bytes, artifact_limits(limit))
                    .ok_or_else(overflow)?,
            )
            .ok_or_else(overflow)?;
    }
    // Both protected policies use the same actual admission limits. Their
    // complete decoded backing is supplied by the anchors above; their
    // recursive validator frames are bounded by that engine's depth limit,
    // independent of unknown private policy bytes. This grants no access to
    // the policies and does not count Rust fields as durable metadata.
    for limit in [plan_limit, lease_limit] {
        memory = memory
            .checked_add(
                canonical_validation_receiving_memory_v4(limit, artifact_limits(limit))
                    .ok_or_else(overflow)?,
            )
            .ok_or_else(overflow)?;
    }
    Ok(ResourceVector::ZERO.with(
        ResourceDimension::MemoryBytes,
        u64::try_from(memory).map_err(|_| overflow())?,
    ))
}
