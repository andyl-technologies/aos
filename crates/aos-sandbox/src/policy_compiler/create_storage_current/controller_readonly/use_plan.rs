//! Derives Root's prospective unsigned Prepare plan from its current originals.
//!
//! Public broker-plan trust comes only from Root's fixed local files. A zero
//! signature and fixed request ID are used solely for nonissuing byte sizing;
//! no SignedBrokerPlan, authenticated request or resource loan is constructed.

use std::error::Error;
use aos_sandbox_core::{BrokerAuthorizationPlan, BrokerPlanTrustAnchor,
    RawPairedClockSample};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_policy::CompiledPolicyCandidateV1;
use aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation;
use aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1;

type Result<T> = std::result::Result<T, Box<dyn Error>>;


pub(crate) struct RootProspectiveStorageUsePlanV1 {
    pub(super) plan: BrokerAuthorizationPlan,
    pub(super) preparation: BrokerPlanPreparation,
    pub(super) anchor: BrokerPlanTrustAnchor,
    pub(super) signature_shape: Vec<u8>,
    pub(super) request_shape: Vec<u8>,
    trust_policy_length: usize,
}

impl RootProspectiveStorageUsePlanV1 {
    pub(crate) fn plan_data_v1(&self) -> &BrokerAuthorizationPlan { &self.plan }

    pub(crate) fn request_shape_bytes_v1(&self) -> usize { self.request_shape.len() }

    // The separate normalized-time zero-signature envelope is sizing DATA.
    // A real signature over the original prepared statement cannot exceed it.
    pub(crate) fn trust_policy_length_v1(&self) -> usize { self.trust_policy_length }

    pub(crate) fn signature_maximum_bytes_v1(&self) -> usize { self.signature_shape.len() }

    pub(crate) fn request_body_maximum_bytes_v1(&self) -> usize { self.request_shape.len() }

    pub(crate) fn preparation_data_v1(&self) -> &BrokerPlanPreparation { &self.preparation }

    pub(crate) fn anchor_v1(&self) -> &BrokerPlanTrustAnchor { &self.anchor }

    pub(super) fn prepare_once(
        public: (&[u8], &[u8], &[u8]),
        protected: &ProtectedStorageCreatePreparationV1,
        candidate: &CompiledPolicyCandidateV1,
        lease: &SignedOwnershipLease,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<Self> {
        let trust = super::public_trust::RootBrokerPlanPublicTrustDataV1::from_fixed_public_data_v1(public)?;
        let prepared = aos_sandbox_protocol::authorization_artifact::prepare_storage_create_plan_v1(
            protected, candidate.portable().policy_descriptor().digest(), lease,
            sample, cutoff, policy_expires, trust.authority, trust.revocation_scope,
        ).map_err(|cause| cause as Box<dyn Error>)?;
        Ok(Self { plan: prepared.plan, preparation: prepared.preparation, anchor: trust.anchor,
            signature_shape: prepared.signature_shape, request_shape: prepared.request_shape,
            trust_policy_length: trust.policy_length })
    }
}
