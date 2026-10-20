//! Normalizes the separate unsigned Storage workspace plan at Root.
//!
//! These results are comparison DATA only. The actual fresh Apply flight must
//! independently authenticate the parent Create, stored Prepare/catalog,
//! Controller/Session prefixes, Source/Cache samples, current compiler and
//! original horizon before it may invoke this purpose-specific recipe. No
//! earlier Prepare signature or Root8 borrower grants Apply authority.

use std::error::Error;
use aos_sandbox_model::{BrokerAuthorizationPlan, BrokerPlanTrustAnchor, RawPairedClockSample};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_policy::CompiledPolicyCandidateV1;
use aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation;
use aos_sandbox_protocol::semantics::ProtectedStorageCreateApplyDataV1;

pub(crate) struct RootProspectiveStorageApplyPlanV1 {
    plan: BrokerAuthorizationPlan,
    preparation: BrokerPlanPreparation,
    anchor: BrokerPlanTrustAnchor,
    signature_shape: Vec<u8>,
    request_shape: Vec<u8>,
    trust_policy_length: usize,
}

impl RootProspectiveStorageApplyPlanV1 {
    pub(crate) fn plan_data_v1(&self) -> &BrokerAuthorizationPlan { &self.plan }

    pub(crate) fn preparation_data_v1(&self) -> &BrokerPlanPreparation { &self.preparation }

    pub(crate) fn anchor_v1(&self) -> &BrokerPlanTrustAnchor { &self.anchor }

    pub(crate) fn signature_maximum_bytes_v1(&self) -> usize { self.signature_shape.len() }

    pub(crate) fn request_body_maximum_bytes_v1(&self) -> usize { self.request_shape.len() }

    pub(crate) fn trust_policy_length_v1(&self) -> usize { self.trust_policy_length }

    pub(in crate::policy_compiler) fn prepare_once(
        public: (&[u8], &[u8], &[u8]),
        protected: &ProtectedStorageCreateApplyDataV1<'_>,
        candidate: &CompiledPolicyCandidateV1,
        lease: &SignedOwnershipLease,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<Self, Box<dyn Error>> {
        let trust = super::public_trust::RootBrokerPlanPublicTrustDataV1::from_fixed_public_data_v1(public)?;
        let prepared = aos_sandbox_protocol::authorization_artifact::prepare_storage_create_apply_plan_v1(
            protected, candidate.portable().policy_descriptor().digest(), lease,
            sample, cutoff, policy_expires, trust.authority, trust.revocation_scope,
        ).map_err(|cause| cause as Box<dyn Error>)?;
        Ok(Self {
            plan: prepared.plan,
            preparation: prepared.preparation,
            anchor: trust.anchor,
            signature_shape: prepared.signature_shape,
            request_shape: prepared.request_shape,
            trust_policy_length: trust.policy_length,
        })
    }
}
