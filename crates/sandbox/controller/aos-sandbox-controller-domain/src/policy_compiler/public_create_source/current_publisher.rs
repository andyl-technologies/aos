//! Shares current protected publisher, cache-domain and revocation DATA.
//!
//! Create and fresh Start keep separate accepted-operation/projection/native
//! validators. This private fold returns policy DATA only and cannot construct
//! either method's typed proof or select an admitted public operation.

use std::time::{SystemTime, UNIX_EPOCH};
use aos_sandbox_model::{ObjectDigest, ProjectId, RevocationScopeId};
use aos_sandbox_model::model::CacheDomain;
use crate::journal::historical_observation::HistoricalObservationV1;
use crate::publisher_admin::policy::{PublisherPolicyStore, PublisherPolicyLimits, PublisherPolicyError};

#[derive(Debug, thiserror::Error)]
pub(in crate::policy_compiler) enum CurrentPublisherPolicyDataErrorV2 {
    #[error("the current protected publisher policy differs or expired")]
    NotCurrent,
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
}

aos_sandbox_protocol::define_current_publisher_policy_data_model_v2!(CurrentPublisherPolicyDataV2, pub(in crate::policy_compiler));

pub(in crate::policy_compiler) fn current_publisher_policy_data_v2(
    journal: HistoricalObservationV1<'_>, project: ProjectId,
    requested_media_type: &str, requested_digest: &[u8], requested_bytes: u64,
    observed_wall: Option<i64>,
) -> Result<CurrentPublisherPolicyDataV2, CurrentPublisherPolicyDataErrorV2> {
    aos_sandbox_protocol::current_publisher_policy_data_recipe_v2!(
        rows = crate::publisher_admin::PublisherReadDataV2::from_state_v2(journal.state_v1()),
        project = project, requested_media_type = requested_media_type, requested_digest = requested_digest,
        requested_bytes = requested_bytes, observed_wall = observed_wall,
        protected = { journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?; },
        outputs = (policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, expires)
    );
    Ok(CurrentPublisherPolicyDataV2 { policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, expires })
}

impl From<aos_sandbox_protocol::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2>
    for CurrentPublisherPolicyDataErrorV2
{
    fn from(error: aos_sandbox_protocol::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2) -> Self {
        use aos_sandbox_protocol::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2 as DataError;
        match error {
            DataError::NotCurrent => Self::NotCurrent,
            DataError::Publisher(error) => Self::Publisher(error.into()),
        }
    }
}
