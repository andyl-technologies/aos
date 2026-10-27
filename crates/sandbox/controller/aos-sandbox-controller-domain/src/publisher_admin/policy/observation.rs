//! Borrows validated Publisher rows through their genuine historical owner.
//!
//! The same canonical namespace and current-head recipes serve this finite
//! readonly borrower and the ordinary Journal store. Every protected check
//! dispatches to the actual owner at its original lookup frontier.

use super::*;
use crate::journal::historical_observation::HistoricalObservationV1;

/// Retains the actual immutable owner after complete namespace validation.
pub(crate) struct PublisherPolicyObservationV2<'read> {
    original: HistoricalObservationV1<'read>,
}

impl<'read> PublisherPolicyObservationV2<'read> {
    pub(crate) fn load_from_observation_v2(
        original: HistoricalObservationV1<'read>,
        limits: PublisherPolicyLimits,
    ) -> Result<Self, PublisherPolicyError> {
        original.ensure_protected_authority()?;
        validate_namespace(super::super::PublisherReadDataV2::from_state_v2(
            original.state_v1(),
        ), limits)?;
        Ok(Self { original })
    }

    pub(crate) fn current_policy(
        &self,
        project: ProjectId,
    ) -> Result<Option<PreparedPublisherPolicyRevisionV1>, PublisherPolicyError> {
        self.original.ensure_protected_authority()?;
        current_data::current_policy_from_data_v2(
            super::super::PublisherReadDataV2::from_state_v2(self.original.state_v1()), project,
        ).map_err(PublisherPolicyError::from)
    }

    pub(crate) fn project_revocation_head(
        &self,
        project: ProjectId,
    ) -> Result<Option<PublisherProjectRevocationHeadV1>, PublisherPolicyError> {
        self.original.ensure_protected_authority()?;
        let Some(scope) = current_data::project_revocation_scope_from_data_v2(
            super::super::PublisherReadDataV2::from_state_v2(self.original.state_v1()), project,
        ).map_err(PublisherPolicyError::from)? else {
            return Ok(None);
        };
        self.original.ensure_protected_authority()?;
        current_data::project_revocation_head_from_scope_data_v2(
            super::super::PublisherReadDataV2::from_state_v2(self.original.state_v1()), project, scope,
        ).map(Some).map_err(PublisherPolicyError::from)
    }

    pub(crate) fn project_cache_domain_head(
        &self,
        project: ProjectId,
    ) -> Result<Option<PublisherProjectCacheDomainHeadV1>, PublisherPolicyError> {
        self.original.ensure_protected_authority()?;
        current_data::project_cache_domain_head_from_data_v2(
            super::super::PublisherReadDataV2::from_state_v2(self.original.state_v1()), project,
        ).map_err(PublisherPolicyError::from)
    }
}

/// Prices the finite readonly borrower and its actual typed recipe interfaces.
pub(crate) fn publisher_observation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    use aos_sandbox_protocol::publisher_policy::PublisherPolicySchemaErrorV1 as DataError;
    type Data<'a> = super::super::PublisherReadDataV2<'a>;

    let load = size_of::<(HistoricalObservationV1<'_>, PublisherPolicyLimits)>().checked_mul(3)?
        .checked_add(size_of::<PublisherPolicyObservationV2<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<PublisherPolicyObservationV2<'_>, PublisherPolicyError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(usize, usize), DataError>>().checked_mul(3)?)?
        .checked_add(size_of::<(Data<'_>, PublisherPolicyLimits)>().checked_mul(3)?)?;

    let policy = size_of::<Result<Option<PreparedPublisherPolicyRevisionV1>, DataError>>().checked_mul(3)?
        .checked_add(size_of::<Result<Option<PreparedPublisherPolicyRevisionV1>, PublisherPolicyError>>().checked_mul(3)?)?;
    let revocation = size_of::<(Data<'_>, ProjectId, RevocationScopeId)>().checked_mul(3)?
        .checked_add(size_of::<Result<Option<RevocationScopeId>, DataError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Option<RevocationScopeId>, PublisherPolicyError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<PublisherProjectRevocationHeadV1, DataError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Option<PublisherProjectRevocationHeadV1>, DataError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Option<PublisherProjectRevocationHeadV1>, PublisherPolicyError>>().checked_mul(3)?)?;
    let cache = size_of::<Result<Option<PublisherProjectCacheDomainHeadV1>, DataError>>().checked_mul(3)?
        .checked_add(size_of::<Result<Option<PublisherProjectCacheDomainHeadV1>, PublisherPolicyError>>().checked_mul(3)?)?;

    // The validated borrower remains resident during every later query. Its
    // header is separate from the sequential constructor and query envelopes.
    size_of::<PublisherPolicyObservationV2<'_>>()
        .checked_add(load.max(policy.max(revocation).max(cache)))?
        .checked_add(size_of::<(&PublisherPolicyObservationV2<'_>, ProjectId)>().checked_mul(3)?)?
        .checked_add(size_of::<(Data<'_>, ProjectId)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), PublisherPolicyError>>().checked_mul(3)?)?
        .checked_add(size_of::<(DataError, PublisherPolicyError)>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
