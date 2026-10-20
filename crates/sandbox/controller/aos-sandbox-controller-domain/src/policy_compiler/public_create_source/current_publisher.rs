//! Shares current protected publisher, cache-domain and revocation DATA.
//!
//! Create and fresh Start keep separate accepted-operation/projection/native
//! validators. This private fold returns policy DATA only and cannot construct
//! either method's typed proof or select an admitted public operation.

use std::time::{SystemTime, UNIX_EPOCH};
use aos_sandbox_model::{ObjectDigest, ProjectId, RevocationScopeId};
use aos_sandbox_model::model::CacheDomain;
use crate::Journal;
use crate::publisher_admin::policy::{PublisherPolicyStore, PublisherPolicyLimits, PublisherPolicyError};

#[derive(Debug, thiserror::Error)]
pub(in crate::policy_compiler) enum CurrentPublisherPolicyDataErrorV2 {
    #[error("the current protected publisher policy differs or expired")]
    NotCurrent,
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
}

pub(in crate::policy_compiler) struct CurrentPublisherPolicyDataV2 {
    pub(in crate::policy_compiler) policy_generation: u64,
    pub(in crate::policy_compiler) policy_digest: ObjectDigest,
    pub(in crate::policy_compiler) cache_domain: CacheDomain,
    pub(in crate::policy_compiler) cache_domain_head: ObjectDigest,
    pub(in crate::policy_compiler) revocation_scope: RevocationScopeId,
    pub(in crate::policy_compiler) revocation_generation: u64,
    pub(in crate::policy_compiler) revocation_head: ObjectDigest,
    pub(in crate::policy_compiler) canonical_policy: Vec<u8>,
    pub(in crate::policy_compiler) expires: i64,
}

pub(in crate::policy_compiler) fn current_publisher_policy_data_v2(
    journal: &mut Journal, project: ProjectId,
    requested_media_type: &str, requested_digest: &[u8], requested_bytes: u64,
    observed_wall: Option<i64>,
) -> Result<CurrentPublisherPolicyDataV2, CurrentPublisherPolicyDataErrorV2> {
    let publisher = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
    let revision = publisher
        .current_policy(project)?
        .ok_or(CurrentPublisherPolicyDataErrorV2::NotCurrent)?;
    let revocation = publisher
        .project_revocation_head(project)?
        .ok_or(CurrentPublisherPolicyDataErrorV2::NotCurrent)?;
    let cache_domain = publisher
        .project_cache_domain_head(project)?
        .ok_or(CurrentPublisherPolicyDataErrorV2::NotCurrent)?;
    let descriptor = revision.descriptor();
    if requested_media_type != descriptor.media_type().as_str()
        || requested_digest != descriptor.digest().as_bytes()
        || requested_bytes != descriptor.encoded_size()
    {
        return Err(CurrentPublisherPolicyDataErrorV2::NotCurrent);
    }
    let now = match observed_wall {
        Some(now) => now,
        None => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| CurrentPublisherPolicyDataErrorV2::NotCurrent)?;
            let now =
                i64::try_from(now.as_secs()).map_err(|_| CurrentPublisherPolicyDataErrorV2::NotCurrent)?;
            now
        }
    };
    if now < revision.not_before() || now >= revision.expires_at() {
        return Err(CurrentPublisherPolicyDataErrorV2::NotCurrent);
    }

    let policy_generation = revision.generation();
    let policy_digest = descriptor.digest();
    let cache_domain_head = cache_domain.digest();
    let cache_domain = cache_domain.domain();
    let revocation_scope = revocation.scope();
    let revocation_generation = revocation.generation();
    let revocation_head = revocation.digest();
    let canonical_policy = revision.canonical_policy().to_vec();
    let expires = revision.expires_at();
    Ok(CurrentPublisherPolicyDataV2 {
        policy_generation, policy_digest, cache_domain, cache_domain_head,
        revocation_scope, revocation_generation, revocation_head, canonical_policy, expires,
    })
}
