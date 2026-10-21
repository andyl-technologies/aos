//! Compares exact current Publisher policy rows without admitting a store.
//!
//! Native protected/currentness checks stay at the original ordinary callers;
//! these same codecs also compare Root's independently read native prefix.

use super::*;
/// Joins the current project head to its exact canonical revision and resources.
///
/// # Errors
///
/// Rejects a malformed or dangling head, differing project/generation/digest or invalid resource binding.

pub fn current_policy_from_data_v2(
    records: PublisherReadDataV2<'_>,
    project: ProjectId,
) -> Result<Option<PreparedPublisherPolicyRevisionV1>, PublisherPolicyError> {
    let Some(head_bytes) = records.get(
        RecordNamespace::PublisherPolicy,
        &policy_current_key(project),
    ) else {
        return Ok(None);
    };
    let head = decode_policy_head(head_bytes)?;
    if head.project != project {
        return Err(PublisherPolicyError::CorruptState);
    }
    let bytes = records
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_revision_key(project, head.generation),
        )
        .ok_or(PublisherPolicyError::CorruptState)?;
    let revision = decode_policy_revision(bytes)?;
    if revision.project() != project
        || revision.generation() != head.generation
        || revision.descriptor().digest() != head.digest
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    replay::validate_policy_resources_from_data_v2(records, &revision)?;
    Ok(Some(revision))
}
/// Decodes the retained current controller head when present.
///
/// # Errors
///
/// Rejects a malformed controller head.

pub fn controller_head_from_data_v2(
    records: PublisherReadDataV2<'_>,
) -> Result<Option<PublisherControllerHeadV1>, PublisherPolicyError> {
    records
        .get(RecordNamespace::PublisherPolicy, CONTROLLER_CURRENT_KEY)
        .map(|bytes| decode_controller(bytes, CONTROLLER_CURRENT_MAGIC))
        .transpose()
}
/// Decodes the current head for the supplied revocation scope when present.
///
/// # Errors
///
/// Rejects a malformed head or a head naming another scope.

pub fn revocation_head_from_data_v2(
    records: PublisherReadDataV2<'_>,
    scope: RevocationScopeId,
) -> Result<Option<PublisherRevocationHeadV1>, PublisherPolicyError> {
    let head = records
        .get(
            RecordNamespace::PublisherPolicy,
            &revocation_current_key(scope),
        )
        .map(|bytes| decode_revocation(bytes, REVOCATION_CURRENT_MAGIC))
        .transpose()?;
    if head.as_ref().is_some_and(|value| value.scope != scope) {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(head)
}

/// Resolves only a project's immutable revocation-scope binding.
///
/// The genuine caller repeats its protected-owner check after this selection
/// and before resolving the current scope head. Neither step grants authority.
///
/// # Errors
/// Rejects malformed binding bytes or a binding naming another project.
pub fn project_revocation_scope_from_data_v2(
    records: PublisherReadDataV2<'_>,
    project: ProjectId,
) -> Result<Option<RevocationScopeId>, PublisherPolicyError> {
    let Some(bytes) = records.get(
        RecordNamespace::PublisherPolicy,
        &project_revocation_key(project),
    ) else {
        return Ok(None);
    };
    let (bound_project, scope) = decode_project_revocation_binding(bytes)?;
    if bound_project != project {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(Some(scope))
}

/// Derives a project head from its selected scope and actual current rows.
///
/// The scope is comparison DATA. A genuine caller independently owns its
/// protected checks and keeps the same rows borrowed across both selections.
///
/// # Errors
/// Rejects a malformed, substituted or missing current revocation head.
pub fn project_revocation_head_from_scope_data_v2(
    records: PublisherReadDataV2<'_>,
    project: ProjectId,
    scope: RevocationScopeId,
) -> Result<PublisherProjectRevocationHeadV1, PublisherPolicyError> {
    let head = revocation_head_from_data_v2(records, scope)?
        .ok_or(PublisherPolicyError::CorruptState)?;
    let digest = project_revocation_digest(project, scope, head.generation);
    Ok(PublisherProjectRevocationHeadV1 {
        project,
        scope,
        generation: head.generation,
        digest,
    })
}

/// Derives the disclosure head of the actual current project policy.
///
/// # Errors
/// Rejects malformed current-policy state or a disclosure domain that does not
/// name this exact project. Absence remains nonauthorizing historical DATA.
pub fn project_cache_domain_head_from_data_v2(
    records: PublisherReadDataV2<'_>,
    project: ProjectId,
) -> Result<Option<PublisherProjectCacheDomainHeadV1>, PublisherPolicyError> {
    let Some(policy) = current_policy_from_data_v2(records, project)? else {
        return Ok(None);
    };
    let domain = policy.policy().cache_domain();
    if domain.kind() != CacheDomainKind::Project
        || domain.domain_id().as_bytes() != project.as_bytes()
    {
        return Err(PublisherPolicyError::InvalidProjectCacheDomainBinding);
    }
    let policy_digest = policy.descriptor().digest();
    let digest = project_cache_domain_digest(project, policy.generation(), policy_digest, domain);
    Ok(Some(PublisherProjectCacheDomainHeadV1 {
        project,
        generation: policy.generation(),
        policy_digest,
        domain,
        digest,
    }))
}
