//! Compares exact current Publisher policy rows without admitting a store.
//!
//! Native protected/currentness checks stay at the original ordinary callers;
//! these same codecs also compare Root's independently read native prefix.

use super::*;

pub(crate) fn current_policy_from_data_v2(
    records: super::super::PublisherReadDataV2<'_>,
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

pub(crate) fn controller_head_from_data_v2(
    records: super::super::PublisherReadDataV2<'_>,
) -> Result<Option<PublisherControllerHeadV1>, PublisherPolicyError> {
    records
        .get(RecordNamespace::PublisherPolicy, CONTROLLER_CURRENT_KEY)
        .map(|bytes| decode_controller(bytes, CONTROLLER_CURRENT_MAGIC))
        .transpose()
}

pub(crate) fn revocation_head_from_data_v2(
    records: super::super::PublisherReadDataV2<'_>,
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
