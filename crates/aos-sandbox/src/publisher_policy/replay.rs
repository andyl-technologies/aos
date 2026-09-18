//! Whole-namespace replay and authority cross-link validation.

use std::collections::BTreeMap;

use super::*;

pub(super) fn validate_policy_resources(
    journal: &Journal,
    policy: &PreparedPublisherPolicyRevisionV1,
) -> Result<(), PublisherPolicyError> {
    // Publisher-policy v1 admits cache publication only for one explicitly
    // bound logical resource. Broader path, tree, or profile selectors cannot
    // establish the immutable project/domain cross-link and fail closed.
    for grant in policy.policy.effective_grants() {
        if grant.resource_kind() == ResourceKind::CachePublish
            && grant.operations().contains(Operation::Publish)
        {
            let aos_sandbox_core::Selector::Resource { resource } = grant.selector() else {
                return Err(PublisherPolicyError::ResourcePolicyMismatch);
            };
            let bytes = journal
                .get(RecordNamespace::PublisherPolicy, &resource_key(*resource))
                .ok_or(PublisherPolicyError::ResourcePolicyMismatch)?;
            let binding = decode_resource(bytes)?;
            if binding.project != policy.project
                || binding.cache_domain != policy.policy.cache_domain()
            {
                return Err(PublisherPolicyError::ResourcePolicyMismatch);
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct Chain {
    count: u64,
    max: u64,
}
fn add_chain(chain: &mut Chain, generation: u64) -> Result<(), PublisherPolicyError> {
    if generation == 0 {
        return Err(PublisherPolicyError::CorruptState);
    }
    chain.count = chain
        .count
        .checked_add(1)
        .ok_or(PublisherPolicyError::CorruptState)?;
    chain.max = chain.max.max(generation);
    Ok(())
}

pub(super) fn validate_namespace(
    journal: &Journal,
    limits: PublisherPolicyLimits,
) -> Result<(usize, usize), PublisherPolicyError> {
    let mut records = 0usize;
    let mut total = 0usize;
    let mut policies: BTreeMap<ProjectId, Chain> = BTreeMap::new();
    let mut heads: BTreeMap<ProjectId, PolicyHead> = BTreeMap::new();
    let mut controller = Chain::default();
    let mut controller_principal = None;
    let mut controller_head = None;
    let mut revocations: BTreeMap<RevocationScopeId, Chain> = BTreeMap::new();
    let mut revocation_heads: BTreeMap<RevocationScopeId, u64> = BTreeMap::new();
    for (key, value) in journal.records(RecordNamespace::PublisherPolicy) {
        records = records
            .checked_add(1)
            .ok_or(PublisherPolicyError::LimitExceeded("record count"))?;
        if records > limits.maximum_records || value.len() > limits.maximum_record_bytes {
            return Err(PublisherPolicyError::LimitExceeded("record"));
        }
        total = total
            .checked_add(key.len() + value.len())
            .ok_or(PublisherPolicyError::LimitExceeded("materialized bytes"))?;
        if total > limits.maximum_materialized_bytes {
            return Err(PublisherPolicyError::LimitExceeded("materialized bytes"));
        }
        if key.starts_with(POLICY_REVISION_PREFIX) && key.len() == POLICY_REVISION_PREFIX.len() + 24
        {
            let revision = decode_policy_revision(value)?;
            if key != policy_revision_key(revision.project, revision.generation) {
                return Err(PublisherPolicyError::CorruptState);
            }
            validate_policy_resources(journal, &revision)
                .map_err(|_| PublisherPolicyError::CorruptState)?;
            add_chain(
                policies.entry(revision.project).or_default(),
                revision.generation,
            )?;
        } else if key.starts_with(POLICY_CURRENT_PREFIX)
            && key.len() == POLICY_CURRENT_PREFIX.len() + 16
        {
            let head = decode_policy_head(value)?;
            if key != policy_current_key(head.project) || heads.insert(head.project, head).is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if key.starts_with(RESOURCE_PREFIX) && key.len() == RESOURCE_PREFIX.len() + 16 {
            let binding = decode_resource(value)?;
            if key != resource_key(binding.resource) {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if key.starts_with(CONTROLLER_REVISION_PREFIX)
            && key.len() == CONTROLLER_REVISION_PREFIX.len() + 8
        {
            let revision = decode_controller(value, CONTROLLER_REVISION_MAGIC)?;
            if key != controller_revision_key(revision.generation)
                || controller_principal.is_some_and(|p| p != revision.principal)
            {
                return Err(PublisherPolicyError::CorruptState);
            }
            controller_principal = Some(revision.principal);
            add_chain(&mut controller, revision.generation)?;
        } else if key == CONTROLLER_CURRENT_KEY {
            if controller_head
                .replace(decode_controller(value, CONTROLLER_CURRENT_MAGIC)?)
                .is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if key.starts_with(REVOCATION_REVISION_PREFIX)
            && key.len() == REVOCATION_REVISION_PREFIX.len() + 24
        {
            let revision = decode_revocation(value, REVOCATION_REVISION_MAGIC)?;
            if key != revocation_revision_key(revision.scope, revision.generation) {
                return Err(PublisherPolicyError::CorruptState);
            }
            add_chain(
                revocations.entry(revision.scope).or_default(),
                revision.generation,
            )?;
        } else if key.starts_with(REVOCATION_CURRENT_PREFIX)
            && key.len() == REVOCATION_CURRENT_PREFIX.len() + 16
        {
            let head = decode_revocation(value, REVOCATION_CURRENT_MAGIC)?;
            if key != revocation_current_key(head.scope)
                || revocation_heads
                    .insert(head.scope, head.generation)
                    .is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else {
            return Err(PublisherPolicyError::CorruptState);
        }
    }
    for (project, chain) in &policies {
        let head = heads
            .get(project)
            .ok_or(PublisherPolicyError::CorruptState)?;
        if chain.count != chain.max || head.generation != chain.max {
            return Err(PublisherPolicyError::CorruptState);
        }
        let bytes = journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_revision_key(*project, head.generation),
            )
            .ok_or(PublisherPolicyError::CorruptState)?;
        if decode_policy_revision(bytes)?.descriptor.digest() != head.digest {
            return Err(PublisherPolicyError::CorruptState);
        }
    }
    if heads.len() != policies.len() {
        return Err(PublisherPolicyError::CorruptState);
    }
    match (controller.count, controller_head) {
        (0, None) => {}
        (count, Some(head))
            if count == controller.max
                && head.generation == controller.max
                && Some(head.principal) == controller_principal => {}
        _ => return Err(PublisherPolicyError::CorruptState),
    }
    for (scope, chain) in &revocations {
        if chain.count != chain.max || revocation_heads.get(scope).copied() != Some(chain.max) {
            return Err(PublisherPolicyError::CorruptState);
        }
    }
    if revocation_heads.len() != revocations.len() {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok((records, total))
}
