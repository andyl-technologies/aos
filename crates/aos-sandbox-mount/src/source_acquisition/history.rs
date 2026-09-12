//! Cross-row provider history validation for AOSMSA01 state.
//!
//! Acquisition rows retain the authority, route, key, selection, resource,
//! catalog, and physical evidence current when their provider disposition was
//! accepted. This module rejects rollback and equal-generation equivocation
//! across that durable history before commit and again during recovery.

use super::*;

pub(super) fn validate_global_provider_history(
    acquisitions: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
) -> Result<()> {
    let mut route_generations = BTreeMap::new();
    let mut route_scopes = BTreeMap::new();
    let mut holder_generations = BTreeMap::new();
    let mut authority_generations = BTreeMap::new();
    let mut key_generations = BTreeMap::new();
    let mut selection_generations = BTreeMap::new();
    let mut selection_targets = BTreeMap::new();
    let history = acquisitions
        .values()
        .map(|row| {
            for provider in std::iter::once(row.provider).chain(row.release_provider) {
                insert_consistent(
                    &mut holder_generations,
                    (provider.holder_authority_id, provider.holder_generation),
                    provider.holder_authority_digest,
                )?;
                insert_consistent(
                    &mut authority_generations,
                    (
                        provider.provider_authority_id,
                        provider.provider_authority_generation,
                    ),
                    provider.provider_authority_digest,
                )?;
                insert_consistent(
                    &mut route_generations,
                    (
                        provider.provider_route_id,
                        provider.provider_route_generation,
                    ),
                    provider.provider_route_digest,
                )?;
                insert_consistent(
                    &mut route_scopes,
                    provider.provider_route_id,
                    (
                        provider.provider_authority_id,
                        provider.resource_namespace_digest,
                    ),
                )?;
                insert_consistent(
                    &mut key_generations,
                    (
                        provider.provider_authority_id,
                        provider.provider_key_generation,
                    ),
                    (
                        provider.provider_key_id,
                        provider.provider_public_key_digest,
                    ),
                )?;
            }
            let Some(evidence) = row.evidence.as_ref() else {
                return Ok(None);
            };
            insert_consistent(
                &mut selection_generations,
                (
                    row.provider.provider_route_id,
                    evidence.provider_selection_generation,
                ),
                evidence.provider_selection_digest,
            )?;
            insert_consistent(
                &mut selection_targets,
                (
                    row.provider.provider_route_id,
                    evidence.provider_selection_generation,
                    evidence.provider_selection_digest,
                ),
                (
                    evidence.provider_resource_id,
                    evidence.provider_resource_digest,
                ),
            )?;
            Ok(Some(MountSourceProviderHistoryV1 {
                authority_id: row.provider.provider_authority_id,
                authority_generation: row.provider.provider_authority_generation,
                authority_digest: row.provider.provider_authority_digest,
                resource_id: evidence.provider_resource_id,
                resource_generation: evidence.provider_resource_generation,
                resource_digest: evidence.provider_resource_digest,
                catalog_generation: evidence.provider_catalog_generation,
                catalog_digest: evidence.provider_catalog_digest,
                physical_proof_digest: evidence.source_physical_proof_digest,
            }))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if !mount_source_provider_history_is_valid_v1(&history) {
        return Err(state_error(
            "source acquisition provider history is nonmonotonic",
        ));
    }
    Ok(())
}

pub(super) fn validate_global_provider_and_head_history(
    acquisitions: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    heads: &BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV1>,
) -> Result<()> {
    validate_global_provider_history(acquisitions)?;

    let mut route_generations = BTreeMap::new();
    let mut route_scopes = BTreeMap::new();
    let mut holder_generations = BTreeMap::new();
    let mut authority_generations = BTreeMap::new();
    let mut key_generations = BTreeMap::new();
    for row in acquisitions.values() {
        for provider in std::iter::once(row.provider).chain(row.release_provider) {
            insert_context_history(
                &mut holder_generations,
                &mut authority_generations,
                &mut route_generations,
                &mut route_scopes,
                &mut key_generations,
                provider,
            )?;
        }
    }
    for head in heads.values() {
        insert_consistent(
            &mut holder_generations,
            (head.holder_authority_id, head.holder_generation),
            head.holder_authority_digest,
        )?;
        insert_consistent(
            &mut authority_generations,
            (
                head.provider_authority_id,
                head.provider_authority_generation,
            ),
            head.provider_authority_digest,
        )?;
        insert_consistent(
            &mut route_generations,
            (head.route_id, head.route_generation),
            head.route_digest,
        )?;
        insert_consistent(
            &mut route_scopes,
            head.route_id,
            (head.provider_authority_id, head.resource_namespace_digest),
        )?;
        insert_consistent(
            &mut key_generations,
            (head.provider_authority_id, head.provider_key_generation),
            (head.provider_key_id, head.provider_public_key_digest),
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_context_history(
    holder_generations: &mut BTreeMap<([u8; 16], u64), [u8; 32]>,
    authority_generations: &mut BTreeMap<([u8; 16], u64), [u8; 32]>,
    route_generations: &mut BTreeMap<([u8; 16], u64), [u8; 32]>,
    route_scopes: &mut BTreeMap<[u8; 16], ([u8; 16], [u8; 32])>,
    key_generations: &mut BTreeMap<([u8; 16], u64), ([u8; 16], [u8; 32])>,
    provider: SourceProviderContextSnapshotV1,
) -> Result<()> {
    insert_consistent(
        holder_generations,
        (provider.holder_authority_id, provider.holder_generation),
        provider.holder_authority_digest,
    )?;
    insert_consistent(
        authority_generations,
        (
            provider.provider_authority_id,
            provider.provider_authority_generation,
        ),
        provider.provider_authority_digest,
    )?;
    insert_consistent(
        route_generations,
        (
            provider.provider_route_id,
            provider.provider_route_generation,
        ),
        provider.provider_route_digest,
    )?;
    insert_consistent(
        route_scopes,
        provider.provider_route_id,
        (
            provider.provider_authority_id,
            provider.resource_namespace_digest,
        ),
    )?;
    insert_consistent(
        key_generations,
        (
            provider.provider_authority_id,
            provider.provider_key_generation,
        ),
        (
            provider.provider_key_id,
            provider.provider_public_key_digest,
        ),
    )?;
    Ok(())
}

fn insert_consistent<K: Ord, V: Eq>(values: &mut BTreeMap<K, V>, key: K, value: V) -> Result<()> {
    if values.get(&key).is_some_and(|existing| existing != &value) {
        return Err(state_error(
            "source acquisition provider history equivocated",
        ));
    }
    values.insert(key, value);
    Ok(())
}
