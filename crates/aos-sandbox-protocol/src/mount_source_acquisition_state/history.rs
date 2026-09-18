//! Cross-record authority, route, signer, and operation history invariants.
//!
//! These checks prevent two individually well-shaped historical records from
//! assigning different meanings to the same stable generation or operation.

use std::collections::{BTreeMap, BTreeSet};

use crate::{MountSourceProviderHistoryV1, mount_source_provider_history_is_valid_v1};

use super::Result;
use super::format::state_error;
use super::model::{
    ProviderAttemptStateV2, ProviderQueryOwnerV2, SourceAcquisitionRowV2,
    SourceProviderQueryAttemptV2, SourceProviderSessionV2,
};

pub fn validate_global_history(
    rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    sessions: &BTreeMap<[u8; 32], SourceProviderSessionV2>,
    attempts: &BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
) -> Result<()> {
    let mut operations = BTreeSet::new();
    let mut provider_acquisition_ids = BTreeMap::new();
    let mut provider_acquisition_sequences = BTreeMap::new();
    let mut holder_generations = BTreeMap::new();
    let mut provider_generations = BTreeMap::new();
    let mut route_generations = BTreeMap::new();
    let mut route_scopes = BTreeMap::new();
    let mut signer_generations = BTreeMap::new();
    let mut signer_ids = BTreeMap::new();
    let mut selection_generations = BTreeMap::new();
    let mut selection_targets = BTreeMap::new();
    let mut session_bindings = BTreeMap::new();
    let mut trust_generations = BTreeMap::new();
    let mut revocation_generations = BTreeMap::new();
    let mut provider_history = Vec::new();

    for row in rows.values() {
        if !operations.insert(row.acquire.operation_id)
            || row
                .release
                .is_some_and(|value| !operations.insert(value.operation_id))
        {
            return Err(state_error(
                "Mount operation identity is reused across AOSMSA02 rows",
            ));
        }
        if let Some(evidence) = &row.evidence {
            let historical = &evidence.historical_lease_signer;
            let signer = &historical.signer;
            insert_consistent(
                &mut provider_generations,
                (signer.authority_id, signer.authority_generation),
                signer.authority_digest,
            )?;
            insert_consistent(
                &mut signer_generations,
                (signer.authority_id, signer.role, signer.key_generation),
                (signer.key_id, signer.public_key_fingerprint),
            )?;
            insert_consistent(
                &mut signer_ids,
                signer.key_id,
                (
                    signer.authority_id,
                    signer.role,
                    signer.public_key_fingerprint,
                ),
            )?;
            insert_consistent(
                &mut route_scopes,
                historical.selection_floor.route_id,
                (
                    historical.selection_floor.provider_authority_id,
                    historical.selection_floor.resource_namespace_digest,
                ),
            )?;
            insert_consistent(
                &mut selection_generations,
                (
                    historical.selection_floor.route_id,
                    historical.selection_floor.selection_generation,
                ),
                historical.selection_floor.selection_digest,
            )?;
            insert_consistent(
                &mut selection_targets,
                (
                    historical.selection_floor.route_id,
                    historical.selection_floor.selection_generation,
                    historical.selection_floor.selection_digest,
                ),
                (
                    evidence.provider_resource_id,
                    evidence.provider_resource_digest,
                ),
            )?;
            insert_consistent(
                &mut trust_generations,
                (
                    row.scope.holder_authority_id,
                    historical.selection_floor.trust_generation,
                ),
                historical.selection_floor.trust_digest,
            )?;
            provider_history.push(MountSourceProviderHistoryV1 {
                authority_id: signer.authority_id,
                authority_generation: signer.authority_generation,
                authority_digest: signer.authority_digest,
                resource_id: evidence.provider_resource_id,
                resource_generation: evidence.provider_resource_generation,
                resource_digest: evidence.provider_resource_digest,
                catalog_generation: evidence.provider_catalog_generation,
                catalog_digest: evidence.provider_catalog_digest,
                physical_proof_digest: evidence.source_physical_proof_digest,
            });
            insert_consistent(
                &mut revocation_generations,
                (
                    row.scope.holder_authority_id,
                    historical.selection_floor.revocation_generation,
                ),
                historical.selection_floor.revocation_digest,
            )?;
        }
    }
    for attempt in attempts.values() {
        let Some(provider_acquisition) = attempt.provider_acquisition else {
            continue;
        };
        let acquisition_id = match attempt.owner {
            ProviderQueryOwnerV2::Acquire { acquisition_id }
            | ProviderQueryOwnerV2::Release { acquisition_id } => acquisition_id,
            ProviderQueryOwnerV2::Inventory => {
                return Err(state_error(
                    "Inventory attempt retains a provider acquisition identity",
                ));
            }
        };
        insert_consistent(
            &mut provider_acquisition_ids,
            provider_acquisition.acquisition_id,
            (
                provider_acquisition.holder_authority_id,
                provider_acquisition.holder_authority_generation,
                provider_acquisition.holder_authority_digest,
                provider_acquisition.acquisition_sequence,
                acquisition_id,
            ),
        )?;
        insert_consistent(
            &mut provider_acquisition_sequences,
            (
                provider_acquisition.holder_authority_id,
                provider_acquisition.acquisition_sequence,
            ),
            acquisition_id,
        )?;
    }
    for session in sessions.values() {
        insert_consistent(
            &mut session_bindings,
            session.session_binding,
            session.session_id,
        )?;
        insert_consistent(
            &mut holder_generations,
            (
                session.scope.holder_authority_id,
                session.root_mount_authority_generation,
            ),
            session.root_mount_authority_digest,
        )?;
        insert_consistent(
            &mut provider_generations,
            (
                session.scope.provider_authority_id,
                session.provider_authority_generation,
            ),
            session.provider_authority_digest,
        )?;
        insert_consistent(
            &mut route_generations,
            (session.scope.route_id, session.route_generation),
            session.route_digest,
        )?;
        insert_consistent(
            &mut route_scopes,
            session.scope.route_id,
            (
                session.scope.provider_authority_id,
                session.scope.resource_namespace_digest,
            ),
        )?;
        for signer in &session.signers {
            insert_consistent(
                &mut signer_generations,
                (signer.authority_id, signer.role, signer.key_generation),
                (signer.key_id, signer.public_key_fingerprint),
            )?;
            insert_consistent(
                &mut signer_ids,
                signer.key_id,
                (
                    signer.authority_id,
                    signer.role,
                    signer.public_key_fingerprint,
                ),
            )?;
        }
        insert_consistent(
            &mut trust_generations,
            (session.scope.holder_authority_id, session.trust_generation),
            session.trust_digest,
        )?;
        insert_consistent(
            &mut revocation_generations,
            (
                session.scope.holder_authority_id,
                session.revocation_generation,
            ),
            session.revocation_digest,
        )?;
    }
    if !mount_source_provider_history_is_valid_v1(&provider_history) {
        return Err(state_error(
            "AOSMSA02 provider resource history is nonmonotonic",
        ));
    }
    validate_session_predecessors(sessions)?;
    Ok(())
}

fn validate_session_predecessors(
    sessions: &BTreeMap<[u8; 32], SourceProviderSessionV2>,
) -> Result<()> {
    let mut successors = BTreeMap::new();
    for session in sessions.values() {
        if let Some(predecessor) = session.predecessor_session_id {
            if successors.insert(predecessor, session.session_id).is_some() {
                return Err(state_error("SourceProvider session history forks"));
            }
        }
    }
    for session in sessions.values() {
        let mut seen = BTreeSet::new();
        let mut current = Some(session.session_id);
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err(state_error(
                    "SourceProvider session predecessor graph is cyclic",
                ));
            }
            current = sessions
                .get(&id)
                .ok_or_else(|| state_error("SourceProvider session predecessor is missing"))?
                .predecessor_session_id;
        }
        if let Some(predecessor_id) = session.predecessor_session_id {
            let predecessor = sessions
                .get(&predecessor_id)
                .ok_or_else(|| state_error("SourceProvider session predecessor is missing"))?;
            if predecessor.scope != session.scope
                || !generation_dominates(
                    predecessor.root_mount_authority_generation,
                    predecessor.root_mount_authority_digest,
                    session.root_mount_authority_generation,
                    session.root_mount_authority_digest,
                )
                || !generation_dominates(
                    predecessor.provider_authority_generation,
                    predecessor.provider_authority_digest,
                    session.provider_authority_generation,
                    session.provider_authority_digest,
                )
                || !generation_dominates(
                    predecessor.route_generation,
                    predecessor.route_digest,
                    session.route_generation,
                    session.route_digest,
                )
                || !generation_dominates(
                    predecessor.trust_generation,
                    predecessor.trust_digest,
                    session.trust_generation,
                    session.trust_digest,
                )
                || !generation_dominates(
                    predecessor.revocation_generation,
                    predecessor.revocation_digest,
                    session.revocation_generation,
                    session.revocation_digest,
                )
                || predecessor
                    .signers
                    .iter()
                    .zip(&session.signers)
                    .any(|(old, new)| {
                        old.role != new.role
                            || new.key_generation < old.key_generation
                            || (new.key_generation == old.key_generation
                                && (new.key_id != old.key_id
                                    || new.public_key_fingerprint != old.public_key_fingerprint))
                    })
            {
                return Err(state_error(
                    "SourceProvider successor session rolls back or changes scope",
                ));
            }
        }
    }
    Ok(())
}

fn generation_dominates(
    old_generation: u64,
    old_digest: [u8; 32],
    new_generation: u64,
    new_digest: [u8; 32],
) -> bool {
    new_generation > old_generation
        || (new_generation == old_generation && new_digest == old_digest)
}

pub fn attempt_is_terminal(state: &ProviderAttemptStateV2) -> bool {
    !matches!(state, ProviderAttemptStateV2::Reserved)
}

fn insert_consistent<K, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> Result<()>
where
    K: Ord,
    V: Eq,
{
    if map.get(&key).is_some_and(|prior| prior != &value) {
        return Err(state_error("AOSMSA02 stable generation equivocated"));
    }
    map.insert(key, value);
    Ok(())
}
