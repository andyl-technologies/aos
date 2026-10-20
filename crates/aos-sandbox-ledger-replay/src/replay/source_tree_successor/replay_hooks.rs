//! Sole raw-COMMIT and complete-prefix saved Source semantic hooks.

use super::*;

/// Runs the same complete saved replay hook without a native grant.
///
/// # Errors
/// Rejects malformed family/issuance/lineage joins or unrepresentable demand.
pub fn validate_replayed_transaction<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
) -> Result<bool, E> {
    validate_replayed_transaction_with_originals::<E, H, R>(state, transaction, limits, None, None, None)
}

/// Runs the same complete saved replay hook without a native grant.
///
/// # Errors
/// Rejects malformed family/issuance/lineage joins or unrepresentable demand.
pub fn validate_replayed_transaction_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1<E, H, R>>,
    genesis_originals: Option<&mut crate::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1<E, H, R>>,
    project_originals: Option<&mut SourceProjectGenesisOriginalsV1<E, H, R>>,
) -> Result<bool, E> {
    let phase = recognize_replayed_phase(transaction)?;
    // A cold phase is complete structural DATA, not a live selected admission.
    let comparison_phase = phase.map(|phase| match phase {
        FirstSourceSuccessorNativePhaseV2::SourceAppend => FirstSourceSuccessorNativePhaseV2::MixedSourceAppend,
        FirstSourceSuccessorNativePhaseV2::SourceAck => FirstSourceSuccessorNativePhaseV2::MixedSourceAck,
        FirstSourceSuccessorNativePhaseV2::RootPrepared => FirstSourceSuccessorNativePhaseV2::MixedRootPrepared,
        FirstSourceSuccessorNativePhaseV2::RootAnchor => FirstSourceSuccessorNativePhaseV2::MixedRootAnchor,
        ordinary => ordinary,
    });
    require_replayed_transition::<E, H, R>(state, transaction, comparison_phase, originals, project_originals)?;
    if phase.is_some() {
        for record in transaction.records() {
            if record.namespace() != RecordNamespace::GlobalCapacityReservation
                || record.value().is_none()
            {
                continue;
            }
            let (request, admission, _) = aos_sandbox_protocol::domain_ledger::capacity_family::decode_capacity_reservation_request_v1(record).map_err(JournalError::from)?;
            if !request.purpose.is_first_source_successor() || &admission != transaction.id() {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            aos_sandbox_protocol::domain_ledger::capacity_family::validate_request_with_limits(
                &request, limits,
            ).map_err(JournalError::from)?;
        }
    }
    crate::replay::controller_source_successor_issuance::require_no_mutation(
        state, transaction,
        crate::replay::controller_source_successor_issuance::recognize_replayed_transition(transaction)?,
    )?;
    let genesis_transition = phase.map(|phase| phase.source_genesis_transition())
        .map_or_else(|| crate::replay::source_tree_genesis::recognize_replayed_transition(transaction), Ok)?;
    crate::replay::source_tree_genesis::require_no_mutation_with_originals::<E, H, R>(
        state, transaction, genesis_transition, genesis_originals,
    )?;
    Ok(phase.is_some() || state.keys().any(|(_, key)| {
        key.starts_with(PREFIX) || key.starts_with(b"\0aos-root-first-source-successor-v2\0")
            || key.starts_with(b"\0aos-controller-source-successor-issuance-v2\0consumer-")
    }))
}

/// Runs the same complete saved replay hook without a native grant.
///
/// # Errors
/// Rejects malformed family/issuance/lineage joins or unrepresentable demand.
pub fn source_member_dynamic_demand_v1<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: Option<&JournalTransaction>,
) -> Result<aos_sandbox_core::ResourceVector, E> {
    let mutation = crate::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1::<E, H, R>::dynamic_demand_v1(state, transaction)?;
    let reached = state.keys().any(|(_, key)| key.starts_with(PREFIX))
        || transaction.is_some_and(|transaction| transaction.records().iter()
            .any(|record| record.key().starts_with(PREFIX)));
    if !reached {
        // Without a successor family, the original COMMIT before-fold and
        // final mutation each keep one genesis map plane. State-only replay
        // has only its original final family fold. Each bound uses actual rows.
        let copies = if transaction.is_some() { 2 } else { 1 };
        let mut total = aos_sandbox_core::ResourceVector::ZERO;
        for dimension in aos_sandbox_core::ResourceDimension::ALL {
            let amount = mutation.get(dimension).checked_mul(copies)
                .ok_or(JournalError::LimitExceeded("Source genesis fold geometry"))?;
            total = total.with(dimension, amount);
        }
        return Ok(total);
    }
    let current = state.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()));
    let proposed = transaction.into_iter().flat_map(|transaction| transaction.records().iter())
        .filter_map(|record| record.value().map(|value| (record.namespace(), record.key(), value)));
    let lineage = crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1::<E, H, R>::receiving_dynamic_demand_v1(current.chain(proposed))?;
    let Some(transaction) = transaction else { return Ok(lineage); };
    // Source COMMIT has before/proposed/after member owners and the final
    // genesis predecessor's member owner, each with its two concrete lanes.
    let models = transition_retained::dynamic_demand_v1(state, transaction)?;
    let mut total = aos_sandbox_core::ResourceVector::ZERO;
    for dimension in aos_sandbox_core::ResourceDimension::ALL {
        let amount = lineage.get(dimension).checked_mul(4)
            .and_then(|amount| amount.checked_add(models.get(dimension)))
            .and_then(|amount| amount.checked_add(mutation.get(dimension)))
            .ok_or(JournalError::LimitExceeded("Source transition geometry"))?;
        total = total.with(dimension, amount);
    }
    Ok(total)
}

/// Runs the same complete saved replay hook without a native grant.
///
/// # Errors
/// Rejects malformed family/issuance/lineage joins or unrepresentable demand.
pub fn validate_replayed_state<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(state: &State, compacted: bool) -> Result<(), E> {
    validate_replayed_state_with_originals::<E, H, R>(state, compacted, None)
}

/// Runs the same complete saved replay hook without a native grant.
///
/// # Errors
/// Rejects malformed family/issuance/lineage joins or unrepresentable demand.
pub fn validate_replayed_state_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    compacted: bool,
    originals: Option<&mut SourceReplayFamilyOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    match originals {
        Some(originals) => originals.observe_once(state)?,
        None => { replay_rows(state)?; }
    }
    validate_root_state(state)?;
    crate::replay::controller_source_successor_issuance::validate_rows(state)?;
    if compacted {
        require_no_compaction(state)?;
        crate::replay::controller_source_successor_issuance::require_no_compaction(state)?;
        crate::replay::source_tree_genesis::require_no_compaction(state)?;
    }
    Ok(())
}


#[cfg(test)]
mod tests;
