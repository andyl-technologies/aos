//! Sole complete saved Source transition comparisons at their original frontiers.

use super::*;

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_transition<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, E> {
    let root_settling = validate_root_transition(state, transaction, phase)?;
    let source_settling = require_source_transition::<E, H, R>(state, transaction, phase)?;
    if root_settling.is_some() && source_settling.is_some() {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    let controller_settling = crate::replay::controller_source_successor_issuance::consumer_settling(
        state, transaction, phase,
    )?;
    Ok(root_settling.or(source_settling).or(controller_settling))
}

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_replayed_transition<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State, transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    mut originals: Option<&mut transition_retained::SourceTransitionOriginalsV1<E, H, R>>,
    mut project_originals: Option<&mut SourceProjectGenesisOriginalsV1<E, H, R>>,
) -> Result<Option<[u8; 32]>, E> {
    #[cfg(target_os = "linux")]
    let root_settling = crate::replay::root_successor::validate_project_successor_transition_v3(
        state, transaction, phase,
    )?;
    #[cfg(not(target_os = "linux"))]
    let root_settling = validate_root_transition(state, transaction, phase)?;
    let genesis_selection = match project_originals.as_deref_mut() {
        Some(originals) => originals.selection.observe_once(state, transaction, phase)?,
        None => select_replayed_genesis_project_engine::<E, R>(state, transaction, phase, None)?,
    };
    let source_settling = if let Some(project) = genesis_selection {
        match project_originals.as_deref_mut() {
            Some(originals) => originals.observe_once(state, transaction, project)?,
            None => require_project_genesis_transition_engine::<E, H, R>(state, transaction, project, None)?,
        }
        None
    } else if matches!(phase, Some(FirstSourceSuccessorNativePhaseV2::MixedSourceAppend
        | FirstSourceSuccessorNativePhaseV2::MixedSourceAck))
    {
        require_source_transition_with_originals::<E, H, R>(state, transaction, phase, originals.as_deref_mut())?
    } else if !state.keys().any(|(_, key)| key.starts_with(RECEIPT_PREFIX)) {
        require_source_transition_with_originals::<E, H, R>(state, transaction, phase.map(FirstSourceSuccessorNativePhaseV2::canonical), originals.as_deref_mut())?
    } else {
        let selected = state.get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
            .map(|bytes| SourceFirstSuccessorPendingV2::decode(bytes).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map(|pending| pending.project()).map_err(|_| JournalError::ProtectedBoundary))
            .transpose()?;
        require_source_transition_with_recipe_originals::<E, H, R>(state, transaction, phase,
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected }, originals.as_deref_mut())?
    };
    if root_settling.is_some() && source_settling.is_some() { return Err(E::from(JournalError::ProtectedBoundary)); }
    let controller_settling = crate::replay::controller_source_successor_issuance::consumer_settling(
        state, transaction, phase.map(FirstSourceSuccessorNativePhaseV2::canonical),
    )?;
    Ok(root_settling.or(source_settling).or(controller_settling))
}

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_source_transition<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, E> {
    require_source_transition_with_originals::<E, H, R>(state, transaction, phase, None)
}

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_source_transition_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1<E, H, R>>,
) -> Result<Option<[u8; 32]>, E> {
    let recipe = match phase {
        Some(FirstSourceSuccessorNativePhaseV2::MixedSourceAppend) => {
            let record = transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?;
            let receipt = SourceFirstSuccessorReceiptV2::decode(required_value(record)?).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(receipt.project()) }
        }
        Some(FirstSourceSuccessorNativePhaseV2::MixedSourceAck) => {
            let pending = SourceFirstSuccessorPendingV2::decode(
                state.get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
                    .ok_or(JournalError::ProtectedBoundary)?,
            ).map_err(crate::data::SourceSuccessorDataErrorV2::from).map_err(|_| JournalError::ProtectedBoundary)?;
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(pending.project()) }
        }
        Some(FirstSourceSuccessorNativePhaseV2::MixedControllerBegin
            | FirstSourceSuccessorNativePhaseV2::MixedControllerAnchored
            | FirstSourceSuccessorNativePhaseV2::MixedControllerComplete) => {
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None }
        }
        _ => SourceSuccessorFamilyRecipeV3::SingleProjectV2,
    };
    require_source_transition_with_recipe_originals::<E, H, R>(state, transaction, phase, recipe, originals)
}

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_source_transition_with_recipe<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<Option<[u8; 32]>, E> {
    require_source_transition_with_recipe_originals::<E, H, R>(state, transaction, phase, recipe, None)
}

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_source_transition_with_recipe_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1<E, H, R>>,
) -> Result<Option<[u8; 32]>, E> {
    match originals {
        Some(originals) => originals.observe_once(state, transaction, phase, recipe),
        None => require_source_transition_engine::<E, H, R>(state, transaction, phase, recipe, None),
    }
}

/// Runs the complete saved transition comparison without native authority.
///
/// # Errors
/// Rejects malformed, inconsistent, foreign or exhausted historical DATA.
pub fn require_source_transition_engine<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1<E, H, R>>,
) -> Result<Option<[u8; 32]>, E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
    let (before_family, after_family, rows_sink, receipt_sink, pending_sink, request_sink,
        capacity_sink, ack_sink, deletion_sink, after_sink, next_sink, members): transition_retained::SourceTransitionSinksV1<'_, E, H, R> = match originals {
        Some(originals) => (
            Some(&mut originals.before_family), Some(&mut originals.after_family),
            Some(&mut originals.rows), Some(&mut originals.receipt), Some(&mut originals.pending),
            Some(&mut originals.request), Some(&mut originals.expected_capacity),
            Some(&mut originals.ack), Some(&mut originals.expected_deletion),
            Some(&mut originals.after), Some(&mut originals.next_rows), Some(&mut originals.members),
        ),
        None => (None, None, None, None, None, None, None, None, None, None, None, None),
    };
    let rows = match before_family {
        Some(originals) => current_family_with_genesis_data_originals::<E, H, R>(state, recipe, None, None, Some(originals))?
            .into_successor(),
        None => current_rows_with_recipe(state, recipe)?,
    };
    let rows = CaptureOnDropV1::new(rows, rows_sink);
    match phase.map(FirstSourceSuccessorNativePhaseV2::canonical) {
        Some(FirstSourceSuccessorNativePhaseV2::SourceAppend) => {
            let [_, _, receipt_record, pending_record, capacity] = transaction.records() else {
                return Err(E::from(JournalError::ProtectedBoundary));
            };
            if rows.pending.is_some()
                || (recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 && !rows.receipts.is_empty())
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            let receipt = SourceFirstSuccessorReceiptV2::decode(required_value(receipt_record)?).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let receipt = CaptureOnDropV1::new(receipt, receipt_sink);
            let pending = SourceFirstSuccessorPendingV2::decode(required_value(pending_record)?).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let pending = CaptureOnDropV1::new(pending, pending_sink);
            let project = receipt.project();
            if matches!(recipe, SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. })
                && rows.receipts.contains_key(&project)
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            let expected_id = transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend);
            let expected_capacity = match request_sink {
                Some(sink) => {
                    let request = CaptureOnDropV1::new(source_capacity_request(&receipt)?, Some(sink));
                    first_source_successor_capacity_record_v2(&request, *transaction.id())?
                }
                None => first_source_successor_capacity_record_v2(
                    &source_capacity_request(&receipt)?, *transaction.id(),
                )?,
            };
            let expected_capacity = CaptureOnDropV1::new(expected_capacity, capacity_sink);
            if transaction.id() != &expected_id
                || receipt_record.namespace() != RecordNamespace::DesiredState
                || receipt_record.key() != receipt_key(project)
                || pending_record.namespace() != RecordNamespace::DesiredState
                || pending_record.key() != PENDING_KEY
                || !pending_matches_receipt(&pending, &receipt)
                || capacity != &*expected_capacity
                || [receipt_record, pending_record, capacity].iter().any(|record| {
                    state.contains_key(&(record.namespace(), record.key().to_vec()))
                })
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            let pair = &transaction.records()[..2];
            match recipe {
                SourceSuccessorFamilyRecipeV3::SingleProjectV2 => {
                    match members {
                        Some(originals) => originals.observe_once(state,
                            crate::replay::tree_lineage::SourceSuccessorMemberRecipe::SingleProjectV2(&receipt), Some(pair), None)?,
                        None => crate::replay::tree_lineage::validate_source_first_successor_members_v2(state, &receipt, Some(pair))?,
                    }
                }
                SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } => {
                    if selected != Some(project) { return Err(E::from(JournalError::ProtectedBoundary)); }
                    match members {
                        Some(originals) => originals.observe_once(state,
                            crate::replay::tree_lineage::SourceSuccessorMemberRecipe::MixedProjectsV3 {
                                receipts: &rows.receipts, proposed: Some(&receipt),
                            }, Some(pair), None)?,
                        None => crate::replay::tree_lineage::validate_source_project_continuation_members_v3(
                            state, &rows.receipts, Some((&receipt, pair)),
                        )?,
                    }
                }
            }
            let after = crate::replay::root_original_inventory::materialize(state, transaction);
            let after = CaptureOnDropV1::new(after, after_sink);
            match after_family {
                Some(originals) => {
                    let next = current_family_with_genesis_data_originals::<E, H, R>(&after, recipe, None, None, Some(originals))?
                        .into_successor();
                    drop(CaptureOnDropV1::new(next, next_sink));
                }
                None => { current_rows_with_recipe(&after, recipe)?; }
            }
            Ok(None)
        }
        Some(FirstSourceSuccessorNativePhaseV2::SourceAck) => {
            let [pending_delete, ack_record, capacity_delete] = transaction.records() else {
                return Err(E::from(JournalError::ProtectedBoundary));
            };
            let pending = rows.pending.as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            let project = pending.project();
            let receipt = rows.receipts.get(&project)
                .ok_or(JournalError::ProtectedBoundary)?;
            let ack = SourceFirstSuccessorAckV2::decode(required_value(ack_record)?).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let ack = CaptureOnDropV1::new(ack, ack_sink);
            let request = source_capacity_request(receipt)?;
            let request = CaptureOnDropV1::new(request, request_sink);
            let admission = transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend);
            let expected_id = transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAck);
            let expected_deletion = first_source_successor_capacity_delete_v2(state, &request, admission)?;
            let expected_deletion = CaptureOnDropV1::new(expected_deletion, deletion_sink);
            if transaction.id() != &expected_id
                || pending_delete != &JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec())
                || ack_record.namespace() != RecordNamespace::DesiredState
                || ack_record.key() != ack_key(project)
                || ack.instance() != receipt.instance()
                || ack.project() != receipt.project()
                || ack.receipt() != receipt.digest()
                || state.contains_key(&(ack_record.namespace(), ack_record.key().to_vec()))
                || capacity_delete != &*expected_deletion
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            match after_family {
                Some(originals) => {
                    let after = crate::replay::root_original_inventory::materialize(state, transaction);
                    let after = CaptureOnDropV1::new(after, after_sink);
                    let next = current_family_with_genesis_data_originals::<E, H, R>(&after, recipe, None, None, Some(originals))?
                        .into_successor();
                    drop(CaptureOnDropV1::new(next, next_sink));
                }
                None => { current_rows_with_recipe(&crate::replay::root_original_inventory::materialize(state, transaction), recipe)?; }
            }
            Ok(Some(first_source_successor_capacity_identity_v2(&request, admission)?))
        }
        _ => {
            if rows.pending.is_some()
                || transaction.records().iter().any(|record| record.key().starts_with(PREFIX))
                || touches_capacity_purpose(state, transaction, GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck)?
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            Ok(None)
        }
    }
}
