//! Exact originally received Pending-to-Closed data and owner proposal checks.
//!
//! The distinct four-owner edge is hot-only. Historical cut reconstruction
//! preserves its irreversible response without recreating receive or signing
//! custody; today's complete legacy graph is always validated independently.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind,
    assertion::{NativeHeldDispositionV1, RootNativeObservationV1},
};

use super::{
    RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldGraphV2, RootNativeHeldSidecarV2,
    RootNativeHeldTransitionV2, RootNativeTransitionKindV2, native_root_sidecar_key_v2,
};
use crate::mount_source_acquisition_state::{
    ProviderAttemptStateV2, ProviderStatusV2, Result, format::state_error,
};

/// Identifies and rejoins the exact immutable consumed-Pending Closed cut.
///
/// A later independently validated Head may differ. The original Session,
/// Pending2 Attempt, Acquisition and R cannot change, and this data predicate
/// supplies no original receive, writer or signer authority.
///
/// # Errors
///
/// Rejects a tag6 cut without its exact partial Closed prefix or retained
/// original companions. Returns false for every other existing cut family.
pub fn has_original_pending_closed_cut_v5(
    graph: &RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
) -> Result<bool> {
    let Some(cut) = sidecar
        .disposition_cut()
        .filter(|cut| cut.is_pending_disposition())
    else {
        return Ok(false);
    };
    let attempt = *sidecar.original_scope().mount_attempt.as_bytes();
    let captured = cut.reconstruct(graph.legacy(), attempt)?;
    let r = sidecar
        .disposition()
        .ok_or_else(|| state_error("original Pending Closed R absent"))?;
    if !matches!(sidecar.suffix().phase(), 10..=13)
        || sidecar.response_transaction() != [0; 16]
        || sidecar.no_interest_terminal().is_some()
        || sidecar.suffix().control(Kind::RootPrepared).is_none()
        || sidecar.suffix().control(Kind::ProviderHeld).is_some()
        || sidecar.suffix().control(Kind::RootAccepted).is_some()
        || r.disposition != NativeHeldDispositionV1::Closed
        || r.observation != RootNativeObservationV1::PreparedOnly
        || &r.scope != sidecar.original_scope()
        || r.source_artifact.as_bytes() != &[0; 32]
        || r.descriptor_commitment.as_bytes() != &[0; 32]
        || r.records != *captured.witnesses()
        || graph.legacy().provider_attempts.get(&attempt) != Some(&captured.attempt)
        || graph.legacy().provider_sessions.get(&captured.session.session_id)
            != Some(&captured.session)
        || graph.legacy().acquisitions.get(&captured.acquisition.acquisition_id)
            != Some(&captured.acquisition)
    {
        return Err(state_error("original Pending immutable Closed association"));
    }
    Ok(true)
}

/// Validates only the original four-owner Pending response and first Closed R.
///
/// The output is data for the original native5 writer. It is deliberately not
/// dispatched by either the generic v2 owner or cold metadata owner.
///
/// # Errors
///
/// Rejects a noncurrent phase1 cut, another signed status, changed immutable
/// owners, unrelated mutations, wrong capture transaction or missing unsigned8.
pub fn validate_original_pending_closed_transition_v5(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
    transaction: [u8; 16],
) -> Result<RootNativeHeldTransitionV2> {
    let old = before
        .sidecars()
        .get(&attempt)
        .ok_or_else(|| state_error("original Pending before sidecar absent"))?;
    let next = after
        .sidecars()
        .get(&attempt)
        .ok_or_else(|| state_error("original Pending after sidecar absent"))?;
    let (original, session) = super::graph_v2::original_rows(before, old)?;
    let (consumed, _) = super::graph_v2::original_rows(after, next)?;
    if transaction == [0; 16]
        || old.suffix().phase() != 1
        || old.response_transaction() != [0; 16]
        || old.disposition().is_some()
        || old.disposition_cut().is_some()
        || old.settlement().is_some()
        || old.terminal_verifier().is_some()
        || old.no_interest_terminal().is_some()
        || old.suffix().control(Kind::RootPrepared).is_none()
        || old.suffix().controls().len() != 1
        || old.suffix().prepared().is_some()
        || original.revision != 1
        || !matches!(original.state, ProviderAttemptStateV2::Reserved)
        || next.suffix().phase() != 10
        || next.settlement().is_some()
        || next.terminal_verifier().is_some()
        || next.no_interest_terminal().is_some()
        || next.suffix().controls() != old.suffix().controls()
        || next
            .suffix()
            .prepared()
            .is_none_or(|prepared| prepared.kind() != Kind::RootClosed)
        || next.admission_cut() != old.admission_cut()
        || consumed.revision != 2
        || !matches!(
            &consumed.state,
            ProviderAttemptStateV2::DispositionConsumed {
                status: ProviderStatusV2::Pending, signed_result, ..
            } if signed_result.is_empty()
        )
    {
        return Err(state_error("original Pending exact phase1-to-Closed10 prefix"));
    }

    super::reducer::preserve_immutable(&old.claims, &next.claims)?;
    let admission = old.admission_cut().reconstruct(before.legacy(), attempt)?;
    if !super::graph_v2::current_companions_equal(before, &admission)
        || !has_original_pending_closed_cut_v5(after, next)?
    {
        return Err(state_error("original Pending current immutable companions"));
    }

    let captured = RootNativeCutV1::capture(
        RootNativeCutKindV1::Disposition,
        transaction,
        after.legacy(),
        attempt,
    )?;
    if next.disposition_cut() != Some(&captured)
        || before
            .canonical
            .keys()
            .any(|key| !after.canonical.contains_key(key))
    {
        return Err(state_error("original Pending capture transaction or retained removal"));
    }

    let puts: BTreeMap<_, _> = after
        .canonical
        .iter()
        .filter(|(key, value)| before.canonical.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    super::reducer::validate_response_companions(
        before.legacy(),
        after.legacy(),
        original,
        consumed,
        session,
        false,
        native_root_sidecar_key_v2(attempt)?,
        &puts,
    )?;

    let before_images = puts
        .keys()
        .map(|key| (key.clone(), before.canonical.get(key).cloned()))
        .collect();

    Ok(RootNativeHeldTransitionV2 {
        kind: RootNativeTransitionKindV2::OriginalPendingClosedRecorded,
        transaction_id: transaction,
        puts,
        before_images,
        maximum_remaining_transactions: 3,
        admission_binding: None,
    })
}
