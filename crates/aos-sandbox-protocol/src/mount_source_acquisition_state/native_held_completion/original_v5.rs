//! Originally funded native-only owner validation over the complete v2 graph.
//!
//! The distinct funding family excludes independently funded ordinary owner
//! transitions. Graph data and this proposal cannot grant a writer or signer.

use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1, frame::PreparedNativeHeldControlV1,
    suffix::NativeHeldCompletionSuffixV1,
};

use super::{
    RootNativeCutV1, RootNativeHeldGraphV2, RootNativeHeldSidecarV1, RootNativeHeldTransitionV2,
    RootNativeTransitionKindV2,
};
use crate::mount_source_acquisition_state::{Result, format::state_error};

/// Joins retained original Root1 bytes to the exact immutable admission cut.
///
/// The actual current graph remains independently validated. Reconstruction
/// checks the retained original Attempt/Session and captured Head/Acquisition
/// stamps; it never guesses a current predecessor or socket cookie.
///
/// # Errors
///
/// Rejects a changed cut/scope/checkpoint, missing original rows, signer or
/// archive mismatch, or different canonical companion witnesses.
pub fn validate_original_root_preparation_v5(
    graph: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
    prepared: &PreparedNativeHeldControlV1,
    cut: &RootNativeCutV1,
) -> Result<()> {
    let sidecar = graph
        .sidecars()
        .get(&attempt)
        .ok_or_else(|| state_error("original Root retained sidecar absent"))?;
    if prepared.kind() != Kind::RootPrepared
        || prepared.scope() != sidecar.original_scope()
        || cut != sidecar.admission_cut()
        || sidecar
            .suffix()
            .control(Kind::RootPrepared)
            .is_some_and(|stored| stored.prepared() != prepared)
        || (sidecar.suffix().phase() == 0 && sidecar.suffix().prepared() != Some(prepared))
    {
        return Err(state_error(
            "original Root retained preparation/cut mismatch",
        ));
    }
    let captured = cut.reconstruct(graph.legacy(), attempt)?;
    let suffix = NativeHeldCompletionSuffixV1::new(
        NativeHeldOwnerV1::Root,
        0,
        prepared.scope().flight,
        Some(prepared.clone()),
        Vec::new(),
    )
    .map_err(|_| state_error("original Root retained preparation suffix"))?;
    let historical =
        RootNativeHeldSidecarV1::new(*prepared.scope(), [0; 16], None, None, None, suffix)?;
    super::graph::validate_historical_archives(
        &historical,
        &captured.attempt,
        &captured.session,
        captured.witnesses(),
        None,
    )
}

/// Returns the native-only suffix count without charging ordinary recovery.
///
/// A signed Closed prefix still owes a terminal and its ACK after independently
/// funded Inventory recovery. Unsigned Closed has no escaped Root1; it cannot
/// manufacture a signed terminal lineage and retains its no-interest cleanup.
///
/// # Errors
///
/// Rejects a missing original sidecar or an unsupported checked suffix phase.
pub fn original_root_remaining_v5(graph: &RootNativeHeldGraphV2, attempt: [u8; 32]) -> Result<u32> {
    let sidecar = graph
        .sidecars()
        .get(&attempt)
        .ok_or_else(|| state_error("original Root native sidecar absent"))?;
    if sidecar.no_interest_terminal().is_some() {
        return Ok(0);
    }
    Ok(match sidecar.suffix().phase() {
        0 => 7,
        1 => 6,
        2 => 5,
        3 => 4,
        4 => 3,
        5 | 11 => 2,
        6 | 12 => 1,
        7 | 13 => 0,
        10 if sidecar.suffix().control(Kind::RootPrepared).is_some() => 3,
        10 => 1,
        _ => return Err(state_error("original Root native suffix phase")),
    })
}

/// Validates the same exact native owner edge with separately original funding.
///
/// # Errors
///
/// Rejects all existing owner/cut/archive violations, ordinary stutters or a
/// nondecreasing native continuation. Ordinary preservation has a separate
/// named validator and cannot spend this owner's native floor.
pub fn validate_original_root_transition_v5(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
    transaction: [u8; 16],
) -> Result<RootNativeHeldTransitionV2> {
    let pending_closed = after.sidecars().get(&attempt).is_some_and(|sidecar| {
        sidecar.suffix().phase() == 10
            && sidecar
                .disposition_cut()
                .is_some_and(RootNativeCutV1::is_pending_disposition)
    });
    let originally_prepared = before
        .sidecars()
        .get(&attempt)
        .is_some_and(|sidecar| sidecar.suffix().phase() == 1);
    if pending_closed && originally_prepared {
        return super::pending_v5::validate_original_pending_closed_transition_v5(
            before,
            after,
            attempt,
            transaction,
        );
    }

    let mut proposal =
        super::reducer_v2::validate_owner_transition(before, after, attempt, transaction)?;
    if matches!(
        proposal.kind,
        RootNativeTransitionKindV2::NativeRecoveryReplacement
            | RootNativeTransitionKindV2::NativeRecoveryInventoryReserved
            | RootNativeTransitionKindV2::NativeRecoveryInventoryResolved
    ) {
        return Err(state_error(
            "ordinary recovery cannot spend original native funding",
        ));
    }
    proposal.maximum_remaining_transactions = original_root_remaining_v5(after, attempt)?;
    if !matches!(
        proposal.kind,
        RootNativeTransitionKindV2::PreparedAssertionRecorded
            | RootNativeTransitionKindV2::Duplicate
    ) && proposal.maximum_remaining_transactions >= original_root_remaining_v5(before, attempt)?
    {
        return Err(state_error("original native continuation did not decrease"));
    }
    Ok(proposal)
}
