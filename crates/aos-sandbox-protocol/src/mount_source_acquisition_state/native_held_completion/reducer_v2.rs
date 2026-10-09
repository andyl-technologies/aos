//! Native v2 atomic proposal checks over complete current before/after graphs.
//!
//! Exact cuts are derived from the actual post-admission or first-R successor.
//! Namespace46 floor rows remain exclusively Sandbox-owned. This module cannot
//! sign, append, establish no-dispatch authority or reserve ordinary operations.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1 as Kind;
use sha2::{Digest, Sha256};

use super::{
    RootNativeAdmissionBindingV1, RootNativeCutKindV1, RootNativeCutV1, RootNativeDataClassV2,
    RootNativeHeldGraphV1, RootNativeHeldGraphV2, RootNativeHeldSidecarV2,
    RootNativeTransitionKindV1, native_root_sidecar_key_v1, native_root_sidecar_key_v2,
};
use crate::mount_source_acquisition_state::{ProviderAttemptStateV2, Result, format::state_error};

/// Binds the original v2 admission to its actual canonical historical cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeAdmissionBindingV2 {
    /// Retains every existing actual Mount/Acquire/signer/checkpoint identity.
    pub original: RootNativeAdmissionBindingV1,
    /// Commits the exact canonical AdmissionCut with its original transaction.
    pub admission_cut_digest: [u8; 32],
}

/// Names one closed v2 native owner proposal, never an ordinary-owner bypass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootNativeTransitionKindV2 {
    /// Reserves original legacy records, cut and unsigned Root1 atomically.
    PreparedAssertionRecorded,
    /// Stores the exact original prepared Root1 signature.
    PreparedStored,
    /// Retains the original Provider3 control before the response CAS.
    HeldStored,
    /// Applies the existing exact response CAS with its concrete companions.
    ResponseDispositionRecorded,
    /// Captures first R and DispositionCut with original unsigned Accepted4.
    AcceptedAssertionRecorded,
    /// Captures irreversible Closed R and its separate DispositionCut.
    ClosedAssertionRecorded,
    /// Consumes actual original Pending and first Closed R together, hot-only v5.
    OriginalPendingClosedRecorded,
    /// Stores the exact original prepared hot4 or hot8 signature.
    DispositionStored,
    /// Stores genuine original7 or current10 with the unsigned terminal ACK.
    TerminalRecorded,
    /// Stores original hot13 or current own9 mode3 after genuine terminal data.
    TerminalAckStored,
    /// Advances exactly the original dead attempt, Session, Acquisition and Head.
    NativeRecoveryReplacement,
    /// Reserves one original barrier's exact recovery Inventory and Head.
    NativeRecoveryInventoryReserved,
    /// Resolves that Inventory and original attempt with exact Acquisition/Head.
    NativeRecoveryInventoryResolved,
    /// Joins genuine dedicated no-dispatch settlement and local terminal marker.
    NativeNoInterestCleanup,
    /// Reproduces the exact already retained graph without a new append.
    Duplicate,
}

/// Contains exact v2 namespace40 mutations and nonauthorizing capacity data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeHeldTransitionV2 {
    /// Names the concrete owner-derived native continuation.
    pub kind: RootNativeTransitionKindV2,
    /// Names the actual proposed append transaction for protected readback.
    pub transaction_id: [u8; 16],
    /// Contains complete canonical values for only the changed namespace40 keys.
    pub puts: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Contains exact before values, including genuine absence as `None`.
    pub before_images: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Bounds the actual retained native prefix's remaining finite alternatives.
    pub maximum_remaining_transactions: u32,
    /// Binds actual admission records and cut for the separate capacity adapter.
    pub admission_binding: Option<RootNativeAdmissionBindingV2>,
}

/// Checks an exact native v2 transition and derives its canonical proposal.
///
/// These checked graphs and outputs remain data. Real admission, capture commit,
/// private hot custody, authenticated unavailable proof and exact old-floor
/// deletion still require their genuine existing owners. No pure transaction ID
/// is proof of commit, and no DTO can construct a protected signing cut.
///
/// # Errors
///
/// Rejects retained-data removal, unrelated mutations, irreversible rewrites,
/// wrong capture transactions, non-exact legacy reducers or unsupported prefixes.
pub fn validate_native_root_transition_v2(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<RootNativeHeldTransitionV2> {
    let mut proposal = validate_owner_transition(before, after, mount_attempt, transaction_id)?;
    let next = after
        .sidecars
        .get(&mount_attempt)
        .ok_or_else(|| state_error("native Root v2 successor sidecar absent"))?;
    proposal.maximum_remaining_transactions = remaining(after, next)?;
    Ok(proposal)
}

/// Shares exact owner validation independently of the legacy mixed ceiling.
pub(super) fn validate_owner_transition(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<RootNativeHeldTransitionV2> {
    let next = after
        .sidecars
        .get(&mount_attempt)
        .ok_or_else(|| state_error("native Root v2 successor sidecar absent"))?;
    if before.canonical == after.canonical {
        return Ok(RootNativeHeldTransitionV2 {
            kind: RootNativeTransitionKindV2::Duplicate,
            transaction_id,
            puts: BTreeMap::new(),
            before_images: BTreeMap::new(),
            maximum_remaining_transactions: 0,
            admission_binding: None,
        });
    }
    if transaction_id == [0; 16]
        || before
            .canonical
            .keys()
            .any(|key| !after.canonical.contains_key(key))
    {
        return Err(state_error(
            "native Root v2 missing transaction or removed retained record",
        ));
    }
    let puts: BTreeMap<_, _> = after
        .canonical
        .iter()
        .filter(|(key, value)| before.canonical.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let sidecar_key = native_root_sidecar_key_v2(mount_attempt)?;
    let old = before.sidecars.get(&mount_attempt);
    let mut admission_binding = None;
    let kind = if let Some(old) = old {
        preserve_cuts(old, next)?;
        if old.no_interest_terminal().is_some() {
            return Err(state_error(
                "native Root local no-interest terminal cannot continue",
            ));
        }
        if next.no_interest_terminal().is_some() {
            super::recovery_v2::validate_no_interest_cleanup(
                before,
                after,
                old,
                next,
                transaction_id,
                &puts,
            )?;
            RootNativeTransitionKindV2::NativeNoInterestCleanup
        } else if old == next {
            super::recovery_v2::validate_native_recovery_step(before, after, old, &puts)?
        } else {
            super::reducer::preserve_immutable(&old.claims, &next.claims)?;
            let original_kind = super::reducer::classify(&old.claims, &next.claims)?;
            if original_kind == RootNativeTransitionKindV1::ResponseDispositionRecorded {
                let a = claims_graph(before)?;
                let b = claims_graph(after)?;
                super::reducer::validate_response_cas(
                    &a,
                    &b,
                    &old.claims,
                    &next.claims,
                    transaction_id,
                    &claims_puts(&puts, mount_attempt)?,
                )?;
            } else if puts.len() != 1 || !puts.contains_key(&sidecar_key) {
                return Err(state_error(
                    "native Root v2 sidecar step changed unrelated records",
                ));
            }
            if matches!(
                original_kind,
                RootNativeTransitionKindV1::AcceptedAssertionRecorded
                    | RootNativeTransitionKindV1::ClosedAssertionRecorded
            ) {
                let captured = RootNativeCutV1::capture(
                    RootNativeCutKindV1::Disposition,
                    transaction_id,
                    &after.legacy,
                    mount_attempt,
                )?;
                if next.disposition_cut.as_ref() != Some(&captured) {
                    return Err(state_error(
                        "native Root first R cut is not actual atomic successor",
                    ));
                }
            }
            // Fresh hot13 still compares physical current companions. A later
            // graph can acknowledge only through the distinct current mode3 path.
            if original_kind == RootNativeTransitionKindV1::TerminalAckStored
                && next
                    .suffix()
                    .controls()
                    .last()
                    .is_some_and(|control| control.kind() == Kind::RootTerminalRecorded)
            {
                require_current_original_companions(before, old)?;
                require_current_original_companions(after, next)?;
            }
            if matches!(
                original_kind,
                RootNativeTransitionKindV1::PreparedStored
                    | RootNativeTransitionKindV1::HeldStored
                    | RootNativeTransitionKindV1::ResponseDispositionRecorded
                    | RootNativeTransitionKindV1::AcceptedAssertionRecorded
                    | RootNativeTransitionKindV1::DispositionStored
            ) {
                require_current_original_companions(before, old)?;
            }
            super::reducer::validate_slot_update(&old.claims, &next.claims, original_kind)?;
            map_kind(original_kind)
        }
    } else {
        if next.suffix().phase() != 0
            || next.response_transaction() != [0; 16]
            || next.no_interest_terminal().is_some()
            || before.v1_sidecars.contains_key(&mount_attempt)
        {
            return Err(state_error("native Root v2 requires new atomic admission"));
        }
        let capture = RootNativeCutV1::capture(
            RootNativeCutKindV1::Admission,
            transaction_id,
            &after.legacy,
            mount_attempt,
        )?;
        if next.admission_cut != capture {
            return Err(state_error(
                "native Root admission cut is not post-reservation successor",
            ));
        }
        let original = super::admission::validate_admission(
            &claims_graph(before)?,
            &claims_graph(after)?,
            &next.claims,
            &claims_puts(&puts, mount_attempt)?,
        )?;
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.mount.native-admission-cut.v2\0");
        digest.update(next.admission_cut.to_canonical_bytes()?);
        admission_binding = Some(RootNativeAdmissionBindingV2 {
            original,
            admission_cut_digest: digest.finalize().into(),
        });
        RootNativeTransitionKindV2::PreparedAssertionRecorded
    };
    let before_images = puts
        .keys()
        .map(|key| (key.clone(), before.canonical.get(key).cloned()))
        .collect();
    Ok(RootNativeHeldTransitionV2 {
        kind,
        transaction_id,
        puts,
        before_images,
        maximum_remaining_transactions: 0,
        admission_binding,
    })
}

/// Checks only cold v2 metadata/recovery continuations without original hot IO.
///
/// # Errors
///
/// Rejects new original-flight preparation, receive, CAS, Accepted or hot ACK;
/// returns the same exact graph/proposal errors as the v2 transition validator.
pub fn validate_native_root_cold_transition_v2(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<RootNativeHeldTransitionV2> {
    let proposal =
        validate_native_root_transition_v2(before, after, mount_attempt, transaction_id)?;
    if matches!(
        proposal.kind,
        RootNativeTransitionKindV2::PreparedAssertionRecorded
            | RootNativeTransitionKindV2::PreparedStored
            | RootNativeTransitionKindV2::HeldStored
            | RootNativeTransitionKindV2::ResponseDispositionRecorded
            | RootNativeTransitionKindV2::OriginalPendingClosedRecorded
            | RootNativeTransitionKindV2::AcceptedAssertionRecorded
            | RootNativeTransitionKindV2::DispositionStored
    ) || (proposal.kind == RootNativeTransitionKindV2::TerminalAckStored
        && after
            .sidecars
            .get(&mount_attempt)
            .and_then(|sidecar| sidecar.suffix().controls().last())
            .is_none_or(|control| control.kind() != Kind::RootRecoveryQuery))
    {
        return Err(state_error(
            "native Root cold v2 cannot recreate original hot effect",
        ));
    }
    Ok(proposal)
}

fn preserve_cuts(old: &RootNativeHeldSidecarV2, next: &RootNativeHeldSidecarV2) -> Result<()> {
    if old.admission_cut != next.admission_cut
        || (old.disposition_cut.is_some() && old.disposition_cut != next.disposition_cut)
        || (old.no_interest_terminal.is_some()
            && old.no_interest_terminal != next.no_interest_terminal)
    {
        return Err(state_error(
            "native Root v2 rewrites immutable original cuts",
        ));
    }
    Ok(())
}

fn require_current_original_companions(
    graph: &RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
) -> Result<()> {
    let attempt = *sidecar.original_scope().mount_attempt.as_bytes();
    let current = graph
        .legacy
        .provider_attempts
        .get(&attempt)
        .ok_or_else(|| state_error("native Root hot original Attempt absent"))?;
    let original_pending = super::pending_v5::has_original_pending_closed_cut_v5(graph, sidecar)?;
    if !original_pending
        && !matches!(
            current.state,
            ProviderAttemptStateV2::Reserved
                | ProviderAttemptStateV2::DispositionConsumed {
                    status: crate::mount_source_acquisition_state::ProviderStatusV2::Complete,
                    ..
                }
        )
    {
        return Err(state_error(
            "native Root hot step cannot revive abandoned original custody",
        ));
    }
    if sidecar.suffix().phase() == 3 {
        let admission = sidecar.admission_cut.reconstruct(&graph.legacy, attempt)?;
        return super::graph_v2::validate_original_cas_projection(graph, sidecar, &admission);
    }
    let cut = sidecar
        .disposition_cut
        .as_ref()
        .unwrap_or(&sidecar.admission_cut)
        .reconstruct(&graph.legacy, attempt)?;
    if !super::graph_v2::current_companions_equal(graph, &cut) {
        return Err(state_error(
            "native Root hot step lost physical original current companions",
        ));
    }
    Ok(())
}

pub(super) fn remaining(
    graph: &RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
) -> Result<u32> {
    if sidecar.no_interest_terminal().is_some() || matches!(sidecar.suffix().phase(), 7 | 13) {
        return Ok(0);
    }
    // A validated terminal settlement has only its ACK continuation, even when
    // Closed skipped the original Held/response-CAS path. Ordinary recovery
    // obligations do not revive this separately funded native continuation.
    if matches!(sidecar.suffix().phase(), 6 | 12) {
        return Ok(1);
    }
    if super::pending_v5::has_original_pending_closed_cut_v5(graph, sidecar)? {
        return match sidecar.suffix().phase() {
            10 => Ok(3),
            11 => Ok(2),
            _ => Err(state_error("original Pending Closed suffix geometry")),
        };
    }
    let attempt_id = *sidecar.original_scope().mount_attempt.as_bytes();
    let (attempt, _) = super::graph_v2::original_rows(graph, sidecar)?;
    if sidecar.suffix().control(Kind::ProviderHeld).is_some()
        || sidecar.response_transaction() != [0; 16]
    {
        return Ok(match sidecar.suffix().phase() {
            2 => 5,
            3 => 4,
            4 | 10 => 3,
            5 | 11 => 2,
            6 | 12 => 1,
            _ => return Err(state_error("native Root v2 held prefix geometry")),
        });
    }
    let root_needed = u32::from(sidecar.disposition().is_none());
    let signature_needed = u32::from(
        sidecar
            .suffix()
            .prepared()
            .is_some_and(|control| control.kind() == Kind::RootClosed)
            || (sidecar.disposition().is_none()
                && sidecar.suffix().control(Kind::RootPrepared).is_some()),
    );
    let (replacement_needed, inventory_needed) = match &attempt.state {
        ProviderAttemptStateV2::Reserved => (1, 2),
        ProviderAttemptStateV2::AbandonedIndeterminate { resolution: None, .. } => {
            let head = graph.legacy.provider_heads.get(&(attempt.scope.holder_authority_id, attempt.scope.provider_authority_id))
                .ok_or_else(|| state_error("native Root v2 recovery head absent"))?;
            let barrier = head.recovery_barrier.as_ref().ok_or_else(|| state_error("native Root v2 original barrier absent"))?;
            if barrier.root_attempt.id != attempt_id || barrier.recovery_inventory_tail.is_some() {
                return Err(state_error("native Root v2 recovery exceeds original finite Inventory prefix"));
            }
            let inventory_needed = match head.pending_attempt {
                None => 2,
                Some(pending) => {
                    let inventory = graph.legacy.provider_attempts.get(&pending.id)
                        .filter(|inventory| inventory.revision == pending.revision && inventory.record_digest == pending.record_digest)
                        .ok_or_else(|| state_error("native Root v2 exact pending Inventory absent"))?;
                    if inventory.method != crate::mount_source_acquisition_state::ProviderMethodV2::Inventory
                        || !matches!(inventory.state, ProviderAttemptStateV2::Reserved)
                        || !matches!(&inventory.intent, crate::mount_source_acquisition_state::ProviderIntentV2::Inventory { value } if value.recovery_root_attempt_id == Some(attempt_id))
                    {
                        return Err(state_error("native Root v2 pending operation is not original Inventory"));
                    }
                    1
                }
            };
            (0, inventory_needed)
        }
        ProviderAttemptStateV2::AbandonedIndeterminate { resolution: Some(crate::mount_source_acquisition_state::RecoveryResolutionV2::RetryAcquireSameIntent { .. }), .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. } => (0, 0),
        _ => return Err(state_error("native Root v2 unproved no-interest prefix geometry")),
    };
    let recovery = root_needed + signature_needed + replacement_needed + inventory_needed + 1;
    if graph.data_class(attempt_id) == Some(RootNativeDataClassV2::LiveOriginal)
        && sidecar.disposition().is_none()
    {
        Ok(recovery.max(match sidecar.suffix().phase() {
            0 => 7,
            1 => 6,
            _ => recovery,
        }))
    } else {
        Ok(recovery)
    }
}

fn claims_graph(graph: &RootNativeHeldGraphV2) -> Result<RootNativeHeldGraphV1> {
    let mut canonical = graph.canonical.clone();
    let mut sidecars = graph.v1_sidecars.clone();
    for (attempt, sidecar) in &graph.sidecars {
        canonical.remove(&native_root_sidecar_key_v2(*attempt)?);
        canonical.insert(
            native_root_sidecar_key_v1(*attempt)?,
            sidecar.claims.to_canonical_bytes()?,
        );
        sidecars.insert(*attempt, sidecar.claims.clone());
    }
    Ok(RootNativeHeldGraphV1 {
        canonical,
        legacy: graph.legacy.clone(),
        sidecars,
    })
}

fn claims_puts(
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
    attempt: [u8; 32],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut result = puts.clone();
    if let Some(value) = result.remove(&native_root_sidecar_key_v2(attempt)?) {
        let sidecar = RootNativeHeldSidecarV2::from_canonical_bytes(
            &native_root_sidecar_key_v2(attempt)?,
            &value,
        )?;
        result.insert(
            native_root_sidecar_key_v1(attempt)?,
            sidecar.claims.to_canonical_bytes()?,
        );
    }
    Ok(result)
}

fn map_kind(kind: RootNativeTransitionKindV1) -> RootNativeTransitionKindV2 {
    match kind {
        RootNativeTransitionKindV1::PreparedAssertionRecorded => {
            RootNativeTransitionKindV2::PreparedAssertionRecorded
        }
        RootNativeTransitionKindV1::PreparedStored => RootNativeTransitionKindV2::PreparedStored,
        RootNativeTransitionKindV1::HeldStored => RootNativeTransitionKindV2::HeldStored,
        RootNativeTransitionKindV1::ResponseDispositionRecorded => {
            RootNativeTransitionKindV2::ResponseDispositionRecorded
        }
        RootNativeTransitionKindV1::AcceptedAssertionRecorded => {
            RootNativeTransitionKindV2::AcceptedAssertionRecorded
        }
        RootNativeTransitionKindV1::ClosedAssertionRecorded => {
            RootNativeTransitionKindV2::ClosedAssertionRecorded
        }
        RootNativeTransitionKindV1::DispositionStored => {
            RootNativeTransitionKindV2::DispositionStored
        }
        RootNativeTransitionKindV1::TerminalRecorded => {
            RootNativeTransitionKindV2::TerminalRecorded
        }
        RootNativeTransitionKindV1::TerminalAckStored => {
            RootNativeTransitionKindV2::TerminalAckStored
        }
        RootNativeTransitionKindV1::Duplicate => RootNativeTransitionKindV2::Duplicate,
    }
}
