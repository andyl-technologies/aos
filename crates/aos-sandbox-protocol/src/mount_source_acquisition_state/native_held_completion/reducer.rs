//! Exact Root before/after transition validation and canonical proposal bytes.
//!
//! A proposal contains only concrete namespace40 puts. The real writer must
//! independently establish original admission, transaction identity, held cuts,
//! signature eligibility and actual readback before applying these bytes. No
//! encoded proposal is a protected mutation or FD-acceptance permit.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldSectionTagV1 as Tag,
    frame::SignedNativeHeldControlV1,
    recovery::{NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1},
};

use super::graph::{original_rows, terminal_control};
use super::{
    RootNativeAdmissionBindingV1, RootNativeHeldGraphV1, RootNativeHeldSidecarV1,
    native_root_sidecar_key_v1,
};
use crate::mount_source_acquisition_state::{
    MountSourceAcquisitionStateV2, ProviderAttemptStateV2, ProviderStatusV2, RecordRefV2, Result,
    SourceProviderQueryAttemptV2, SourceProviderSessionV2, StoredRecordV2, acquisition_key,
    format::state_error, projection_entries, projection_from_entries, provider_attempt_key,
    provider_head_key, record_digest,
};

/// Names one closed native Root transaction, never a caller-selected scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootNativeTransitionKindV1 {
    /// Atomically reserves the original graph and its exact phase0 sidecar.
    PreparedAssertionRecorded,
    /// Stores the exact signed successor of the prepared original1.
    PreparedStored,
    /// Retains the original signed Provider3 before consuming its response.
    HeldStored,
    /// Records the exact original response CAS and its concrete companions.
    ResponseDispositionRecorded,
    /// Records the irreversible Accepted assertion and its unsigned hot4.
    AcceptedAssertionRecorded,
    /// Records irreversible Closed while preserving all prior response history.
    ClosedAssertionRecorded,
    /// Stores the exact signed hot4/8 already prepared under its fixed signer.
    DispositionStored,
    /// Records original7 or current10 terminal settlement and unsigned13.
    TerminalRecorded,
    /// Stores exact13 or current own9(mode3) as the one terminal acknowledgement.
    TerminalAckStored,
    /// Reproduces the exact entire before snapshot without any new append.
    Duplicate,
}

/// Describes validated exact native Root puts without granting journal authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeHeldTransitionV1 {
    /// Names the concrete closed transition that produced these bytes.
    pub kind: RootNativeTransitionKindV1,
    /// Retains the caller's actual transaction identity for real-owner readback.
    pub transaction_id: [u8; 16],
    /// Lists only changed namespace40 keys and their full canonical after values.
    pub puts: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Retains exact canonical before values, with `None` for genuine absence.
    pub before_images: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Bounds the remaining native Root appends without adding a late grant.
    pub maximum_remaining_transactions: u32,
    /// Binds the exact phase0 reservation for the independent capacity adapter.
    pub admission_binding: Option<RootNativeAdmissionBindingV1>,
}

/// Checks one complete native Root before/after graph and derives exact puts.
///
/// The supplied graphs must come from [`super::validate_native_root_graph_v1`].
/// Their validated data is not proof of protected provenance. On response CAS,
/// `transaction_id` must be the actual retained journal transaction ID; the pure
/// comparison prevents a different ID from being inserted into the sidecar.
///
/// # Errors
///
/// Rejects missing/removed rows, rewrites of unrelated keys or immutable fields,
/// illegal phases, altered archives/preparations, wrong CAS companions or identity.
pub fn validate_native_root_transition_v1(
    before: &RootNativeHeldGraphV1,
    after: &RootNativeHeldGraphV1,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<RootNativeHeldTransitionV1> {
    let next = after
        .sidecars
        .get(&mount_attempt)
        .ok_or_else(|| state_error("native Root successor sidecar absent"))?;
    let old = before.sidecars.get(&mount_attempt);
    if before.canonical == after.canonical {
        return Ok(RootNativeHeldTransitionV1 {
            kind: RootNativeTransitionKindV1::Duplicate,
            transaction_id,
            puts: BTreeMap::new(),
            before_images: BTreeMap::new(),
            maximum_remaining_transactions: remaining(next),
            admission_binding: None,
        });
    }
    if transaction_id == [0; 16] {
        return Err(state_error("native Root actual transaction ID absent"));
    }

    let sidecar_key = native_root_sidecar_key_v1(mount_attempt)?;
    let mut puts = BTreeMap::new();
    if before
        .canonical
        .keys()
        .any(|key| !after.canonical.contains_key(key))
    {
        return Err(state_error(
            "native Root transition removes retained records",
        ));
    }
    for (key, value) in &after.canonical {
        if before.canonical.get(key) != Some(value) {
            puts.insert(key.clone(), value.clone());
        }
    }
    let mut admission_binding = None;
    let kind = match old {
        None => {
            if next.suffix.phase() != 0 || next.response_transaction != [0; 16] {
                return Err(state_error(
                    "native Root initial exact reservation-sidecar append",
                ));
            }
            admission_binding = Some(super::admission::validate_admission(
                before, after, next, &puts,
            )?);
            RootNativeTransitionKindV1::PreparedAssertionRecorded
        }
        Some(old) => {
            preserve_immutable(old, next)?;
            let kind = classify(old, next)?;
            if kind == RootNativeTransitionKindV1::ResponseDispositionRecorded {
                validate_response_cas(before, after, old, next, transaction_id, &puts)?;
            } else if puts.len() != 1 || !puts.contains_key(&sidecar_key) {
                return Err(state_error(
                    "native Root sidecar transition changed unrelated bytes",
                ));
            }
            validate_slot_update(old, next, kind)?;
            kind
        }
    };
    let before_images = puts
        .keys()
        .map(|key| (key.clone(), before.canonical.get(key).cloned()))
        .collect();
    Ok(RootNativeHeldTransitionV1 {
        kind,
        transaction_id,
        puts,
        before_images,
        maximum_remaining_transactions: remaining(next),
        admission_binding,
    })
}

/// Validates a cold metadata transition without recapturing an original flight.
///
/// This separate recovery entry refuses every new original-flight preparation,
/// receive, response CAS or Accepted assertion. Existing Accepted history may
/// only settle its already recorded disposition and terminal wait.
///
/// # Errors
///
/// Returns the same graph/transition errors as the original-flight validator and
/// rejects any transition requiring continuous original FD/session/clock custody.
pub fn validate_native_root_cold_transition_v1(
    before: &RootNativeHeldGraphV1,
    after: &RootNativeHeldGraphV1,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<RootNativeHeldTransitionV1> {
    let proposal =
        validate_native_root_transition_v1(before, after, mount_attempt, transaction_id)?;
    if matches!(
        proposal.kind,
        RootNativeTransitionKindV1::PreparedAssertionRecorded
            | RootNativeTransitionKindV1::PreparedStored
            | RootNativeTransitionKindV1::HeldStored
            | RootNativeTransitionKindV1::ResponseDispositionRecorded
            | RootNativeTransitionKindV1::AcceptedAssertionRecorded
            | RootNativeTransitionKindV1::DispositionStored
    ) {
        return Err(state_error(
            "native Root cold metadata cannot recreate original hot stages",
        ));
    }
    if proposal.kind == RootNativeTransitionKindV1::TerminalAckStored
        && after
            .sidecars
            .get(&mount_attempt)
            .and_then(|sidecar| sidecar.suffix.controls().last())
            .is_none_or(|control| control.kind() != Kind::RootRecoveryQuery)
    {
        return Err(state_error(
            "native Root cold ACK requires own current mode3, not original hot13",
        ));
    }
    Ok(proposal)
}

pub(super) fn preserve_immutable(
    old: &RootNativeHeldSidecarV1,
    next: &RootNativeHeldSidecarV1,
) -> Result<()> {
    if old.original_scope != next.original_scope
        || (old.response_transaction != [0; 16]
            && old.response_transaction != next.response_transaction)
        || (old.disposition.is_some() && old.disposition != next.disposition)
        || (old.settlement.is_some() && old.settlement != next.settlement)
        || (old.terminal_verifier.is_some() && old.terminal_verifier != next.terminal_verifier)
        || !next.suffix.controls().starts_with(old.suffix.controls())
    {
        return Err(state_error(
            "native Root transition rewrites irreversible history",
        ));
    }
    Ok(())
}

pub(super) fn classify(
    old: &RootNativeHeldSidecarV1,
    next: &RootNativeHeldSidecarV1,
) -> Result<RootNativeTransitionKindV1> {
    use RootNativeTransitionKindV1 as Transition;
    match (old.suffix.phase(), next.suffix.phase()) {
        (0, 1) => Ok(Transition::PreparedStored),
        (1, 2) => Ok(Transition::HeldStored),
        (2, 3) => Ok(Transition::ResponseDispositionRecorded),
        (3, 4) => Ok(Transition::AcceptedAssertionRecorded),
        (0..=3, 10) => Ok(Transition::ClosedAssertionRecorded),
        (4, 5) | (10, 11) => Ok(Transition::DispositionStored),
        (4 | 5, 6) | (10 | 11, 12) => Ok(Transition::TerminalRecorded),
        (6, 7) | (12, 13) => Ok(Transition::TerminalAckStored),
        _ => Err(state_error("native Root illegal durable phase transition")),
    }
}

pub(super) fn validate_slot_update(
    old: &RootNativeHeldSidecarV1,
    next: &RootNativeHeldSidecarV1,
    kind: RootNativeTransitionKindV1,
) -> Result<()> {
    use RootNativeTransitionKindV1 as Transition;
    let added = &next.suffix.controls()[old.suffix.controls().len()..];
    let expected: &[Kind] = match kind {
        Transition::PreparedStored => &[Kind::RootPrepared],
        Transition::HeldStored => &[Kind::ProviderHeld],
        Transition::DispositionStored if next.suffix.phase() == 5 => &[Kind::RootAccepted],
        Transition::DispositionStored => &[Kind::RootClosed],
        Transition::TerminalRecorded => &[],
        Transition::TerminalAckStored => &[],
        _ => &[],
    };
    if matches!(kind, Transition::TerminalRecorded) {
        if added.len() != 1
            || !matches!(
                added[0].kind(),
                Kind::ProviderSettled | Kind::ProviderRecoveryState
            )
            || next
                .suffix
                .prepared()
                .is_none_or(|prepared| prepared.kind() != Kind::RootTerminalRecorded)
        {
            return Err(state_error(
                "native Root exact terminal proof and ACK preparation",
            ));
        }
    } else if kind == Transition::TerminalAckStored {
        if added.len() != 1
            || !matches!(
                added[0].kind(),
                Kind::RootTerminalRecorded | Kind::RootRecoveryQuery
            )
            || next.suffix.prepared().is_some()
        {
            return Err(state_error("native Root exact terminal ACK store"));
        }
        if added[0].kind() == Kind::RootTerminalRecorded {
            require_signed_preparation(old, &added[0])?;
        } else {
            let q = NativeHeldRecoveryQueryV1::from_canonical_bytes(
                added[0]
                    .section(Tag::RecoveryQuery)
                    .ok_or_else(|| state_error("native Root mode3 query absent"))?,
            )
            .map_err(|_| state_error("native Root mode3 query"))?;
            if q.mode != NativeHeldRecoveryModeV1::RecordRootTerminal {
                return Err(state_error("native Root terminal ACK mode"));
            }
        }
    } else {
        if added
            .iter()
            .map(SignedNativeHeldControlV1::kind)
            .collect::<Vec<_>>()
            != expected
        {
            return Err(state_error("native Root exact archive insertion"));
        }
        if matches!(
            kind,
            Transition::PreparedStored | Transition::DispositionStored
        ) {
            require_signed_preparation(old, &added[0])?;
            if next.suffix.prepared().is_some() {
                return Err(state_error(
                    "native Root signature store did not clear preparation",
                ));
            }
        }
        if kind == Transition::AcceptedAssertionRecorded
            && next
                .suffix
                .prepared()
                .is_none_or(|prepared| prepared.kind() != Kind::RootAccepted)
        {
            return Err(state_error(
                "native Root Accepted unsigned preparation absent",
            ));
        }
        if kind == Transition::ClosedAssertionRecorded
            && next
                .suffix
                .prepared()
                .is_some_and(|prepared| prepared.kind() != Kind::RootClosed)
        {
            return Err(state_error("native Root Closed unsigned preparation kind"));
        }
        if matches!(
            kind,
            Transition::HeldStored | Transition::ResponseDispositionRecorded
        ) && next.suffix.prepared().is_some()
        {
            return Err(state_error("native Root unexpected preparation checkpoint"));
        }
    }
    if !matches!(kind, Transition::ResponseDispositionRecorded)
        && old.response_transaction != next.response_transaction
    {
        return Err(state_error(
            "native Root CAS identity changed outside response cut",
        ));
    }
    if kind == Transition::TerminalRecorded && terminal_control(next).is_none() {
        return Err(state_error("native Root terminal carrier absent"));
    }
    Ok(())
}

fn require_signed_preparation(
    old: &RootNativeHeldSidecarV1,
    signed: &SignedNativeHeldControlV1,
) -> Result<()> {
    if old
        .suffix
        .prepared()
        .is_none_or(|prepared| prepared != signed.prepared())
    {
        return Err(state_error(
            "native Root stored signature changed prepared bytes/signer",
        ));
    }
    Ok(())
}

pub(super) fn validate_response_cas(
    before: &RootNativeHeldGraphV1,
    after: &RootNativeHeldGraphV1,
    old: &RootNativeHeldSidecarV1,
    next: &RootNativeHeldSidecarV1,
    transaction_id: [u8; 16],
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let (original, session) = original_rows(before, old)?;
    let (consumed, _) = original_rows(after, next)?;
    if old.response_transaction != [0; 16]
        || next.response_transaction != transaction_id
        || original.revision != 1
        || consumed.revision != 2
        || !matches!(original.state, ProviderAttemptStateV2::Reserved)
        || !matches!(
            consumed.state,
            ProviderAttemptStateV2::DispositionConsumed {
                status: ProviderStatusV2::Complete,
                ..
            }
        )
    {
        return Err(state_error(
            "native Root actual response CAS identity/state",
        ));
    }
    validate_response_companions(
        &before.legacy,
        &after.legacy,
        original,
        consumed,
        session,
        true,
        native_root_sidecar_key_v1(original.attempt_id)?,
        puts,
    )
}

/// Shares exact immutable lineage/Head checks, without granting a status choice.
pub(super) fn validate_response_companions(
    before: &MountSourceAcquisitionStateV2,
    after: &MountSourceAcquisitionStateV2,
    original: &SourceProviderQueryAttemptV2,
    consumed: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    complete: bool,
    sidecar_key: Vec<u8>,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let mut reconstructed = consumed.clone();
    reconstructed.revision = original.revision;
    reconstructed.record_digest = original.record_digest;
    reconstructed.state = ProviderAttemptStateV2::Reserved;
    if reconstructed != *original {
        return Err(state_error(
            "native Root response changed immutable attempt",
        ));
    }

    let acquisition_id = original.owner.owner_id();
    let previous_row = before
        .acquisitions
        .get(&acquisition_id)
        .ok_or_else(|| state_error("native Root response before acquisition absent"))?;
    let next_row = after
        .acquisitions
        .get(&acquisition_id)
        .ok_or_else(|| state_error("native Root response after acquisition absent"))?;
    let previous_ref = RecordRefV2 {
        id: original.attempt_id,
        revision: original.revision,
        record_digest: original.record_digest,
    };
    let consumed_ref = RecordRefV2 {
        id: consumed.attempt_id,
        revision: consumed.revision,
        record_digest: consumed.record_digest,
    };
    let mut expected_row = previous_row.clone();
    expected_row.revision = previous_row
        .revision
        .checked_add(1)
        .ok_or_else(|| state_error("native Root acquisition revision overflow"))?;
    if expected_row.acquire_lineage.tail != previous_ref {
        return Err(state_error("native Root exact Acquire lineage predecessor"));
    }
    if expected_row.acquire_lineage.root == previous_ref {
        expected_row.acquire_lineage.root = consumed_ref;
    }
    expected_row.acquire_lineage.tail = consumed_ref;
    if complete {
        expected_row.acquire_terminal_attempt = Some(consumed_ref);
        // The unchanged complete legacy graph validator has independently verified
        // this evidence against the exact signed response, lease and descriptor.
        expected_row.evidence = next_row.evidence.clone();
    }
    expected_row.record_digest = next_row.record_digest;
    if expected_row != *next_row {
        return Err(state_error(
            "native Root response changed acquisition outside exact evidence/lineage",
        ));
    }

    let head_id = (
        session.scope.holder_authority_id,
        session.scope.provider_authority_id,
    );
    let previous_head = before
        .provider_heads
        .get(&head_id)
        .ok_or_else(|| state_error("native Root response before head absent"))?;
    let next_head = after
        .provider_heads
        .get(&head_id)
        .ok_or_else(|| state_error("native Root response after head absent"))?;
    if previous_head.pending_attempt != Some(previous_ref) {
        return Err(state_error(
            "native Root response head did not own original reservation",
        ));
    }
    let mut expected_head = previous_head.clone();
    expected_head.revision = previous_head
        .revision
        .checked_add(1)
        .ok_or_else(|| state_error("native Root head revision overflow"))?;
    expected_head.next_response_sequence = previous_head
        .next_response_sequence
        .checked_add(1)
        .ok_or_else(|| state_error("native Root response sequence overflow"))?;
    if expected_head.next_response_sequence != previous_head.next_request_sequence {
        return Err(state_error("native Root response head sequence"));
    }
    expected_head.pending_attempt = None;
    let previous_entries = projection_entries(previous_head.scope, &before.acquisitions);
    let next_entries = projection_entries(previous_head.scope, &after.acquisitions);
    if previous_entries != next_entries {
        expected_head.current_projection_epoch = previous_head
            .current_projection_epoch
            .checked_add(1)
            .ok_or_else(|| state_error("native Root projection epoch overflow"))?;
        expected_head.current_projection_digest = projection_from_entries(
            previous_head.scope,
            expected_head.current_projection_epoch,
            &next_entries,
        )?
        .digest;
        expected_head.last_reconciliation = None;
    }
    expected_head.record_digest = record_digest(&StoredRecordV2::ProviderHead {
        value: expected_head.clone(),
    })?;
    if expected_head != *next_head {
        return Err(state_error(
            "native Root response changed unrelated head fields",
        ));
    }

    let exact_keys = [
        sidecar_key,
        provider_attempt_key(original.attempt_id),
        acquisition_key(acquisition_id),
        provider_head_key(head_id.0, head_id.1),
    ];
    if puts.len() != exact_keys.len() || exact_keys.iter().any(|key| !puts.contains_key(key)) {
        return Err(state_error(
            "native Root response CAS exact four native keys",
        ));
    }
    Ok(())
}

fn remaining(sidecar: &RootNativeHeldSidecarV1) -> u32 {
    match sidecar.suffix.phase() {
        0 => 7,
        1 => 6,
        2 => 5,
        3 => 4,
        4 => 3,
        5 => 2,
        6 => 1,
        // Missing original1 cannot settle through this barrier. Preserve the
        // unresolved floor until a separately owned no-dispatch cleanup proves
        // terminality; this data profile never releases it by inference.
        10 => 3,
        11 => 2,
        12 => 1,
        7 | 13 => 0,
        _ => 0,
    }
}
