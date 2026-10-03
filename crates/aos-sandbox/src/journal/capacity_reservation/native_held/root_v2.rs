//! Root V2 DATA framing over actual complete Protocol reducer edges.
//!
//! The original phase0 graph is borrowed historical DATA, not current-owner
//! authority. It preserves unsignedRoot1 when a legal cold Closed successor no
//! longer retains it. Current graphs are independently checked by Protocol;
//! exact original cut/scope joins never substitute historical rows for them.

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeDataClassV2, RootNativeHeldGraphV2, RootNativeHeldTransitionV2,
    RootNativeNoInterestTerminalV1, RootNativeTransitionKindV2 as Kind,
    validate_native_root_transition_v2,
};
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    validate_transaction,
};
use super::super::digest_bytes;
use super::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityChangeV3, NativeHeldCapacityPurposeV3,
    NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3, NativeHeldCapacitySuffixV2, invalid,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RootCapacityBindingV2 {
    mount_attempt: [u8; 32],
    attempt_digest: [u8; 32],
    operation: [u8; 16],
    signed_request: [u8; 32],
    root_prepared: [u8; 32],
    head: [u8; 32],
    admission: [u8; 16],
}

impl RootCapacityBindingV2 {
    pub(super) const fn mount_attempt(&self) -> [u8; 32] {
        self.mount_attempt
    }

    pub(super) fn require_request(
        &self,
        request: NativeHeldCapacityRequestV3,
        admission: [u8; 16],
    ) -> Result<(), JournalError> {
        if request.purpose != NativeHeldCapacityPurposeV3::Root
            || request.owner_id != self.mount_attempt
            || request.owner_digest != self.attempt_digest
            || request.operation_id != self.operation
            || request.artifact_digest != self.signed_request
            || request.checkpoint_digest != self.root_prepared
            || request.chain_head_digest != self.head
            || admission != self.admission
        {
            return Err(invalid(
                "native V2 floor does not join original admission DATA",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct RootCapacityEdgeV2<'graph> {
    pub(super) original: &'graph RootNativeHeldGraphV2,
    pub(super) before: &'graph RootNativeHeldGraphV2,
    pub(super) after: &'graph RootNativeHeldGraphV2,
    pub(super) binding: RootCapacityBindingV2,
    pub(super) before_remaining: u32,
    pub(super) after_remaining: u32,
    pub(super) kind: Kind,
}

/// Frames original Root V2 reservation plus native8 using measured continuations.
///
/// The public proposal is rederived and compared in full. Both actual complete
/// alternatives begin at this exact original successor graph and fund Root7 in
/// the original six/seven-record append. This returns DATA, never admission or
/// a protected writer/signing/currentness scope.
/// The measured pair does not establish exhaustive legal branch maxima; the
/// future actual original producer must derive them and all-floor headroom.
///
/// # Errors
///
/// Rejects a stale/forged proposal, nonoriginal phase0, foreign original bindings,
/// missing/short measured alternatives, enlarged/changed floor or journal limit.
#[allow(clippy::too_many_arguments)]
pub fn root_native_capacity_admission_v2(
    proposal: &RootNativeHeldTransitionV2,
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
    capacity: &NativeHeldCapacityRecordV3,
    normal: &NativeHeldCapacitySuffixV2<'_>,
    cold: &NativeHeldCapacitySuffixV2<'_>,
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    require_proposal(proposal, before, after, mount_attempt, transaction_id)?;
    if proposal.kind != Kind::PreparedAssertionRecorded
        || proposal.maximum_remaining_transactions != 7
        || proposal.admission_binding.is_none()
        || !(5..=6).contains(&proposal.puts.len())
    {
        return Err(invalid(
            "native V2 capacity admission is not original atomic phase0",
        ));
    }
    let binding = original_binding(after, after, mount_attempt)?;
    require_floor(capacity)?;
    binding.require_request(capacity.request(), capacity.admission_transaction_id())?;
    if capacity.request().future_transactions != 7
        || capacity.admission_transaction_id() != transaction_id
        || normal
            .root_start()
            .is_none_or(|edge| edge.before.canonical_records() != after.canonical_records())
        || cold
            .root_start()
            .is_none_or(|edge| edge.before.canonical_records() != after.canonical_records())
        || NativeHeldCapacityRecordV3::from_suffixes_v2(
            capacity.request(),
            transaction_id,
            normal,
            cold,
            limits,
        )? != *capacity
    {
        return Err(invalid(
            "native V2 original floor is not the measured complete Root7",
        ));
    }
    let mut records = proposal_records(proposal);
    records.push(capacity.to_journal_record());
    let transaction = JournalTransaction::new(transaction_id, records)?;
    validate_transaction(&transaction, limits)?;
    Ok(transaction)
}

/// Adapts one rederived Root V2 edge while borrowing its original phase0 context.
///
/// Complete current graphs remain the reducer inputs. The separate original
/// graph retains the unsignedRoot1 checkpoint even when a legal Closed graph
/// discards it. Neither this historical context nor graph validation is IO or
/// protected origin/currentness proof.
/// Caller-retained DATA cannot supply cold-restart provenance when Root1 is no
/// longer retained; a future runtime owner must retain or rederive it genuinely.
/// Resolved Inventory/no-interest prefixes that also permit a later Source
/// terminal may have a nondecreasing owner ceiling and remain unsupported here.
/// Their ordinary-versus-native funding/exclusion contract is not established;
/// this adapter refuses them rather than enlarging immutable Root7 credit.
///
/// # Errors
///
/// Rejects a stale proposal, admission/duplicate, different original cut/scope,
/// missing phase0 Root1, unrelated bytes or a nondecreasing reducer ceiling.
pub fn root_native_capacity_append_v2<'graph>(
    proposal: &RootNativeHeldTransitionV2,
    before: &'graph RootNativeHeldGraphV2,
    after: &'graph RootNativeHeldGraphV2,
    original: &'graph RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<NativeHeldCapacityAppendV2<'graph>, JournalError> {
    require_proposal(proposal, before, after, mount_attempt, transaction_id)?;
    if matches!(
        proposal.kind,
        Kind::PreparedAssertionRecorded | Kind::Duplicate
    ) || proposal.admission_binding.is_some()
    {
        return Err(invalid("native V2 continuation cannot admit or repeat"));
    }
    let binding = original_binding(original, before, mount_attempt)?;
    if binding != original_binding(original, after, mount_attempt)? {
        return Err(invalid("native V2 continuation changed original binding"));
    }
    let before_remaining = remaining(before, mount_attempt, transaction_id)?;
    if proposal.maximum_remaining_transactions >= before_remaining {
        return Err(invalid(
            "native V2 reducer continuation count did not decrease",
        ));
    }
    let changes = proposal
        .puts
        .iter()
        .map(|(key, value)| {
            NativeHeldCapacityChangeV3::new(
                key.clone(),
                proposal
                    .before_images
                    .get(key)
                    .ok_or(invalid("native V2 before image absent"))?
                    .clone(),
                Some(value.clone()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    NativeHeldCapacityAppendV2::root(
        RootCapacityEdgeV2 {
            original,
            before,
            after,
            binding,
            before_remaining,
            after_remaining: proposal.maximum_remaining_transactions,
            kind: proposal.kind,
        },
        transaction_id,
        changes,
    )
}

/// Frames one actual V2 continuation or its distinct legitimate final deletion.
///
/// Old/next floors retain the exact original cut, Root1 and admission identity.
/// No-interest cleanup additionally joins the marker to the old native8 ID and
/// SHA256 of its exact canonical266-byte value, using the existing floor digest
/// contract. Terminal ACK is a separate legal final path. This creates DATA only.
///
/// # Errors
///
/// Rejects stale/foreign bindings, changed admission, nondecreasing counts,
/// early deletion, wrong marker ID/digest, enlarged floor or full framed limits.
#[allow(clippy::too_many_arguments)]
pub fn root_native_capacity_transition_v2(
    proposal: &RootNativeHeldTransitionV2,
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    original: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
    old: &NativeHeldCapacityRecordV3,
    next: Option<&NativeHeldCapacityRecordV3>,
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    let append = root_native_capacity_append_v2(
        proposal,
        before,
        after,
        original,
        mount_attempt,
        transaction_id,
    )?;
    let edge = append
        .root_edge()
        .ok_or(invalid("native V2 checked Root edge absent"))?;
    require_floor(old)?;
    edge.binding
        .require_request(old.request(), old.admission_transaction_id())?;
    if old.request().future_transactions != edge.before_remaining {
        return Err(invalid(
            "native V2 old floor count does not describe actual prefix",
        ));
    }
    match next {
        Some(next) => {
            require_floor(next)?;
            edge.binding
                .require_request(next.request(), next.admission_transaction_id())?;
            if proposal.maximum_remaining_transactions == 0
                || next.request().future_transactions != proposal.maximum_remaining_transactions
            {
                return Err(invalid("native V2 successor floor count or early final"));
            }
        }
        None if proposal.maximum_remaining_transactions == 0
            && matches!(
                proposal.kind,
                Kind::TerminalAckStored | Kind::NativeNoInterestCleanup
            ) => {}
        None => return Err(invalid("native V2 premature floor deletion")),
    }
    if proposal.kind == Kind::NativeNoInterestCleanup {
        let marker = after
            .sidecars()
            .get(&mount_attempt)
            .and_then(|sidecar| sidecar.no_interest_terminal())
            .ok_or(invalid("native V2 actual no-interest marker absent"))?;
        require_retired_floor(marker, old)?;
    }
    super::transfer::frame_transfer(
        transaction_id,
        append.owner_records(),
        old,
        next,
        limits,
        (
            "native Root consumed records",
            "native Root complete transferred suffix",
        ),
    )
}

fn require_retired_floor(
    marker: &RootNativeNoInterestTerminalV1,
    old: &NativeHeldCapacityRecordV3,
) -> Result<(), JournalError> {
    require_floor(old)?;
    let record = old.to_journal_record();
    let value = record.value().ok_or(JournalError::InvalidTransaction)?;
    if marker.retired_capacity() != (old.reservation_id(), digest_bytes(value)) {
        return Err(invalid(
            "native V2 no-interest marker does not retire exact old floor",
        ));
    }
    Ok(())
}

fn require_proposal(
    proposal: &RootNativeHeldTransitionV2,
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<(), JournalError> {
    let actual = validate_native_root_transition_v2(before, after, mount_attempt, transaction_id)
        .map_err(|_| invalid("native V2 actual Protocol transition invalid"))?;
    if &actual != proposal {
        return Err(invalid(
            "native V2 public proposal differs from actual reducer",
        ));
    }
    Ok(())
}

fn remaining(
    graph: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<u32, JournalError> {
    // Protocol's duplicate DATA projection exposes the same exact remaining
    // ceiling without reimplementing its original/cold owner phase calculation.
    Ok(
        validate_native_root_transition_v2(graph, graph, attempt, transaction_id)
            .map_err(|_| invalid("native V2 original prefix geometry invalid"))?
            .maximum_remaining_transactions,
    )
}

fn original_binding(
    original: &RootNativeHeldGraphV2,
    current: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
) -> Result<RootCapacityBindingV2, JournalError> {
    let phase0 = original
        .sidecars()
        .get(&attempt)
        .ok_or(invalid("native V2 original phase0 sidecar absent"))?;
    let now = current
        .sidecars()
        .get(&attempt)
        .ok_or(invalid("native V2 current original sidecar absent"))?;
    let cut = phase0.admission_cut();
    let prepared = phase0
        .suffix()
        .prepared()
        .ok_or(invalid("native V2 original unsignedRoot1 absent"))?;
    if phase0.suffix().phase() != 0
        || prepared.kind() != NativeHeldControlKindV1::RootPrepared
        || phase0.response_transaction() != [0; 16]
        || phase0.disposition().is_some()
        || phase0.disposition_cut().is_some()
        || phase0.settlement().is_some()
        || phase0.terminal_verifier().is_some()
        || phase0.no_interest_terminal().is_some()
        || original.data_class(attempt) != Some(RootNativeDataClassV2::LiveOriginal)
        || phase0.original_scope() != now.original_scope()
        || cut != now.admission_cut()
    {
        return Err(invalid(
            "native V2 context is not the exact original phase0 cut/scope",
        ));
    }
    cut.reconstruct(current.legacy(), attempt).map_err(|_| {
        invalid("native V2 original cut cannot reconstruct exact retained originals")
    })?;
    let captured = cut
        .reconstruct(original.legacy(), attempt)
        .map_err(|_| invalid("native V2 phase0 cut cannot reconstruct original companions"))?;
    if captured
        .canonical_records()
        .iter()
        .any(|(key, value)| original.canonical_records().get(key) != Some(value))
    {
        return Err(invalid(
            "native V2 phase0 is not the exact captured admission successor",
        ));
    }
    let original_attempt = original
        .legacy()
        .provider_attempts
        .get(&attempt)
        .ok_or(invalid("native V2 original Attempt absent"))?;
    let current_attempt = current
        .legacy()
        .provider_attempts
        .get(&attempt)
        .ok_or(invalid(
            "native V2 current retained original Attempt absent",
        ))?;
    if original_attempt.signed_request != current_attempt.signed_request
        || original_attempt.signed_request_digest != current_attempt.signed_request_digest
        || cut.original_attempt(attempt).record_digest != original_attempt.record_digest
    {
        return Err(invalid(
            "native V2 current original request or Attempt changed",
        ));
    }
    if now
        .suffix()
        .control(NativeHeldControlKindV1::RootPrepared)
        .is_some_and(|one| one.prepared() != prepared)
        || (now.suffix().phase() == 0 && now.suffix().prepared() != Some(prepared))
    {
        return Err(invalid(
            "native V2 retained Root1 bytes differ from original context",
        ));
    }
    Ok(RootCapacityBindingV2 {
        mount_attempt: attempt,
        attempt_digest: cut.original_attempt(attempt).record_digest,
        operation: cut.acquisition().acquire.operation_id,
        signed_request: original_attempt.signed_request_digest,
        root_prepared: *prepared.digest().as_bytes(),
        head: cut.head().record_digest,
        admission: cut.capture_transaction(),
    })
}

fn require_floor(floor: &NativeHeldCapacityRecordV3) -> Result<(), JournalError> {
    let record = floor.to_journal_record();
    if NativeHeldCapacityRecordV3::from_journal_record(&record)? != *floor {
        return Err(invalid("native V2 exact canonical floor mismatch"));
    }
    Ok(())
}

fn proposal_records(proposal: &RootNativeHeldTransitionV2) -> Vec<JournalRecord> {
    proposal
        .puts
        .iter()
        .map(|(key, value)| {
            JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                key.clone(),
                value.clone(),
            )
        })
        .collect()
}

#[cfg(test)]
pub(super) mod tests;
