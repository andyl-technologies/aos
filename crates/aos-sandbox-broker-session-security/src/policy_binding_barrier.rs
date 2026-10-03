//! Held controller/source-domain/Cache/root cut for a closed policy binding.
//!
//! A future controller caller supplies its already-held controller journal.
//! This bridge opens source-domain and protected Cache custody in that order,
//! then acquires the root writer through the authenticated local exchange.
//! The held-cut exchange freezes Controller and source-domain mutations before
//! Q04 SUBMIT; Root retains its writer through signer proof and durable CAS.
//! It sends no release ACK. Cache still has process-local custody and rechecks.
//! A crash leaves Controller and source-domain journals frozen for exact Root
//! cold readback, whether Root committed or not. No production Create path calls
//! this bridge, and its observation cannot authorize publication or an effect.

use std::cell::Cell;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::cache_residency::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2, CacheOwnerReadbackChallengeV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOwnerV1,
    CacheResidencyWriterReadbackV2, DormantCacheOwnerV1, PinnedCacheOwnerReadbackSignerV1,
    verify_closed_cache_owner_readback_v2,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasBaseV2, ClosedPolicyRootCasObservationV2,
    PolicyCompilerInputV1, RootEffectAckV1, RootV8EffectAckV1, RootV8ReleasedProofV1,
    StagedClosedPolicyRootBaseV2, StagedClosedPolicySignerChallengeV2,
    clear_current_create_v8_successor_fences_v1, closed_policy_binding_digest_v2,
    closed_policy_effect_handoff_v2, compare_closed_policy_binding_hold_claims_v2,
    compare_closed_policy_binding_released_cache_claims_v2,
    current_parentless_create_compiler_input_v1,
    current_parentless_create_project_source_v1,
    propose_closed_current_create_explicit_policy_binding_v2, query_fixed_root_v8_settled_grant_v1,
    record_current_source_signer_challenge_v1, require_current_source_signer_challenge_v1,
    validate_current_create_controller_journal_v1,
    with_current_create_cache_signer_barrier_v5,
    with_current_create_cache_signer_release_barrier_v7,
    with_current_create_cache_signer_released_barrier_v8,
    with_current_create_cache_signer_terminal_barrier_v6,
    with_current_create_policy_source_barrier_v4,
    with_current_create_v8_owner_settlement_barrier_v9,
};
use aos_sandbox::{
    ControllerPolicyEffectAckV1, ControllerPolicyHoldV1, Journal, JournalError,
    journal::{
        CachePolicyHoldV1, ControllerPolicyV8AttemptV1, ControllerPolicyV8EffectAckV1,
        SourceDomainPolicyHoldV1,
    },
};
use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use ed25519_dalek::VerifyingKey;

use crate::cache_signer_exchange::request_controller_q04_cache_signer_readback_v3;
use crate::controller_hold_credential::with_process_controller_hold_signer_v1;
use crate::policy_authority_client::{
    ClosedPolicyBindingClientObservationV4, ClosedPolicyBindingPreviewV4,
    ClosedPolicyBindingSignerFlightV4, ClosedPolicyHeldCasCompletionV8,
    ClosedPolicyHeldCasReplayV8, ClosedPolicySourceWriterFlightV5,
    PolicyAuthorityExplicitHeadReceiptV4,
    PendingClosedPolicySourceWriterFlightV6, PendingClosedPolicySourceWriterFlightV7,
    PendingClosedPolicySourceWriterFlightV8, begin_staged_source_writer_held_flight_v6,
    begin_staged_source_writer_held_flight_v7, begin_staged_source_writer_held_flight_v8,
    commit_closed_policy_binding_v4, commit_staged_closed_policy_signer_flight_v4,
    inspect_staged_closed_policy_signer_flight_v4, inspect_staged_source_writer_flight_v5,
    preview_staged_closed_policy_binding_v4, recover_closed_policy_binding_decision_v5,
    recover_committed_source_held_binding_v8,
    stage_closed_policy_binding_base_v4,
};
use crate::policy_root_ack_client::acknowledge_held_root_effect_v1;
use crate::policy_root_ack_v8_client::{
    acknowledge_held_root_v8_effect, begin_held_root_v8_terminal_release,
    complete_held_root_v8_terminal, recover_root_v8_terminal_custody,
    require_exact_released_root_v8_replay, verify_exact_released_root_v8_custody,
};

/// Stages signed Root sources and constructs Controller-current proposal input.
///
/// This calls the existing fixed AOSPHQ4B endpoint once. Root durably issues its
/// stage nonce/epoch, then releases its writer before sending the receipt/base.
/// The verification keys check that response; they do not nominate Root's
/// stored head or signers. This function does not provision those keys.
///
/// The fixed Controller names and production limits are checked before Stage
/// and again after input construction; Stage itself still commits issuance.
///
/// The owned receipt, stage and input are DATA only. No Source/Cache ancestry
/// barrier, live Root hold, policy publication, V8 authority or public Create
/// completion is supplied. A caller must establish all missing original-owner
/// and live backend joins before later binding or effect work.
///
/// # Errors
///
/// Rejects an unsafe Controller journal, stale accepted Create or publisher
/// cut, failed Root stage exchange, expired/mismatched receipt, or failed input
/// constructor. There is no implicit stage retry. A transport failure may
/// follow durable issuance; the existing stage API does not return its local
/// socket/buffer prefix on error, so this function claims no retained Root
/// failure custody, rollback or debt settlement.
pub(crate) fn stage_fixed_parentless_create_compiler_input_v1(
    controller: &mut Journal,
    operation: OperationId,
    sandbox: SandboxId,
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
) -> io::Result<(
    PolicyAuthorityExplicitHeadReceiptV4,
    StagedClosedPolicyRootBaseV2,
    PolicyCompilerInputV1,
)> {
    validate_current_create_controller_journal_v1(controller).map_err(io::Error::other)?;
    let source = current_parentless_create_project_source_v1(controller, operation, sandbox)
        .map_err(io::Error::other)?;

    let (receipt, staged) =
        stage_closed_policy_binding_base_v4(deployment_verifying_key, project_verifying_key)?;
    if !receipt.matches_create_source(&source) {
        return Err(invalid_cut());
    }
    let input = current_parentless_create_compiler_input_v1(
        controller,
        operation,
        sandbox,
        receipt.head(),
        receipt.sources(),
        receipt.project(),
    )
    .map_err(io::Error::other)?;

    validate_current_create_controller_journal_v1(controller).map_err(io::Error::other)?;
    let current = current_parentless_create_project_source_v1(controller, operation, sandbox)
        .map_err(io::Error::other)?;
    if current.commitment() != source.commitment()
        || !receipt.matches_compiler_input(&current, &input)
    {
        return Err(invalid_cut());
    }
    Ok((receipt, staged, input))
}

/// Commits one held Q04 cut without opening public Create or effect handoff.
///
/// The caller retains Controller, Source, protected Cache, and physical Cache
/// writers. Root is last and holds its writer through both independent signer
/// proofs and the durable binding/head/held-decision transaction. An ambiguous
/// reply is accepted only after exact protected Root replay under these holds.
///
/// # Errors
///
/// Rejects stale owner custody, mismatched claims or signer proof, absent or
/// released Root decision, replay mismatch, or transport loss.
#[allow(clippy::too_many_arguments)]
pub fn commit_fixed_parentless_create_held_binding_v4(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<ClosedPolicyRootCasObservationV2> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, _, _, held| -> io::Result<_> {
            validate_staged_held_claims(
                proposed,
                staged,
                controller_hold,
                source_hold,
                held.hold(),
            )?;

            let cache_packet_verified = Cell::new(false);
            let outcome = commit_staged_closed_policy_signer_flight_v4(
                staged,
                proposed,
                source_hold,
                |challenge| {
                    let packet = request_verified_held_cache_packet(
                        physical,
                        held,
                        challenge,
                        cache_signer_uid,
                        controller_gid,
                        cache_signer,
                    )?;
                    cache_packet_verified.set(true);
                    Ok(packet)
                },
            );

            let observation = match outcome {
                Ok(committed) => {
                    if committed.binding() != controller_hold.binding()
                        || committed.handoff_epoch() != controller_hold.epoch()
                    {
                        return Err(invalid_cut());
                    }
                    ClosedPolicyRootCasObservationV2::from_replayed_fields(
                        committed.binding(),
                        committed.handoff_epoch(),
                    )
                    .map_err(io::Error::other)?
                }
                Err(_) => {
                    // A lost reply can follow a durable commit. Only the
                    // protected exact proposal and held decision resolve it.
                    if !cache_packet_verified.get() {
                        return Err(invalid_cut());
                    }
                    let (decision, recorded, _) = recover_closed_policy_binding_decision_v5(
                        controller_hold.binding(),
                        controller_hold.epoch(),
                    )?;
                    verify_exact_held_replay(
                        decision,
                        recorded.as_deref(),
                        proposed,
                        controller_hold.binding(),
                        controller_hold.epoch(),
                    )?
                }
            };
            Ok(observation)
        },
    )
    .map_err(io::Error::other)?
}

fn verify_exact_held_replay(
    decision: ClosedPolicyBindingDecisionV2,
    recorded: Option<&[u8]>,
    proposed: &[u8],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<ClosedPolicyRootCasObservationV2> {
    match decision {
        ClosedPolicyBindingDecisionV2::CommittedQualifiedHeld(observation)
            if recorded == Some(proposed)
                && observation.binding() == binding
                && observation.handoff_epoch() == epoch =>
        {
            Ok(observation)
        }
        _ => Err(invalid_cut()),
    }
}

fn held_policy_claims(
    controller: &Journal,
    source_domains: &ProtectedSourceDomainJournalOwnerV1,
) -> io::Result<(ControllerPolicyHoldV1, SourceDomainPolicyHoldV1)> {
    let controller_hold = controller
        .controller_policy_hold_v1()
        .map_err(io::Error::other)?
        .filter(|hold| hold.is_held())
        .ok_or_else(invalid_cut)?;
    let source_hold = source_domains
        .closed_policy_source_hold_v1()
        .map_err(io::Error::other)?
        .filter(|hold| hold.is_held())
        .ok_or_else(invalid_cut)?;
    Ok((controller_hold, source_hold))
}

fn validate_staged_held_claims(
    proposed: &[u8],
    staged: StagedClosedPolicyRootBaseV2,
    controller_hold: ControllerPolicyHoldV1,
    source_hold: SourceDomainPolicyHoldV1,
    cache_hold: CachePolicyHoldV1,
) -> io::Result<()> {
    compare_closed_policy_binding_hold_claims_v2(
        proposed,
        controller_hold,
        source_hold,
        cache_hold,
    )
    .map_err(io::Error::other)?;
    if staged.base().next_generation() != controller_hold.epoch() {
        return Err(invalid_cut());
    }
    Ok(())
}

fn request_verified_held_cache_packet(
    physical: &DormantCacheOwnerV1,
    held: &CacheResidencyWriterReadbackV2,
    challenge: StagedClosedPolicySignerChallengeV2,
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
    let snapshot = physical.held_snapshot().map_err(io::Error::other)?;
    let cache_challenge = CacheOwnerReadbackChallengeV1::new(challenge.nonce(), challenge.cut())
        .map_err(io::Error::other)?;
    let packet = request_controller_q04_cache_signer_readback_v3(
        challenge,
        cache_signer_uid,
        controller_gid,
        cache_signer,
        snapshot.owner_uid(),
    )?;
    let verified = verify_closed_cache_owner_readback_v2(
        &packet,
        cache_signer,
        cache_challenge,
        snapshot.owner_uid(),
    )
    .map_err(io::Error::other)?;
    if verified.hold() != held.hold() || verified.quota_digest() != held.quota_digest() {
        return Err(invalid_cut());
    }
    snapshot
        .require_verified_readback_v2(verified)
        .map_err(io::Error::other)?;
    Ok(packet)
}

/// Inspects a held Q04 signer flight without committing or releasing any owner.
///
/// The caller retains the Controller, Source, four Cache writers, and physical
/// Cache flock. Root takes its writer last and independently verifies Source
/// and Cache packets under one durable staged challenge. The packet and
/// physical claims are rechecked against the held local Cache snapshot before
/// the Root exchange completes. This result cannot authorize CAS or Create.
///
/// # Errors
///
/// Rejects changed held owners, stale stage or proposal, signer mismatch,
/// physical Cache mismatch, malformed Root reply, or transport loss.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fixed_parentless_create_staged_signer_flight_v4(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<ClosedPolicyBindingSignerFlightV4> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, _, _, held| -> io::Result<_> {
            validate_staged_held_claims(
                proposed,
                staged,
                controller_hold,
                source_hold,
                held.hold(),
            )?;
            let flight = inspect_staged_closed_policy_signer_flight_v4(
                staged,
                proposed,
                source_hold,
                |challenge| {
                    request_verified_held_cache_packet(
                        physical,
                        held,
                        challenge,
                        cache_signer_uid,
                        controller_gid,
                        cache_signer,
                    )
                },
            )?;
            let preview = flight.preview();
            if preview.binding() != controller_hold.binding()
                || preview.epoch() != controller_hold.epoch()
                || preview.project() != held.hold().project()
                || preview.partition() != held.hold().partition()
                || preview.cache_head() != held.hold().cache_head()
            {
                return Err(invalid_cut());
            }
            Ok(flight)
        },
    )
    .map_err(io::Error::other)?
}

/// Inspects the fresh Root-last Source V2 signer cut without submitting Q04.
///
/// Controller retains its journal, Source writer, protected Cache writers,
/// and physical Cache flock through the Root challenge, durable Source row,
/// independent signer replies, and final Source/Cache postflight. The result
/// cannot authorize Create, Apply, Root CAS, or any owner release.
///
/// # Errors
///
/// Rejects a stale Root stage, changed Source row or named writer, signer or
/// Cache mismatch, failed held-owner postflight, or ambiguous Root reply.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fixed_parentless_create_source_writer_flight_v5(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<ClosedPolicySourceWriterFlightV5> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, source_writer, source, _, held| -> io::Result<_> {
            validate_staged_held_claims(
                proposed,
                staged,
                controller_hold,
                source_hold,
                held.hold(),
            )?;
            let mut recorded = None;
            let outcome = inspect_staged_source_writer_flight_v5(
                staged,
                proposed,
                source_hold,
                |cache_challenge, source_challenge, root_issue| {
                    let row = record_current_source_signer_challenge_v1(
                        source_writer,
                        source.project(),
                        source_challenge,
                    )
                    .map_err(io::Error::other)?;
                    recorded = Some((row, root_issue));
                    let cache_packet = request_verified_held_cache_packet(
                        physical,
                        held,
                        cache_challenge,
                        cache_signer_uid,
                        controller_gid,
                        cache_signer,
                    )?;
                    Ok((cache_packet, row.names()))
                },
            );
            if let Some((row, _)) = recorded {
                require_current_source_signer_challenge_v1(source_writer, source.project(), row)
                    .map_err(io::Error::other)?;
            }
            let flight = outcome?;
            let (row, root_issue) = recorded.ok_or_else(invalid_cut)?;
            if flight.source_issue() != root_issue || flight.source_names() != row.names() {
                return Err(invalid_cut());
            }
            let preview = flight.preview();
            if preview.binding() != controller_hold.binding()
                || preview.epoch() != controller_hold.epoch()
                || preview.project() != held.hold().project()
                || preview.partition() != held.hold().partition()
                || preview.cache_head() != held.hold().cache_head()
            {
                return Err(invalid_cut());
            }
            Ok(flight)
        },
    )
    .map_err(io::Error::other)?
}

/// Acknowledges an inert Root-last Source flight after every owner postflight.
///
/// Root's writer remains held across its signer preview and the terminal
/// response. Controller and Source are rechecked after Cache validates all
/// four protected writers and physical custody, while those Cache guards
/// remain live. No CAS, owner release, Create, or Apply consumes this result.
/// A lost final response remains nonauthorizing until durable Root terminal
/// replay and a qualified proof are separately implemented.
///
/// # Errors
///
/// Rejects stale local writers, changed Source row or names, signer mismatch,
/// failed postflight, or ambiguous Root completion.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fixed_parentless_create_source_writer_held_flight_v6(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<ClosedPolicySourceWriterFlightV5> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_terminal_barrier_v6(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, source_writer, source, _, held| -> io::Result<_> {
            validate_staged_held_claims(
                proposed,
                staged,
                controller_hold,
                source_hold,
                held.hold(),
            )?;
            let mut recorded = None;
            let outcome: io::Result<PendingClosedPolicySourceWriterFlightV6> =
                begin_staged_source_writer_held_flight_v6(
                    staged,
                    proposed,
                    source_hold,
                    |cache_challenge, source_challenge, root_issue| {
                        let row = record_current_source_signer_challenge_v1(
                            source_writer,
                            source.project(),
                            source_challenge,
                        )
                        .map_err(io::Error::other)?;
                        recorded = Some((row, root_issue));
                        let cache_packet = request_verified_held_cache_packet(
                            physical,
                            held,
                            cache_challenge,
                            cache_signer_uid,
                            controller_gid,
                            cache_signer,
                        )?;
                        Ok((cache_packet, row.names()))
                    },
                );
            if let Some((row, _)) = recorded {
                require_current_source_signer_challenge_v1(source_writer, source.project(), row)
                    .map_err(io::Error::other)?;
            }
            let pending = outcome?;
            let (row, root_issue) = recorded.ok_or_else(invalid_cut)?;
            let flight = pending.preview();
            if flight.source_issue() != root_issue || flight.source_names() != row.names() {
                return Err(invalid_cut());
            }
            let preview = flight.preview();
            if preview.binding() != controller_hold.binding()
                || preview.epoch() != controller_hold.epoch()
                || preview.project() != held.hold().project()
                || preview.partition() != held.hold().partition()
                || preview.cache_head() != held.hold().cache_head()
            {
                return Err(invalid_cut());
            }
            Ok((pending, row, source.project()))
        },
        |_, source_writer, prepared| -> io::Result<_> {
            let (pending, row, project) = prepared?;
            require_current_source_signer_challenge_v1(source_writer, project, row)
                .map_err(io::Error::other)?;
            pending.finish()
        },
    )
    .map_err(io::Error::other)?
}

/// Completes the signed, durable, still nonauthorizing Root-last V7 flight.
///
/// The Controller-only packet is signed inside Cache's after-postflight
/// continuation, while Controller, Source, protected Cache, and physical Cache
/// writers remain held. Ambiguous completion replays Root's exact protected
/// row before any guard drops. No result opens first CAS or public Create.
///
/// # Errors
///
/// Rejects stale owner claims, changed Source names, absent Controller-only
/// credential, substituted Root peer, or missing protected Root replay.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fixed_parentless_create_source_writer_signed_flight_v7(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<ClosedPolicySourceWriterFlightV5> {
    match inspect_fixed_parentless_create_signed_flight(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        staged,
        proposed,
        cache_signer_uid,
        controller_gid,
        cache_signer,
        false,
    )? {
        SignedFlightCompletion::V7(flight) => Ok(flight),
        SignedFlightCompletion::V8(_) => Err(invalid_cut()),
    }
}

/// Commits a closed V8 Root CAS only inside the held terminal continuation.
///
/// The distinct V8 receipt and its cold replay remain nonauthorizing. Every
/// Controller, Source, protected Cache, and physical Cache writer stays held
/// until Root has durably committed and answered (or replay has resolved).
///
/// # Errors
///
/// Rejects changed owner currentness, Source names, signed terminal, Root
/// proof, or missing exact committed replay after an ambiguous completion.
#[allow(clippy::too_many_arguments)]
pub fn commit_fixed_parentless_create_source_writer_held_cas_v8(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
) -> io::Result<ClosedPolicyHeldCasCompletionV8> {
    match inspect_fixed_parentless_create_signed_flight(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        staged,
        proposed,
        cache_signer_uid,
        controller_gid,
        cache_signer,
        true,
    )? {
        SignedFlightCompletion::V8(committed) => Ok(committed),
        SignedFlightCompletion::V7(_) => Err(invalid_cut()),
    }
}

/// Cold-replays only an exact durably prepared and committed V8 held decision.
///
/// Controller reacquires its own, Source, protected Cache, and physical Cache
/// writers before Root. Its pre-send attempt supplies the exact terminal
/// digest even after process death. Root verifies its historical CAS; this
/// bridge compares the proposal, held owner claims, and complete current
/// Cache quota envelope under those writers. The result is still historical
/// custody, not a transferable same-cut grant or owner-release capability.
///
/// # Errors
///
/// Rejects absent or changed attempt, local owner cut, Root proposal, Cache
/// quota, committed terminal/proof, or ambiguous authenticated replay.
pub fn recover_fixed_parentless_create_source_writer_held_cas_v8(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<ClosedPolicyHeldCasReplayV8> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;
    let attempt = controller
        .controller_policy_v8_attempt_v1()
        .map_err(io::Error::other)?
        .filter(|attempt| attempt.hold() == controller_hold)
        .ok_or_else(invalid_cut)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, _, _, held| -> io::Result<_> {
            if controller
                .controller_policy_v8_attempt_v1()
                .map_err(io::Error::other)?
                != Some(attempt)
            {
                return Err(invalid_cut());
            }
            let (_, replay) =
                replay_exact_held_v8_cut(controller_hold, source_hold, held, attempt)?;
            Ok(replay)
        },
    )
    .map_err(io::Error::other)?
}

/// Durably acknowledges an exact committed V8 attempt without releasing owners.
///
/// Controller, Source, protected Cache, and physical Cache writers remain held
/// while Root's historical CAS and AOSPCP02 are replayed last. The accepted
/// Create generation and effect transaction come from Root's exact proposal;
/// the complete quota envelope must still match Cache's retained writer.
/// This ACK is neither an Apply grant nor a Root/Source/Cache release token.
///
/// # Errors
///
/// Rejects missing or changed attempt custody, stale Create or owner heads,
/// absent/mismatched Root CAS, changed quota, or failed Controller durability.
pub fn acknowledge_fixed_parentless_create_v8_effect_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<ControllerPolicyV8EffectAckV1> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;
    let attempt = controller
        .controller_policy_v8_attempt_v1()
        .map_err(io::Error::other)?
        .filter(|attempt| attempt.hold() == controller_hold)
        .ok_or_else(invalid_cut)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| -> io::Result<_> {
            if controller
                .controller_policy_v8_attempt_v1()
                .map_err(io::Error::other)?
                != Some(attempt)
            {
                return Err(invalid_cut());
            }
            let (proposed, replay) =
                replay_exact_held_v8_cut(controller_hold, source_hold, held, attempt)?;
            let handoff = closed_policy_effect_handoff_v2(&proposed).map_err(io::Error::other)?;
            if handoff.operation != operation
                || handoff.sandbox != sandbox
                || handoff.accepted_generation != source.accepted_generation()
                || handoff.epoch != controller_hold.epoch()
            {
                return Err(invalid_cut());
            }
            let ack = ControllerPolicyV8EffectAckV1::new(
                attempt,
                handoff.accepted_generation,
                handoff.effect_transaction,
                replay.proof(),
                replay.quota(),
            )
            .map_err(io::Error::other)?;
            controller
                .acknowledge_controller_policy_v8_effect_v1(ack)
                .map_err(io::Error::other)?;
            Ok(ack)
        },
    )
    .map_err(io::Error::other)?
}

/// Retains Root's protected V8 ACK under the earlier-owner held barrier.
///
/// The Controller-signed AOSQ8K01 digest is compared to exact historical
/// AOSPCP02 replay while Controller, Source, protected Cache, and physical
/// Cache writers remain held. The exact Root reply is then durably retained in
/// Controller custody. Root has released its writer before sending that reply;
/// this historical receipt does not release any owner or open Create.
///
/// # Errors
///
/// Rejects a changed Controller ACK, Root CAS, accepted Create, held Cache
/// quota, signer, or ambiguous Root response without exact cold replay.
pub fn acknowledge_fixed_parentless_create_root_v8_effect_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<RootV8EffectAckV1> {
    with_exact_root_v8_ack_barrier(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, ack| {
            with_process_controller_hold_signer_v1(|generation, key| {
                let receipt = acknowledge_held_root_v8_effect(controller, ack, generation, key)?;
                controller
                    .record_controller_policy_v8_root_receipt_v1(receipt)
                    .map_err(io::Error::other)?;
                Ok(receipt)
            })
        },
    )
}

/// Completes the V8 Root terminal while every owner writer remains held.
///
/// Root keeps its protected writer across its ACK, Controller's durable
/// AOSQ8R01 record, and the signed AOSCTR08 readback. This terminal grants no
/// release or Apply authority.
///
/// # Errors
///
/// Rejects changed owner custody, mismatched Root CAS or Cache quota, stale
/// signer, or an ambiguous terminal without exact protected cold replay.
pub fn verify_fixed_parentless_create_root_v8_terminal_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<RootV8EffectAckV1> {
    with_exact_root_v8_ack_barrier(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, ack| {
            with_process_controller_hold_signer_v1(|generation, key| {
                complete_held_root_v8_terminal(controller, ack, generation, key)
            })
        },
    )
}

/// Releases Root, then the exact Cache hold, under the still-held owner cut.
///
/// The Root-last Q8V socket opens in Cache's inspection phase. Its writer and
/// socket survive Cache's final postflight, after which Controller rechecks
/// its exact ACK and Root receipt before signing AOSCTF08. Only a typed Root
/// Released reply (or exact released replay after an ambiguous submission)
/// permits Cache's already-open hold journal to retire its own hold. Source
/// and Controller remain held; public Create and Apply remain closed. The
/// result is `(Root proof, actual held Cache row, exact released Cache row)`.
///
/// # Errors
///
/// Rejects any changed owner claim, failed final postflight, Root transport
/// loss without exact released replay, or failed durable Cache retirement.
#[allow(clippy::too_many_arguments)]
pub(crate) fn release_fixed_parentless_create_root_cache_v8_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<(RootV8ReleasedProofV1, CachePolicyHoldV1, CachePolicyHoldV1)> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;
    with_current_create_cache_signer_release_barrier_v7(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| {
            let ack = exact_root_v8_ack_at_held_cut(
                controller,
                source,
                held,
                controller_hold,
                source_hold,
                operation,
                sandbox,
            )
            .map_err(cache_bridge_error)?;
            let pending = with_process_controller_hold_signer_v1(|generation, key| {
                begin_held_root_v8_terminal_release(controller, ack, generation, key)
            })
            .map_err(cache_bridge_error)?;
            Ok((pending, ack, held.clone()))
        },
        |controller, _, (pending, ack, held)| {
            with_process_controller_hold_signer_v1(|generation, key| {
                pending.finish(controller, &held, generation, key, |controller, row| {
                    if controller
                        .controller_policy_v8_effect_ack_v1()
                        .map_err(io::Error::other)?
                        != Some(ack)
                        || controller
                            .controller_policy_v8_root_receipt_v1()
                            .map_err(io::Error::other)?
                            != Some(row)
                    {
                        return Err(invalid_cut());
                    }
                    Ok(())
                })
            })
            .map_err(cache_bridge_error)
        },
    )
    .map_err(io::Error::other)
}

/// Completes Cache retirement after a crash following exact Root release.
///
/// This path starts only from Root's protected Released replay and repeats
/// that exact replay after Cache postflight. It never signs a new final
/// command, and a held/absent Root phase cannot release Cache. Controller
/// and Source remain held afterward. The returned value omits the historical
/// held Cache row; the separate V8 settlement barrier recovers it only through
/// Cache's validated pending marker under its retained writer.
///
/// # Errors
///
/// Rejects changed Root release evidence, owner claims, Cache quota, or
/// Controller's durable ACK/receipt before retiring Cache's exact hold.
pub(crate) fn recover_fixed_parentless_create_root_cache_v8_release_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<(RootV8ReleasedProofV1, CachePolicyHoldV1)> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;
    let held_result = with_current_create_cache_signer_release_barrier_v7(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| {
            recover_root_released_at_cut(
                controller,
                source,
                held,
                controller_hold,
                source_hold,
                operation,
                sandbox,
            )
        },
        |controller, _, prepared| {
            require_same_root_release_after_postflight(controller, prepared, controller_hold)
        },
    );
    if let Ok((proof, _, released)) = held_result {
        return Ok((proof, released));
    }

    // A lost post-commit readback can leave Cache released despite an error.
    // Only an exact released-row replay under the same owners can settle it.
    with_current_create_cache_signer_released_barrier_v8(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| {
            recover_root_released_at_cut(
                controller,
                source,
                held,
                controller_hold,
                source_hold,
                operation,
                sandbox,
            )
        },
        |controller, _, prepared| {
            require_same_root_release_after_postflight(controller, prepared, controller_hold)
        },
    )
    .map_err(io::Error::other)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum V8OwnerReleaseStep {
    ReleaseRootCache,
    RecoverRootCache,
    SettleSourceController,
}

// The Cache row is only a routing hint. Every effect rechecks fixed names and
// authority itself; an ambiguous release may advance only by Root replay.
fn run_v8_owner_release_steps(
    cache_hold: CachePolicyHoldV1,
    mut run: impl FnMut(V8OwnerReleaseStep) -> io::Result<()>,
) -> io::Result<()> {
    if cache_hold.is_held() && run(V8OwnerReleaseStep::ReleaseRootCache).is_err() {
        run(V8OwnerReleaseStep::RecoverRootCache)?;
    }
    run(V8OwnerReleaseStep::SettleSourceController)
}

/// Releases the held Root/Cache cut and settles Source, then Controller.
///
/// Cache's current row selects the entry point only; the selected path checks
/// its fixed named writer, pending marker, Root peer, and exact owner claims.
/// After an ambiguous held release, recovery accepts only an authenticated
/// Root Released replay. A cold retry after Cache release enters the same
/// Source/Controller settlement barrier, including after Source is retired.
/// No Root successor, public Create, or Apply authority is issued here.
///
/// # Errors
///
/// Rejects an absent or changed Cache row, failed Root release/replay, or any
/// failed owner postflight or durable settlement.
#[allow(clippy::too_many_arguments)]
pub(crate) fn release_and_settle_fixed_parentless_create_v8_owners_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<()> {
    let cache_hold = cache
        .closed_policy_hold_v1()
        .map_err(io::Error::other)?
        .ok_or_else(invalid_cut)?;
    run_v8_owner_release_steps(cache_hold, |step| match step {
        V8OwnerReleaseStep::ReleaseRootCache => release_fixed_parentless_create_root_cache_v8_v1(
            controller,
            source_domains,
            cache,
            physical,
            operation,
            sandbox,
        )
        .map(|_| ()),
        V8OwnerReleaseStep::RecoverRootCache => {
            recover_fixed_parentless_create_root_cache_v8_release_v1(
                controller,
                source_domains,
                cache,
                physical,
                operation,
                sandbox,
            )
            .map(|_| ())
        }
        V8OwnerReleaseStep::SettleSourceController => settle_fixed_parentless_create_v8_owners_v1(
            controller,
            source_domains,
            cache,
            physical,
            operation,
            sandbox,
        ),
    })
}

/// Retires Source, then Controller, after exact Root and Cache V8 release.
///
/// The fixed Root socket supplies typed Released custody. The sandbox barrier
/// verifies the Controller floor and both owner-local pending markers before
/// Source or Controller changes phase. A lost Source or Controller reply is
/// retried from their durable rows, without rejoining live Source ancestry.
/// This private path does not grant Root successor, Create, or Apply.
///
/// # Errors
///
/// Rejects changed owner evidence, an absent Root release, or failed durable
/// Source or Controller retirement.
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle_fixed_parentless_create_v8_owners_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<()> {
    with_current_create_v8_owner_settlement_barrier_v9(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, hold| {
            recover_root_v8_terminal_custody(hold.binding(), hold.epoch())
                .map_err(cache_bridge_error)?
                .ok_or_else(|| cache_bridge_error(invalid_cut()))
        },
    )
    .map_err(io::Error::other)
}

/// Couriers Root's settled V8 grant through the ordered owner marker clear.
///
/// The fixed Root socket authenticates the Controller peer and returns an
/// opaque immutable AOSPC88S grant. The local barrier compares Controller's
/// AOSQ8S01 and both released owner rows before Cache clears AOSCPP08, then
/// Source clears AOSSDP08. Exact retries replay the owner readbacks after an
/// ambiguous commit. This private path grants no public Create or Apply.
///
/// # Errors
///
/// Rejects a missing or changed V8 settlement, Root peer or transport failure,
/// a changed owner row, or failed marker deletion and readback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn clear_fixed_parentless_create_v8_successor_fences_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<()> {
    let released = controller
        .controller_policy_hold_v1()
        .map_err(io::Error::other)?
        .filter(|hold| {
            !hold.is_held() && hold.operation() == operation && hold.sandbox() == sandbox
        })
        .ok_or_else(invalid_cut)?;

    let grant = query_fixed_root_v8_settled_grant_v1(released.binding(), released.epoch())?
        .ok_or_else(invalid_cut)?;
    clear_current_create_v8_successor_fences_v1(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        grant,
    )
    .map_err(io::Error::other)
}

#[allow(clippy::too_many_arguments)]
fn recover_root_released_at_cut(
    controller: &mut Journal,
    source: &aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1,
    held: &CacheResidencyWriterReadbackV2,
    controller_hold: ControllerPolicyHoldV1,
    source_hold: SourceDomainPolicyHoldV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> Result<
    (ControllerPolicyV8EffectAckV1, RootV8ReleasedProofV1),
    CacheResidencyProtectedJournalErrorV1,
> {
    let ack = exact_root_v8_ack_at_released_cut(
        controller,
        source,
        held,
        controller_hold,
        source_hold,
        operation,
        sandbox,
    )
    .map_err(cache_bridge_error)?;
    let proof =
        recover_root_v8_terminal_custody(controller_hold.binding(), controller_hold.epoch())
            .map_err(cache_bridge_error)?
            .ok_or_else(|| cache_bridge_error(invalid_cut()))?;
    with_process_controller_hold_signer_v1(|generation, _| {
        verify_exact_released_root_v8_custody(controller, ack, generation, proof)
    })
    .map_err(cache_bridge_error)?;
    Ok((ack, proof))
}

fn require_same_root_release_after_postflight(
    controller: &mut Journal,
    (ack, prior): (ControllerPolicyV8EffectAckV1, RootV8ReleasedProofV1),
    hold: ControllerPolicyHoldV1,
) -> Result<RootV8ReleasedProofV1, CacheResidencyProtectedJournalErrorV1> {
    let current = recover_root_v8_terminal_custody(hold.binding(), hold.epoch())
        .map_err(cache_bridge_error)?
        .ok_or_else(|| cache_bridge_error(invalid_cut()))?;
    require_exact_released_root_v8_replay(prior, current).map_err(cache_bridge_error)?;
    with_process_controller_hold_signer_v1(|generation, _| {
        verify_exact_released_root_v8_custody(controller, ack, generation, current)
    })
    .map_err(cache_bridge_error)?;
    Ok(current)
}

#[allow(clippy::too_many_arguments)]
fn exact_root_v8_ack_at_released_cut(
    controller: &mut Journal,
    source: &aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1,
    held: &CacheResidencyWriterReadbackV2,
    controller_hold: ControllerPolicyHoldV1,
    source_hold: SourceDomainPolicyHoldV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<ControllerPolicyV8EffectAckV1> {
    let ack = controller
        .controller_policy_v8_effect_ack_v1()
        .map_err(io::Error::other)?
        .ok_or_else(invalid_cut)?;
    if ack.attempt().hold() != controller_hold
        || controller
            .controller_policy_v8_attempt_v1()
            .map_err(io::Error::other)?
            != Some(ack.attempt())
        || ack.accepted_generation() != source.accepted_generation()
        || ack.cache_quota() != held.quota_digest()
    {
        return Err(invalid_cut());
    }
    let (decision, proposed, _) = recover_closed_policy_binding_decision_v5(
        controller_hold.binding(),
        controller_hold.epoch(),
    )?;
    if !matches!(
        decision,
        ClosedPolicyBindingDecisionV2::CommittedReleased(_)
    ) {
        return Err(invalid_cut());
    }
    let proposed = proposed.ok_or_else(invalid_cut)?;
    if held.hold().is_held() {
        compare_closed_policy_binding_hold_claims_v2(
            &proposed,
            controller_hold,
            source_hold,
            held.hold(),
        )
    } else {
        compare_closed_policy_binding_released_cache_claims_v2(
            &proposed,
            controller_hold,
            source_hold,
            held.hold(),
        )
    }
    .map_err(io::Error::other)?;
    let handoff = closed_policy_effect_handoff_v2(&proposed).map_err(io::Error::other)?;
    if handoff.operation != operation
        || handoff.sandbox != sandbox
        || handoff.epoch != controller_hold.epoch()
        || handoff.accepted_generation != ack.accepted_generation()
        || handoff.effect_transaction != ack.effect_transaction()
    {
        return Err(invalid_cut());
    }
    Ok(ack)
}

fn cache_bridge_error(error: io::Error) -> CacheResidencyProtectedJournalErrorV1 {
    JournalError::Io(error).into()
}

fn with_exact_root_v8_ack_barrier<T>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    action: impl FnOnce(&mut Journal, ControllerPolicyV8EffectAckV1) -> io::Result<T>,
) -> io::Result<T> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;
    with_current_create_cache_signer_terminal_barrier_v6(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| -> io::Result<_> {
            exact_root_v8_ack_at_held_cut(
                controller,
                source,
                held,
                controller_hold,
                source_hold,
                operation,
                sandbox,
            )
        },
        |controller, _, prepared| -> io::Result<_> {
            let ack = prepared?;
            action(controller, ack)
        },
    )
    .map_err(io::Error::other)?
}

#[allow(clippy::too_many_arguments)]
fn exact_root_v8_ack_at_held_cut(
    controller: &mut Journal,
    source: &aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1,
    held: &CacheResidencyWriterReadbackV2,
    controller_hold: ControllerPolicyHoldV1,
    source_hold: SourceDomainPolicyHoldV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<ControllerPolicyV8EffectAckV1> {
    let ack = controller
        .controller_policy_v8_effect_ack_v1()
        .map_err(io::Error::other)?
        .ok_or_else(invalid_cut)?;
    let attempt = ack.attempt();
    if attempt.hold() != controller_hold
        || controller
            .controller_policy_v8_attempt_v1()
            .map_err(io::Error::other)?
            != Some(attempt)
        || ack.accepted_generation() != source.accepted_generation()
    {
        return Err(invalid_cut());
    }
    let (proposed, replay) = replay_exact_held_v8_cut(controller_hold, source_hold, held, attempt)?;
    let handoff = closed_policy_effect_handoff_v2(&proposed).map_err(io::Error::other)?;
    if handoff.operation != operation
        || handoff.sandbox != sandbox
        || handoff.epoch != controller_hold.epoch()
        || handoff.accepted_generation != ack.accepted_generation()
        || handoff.effect_transaction != ack.effect_transaction()
        || replay.proof() != ack.root_proof()
        || replay.quota() != ack.cache_quota()
    {
        return Err(invalid_cut());
    }
    Ok(ack)
}

fn replay_exact_held_v8_cut(
    controller_hold: ControllerPolicyHoldV1,
    source_hold: SourceDomainPolicyHoldV1,
    held: &CacheResidencyWriterReadbackV2,
    attempt: ControllerPolicyV8AttemptV1,
) -> io::Result<(Vec<u8>, ClosedPolicyHeldCasReplayV8)> {
    if attempt.hold() != controller_hold || !controller_hold.is_held() {
        return Err(invalid_cut());
    }
    let (decision, proposed, _) = recover_closed_policy_binding_decision_v5(
        controller_hold.binding(),
        controller_hold.epoch(),
    )?;
    if !matches!(decision, ClosedPolicyBindingDecisionV2::CommittedHeld(_)) {
        return Err(invalid_cut());
    }
    let proposed = proposed.ok_or_else(invalid_cut)?;
    compare_closed_policy_binding_hold_claims_v2(
        &proposed,
        controller_hold,
        source_hold,
        held.hold(),
    )
    .map_err(io::Error::other)?;
    let replay = recover_committed_source_held_binding_v8(
        controller_hold.binding(),
        controller_hold.epoch(),
        attempt.terminal(),
    )?;
    if replay.quota() != held.quota_digest() {
        return Err(invalid_cut());
    }
    Ok((proposed, replay))
}

enum PendingSignedFlight {
    V7(PendingClosedPolicySourceWriterFlightV7),
    V8(PendingClosedPolicySourceWriterFlightV8),
}

impl PendingSignedFlight {
    fn preview(&self) -> ClosedPolicySourceWriterFlightV5 {
        match self {
            Self::V7(pending) => pending.preview(),
            Self::V8(pending) => pending.preview(),
        }
    }

    fn finish(
        self,
        controller: &mut Journal,
        generation: u64,
        key: &ed25519_dalek::SigningKey,
    ) -> io::Result<SignedFlightCompletion> {
        match self {
            Self::V7(pending) => pending
                .finish(controller, generation, key)
                .map(SignedFlightCompletion::V7),
            Self::V8(pending) => pending
                .finish(controller, generation, key)
                .map(SignedFlightCompletion::V8),
        }
    }
}

enum SignedFlightCompletion {
    V7(ClosedPolicySourceWriterFlightV5),
    V8(ClosedPolicyHeldCasCompletionV8),
}

#[allow(clippy::too_many_arguments)]
fn inspect_fixed_parentless_create_signed_flight(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
    cache_signer_uid: u32,
    controller_gid: u32,
    cache_signer: &PinnedCacheOwnerReadbackSignerV1,
    commit_cas: bool,
) -> io::Result<SignedFlightCompletion> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_terminal_barrier_v6(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, source_writer, source, _, held| -> io::Result<_> {
            validate_staged_held_claims(
                proposed,
                staged,
                controller_hold,
                source_hold,
                held.hold(),
            )?;
            let mut recorded = None;
            let mut read_held = |cache_challenge, source_challenge, root_issue| {
                let row = record_current_source_signer_challenge_v1(
                    source_writer,
                    source.project(),
                    source_challenge,
                )
                .map_err(io::Error::other)?;
                recorded = Some((row, root_issue));
                let cache_packet = request_verified_held_cache_packet(
                    physical,
                    held,
                    cache_challenge,
                    cache_signer_uid,
                    controller_gid,
                    cache_signer,
                )?;
                Ok((cache_packet, row.names()))
            };
            let outcome = if commit_cas {
                begin_staged_source_writer_held_flight_v8(
                    staged,
                    proposed,
                    source_hold,
                    &mut read_held,
                )
                .map(PendingSignedFlight::V8)
            } else {
                begin_staged_source_writer_held_flight_v7(
                    staged,
                    proposed,
                    source_hold,
                    &mut read_held,
                )
                .map(PendingSignedFlight::V7)
            };
            if let Some((row, _)) = recorded {
                require_current_source_signer_challenge_v1(source_writer, source.project(), row)
                    .map_err(io::Error::other)?;
            }
            let pending = outcome?;
            let (row, root_issue) = recorded.ok_or_else(invalid_cut)?;
            let flight = pending.preview();
            if flight.source_issue() != root_issue || flight.source_names() != row.names() {
                return Err(invalid_cut());
            }
            let preview = flight.preview();
            if preview.binding() != controller_hold.binding()
                || preview.epoch() != controller_hold.epoch()
                || preview.project() != held.hold().project()
                || preview.partition() != held.hold().partition()
                || preview.cache_head() != held.hold().cache_head()
            {
                return Err(invalid_cut());
            }
            Ok((pending, row, source.project(), held.quota_digest()))
        },
        |controller, source_writer, prepared| -> io::Result<_> {
            let (pending, row, project, quota) = prepared?;
            require_current_source_signer_challenge_v1(source_writer, project, row)
                .map_err(io::Error::other)?;
            let completion = with_process_controller_hold_signer_v1(|generation, key| {
                pending.finish(controller, generation, key)
            })?;
            if matches!(completion, SignedFlightCompletion::V8(receipt) if receipt.quota() != quota)
            {
                return Err(invalid_cut());
            }
            Ok(completion)
        },
    )
    .map_err(io::Error::other)?
}

/// Inspects a staged Q04 proposal with Root acquired after all local writers.
///
/// The caller supplies already-retained Controller, Source, four protected
/// Cache writers, and physical Cache flock. The exact Root stage and proposal
/// are checked over the authenticated Root socket; local held claims and
/// fixed names are compared before and after the RPC. This nonauthorizing
/// preview does not include same-cut independent signer receipts, commit the
/// Q04 binding, release any hold, or enable public Create.
///
/// # Errors
///
/// Rejects stale local writers or Create, substituted held claims, changed
/// physical Cache state, a stale Root stage, or transport loss.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fixed_parentless_create_staged_binding_v4(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
) -> io::Result<ClosedPolicyBindingPreviewV4> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, _, _, held| -> io::Result<_> {
            validate_staged_held_claims(
                proposed,
                staged,
                controller_hold,
                source_hold,
                held.hold(),
            )?;
            let preview = preview_staged_closed_policy_binding_v4(staged, proposed)?;
            if preview.binding() != controller_hold.binding()
                || preview.epoch() != controller_hold.epoch()
                || preview.project() != held.hold().project()
                || preview.partition() != held.hold().partition()
                || preview.cache_head() != held.hold().cache_head()
            {
                return Err(invalid_cut());
            }
            Ok(preview)
        },
    )
    .map_err(io::Error::other)?
}

/// Replays an ambiguous inert Q04 decision with Root acquired last.
///
/// The caller retains Controller, Source, all protected Cache writers, and
/// the physical Cache flock in that order. Their current holds must already
/// name one binding and epoch. Root returns its exact durable proposal, which
/// is compared to those retained claims before any observation escapes the
/// local postflight checks. A committed reply is not a Create or effect grant;
/// none of the holds is released here.
///
/// # Errors
///
/// Rejects stale local writers, a changed physical Cache owner, a missing or
/// substituted Root decision, malformed stored proposal, or transport loss.
#[allow(clippy::too_many_arguments)]
pub fn recover_fixed_parentless_create_closed_binding_decision_v4(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<ClosedPolicyBindingDecisionV2> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, _, _, held| -> io::Result<_> {
            let binding = controller_hold.binding();
            let epoch = controller_hold.epoch();
            let (decision, proposed, _) =
                recover_closed_policy_binding_decision_v5(binding, epoch)?;
            if let Some(proposed) = proposed {
                compare_closed_policy_binding_hold_claims_v2(
                    &proposed,
                    controller_hold,
                    source_hold,
                    held.hold(),
                )
                .map_err(io::Error::other)?;
            } else if !matches!(decision, ClosedPolicyBindingDecisionV2::Absent) {
                return Err(invalid_cut());
            }
            Ok(decision)
        },
    )
    .map_err(io::Error::other)?
}

/// Durably acknowledges one qualified Root decision under the held Q04 cut.
///
/// Root is replayed last with Controller, Source, protected Cache, and physical
/// Cache writers retained. The exact proposal, pinned signer-proof digest,
/// accepted Create generation, and effect transaction are committed to the
/// Controller journal before physical custody is dropped. This transition is
/// explicitly no-Apply and leaves every owner held for later Root ACK/release.
///
/// # Errors
///
/// Rejects stale Create or owner heads, an unqualified or released Root
/// decision, substituted proposal or proof, and failed Controller readback.
#[allow(clippy::too_many_arguments)]
pub fn acknowledge_fixed_parentless_create_held_effect_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<ControllerPolicyEffectAckV1> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| -> io::Result<_> {
            let (decision, proposed, proof) = recover_closed_policy_binding_decision_v5(
                controller_hold.binding(),
                controller_hold.epoch(),
            )?;
            if !matches!(
                decision,
                ClosedPolicyBindingDecisionV2::CommittedQualifiedHeld(_)
            ) {
                return Err(invalid_cut());
            }
            let proposed = proposed.ok_or_else(invalid_cut)?;
            compare_closed_policy_binding_hold_claims_v2(
                &proposed,
                controller_hold,
                source_hold,
                held.hold(),
            )
            .map_err(io::Error::other)?;
            let handoff = closed_policy_effect_handoff_v2(&proposed).map_err(io::Error::other)?;
            if handoff.operation != operation
                || handoff.sandbox != sandbox
                || handoff.accepted_generation != source.accepted_generation()
                || handoff.epoch != controller_hold.epoch()
            {
                return Err(invalid_cut());
            }
            let ack = ControllerPolicyEffectAckV1::new(
                controller_hold,
                handoff.accepted_generation,
                handoff.effect_transaction,
                proof.ok_or_else(invalid_cut)?,
            )
            .map_err(io::Error::other)?;
            controller
                .acknowledge_controller_policy_effect_v1(ack)
                .map_err(io::Error::other)?;
            Ok(ack)
        },
    )
    .map_err(io::Error::other)?
}

/// Sends the durable Controller no-Apply ACK to Root under the full held cut.
///
/// Controller, Source, protected Cache, and physical Cache remain writer-held
/// through Root's fresh challenge, Controller-only signature, durable Root ACK,
/// and ambiguous-reply replay. Root is acquired last. This neither releases
/// custody nor opens public Create or Apply.
///
/// # Errors
///
/// Rejects stale Create or owner heads, a missing or substituted Controller
/// ACK, changed Root proof, invalid signer credentials, and unresolved Root
/// transport or replay.
#[allow(clippy::too_many_arguments)]
pub fn acknowledge_fixed_parentless_create_root_effect_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
) -> io::Result<RootEffectAckV1> {
    let (controller_hold, source_hold) = held_policy_claims(controller, source_domains)?;

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |controller, _, source, _, held| -> io::Result<_> {
            let ack = controller
                .controller_policy_effect_ack_v1()
                .map_err(io::Error::other)?
                .ok_or_else(invalid_cut)?;
            if ack.hold() != controller_hold
                || ack.accepted_generation() != source.accepted_generation()
            {
                return Err(invalid_cut());
            }
            let (decision, proposed, proof) = recover_closed_policy_binding_decision_v5(
                controller_hold.binding(),
                controller_hold.epoch(),
            )?;
            if !matches!(
                decision,
                ClosedPolicyBindingDecisionV2::CommittedQualifiedHeld(_)
            ) || proof != Some(ack.root_proof())
            {
                return Err(invalid_cut());
            }
            let proposed = proposed.ok_or_else(invalid_cut)?;
            compare_closed_policy_binding_hold_claims_v2(
                &proposed,
                controller_hold,
                source_hold,
                held.hold(),
            )
            .map_err(io::Error::other)?;
            let handoff = closed_policy_effect_handoff_v2(&proposed).map_err(io::Error::other)?;
            if handoff.operation != operation
                || handoff.sandbox != sandbox
                || handoff.accepted_generation != ack.accepted_generation()
                || handoff.effect_transaction != ack.effect_transaction()
                || handoff.epoch != controller_hold.epoch()
            {
                return Err(invalid_cut());
            }
            with_process_controller_hold_signer_v1(|generation, key| {
                acknowledge_held_root_effect_v1(controller, ack, generation, key)
            })
        },
    )
    .map_err(io::Error::other)?
}

/// Opens and retains all remaining owners under the held controller writer.
///
/// The caller must supply a protected, writer-held controller journal and its
/// privileged controller UID, not values from a public request. The accepted
/// Create is checked before source-domain and Cache open, which fixes local
/// lock order. The verification keys only check the root receipt; privileged
/// root deployment credentials choose the authoritative signer generations.
/// A successful return reports an inert durable root record and leaves both
/// source journals frozen until root-only cold resolution. It is not permission
/// to publish or hand off an effect.
///
/// # Errors
///
/// Rejects stale Create, ancestry, publisher, revocation, or protected Cache
/// state, changed signed inputs, root peer or CAS mismatch, and lost transport.
#[allow(clippy::too_many_arguments)]
pub fn commit_fixed_parentless_create_closed_binding_v4(
    controller: &mut Journal,
    controller_uid: u32,
    operation: OperationId,
    sandbox: SandboxId,
    input: &PolicyCompilerInputV1,
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
) -> io::Result<ClosedPolicyBindingClientObservationV4> {
    current_parentless_create_project_source_v1(controller, operation, sandbox)
        .map_err(io::Error::other)?;
    let (mut source_domains, _) =
        ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)
            .map_err(io::Error::other)?;
    let (mut cache, _) =
        CacheResidencyProtectedOwnerV1::open_fixed_protected_for_uid(controller_uid)
            .map_err(io::Error::other)?;

    commit_under_held_owners(
        controller,
        &mut source_domains,
        &mut cache,
        operation,
        sandbox,
        input,
        deployment_verifying_key,
        project_verifying_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_under_held_owners(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    input: &PolicyCompilerInputV1,
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
) -> io::Result<ClosedPolicyBindingClientObservationV4> {
    with_current_create_policy_source_barrier_v4(
        controller,
        source_domains,
        cache,
        operation,
        sandbox,
        |controller, source_domains, source, heads| {
            commit_closed_policy_binding_v4(
                deployment_verifying_key,
                project_verifying_key,
                |receipt, remote_base| {
                    if !receipt.matches_compiler_input(source, input) {
                        return Err(invalid_cut());
                    }
                    let root_base = ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
                        remote_base.issuer_owner(),
                        remote_base.predecessor(),
                        remote_base.next_generation(),
                        remote_base.deployment_signer_generation(),
                        remote_base.project_signer_generation(),
                    )
                    .map_err(io::Error::other)?;
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(io::Error::other)?;
                    let now = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
                    let proposed = propose_closed_current_create_explicit_policy_binding_v2(
                        source,
                        heads,
                        receipt.project(),
                        receipt.head(),
                        receipt.sources(),
                        input,
                        root_base,
                        now,
                    )
                    .map_err(io::Error::other)?;
                    let binding =
                        closed_policy_binding_digest_v2(&proposed).map_err(io::Error::other)?;
                    let hold = ControllerPolicyHoldV1::new(
                        operation,
                        sandbox,
                        source.commitment(),
                        binding,
                        remote_base.next_generation(),
                    )
                    .map_err(io::Error::other)?;
                    controller
                        .acquire_controller_policy_hold_v1(hold)
                        .map_err(io::Error::other)?;
                    let source_hold = SourceDomainPolicyHoldV1::new(
                        operation,
                        sandbox,
                        source.commitment(),
                        heads.ancestry(),
                        binding,
                        remote_base.next_generation(),
                    )
                    .map_err(io::Error::other)?;
                    source_domains
                        .acquire_closed_policy_source_hold_v1(source_hold)
                        .map_err(io::Error::other)?;
                    Ok(proposed)
                },
            )
        },
    )
    .map_err(io::Error::other)?
}

fn invalid_cut() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "policy owner cut changed")
}

#[cfg(test)]
mod tests {
    use std::io;

    use aos_sandbox::journal::CachePolicyHoldV1;
    use aos_sandbox::policy_compiler::{
        ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasObservationV2,
    };
    use aos_sandbox_core::{ObjectDigest, ProjectId};

    use super::{V8OwnerReleaseStep, run_v8_owner_release_steps, verify_exact_held_replay};

    fn held_cache_row() -> CachePolicyHoldV1 {
        CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("typed held Cache row")
    }

    #[test]
    fn v8_owner_release_schedules_replay_before_later_settlement() {
        let mut visited = Vec::new();
        run_v8_owner_release_steps(held_cache_row(), |step| {
            visited.push(step);
            if step == V8OwnerReleaseStep::ReleaseRootCache {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ambiguous Root reply",
                ))
            } else {
                Ok(())
            }
        })
        .expect("recovery step permits later settlement");
        assert_eq!(
            visited.as_slice(),
            &[
                V8OwnerReleaseStep::ReleaseRootCache,
                V8OwnerReleaseStep::RecoverRootCache,
                V8OwnerReleaseStep::SettleSourceController,
            ]
        );

        visited.clear();
        assert!(
            run_v8_owner_release_steps(held_cache_row(), |step| {
                visited.push(step);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Root not released",
                ))
            })
            .is_err()
        );
        assert_eq!(
            visited.as_slice(),
            &[
                V8OwnerReleaseStep::ReleaseRootCache,
                V8OwnerReleaseStep::RecoverRootCache,
            ]
        );
    }

    #[test]
    fn v8_owner_release_does_not_hide_source_or_controller_failure() {
        let mut visited = Vec::new();
        assert!(
            run_v8_owner_release_steps(held_cache_row(), |step| {
                visited.push(step);
                if step == V8OwnerReleaseStep::SettleSourceController {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "owner postflight",
                    ))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(
            visited.as_slice(),
            &[
                V8OwnerReleaseStep::ReleaseRootCache,
                V8OwnerReleaseStep::SettleSourceController,
            ]
        );
    }

    #[test]
    fn ambiguous_held_cas_replay_rejects_absent_released_and_substituted_record() {
        let binding = ObjectDigest::from_bytes([7; 32]);
        let observed = ClosedPolicyRootCasObservationV2::from_replayed_fields(binding, 9)
            .expect("held observation");
        let proposed = [11; 16];
        let held = ClosedPolicyBindingDecisionV2::CommittedQualifiedHeld(observed);
        assert_eq!(
            verify_exact_held_replay(held, Some(&proposed), &proposed, binding, 9)
                .expect("exact held replay"),
            observed
        );
        assert!(verify_exact_held_replay(held, Some(&[12; 16]), &proposed, binding, 9).is_err());
        assert!(verify_exact_held_replay(held, None, &proposed, binding, 9).is_err());
        assert!(verify_exact_held_replay(held, Some(&proposed), &proposed, binding, 10).is_err());
        assert!(
            verify_exact_held_replay(
                ClosedPolicyBindingDecisionV2::CommittedHeld(observed),
                Some(&proposed),
                &proposed,
                binding,
                9,
            )
            .is_err()
        );
        assert!(
            verify_exact_held_replay(
                ClosedPolicyBindingDecisionV2::Absent,
                None,
                &proposed,
                binding,
                9,
            )
            .is_err()
        );
        assert!(
            verify_exact_held_replay(
                ClosedPolicyBindingDecisionV2::CommittedReleased(observed),
                Some(&proposed),
                &proposed,
                binding,
                9,
            )
            .is_err()
        );
    }
}
