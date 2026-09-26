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
    CacheResidencyProtectedOwnerV1, CacheResidencyWriterReadbackV2, DormantCacheOwnerV1,
    PinnedCacheOwnerReadbackSignerV1, verify_closed_cache_owner_readback_v2,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasBaseV2, ClosedPolicyRootCasObservationV2,
    PolicyCompilerInputV1, RootEffectAckV1, StagedClosedPolicyRootBaseV2,
    StagedClosedPolicySignerChallengeV2, closed_policy_binding_digest_v2,
    closed_policy_effect_handoff_v2, compare_closed_policy_binding_hold_claims_v2,
    current_parentless_create_project_source_v1,
    propose_closed_current_create_explicit_policy_binding_v2,
    record_current_source_signer_challenge_v1, require_current_source_signer_challenge_v1,
    with_current_create_cache_signer_barrier_v5,
    with_current_create_cache_signer_terminal_barrier_v6,
    with_current_create_policy_source_barrier_v4,
};
use aos_sandbox::{
    ControllerPolicyEffectAckV1, ControllerPolicyHoldV1, Journal,
    journal::{CachePolicyHoldV1, SourceDomainPolicyHoldV1},
};
use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use ed25519_dalek::VerifyingKey;

use crate::cache_signer_exchange::request_controller_q04_cache_signer_readback_v3;
use crate::controller_hold_credential::with_process_controller_hold_signer_v1;
use crate::policy_authority_client::{
    ClosedPolicyBindingClientObservationV4, ClosedPolicyBindingPreviewV4,
    ClosedPolicyBindingSignerFlightV4, ClosedPolicySourceWriterFlightV5,
    PendingClosedPolicySourceWriterFlightV6, begin_staged_source_writer_held_flight_v6,
    commit_closed_policy_binding_v4, commit_staged_closed_policy_signer_flight_v4,
    inspect_staged_closed_policy_signer_flight_v4, inspect_staged_source_writer_flight_v5,
    preview_staged_closed_policy_binding_v4, recover_closed_policy_binding_decision_v5,
};
use crate::policy_root_ack_client::acknowledge_held_root_effect_v1;

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
    use aos_sandbox::policy_compiler::{
        ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasObservationV2,
    };
    use aos_sandbox_core::ObjectDigest;

    use super::verify_exact_held_replay;

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
