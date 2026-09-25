//! Held controller/source-domain/Cache/root cut for a closed policy binding.
//!
//! A future controller caller supplies its already-held controller journal.
//! This bridge opens source-domain and protected Cache custody in that order,
//! then acquires the root writer through the authenticated local exchange.
//! The bridge durably freezes Controller and source-domain mutations before Q04 SUBMIT;
//! root retains its writer through AOSPCB02 CAS and terminal acknowledgement.
//! Cache still has only process-local custody and rechecks. A crash leaves
//! Controller and source-domain journals frozen for exact root cold readback,
//! whether root committed or not. No production Create path calls this bridge,
//! and its observation cannot authorize policy publication or an effect.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::cache_residency::{
    CacheOwnerReadbackChallengeV1, CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1,
    PinnedCacheOwnerReadbackSignerV1, verify_closed_cache_owner_readback_v2,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasBaseV2, PolicyCompilerInputV1,
    StagedClosedPolicyRootBaseV2, closed_policy_binding_digest_v2,
    compare_closed_policy_binding_hold_claims_v2, current_parentless_create_project_source_v1,
    propose_closed_current_create_explicit_policy_binding_v2,
    with_current_create_cache_signer_barrier_v5, with_current_create_policy_source_barrier_v4,
};
use aos_sandbox::{ControllerPolicyHoldV1, Journal, journal::SourceDomainPolicyHoldV1};
use aos_sandbox_core::{OperationId, SandboxId};
use ed25519_dalek::VerifyingKey;

use crate::cache_signer_exchange::request_controller_q04_cache_signer_readback_v3;
use crate::policy_authority_client::{
    ClosedPolicyBindingClientObservationV4, ClosedPolicyBindingPreviewV4,
    ClosedPolicyBindingSignerFlightV4, commit_closed_policy_binding_v4,
    inspect_staged_closed_policy_signer_flight_v4, preview_staged_closed_policy_binding_v4,
    recover_closed_policy_binding_decision_v4,
};

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

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, held| -> io::Result<_> {
            compare_closed_policy_binding_hold_claims_v2(
                proposed,
                controller_hold,
                source_hold,
                held.hold(),
            )
            .map_err(io::Error::other)?;
            if staged.base().next_generation() != controller_hold.epoch() {
                return Err(invalid_cut());
            }
            let flight = inspect_staged_closed_policy_signer_flight_v4(
                staged,
                proposed,
                source_hold,
                |challenge| {
                    let snapshot = physical.held_snapshot().map_err(io::Error::other)?;
                    let cache_challenge =
                        CacheOwnerReadbackChallengeV1::new(challenge.nonce(), challenge.cut())
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
                    if verified.hold() != held.hold()
                        || verified.quota_digest() != held.quota_digest()
                    {
                        return Err(invalid_cut());
                    }
                    snapshot
                        .require_verified_readback_v2(verified)
                        .map_err(io::Error::other)?;
                    Ok(packet)
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

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, held| -> io::Result<_> {
            compare_closed_policy_binding_hold_claims_v2(
                proposed,
                controller_hold,
                source_hold,
                held.hold(),
            )
            .map_err(io::Error::other)?;
            if staged.base().next_generation() != controller_hold.epoch() {
                return Err(invalid_cut());
            }
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

    with_current_create_cache_signer_barrier_v5(
        controller,
        source_domains,
        cache,
        physical,
        operation,
        sandbox,
        |_, _, held| -> io::Result<_> {
            let binding = controller_hold.binding();
            let epoch = controller_hold.epoch();
            let (decision, proposed) = recover_closed_policy_binding_decision_v4(binding, epoch)?;
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
