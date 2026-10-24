//! Keeps Controller/Source V8 semantics above the actual finite Cache cut.
//!
//! The ordinary/library APIs retain their existing callback surface here;
//! native Cache receives only concrete contexts and genuine Root evidence.
//! Currentness, Root reply comparison and durable Controller floors stay at
//! their original positions. This does not install a paid selected programme.

use super::*;
use aos_sandbox_cache::CacheV8TerminalContextV1;

// The inspection's own authority-final post completes before Cache's first
// owed post. Both native post failures keep their original precedence; upper
// inspect refusal skips only the old positive inner refresh, never the final.
fn inspect_cache_v8_native_once_v1<Prepared>(
    native: &mut CacheV8TerminalContextV1<'_>,
    inspect: impl FnOnce(
        &CacheResidencyWriterReadbackV2,
    ) -> Result<Prepared, CurrentCreatePolicySourceErrorV1>,
) -> Result<Prepared, CurrentCreatePolicySourceErrorV1> {
    let result = {
        let returned = native.borrow_inspection_once_v1();
        match returned {
            Err(cause) => {
                drop(inspect);
                Err(cause.into())
            }
            Ok(mut guard) => {
                let returned_context = guard.borrow_context_once_v1();
                let result = match returned_context {
                    Err(cause) => {
                        drop(inspect);
                        Err(cause.into())
                    }
                    Ok(mut context) => match context.readback_v1() {
                        None => {
                            context.retire_failed_capture_before_upper_drop_v1();
                            drop(inspect);
                            context
                                .finish_after_upper_refusal_v1()
                                .map_err(CurrentCreatePolicySourceErrorV1::from)
                                .and_then(|()| {
                                    Err(ProtectedDomainJournalErrorV1::StaleAuthority.into())
                                })
                        }
                        Some(readback) => {
                            match inspect(readback) {
                                Err(cause) => {
                                    context
                                        .finish_after_upper_refusal_v1()
                                        .map_err(CurrentCreatePolicySourceErrorV1::from)
                                        .and(Err(cause))
                                }
                                Ok(prepared) => match context.refresh_after_inspect_once_v1() {
                                    Err(cause) => {
                                        // The old refresh's ? dropped selected before the
                                        // projection and independently owed outer check.
                                        drop(prepared);
                                        context
                                            .finish_after_inspect_v1()
                                            .map_err(CurrentCreatePolicySourceErrorV1::from)
                                            .and(Err(cause.into()))
                                    }
                                    Ok(()) => context
                                        .finish_after_inspect_v1()
                                        .map_err(CurrentCreatePolicySourceErrorV1::from)
                                        .map(|()| prepared),
                                },
                            }
                        }
                    },
                };
                result
            }
        }
    };
    native.postflight_after_inspect_v1()?;
    result
}

/// Runs the existing Root-last release under the same Cache and upper owners.
///
/// # Errors
/// Preserves Controller/Source/Root/floor refusals and every Cache native post.
#[allow(clippy::too_many_arguments)]
pub fn with_current_create_cache_signer_release_barrier_v7<Prepared>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        &CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicyBarrierHeadsV2,
        &CacheResidencyWriterReadbackV2,
    ) -> Result<Prepared, CacheResidencyProtectedJournalErrorV1>,
    release: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        Prepared,
    ) -> Result<RootV8ReleasedProofV1, CacheResidencyProtectedJournalErrorV1>,
) -> Result<
    (RootV8ReleasedProofV1, CachePolicyHoldV1, CachePolicyHoldV1),
    CurrentCreatePolicySourceErrorV1,
> {
    let cut = HeldCreateSourceCut::begin(controller, source_domains, operation, sandbox)?;
    let mut original = cache.borrow_v8_held_release_v1(physical)?;
    let mut native = original.borrow_context_once_v1()?;
    let (prepared, finalize) = inspect_cache_v8_native_once_v1(&mut native, |held| {
        let heads = cut.cache_heads(held)?;
        let actual_held = held.hold();
        let cache_readback = held.clone();
        let prepared = inspect(controller, source_domains, &cut.source, heads, held)?;
        Ok((prepared, move |prepared| {
            cut.revalidate(controller, source_domains, operation, sandbox)
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let output = release(controller, source_domains, prepared)?;
            cut.validate_released_root_proof(controller, &cache_readback, output)?;
            cut.revalidate(controller, source_domains, operation, sandbox)
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            cut.record_pre_release_floor(controller, source_domains, &cache_readback, output)?;
            cut.revalidate(controller, source_domains, operation, sandbox)
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            Ok::<_, CurrentCreatePolicySourceErrorV1>((output, actual_held))
        }))
    })?;
    // Retain the old identity-Finish Result through P2: on post refusal its
    // Prepared drops before finalize's captured Controller/Source/Root owners.
    let outcome = Ok::<_, CurrentCreatePolicySourceErrorV1>(prepared);
    native.postflight_after_finish_v1()?;
    let finalized = finalize(outcome?);
    native.postflight_before_commit_v1()?;
    let (proof, actual_held) = finalized?;
    let released = native.release_after_root_original_v1(&proof)?;
    Ok((proof, actual_held, released))
}

/// Replays released Root evidence beneath the exact retained Cache readback.
///
/// # Errors
/// Preserves all original upper/floor checks and both native Cache posts.
#[allow(clippy::too_many_arguments)]
pub fn with_current_create_cache_signer_released_barrier_v8<Prepared>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        &CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicyBarrierHeadsV2,
        &CacheResidencyWriterReadbackV2,
    ) -> Result<Prepared, CacheResidencyProtectedJournalErrorV1>,
    replay: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        Prepared,
    ) -> Result<RootV8ReleasedProofV1, CacheResidencyProtectedJournalErrorV1>,
) -> Result<(RootV8ReleasedProofV1, CachePolicyHoldV1), CurrentCreatePolicySourceErrorV1> {
    let cut = HeldCreateSourceCut::begin(controller, source_domains, operation, sandbox)?;
    let mut original = cache.borrow_v8_released_readback_v1(physical)?;
    let mut native = original.borrow_context_once_v1()?;
    let historical = native.historical_held_v1();
    let (prepared, finish) = inspect_cache_v8_native_once_v1(&mut native, |held| {
        let historical_cache_held =
            historical.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let heads = cut.cache_heads(held)?;
        let cache_readback = held.clone();
        let prepared = inspect(controller, source_domains, &cut.source, heads, held)?;
        Ok((prepared, move |prepared| {
            cut.revalidate(controller, source_domains, operation, sandbox)
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let proof = replay(controller, source_domains, prepared)?;
            cut.validate_released_root_proof(controller, &cache_readback, proof)?;
            cut.require_pre_release_floor(
                controller,
                source_domains,
                historical_cache_held,
                proof,
            )?;
            cut.revalidate(controller, source_domains, operation, sandbox)
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            Ok::<_, CurrentCreatePolicySourceErrorV1>(proof)
        }))
    })?;
    let outcome = finish(prepared);
    native.postflight_after_finish_v1()?;
    let proof = outcome?;
    let released = native.finish_readback_v1()?;
    Ok((proof, released))
}

/// Settles the existing released Source/Controller rows under the same Cache cut.
///
/// # Errors
/// Preserves original Root/ACK/floor/currentness checks and owed native posts.
#[allow(clippy::too_many_arguments)]
pub fn with_current_create_v8_owner_settlement_barrier_v9(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    replay: impl FnOnce(
        &mut Journal,
        ControllerPolicyHoldV1,
    ) -> Result<RootV8ReleasedProofV1, CacheResidencyProtectedJournalErrorV1>,
) -> Result<(), CurrentCreatePolicySourceErrorV1> {
    let controller_uid = controller.protected_owner_uid()?;
    HeldCreateSourceCut::require_controller_name(controller, controller_uid)?;
    source_domains.require_fixed_named_writer_v1()?;
    let attempt = controller
        .controller_policy_v8_attempt_v1()?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let held_controller = attempt.hold();
    if held_controller.operation() != operation || held_controller.sandbox() != sandbox {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let mut original = cache.borrow_v8_released_readback_v1(physical)?;
    let mut native = original.borrow_context_once_v1()?;
    let historical = native.historical_held_v1();
    let (prepared, finish) = inspect_cache_v8_native_once_v1(&mut native, |readback| {
        let cache_held = historical.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let cache_released = readback.hold();
        let quota = readback.quota_digest();
        Ok(((), move |_| {
            HeldCreateSourceCut::require_controller_name(controller, controller_uid)?;
            source_domains.require_fixed_named_writer_v1()?;
            let ack = controller
                .controller_policy_v8_effect_ack_v1()?
                .filter(|ack| ack.attempt() == attempt && ack.cache_quota() == quota)
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let receipt = controller
                .controller_policy_v8_root_receipt_v1()?
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let proof = replay(controller, held_controller)?;
            if !proof.matches_controller_ack(ack, controller_uid) || proof.ack() != receipt {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            settle_released_v8_owner_rows(
                controller,
                source_domains,
                held_controller,
                receipt,
                proof,
                cache_held,
                cache_released,
                controller_uid,
            )
        }))
    })?;
    let outcome = finish(prepared);
    native.postflight_after_finish_v1()?;
    outcome?;
    native.finish_readback_v1()?;
    Ok(())
}
