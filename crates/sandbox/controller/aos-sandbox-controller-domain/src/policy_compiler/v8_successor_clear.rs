//! Ordered retirement of owner-local V8 settlement fences.
//!
//! Root's fixed socket mints the opaque settled grant for the Controller
//! process. This local barrier compares it with Controller's durable settlement
//! and the released Source row before asking Cache, then Source, to clear their
//! own pending markers. No owner row is deleted and no Create or Apply authority
//! follows from the clear.

use aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldCodecV1;

use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

use std::path::Path;

use aos_sandbox_model::{OperationId, SandboxId};

use crate::Journal;
use aos_sandbox_cache::{CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1};
use crate::journal::controller::production_journal_limits;

use crate::protected_domain_journal::ProtectedDomainJournalErrorV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

use super::CurrentCreatePolicySourceErrorV1;
use aos_sandbox_broker::root_settlement::RootV8SettledGrantV1;

/// Clears Cache's pending V8 marker before Source's under retained owner custody.
///
/// The grant must originate from the fixed, peer-checked Root settlement query.
/// Exact repetition after either owner has committed its marker deletion is
/// accepted by that owner's readback; a changed grant or released row fails.
/// The caller retains the Controller and Source writers in that order. Cache's
/// callback retains its hold writer and physical snapshot through Source clear.
///
/// # Errors
///
/// Rejects an absent or changed Controller settlement, a changed Source row,
/// failed Cache replay or marker clear, or failed Source marker clear.
#[allow(clippy::too_many_arguments)]
pub fn clear_current_create_v8_successor_fences_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    grant: RootV8SettledGrantV1,
) -> Result<(), CurrentCreatePolicySourceErrorV1> {
    let released_source =
        require_settled_owner_cut(controller, source_domains, operation, sandbox, grant)?;

    let mut original = cache.borrow_v8_settlement_clear_v1(physical, grant)?;
    let mut native = original.borrow_context_once_v1()?;
    // The old inspect/finish/finalize were exactly no-op successes. Their
    // native currentness and all three pre-commit posts remain real entries.
    let inspected = {
        let returned = native.borrow_inspection_once_v1();
        match returned {
            Err(cause) => Err(cause),
            Ok(mut guard) => {
                let returned_context = guard.borrow_context_once_v1();
                let result = match returned_context {
                    Err(cause) => Err(cause),
                    Ok(mut context) => {
                        if context.readback_v1().is_none() {
                            context.finish_after_upper_refusal_v1()
                        } else {
                            let inner = context.refresh_after_inspect_once_v1();
                            context.finish_after_inspect_v1().and(inner)
                        }
                    }
                };
                result
            }
        }
    };
    native.postflight_after_inspect_v1()?;
    inspected?;
    native.postflight_after_finish_v1()?;
    native.postflight_before_commit_v1()?;
    let cache_clear = native.clear_settlement_once_v1()?;
    let result = (|| {
        require_settled_owner_cut(controller, source_domains, operation, sandbox, grant)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        source_domains.clear_closed_policy_source_v8_settlement_v1(
            released_source,
            grant,
            cache_clear,
        )?;
        require_settled_owner_cut(controller, source_domains, operation, sandbox, grant)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        Ok::<(), ProtectedDomainJournalErrorV1>(())
    })();
    // The post remains owed after Source refusal; it cannot replace that
    // earlier owner's error when both sides fail.
    let post = native.postflight_after_settlement_clear_v1();
    result?;
    post?;
    Ok(())
}

fn require_settled_owner_cut(
    controller: &Journal,
    source_domains: &ProtectedSourceDomainJournalOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    grant: RootV8SettledGrantV1,
) -> Result<SourceDomainPolicyHoldV1, CurrentCreatePolicySourceErrorV1> {
    let controller_uid = controller.protected_owner_uid()?;
    controller.require_protected_named_location(
        Path::new("/var/lib/aos/sandboxd"),
        "controller.journal",
        controller_uid,
        production_journal_limits(),
    )?;
    source_domains.require_fixed_named_writer_v1()?;

    let released_controller = controller
        .controller_policy_hold_v1()?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let settlement = controller
        .controller_policy_v8_settlement_v1()?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let released_source = source_domains
        .closed_policy_source_hold_v1()?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;

    if released_controller.is_held()
        || released_controller.operation() != operation
        || released_controller.sandbox() != sandbox
        || released_controller.binding() != grant.predecessor()
        || released_controller.epoch() != grant.epoch()
        || settlement.binding() != grant.predecessor()
        || settlement.epoch() != grant.epoch()
        || settlement
            .record_digest()
            .map_err(crate::journal::JournalError::from)?
            != grant.settlement()
        || settlement.controller_released_digest()
            != released_controller
                .record_digest()
                .map_err(crate::journal::JournalError::from)?
        || settlement.root_release_marker_digest() != grant.release_marker()
        || settlement.cache_released_digest() != grant.cache_released()
        || settlement.source_released_digest() != grant.source_released()
        || released_source.is_held()
        || released_source.operation() != operation
        || released_source.sandbox() != sandbox
        || released_source.binding() != grant.predecessor()
        || released_source.epoch() != grant.epoch()
        || released_source.record_digest().map_err(crate::journal::JournalError::from)? != grant.source_released()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    Ok(released_source)
}
