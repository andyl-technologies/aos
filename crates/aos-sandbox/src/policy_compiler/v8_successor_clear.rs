//! Ordered retirement of owner-local V8 settlement fences.
//!
//! Root's fixed socket mints the opaque settled grant for the Controller
//! process. This local barrier compares it with Controller's durable settlement
//! and the released Source row before asking Cache, then Source, to clear their
//! own pending markers. No owner row is deleted and no Create or Apply authority
//! follows from the clear.

use std::path::Path;

use aos_sandbox_core::{OperationId, SandboxId};

use crate::Journal;
use crate::cache_residency::{CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1};
use crate::controller_service::journal::production_journal_limits;
use crate::journal::SourceDomainPolicyHoldV1;
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::{CurrentCreatePolicySourceErrorV1, RootV8SettledGrantV1};

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

    cache.with_cleared_v8_pending_cache_settlement_v1(physical, grant, |cache_clear| {
        require_settled_owner_cut(controller, source_domains, operation, sandbox, grant)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        source_domains.clear_closed_policy_source_v8_settlement_v1(
            released_source,
            grant,
            cache_clear,
        )?;
        require_settled_owner_cut(controller, source_domains, operation, sandbox, grant)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        Ok(())
    })?;
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
        || settlement.record_digest()? != grant.settlement()
        || settlement.controller_released_digest() != released_controller.record_digest()?
        || settlement.root_release_marker_digest() != grant.release_marker()
        || settlement.cache_released_digest() != grant.cache_released()
        || settlement.source_released_digest() != grant.source_released()
        || released_source.is_held()
        || released_source.operation() != operation
        || released_source.sandbox() != sandbox
        || released_source.binding() != grant.predecessor()
        || released_source.epoch() != grant.epoch()
        || released_source.record_digest()? != grant.source_released()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    Ok(released_source)
}
