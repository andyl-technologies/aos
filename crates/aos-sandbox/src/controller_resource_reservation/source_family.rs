//! Compares already-paid complete Source families without issuing a read grant.
//!
//! Both Recover and maintenance first obtain the same retained canonical
//! Lifecycle projection under their own native interval and original horizon.
//! This comparison accepts no replacement projection or caller-empty model.

use crate::lifecycle::LifecycleHistoricalReadOriginalV1;
use crate::{Journal, JournalError, RecordNamespace};
use aos_sandbox_core::OperationId;

pub(super) fn require_first_local_source_families_data_v2(
    source: &Journal,
    model: &LifecycleHistoricalReadOriginalV1,
    expected: Option<(OperationId, [u8; 32])>,
) -> Result<(), JournalError> {
    const CLOSED: JournalError = JournalError::ProtectedBoundary;
    require_supported_source_barriers_v1(source)?;
    if let Some((parent, expected_terminal)) = expected {
        let (operation, digest) = model.operation_v1().map_err(|_| CLOSED)?;
        if operation.operation_id() != parent || digest.digest().as_bytes() != &expected_terminal {
            return Err(CLOSED);
        }
    }
    let (projection, _) = model.projection_ready_v1().map_err(|_| CLOSED)?;
    use crate::lifecycle::protected_journal::{
        LifecycleProtectedRecordKindV1 as Kind, lifecycle_key_selects_operation_v2,
    };
    for envelope in projection.records() {
        if matches!(
            envelope.key().kind(),
            Kind::Intent | Kind::Operation | Kind::Effect
        ) && expected
            .is_none_or(|(parent, _)| !lifecycle_key_selects_operation_v2(envelope.key(), parent))
        {
            return Err(CLOSED);
        }
    }
    Ok(())
}

fn require_supported_source_barriers_v1(source: &Journal) -> Result<(), JournalError> {
    const CLOSED: JournalError = JournalError::ProtectedBoundary;
    use aos_sandbox_ledger_replay::source_policy_hold;
    // Unsupported pending families deny before their dynamic decoder.
    // The remaining same canonical fold contains only fixed hold/Q04 DATA.
    if source
        .records(RecordNamespace::SourceDomainPolicyHold)
        .any(|(key, _)| {
            key == source_policy_hold::DELETE_PENDING_KEY
                || key == source_policy_hold::V8_PENDING_KEY
        })
    {
        return Err(CLOSED);
    }
    let custody =
        source_policy_hold::current_state(source.historical_read_view_v1().materialized_state_v1())
            .map_err(|_| CLOSED)?;
    if custody.hold.is_some_and(|hold| hold.is_held())
        || custody
            .q04_pending
            .as_ref()
            .is_some_and(|pending| pending.is_held())
    {
        return Err(CLOSED);
    }
    use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaV1;
    if source.all_records().any(|(_, key, _)| {
        key.starts_with(
            crate::environment::protected_journal::EnvironmentProtectedJournalSchemaV1::KEY_PREFIX,
        )
    }) {
        return Err(CLOSED);
    }
    Ok(())
}

/// Accepts only operation IDs earned by the same finite historical classifiers.
pub(super) fn require_completed_stop_source_families_data_v1(
    source: &Journal,
    model: &LifecycleHistoricalReadOriginalV1,
    history: &crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1,
    starts: &super::catalog_maintenance::CatalogMaintenanceCompletedStartOriginalV1,
    family: &super::catalog_maintenance::closed_family::CatalogMaintenanceClosedFamilyOriginalV1,
) -> Result<(), JournalError> {
    require_supported_source_barriers_v1(source)?;
    let (projection, _) = model.projection_ready_v1()?;
    use crate::lifecycle::protected_journal::LifecycleProtectedRecordKindV1 as Kind;
    for envelope in projection.records() {
        if !matches!(envelope.key().kind(), Kind::Intent | Kind::Operation | Kind::Effect) {
            continue;
        }
        let id = OperationId::from_bytes(envelope.key().identity()[32..48]
            .try_into().map_err(|_| JournalError::ProtectedBoundary)?);
        if !history.operation_is_completed_v1(id)?
            && !starts.source_operation_is_proved_v1(id)
            && !family.source_operation_is_proved_v1(id)
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}
