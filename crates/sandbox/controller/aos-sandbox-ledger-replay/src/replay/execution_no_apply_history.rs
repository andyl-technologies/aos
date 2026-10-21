//! Checks the complete actual namespace78 history before an issuer appends.
//!
//! These borrowed map operations perform no IO, generate no entropy and grant
//! no native permission. The real paid floor original owns the writer and all
//! retained failure/results. Missing instance metadata never repairs itself.

use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::{
    ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2 as INSTANCE_KEY,
    RootExecutionNoApplyFloorHeadDataV2 as Head, RootExecutionNoApplyFloorKeyDataV2 as Key,
    RootExecutionNoApplyFloorRecordDataV2 as Record,
    RootExecutionNoApplyInstanceDataV2 as Instance,
};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

/// Retains the complete canonical namespace78 selection as comparison DATA.
///
/// Construction scans every actual row and checks all predecessor/head joins;
/// this DATA cannot issue native append or a new Root continuation purpose.
pub struct HistoryDataV2 {
    instance: Option<Instance>,
    selected: Option<Record>,
}

impl HistoryDataV2 {
    /// Returns the canonical saved instance without creating a replacement.
    #[must_use]
    pub const fn instance_data_v2(&self) -> Option<Instance> {
        self.instance
    }

    /// Returns the selected exact latest floor without authorizing mutation.
    #[must_use]
    pub const fn selected_data_v2(&self) -> Option<Record> {
        self.selected
    }
}

/// Checks every instance, head, revision and immutable predecessor association.
///
/// # Errors
/// Refuses malformed or orphaned rows, inconsistent instances, broken revision
/// chains and count overflow. A missing instance never repairs itself.
pub fn inspect_history_data_v2(
    authority: HistoricalLedgerReadViewV1<'_>,
    operation: [u8; 16],
) -> Result<HistoryDataV2, JournalError> {
    Key::new(operation, 1).map_err(|_| JournalError::ProtectedBoundary)?;
    let namespace = RecordNamespace::RootExecutionNoApplyFloorV2;
    let instance = authority
        .get(namespace, &INSTANCE_KEY)
        .map(|bytes| Instance::decode_canonical(&INSTANCE_KEY, bytes))
        .transpose()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let mut floors = 0_u64;
    let mut heads = 0_u64;
    for (key, bytes) in authority.records(namespace) {
        if key == INSTANCE_KEY {
            continue;
        }
        let instance = instance.ok_or(JournalError::ProtectedBoundary)?;
        match key.len() {
            16 => {
                let head = Head::decode_canonical(key, bytes)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                let floor = record_data_v2(authority, head.revision_key_data_v2())?;
                if !head.matches_floor_data_v2(floor)
                    || floor.fields().root_instance != instance.instance()
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                heads = heads.checked_add(1).ok_or(JournalError::JournalTooLarge)?;
            }
            24 => {
                let floor = Record::decode_canonical(key, bytes)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                let fields = floor.fields();
                let head_key = floor.key().head_key_data_v2();
                let head = Head::decode_canonical(
                    &head_key,
                    authority
                        .get(namespace, &head_key)
                        .ok_or(JournalError::ProtectedBoundary)?,
                )
                .map_err(|_| JournalError::ProtectedBoundary)?;
                if fields.root_instance != instance.instance()
                    || head.revision_key_data_v2().revision() < fields.revision
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                if fields.revision > 1 {
                    let previous = record_data_v2(
                        authority,
                        Key::new(fields.operation, fields.revision - 1)
                            .map_err(|_| JournalError::ProtectedBoundary)?,
                    )?;
                    require_immutable_successor_data_v2(previous, floor)?;
                }
                floors = floors.checked_add(1).ok_or(JournalError::JournalTooLarge)?;
            }
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }
    // A genuine first transaction always saves all three atomic members.
    // An isolated instance, orphan floor/head or lost instance is quarantine.
    if instance.is_some() != (floors > 0 && heads > 0) {
        return Err(JournalError::ProtectedBoundary);
    }
    let selected = authority
        .get(namespace, &operation)
        .map(|bytes| {
            let head = Head::decode_canonical(&operation, bytes)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            record_data_v2(authority, head.revision_key_data_v2())
        })
        .transpose()?;
    Ok(HistoryDataV2 { instance, selected })
}

/// Decodes the exact existing canonical revision from the supplied history.
///
/// # Errors
/// Refuses an absent, malformed or differently keyed saved revision.
pub fn record_data_v2(authority: HistoricalLedgerReadViewV1<'_>, key: Key) -> Result<Record, JournalError> {
    let key = key.encode_canonical();
    Record::decode_canonical(
        &key,
        authority
            .get(RecordNamespace::RootExecutionNoApplyFloorV2, &key)
            .ok_or(JournalError::ProtectedBoundary)?,
    )
    .map_err(|_| JournalError::ProtectedBoundary)
}

/// Compares all immutable associations and the exact advancing predecessor.
///
/// # Errors
/// Refuses a changed family member, nonconsecutive revision or stale authority
/// watermark. These comparisons neither sample nor lend a native writer.
pub fn require_immutable_successor_data_v2(
    old: Record,
    fresh: Record,
) -> Result<(), JournalError> {
    let old_fields = old.fields();
    let fields = fresh.fields();
    if fields.root_instance != old_fields.root_instance
        || fields.operation != old_fields.operation
        || old_fields.revision.checked_add(1) != Some(fields.revision)
        || fields.authority_next <= old_fields.authority_next
        || fields.predecessor_floor != old.digest()
        || fields.host_lease.fields().accepted_source
            != old_fields.host_lease.fields().accepted_source
        || fields.host_lease.fields().marker != old_fields.host_lease.fields().marker
        || fields.host_lease.fields().terminal_archive_head
            != old_fields.host_lease.fields().terminal_archive_head
        || fields.host_lease.fields().signed_terminal_outcome
            != old_fields.host_lease.fields().signed_terminal_outcome
        || fields.predecessor_rows != old_fields.predecessor_rows
        || fields.successor_rows != old_fields.successor_rows
        || fields.terminal_wall_seconds != old_fields.terminal_wall_seconds
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}
