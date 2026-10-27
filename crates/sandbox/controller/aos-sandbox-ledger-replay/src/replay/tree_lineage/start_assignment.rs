//! Selects complete historical Tree/Lineage DATA for Start assignment.
//!
//! The same full lineage replay and decoder geometry serve ordinary and actual
//! Root readers. Rows grant no native health, ancestry or mutation authority.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_model::{ObjectDigest, ProjectId, SandboxId};
use aos_sandbox_protocol::domain_ledger::{
    DomainLedgerDataError, readonly::HistoricalLedgerRowsDataV2,
};

/// Preserves a canonical lineage refusal or an absent exact project/sandbox.
#[derive(Debug, thiserror::Error)]
pub enum StartAssignmentTreeReadDataErrorV2 {
    /// The complete canonical lineage is malformed or inconsistent.
    #[error(transparent)]
    History(#[from] DomainLedgerDataError),
    /// The supplied complete rows contain no exact predecessor target.
    #[error("historical assignment tree target is absent")]
    MissingTarget,
}

/// Prices one complete structural replay from these same historical rows.
///
/// The 16-byte record minimum preserves the original decoder/cell bound and
/// compiled canonical model types. No native or generic replay is included.
///
/// # Errors
/// Rejects checked geometry or scalar conversion overflow.
pub fn create_storage_tree_model_demand_v1(
    rows: HistoricalLedgerRowsDataV2<'_>,
) -> Result<aos_sandbox_model::ResourceVector, Mechanical> {
    use aos_sandbox_model::source_tree_model::SandboxTreeRecordV1;
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    let invalid = || Mechanical::JournalTooLarge;
    let mut bytes = 0_usize;
    let mut row_count = 0_usize;
    for (_, key, value) in rows.all_records() {
        bytes = bytes
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(invalid)?;
        row_count = row_count.checked_add(1).ok_or_else(invalid)?;
    }
    let children = bytes
        .checked_div(16)
        .and_then(|n| n.checked_add(row_count))
        .ok_or_else(invalid)?;
    let width = std::mem::size_of::<(SandboxTreeRecordV1, SandboxId, usize, [usize; 6])>();
    let cells = children
        .checked_mul(8)
        .and_then(|n| n.checked_add(8))
        .ok_or_else(invalid)?;
    let maps = row_count
        .checked_mul(8)
        .and_then(|n| {
            n.checked_mul(std::mem::size_of::<(
                ProjectId,
                super::ClosedTreeLineageHeadV1,
                [usize; 6],
            )>())
        })
        .ok_or_else(invalid)?;
    let memory = cells
        .checked_mul(width)
        .and_then(|n| n.checked_add(maps))
        .and_then(|n| n.checked_add(bytes.checked_mul(32)?))
        .ok_or_else(invalid)?;
    let memory = memory
        .checked_add(model_forwarding_control_bytes_v1().ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(
            D::MemoryBytes,
            u64::try_from(memory).map_err(|_| invalid())?,
        )
        .with(
            D::MetadataEntries,
            u64::try_from(cells).map_err(|_| invalid())?,
        ))
}

/// Selects the exact predecessor through the sole complete lineage replay.
///
/// The actual caller performs its native health check before this pure entry.
/// Supplied rows and the returned structural tuple grant no currentness.
///
/// # Errors
/// Rejects invalid complete lineage or an absent exact project/sandbox.
pub fn start_assignment_source_tree_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>,
    project: ProjectId,
    sandbox: SandboxId,
) -> Result<
    (
        aos_sandbox_model::source_tree_model::SandboxTreeRecordV1,
        ObjectDigest,
        ObjectDigest,
    ),
    StartAssignmentTreeReadDataErrorV2,
> {
    let heads = super::replay_closed_tree_lineage_records_v2(rows.all_records())?;
    let head = heads
        .get(&project)
        .ok_or(StartAssignmentTreeReadDataErrorV2::MissingTarget)?;
    let record = *head
        .tree
        .record(sandbox)
        .ok_or(StartAssignmentTreeReadDataErrorV2::MissingTarget)?;
    Ok((record, head.tree_head, head.lineage_head))
}

/// Prices the same full structural replay and actual keyed containers.
///
/// Native replay, role checks and admission remain with the genuine caller.
/// The additional typed row/error/return carriers affect memory only.
///
/// # Errors
/// Rejects malformed cardinalities or checked geometry overflow.
pub fn start_assignment_tree_receiving_demand_v2(
    rows: HistoricalLedgerRowsDataV2<'_>,
) -> Result<aos_sandbox_model::ResourceVector, Mechanical> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

    let memory = create_storage_tree_model_demand_v1(rows)?.get(D::MemoryBytes);
    let names = super::retained::closed_tree_lineage_named_entries_v2(rows.all_records())?;
    let controls = assignment_forwarding_control_bytes_v2().ok_or(Mechanical::JournalTooLarge)?;
    let memory = memory
        .checked_add(u64::try_from(controls).map_err(|_| Mechanical::JournalTooLarge)?)
        .ok_or(Mechanical::JournalTooLarge)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(D::MetadataEntries, names))
}

fn model_forwarding_control_bytes_v1() -> Option<usize> {
    use aos_sandbox_model::ResourceVector;

    // Actual row argument and typed result constructor/ABI/caller planes.
    std::mem::size_of::<HistoricalLedgerRowsDataV2<'_>>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<Result<ResourceVector, Mechanical>>().checked_mul(3)?)
}

fn assignment_forwarding_control_bytes_v2() -> Option<usize> {
    use aos_sandbox_model::{ResourceVector, source_tree_model::SandboxTreeRecordV1};
    type TreeResult = Result<
        (SandboxTreeRecordV1, ObjectDigest, ObjectDigest),
        StartAssignmentTreeReadDataErrorV2,
    >;

    // The demand and actual later selector each receive the same borrowed map;
    // constructor/ABI/caller values are explicit, with no Rust-field name fee.
    std::mem::size_of::<HistoricalLedgerRowsDataV2<'_>>()
        .checked_mul(6)?
        .checked_add(std::mem::size_of::<Result<ResourceVector, Mechanical>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<TreeResult>().checked_mul(3)?)
}
