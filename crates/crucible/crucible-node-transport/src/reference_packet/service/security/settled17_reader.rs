//! Retains checked empty supervisor banks under their actual native17 group.
//!
//! The source writer retains and serializes all incident/quarantine branches.
//! This reader explicitly refuses active branches until their complete typed
//! readers are supplied; it never substitutes empty state for retained data.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};
use std::mem::{align_of, size_of};

/// Retains the actual requested empty-bank capacities without quarantine traits.
pub(crate) struct HistoricalNativeSupervisor17 {
    pub(crate) banks: HistoricalNativeSupervisorBanks,
    pub(crate) group: usize,
}

/// Validates the complete supported payload before defining its shared group.
///
/// # Errors
/// Refuses malformed schema/rows, nonempty retained incidents or quarantines,
/// changed shared identity or unavailable exact final bank capacity.
pub(crate) fn read_current_native17_supervisor_root_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativeSupervisor17>, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Supervisor>())?
        != size_of::<Supervisor>()
    {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::NativeSupervisor)?;
    let mut fields = Fields::object(input)?;
    if plain_string(fields.named("schema")?)? != "source-private.native-supervisor-history/17" {
        return Err(invalid());
    }
    let incident_capacity = ledger
        .read::<usize>(fields.named("incidents_capacity")?, true)?
        .ok_or_else(invalid)?;
    let mut incidents = Fields::array(fields.named("incidents")?)?;
    if incidents.next_value()?.is_some() {
        return Err(ProviderError::Correlation(
            "native17 retained supervisor incident unsupported",
        ));
    }
    let quarantine_capacity = ledger
        .read::<usize>(fields.named("quarantines_capacity")?, true)?
        .ok_or_else(invalid)?;
    let mut quarantines = Fields::array(fields.named("quarantines")?)?;
    if quarantines.next_value()?.is_some() {
        return Err(ProviderError::Correlation(
            "native17 retained Blob quarantine unsupported",
        ));
    }
    fields.finish()?;
    if ledger.row_aligned(
        MetadataRecordKind::Vector,
        size_of::<ConnectionIncident>(),
        align_of::<ConnectionIncident>(),
    )? != incident_capacity
        || ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<BlobQuarantine>(),
            align_of::<BlobQuarantine>(),
        )? != quarantine_capacity
    {
        return Err(invalid());
    }
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, size_of::<Supervisor>(), input, rows)?;
    ledger.native17_target_vector_data::<ConnectionIncident>(incident_capacity)?;
    ledger.native17_target_vector_data::<BlobQuarantine>(quarantine_capacity)?;
    if !build {
        return Ok((None, group));
    }
    let bytes = incident_capacity
        .checked_mul(size_of::<ConnectionIncident>())
        .and_then(|bytes| {
            quarantine_capacity
                .checked_mul(size_of::<BlobQuarantine>())
                .and_then(|quarantines| bytes.checked_add(quarantines))
        })
        .ok_or_else(invalid)?;
    let mut banks = None;
    HistoricalNativeSupervisorBanks::reconstruct_empty_into(
        &mut banks,
        incident_capacity,
        quarantine_capacity,
        bytes,
    )?;
    Ok((
        Some(HistoricalNativeSupervisor17 {
            banks: banks.ok_or_else(invalid)?,
            group,
        }),
        group,
    ))
}

#[cfg(test)]
mod tests;
