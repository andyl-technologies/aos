//! Checks every full output bank and active recorder marker without copying it.

use super::*;
use crate::retained_metadata::{
    aliases::MetadataAliasAllocationFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind},
};
use std::mem::{align_of, size_of};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ActiveRole17 {
    Before,
    After,
}
#[derive(Clone, Copy)]
pub(crate) struct ActiveOutput17 {
    pub(crate) capacity: usize,
    pub(crate) maximum: usize,
    pub(crate) initial_length: usize,
    pub(crate) attempted: bool,
    pub(crate) has_reference: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct ActiveRecorder17 {
    pub(crate) maximum_rows: usize,
    pub(crate) capacity_rows: usize,
    pub(crate) retained_rows: usize,
    pub(crate) alias_allocation: MetadataAliasAllocationFacts,
    pub(crate) initialized_lookup_entries: usize,
}

/// Borrows every actual slot; active slots retain exact initial bookkeeping.
pub(crate) struct BorrowedCaptureOutputs17<'body> {
    definition: &'body [u8],
    pub(crate) active_role: Option<ActiveRole17>,
    pub(crate) banks: [&'body [u8]; 5],
    pub(crate) recorders: [&'body [u8]; 2],
    pub(crate) active_output: Option<ActiveOutput17>,
    pub(crate) active_recorder: Option<ActiveRecorder17>,
    pub(crate) limits: [usize; 5],
    pub(crate) reserved: bool,
    pub(crate) failed: bool,
}
impl BorrowedCaptureOutputs17<'_> {
    pub(crate) fn definition_data(&self) -> &[u8] {
        self.definition
    }
}

fn number(raw: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(raw)?).map_err(|_| invalid())
}
fn truth(raw: &[u8]) -> Result<bool, ProviderError> {
    match raw {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(invalid()),
    }
}
fn alias_facts(
    raw: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<MetadataAliasAllocationFacts, ProviderError> {
    ledger
        .read::<MetadataAliasAllocationFacts>(raw, true)?
        .ok_or_else(invalid)
}
fn aliases_layout(
    facts: &MetadataAliasAllocationFacts,
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    let layouts = crate::retained_metadata::aliases::settled17_alias_bank_layouts_data();
    if facts.maximum_rows == 0
        || facts.maximum_rows > 131072
        || facts.row_capacity < facts.maximum_rows
        || facts.lookup_capacity < facts.maximum_rows
        || facts.retained_rows > facts.maximum_rows
        || facts.row_capacity.checked_mul(layouts[0].0) != Some(facts.row_bytes)
        || facts.lookup_capacity.checked_mul(layouts[1].0) != Some(facts.lookup_bytes)
    {
        return Err(invalid());
    }
    if ledger.row_aligned(MetadataRecordKind::Vector, layouts[0].0, layouts[0].1)?
        != facts.row_capacity
        || ledger.row_aligned(MetadataRecordKind::Vector, layouts[1].0, layouts[1].1)?
            != facts.lookup_capacity
    {
        return Err(invalid());
    }
    Ok(())
}
fn capacity_record(raw: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::array(raw)?;
    let kind = plain_string(fields.next_value()?.ok_or_else(invalid)?)?;
    if !matches!(kind, "string" | "vector" | "tree" | "shared" | "boxed") {
        return Err(invalid());
    }
    let extent = number(fields.next_value()?.ok_or_else(invalid)?)?;
    let element = number(fields.next_value()?.ok_or_else(invalid)?)?;
    let alignment = number(fields.next_value()?.ok_or_else(invalid)?)?;
    fields.finish()?;
    if !alignment.is_power_of_two()
        || alignment > isize::MAX as usize
        || kind == "string" && alignment != 1
        || !matches!(kind, "vector" | "tree") && element != 1
        || extent.checked_mul(element).is_none()
    {
        return Err(invalid());
    }
    Ok(())
}
fn retained_bank(raw: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    let mut f = Fields::object(raw)?;
    discard::<crate::connection::settled17::HistoricalReversedByteBank17>(
        f.named("bytes")?,
        ledger,
    )?;
    discard::<Option<ContentRef>>(f.named("reference")?, ledger)?;
    truth(f.named("attempted")?)?;
    f.finish()
}
fn retained_recorder(raw: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    let mut f = Fields::object(raw)?;
    let records = f.named("records")?;
    let aliases = f.named("aliases")?;
    f.finish()?;
    if records != b"null" {
        let mut record = Fields::array(records)?;
        let maximum = number(record.next_value()?.ok_or_else(invalid)?)?;
        let capacity = number(record.next_value()?.ok_or_else(invalid)?)?;
        let mut rows = Fields::array(record.next_value()?.ok_or_else(invalid)?)?;
        record.finish()?;
        if maximum == 0
            || maximum > 131072
            || capacity < maximum
            || ledger.row_aligned(
                MetadataRecordKind::Vector,
                size_of::<MetadataCapacityRecord>(),
                align_of::<MetadataCapacityRecord>(),
            )? != capacity
        {
            return Err(invalid());
        }
        let mut length = 0usize;
        while let Some(raw) = rows.next_value()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > maximum {
                return Err(invalid());
            }
            capacity_record(raw)?;
        }
        rows.finish()?;
    }
    if aliases != b"null" {
        let mut alias = Fields::array(aliases)?;
        let facts = alias_facts(alias.next_value()?.ok_or_else(invalid)?, ledger)?;
        let initialized = number(alias.next_value()?.ok_or_else(invalid)?)?;
        let mut rows = Fields::array(alias.next_value()?.ok_or_else(invalid)?)?;
        alias.finish()?;
        aliases_layout(&facts, ledger)?;
        if initialized > facts.lookup_capacity || initialized > facts.retained_rows {
            return Err(invalid());
        }
        let mut length = 0usize;
        while let Some(raw) = rows.next_value()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > facts.maximum_rows {
                return Err(invalid());
            }
            let _ = super::super::aliases::read_alias_row17_data(raw)?;
        }
        rows.finish()?;
        if length != facts.retained_rows {
            return Err(invalid());
        }
    }
    Ok(())
}
fn active_bank(
    raw: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<ActiveOutput17, ProviderError> {
    let mut f = Fields::object(raw)?;
    let capacity = number(f.named("capacity")?)?;
    let maximum = number(f.named("maximum")?)?;
    let initial_length = number(f.named("initial_length")?)?;
    let attempted = truth(f.named("attempted")?)?;
    let has_reference = truth(f.named("has_reference")?)?;
    f.finish()?;
    if initial_length != 0
        || !attempted
        || has_reference
        || capacity < maximum
        || ledger.row_aligned(MetadataRecordKind::Vector, 1, 1)? != capacity
    {
        return Err(invalid());
    }
    Ok(ActiveOutput17 {
        capacity,
        maximum,
        initial_length,
        attempted,
        has_reference,
    })
}
fn active_recorder(
    raw: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<ActiveRecorder17, ProviderError> {
    let mut f = Fields::object(raw)?;
    let maximum_rows = number(f.named("maximum_rows")?)?;
    let capacity_rows = number(f.named("capacity_rows")?)?;
    let retained_rows = number(f.named("retained_rows")?)?;
    let alias_allocation = alias_facts(f.named("alias_allocation")?, ledger)?;
    let initialized_lookup_entries = number(f.named("initialized_lookup_entries")?)?;
    f.finish()?;
    if maximum_rows == 0
        || maximum_rows > 131072
        || capacity_rows < maximum_rows
        || retained_rows != 0
        || alias_allocation.retained_rows != 0
        || initialized_lookup_entries != 0
        || ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<MetadataCapacityRecord>(),
            align_of::<MetadataCapacityRecord>(),
        )? != capacity_rows
    {
        return Err(invalid());
    }
    aliases_layout(&alias_allocation, ledger)?;
    Ok(ActiveRecorder17 {
        maximum_rows,
        capacity_rows,
        retained_rows,
        alias_allocation,
        initialized_lookup_entries,
    })
}
fn pair(raw: &[u8]) -> Result<(&str, &[u8]), ProviderError> {
    let mut f = Fields::array(raw)?;
    let kind = plain_string(f.next_value()?.ok_or_else(invalid)?)?;
    let body = f.next_value()?.ok_or_else(invalid)?;
    f.finish()?;
    Ok((kind, body))
}

pub(super) fn read<'body>(
    input: &'body [u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<BorrowedCaptureOutputs17<'body>, ProviderError> {
    let mut f = Fields::object(input)?;
    let schema = plain_string(f.named("schema")?)?;
    let active_role = match schema {
        "source-private.native-capture-retained-outputs/17" => None,
        "source-private.native-capture-active-recorder-cut/17" => {
            Some(match plain_string(f.named("active_role")?)? {
                "before" => ActiveRole17::Before,
                "after" => ActiveRole17::After,
                _ => return Err(invalid()),
            })
        }
        _ => return Err(invalid()),
    };
    let mut banks_fields = Fields::array(f.named("banks")?)?;
    let banks = [
        banks_fields.next_value()?.ok_or_else(invalid)?,
        banks_fields.next_value()?.ok_or_else(invalid)?,
        banks_fields.next_value()?.ok_or_else(invalid)?,
        banks_fields.next_value()?.ok_or_else(invalid)?,
        banks_fields.next_value()?.ok_or_else(invalid)?,
    ];
    banks_fields.finish()?;
    let mut limits_fields = Fields::array(f.named("limits")?)?;
    let limits = [
        number(limits_fields.next_value()?.ok_or_else(invalid)?)?,
        number(limits_fields.next_value()?.ok_or_else(invalid)?)?,
        number(limits_fields.next_value()?.ok_or_else(invalid)?)?,
        number(limits_fields.next_value()?.ok_or_else(invalid)?)?,
        number(limits_fields.next_value()?.ok_or_else(invalid)?)?,
    ];
    limits_fields.finish()?;
    let mut recorders_fields = Fields::array(f.named("recorders")?)?;
    let recorders = [
        recorders_fields.next_value()?.ok_or_else(invalid)?,
        recorders_fields.next_value()?.ok_or_else(invalid)?,
    ];
    recorders_fields.finish()?;
    let reserved = truth(f.named("reserved")?)?;
    let failed = truth(f.named("failed")?)?;
    f.finish()?;
    let mut active_output = None;
    let mut active_recorder_value = None;
    for (index, raw) in banks.iter().enumerate() {
        if let Some(role) = active_role {
            let (kind, body) = pair(raw)?;
            let selected = index
                == match role {
                    ActiveRole17::Before => 2,
                    ActiveRole17::After => 4,
                };
            if selected {
                if kind != "active_recorder17" {
                    return Err(invalid());
                }
                let active = active_bank(body, ledger)?;
                if active.maximum != limits[index] {
                    return Err(invalid());
                }
                active_output = Some(active);
            } else {
                if kind != "retained" {
                    return Err(invalid());
                }
                retained_bank(body, ledger)?;
            }
        } else {
            retained_bank(raw, ledger)?;
        }
    }
    for (index, raw) in recorders.iter().enumerate() {
        if let Some(role) = active_role {
            let (kind, body) = pair(raw)?;
            let selected = index
                == match role {
                    ActiveRole17::Before => 0,
                    ActiveRole17::After => 1,
                };
            if selected {
                if kind != "active_recorder17" {
                    return Err(invalid());
                }
                active_recorder_value = Some(active_recorder(body, ledger)?);
            } else {
                if kind != "retained" {
                    return Err(invalid());
                }
                retained_recorder(body, ledger)?;
            }
        } else {
            retained_recorder(raw, ledger)?;
        }
    }
    if active_role.is_some()
        && (!reserved || !failed || active_output.is_none() || active_recorder_value.is_none())
    {
        return Err(invalid());
    }
    Ok(BorrowedCaptureOutputs17 {
        definition: input,
        active_role,
        banks,
        recorders,
        active_output,
        active_recorder: active_recorder_value,
        limits,
        reserved,
        failed,
    })
}
