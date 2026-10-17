//! Parses the complete portable host admission envelope independently of policy.
//!
//! Every field is a canonical unsigned decimal scalar. The projection is either
//! absent or complete; zero is an explicit entitlement rather than a default.
//! Actual native inventory and capability checks decide whether it is sufficient.
//!
//! ```text
//! ram_resident_peak=...,ram_backing_peak=...,ram_metadata_peak=...,
//! ram_staging_peak=...,ram_io_slots=...,ram_cpu_slots=...,
//! ram_task_slots=...,ram_fd_slots=...
//! ```

use super::{ParsedPluginArgs, PluginArgsParseError};
use crucible_protocol::ram_control::{
    RAM_CONTROL_BUDGET_COUNT, RAM_CONTROL_BUDGET_ROSTER_MAX_BYTES, RamControlBudget,
    decode_ram_control_budgets,
};

const KEYS: [&str; 8] = [
    "ram_resident_peak",
    "ram_backing_peak",
    "ram_metadata_peak",
    "ram_staging_peak",
    "ram_io_slots",
    "ram_cpu_slots",
    "ram_task_slots",
    "ram_fd_slots",
];

pub use crucible_protocol::ram_control::RamControlResources as PluginRamResources;

pub(super) fn is_key(key: &str) -> bool {
    KEYS.contains(&key) || key == "ram_initial_budgets" || key == "ram_outer_cap"
}

pub(super) fn parse_budgets(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<[RamControlBudget; RAM_CONTROL_BUDGET_COUNT]>, PluginArgsParseError> {
    let Some(text) = parsed.value("ram_initial_budgets") else {
        return Ok(None);
    };
    if text.len() > 2 * RAM_CONTROL_BUDGET_ROSTER_MAX_BYTES
        || text.len() % 2 != 0
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PluginArgsParseError::InvalidRamResources);
    }
    // Length is bounded before decode allocation; upper-case encodings are
    // rejected so setup has one canonical textual projection.
    let bytes = hex::decode(text).map_err(|_| PluginArgsParseError::InvalidRamResources)?;
    decode_ram_control_budgets(&bytes)
        .map(Some)
        .map_err(|_| PluginArgsParseError::InvalidRamResources)
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<PluginRamResources>, PluginArgsParseError> {
    if !KEYS.iter().any(|key| parsed.value(key).is_some()) {
        return Ok(None);
    }
    let mut values = [0; 8];
    for (index, key) in KEYS.iter().enumerate() {
        let text = parsed
            .value(key)
            .ok_or(PluginArgsParseError::MissingRequiredKey { key })?;
        let value = text
            .parse::<u64>()
            .map_err(|_| PluginArgsParseError::InvalidRamResources)?;
        if value.to_string() != text {
            return Err(PluginArgsParseError::InvalidRamResources);
        }
        values[index] = value;
    }
    Ok(Some(PluginRamResources {
        resident_peak_bytes: values[0],
        backing_peak_bytes: values[1],
        metadata_bytes: values[2],
        staging_bytes: values[3],
        paging_io_slots: values[4],
        cpu_slots: values[5],
        task_slots: values[6],
        file_descriptors: values[7],
    }))
}

/// Parses the bounded authenticated operational anchor independently of guest time.
pub(super) fn parse_outer(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<crucible_protocol::ram_control::RamControlOuterCap>, PluginArgsParseError> {
    let Some(text) = parsed.value("ram_outer_cap") else {
        return Ok(None);
    };
    if text.len() != 2 * crucible_protocol::ram_control::RAM_CONTROL_OUTER_BYTES
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PluginArgsParseError::InvalidRamResources);
    }
    let bytes = hex::decode(text).map_err(|_| PluginArgsParseError::InvalidRamResources)?;
    crucible_protocol::ram_control::decode_ram_control_outer(&bytes)
        .map(Some)
        .map_err(|_| PluginArgsParseError::InvalidRamResources)
}
