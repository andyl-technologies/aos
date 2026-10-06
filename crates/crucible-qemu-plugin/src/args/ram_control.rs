//! Descriptor-bound independent pager controller launch authority.

use super::*;
use crucible_protocol::ram_control::RamControlTarget;

const KEYS: [&str; 8] = [
    "ram_control_fd",
    "ram_control_session",
    "ram_control_daemon",
    "ram_control_owner",
    "ram_control_node",
    "ram_control_owner_generation",
    "ram_control_arena_generation",
    "ram_control_template",
];

/// Authenticated pager-control setup, passed as one complete launch projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginRamControlArgs {
    /// Independent socket descriptor; distinct from deterministic control IPC.
    pub descriptor: i32,
    /// Fresh controller session, replaced at every fork or restore.
    pub session: [u8; 32],
    /// Exact operational arena authority.
    pub target: RamControlTarget,
}

pub(super) fn is_key(key: &str) -> bool {
    KEYS.contains(&key)
}

fn generation(
    parsed: &ParsedPluginArgs<'_>,
    key: &'static str,
) -> Result<u64, PluginArgsParseError> {
    let value = parsed
        .value(key)
        .ok_or(PluginArgsParseError::MissingRequiredKey { key })?;
    match value.parse::<u64>() {
        Ok(generation) if generation > 0 && generation.to_string() == value => Ok(generation),
        _ => Err(PluginArgsParseError::InvalidRamControl),
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
    sim_fd: i32,
    inherited: Option<PluginInheritedFds>,
) -> Result<Option<PluginRamControlArgs>, PluginArgsParseError> {
    if !KEYS.iter().any(|key| parsed.value(key).is_some()) {
        return Ok(None);
    }
    let descriptor = parse_required_fd(parsed, KEYS[0])?;
    if descriptor <= 2
        || descriptor == sim_fd
        || inherited.is_some_and(|fds| descriptor == fds.shmem_fd || descriptor == fds.wake_fd)
    {
        return Err(PluginArgsParseError::InvalidRamControl);
    }
    let session = parse_required_hash(parsed, KEYS[1])?;
    let daemon_epoch = parse_required_hash(parsed, KEYS[2])?;
    let owner_id = parse_required_hash(parsed, KEYS[3])?;
    let node_id = parse_required_hash(parsed, KEYS[4])?;
    let retained_template = match parsed.value(KEYS[7]) {
        Some("0") => false,
        Some("1") => true,
        _ => return Err(PluginArgsParseError::InvalidRamControl),
    };
    if session == [0; 32] || daemon_epoch == [0; 32] || owner_id == [0; 32] || node_id == [0; 32] {
        return Err(PluginArgsParseError::InvalidRamControl);
    }
    Ok(Some(PluginRamControlArgs {
        descriptor,
        session,
        target: RamControlTarget {
            daemon_epoch,
            owner_id,
            node_id,
            owner_generation: generation(parsed, KEYS[5])?,
            arena_generation: generation(parsed, KEYS[6])?,
            retained_template,
        },
    }))
}
