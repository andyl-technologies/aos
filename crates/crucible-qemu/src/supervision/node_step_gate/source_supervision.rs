//! Publishes the existing Source supervisor before launch and callback birth.
//!
//! The portable roster and original outer anchor describe the same retained
//! host owner for resident and controlled guests. This projection enters no
//! operation and grants no native resident holder, storage, or execution credit.

use crucible_linux_resource::host_supervision::HostOperationSupervisor;

use super::{QemuLaunchPluginConfig, QemuLiveNodeStepGateError};

/// Projects the actual common owner without requiring a pager endpoint.
///
/// # Errors
/// Refuses unavailable supervision, unrepresentable timing, or noncanonical
/// portable records before any child or Source callback can be born.
pub(super) fn publish(
    plugin: QemuLaunchPluginConfig,
    supervisor: &HostOperationSupervisor,
) -> Result<QemuLaunchPluginConfig, QemuLiveNodeStepGateError> {
    let refuse = |operation, source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: format!("{operation}: {source}"),
    };
    let (_, budgets) = supervisor
        .budgets()
        .map_err(|source| refuse("observe Source operation budgets", source.to_string()))?;
    let outer = supervisor
        .outer_cap_binding()
        .map_err(|source| refuse("observe Source original outer anchor", source.to_string()))?;
    let outer = crate::ram_control::outer_cap_to_wire(outer)
        .map_err(|source| refuse("encode Source original outer anchor", source.to_string()))?;

    plugin
        .with_ram_outer_cap(outer)
        .map_err(|source| refuse("publish Source original outer anchor", source.to_string()))?
        .with_ram_initial_budgets(budgets)
        .map_err(|source| refuse("publish Source operation budgets", source.to_string()))
}

#[cfg(test)]
mod tests;
