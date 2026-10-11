//! Qualifies mandatory operations only for the complete preserving four-owner source.
//!
//! Contract matching and actual installed native enrollment remain conjuncts.
//! These operation names select existing public owner codecs; they supply no
//! physical capture, architecture, replay, fork or general backend authority.

use super::super::{InstalledNodeKind, InstalledNodeSelection, NodeObservedError, refused};
use crucible::node_admission::NodeCapabilityRequirement;

pub(super) fn selected(selections: &[InstalledNodeSelection]) -> bool {
    super::super::native_state::host_group::selection::preserving_selected(selections)
}

pub(super) fn qualify(
    kind: &InstalledNodeKind,
    demand: &NodeCapabilityRequirement,
) -> Result<(), NodeObservedError> {
    if demand.compute.is_some()
        || !demand.extensions.is_empty()
        || demand.guarantees.isolated_fork
        || demand.guarantees.conditional_replay
    {
        return Err(refused(
            "preserving group excludes architecture, EXT, fork and replay",
        ));
    }
    for operation in &demand.operations {
        let facet = match (kind, operation.operation.as_str()) {
            (InstalledNodeKind::HostClock, "exact_run" | "boundary_settle")
            | (InstalledNodeKind::HostScripted { .. }, "exact_run" | "boundary_settle")
            | (InstalledNodeKind::HostIo { .. }, "exact_run" | "boundary_settle") => {
                "host/exact-v1"
            }
            (InstalledNodeKind::HostClock, "capture" | "durable_restart") => {
                crucible::node_adapters::HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE
            }
            (InstalledNodeKind::HostScripted { .. }, "capture" | "durable_restart")
            | (InstalledNodeKind::HostIo { .. }, "capture" | "durable_restart") => {
                crucible::node_adapters::HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE
            }
            (InstalledNodeKind::Gem5ClosedPreserving { .. }, "exact_run" | "boundary_settle") => {
                crucible::node_adapters::gem5::GEM5_CLOSED_EXACT_PROFILE
            }
            (InstalledNodeKind::Gem5ClosedPreserving { .. }, "capture" | "durable_restart") => {
                "gem5/public-process-preservation-v1"
            }
            _ => {
                return Err(refused(
                    "operation is outside the complete preserving group policy",
                ));
            }
        };
        if operation.facet.id.as_str() != facet || operation.facet.version != 1 {
            return Err(refused(
                "operation selects another original preserving owner codec",
            ));
        }
    }
    Ok(())
}
