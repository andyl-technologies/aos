//! Prepares the bounded source-selected native model roster before child effects.
//!
//! Each selection constructs its own actual inactive model, including an
//! independent Block copy-on-write overlay even when immutable base bytes are
//! shared. This planner supplies ownership and storage, not admission or Ready.
//! Complete profile regeneration and artifact enrollment precede it; original
//! graph evidence and the all-owner activation barrier remain mandatory afterward.

use std::collections::{BTreeMap, BTreeSet};

use crate::node_scenario::NodeScenario;
use crucible::{node_adapters::HostModel, node_contract::SimulationNode};
use crucible_device::{
    clock::VirtualClock,
    netlink::{LinkFaults, NetLink},
};
use crucible_node_contract::{Id, canonical};

const MAXIMUM_NODES: usize = 64;
const MAXIMUM_INITIALIZATION_BYTES: usize = 4 * 1024 * 1024;

use super::{
    InstalledIoArtifact, InstalledNodeKind, InstalledNodeSelection, NodeObservedError,
    condition_debug, controlled, faulted, io, native, refused, scripted, seeded, semantics,
};

/// Holds each independently constructed original model and pre-reserved node slots.
pub(super) struct PreparedModelRoster {
    models: BTreeMap<Id, HostModel>,
    nodes: Vec<Box<dyn SimulationNode>>,
}

impl PreparedModelRoster {
    /// Constructs the complete inactive host roster before any provider child.
    ///
    /// # Errors
    /// Refuses an empty, oversized, unsorted or aliased roster, unavailable finite
    /// node storage, unsupported native backend, changed artifact or model body.
    pub(super) fn new(
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
    ) -> Result<Self, NodeObservedError> {
        if selections.is_empty()
            || selections.len() > MAXIMUM_NODES
            || selections
                .windows(2)
                .any(|pair| pair[0].node >= pair[1].node)
            || selections
                .iter()
                .map(|node| &node.owner)
                .collect::<BTreeSet<_>>()
                .len()
                != selections.len()
        {
            return Err(refused(
                "prepared roster needs 1–64 sorted nodes with independent owners",
            ));
        }

        // The original source descriptor bodies bound serialized model geometry
        // before constructors copy their installed artifacts. This uses the
        // existing 64-node/4MiB model interface, not a larger aggregate budget.
        let mut initialization_credit = 0usize;
        for selected in selections {
            if matches!(
                selected.kind,
                InstalledNodeKind::ReferenceDevice { .. }
                    | InstalledNodeKind::ReferenceNativeLinked { .. }
            ) {
                continue;
            }
            let descriptor = scenario
                .descriptors
                .iter()
                .find(|node| node.id == selected.node)
                .ok_or_else(|| refused("prepared model omitted its original source descriptor"))?;
            let length =
                usize::try_from(descriptor.initialization_ref.length.get()).map_err(native)?;
            if length > MAXIMUM_INITIALIZATION_BYTES {
                return Err(refused(
                    "prepared model initialization exceeds its original interface credit",
                ));
            }
            initialization_credit = initialization_credit.checked_add(length).ok_or_else(|| {
                refused("prepared model aggregate initialization credit overflow")
            })?;
            if initialization_credit > MAXIMUM_NODES * MAXIMUM_INITIALIZATION_BYTES {
                return Err(refused(
                    "prepared model aggregate initialization credit exceeded",
                ));
            }
            let body = scenario
                .content
                .iter()
                .find(|body| body.reference == descriptor.initialization_ref)
                .ok_or_else(|| refused("prepared model source initialization body missing"))?;
            if canonical::content_ref(&body.bytes, &body.reference.media_type)? != body.reference {
                return Err(refused("prepared model source initialization body changed"));
            }
        }

        let mut nodes = Vec::new();
        nodes.try_reserve_exact(selections.len()).map_err(native)?;
        let mut models = BTreeMap::new();
        for selection in selections {
            match &selection.kind {
                InstalledNodeKind::HostNetLink {
                    source_node,
                    latency_ps,
                    floor_ps,
                    ..
                } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::Link(Box::new(
                            NetLink::new(
                                *source_node,
                                latency_ps.get(),
                                floor_ps.get(),
                                LinkFaults::none(),
                            )
                            .map_err(native)?,
                        )),
                    );
                }
                InstalledNodeKind::HostSeededLink { profile } => {
                    models.insert(
                        selection.node.clone(),
                        seeded::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::HostRecordedBlock { profile }
                | InstalledNodeKind::HostRecordedBlockPreserving { profile } => {
                    models.insert(
                        selection.node.clone(),
                        io::build_model(selection, &profile.storage, artifacts)?,
                    );
                }
                InstalledNodeKind::HostPacketReceiver {
                    source_node,
                    latency_ps,
                } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::PacketReceiver(Box::new(
                            crucible::node_adapters::PacketReceiver::new(
                                *source_node,
                                latency_ps.get(),
                            )
                            .map_err(|error| refused(&error.reason))?,
                        )),
                    );
                }
                InstalledNodeKind::HostControlledFaultLink { profile } => {
                    models.insert(
                        selection.node.clone(),
                        controlled::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::HostFaultedLink { profile } => {
                    models.insert(
                        selection.node.clone(),
                        faulted::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::HostIo { profile } => {
                    models.insert(
                        selection.node.clone(),
                        io::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::HostScripted { profile } => {
                    models.insert(
                        selection.node.clone(),
                        scripted::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::Gem5ArmRoot
                | InstalledNodeKind::Gem5Closed { .. }
                | InstalledNodeKind::Gem5ClosedPreserving { .. }
                | InstalledNodeKind::Gem5ClosedEpochPreserving { .. } => {
                    return Err(refused(
                        "closed gem5 requires its original public preparation bridge",
                    ));
                }
                InstalledNodeKind::HostRateAlarmClock { definition }
                | InstalledNodeKind::HostRateAlarmClockProducer { definition } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::RateAlarmClock(Box::new(
                            crucible::node_adapters::RateAlarmClock::new(definition.clone())
                                .map_err(native)?,
                        )),
                    );
                }
                InstalledNodeKind::HostClock => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::Clock(VirtualClock::new()),
                    );
                }
                InstalledNodeKind::HostConditionDebug { profile }
                | InstalledNodeKind::HostConditionDebugPreserving { profile } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::ConditionObserver(Box::new(condition_debug::build_model(
                            selection, selections, profile, artifacts,
                        )?)),
                    );
                }
                InstalledNodeKind::HostSemantics { profile } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::Semantics(Box::new(semantics::build_model(
                            selection, selections, profile, artifacts,
                        )?)),
                    );
                }
                InstalledNodeKind::ReferenceDevice { .. }
                | InstalledNodeKind::ReferenceNativeLinked { .. } => {}
            }
        }

        for (node, model) in &models {
            let descriptor = scenario
                .descriptors
                .iter()
                .find(|descriptor| &descriptor.id == node)
                .ok_or_else(|| refused("original inactive model descriptor disappeared"))?;
            let expected = scenario
                .content
                .iter()
                .find(|body| body.reference == descriptor.initialization_ref)
                .ok_or_else(|| refused("original inactive model source body disappeared"))?;
            if model
                .initialization_bytes(MAXIMUM_INITIALIZATION_BYTES)
                .map_err(native)?
                != expected.bytes
            {
                return Err(refused(
                    "actual inactive model differs from complete source initialization",
                ));
            }
        }

        Ok(Self { models, nodes })
    }

    /// Transfers original models and reserved slots to the owning world builder.
    pub(super) fn into_parts(self) -> (BTreeMap<Id, HostModel>, Vec<Box<dyn SimulationNode>>) {
        (self.models, self.nodes)
    }
}
