//! Forwarder lifecycle topology resolution.

use super::*;

pub(super) fn forwarder_queue_targets(
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
) -> Result<BTreeSet<crucible::model::ResolvedFaultTarget>, SchedulerError> {
    let crucible::model::ResolvedFaultTarget::NetworkForwarder { forwarder } = &action.target
    else {
        return Err(network_effect_application_error(
            action,
            "forwarder lifecycle requires a network-forwarder target",
        ));
    };
    if !topology
        .network_forwarders
        .iter()
        .any(|declaration| declaration.id.as_str() == forwarder.as_str())
    {
        return Err(network_effect_application_error(
            action,
            "forwarder lifecycle target is absent from World",
        ));
    }

    topology
        .network_queues
        .iter()
        .filter(|queue| queue.owner.as_str() == forwarder.as_str())
        .map(|queue| {
            FaultObjectId::parse(queue.id.as_str().to_owned())
                .map(
                    |queue_id| crucible::model::ResolvedFaultTarget::NetworkQueue {
                        owner: forwarder.clone(),
                        queue: queue_id,
                    },
                )
                .map_err(|_error| {
                    network_effect_application_error(
                        action,
                        "forwarder queue ID is not a valid fault object ID",
                    )
                })
        })
        .collect()
}
