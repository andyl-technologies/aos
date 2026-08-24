//! Bounded host-contention and scheduler authorization for the block-I/O gate.

use crucible::{
    SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};

pub(super) use crate::supervision::bounded_scheduler_preemption::BoundedSchedulerPreemption as HostAdversary;

/// Authorizes the single node's block-I/O traffic.
pub(super) struct GateSendAuthorizer;

impl SchedulerSendAuthorizer for GateSendAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}
