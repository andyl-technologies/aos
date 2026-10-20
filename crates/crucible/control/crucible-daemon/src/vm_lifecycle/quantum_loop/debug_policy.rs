//! QEMU lifecycle configuration adapter for common debugger listener policy.

use super::*;
use crate::node_lifecycle::DebuggerListenerPolicy;

fn listener_policy(configured: &ProductionVmDebugConfig) -> DebuggerListenerPolicy<'_> {
    DebuggerListenerPolicy {
        configured_listener: &configured.operator_listen,
        allow_requested_loopback_listen: configured.allow_requested_loopback_listen,
    }
}

#[cfg(test)]
pub(super) fn trusted_debug_listener(
    configured: &ProductionVmDebugConfig,
    listen: &GdbListen,
) -> Result<SocketAddr, SchedulerError> {
    listener_policy(configured).trusted_listener(listen)
}

pub(super) fn private_gateway_listener_request(
    configured: &ProductionVmDebugConfig,
    listen: &GdbListen,
) -> Result<(), SchedulerError> {
    listener_policy(configured).private_gateway_request(listen)
}
