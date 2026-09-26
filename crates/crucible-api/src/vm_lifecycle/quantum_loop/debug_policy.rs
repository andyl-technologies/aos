//! Production debugger listener policy.

use super::*;

/// Validates an operator listener against the lifecycle's debugger policy.
///
/// # Errors
///
/// Returns an error for malformed, non-loopback, or unauthorized listeners.
pub(super) fn trusted_debug_listener(
    configured: &ProductionVmDebugConfig,
    listen: &GdbListen,
) -> Result<SocketAddr, SchedulerError> {
    let requested: SocketAddr =
        listen
            .as_str()
            .parse()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "parse trusted debugger listener {}: {error}",
                    listen.as_str()
                ),
            })?;
    if !requested.ip().is_loopback() {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "unauthenticated production debugger listener must be loopback, not {requested}"
            ),
        });
    }
    if !configured.allow_requested_loopback_listen && listen.as_str() != configured.operator_listen
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "requested debugger listener {} does not match configured listener {}",
                listen.as_str(),
                configured.operator_listen
            ),
        });
    }
    Ok(requested)
}

/// Accepts the internal ephemeral-listener sentinel for private Unix relay.
///
/// # Errors
///
/// Returns an error when a caller requests a concrete TCP address that the
/// production gateway cannot expose.
pub(super) fn private_gateway_listener_request(
    configured: &ProductionVmDebugConfig,
    listen: &GdbListen,
) -> Result<(), SchedulerError> {
    let requested = trusted_debug_listener(configured, listen)?;
    if requested.port() != 0 {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "production debugger gateway uses a private Unix endpoint; explicit TCP listener {requested} is unsupported"
            ),
        });
    }
    Ok(())
}
