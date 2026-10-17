//! Listener admission for node debugger gateways.

use std::net::SocketAddr;

use crucible::{GdbListen, SchedulerError};

/// Validates operator listener requests without exposing native debugger custody.
///
/// The policy accepts loopback TCP metadata and an ephemeral-listener sentinel
/// for private Unix relays. It neither opens a listener nor binds a debugger to
/// an execution owner.
#[derive(Clone, Copy, Debug)]
pub struct DebuggerListenerPolicy<'a> {
    /// Listener spelling authorized by the existing configuration.
    pub configured_listener: &'a str,
    /// Permission to request another loopback listener spelling.
    pub allow_requested_loopback_listen: bool,
}

impl DebuggerListenerPolicy<'_> {
    /// Validates a listener against the configured loopback policy.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, non-loopback or unauthorized listeners.
    pub fn trusted_listener(&self, listen: &GdbListen) -> Result<SocketAddr, SchedulerError> {
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
        if !self.allow_requested_loopback_listen && listen.as_str() != self.configured_listener {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "requested debugger listener {} does not match configured listener {}",
                    listen.as_str(),
                    self.configured_listener
                ),
            });
        }
        Ok(requested)
    }

    /// Validates the ephemeral-listener sentinel used by private Unix relays.
    ///
    /// # Errors
    ///
    /// Returns an error for a concrete TCP listener or a rejected listener policy.
    pub fn private_gateway_request(&self, listen: &GdbListen) -> Result<(), SchedulerError> {
        let requested = self.trusted_listener(listen)?;
        if requested.port() != 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "production debugger gateway uses a private Unix endpoint; explicit TCP listener {requested} is unsupported"
                ),
            });
        }
        Ok(())
    }
}
