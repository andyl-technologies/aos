//! Negotiation keeps model semantics, provider guarantees, and backend features distinct.

use crate::{wire, ProtocolError, MODEL_VERSION, WORKER_VERSION};

/// Contains the intersection of requested and supported worker contracts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// Selected transport contract.
    pub protocol_version: wire::Version,
    /// Allocation semantics supported by both peers.
    pub model_version: wire::Version,
    /// Finite resource bounds applied to the channel and decoded input.
    pub limits: wire::WireLimits,
    /// Native solver and compiler-adapter build identity.
    pub backend_build_id: String,
}

impl wire::WireLimits {
    /// Returns finite default limits for portable application-owned workers.
    pub fn standard() -> Self {
        Self {
            max_frame_bytes: 16 * 1024 * 1024,
            max_problem_bytes: 8 * 1024 * 1024,
            max_decoded_bytes: 64 * 1024 * 1024,
            max_items: 100_000,
            max_targets: 10_000,
            max_dimensions: 128,
            max_memberships: 1_000_000,
            max_domain_entries: 1_000_000,
            max_overrides: 1_000_000,
            max_constraints: 100_000,
            max_objectives: 10_000,
            max_nesting: 32,
            max_string_bytes: 4096,
            max_prepared: 16,
            max_prepared_bytes: 64 * 1024 * 1024,
            max_diagnostic_bytes: 16_384,
        }
    }
}

/// Validates a capability response and computes finite shared limits.
///
/// # Errors
///
/// Returns an error for unsupported versions, absent limits/build identity,
/// missing required capabilities, or zero bounds.
pub fn negotiate(
    hello: &wire::Hello,
    capabilities: &wire::Capabilities,
) -> Result<Negotiated, ProtocolError> {
    let version = capabilities
        .protocol_version
        .ok_or_else(|| ProtocolError::Negotiation("missing selected protocol version".into()))?;
    if version != WORKER_VERSION || !hello.protocol_versions.contains(&version) {
        return Err(ProtocolError::Negotiation(
            "unsupported worker version".into(),
        ));
    }
    if !hello.model_versions.contains(&MODEL_VERSION)
        || !capabilities.model_versions.contains(&MODEL_VERSION)
    {
        return Err(ProtocolError::Negotiation(
            "unsupported allocation model".into(),
        ));
    }
    if capabilities.backend_name.is_empty() || capabilities.backend_build_id.is_empty() {
        return Err(ProtocolError::Negotiation(
            "missing backend build identity".into(),
        ));
    }
    for required in &hello.required_capabilities {
        if !capabilities.capabilities.contains(required) {
            return Err(ProtocolError::Negotiation(format!(
                "missing required capability {required}"
            )));
        }
    }
    let requested = hello
        .limits
        .as_ref()
        .ok_or_else(|| ProtocolError::Negotiation("missing requested bounds".into()))?;
    let offered = capabilities
        .limits
        .as_ref()
        .ok_or_else(|| ProtocolError::Negotiation("missing offered bounds".into()))?;
    let limits = intersect_limits(requested, offered)?;

    Ok(Negotiated {
        protocol_version: version,
        model_version: MODEL_VERSION,
        limits,
        backend_build_id: capabilities.backend_build_id.clone(),
    })
}

/// Binds an exchange to one session, worker generation, and request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Correlation {
    /// Application-owned session generation.
    pub session_generation: u64,
    /// Provider-issued generation unique within the session.
    pub worker_generation: u64,
    /// Strictly increasing request identifier within the worker generation.
    pub request_id: u64,
}

impl Correlation {
    /// Extracts a nonzero exchange identity from an envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if any generation or request identifier is zero.
    pub fn from_envelope(envelope: &wire::WorkerEnvelope) -> Result<Self, ProtocolError> {
        if envelope.session_generation == 0
            || envelope.worker_generation == 0
            || envelope.request_id == 0
        {
            return Err(ProtocolError::Correlation(
                "zero generation or request identifier".into(),
            ));
        }
        Ok(Self {
            session_generation: envelope.session_generation,
            worker_generation: envelope.worker_generation,
            request_id: envelope.request_id,
        })
    }

    /// Checks that a response belongs to this exact exchange.
    ///
    /// # Errors
    ///
    /// Returns an error for stale generations, request mismatches, or versions.
    pub fn check(&self, envelope: &wire::WorkerEnvelope) -> Result<(), ProtocolError> {
        if envelope.protocol_version != Some(WORKER_VERSION)
            || Self::from_envelope(envelope)? != *self
        {
            return Err(ProtocolError::Correlation(
                "version, generation, or request differs".into(),
            ));
        }
        Ok(())
    }
}

/// Tracks one active solve and bounds replay detection to scalar state.
#[derive(Debug)]
pub struct SolveTracker {
    session_generation: u64,
    worker_generation: u64,
    last_request_id: u64,
    active: Option<Correlation>,
}

impl SolveTracker {
    /// Creates an idle tracker bound to two nonzero generations.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero session or worker generation.
    pub fn new(session_generation: u64, worker_generation: u64) -> Result<Self, ProtocolError> {
        if session_generation == 0 || worker_generation == 0 {
            return Err(ProtocolError::Correlation("zero generation".into()));
        }
        Ok(Self {
            session_generation,
            worker_generation,
            last_request_id: 0,
            active: None,
        })
    }

    /// Begins one solve without allowing overlapping or repeated request IDs.
    ///
    /// # Errors
    ///
    /// Returns an error for another active solve or an invalid binding/operation.
    pub fn begin(&mut self, envelope: &wire::WorkerEnvelope) -> Result<(), ProtocolError> {
        if self.active.is_some() {
            return Err(ProtocolError::Correlation(
                "worker already has an active solve".into(),
            ));
        }
        let correlation = Correlation::from_envelope(envelope)?;
        if correlation.session_generation != self.session_generation
            || correlation.worker_generation != self.worker_generation
            || correlation.request_id <= self.last_request_id
            || envelope.protocol_version != Some(WORKER_VERSION)
        {
            return Err(ProtocolError::Correlation(
                "stale or repeated solve request".into(),
            ));
        }
        if !matches!(envelope.body, Some(wire::worker_envelope::Body::Solve(_))) {
            return Err(ProtocolError::InvalidMessage(
                "expected solve request".into(),
            ));
        }
        self.last_request_id = correlation.request_id;
        self.active = Some(correlation);
        Ok(())
    }

    /// Accepts a correlated event and returns whether it is terminal.
    ///
    /// # Errors
    ///
    /// Returns an error for unsolicited, stale, duplicate terminal, or wrong events.
    pub fn accept(&mut self, envelope: &wire::WorkerEnvelope) -> Result<bool, ProtocolError> {
        let correlation = self
            .active
            .ok_or_else(|| ProtocolError::Correlation("no active solve".into()))?;
        correlation.check(envelope)?;
        let terminal = match envelope.body {
            Some(
                wire::worker_envelope::Body::Progress(_)
                | wire::worker_envelope::Body::Candidate(_),
            ) => false,
            Some(
                wire::worker_envelope::Body::Finished(_) | wire::worker_envelope::Body::Error(_),
            ) => true,
            _ => {
                return Err(ProtocolError::InvalidMessage(
                    "unexpected solve response".into(),
                ))
            }
        };
        if terminal {
            self.active = None;
        }
        Ok(terminal)
    }
}

fn intersect_limits(
    left: &wire::WireLimits,
    right: &wire::WireLimits,
) -> Result<wire::WireLimits, ProtocolError> {
    macro_rules! minimum {
        ($field:ident) => {{
            if left.$field == 0 || right.$field == 0 {
                return Err(ProtocolError::Negotiation(
                    concat!("zero bound: ", stringify!($field)).into(),
                ));
            }
            left.$field.min(right.$field)
        }};
    }
    Ok(wire::WireLimits {
        max_frame_bytes: minimum!(max_frame_bytes),
        max_problem_bytes: minimum!(max_problem_bytes),
        max_decoded_bytes: minimum!(max_decoded_bytes),
        max_items: minimum!(max_items),
        max_targets: minimum!(max_targets),
        max_dimensions: minimum!(max_dimensions),
        max_memberships: minimum!(max_memberships),
        max_domain_entries: minimum!(max_domain_entries),
        max_overrides: minimum!(max_overrides),
        max_constraints: minimum!(max_constraints),
        max_objectives: minimum!(max_objectives),
        max_nesting: minimum!(max_nesting),
        max_string_bytes: minimum!(max_string_bytes),
        max_prepared: minimum!(max_prepared),
        max_prepared_bytes: minimum!(max_prepared_bytes),
        max_diagnostic_bytes: minimum!(max_diagnostic_bytes),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_capability_and_unbounded_limits_fail_negotiation() {
        let hello = wire::Hello {
            protocol_versions: vec![WORKER_VERSION],
            model_versions: vec![MODEL_VERSION],
            limits: Some(wire::WireLimits::standard()),
            required_capabilities: vec!["graceful_cancel".into()],
        };
        let capabilities = wire::Capabilities {
            protocol_version: Some(WORKER_VERSION),
            model_versions: vec![MODEL_VERSION],
            limits: Some(wire::WireLimits::standard()),
            backend_name: "rebalancer".into(),
            backend_build_id: "test-build".into(),
            ..Default::default()
        };
        assert!(negotiate(&hello, &capabilities).is_err());

        let mut hello = hello;
        hello.required_capabilities.clear();
        assert!(negotiate(&hello, &capabilities).is_ok());
        hello.limits.as_mut().unwrap().max_items = 0;
        assert!(negotiate(&hello, &capabilities).is_err());
    }
}
