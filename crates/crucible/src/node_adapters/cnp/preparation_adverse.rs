//! Retains source-qualified adverse controls inside original prepared custody.
//!
//! This bounded optional seam cannot activate a world or expose its controller.
//! The installed policy admits an exact predeclared case population; responses
//! are observations, never readiness or behavioral qualification authority.

use crucible_node_contract::{Id, Validate, canonical};
use crucible_node_provider::bodies::{BeginKind, BeginRequest, ObserveRequest, ResponseBody};
use crucible_node_provider::envelope::Method;

use super::{CnpReferencePreparation, CnpReferenceQualification};
use crate::node_contract::{EffectKnowledge, OperationFailure};

const MAXIMUM_REQUESTS: usize = 16;
const MAXIMUM_BODY_BYTES: usize = 256 * 1024;
const MAXIMUM_REPLY_BYTES: usize = 1024 * 1024;

/// Contains data controls for independently reviewed unsupported or stale scopes.
pub enum CnpPreparedAdverseBody {
    /// Probes unsupported exact execution or complete-state capture.
    UnsupportedBegin(Box<BeginRequest>),
    /// Probes a bounded owner observation, including a stale body identity.
    Observe(Box<ObserveRequest>),
}

/// Binds an original request and operation to one predeclared adverse body.
pub struct CnpPreparedAdverseRequest {
    /// Names the immutable original controller request.
    pub request: Id,
    /// Names the original operation for Begin, or none for Observe.
    pub operation: Option<Id>,
    /// Contains the actual typed control body.
    pub body: CnpPreparedAdverseBody,
}

impl CnpReferencePreparation {
    /// Runs source-qualified adverse controls beneath original prepared custody.
    ///
    /// Credits and schemas are checked before dispatch. The original controller,
    /// handshake registrar, child, journal and gate remain owned by preparation
    /// through every failure and unwind. No replacement process is allocated.
    ///
    /// # Errors
    /// Refuses exhausted credits, changed preparation or uninstalled source
    /// policy. Every failure after dispatch begins reports Unknown and retains
    /// all originals; an error never establishes native absence of effects.
    pub fn probe_pre_activation(
        &mut self,
        qualification: &dyn CnpReferenceQualification,
        requests: &[CnpPreparedAdverseRequest],
    ) -> Result<Vec<ResponseBody>, OperationFailure> {
        let bodies = prepare_bodies(requests)?;
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(requests.len())
            .map_err(|_| failure("prepared adverse reply credits unavailable", false))?;
        let maximum_bytes = requests
            .len()
            .checked_mul(MAXIMUM_REPLY_BYTES)
            .ok_or_else(|| failure("prepared adverse reply credits overflow", false))?;
        let mut arena = Vec::new();
        arena
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| failure("prepared adverse raw reply credits unavailable", false))?;

        let custody = self
            .guard
            .custody
            .as_ref()
            .ok_or_else(|| failure("original prepared custody unavailable", false))?;
        if custody.companion != Some(self.companion_pid)
            || custody.runtime.is_some()
            || custody.handshake.is_none()
            || self.binding.authority.activation_id.is_some()
            || self.binding.authority.world_generation.get() != 0
        {
            return Err(failure(
                "prepared adverse controls require inactive original custody",
                false,
            ));
        }
        // This default-refusing hook checks the full original population and
        // independently measured live native scope. Cached metadata is no proof.
        qualification.authenticate_prepared_adverse_probes(self, requests)?;

        let controller = self
            .guard
            .custody
            .as_mut()
            .and_then(|custody| custody.controller.as_mut())
            .ok_or_else(|| failure("original prepared controller unavailable", false))?;
        for (request, (method, body)) in requests.iter().zip(bodies) {
            let response = controller
                .call(
                    request.request.clone(),
                    request.operation.clone(),
                    method,
                    true,
                    body,
                )
                .map_err(|error| failure(&error.to_string(), true))?;
            let encoded = canonical::canonical_json(
                &serde_json::to_value(&response.shape)
                    .map_err(|error| failure(&error.to_string(), true))?,
            )
            .map_err(|error| failure(&error.to_string(), true))?;
            if encoded.len() > MAXIMUM_REPLY_BYTES
                || arena
                    .len()
                    .checked_add(encoded.len())
                    .is_none_or(|bytes| bytes > maximum_bytes)
            {
                return Err(failure("prepared adverse raw reply ceiling", true));
            }
            arena.extend_from_slice(&encoded);
            replies.push(response);
        }
        Ok(replies)
    }
}

fn prepare_bodies(
    requests: &[CnpPreparedAdverseRequest],
) -> Result<Vec<(Method, serde_json::Value)>, OperationFailure> {
    if requests.is_empty() || requests.len() > MAXIMUM_REQUESTS {
        return Err(failure(
            "prepared adverse request population ceiling",
            false,
        ));
    }
    let mut bodies = Vec::new();
    bodies
        .try_reserve_exact(requests.len())
        .map_err(|_| failure("prepared adverse body credits unavailable", false))?;
    let mut total_bytes = 0usize;
    for (index, request) in requests.iter().enumerate() {
        if requests[..index]
            .iter()
            .any(|prior| prior.request == request.request)
        {
            return Err(failure("prepared adverse original request repeated", false));
        }
        let (method, body) = match &request.body {
            CnpPreparedAdverseBody::UnsupportedBegin(body) => {
                if !matches!(body.kind, BeginKind::Capture | BeginKind::ExactRun)
                    || request.operation.is_none()
                {
                    return Err(failure(
                        "prepared adverse Begin outside unsupported scope",
                        false,
                    ));
                }
                body.validate().map_err(invalid)?;
                (Method::Begin, serde_json::to_value(body))
            }
            CnpPreparedAdverseBody::Observe(body) => {
                if request.operation.is_some() {
                    return Err(failure("prepared adverse Observe has operation", false));
                }
                body.validate().map_err(invalid)?;
                (Method::Observe, serde_json::to_value(body))
            }
        };
        let body = body.map_err(invalid)?;
        total_bytes = total_bytes
            .checked_add(canonical::canonical_json(&body).map_err(invalid)?.len())
            .filter(|bytes| *bytes <= MAXIMUM_BODY_BYTES)
            .ok_or_else(|| failure("prepared adverse body ceiling", false))?;
        bodies.push((method, body));
    }
    Ok(bodies)
}

fn invalid(error: impl std::fmt::Display) -> OperationFailure {
    failure(&error.to_string(), false)
}

fn failure(reason: &str, dispatched: bool) -> OperationFailure {
    OperationFailure {
        effects: if dispatched {
            EffectKnowledge::Unknown
        } else {
            EffectKnowledge::None
        },
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "preparation_adverse_tests.rs"]
mod tests;
