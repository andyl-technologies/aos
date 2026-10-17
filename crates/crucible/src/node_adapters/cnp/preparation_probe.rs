//! Runs bounded qualification controls beneath the original launch guard.
//!
//! This source-installed preparation seam exposes data controls, not a
//! controller handle. The original controller, registrar, requests and native
//! process remain in guarded custody across refusal, transport loss or unwind.
//! Results are observations and do not qualify the provider or activate a world.

use crucible_node_contract::{Id, Validate, canonical};
use crucible_node_provider::{
    bodies::{AdmitRequest, DiscoverRequest, RealizeRequest, ResponseBody},
    envelope::Method,
};

use crate::node_contract::{EffectKnowledge, OperationFailure};

use super::{CnpLaunchGuard, CnpReferenceQualification};

const MAXIMUM_REQUESTS: usize = 16;
const MAXIMUM_REQUEST_BYTES: usize = 256 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;

/// Selects a closed control before ordinary discovery and realization.
///
/// These requests may be adversarial data. Source policy authenticates the
/// complete immutable fixture before Child; this enum issues no permission.
pub enum CnpPreRealizationProbeBody {
    /// Requests the unchanged source-installed profile.
    Discover(Box<DiscoverRequest>),
    /// Probes the original privately installed realization contract.
    Realize(Box<RealizeRequest>),
    /// Probes admission before a companion has been realized.
    Admit(Box<AdmitRequest>),
}

/// Names one original request in a predeclared qualification fixture.
pub struct CnpPreRealizationProbeRequest {
    /// Identifies the original request, which must not be replaced on retry.
    pub request: Id,
    /// Contains the exact typed original body.
    pub body: CnpPreRealizationProbeBody,
}

impl CnpLaunchGuard {
    /// Runs predeclared controls while retaining all original native journals.
    ///
    /// The trusted qualifier first authenticates the actual original provider.
    /// Every body and request/reply credit is validated and reserved before any
    /// dispatch. This method never exposes or removes the controller and cannot
    /// activate, begin execution, replace custody, or return native authority.
    /// The caller independently checks original responses and native effects;
    /// a typed response or this method's success is not a conformance verdict.
    ///
    /// # Errors
    /// Refuses unavailable or already-realized custody, invalid source policy,
    /// duplicate requests, invalid bodies or exhausted finite credits. After
    /// dispatch begins, all failures retain original custody and report Unknown.
    pub fn probe_pre_realization(
        &mut self,
        qualification: &dyn CnpReferenceQualification,
        requests: &[CnpPreRealizationProbeRequest],
    ) -> Result<Vec<ResponseBody>, OperationFailure> {
        let bodies = prepare_bodies(requests)?;
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(requests.len())
            .map_err(|_| failure("CNP original probe reply credits unavailable", false))?;
        let maximum_reply_bytes = requests
            .len()
            .checked_mul(MAXIMUM_RESPONSE_BYTES)
            .ok_or_else(|| failure("CNP original probe reply credits overflow", false))?;
        let mut reply_arena = Vec::new();
        reply_arena
            .try_reserve_exact(maximum_reply_bytes)
            .map_err(|_| failure("CNP original probe raw reply credits unavailable", false))?;

        let custody = self
            .custody
            .as_ref()
            .ok_or_else(|| failure("CNP original probe custody unavailable", false))?;
        if custody.companion.is_some() || custody.runtime.is_some() || custody.handshake.is_none() {
            return Err(failure(
                "CNP probe requires original pre-realization custody",
                false,
            ));
        }
        let profile = custody
            .controller
            .as_ref()
            .ok_or_else(|| failure("CNP original probe controller unavailable", false))?
            .profile
            .clone();
        qualification.authenticate_provider(self, &profile)?;
        // Cached companion metadata is not native absence evidence. Only the
        // trusted installer may authorize this exact adverse population.
        qualification.authenticate_pre_realization_probes(self, requests)?;

        let controller = self
            .custody
            .as_mut()
            .and_then(|custody| custody.controller.as_mut())
            .ok_or_else(|| failure("CNP original probe controller unavailable", false))?;
        for (request, (method, body)) in requests.iter().zip(bodies) {
            let response = controller
                .call(request.request.clone(), None, method, false, body)
                .map_err(|error| failure(&error.to_string(), true))?;
            let encoded = canonical::canonical_json(
                &serde_json::to_value(&response.shape)
                    .map_err(|error| failure(&error.to_string(), true))?,
            )
            .map_err(|error| failure(&error.to_string(), true))?;
            if encoded.len() > MAXIMUM_RESPONSE_BYTES
                || reply_arena
                    .len()
                    .checked_add(encoded.len())
                    .is_none_or(|total| total > maximum_reply_bytes)
            {
                return Err(failure("CNP original probe raw reply ceiling", true));
            }
            reply_arena.extend_from_slice(&encoded);
            replies.push(response);
        }
        Ok(replies)
    }
}

fn prepare_bodies(
    requests: &[CnpPreRealizationProbeRequest],
) -> Result<Vec<(Method, serde_json::Value)>, OperationFailure> {
    if requests.is_empty() || requests.len() > MAXIMUM_REQUESTS {
        return Err(failure(
            "CNP original probe request population ceiling",
            false,
        ));
    }
    let mut bodies = Vec::new();
    bodies
        .try_reserve_exact(requests.len())
        .map_err(|_| failure("CNP original probe request credits unavailable", false))?;
    let mut bytes = 0usize;
    for (index, request) in requests.iter().enumerate() {
        if requests[..index]
            .iter()
            .any(|prior| prior.request == request.request)
        {
            return Err(failure("CNP original probe request repeated", false));
        }
        let (method, body) = match &request.body {
            CnpPreRealizationProbeBody::Discover(body) => {
                body.validate().map_err(invalid)?;
                (Method::Discover, serde_json::to_value(body))
            }
            CnpPreRealizationProbeBody::Realize(body) => {
                body.validate().map_err(invalid)?;
                (Method::Realize, serde_json::to_value(body))
            }
            CnpPreRealizationProbeBody::Admit(body) => {
                body.validate().map_err(invalid)?;
                (Method::Admit, serde_json::to_value(body))
            }
        };
        let body = body.map_err(invalid)?;
        let encoded = canonical::canonical_json(&body).map_err(invalid)?;
        bytes = bytes
            .checked_add(encoded.len())
            .filter(|total| *total <= MAXIMUM_REQUEST_BYTES)
            .ok_or_else(|| failure("CNP original probe request byte ceiling", false))?;
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
#[path = "preparation_probe_tests.rs"]
mod tests;
