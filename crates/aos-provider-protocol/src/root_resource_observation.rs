//! Effect-free observation of a resource established before stage admission.
//!
//! The request pins a desired resource to an authenticated terminal handler.
//! The handler must inspect native state in the current boot before reporting
//! readiness. A matching revision echoed without native evidence is not enough.
//!
//! ```text
//! RootResourceObservationRequest { root: selected handler probe, resource: exact revision }
//! RootResourceObservationResult  { root: live handler probe, observed_revision, ready, evidence }
//! ```

use anyhow::{Result, ensure};
use aos_ability_model::document::ProviderState;
use aos_ability_model::{AbilityValue, ResourceId, ResourceRevision, RevisionId};
use serde::{Deserialize, Serialize};

use crate::{RootObservationRequest, RootObservationResult, validate_root_observation};

/// Identifies the bounded request to observe one existing resource.
pub const ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA: &str =
    "aos.primitive.root-resource-observation-request/v1";

/// Identifies the handler's native observation of that resource.
pub const ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA: &str =
    "aos.primitive.root-resource-observation-result/v1";

/// Pins one image-established resource to an exact selected root handler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootResourceObservationRequest {
    /// Carries [`ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA`].
    pub schema: String,
    /// Selects the authenticated handler and fresh boot challenge.
    pub root: RootObservationRequest,
    /// Names the exact desired resource and semantic revision to inspect.
    pub resource: ResourceRevision,
}

/// Reports the native state of one image-established resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootResourceObservationResult {
    /// Carries [`ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA`].
    pub schema: String,
    /// Proves the selected handler was available in this boot and invocation.
    pub root: RootObservationResult,
    /// Echoes the exact logical resource that was inspected.
    pub resource: ResourceId,
    /// Names the revision found in native state, when identifiable.
    pub observed_revision: Option<RevisionId>,
    /// States whether the desired resource is currently ready.
    pub ready: bool,
    /// Carries the package handler's native resource observation.
    pub evidence: AbilityValue,
}

/// Checks the resource result against its selected handler and desired revision.
///
/// The authenticated package handler owns the native inspection. This shared
/// check binds its claim to the selected resource, handler, challenge, boot,
/// and freshness limit; stage admission separately requires `ready`.
///
/// # Errors
///
/// Returns an error for changed identities, an invalid root observation,
/// unsupported schemas, or a readiness claim for another revision.
pub fn validate_root_resource_observation(
    request: &RootResourceObservationRequest,
    result: &RootResourceObservationResult,
) -> Result<()> {
    ensure!(
        request.schema == ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA
            && result.schema == ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA,
        "root resource observation has an unsupported schema"
    );
    validate_root_observation(&request.root, &result.root)?;
    ensure!(
        request.resource.resource.provider == request.root.provider,
        "root resource belongs to another provider"
    );
    ensure!(
        result.root.state == ProviderState::Available,
        "root resource observation used an unavailable handler"
    );
    ensure!(
        result.resource == request.resource.resource,
        "root resource observation names another resource"
    );
    ensure!(
        !result.ready || result.observed_revision == Some(request.resource.revision),
        "root resource readiness names another revision"
    );
    ensure!(
        !result.evidence.as_json().is_null(),
        "root resource observation has no native evidence"
    );
    Ok(())
}
