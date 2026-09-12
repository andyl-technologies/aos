//! Portable current-policy authority for effects that retire prior providers.
//!
//! A transition authorization is distinct from both planning snapshots. The
//! prior snapshot proves what was selected, while this document records fresh
//! grants for exact prior bindings that may be used during teardown.
//!
//! ```json
//! {"schema":"aos.ability.transition-authorization/v1","required_features":[],"desired_planning":"sha256:...","current_planning":"sha256:...","desired_policy_revision":"sha256:...","prior_policy_revision":"sha256:...","authorization_policy_revision":"sha256:...","teardown_bindings":[{"source_binding":"old-manager","request":{"id":{"consumer":"...","scope":[],"key":"transition-old-manager"},"accepted_interfaces":["..."],"methods":["start"],"guarantees":[],"lifetime":"instance"},"binding":{"id":"transition-old-manager","request":{"consumer":"...","scope":[],"key":"transition-old-manager"},"interface":"...","provider":"...","provider_package":null,"implementation":"...","source":"existing-pin","caller_grant":{"principal":"...","methods":["stop"],"contributions":[],"resources":[]},"provider_grant":{"principal":"...","methods":[],"contributions":[],"resources":[]},"guarantees":[],"policy_revision":"sha256:...","lifetime":"instance","mediation_allowed":false}}],"teardown_providers":[]}
//! ```

use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{
    Binding, BindingId, BindingRequest, IncarnationId, InstanceId, InterfaceKey, LocalKey,
    ProviderImplementationReference, ProviderStateFormat, RequiredFeature, ResourceId, RevisionId,
    VersionedDocument,
};

/// Names the version-1 explicit provider-state adoption semantics.
pub const PROVIDER_STATE_ADOPTION_V1: &str = "provider-state-adoption-v1";

/// Pins one side of an explicit provider-state ownership transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdoptionEndpoint {
    /// Identifies the stable provider instance that owns the state.
    pub provider: InstanceId,
    /// Identifies the exact package manifest supplying the implementation.
    pub package: Sha256Digest,
    /// Identifies the exact public interface implemented by the provider.
    pub interface: InterfaceKey,
    /// Pins the exact provider implementation and executable artifact.
    pub implementation: ProviderImplementationReference,
    /// Pins the format declaration and the artifact that made it.
    pub state_format: ProviderStateFormat,
    /// Identifies the exact terminal binding used to affect the resource.
    pub handler_binding: BindingId,
    /// Names the exact handler method that writes the retained resource.
    pub handler_method: LocalKey,
    /// Identifies the provider instance supplying the terminal handler.
    pub handler_provider: InstanceId,
    /// Identifies the handler provider's exact observed incarnation.
    pub handler_incarnation: IncarnationId,
    /// Identifies the handler's exact public interface.
    pub handler_interface: InterfaceKey,
    /// Pins the exact terminal handler implementation and artifact.
    pub handler_implementation: ProviderImplementationReference,
    /// Identifies the exact package manifest supplying the terminal handler.
    pub handler_package: Sha256Digest,
}

/// Authorizes one exact persistent resource to change provider ownership.
///
/// Version 1 permits adoption only when both endpoints declare the same state
/// format descriptor. It does not authorize state migration or mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdoptionAuthorization {
    /// Identifies the exact logical resource whose ownership may change.
    pub resource: ResourceId,
    /// Identifies the exact public kind of the retained resource.
    pub resource_interface: InterfaceKey,
    /// Pins the sole current owner and its authenticated handler path.
    pub source: ProviderAdoptionEndpoint,
    /// Pins the sole candidate owner and its authenticated handler path.
    pub candidate: ProviderAdoptionEndpoint,
}

/// Authorizes one transition-local binding derived from an exact prior binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownBindingAuthorization {
    /// Identifies the binding in the verified prior planning snapshot.
    pub source_binding: BindingId,
    /// Remaps the exact prior request to a collision-free transition identity.
    ///
    /// Its contract remains historical evidence. Fresh grants may intentionally
    /// authorize a teardown method absent from `request.methods`, such as Stop
    /// for a prior Start-only request.
    pub request: BindingRequest,
    /// Carries the exact prior selection with fresh current-policy grants.
    ///
    /// Its identifier is transition-local and must not collide with a desired
    /// binding or another teardown binding.
    pub binding: Binding,
}

/// Reauthorizes an exact prior operator-enabled root provider for retirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownProviderAuthorization {
    /// Identifies the prior enabled provider instance.
    pub provider: InstanceId,
    /// Pins the exact prior provider implementation and artifact.
    pub implementation: ProviderImplementationReference,
    /// Pins the exact prior package manifest.
    pub package: Sha256Digest,
    /// Identifies the fresh current policy revision selecting the constructor.
    ///
    /// This is not ambient effect authority. Every effect still needs a fresh
    /// exact lower binding in [`TransitionAuthorizationDocument::teardown_bindings`].
    pub policy_revision: RevisionId,
}

/// Carries independently authenticated current-policy teardown authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionAuthorizationDocument {
    /// Carries [`Self::SCHEMA`].
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Commits to the verified desired planning snapshot.
    pub desired_planning: Sha256Digest,
    /// Commits to the verified prior planning snapshot.
    pub current_planning: Sha256Digest,
    /// Records the policy revision used by the desired binding plan.
    pub desired_policy_revision: RevisionId,
    /// Records the historical policy revision used by the prior binding plan.
    pub prior_policy_revision: RevisionId,
    /// Identifies the fresh runtime policy revision authorizing teardown.
    pub authorization_policy_revision: RevisionId,
    /// Lists exact prior bindings reauthorized under current policy.
    pub teardown_bindings: Vec<TeardownBindingAuthorization>,
    /// Lists exact prior operator-enabled roots reauthorized for retirement.
    pub teardown_providers: Vec<TeardownProviderAuthorization>,
    /// Lists explicit compatible provider-state ownership transfers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_adoptions: Vec<ProviderAdoptionAuthorization>,
}

impl VersionedDocument for TransitionAuthorizationDocument {
    const SCHEMA: &'static str = "aos.ability.transition-authorization/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }
}
