//! Retains actual authenticated admission inputs under the Controller writer.

use aos_sandbox_core::{
    CapabilityId, CapabilityRecord, ChannelBinding, ObjectDescriptor, ObjectDigest,
    PortableMediaType, PrincipalId, ProjectId,
};
use serde::{Deserialize, Serialize};

use crate::Journal;
use crate::cli_model::PublicMutationAuthorizationV1;
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1;
use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

/// Historical provenance, never independently usable as current read authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionAuthorityV1 {
    pub(super) capability: CapabilityRecord,
    pub(super) holder: PrincipalId,
    pub(super) key_binding: ChannelBinding,
    pub(super) project: ProjectId,
    pub(super) accepted_wall_seconds: i64,
    pub(super) policy_generation: u64,
    pub(super) policy_descriptor: ObjectDescriptor,
    pub(super) controller_generation: u64,
    pub(super) authorization_revision: ObjectDigest,
    pub(super) authenticated_request: ObjectDigest,
}

impl AdmissionAuthorityV1 {
    /// Retains actual selected authority after the genuine evaluator succeeds.
    ///
    /// # Errors
    ///
    /// Rejects lost peer/journal custody or changed registry, policy,
    /// revocation, holder/key, project or accepted authorization coordinates.
    pub(crate) fn capture(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        authorization: PublicMutationAuthorizationV1,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        let rejected = || PublicMutationAuthorizationErrorV1::Rejected;
        peer.recheck().map_err(|_| rejected())?;
        journal
            .validate_held_protected_names()
            .map_err(|_| rejected())?;

        // Authorization and this capture retain the same exclusive journal.
        // Immutable registry lookup preserves the actual selected record; it
        // never guesses a capability from the target Attachment or holder ID.
        let capability =
            PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
                .and_then(|registry| registry.resolve_current(capability_id))
                .map_err(|_| rejected())?;
        let claims = capability.claims();
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
            .map_err(|_| rejected())?;
        let controller = store
            .controller_head()
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let policy = store
            .current_policy(peer.project())
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let revocation = store
            .revocation_head(claims.revocation_scope)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if claims.holder != peer.principal()
            || claims.channel_binding != peer.key_binding()
            || claims.project != peer.project()
            || claims.audience != controller.principal
            || claims.policy_digest != policy.descriptor().digest()
            || policy.generation() != authorization.policy_generation()
            || revocation.generation != claims.revocation_generation.get()
            || authorization.accepted_wall_seconds() < policy.not_before()
            || authorization.accepted_wall_seconds() >= policy.expires_at()
        {
            return Err(rejected());
        }

        let (_, revision, _, request, _) = authorization.provenance().commitments();
        let captured = Self {
            capability,
            holder: peer.principal(),
            key_binding: peer.key_binding(),
            project: peer.project(),
            accepted_wall_seconds: authorization.accepted_wall_seconds(),
            policy_generation: policy.generation(),
            policy_descriptor: policy.descriptor().clone(),
            controller_generation: controller.generation,
            authorization_revision: revision.digest(),
            authenticated_request: request.digest(),
        };
        captured.validate().map_err(|_| rejected())?;
        peer.recheck().map_err(|_| rejected())?;
        journal
            .validate_held_protected_names()
            .map_err(|_| rejected())?;
        Ok(captured)
    }

    pub(super) fn validate(&self) -> Result<(), super::ControllerFuseAdmissionErrorV1> {
        let claims = self.capability.claims();
        if claims.holder != self.holder
            || claims.channel_binding != self.key_binding
            || claims.project != self.project
            || claims.policy_digest != self.policy_descriptor.digest()
            || self.policy_descriptor.media_type().as_str() != PortableMediaType::Policy.as_str()
            || self.policy_descriptor.encoded_size() == 0
            || self.policy_generation == 0
            || self.controller_generation == 0
            || self.accepted_wall_seconds < claims.not_before
            || self.accepted_wall_seconds >= claims.expires_at
            || self.authorization_revision.as_bytes() == &[0; 32]
            || self.authenticated_request.as_bytes() == &[0; 32]
        {
            return Err(super::ControllerFuseAdmissionErrorV1::Rejected);
        }
        Ok(())
    }
}
