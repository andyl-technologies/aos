//! Retains actual authenticated admission inputs under the Controller writer.

use aos_sandbox_core::{
    CapabilityRecord, ChannelBinding, ObjectDescriptor, ObjectDigest, PortableMediaType,
    PrincipalId, ProjectId,
};
use serde::{Deserialize, Serialize};

use crate::Journal;
use crate::cli_model::PublicMutationAuthorizationV1;
use crate::cli_model::authorization_adapter::CurrentCapabilityDecisionV1;
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1;

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
    /// Rejects lost peer/journal custody or a checked decision that does not
    /// exactly match the accepted authorization and live authenticated peer.
    pub(crate) fn capture(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        decision: &CurrentCapabilityDecisionV1,
        authorization: PublicMutationAuthorizationV1,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        let rejected = || PublicMutationAuthorizationErrorV1::Rejected;
        peer.recheck().map_err(|_| rejected())?;
        journal
            .validate_held_protected_names()
            .map_err(|_| rejected())?;

        // This is the actual decision retained through authenticated request
        // binding, not a second grant evaluation or a later registry lookup.
        let coordinates = authorization.original_coordinates().ok_or_else(rejected)?;
        if decision.original_coordinates(coordinates.session_commitment) != coordinates
            || decision.authorized_wall_seconds() != authorization.accepted_wall_seconds()
            || decision.policy().generation() != authorization.policy_generation()
        {
            return Err(rejected());
        }
        let capability = decision.capability().clone();
        let claims = capability.claims();
        let policy = decision.policy();
        if claims.holder != peer.principal()
            || claims.channel_binding != peer.key_binding()
            || claims.project != peer.project()
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
            controller_generation: coordinates.controller_generation,
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
