//! Captures the real checked Start decision without selecting a recipe or lease.
//!
//! These serializable originals are historical data. Only the authenticated
//! evaluator and its retained peer can produce the fresh capture; decoding a
//! retained carrier cannot revive that evaluator or its TLS session.

use aos_sandbox_core::{CapabilityRecord, ObjectDescriptor, PrincipalId, ProjectId};
use serde::{Deserialize, Serialize};

use crate::Journal;
use crate::cli_model::PublicMutationAuthorizationV1;
use crate::cli_model::authorization_adapter::CurrentCapabilityDecisionV1;
use crate::cli_model::provenance::OriginalPublicMutationCoordinatesV2;
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1;

use super::super::NixStartAdmissionErrorV2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckedStartAuthorityV2 {
    pub(super) capability: CapabilityRecord,
    pub(super) coordinates: OriginalPublicMutationCoordinatesV2,
    pub(super) holder: PrincipalId,
    pub(super) project: ProjectId,
    pub(super) accepted_wall_seconds: i64,
    pub(super) policy: ObjectDescriptor,
    pub(super) canonical_policy: Vec<u8>,
    pub(super) original_request: Vec<u8>,
    pub(super) original_trust: [[u8; 32]; 4],
}

impl CheckedStartAuthorityV2 {
    pub(crate) fn original_request(&self) -> &[u8] {
        &self.original_request
    }

    pub(crate) fn capture(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        decision: &CurrentCapabilityDecisionV1,
        authorization: PublicMutationAuthorizationV1,
        original_request: &[u8],
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        let rejected = || PublicMutationAuthorizationErrorV1::Rejected;
        peer.recheck().map_err(|_| rejected())?;
        journal.validate_held_protected_names().map_err(|_| rejected())?;
        let coordinates = authorization.original_coordinates().ok_or_else(rejected)?;
        if decision.original_coordinates(coordinates.session_commitment) != coordinates
            || decision.authorized_wall_seconds() != authorization.accepted_wall_seconds()
            || decision.policy().generation() != authorization.policy_generation()
        {
            return Err(rejected());
        }
        if original_request.len().checked_add(decision.policy().canonical_policy().len())
            .is_none_or(|length| length > 1_048_576)
        {
            return Err(rejected());
        }

        let captured = Self {
            capability: decision.capability().clone(),
            coordinates,
            holder: peer.principal(),
            project: peer.project(),
            accepted_wall_seconds: authorization.accepted_wall_seconds(),
            policy: decision.policy().descriptor().clone(),
            canonical_policy: decision.policy().canonical_policy().to_vec(),
            original_request: original_request.to_vec(),
            original_trust: peer.original_trust_coordinates().map_err(|_| rejected())?,
        };
        captured.validate().map_err(|_| rejected())?;
        peer.recheck().map_err(|_| rejected())?;
        journal.validate_held_protected_names().map_err(|_| rejected())?;
        Ok(captured)
    }

    pub(super) fn validate(&self) -> Result<(), NixStartAdmissionErrorV2> {
        let claims = self.capability.claims();
        let policy = crate::publisher_policy::PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            self.project,
            self.coordinates.policy_generation,
            self.coordinates.policy_not_before,
            self.coordinates.policy_expires_at,
            &self.canonical_policy,
            aos_sandbox_core::DecodeLimits::default(),
        ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
            &self.original_request,
        ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        if !matches!(request.request(), crate::cli_model::DormantSandboxRequestKindV1::Start(_))
            || claims.holder != self.holder
            || claims.project != self.project
            || claims.id.as_bytes() != &self.coordinates.capability
            || claims.channel_binding.as_bytes() != &self.coordinates.channel_binding
            || claims.revocation_scope.as_bytes() != &self.coordinates.revocation_scope
            || claims.revocation_generation.get() != self.coordinates.revocation_generation
            || claims.policy_digest != self.policy.digest()
            || self.policy.digest().as_bytes() != &self.coordinates.policy_digest
            || policy.descriptor() != &self.policy
            || claims.not_before != self.coordinates.capability_not_before
            || claims.expires_at != self.coordinates.capability_expires_at
            || self.coordinates.controller_generation == 0
            || self.coordinates.controller == [0; 16]
            || self.coordinates.authorization_revision == [0; 32]
            || self.coordinates.session_commitment == [0; 32]
            || self.original_trust.contains(&[0; 32])
            || self.accepted_wall_seconds < claims.not_before
            || self.accepted_wall_seconds < policy.not_before()
            || self.accepted_wall_seconds >= claims.expires_at
            || self.accepted_wall_seconds >= policy.expires_at()
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        Ok(())
    }

    pub(super) fn require_current_decision(
        &self,
        current: &Self,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        self.validate()?;
        current.validate()?;
        // A reconnect may change the historical exporter and protected clock
        // revision. It cannot change the original capability, policy or bounds.
        if self.capability != current.capability
            || self.policy != current.policy
            || self.canonical_policy != current.canonical_policy
            || self.holder != current.holder
            || self.project != current.project
            || self.original_request != current.original_request
            || self.original_trust != current.original_trust
            || self.coordinates.controller != current.coordinates.controller
            || self.coordinates.controller_generation != current.coordinates.controller_generation
            || self.coordinates.policy_generation != current.coordinates.policy_generation
            || self.coordinates.policy_not_before != current.coordinates.policy_not_before
            || self.coordinates.policy_expires_at != current.coordinates.policy_expires_at
            || current.accepted_wall_seconds < self.accepted_wall_seconds
            || current.accepted_wall_seconds >= self.coordinates.capability_expires_at
            || current.accepted_wall_seconds >= self.coordinates.policy_expires_at
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        Ok(())
    }
}
