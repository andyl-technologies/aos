//! Current protected admission for exact public mutation requests.
//!
//! Protocol owns the complete envelope and historical endpoint selector DATA.
//! This native boundary retains authenticated peer and protected registry
//! checks, the current Controller decision, and fixed FUSE/Nix original capture.
//! Domain lowering consumes the private admitted value with current state;
//! structural request decoding does not produce that authority.

#[cfg(test)]
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_model::{CapabilityId, PrincipalId, ProjectId};

#[cfg(test)]
use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
use crate::public_api_session::PublicApiPeer;
use crate::{Journal, JournalError};
#[cfg(test)]
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;

pub(crate) mod delete_admission;
mod authorization_native;
pub(crate) use authorization_native::PublicMutationAuthorizationNativeV1;

// A purpose selects only the existing retained engine's native destinations.
// Each entry separately verifies the exact decoded method and genuine C loan.
enum RetainedMutationPurposeV1<'native> {
    Delete(&'native mut PublicMutationAuthorizationNativeV1),
    Start(&'native mut PublicMutationAuthorizationNativeV1),
    Execution(&'native mut PublicMutationAuthorizationNativeV1),
}

impl RetainedMutationPurposeV1<'_> {
    fn original_v1(&mut self) -> &mut PublicMutationAuthorizationNativeV1 {
        match self { Self::Delete(original) | Self::Start(original) | Self::Execution(original) => original }
    }
}

/// Carries a resolved mutation only after current protected authorization.
///
/// The authorization proof remains private so downstream planning can consume
/// this value but cannot construct one from request bytes alone.
#[derive(Clone, PartialEq)]
pub(crate) struct AuthorizedPublicMutationRequestV1 {
    request: ResolvedPublicMutationRequestV1,
    authorization: crate::cli_model::PublicMutationAuthorizationV1,
    caller: PrincipalId,
    project: ProjectId,
    fuse_authority: Option<crate::controller_fuse_admission::AdmissionAuthorityV1>,
    #[cfg(target_os = "linux")]
    start_authority: Option<crate::production_operation_compiler::CheckedStartAuthorityV2>,
    accepted_start: Option<aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1>,
    original_request: Vec<u8>,
    original_trust: [[u8; 32]; 4],
}

impl std::fmt::Debug for AuthorizedPublicMutationRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthorizedPublicMutationRequestV1(<redacted>)")
    }
}

impl AuthorizedPublicMutationRequestV1 {
    /// Resolves and currently authorizes one exact public mutation.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationAuthorizationErrorV1`] for malformed endpoint
    /// input or any rejected protected authorization decision.
    pub(crate) fn authorize(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        encoded: &[u8],
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        Self::authorize_inner(
            journal,
            peer,
            capability_id,
            encoded,
            #[cfg(target_os = "linux")]
            None,
            None,
        )
    }

    /// Authorizes with the compiler's genuinely retained optional Nix owner.
    ///
    /// Only configured Start work captures the additional Nix originals. The
    /// same current authorization still precedes idempotency classification.
    ///
    /// # Errors
    ///
    /// Rejects malformed input or failed current authorization, and rejects
    /// configured Nix Start when its additional original capture fails.
    #[cfg(target_os = "linux")]
    pub(crate) fn authorize_with_nix_start(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        encoded: &[u8],
        nix_start: Option<&crate::production_operation_compiler::ControllerNixStartRecipeSelectorV2>,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        Self::authorize_inner(journal, peer, capability_id, encoded, nix_start, None)
    }

    // The only selected caller holds the genuine consumed Delete C17 loan.
    pub(crate) fn authorize_delete_retaining_v1(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        encoded: &[u8],
        native: &mut delete_admission::DeleteAuthorizationNativeV1,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        Self::authorize_inner(journal, peer, capability_id, encoded,
            #[cfg(target_os = "linux")]
            None,
            Some(RetainedMutationPurposeV1::Delete(native)),
        )
    }

    // Only the closed genuine C23 Start admission owner selects this entry.
    pub(crate) fn authorize_start_retaining_v1(
        journal: &mut Journal, peer: &PublicApiPeer, capability_id: CapabilityId,
        encoded: &[u8], native: &mut PublicMutationAuthorizationNativeV1,
        nix_start: Option<&crate::production_operation_compiler::ControllerNixStartRecipeSelectorV2>,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        Self::authorize_inner(journal, peer, capability_id, encoded,
            #[cfg(target_os = "linux")]
            nix_start,
            Some(RetainedMutationPurposeV1::Start(native)),
        )
    }

    // Only the genuine predurable C18 scope selects this retained entrance.
    pub(crate) fn authorize_execution_retaining_v2(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        encoded: &[u8],
        native: &mut PublicMutationAuthorizationNativeV1,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        journal.require_execution_admission_current_v2()
            .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?;
        Self::authorize_inner(journal, peer, capability_id, encoded,
            #[cfg(target_os = "linux")]
            None,
            Some(RetainedMutationPurposeV1::Execution(native)),
        )
    }

    fn authorize_inner(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        encoded: &[u8],
        #[cfg(target_os = "linux")]
        nix_start: Option<&crate::production_operation_compiler::ControllerNixStartRecipeSelectorV2>,
        mut native: Option<RetainedMutationPurposeV1<'_>>,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        let request = match native.as_ref() {
            Some(RetainedMutationPurposeV1::Delete(_)) => ResolvedPublicMutationRequestV1::decode_delete(encoded),
            Some(RetainedMutationPurposeV1::Execution(_)) => ResolvedPublicMutationRequestV1::decode_execution_v2(encoded),
            Some(RetainedMutationPurposeV1::Start(_)) | None => ResolvedPublicMutationRequestV1::decode_with_historical_capability_id(
                encoded, Some(capability_id),
            ),
        }.map_err(|_| PublicMutationAuthorizationErrorV1::Malformed)?;
        if matches!(native.as_ref(), Some(RetainedMutationPurposeV1::Start(_)))
            && !matches!(request.request(), DormantSandboxRequestKindV1::Start(_)) {
            return Err(PublicMutationAuthorizationErrorV1::Rejected);
        }
        if matches!(native.as_ref(), Some(RetainedMutationPurposeV1::Execution(_)))
            && !matches!(request.request(), DormantSandboxRequestKindV1::Exec(_))
        {
            return Err(PublicMutationAuthorizationErrorV1::Rejected);
        }
        let target_handle = match request.request() {
            DormantSandboxRequestKindV1::CapabilityAttenuate(value) => {
                Some(value.parent_capability_handle.as_slice())
            }
            DormantSandboxRequestKindV1::CapabilityRenew(value) => {
                Some(value.capability_handle.as_slice())
            }
            _ => None,
        };
        if let Some(handle) = target_handle {
            peer.recheck()
                .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?;
            let registry = crate::publisher_admin::capabilities::PublisherCapabilityRegistry::load(
                journal,
                crate::publisher_admin::capabilities::PublisherAuthorityLimits::default(),
            )
            .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?;
            if registry
                .resolve_holder_handle(handle, peer.principal(), peer.key_binding())
                .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?
                != capability_id
            {
                return Err(PublicMutationAuthorizationErrorV1::Rejected);
            }
        }
        let (authorization, checked_admission) = match native.as_mut() {
            Some(RetainedMutationPurposeV1::Delete(native)) => crate::controller::authorize_resolved_delete_retaining_v1(
                journal, peer, capability_id, &request, native,
            ),
            Some(RetainedMutationPurposeV1::Start(native)) => crate::controller::authorize_resolved_start_retaining_v1(
                journal, peer, capability_id, &request, native,
            ),
            Some(RetainedMutationPurposeV1::Execution(native)) => crate::controller::authorize_resolved_execution_retaining_v2(
                journal, peer, capability_id, &request, native,
            ),
            None => crate::controller::authorize_resolved_public_mutation_v1(
                journal, peer, capability_id, &request,
            ),
        }.map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?;

        // Capture the SAME paid protected-floor sample and immutable peer cutoff
        // before ordinary lowering releases the checked authorization decision.
        let accepted_start = if let DormantSandboxRequestKindV1::Start(start) = request.request() {
            let coordinates = authorization.original_coordinates()
                .ok_or(PublicMutationAuthorizationErrorV1::Rejected)?;
            let timeout = start.mutation.as_option()
                .and_then(|mutation| mutation.operation_timeout.as_option())
                .ok_or(PublicMutationAuthorizationErrorV1::Malformed)?;
            let clock = checked_admission.clock();
            if clock.wall_seconds() != authorization.accepted_wall_seconds() {
                return Err(PublicMutationAuthorizationErrorV1::Rejected);
            }
            Some(aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1::from_data_v1(
                clock, peer.accepted_original_deadline_data_v1(),
                coordinates.capability_expires_at(), coordinates.policy_expires_at(),
                timeout.nanoseconds,
            ).map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?)
        } else { None };

        let fuse_authority = if matches!(
            request.request(),
            DormantSandboxRequestKindV1::ViewAttach(_)
                | DormantSandboxRequestKindV1::ViewReplace(_)
        ) {
            Some(
                crate::controller_fuse_admission::capture_admission_authority(
                    journal,
                    peer,
                    &checked_admission,
                    authorization,
                )?,
            )
        } else {
            None
        };

        let attach = matches!(request.request(), DormantSandboxRequestKindV1::ExecutionControl(control)
            if control.action.as_known() == Some(aos_sandbox_api::aos::sandbox::v1::ExecutionControlAction::EXECUTION_CONTROL_ACTION_ATTACH));
        let original_request = if attach { encoded.to_vec() } else { Vec::new() };
        let original_trust = if attach {
            peer.original_trust_coordinates()
                .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?
        } else {
            [[0; 32]; 4]
        };

        // Authorization precedes idempotency classification. Retain only the
        // real decision here; assignment and recipe selection belong to Vacant.
        #[cfg(target_os = "linux")]
        let start_authority = if nix_start.is_some()
            && matches!(request.request(), DormantSandboxRequestKindV1::Start(_))
        {
            Some(
                crate::production_operation_compiler::capture_checked_start_authority(
                    journal,
                    peer,
                    &checked_admission,
                    authorization,
                    encoded,
                )?,
            )
        } else {
            None
        };

        if let Some(mut native) = native {
            native.original_v1().decision = Some(checked_admission);
        }

        Ok(Self {
            request,
            authorization,
            caller: peer.principal(),
            project: peer.project(),
            fuse_authority,
            #[cfg(target_os = "linux")]
            start_authority,
            accepted_start,
            original_request,
            original_trust,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_authorized_delete(encoded: &[u8]) -> Self {
        use crate::cli_model::{
            AuthenticatedRequestSemanticsDigestV1, CanonicalRequestDigestV1, RequestProvenanceV1,
        };
        use aos_sandbox_protocol::public_api::{
            AuthorizationRevisionDigestV1,
            ObservationSchemaDigestV1,
            QueryPrincipalDigestV1,
        };

        let request = ResolvedPublicMutationRequestV1::decode_with_historical_capability_id(
            encoded,
            Some(CapabilityId::from_bytes([3; 16])),
        )
        .unwrap();
        assert!(matches!(
            request.request(),
            DormantSandboxRequestKindV1::Delete(_)
        ));
        let provenance = RequestProvenanceV1::from_authenticated(
            QueryPrincipalDigestV1::commit(b"delete-admission-test-principal"),
            AuthorizationRevisionDigestV1::commit(b"delete-admission-test-authorization"),
            ObservationSchemaDigestV1::commit(b"delete-admission-test-schema"),
            CanonicalRequestDigestV1::from_authenticated_canonical(encoded).unwrap(),
            AuthenticatedRequestSemanticsDigestV1::from_decoded(ObjectDigest::from_bytes([4; 32])),
        );

        Self {
            request,
            authorization: crate::cli_model::PublicMutationAuthorizationV1::from_authorized(
                provenance, 1, 1,
            ),
            caller: PrincipalId::from_bytes([1; 16]),
            project: ProjectId::from_bytes([2; 16]),
            fuse_authority: None,
            #[cfg(target_os = "linux")]
            start_authority: None,
            accepted_start: None,
            original_request: Vec::new(),
            original_trust: [[0; 32]; 4],
        }
    }

    /// Returns the validated request and its closed endpoint semantics.
    #[must_use]
    pub(crate) const fn request(&self) -> &ResolvedPublicMutationRequestV1 {
        &self.request
    }

    /// Borrows the immutable request originally authorized for this Start.
    ///
    /// This accessor performs no decoding or authorization. Later native Root
    /// readers independently compare these bytes with the actual protected
    /// accepted operation and Source origin.
    pub(crate) fn retained_start_request_data_v2(
        &self,
    ) -> Result<&[u8], PublicMutationAuthorizationErrorV1> {
        if self.accepted_start.is_none() || self.original_request.is_empty() {
            return Err(PublicMutationAuthorizationErrorV1::Malformed);
        }
        Ok(&self.original_request)
    }

    /// Returns only the original accepted Start DATA captured by authorization.
    pub(crate) const fn accepted_start_origin_v1(&self)
        -> Option<aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1>
    { self.accepted_start }

    /// Returns the protected authorization decision time in Unix seconds.
    #[must_use]
    pub(crate) const fn accepted_wall_seconds(&self) -> i64 {
        self.authorization.accepted_wall_seconds()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn checked_start_authority(
        &self,
    ) -> Result<&crate::production_operation_compiler::CheckedStartAuthorityV2, PublicMutationAuthorizationErrorV1> {
        self.start_authority.as_ref().ok_or(PublicMutationAuthorizationErrorV1::Rejected)
    }

    /// Returns the immutable capability and policy limit accepted for attachment.
    ///
    /// The checked capability registry already requires every child expiry to
    /// remain within all retained ancestors. This projection does not reissue
    /// authority or replace the current authorization checks.
    #[must_use]
    pub(crate) fn original_attach_authority_expires_at(&self) -> Option<i64> {
        self.authorization
            .original_coordinates()
            .map(|coordinates| {
                coordinates
                    .capability_expires_at()
                    .min(coordinates.policy_expires_at())
            })
    }

    /// Encodes historical custody from this already checked attach decision.
    ///
    /// # Errors
    /// Rejects absent attach-only original request/trust or protected coordinates.
    pub(crate) fn original_attach_decision(
        &self,
    ) -> Result<Vec<u8>, crate::attach_route_issuer::AttachRouteIssuanceErrorV1> {
        crate::attach_decision::encode_original_decision(
            &self.original_request,
            self.authorization
                .original_coordinates()
                .ok_or(crate::attach_route_issuer::AttachRouteIssuanceErrorV1::DurableRecord)?,
            self.original_trust,
            self.caller,
            self.project,
            self.accepted_wall_seconds(),
        )
    }

    /// Returns the exact protected policy generation used by authorization.
    #[must_use]
    pub(crate) const fn policy_generation(&self) -> u64 {
        self.authorization.policy_generation()
    }

    /// Returns the mutually authenticated caller fixed at authorization.
    #[must_use]
    pub(crate) const fn caller(&self) -> PrincipalId {
        self.caller
    }

    /// Returns the registered project fixed at authorization.
    #[must_use]
    pub(crate) const fn project(&self) -> ProjectId {
        self.project
    }

    pub(crate) const fn fuse_authority(
        &self,
    ) -> Option<&crate::controller_fuse_admission::AdmissionAuthorityV1> {
        self.fuse_authority.as_ref()
    }
}

/// Classifies public mutation rejection at the compiler boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum PublicMutationAuthorizationErrorV1 {
    /// Exact transport or endpoint bytes are malformed.
    #[error("public mutation is malformed")]
    Malformed,
    /// Current protected authorization rejected the request.
    #[error("public mutation authorization was rejected")]
    Rejected,
}

pub use aos_sandbox_protocol::public_api::mutation::{
    PublicMutationResolutionErrorV1, ResolvedPublicMutationRequestV1,
};

impl From<JournalError> for PublicMutationResolutionErrorV1 {
    fn from(_: JournalError) -> Self {
        Self::InvalidIdempotencyKey
    }
}

#[cfg(test)]
mod handle_decode_tests {
    use aos_sandbox_api::aos::sandbox::v1::AttenuateCapabilityRequest;
    use aos_sandbox_model::{CapabilityId, ResourceId, Selector};
    use buffa::Message as _;

    use super::*;

    #[test]
    fn accepted_attach_lifetime_projects_original_capability_and_policy_minimum() {
        use crate::cli_model::provenance::OriginalPublicMutationCoordinatesV2;

        let request = aos_sandbox_api::aos::sandbox::v1::DeleteSandboxRequest {
            sandbox_id: vec![1; 16],
            expected_plan_digest: vec![11; 32],
            mutation: Some(aos_sandbox_api::aos::sandbox::v1::MutationContext {
                idempotency_key: vec![2; 16],
                expected_resource_version: vec![3; 32],
                operation_timeout: Some(aos_sandbox_api::aos::sandbox::v1::Duration {
                    nanoseconds: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let encoded = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::DeleteSandbox,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        let mut accepted = AuthorizedPublicMutationRequestV1::test_authorized_delete(&encoded);
        assert_eq!(accepted.original_attach_authority_expires_at(), None);

        for (capability_expires_at, policy_expires_at, expected) in
            [(40, 70, 40), (70, 40, 40), (40, 40, 40)]
        {
            let coordinates = OriginalPublicMutationCoordinatesV2::from_historical_parts((
                [4; 16],
                [5; 16],
                1,
                [6; 32],
                1,
                [7; 16],
                1,
                1,
                capability_expires_at,
                1,
                policy_expires_at,
                [8; 32],
                [9; 32],
                [10; 32],
            ));
            accepted.authorization = accepted
                .authorization
                .with_original_coordinates(coordinates);

            assert_eq!(
                accepted.original_attach_authority_expires_at(),
                Some(expected)
            );
            assert_eq!(
                accepted.authorization.original_coordinates(),
                Some(coordinates)
            );
        }
    }

    #[test]
    fn structural_replay_decode_defers_capability_selector_until_protected_lookup() {
        let request = AttenuateCapabilityRequest {
            parent_capability_handle: vec![7; 32],
            attenuation: b"{}".to_vec(),
            holder_channel_binding: vec![8; 32],
            idempotency_key: vec![9],
            expected_parent_resource_version: vec![10],
            ..Default::default()
        };
        let envelope = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::AttenuateCapability,
            &request.encode_to_vec(),
        )
        .unwrap();
        let encoded = envelope.encode();

        let structural = ResolvedPublicMutationRequestV1::decode(&encoded).unwrap();
        assert_eq!(
            structural.operation_method(),
            PublicOperationMethodV1::AttenuateCapability
        );
        assert!(structural.selector().is_none());

        let uid = CapabilityId::from_bytes([11; 16]);
        let protected = ResolvedPublicMutationRequestV1::decode_with_historical_capability_id(
            &encoded,
            Some(uid),
        )
        .unwrap();
        assert_eq!(
            protected.selector(),
            Some(&Selector::Resource {
                resource: ResourceId::from_bytes(uid.into_bytes())
            })
        );
    }
}

pub(crate) use aos_sandbox_protocol::public_api::mutation::object_descriptor;
