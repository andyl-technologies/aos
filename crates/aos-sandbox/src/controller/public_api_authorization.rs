//! Binds live mutually authenticated public sessions to protected controller authority.
//!
//! The TLS registration supplies principal and project, while the journal
//! supplies capability claims and current policy. Neither a request header nor
//! a certificate registration alone grants authority. RPC admission constructs
//! its canonical authorization envelope from the exact body received on the
//! retained stream.
//!
//! The private owner keeps its Journal and fixed clock together across public
//! request binding; transport evidence and current authorization remain separate.

use aos_sandbox_core::CapabilityId;

use super::{ActivatedOperationCompiler, ControllerProtectedClockV1, NodeController};
use crate::PublicOperationAuthorizationV1;
use crate::SingleNodeEffectExecutor;
use crate::cli_model::authorization_adapter::{
    AuthenticatedCliChannelEvidenceV1, AuthenticatedCliIdentityEvidenceV1,
    AuthenticatedCliSessionEvidenceV1, CliAuthorizationAdapterError, CurrentCapabilityDecisionV1,
    CurrentProtectedCliAuthorizationV1, DecodedAuthenticatedCliRequestV1,
    DormantAuthenticatedCliRequestV1, PublicApiAuditMethodV1, canonical_public_audit_request_v2,
    canonical_public_mutation_request_v2,
};
use crate::cli_model::{AuditAuthorizationV1, PublicMutationAuthorizationV1};
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::ResolvedPublicMutationRequestV1;
use crate::publisher_admin::capabilities::PublisherAuthorityLimits;
use crate::publisher_admin::policy::PublisherPolicyLimits;

#[cfg(target_os = "linux")]
const DORMANT_CLI_OBSERVATION_SCHEMA_V1: &[u8] = b"aos.sandbox.cli.observation-schema.v1\0";

/// Borrows the controller's sole protected journal for dormant CLI authorization.
///
/// Construction belongs to [`NodeController::dormant_cli_authorization`] and
/// the fixed protected public-compiler bridges in this module.
/// It cannot be redirected to a caller-selected journal and exposes no journal
/// accessor, command registration, route, or effect-dispatch operation. Its
/// fixed clock owner reads only kernel realtime, BOOTTIME, and boot identity;
/// callers cannot supply samples or replace its source.
#[cfg(target_os = "linux")]
#[must_use = "the dormant CLI authorization owner must be used while borrowed"]
pub(crate) struct DormantCliAuthorizationOwnerV1<'controller> {
    journal: &'controller mut crate::Journal,
    protected_clock: ControllerProtectedClockV1,
}

/// Inspects an original fixed Gateway request against the sole protected engine.
/// The opaque owner, not received scalar fields, establishes its live origin.
/// No public mutation/operation authorization object is constructed here.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_original_gateway_git_read_v1(
    journal: &mut crate::Journal,
    original: &mut crate::git::delegated_read::GitReadRequestOwnerV1,
    acceptor: &crate::public_api_session::PublicApiSessionAcceptor,
) {
    let Some((capability, facts)) =
        prepare_original_gateway_git_read_v1(journal, original, acceptor)
    else {
        return;
    };
    original.evaluate_current(journal, capability, facts);
}

// One begin/lookup body serves ordinary and enrolled crossings. Failure stays
// with the genuine request before either path can perform a time-floor effect.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_original_gateway_git_read_v1(
    journal: &mut crate::Journal,
    original: &mut crate::git::delegated_read::GitReadRequestOwnerV1,
    acceptor: &crate::public_api_session::PublicApiSessionAcceptor,
) -> Option<(CapabilityId, crate::git::delegated_read::ReadFactsV1)> {
    use crate::publisher_admin::capabilities::PublisherCapabilityRegistry;

    let facts = match original.begin_evaluation(acceptor) {
        Ok(facts) => facts,
        Err(cause) => {
            original.decision = Some(Err(cause));
            return None;
        }
    };
    let lookup = (|| {
        let registry =
            PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
        registry.resolve_holder_handle(&facts.holder, facts.principal, facts.binding)
    })();
    let capability = match lookup {
        Ok(capability) => capability,
        Err(cause) => {
            original.lookup_failure = Some(cause);
            original.decision = Some(Err(
                CliAuthorizationAdapterError::ProtectedAuthorizationRejected,
            ));
            return None;
        }
    };
    Some((capability, facts))
}

/// Authorizes one resolved public mutation using the sole protected journal.
///
/// This helper is the only bridge from endpoint resolution into the dormant
/// authorization owner. It constructs the fixed protected clock internally,
/// rejects a create/fork project that differs from the registered TLS project,
/// and binds the exact method, body, operation, kind, and selector.
///
/// # Errors
///
/// Rejects unavailable protected time, project substitution, stale transport
/// evidence, or any current capability, policy, expiry, revocation, or grant
/// failure.
pub(crate) fn authorize_resolved_public_mutation_v1(
    journal: &mut crate::Journal,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    request: &ResolvedPublicMutationRequestV1,
) -> Result<
    (PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1),
    CliAuthorizationAdapterError,
> {
    authorize_resolved_public_mutation_inner_v1(journal, peer, capability_id, request, None)
}

pub(crate) fn authorize_resolved_delete_retaining_v1(
    journal: &mut crate::Journal,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    request: &ResolvedPublicMutationRequestV1,
    native: &mut crate::public_mutation_compiler::delete_admission::DeleteAuthorizationNativeV1,
) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    if request.method() != PublicApiAuditMethodV1::DeleteSandbox {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    authorize_resolved_public_mutation_inner_v1(journal, peer, capability_id, request, Some(native))
}

// Only the genuine C23 Start owner supplies these retained native destinations.
// The exact method check precedes the unchanged common grant/timefloor engine.
pub(crate) fn authorize_resolved_start_retaining_v1(
    journal: &mut crate::Journal,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    request: &ResolvedPublicMutationRequestV1,
    native: &mut crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1,
) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    if request.method() != PublicApiAuditMethodV1::StartSandbox {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    authorize_resolved_public_mutation_inner_v1(journal, peer, capability_id, request, Some(native))
}

// C18 is already entered before the shared canonical authorization engine.
pub(crate) fn authorize_resolved_execution_retaining_v2(
    journal: &mut crate::Journal,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    request: &ResolvedPublicMutationRequestV1,
    native: &mut crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1,
) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    if request.method() != PublicApiAuditMethodV1::CreateExecution {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    journal.require_execution_admission_current_v2()
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    authorize_resolved_public_mutation_inner_v1(journal, peer, capability_id, request, Some(native))
}

fn authorize_resolved_public_mutation_inner_v1(
    journal: &mut crate::Journal,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    request: &ResolvedPublicMutationRequestV1,
    mut native: Option<&mut crate::public_mutation_compiler::delete_admission::DeleteAuthorizationNativeV1>,
) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    if request
        .target_project()
        .is_some_and(|project| project != peer.project())
    {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }

    let protected_clock = match native.as_deref_mut() {
        Some(native) => ControllerProtectedClockV1::open_retaining_v1(&mut native.boot),
        None => ControllerProtectedClockV1::open_fixed(),
    }.map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let mut owner = DormantCliAuthorizationOwnerV1 {
        journal,
        protected_clock,
    };
    let authorized = owner.authorize_public_mutation_with_decision_inner(
        peer,
        capability_id,
        request.method(),
        request.resource_kind(),
        request.operation(),
        request
            .selector()
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?
            .clone(),
        request.protobuf_body(),
        native.as_deref_mut(),
    )?;
    // The ordinary protected decision, floor and independent peer post keep
    // their original order. Only then reject a concrete new use; the same
    // accepted-request check is repeated by resumed effect owners.
    match native {
        Some(native) => {
            if native.new_use.is_some() {
                return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
            }
            native.new_use = Some(owner.journal.require_public_mutation_targets_live_v2(
                peer.project(), request.request()));
            if !matches!(native.new_use, Some(Ok(()))) {
                return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
            }
        }
        None => owner.journal.require_public_mutation_targets_live_v2(peer.project(), request.request())
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?,
    }
    Ok(authorized)
}

/// Authorizes operator recovery after protected state resolves its target kind.
///
/// The request never supplies a resource kind. The specialized compiler must
/// first prove whether the named identity is a sandbox or operation, then pass
/// that exact kind here with the resource selector derived from the identity.
///
/// # Errors
///
/// Rejects stale transport evidence or any current capability, policy, expiry,
/// revocation, project, selector, method, or body mismatch.
#[cfg(target_os = "linux")]
pub(crate) fn authorize_public_operator_recovery_v1(
    journal: &mut crate::Journal, peer: &PublicApiPeer, capability_id: CapabilityId,
    resource_kind: aos_sandbox_core::ResourceKind, selector: aos_sandbox_core::Selector,
    protobuf_body: &[u8],
) -> Result<PublicMutationAuthorizationV1, CliAuthorizationAdapterError> {
    authorize_public_operator_recovery_inner_v1(journal, peer, capability_id,
        resource_kind, selector, protobuf_body, None).map(|(authorization, _)| authorization)
}

pub(crate) fn authorize_public_operator_recovery_retaining_v1(
    journal: &mut crate::Journal, peer: &PublicApiPeer, capability_id: CapabilityId,
    resource_kind: aos_sandbox_core::ResourceKind, selector: aos_sandbox_core::Selector,
    protobuf_body: &[u8],
    native: &mut crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1,
) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    authorize_public_operator_recovery_inner_v1(journal, peer, capability_id,
        resource_kind, selector, protobuf_body, Some(native))
}

fn authorize_public_operator_recovery_inner_v1(
    journal: &mut crate::Journal, peer: &PublicApiPeer, capability_id: CapabilityId,
    resource_kind: aos_sandbox_core::ResourceKind, selector: aos_sandbox_core::Selector,
    protobuf_body: &[u8],
    mut native: Option<&mut crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1>,
) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    if !matches!(
        resource_kind,
        aos_sandbox_core::ResourceKind::Sandbox | aos_sandbox_core::ResourceKind::Operation
    ) {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }

    let protected_clock = match native.as_deref_mut() {
        Some(native) => ControllerProtectedClockV1::open_retaining_v1(&mut native.boot),
        None => ControllerProtectedClockV1::open_fixed(),
    }
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let mut owner = DormantCliAuthorizationOwnerV1 {
        journal,
        protected_clock,
    };
    owner.authorize_public_mutation_with_decision_inner(
        peer,
        capability_id,
        PublicApiAuditMethodV1::OperatorRecover,
        resource_kind,
        aos_sandbox_core::Operation::LifecycleControl,
        selector,
        protobuf_body,
        native,
    )
}

impl DormantCliAuthorizationOwnerV1<'_> {
    /// Reauthorizes an exact public operation read against its admitted scope.
    ///
    /// The server, rather than the caller, supplies the immutable operation
    /// scope. The canonical authorization envelope commits the registered RPC
    /// method and exact decoded protobuf buffer, preventing a capability lookup
    /// header from being reused as authority for another request.
    ///
    /// # Errors
    ///
    /// Rejects project substitution, malformed request bytes, stale transport
    /// evidence, or any current capability, policy, expiry, or revocation
    /// failure.
    pub(crate) fn authorize_public_operation_read(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        scope: &PublicOperationAuthorizationV1,
        protobuf_body: &[u8],
    ) -> Result<AuditAuthorizationV1, CliAuthorizationAdapterError> {
        self.authorize_public_operation_read_inner_v1(peer, capability_id, scope, protobuf_body, None)
            .map(|(authorization, _)| authorization)
    }

    fn authorize_public_operation_read_inner_v1(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        scope: &PublicOperationAuthorizationV1,
        protobuf_body: &[u8],
        native: Option<&mut crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1>,
    ) -> Result<(AuditAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
        if peer.project() != scope.project() {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        let authorization_request = canonical_public_audit_request_v2(
            PublicApiAuditMethodV1::GetOperation,
            scope.resource_kind(),
            aos_sandbox_core::Operation::MetadataRead,
            scope.selector().clone(),
            protobuf_body,
        )?;
        let (authenticated, decision) = self.authenticate_public_request_with_decision_inner(
            peer, capability_id, &authorization_request, native,
        )?;
        Ok((authenticated.authorize_audit()?, decision))
    }

    /// Reauthorizes one exact public read against current protected state.
    ///
    /// The service selects the closed method, resource kind, operation, and
    /// selector from its decoded request. The exact received protobuf bytes are
    /// committed beside those semantics, so lookup metadata cannot authorize a
    /// different procedure or body.
    ///
    /// # Errors
    ///
    /// Rejects malformed request bytes, stale transport evidence, or any
    /// current capability, policy, expiry, revocation, project, or grant failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_public_read(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
    ) -> Result<AuditAuthorizationV1, CliAuthorizationAdapterError> {
        let authorization_request = canonical_public_audit_request_v2(
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
        )?;
        self.authenticate_public_request(peer, capability_id, &authorization_request)?
            .authorize_audit()
    }

    /// Reauthorizes one exact public mutation for a typed endpoint compiler.
    ///
    /// The endpoint supplies closed resource semantics after decoding the exact
    /// protobuf body. Successful authorization does not admit desired state or
    /// dispatch an effect; the compiler must consume it while constructing one
    /// atomic [`crate::OperationPlan`].
    ///
    /// # Errors
    ///
    /// Rejects stale transport evidence, malformed input, project substitution,
    /// or any current capability, policy, expiry, revocation, or grant failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_public_mutation(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
    ) -> Result<PublicMutationAuthorizationV1, CliAuthorizationAdapterError> {
        self.authorize_public_mutation_with_decision(
            peer,
            capability_id,
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
        )
        .map(|(authorization, _)| authorization)
    }

    /// Retains genuine admission inputs without re-evaluating the grant.
    ///
    /// # Errors
    /// Rejects exactly the same request, peer or protected-state failures as
    /// `authorize_public_mutation`.
    #[allow(clippy::too_many_arguments)]
    fn authorize_public_mutation_with_decision(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
    ) -> Result<
        (PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1),
        CliAuthorizationAdapterError,
    > {
        self.authorize_public_mutation_with_decision_inner(
            peer, capability_id, method, resource_kind, operation, selector, protobuf_body, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_public_mutation_with_decision_inner(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
        native: Option<&mut crate::public_mutation_compiler::delete_admission::DeleteAuthorizationNativeV1>,
    ) -> Result<(PublicMutationAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
        let (authorization_request, mutation_fence) = canonical_public_mutation_request_v2(
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
        )?;
        let (authenticated, decision) = self.authenticate_public_request_with_decision_inner(
            peer,
            capability_id,
            &authorization_request,
            native,
        )?;
        let authorization = authenticated.authorize_public_mutation(mutation_fence)?;
        Ok((authorization, decision))
    }

    /// Authenticates one exact public request against current protected authority.
    ///
    /// The caller must obtain `canonical_request` from the HTTP/2 request on
    /// the stream that owns `peer`; it must not substitute a client-provided
    /// digest or reconstruct a different request after authentication. The
    /// capability handle is only a lookup key, never proof of authorization.
    /// The registered certificate binds the capability's proof-of-possession
    /// key, and the TLS exporter binds the resulting provenance to this session.
    ///
    /// # Errors
    ///
    /// Rejects stale sessions, malformed envelopes, project mismatches, and
    /// any failure of protected capability, policy, expiry, or revocation checks.
    pub(crate) fn authenticate_public_request(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
    ) -> Result<DormantAuthenticatedCliRequestV1, CliAuthorizationAdapterError> {
        self.authenticate_public_request_with_decision(peer, capability_id, canonical_request)
            .map(|(authenticated, _)| authenticated)
    }

    // Keeps the actual decision through binding rather than reconstructing its
    // capability/policy inputs from a later lookup or authenticated scalars.
    fn authenticate_public_request_with_decision(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
    ) -> Result<
        (
            DormantAuthenticatedCliRequestV1,
            CurrentCapabilityDecisionV1,
        ),
        CliAuthorizationAdapterError,
    > {
        self.authenticate_public_request_with_decision_inner(peer, capability_id, canonical_request, None)
    }

    fn authenticate_public_request_with_decision_inner(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
        mut native: Option<&mut crate::public_mutation_compiler::delete_admission::DeleteAuthorizationNativeV1>,
    ) -> Result<(DormantAuthenticatedCliRequestV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
        match native.as_deref_mut() {
            Some(native) => peer.recheck_retaining_v1(&mut native.peers[0]),
            None => peer.recheck(),
        }.map_err(|_| CliAuthorizationAdapterError::InvalidAuthenticatedEvidence)?;

        let decoded = DecodedAuthenticatedCliRequestV1::decode_authenticated(canonical_request)?;
        let principal = peer.principal();
        let session_binding = peer.session_binding();
        let identity =
            AuthenticatedCliIdentityEvidenceV1::from_verified_transport_identity(principal)?;
        let session =
            AuthenticatedCliSessionEvidenceV1::from_verified_session(principal, &session_binding)?;
        let channel = AuthenticatedCliChannelEvidenceV1::from_verified_channel(
            principal,
            &session_binding,
            peer.key_binding(),
            canonical_request,
            DORMANT_CLI_OBSERVATION_SCHEMA_V1,
        )?;
        let (authorization, decision) = match native.as_deref_mut() {
            Some(native) => CurrentProtectedCliAuthorizationV1::from_current_protected_capability_retaining_v1(
                self.journal, PublisherAuthorityLimits::default(), PublisherPolicyLimits::default(),
                capability_id, peer.project(), &mut self.protected_clock,
                &decoded, &identity, &channel, &mut native.time_floor,
            ),
            None => CurrentProtectedCliAuthorizationV1::from_current_protected_capability_with_decision(
                self.journal, PublisherAuthorityLimits::default(), PublisherPolicyLimits::default(),
                capability_id, peer.project(), &mut self.protected_clock,
                &decoded, &identity, &channel,
            ),
        }?;

        // Protected journal reads must not extend the lifetime of transport proof.
        match native.as_deref_mut() {
            Some(native) => peer.recheck_retaining_v1(&mut native.peers[1]),
            None => peer.recheck(),
        }.map_err(|_| CliAuthorizationAdapterError::InvalidAuthenticatedEvidence)?;
        let authenticated = DormantAuthenticatedCliRequestV1::bind(
            decoded,
            identity,
            session,
            channel,
            authorization,
        )?;
        Ok((authenticated, decision))
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Borrows the sole controller journal for dormant authenticated CLI requests.
    ///
    /// This source-only factory registers no public command or route and grants
    /// no effect authority. The returned owner derives CLI provenance from
    /// a live registered public TLS peer, the fixed controller-owned paired
    /// clock, and current protected state. The capability binds to that project.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedOwnershipClockError`](aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError)
    /// when the fixed kernel boot identity cannot be read or validated.
    #[cfg(target_os = "linux")]
    pub(crate) fn dormant_cli_authorization(
        &mut self,
    ) -> Result<DormantCliAuthorizationOwnerV1<'_>, aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError> {
        Ok(DormantCliAuthorizationOwnerV1 {
            journal: self.reconciler.journal_mut(),
            protected_clock: ControllerProtectedClockV1::open_fixed()?,
        })
    }
}

pub(super) fn authorize_public_operation_read_retaining_v1(
    journal: &mut crate::Journal,
    peer: &PublicApiPeer,
    capability: CapabilityId,
    scope: &PublicOperationAuthorizationV1,
    protobuf_body: &[u8],
    native: &mut crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1,
) -> Result<(AuditAuthorizationV1, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
    let protected_clock = ControllerProtectedClockV1::open_retaining_v1(&mut native.boot)
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    DormantCliAuthorizationOwnerV1 { journal, protected_clock }
        .authorize_public_operation_read_inner_v1(peer, capability, scope, protobuf_body, Some(native))
}

