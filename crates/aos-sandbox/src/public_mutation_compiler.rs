//! Authenticated public mutation decoding and semantic resolution.
//!
//! This boundary turns an exact mutation envelope into the closed capability
//! operation selected by its RPC. It does not synthesize broker requests or
//! claim that requested state is observed. Domain lowering consumes this
//! checked value together with protected current state.

use aos_proto::aos::sandbox::v1::{MutationContext, ObjectDescriptor as ProtoObjectDescriptor};
use aos_sandbox_core::{
    CapabilityId, MediaType, ObjectDescriptor, ObjectDigest, Operation, PrincipalId, ProjectId,
    ResourceId, ResourceKind, Selector,
};

use crate::cli_model::{
    DormantSandboxRequestKindV1, PublicApiAuditMethodV1, PublicMutationRequestError,
    PublicMutationRequestV1,
};
use crate::controller_query::PublicOperationMethodV1;
use crate::public_api_session::PublicApiPeer;
use crate::{IdempotencyKey, Journal, JournalError};

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
        Self::authorize_inner(journal, peer, capability_id, encoded, nix_start)
    }

    fn authorize_inner(
        journal: &mut Journal,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        encoded: &[u8],
        #[cfg(target_os = "linux")]
        nix_start: Option<&crate::production_operation_compiler::ControllerNixStartRecipeSelectorV2>,
    ) -> Result<Self, PublicMutationAuthorizationErrorV1> {
        let request = ResolvedPublicMutationRequestV1::decode_with_capability_id(
            encoded,
            Some(capability_id),
        )
        .map_err(|_| PublicMutationAuthorizationErrorV1::Malformed)?;
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
            let registry = crate::publisher_authority::PublisherCapabilityRegistry::load(
                journal,
                crate::publisher_authority::PublisherAuthorityLimits::default(),
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
        let (authorization, checked_admission) =
            crate::controller::authorize_resolved_public_mutation_v1(
                journal,
                peer,
                capability_id,
                &request,
            )
            .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?;

        let fuse_authority = if matches!(
            request.request(),
            DormantSandboxRequestKindV1::ViewAttach(_)
                | DormantSandboxRequestKindV1::ViewReplace(_)
        ) {
            Some(
                crate::controller_fuse_admission::AdmissionAuthorityV1::capture(
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
            if control.action.as_known() == Some(aos_proto::aos::sandbox::v1::ExecutionControlAction::EXECUTION_CONTROL_ACTION_ATTACH));
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
            Some(crate::production_operation_compiler::CheckedStartAuthorityV2::capture(
                journal, peer, &checked_admission, authorization, encoded,
            )?)
        } else {
            None
        };

        Ok(Self {
            request,
            authorization,
            caller: peer.principal(),
            project: peer.project(),
            fuse_authority,
            #[cfg(target_os = "linux")]
            start_authority,
            original_request,
            original_trust,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_authorized_delete(encoded: &[u8]) -> Self {
        use crate::cli_model::{
            AuthenticatedRequestSemanticsDigestV1, CanonicalRequestDigestV1, RequestProvenanceV1,
        };
        use crate::controller_query::{
            AuthorizationRevisionDigestV1, ObservationSchemaDigestV1, QueryPrincipalDigestV1,
        };

        let request = ResolvedPublicMutationRequestV1::decode_with_capability_id(
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
            original_request: Vec::new(),
            original_trust: [[0; 32]; 4],
        }
    }

    /// Returns the validated request and its closed endpoint semantics.
    #[must_use]
    pub(crate) const fn request(&self) -> &ResolvedPublicMutationRequestV1 {
        &self.request
    }

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
                    .capability_expires_at
                    .min(coordinates.policy_expires_at)
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

/// Carries a validated public mutation and its closed authorization semantics.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedPublicMutationRequestV1 {
    method: PublicApiAuditMethodV1,
    operation_method: PublicOperationMethodV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: Option<Selector>,
    idempotency_key: IdempotencyKey,
    target_project: Option<ProjectId>,
    request: DormantSandboxRequestKindV1,
    protobuf_body: Vec<u8>,
}

impl ResolvedPublicMutationRequestV1 {
    /// Decodes an exact envelope, validates the endpoint body, and resolves its
    /// capability operation without consulting caller-provided metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationResolutionErrorV1`] for a malformed envelope,
    /// invalid endpoint body, non-exact identity, invalid descriptor selector,
    /// or missing/oversized idempotency key.
    pub fn decode(encoded: &[u8]) -> Result<Self, PublicMutationResolutionErrorV1> {
        Self::decode_with_capability_id(encoded, None)
    }

    fn decode_with_capability_id(
        encoded: &[u8],
        capability_id: Option<CapabilityId>,
    ) -> Result<Self, PublicMutationResolutionErrorV1> {
        let envelope = PublicMutationRequestV1::decode(encoded)?;
        let method = envelope.method();
        let protobuf_body = envelope.protobuf_body().to_vec();
        let request = envelope.decode_validated_kind()?;
        let semantics = endpoint_semantics(&request, capability_id)?;

        Ok(Self {
            method,
            operation_method: semantics.operation_method,
            resource_kind: semantics.resource_kind,
            operation: semantics.operation,
            selector: semantics.selector,
            idempotency_key: semantics.idempotency_key,
            target_project: semantics.target_project,
            request,
            protobuf_body,
        })
    }

    /// Returns the exact public method selected by the envelope.
    #[must_use]
    pub const fn method(&self) -> PublicApiAuditMethodV1 {
        self.method
    }

    /// Returns the stable method recorded on the public operation.
    #[must_use]
    pub const fn operation_method(&self) -> PublicOperationMethodV1 {
        self.operation_method
    }

    /// Returns the closed capability resource kind.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Returns the closed capability operation.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the exact logical selector when protected identity resolution ran.
    ///
    /// Structural decoding of a 32-byte capability handle leaves this unset;
    /// only authenticated protected lookup can select its capability UID.
    #[must_use]
    pub const fn selector(&self) -> Option<&Selector> {
        self.selector.as_ref()
    }

    /// Returns the validated client idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns a project named directly by a create/fork request.
    #[must_use]
    pub const fn target_project(&self) -> Option<ProjectId> {
        self.target_project
    }

    /// Returns the fully validated method-specific protobuf request.
    #[must_use]
    pub const fn request(&self) -> &DormantSandboxRequestKindV1 {
        &self.request
    }

    /// Returns the exact protobuf bytes received by the public service.
    #[must_use]
    pub fn protobuf_body(&self) -> &[u8] {
        &self.protobuf_body
    }
}

/// Reports rejection while resolving an exact public mutation endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicMutationResolutionErrorV1 {
    /// The exact mutation envelope or endpoint body is invalid.
    #[error("public mutation request is malformed")]
    Malformed,
    /// A resource or project identity is not exactly 16 nonzero bytes.
    #[error("public mutation identity is invalid")]
    InvalidIdentity,
    /// A descriptor selected for authorization is invalid.
    #[error("public mutation descriptor is invalid")]
    InvalidDescriptor,
    /// The request has no valid idempotency key.
    #[error("public mutation idempotency key is invalid")]
    InvalidIdempotencyKey,
}

impl From<PublicMutationRequestError> for PublicMutationResolutionErrorV1 {
    fn from(_: PublicMutationRequestError) -> Self {
        Self::Malformed
    }
}

impl From<JournalError> for PublicMutationResolutionErrorV1 {
    fn from(_: JournalError) -> Self {
        Self::InvalidIdempotencyKey
    }
}

struct EndpointSemanticsV1 {
    operation_method: PublicOperationMethodV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: Option<Selector>,
    idempotency_key: IdempotencyKey,
    target_project: Option<ProjectId>,
}

fn endpoint_semantics(
    request: &DormantSandboxRequestKindV1,
    capability_id: Option<CapabilityId>,
) -> Result<EndpointSemanticsV1, PublicMutationResolutionErrorV1> {
    use DormantSandboxRequestKindV1 as R;
    use PublicOperationMethodV1 as M;

    let semantics = match request {
        R::Create(value) => {
            let project = exact_project(&value.project_id)?;
            EndpointSemanticsV1 {
                operation_method: M::CreateSandbox,
                resource_kind: ResourceKind::ChildDelegation,
                operation: Operation::Create,
                selector: Some(resource_selector(create_scope(
                    &value.parent_sandbox_id,
                    &value.project_id,
                )?)?),
                idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())?,
                target_project: Some(project),
            }
        }
        R::UpdatePolicy(value) => resource_mutation(
            M::UpdatePolicy,
            ResourceKind::Sandbox,
            Operation::MetadataWrite,
            &value.sandbox_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::Start(value) => lifecycle_mutation(M::StartSandbox, value)?,
        R::Stop(value) => lifecycle_mutation(M::StopSandbox, value)?,
        R::Suspend(value) => lifecycle_mutation(M::SuspendSandbox, value)?,
        R::Resume(value) => lifecycle_mutation(M::ResumeSandbox, value)?,
        R::Delete(value) => resource_mutation(
            M::DeleteSandbox,
            ResourceKind::Sandbox,
            Operation::Remove,
            &value.sandbox_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::Exec(value) => resource_mutation(
            M::CreateExecution,
            ResourceKind::Execution,
            Operation::Execute,
            &value.sandbox_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::ExecutionControl(value) => resource_mutation(
            M::ControlExecution,
            ResourceKind::Execution,
            Operation::LifecycleControl,
            &value.execution_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::CancelExec(value) => resource_mutation(
            M::CancelExecution,
            ResourceKind::Execution,
            Operation::LifecycleControl,
            &value.execution_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::ViewCreate(value) => {
            let project = exact_project(&value.project_id)?;
            EndpointSemanticsV1 {
                operation_method: M::CreateView,
                resource_kind: ResourceKind::Tree,
                operation: Operation::Create,
                selector: Some(resource_selector(value.project_id.as_slice())?),
                idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())?,
                target_project: Some(project),
            }
        }
        R::ViewAttach(value) => resource_mutation(
            M::AttachView,
            ResourceKind::AttachmentSlot,
            Operation::Attach,
            &value.destination_slot_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::ViewReplace(value) => resource_mutation(
            M::ReplaceAttachment,
            ResourceKind::AttachmentSlot,
            Operation::Attach,
            &value.attachment_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::ViewDetach(value) => resource_mutation(
            M::DetachView,
            ResourceKind::AttachmentSlot,
            Operation::Remove,
            &value.attachment_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::ViewRelease(value) => resource_mutation(
            M::ReleaseView,
            ResourceKind::Tree,
            Operation::Remove,
            &value.view_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::Snapshot(value) => resource_mutation(
            M::CreateSnapshot,
            ResourceKind::Snapshot,
            Operation::Create,
            &value.sandbox_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::Restore(value) => resource_mutation(
            M::RestoreSnapshot,
            ResourceKind::Snapshot,
            Operation::Create,
            &value.snapshot_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::Fork(value) => {
            let project = exact_project(&value.target_project_id)?;
            EndpointSemanticsV1 {
                operation_method: M::ForkSnapshot,
                resource_kind: ResourceKind::Snapshot,
                operation: Operation::Create,
                selector: Some(resource_selector(create_scope(
                    &value.parent_sandbox_id,
                    &value.target_project_id,
                )?)?),
                idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())?,
                target_project: Some(project),
            }
        }
        R::DeleteSnapshot(value) => resource_mutation(
            M::DeleteSnapshot,
            ResourceKind::Snapshot,
            Operation::Remove,
            &value.snapshot_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::CapabilityAttenuate(value) => EndpointSemanticsV1 {
            operation_method: M::AttenuateCapability,
            resource_kind: ResourceKind::Capability,
            operation: Operation::Delegate,
            selector: capability_selector(&value.parent_capability_handle, capability_id)?,
            idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())?,
            target_project: None,
        },
        R::CapabilityRenew(value) => EndpointSemanticsV1 {
            operation_method: M::RenewCapability,
            resource_kind: ResourceKind::Capability,
            operation: Operation::Delegate,
            selector: capability_selector(&value.capability_handle, capability_id)?,
            idempotency_key: IdempotencyKey::new(
                mutation(value.mutation.as_option())?
                    .idempotency_key
                    .clone(),
            )?,
            target_project: None,
        },
        R::CapabilityRevoke(value) => resource_mutation(
            M::RevokeCapability,
            ResourceKind::Capability,
            Operation::Remove,
            &value.capability_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::CancelOperation(value) => resource_mutation(
            M::CancelOperation,
            ResourceKind::Operation,
            Operation::LifecycleControl,
            &value.operation_id,
            mutation(value.mutation.as_option())?,
        )?,
        R::CachePin(value) => {
            validate_cache_consumer(&value.view_id, &value.attachment_id)?;
            descriptor_mutation(
                M::PinCacheObject,
                Operation::Publish,
                value.object.as_option(),
                mutation(value.mutation.as_option())?,
            )?
        }
        R::CacheUnpin(value) => {
            validate_cache_consumer(&value.view_id, &value.attachment_id)?;
            descriptor_mutation(
                M::UnpinCacheObject,
                Operation::Remove,
                value.object.as_option(),
                mutation(value.mutation.as_option())?,
            )?
        }
        _ => return Err(PublicMutationResolutionErrorV1::Malformed),
    };

    Ok(semantics)
}

fn lifecycle_mutation(
    method: PublicOperationMethodV1,
    value: &aos_proto::aos::sandbox::v1::SandboxLifecycleRequest,
) -> Result<EndpointSemanticsV1, PublicMutationResolutionErrorV1> {
    resource_mutation(
        method,
        ResourceKind::Sandbox,
        Operation::LifecycleControl,
        &value.sandbox_id,
        mutation(value.mutation.as_option())?,
    )
}

fn resource_mutation(
    operation_method: PublicOperationMethodV1,
    resource_kind: ResourceKind,
    operation: Operation,
    resource_id: &[u8],
    mutation: &MutationContext,
) -> Result<EndpointSemanticsV1, PublicMutationResolutionErrorV1> {
    Ok(EndpointSemanticsV1 {
        operation_method,
        resource_kind,
        operation,
        selector: Some(resource_selector(resource_id)?),
        idempotency_key: IdempotencyKey::new(mutation.idempotency_key.clone())?,
        target_project: None,
    })
}

fn descriptor_mutation(
    operation_method: PublicOperationMethodV1,
    operation: Operation,
    descriptor: Option<&ProtoObjectDescriptor>,
    mutation: &MutationContext,
) -> Result<EndpointSemanticsV1, PublicMutationResolutionErrorV1> {
    Ok(EndpointSemanticsV1 {
        operation_method,
        resource_kind: ResourceKind::CachePublish,
        operation,
        selector: Some(Selector::Tree {
            tree: object_descriptor(
                descriptor.ok_or(PublicMutationResolutionErrorV1::InvalidDescriptor)?,
            )?,
        }),
        idempotency_key: IdempotencyKey::new(mutation.idempotency_key.clone())?,
        target_project: None,
    })
}

fn validate_cache_consumer(
    view_id: &[u8],
    attachment_id: &[u8],
) -> Result<(), PublicMutationResolutionErrorV1> {
    let valid_identity =
        |identity: &[u8]| identity.len() == 16 && identity.iter().any(|byte| *byte != 0);
    if !valid_identity(view_id) || (!attachment_id.is_empty() && !valid_identity(attachment_id)) {
        return Err(PublicMutationResolutionErrorV1::Malformed);
    }
    Ok(())
}

fn mutation(
    mutation: Option<&MutationContext>,
) -> Result<&MutationContext, PublicMutationResolutionErrorV1> {
    mutation.ok_or(PublicMutationResolutionErrorV1::Malformed)
}

fn create_scope<'a>(
    parent: &'a [u8],
    project: &'a [u8],
) -> Result<&'a [u8], PublicMutationResolutionErrorV1> {
    if parent.is_empty() {
        exact_identity(project)?;
        Ok(project)
    } else {
        exact_identity(parent)?;
        Ok(parent)
    }
}

fn resource_selector(bytes: &[u8]) -> Result<Selector, PublicMutationResolutionErrorV1> {
    Ok(Selector::Resource {
        resource: ResourceId::from_bytes(exact_identity(bytes)?),
    })
}

fn capability_selector(
    handle: &[u8],
    capability_id: Option<CapabilityId>,
) -> Result<Option<Selector>, PublicMutationResolutionErrorV1> {
    if handle.len() != 32 || handle.iter().all(|byte| *byte == 0) {
        return Err(PublicMutationResolutionErrorV1::InvalidIdentity);
    }
    if let Some(id) = capability_id {
        resource_selector(id.as_bytes()).map(Some)
    } else {
        Ok(None)
    }
}

fn exact_project(bytes: &[u8]) -> Result<ProjectId, PublicMutationResolutionErrorV1> {
    Ok(ProjectId::from_bytes(exact_identity(bytes)?))
}

fn exact_identity(bytes: &[u8]) -> Result<[u8; 16], PublicMutationResolutionErrorV1> {
    let identity = bytes
        .try_into()
        .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdentity)?;
    if identity == [0; 16] {
        return Err(PublicMutationResolutionErrorV1::InvalidIdentity);
    }
    Ok(identity)
}

#[cfg(test)]
mod handle_decode_tests {
    use aos_proto::aos::sandbox::v1::AttenuateCapabilityRequest;
    use aos_sandbox_core::{CapabilityId, ResourceId, Selector};
    use buffa::Message as _;

    use super::*;

    #[test]
    fn accepted_attach_lifetime_projects_original_capability_and_policy_minimum() {
        use crate::cli_model::provenance::OriginalPublicMutationCoordinatesV2;

        let request = aos_proto::aos::sandbox::v1::DeleteSandboxRequest {
            sandbox_id: vec![1; 16],
            expected_plan_digest: vec![11; 32],
            mutation: Some(aos_proto::aos::sandbox::v1::MutationContext {
                idempotency_key: vec![2; 16],
                expected_resource_version: vec![3; 32],
                operation_timeout: Some(aos_proto::aos::sandbox::v1::Duration {
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
            let coordinates = OriginalPublicMutationCoordinatesV2 {
                capability: [4; 16],
                revocation_scope: [5; 16],
                revocation_generation: 1,
                policy_digest: [6; 32],
                policy_generation: 1,
                controller: [7; 16],
                controller_generation: 1,
                capability_not_before: 1,
                capability_expires_at,
                policy_not_before: 1,
                policy_expires_at,
                channel_binding: [8; 32],
                session_commitment: [9; 32],
                authorization_revision: [10; 32],
            };
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
        let protected =
            ResolvedPublicMutationRequestV1::decode_with_capability_id(&encoded, Some(uid))
                .unwrap();
        assert_eq!(
            protected.selector(),
            Some(&Selector::Resource {
                resource: ResourceId::from_bytes(uid.into_bytes())
            })
        );
    }
}

pub(crate) fn object_descriptor(
    value: &ProtoObjectDescriptor,
) -> Result<ObjectDescriptor, PublicMutationResolutionErrorV1> {
    let digest: [u8; 32] = value
        .sha256
        .as_slice()
        .try_into()
        .map_err(|_| PublicMutationResolutionErrorV1::InvalidDescriptor)?;
    if digest == [0; 32] || value.encoded_size == 0 {
        return Err(PublicMutationResolutionErrorV1::InvalidDescriptor);
    }
    let media_type = MediaType::new(value.media_type.clone())
        .map_err(|_| PublicMutationResolutionErrorV1::InvalidDescriptor)?;

    Ok(ObjectDescriptor::new(
        media_type,
        ObjectDigest::from_bytes(digest),
        value.encoded_size,
    ))
}
