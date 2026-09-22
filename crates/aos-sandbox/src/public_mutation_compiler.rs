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
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AuthorizedPublicMutationRequestV1 {
    request: ResolvedPublicMutationRequestV1,
    authorization: crate::cli_model::PublicMutationAuthorizationV1,
    caller: PrincipalId,
    project: ProjectId,
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
        let request = ResolvedPublicMutationRequestV1::decode(encoded)
            .map_err(|_| PublicMutationAuthorizationErrorV1::Malformed)?;
        let authorization = crate::controller::authorize_resolved_public_mutation_v1(
            journal,
            peer,
            capability_id,
            &request,
        )
        .map_err(|_| PublicMutationAuthorizationErrorV1::Rejected)?;

        Ok(Self {
            request,
            authorization,
            caller: peer.principal(),
            project: peer.project(),
        })
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
    selector: Selector,
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
        let envelope = PublicMutationRequestV1::decode(encoded)?;
        let method = envelope.method();
        let protobuf_body = envelope.protobuf_body().to_vec();
        let request = envelope.decode_validated_kind()?;
        let semantics = endpoint_semantics(&request)?;

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

    /// Returns the exact logical selector derived from the typed body.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
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
    selector: Selector,
    idempotency_key: IdempotencyKey,
    target_project: Option<ProjectId>,
}

fn endpoint_semantics(
    request: &DormantSandboxRequestKindV1,
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
                selector: resource_selector(create_scope(
                    &value.parent_sandbox_id,
                    &value.project_id,
                )?)?,
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
                selector: resource_selector(value.project_id.as_slice())?,
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
                selector: resource_selector(create_scope(
                    &value.parent_sandbox_id,
                    &value.target_project_id,
                )?)?,
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
            selector: resource_selector(&value.parent_capability_handle)?,
            idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())?,
            target_project: None,
        },
        R::CapabilityRenew(value) => resource_mutation(
            M::RenewCapability,
            ResourceKind::Capability,
            Operation::Delegate,
            &value.capability_handle,
            mutation(value.mutation.as_option())?,
        )?,
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
        R::CachePin(value) => descriptor_mutation(
            M::PinCacheObject,
            Operation::Publish,
            value.object.as_option(),
            mutation(value.mutation.as_option())?,
        )?,
        R::CacheUnpin(value) => descriptor_mutation(
            M::UnpinCacheObject,
            Operation::Remove,
            value.object.as_option(),
            mutation(value.mutation.as_option())?,
        )?,
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
        selector: resource_selector(resource_id)?,
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
        selector: Selector::Tree {
            tree: object_descriptor(
                descriptor.ok_or(PublicMutationResolutionErrorV1::InvalidDescriptor)?,
            )?,
        },
        idempotency_key: IdempotencyKey::new(mutation.idempotency_key.clone())?,
        target_project: None,
    })
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

fn object_descriptor(
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
