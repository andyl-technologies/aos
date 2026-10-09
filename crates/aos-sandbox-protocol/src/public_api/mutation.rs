//! Exact public mutation envelopes and historical endpoint selectors.
//!
//! The envelope retains the closed RPC method and exact received protobuf bytes.
//! Method-selected decoding reuses the full public request validator before
//! selecting capability operations, resource identities, and idempotency DATA.
//! Supplied historical identities do not authenticate a request or authorize a
//! mutation; the native Controller retains protected lookup and current admission.
//! The envelope preserves its body without decoding and re-encoding it first:
//!
//! ```text
//! +----------------+----------------+----------------+-------------------+
//! | magic (8 bytes)| method (u16 BE)| length (u32 BE)| protobuf body ... |
//! +----------------+----------------+----------------+-------------------+
//! ```

use aos_proto::aos::sandbox::v1 as wire;
use buffa::Message as _;

use super::PublicOperationMethodV1;
use crate::domain_ledger::transaction::IdempotencyKey;
use aos_proto::aos::sandbox::v1::{MutationContext, ObjectDescriptor as ProtoObjectDescriptor};
use aos_sandbox_core::{
    CapabilityId, MediaType, ObjectDescriptor, ObjectDigest, Operation, ProjectId, ResourceId,
    ResourceKind, Selector,
};

use super::method::PublicApiAuditMethodV1;
use super::request::{
    DormantClientStatePlanV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1,
    PublicSandboxRequestDataV1,
};

const MAGIC: &[u8; 8] = b"AOSPMR01";
const HEADER_BYTES: usize = MAGIC.len() + 2 + 4;
const MAXIMUM_PROTOBUF_BODY_BYTES: usize = 64 * 1024;

/// Carries one mutation RPC method and its exact received protobuf body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMutationRequestV1 {
    method: PublicApiAuditMethodV1,
    method_code: u16,
    protobuf_body: Vec<u8>,
}

impl PublicMutationRequestV1 {
    /// Constructs an envelope from one supported mutation method and exact body.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationRequestError`] when the method is not a mutation
    /// or the protobuf body is empty or exceeds the authorization bound.
    pub fn new(
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<Self, PublicMutationRequestError> {
        let method_code = mutation_method_code(method)?;
        if protobuf_body.is_empty() || protobuf_body.len() > MAXIMUM_PROTOBUF_BODY_BYTES {
            return Err(PublicMutationRequestError::InvalidBody);
        }

        Ok(Self {
            method,
            method_code,
            protobuf_body: protobuf_body.to_vec(),
        })
    }

    /// Decodes and exact-validates a canonical mutation envelope.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationRequestError`] for an invalid magic, method,
    /// length, body bound, or trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, PublicMutationRequestError> {
        let header = encoded
            .get(..HEADER_BYTES)
            .ok_or(PublicMutationRequestError::MalformedEnvelope)?;
        if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(PublicMutationRequestError::MalformedEnvelope);
        }
        let method_bytes: [u8; 2] = header[MAGIC.len()..MAGIC.len() + 2]
            .try_into()
            .map_err(|_| PublicMutationRequestError::MalformedEnvelope)?;
        let length_bytes: [u8; 4] = header[MAGIC.len() + 2..HEADER_BYTES]
            .try_into()
            .map_err(|_| PublicMutationRequestError::MalformedEnvelope)?;
        let body_length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| PublicMutationRequestError::MalformedEnvelope)?;
        let protobuf_body = encoded
            .get(HEADER_BYTES..)
            .filter(|body| body.len() == body_length)
            .ok_or(PublicMutationRequestError::MalformedEnvelope)?;

        Self::new(
            mutation_method(u16::from_be_bytes(method_bytes))?,
            protobuf_body,
        )
    }

    /// Encodes the canonical envelope without changing the protobuf body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body_length = self.protobuf_body.len() as u32;
        let mut encoded = Vec::with_capacity(HEADER_BYTES + self.protobuf_body.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&self.method_code.to_be_bytes());
        encoded.extend_from_slice(&body_length.to_be_bytes());
        encoded.extend_from_slice(&self.protobuf_body);
        encoded
    }

    /// Returns the closed public RPC method.
    #[must_use]
    pub const fn method(&self) -> PublicApiAuditMethodV1 {
        self.method
    }

    /// Returns the exact protobuf bytes received from the public transport.
    #[must_use]
    pub fn protobuf_body(&self) -> &[u8] {
        &self.protobuf_body
    }

    /// Decodes the exact body into the method-selected request and validates it.
    ///
    /// The ordinary CLI route validator remains the single source of field,
    /// feature, descriptor, and concurrency-fence constraints. The temporary
    /// client context used here is opaque and never becomes controller
    /// authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationRequestError`] when the body is malformed,
    /// noncanonical, inconsistent with the selected method, or fails the
    /// established request validator.
    pub fn decode_validated_kind(
        &self,
    ) -> Result<DormantSandboxRequestKindV1, PublicMutationRequestError> {
        macro_rules! decode {
            ($message:ty, $variant:ident) => {{
                let message = <$message>::decode_from_slice(&self.protobuf_body)
                    .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;
                if message.encode_to_vec() != self.protobuf_body {
                    return Err(PublicMutationRequestError::InvalidProtobuf);
                }
                DormantSandboxRequestKindV1::$variant(message)
            }};
        }

        use PublicApiAuditMethodV1 as M;
        let kind = match self.method {
            M::CreateSandbox => decode!(wire::CreateSandboxRequest, Create),
            M::UpdatePolicy => decode!(wire::UpdateSandboxPolicyRequest, UpdatePolicy),
            M::StartSandbox => decode!(wire::SandboxLifecycleRequest, Start),
            M::StopSandbox => decode!(wire::SandboxLifecycleRequest, Stop),
            M::SuspendSandbox => decode!(wire::SandboxLifecycleRequest, Suspend),
            M::ResumeSandbox => decode!(wire::SandboxLifecycleRequest, Resume),
            M::DeleteSandbox => decode!(wire::DeleteSandboxRequest, Delete),
            M::CreateExecution => decode!(wire::CreateExecutionRequest, Exec),
            M::ControlExecution => decode!(wire::ExecutionControlRequest, ExecutionControl),
            M::CancelExecution => decode!(wire::CancelExecutionRequest, CancelExec),
            M::CreateView => decode!(wire::CreateViewRequest, ViewCreate),
            M::AttachView => decode!(wire::AttachViewRequest, ViewAttach),
            M::ReplaceAttachment => {
                decode!(wire::ReplaceAttachmentRequest, ViewReplace)
            }
            M::DetachView => decode!(wire::DetachViewRequest, ViewDetach),
            M::ReleaseView => decode!(wire::ReleaseViewRequest, ViewRelease),
            M::CreateSnapshot => decode!(wire::CreateSnapshotRequest, Snapshot),
            M::RestoreSnapshot => decode!(wire::RestoreSnapshotRequest, Restore),
            M::ForkSnapshot => decode!(wire::ForkSnapshotRequest, Fork),
            M::DeleteSnapshot => decode!(wire::DeleteSnapshotRequest, DeleteSnapshot),
            M::AttenuateCapability => {
                decode!(wire::AttenuateCapabilityRequest, CapabilityAttenuate)
            }
            M::RenewCapability => decode!(wire::RenewCapabilityRequest, CapabilityRenew),
            M::RevokeCapability => decode!(wire::RevokeCapabilityRequest, CapabilityRevoke),
            M::CancelOperation => decode!(wire::CancelOperationRequest, CancelOperation),
            M::PinCacheObject => decode!(wire::PinCacheObjectRequest, CachePin),
            M::UnpinCacheObject => decode!(wire::UnpinCacheObjectRequest, CacheUnpin),
            M::OperatorRecover => decode!(wire::OperatorRecoveryRequest, OperatorRecover),
            _ => return Err(PublicMutationRequestError::UnsupportedMethod),
        };
        let client_state = DormantClientStatePlanV1::new(1, 1, None)
            .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;
        PublicSandboxRequestDataV1::new(
            kind.clone(),
            DormantSandboxOutputV1::Json,
            client_state,
        )
        .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;

        Ok(kind)
    }
}

/// Reports an invalid public mutation request envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicMutationRequestError {
    /// The selected RPC is not part of the public mutation surface.
    #[error("public RPC method is not a mutation")]
    UnsupportedMethod,
    /// The exact protobuf body is empty or exceeds the authorization bound.
    #[error("public mutation protobuf body is invalid")]
    InvalidBody,
    /// The transport envelope is truncated, inconsistent, or has trailing bytes.
    #[error("public mutation envelope is malformed")]
    MalformedEnvelope,
    /// The method-selected protobuf body is malformed, noncanonical, or invalid.
    #[error("public mutation protobuf body is malformed or invalid")]
    InvalidProtobuf,
}

fn mutation_method_code(method: PublicApiAuditMethodV1) -> Result<u16, PublicMutationRequestError> {
    use PublicApiAuditMethodV1 as M;

    match method {
        M::CreateSandbox => Ok(1),
        M::UpdatePolicy => Ok(2),
        M::StartSandbox => Ok(3),
        M::StopSandbox => Ok(4),
        M::SuspendSandbox => Ok(5),
        M::ResumeSandbox => Ok(6),
        M::DeleteSandbox => Ok(7),
        M::CreateExecution => Ok(8),
        M::ControlExecution => Ok(9),
        M::CancelExecution => Ok(10),
        M::CreateView => Ok(11),
        M::AttachView => Ok(12),
        M::ReplaceAttachment => Ok(13),
        M::DetachView => Ok(14),
        M::ReleaseView => Ok(15),
        M::CreateSnapshot => Ok(16),
        M::RestoreSnapshot => Ok(17),
        M::ForkSnapshot => Ok(18),
        M::DeleteSnapshot => Ok(19),
        M::AttenuateCapability => Ok(20),
        M::RenewCapability => Ok(21),
        M::RevokeCapability => Ok(22),
        M::CancelOperation => Ok(23),
        M::PinCacheObject => Ok(24),
        M::UnpinCacheObject => Ok(25),
        M::OperatorRecover => Ok(26),
        _ => Err(PublicMutationRequestError::UnsupportedMethod),
    }
}

fn mutation_method(code: u16) -> Result<PublicApiAuditMethodV1, PublicMutationRequestError> {
    use PublicApiAuditMethodV1 as M;

    match code {
        1 => Ok(M::CreateSandbox),
        2 => Ok(M::UpdatePolicy),
        3 => Ok(M::StartSandbox),
        4 => Ok(M::StopSandbox),
        5 => Ok(M::SuspendSandbox),
        6 => Ok(M::ResumeSandbox),
        7 => Ok(M::DeleteSandbox),
        8 => Ok(M::CreateExecution),
        9 => Ok(M::ControlExecution),
        10 => Ok(M::CancelExecution),
        11 => Ok(M::CreateView),
        12 => Ok(M::AttachView),
        13 => Ok(M::ReplaceAttachment),
        14 => Ok(M::DetachView),
        15 => Ok(M::ReleaseView),
        16 => Ok(M::CreateSnapshot),
        17 => Ok(M::RestoreSnapshot),
        18 => Ok(M::ForkSnapshot),
        19 => Ok(M::DeleteSnapshot),
        20 => Ok(M::AttenuateCapability),
        21 => Ok(M::RenewCapability),
        22 => Ok(M::RevokeCapability),
        23 => Ok(M::CancelOperation),
        24 => Ok(M::PinCacheObject),
        25 => Ok(M::UnpinCacheObject),
        26 => Ok(M::OperatorRecover),
        _ => Err(PublicMutationRequestError::UnsupportedMethod),
    }
}

/// Carries a structurally validated mutation and its closed endpoint semantics.
///
/// The selectors and request bytes are historical DATA, not protected lookup
/// evidence or current mutation authorization.
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
        Self::decode_with_historical_capability_id(encoded, None)
    }

    /// Decodes an envelope with an unchecked historical capability identity.
    ///
    /// Capability attenuation and renewal use the supplied identity as their
    /// logical selector; `None` leaves that selector unresolved. The original
    /// handle is still structurally checked, but this function does not verify
    /// the handle-to-identity relationship or grant protected authorization.
    /// Native admission retains that lookup and its current decision checks.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationResolutionErrorV1`] for an invalid envelope or
    /// endpoint, identity, descriptor, or idempotency key. Operator recovery
    /// remains outside ordinary endpoint resolution.
    pub fn decode_with_historical_capability_id(
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

    /// Returns the logical selector selected from structurally checked DATA.
    ///
    /// Structural decoding of a capability handle leaves this unset unless a
    /// historical identity was supplied. A populated selector is not proof of
    /// authenticated protected lookup or current authorization.
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
                idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())
                    .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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
                idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())
                    .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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
                idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())
                    .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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
            idempotency_key: IdempotencyKey::new(value.idempotency_key.clone())
                .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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
            ).map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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
        idempotency_key: IdempotencyKey::new(mutation.idempotency_key.clone())
            .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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
        idempotency_key: IdempotencyKey::new(mutation.idempotency_key.clone())
            .map_err(|_| PublicMutationResolutionErrorV1::InvalidIdempotencyKey)?,
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

/// Converts a protobuf descriptor through the established mutation checks.
///
/// # Errors
///
/// Returns [`PublicMutationResolutionErrorV1::InvalidDescriptor`] when the
/// digest is not exactly 32 bytes or is all zero, size is zero, or media type is
/// invalid.
pub fn object_descriptor(
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
