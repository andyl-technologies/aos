//! Authenticated public policy-planning requests.
//!
//! This boundary decodes the exact protobuf body selected by the registered
//! `PlanCreate` or `PlanPolicy` route, derives its closed capability semantics,
//! and retains the current protected authorization decision. The resulting
//! request permits pure planning only; it carries no mutation context and
//! grants no operation-admission or effect authority.

use crate::cli_model::{
    AuditAuthorizationV1, DormantClientStatePlanV1, DormantSandboxOutputV1,
    DormantSandboxRequestKindV1, DormantSandboxRequestV1, PublicApiAuditMethodV1,
};
use aos_proto::aos::sandbox::v1 as wire;
use aos_sandbox_core::{Operation, ProjectId, ResourceId, ResourceKind, Selector};

/// Carries a policy-planning request after current protected authorization.
///
/// The constructor is controller-private. An injected planner can inspect the
/// validated request, but cannot construct this proof from transport bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedPublicPolicyPlanRequestV1 {
    request: ResolvedPublicPolicyPlanRequestV1,
    authorization: AuditAuthorizationV1,
}

impl AuthorizedPublicPolicyPlanRequestV1 {
    pub(crate) const fn new(
        request: ResolvedPublicPolicyPlanRequestV1,
        authorization: AuditAuthorizationV1,
    ) -> Self {
        Self {
            request,
            authorization,
        }
    }

    /// Returns the validated request and its closed endpoint semantics.
    #[must_use]
    pub const fn request(&self) -> &ResolvedPublicPolicyPlanRequestV1 {
        &self.request
    }

    /// Returns the protected authorization decision's wall time.
    #[must_use]
    pub(crate) const fn authorized_wall_seconds(&self) -> i64 {
        self.authorization.authorized_wall_seconds()
    }
}

/// Carries one validated public policy-planning request.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedPublicPolicyPlanRequestV1 {
    method: PublicApiAuditMethodV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: Selector,
    target_project: Option<ProjectId>,
    request: DormantSandboxRequestKindV1,
    protobuf_body: Vec<u8>,
}

impl ResolvedPublicPolicyPlanRequestV1 {
    /// Decodes and validates the exact body selected by a planning RPC.
    ///
    /// # Errors
    ///
    /// Returns [`PublicPolicyPlanResolutionErrorV1`] for an unsupported method,
    /// malformed or noncanonical protobuf, invalid request fields, or a resource
    /// identity that is not exactly 16 nonzero bytes.
    pub fn decode(
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<Self, PublicPolicyPlanResolutionErrorV1> {
        if protobuf_body.is_empty() {
            return Err(PublicPolicyPlanResolutionErrorV1::Malformed);
        }

        let request = match method {
            PublicApiAuditMethodV1::PlanCreate => {
                let request = decode_exact::<wire::PlanCreateSandboxRequest>(protobuf_body)?;
                DormantSandboxRequestKindV1::PlanCreate(request)
            }
            PublicApiAuditMethodV1::PlanPolicy => {
                let request = decode_exact::<wire::PlanSandboxPolicyRequest>(protobuf_body)?;
                DormantSandboxRequestKindV1::PlanPolicy(request)
            }
            _ => return Err(PublicPolicyPlanResolutionErrorV1::UnsupportedMethod),
        };
        validate_request(request.clone())?;

        let (resource_kind, operation, selector, target_project) = match &request {
            DormantSandboxRequestKindV1::PlanCreate(value) => {
                let project = exact_project(&value.project_id)?;
                let scope = if value.parent_sandbox_id.is_empty() {
                    value.project_id.as_slice()
                } else {
                    value.parent_sandbox_id.as_slice()
                };
                (
                    ResourceKind::ChildDelegation,
                    Operation::Create,
                    resource_selector(scope)?,
                    Some(project),
                )
            }
            DormantSandboxRequestKindV1::PlanPolicy(value) => (
                ResourceKind::Sandbox,
                Operation::MetadataWrite,
                resource_selector(&value.sandbox_id)?,
                None,
            ),
            _ => return Err(PublicPolicyPlanResolutionErrorV1::UnsupportedMethod),
        };

        Ok(Self {
            method,
            resource_kind,
            operation,
            selector,
            target_project,
            request,
            protobuf_body: protobuf_body.to_vec(),
        })
    }

    /// Returns the registered public RPC method.
    #[must_use]
    pub const fn method(&self) -> PublicApiAuditMethodV1 {
        self.method
    }

    /// Returns the capability resource class derived from the typed body.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Returns the capability operation required to compute this plan.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the exact logical resource selector derived from the typed body.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Returns a project named directly by a create-planning request.
    #[must_use]
    pub const fn target_project(&self) -> Option<ProjectId> {
        self.target_project
    }

    /// Returns the fully validated method-specific protobuf request.
    #[must_use]
    pub const fn typed_request(&self) -> &DormantSandboxRequestKindV1 {
        &self.request
    }

    /// Returns the exact protobuf bytes received by the public service.
    #[must_use]
    pub fn protobuf_body(&self) -> &[u8] {
        &self.protobuf_body
    }
}

/// Reports rejection while resolving a public policy-planning request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicPolicyPlanResolutionErrorV1 {
    /// The selected method is not a policy-planning RPC.
    #[error("public RPC method is not a policy-planning method")]
    UnsupportedMethod,
    /// The protobuf body or one of its closed fields is invalid.
    #[error("public policy-planning request is malformed")]
    Malformed,
    /// A resource or project identity is not exactly 16 nonzero bytes.
    #[error("public policy-planning identity is invalid")]
    InvalidIdentity,
}

/// Classifies policy-planning failure at the injected planner boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicPolicyPlanningErrorV1 {
    /// The exact endpoint request is malformed.
    #[error("public policy-planning request is malformed")]
    Malformed,
    /// Current authentication, authorization, or policy rejected the request.
    #[error("public policy-planning request was rejected")]
    Rejected,
    /// The deployment has no current policy-planning implementation.
    #[error("public policy planning is unavailable")]
    Unavailable,
    /// The injected planner returned a plan outside the public contract.
    #[error("public policy planner returned an invalid plan")]
    InvalidPlan,
}

fn decode_exact<M>(protobuf_body: &[u8]) -> Result<M, PublicPolicyPlanResolutionErrorV1>
where
    M: buffa::Message + PartialEq,
{
    let message = M::decode_from_slice(protobuf_body)
        .map_err(|_| PublicPolicyPlanResolutionErrorV1::Malformed)?;
    if message.encode_to_vec() != protobuf_body {
        return Err(PublicPolicyPlanResolutionErrorV1::Malformed);
    }

    Ok(message)
}

fn validate_request(
    request: DormantSandboxRequestKindV1,
) -> Result<(), PublicPolicyPlanResolutionErrorV1> {
    let client_state = DormantClientStatePlanV1::new(1, 1, None)
        .map_err(|_| PublicPolicyPlanResolutionErrorV1::Malformed)?;
    DormantSandboxRequestV1::from_parsed_command(
        request,
        DormantSandboxOutputV1::Json,
        client_state,
    )
    .map_err(|_| PublicPolicyPlanResolutionErrorV1::Malformed)?;

    Ok(())
}

fn exact_project(bytes: &[u8]) -> Result<ProjectId, PublicPolicyPlanResolutionErrorV1> {
    Ok(ProjectId::from_bytes(exact_identity(bytes)?))
}

fn resource_selector(bytes: &[u8]) -> Result<Selector, PublicPolicyPlanResolutionErrorV1> {
    Ok(Selector::Resource {
        resource: ResourceId::from_bytes(exact_identity(bytes)?),
    })
}

fn exact_identity(bytes: &[u8]) -> Result<[u8; 16], PublicPolicyPlanResolutionErrorV1> {
    let identity = bytes
        .try_into()
        .map_err(|_| PublicPolicyPlanResolutionErrorV1::InvalidIdentity)?;
    if identity == [0; 16] {
        return Err(PublicPolicyPlanResolutionErrorV1::InvalidIdentity);
    }

    Ok(identity)
}
