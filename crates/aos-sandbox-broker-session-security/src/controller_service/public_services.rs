//! Registered public resource services backed by the sole controller worker.

use aos_proto::aos::sandbox::v1::{
    AttachViewRequest, AttachViewResponse, AttenuateCapabilityRequest, AttenuateCapabilityResponse,
    CacheService as PublicCacheService, CancelExecutionRequest, CancelExecutionResponse,
    CapabilityService as PublicCapabilityService, CreateExecutionRequest, CreateExecutionResponse,
    CreateSandboxRequest, CreateSandboxResponse, CreateSnapshotRequest, CreateSnapshotResponse,
    CreateViewRequest, CreateViewResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DeleteSnapshotRequest, DeleteSnapshotResponse, DetachViewRequest, DetachViewResponse,
    ExecutionControlRequest, ExecutionControlResult, ExecutionService, FilesystemViewService,
    ForkSnapshotRequest, ForkSnapshotResponse, GetAttachmentRequest, GetAttachmentResponse,
    GetCacheStatusRequest, GetCacheStatusResponse, GetExecutionRequest, GetExecutionResponse,
    GetSandboxRequest, GetSandboxResponse, GetSnapshotRequest, GetSnapshotResponse, GetViewRequest,
    GetViewResponse, InspectCapabilityRequest, InspectCapabilityResponse, ListAncestorsRequest,
    ListAncestorsResponse, ListChildrenRequest, ListChildrenResponse, ListDescendantsRequest,
    ListDescendantsResponse, ListExecutionsRequest, ListExecutionsResponse, ListSandboxesRequest,
    ListSandboxesResponse, ListSnapshotsRequest, ListSnapshotsResponse, ListViewsRequest,
    ListViewsResponse, Operation as PublicOperation, PageInfo, PinCacheObjectRequest,
    PinCacheObjectResponse, PlanCreateSandboxRequest, PlanCreateSandboxResponse,
    PlanSandboxPolicyRequest, PlanSandboxPolicyResponse, ReleaseViewRequest, ReleaseViewResponse,
    RenewCapabilityRequest, RenewCapabilityResponse, ReplaceAttachmentRequest,
    ReplaceAttachmentResponse, RestoreSnapshotRequest, RestoreSnapshotResponse,
    RevokeCapabilityRequest, RevokeCapabilityResponse, Sandbox as PublicSandbox,
    SandboxLifecycleRequest, SandboxLifecycleResponse, SandboxService, SnapshotService,
    UnpinCacheObjectRequest, UnpinCacheObjectResponse, UpdateSandboxPolicyRequest,
    UpdateSandboxPolicyResponse,
};
use aos_sandbox::cli_model::MAXIMUM_CLI_PAGE_SIZE;
use aos_sandbox::cli_model::{
    AuditAuthorizationV1, PublicApiAuditMethodV1, PublicMutationRequestV1,
};
use aos_sandbox::client_state::MAXIMUM_PAGE_BYTES;
use aos_sandbox::controller_query::{
    NormalizedQueryDigestV1, QUERY_BINDING_TRANSPORT_BYTES, QueryBindingV1, QueryFilterDigestV1,
    QuerySortDigestV1, QueryVisibilityDigestV1,
};
use aos_sandbox::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionQueryV1, PublicProjectionRecordV1,
    PublicProjectionResourceV1,
};
use aos_sandbox_core::{ObjectDigest, Operation, ProjectId, ResourceId, ResourceKind, Selector};
use connectrpc::{
    ConnectError, Encodable, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use sha2::{Digest as _, Sha256};

use super::{AdmittedPublicMutationV1, CapabilityService, mutation_unavailable};

const QUERY_BINDING_HEADER: &str = "aos-query-binding-v1";
const PAGE_TOKEN_MAGIC: &[u8; 8] = b"AOSPGT01";
const PAGE_TOKEN_BYTES: usize = 8 + QUERY_BINDING_TRANSPORT_BYTES + 32 + 16 + 32;

impl CapabilityService {
    pub(super) async fn admit_public_command(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<AdmittedPublicMutationV1, ConnectError> {
        let request = PublicMutationRequestV1::new(method, protobuf_body).map_err(|_| {
            ConnectError::new(
                ErrorCode::InvalidArgument,
                "public mutation request envelope is invalid",
            )
        })?;

        self.admit_public_mutation(context, request.encode()).await
    }

    async fn admit_sandbox_command(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<(PublicOperation, PublicSandbox), ConnectError> {
        let admitted = self
            .admit_public_command(context, method, protobuf_body)
            .await?;
        let (operation, resource) = admitted_projection(admitted, PublicProjectionKindV1::Sandbox)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = resource else {
            return Err(projection_mismatch());
        };

        Ok((operation, sandbox))
    }
}

fn admitted_projection(
    admitted: AdmittedPublicMutationV1,
    expected_kind: PublicProjectionKindV1,
) -> Result<(PublicOperation, PublicProjectionResourceV1), ConnectError> {
    let record = single_record(admitted.projections)?;
    if record.resource().kind() != expected_kind {
        return Err(projection_mismatch());
    }

    Ok((admitted.operation, record.resource().clone()))
}

impl PublicCapabilityService for CapabilityService {
    async fn attenuate<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, AttenuateCapabilityRequest>,
    ) -> ServiceResult<impl Encodable<AttenuateCapabilityResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::AttenuateCapability,
                request.bytes(),
            )
            .await?;
        let (_, resource) = admitted_projection(admitted, PublicProjectionKindV1::Capability)?;
        let PublicProjectionResourceV1::Capability(capability) = resource else {
            return Err(projection_mismatch());
        };
        let capability_handle = capability.capability_id.clone();

        Response::ok(AttenuateCapabilityResponse {
            capability: Some(capability).into(),
            capability_handle,
            ..Default::default()
        })
    }

    async fn inspect<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, InspectCapabilityRequest>,
    ) -> ServiceResult<impl Encodable<InspectCapabilityResponse> + Send + use<'a>> {
        let resource_id = exact_resource_id(request.view().capability_handle, "capability handle")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::InspectCapability,
                ResourceKind::Capability,
                Operation::MetadataRead,
                resource_selector(resource_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind: PublicProjectionKindV1::Capability,
                    resource_id,
                },
            )
            .await?;
        let record = single_record(read.into_parts().1)?;
        let PublicProjectionResourceV1::Capability(capability) = record.resource().clone() else {
            return Err(projection_mismatch());
        };

        Response::ok(InspectCapabilityResponse {
            capability: Some(capability).into(),
            ..Default::default()
        })
    }

    async fn renew<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, RenewCapabilityRequest>,
    ) -> ServiceResult<impl Encodable<RenewCapabilityResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::RenewCapability,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Capability)?;
        let PublicProjectionResourceV1::Capability(capability) = resource else {
            return Err(projection_mismatch());
        };
        let capability_handle = capability.capability_id.clone();

        Response::ok(RenewCapabilityResponse {
            capability: Some(capability).into(),
            capability_handle,
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn revoke<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, RevokeCapabilityRequest>,
    ) -> ServiceResult<impl Encodable<RevokeCapabilityResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::RevokeCapability,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Capability)?;
        let PublicProjectionResourceV1::Capability(capability) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(RevokeCapabilityResponse {
            operation: Some(operation).into(),
            capability: Some(capability).into(),
            ..Default::default()
        })
    }
}

impl PublicCacheService for CapabilityService {
    async fn get_status<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetCacheStatusRequest>,
    ) -> ServiceResult<impl Encodable<GetCacheStatusResponse> + Send + use<'a>> {
        let view = request.view();
        let (kind, scope_id) = match (view.project_id.is_empty(), view.sandbox_id.is_empty()) {
            (false, true) => (
                PublicProjectionKindV1::ProjectCacheStatus,
                exact_resource_id(view.project_id, "project")?,
            ),
            (true, false) => (
                PublicProjectionKindV1::SandboxCacheStatus,
                exact_resource_id(view.sandbox_id, "sandbox")?,
            ),
            _ => {
                return Err(ConnectError::new(
                    ErrorCode::InvalidArgument,
                    "cache status requires exactly one project or sandbox scope",
                ));
            }
        };
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::GetCacheStatus,
                ResourceKind::CacheRead,
                Operation::MetadataRead,
                resource_selector(scope_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind,
                    resource_id: scope_id,
                },
            )
            .await?;
        let record = single_record(read.into_parts().1)?;
        let status = match record.resource().clone() {
            PublicProjectionResourceV1::ProjectCacheStatus { project_id, status }
                if project_id == scope_id =>
            {
                status
            }
            PublicProjectionResourceV1::SandboxCacheStatus { sandbox_id, status }
                if sandbox_id == scope_id =>
            {
                status
            }
            _ => return Err(projection_mismatch()),
        };

        Response::ok(GetCacheStatusResponse {
            status: Some(status).into(),
            ..Default::default()
        })
    }

    async fn pin_object<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, PinCacheObjectRequest>,
    ) -> ServiceResult<impl Encodable<PinCacheObjectResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::PinCacheObject,
                request.bytes(),
            )
            .await?;

        Response::ok(PinCacheObjectResponse {
            operation: Some(admitted.operation).into(),
            ..Default::default()
        })
    }

    async fn unpin_object<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, UnpinCacheObjectRequest>,
    ) -> ServiceResult<impl Encodable<UnpinCacheObjectResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::UnpinCacheObject,
                request.bytes(),
            )
            .await?;

        Response::ok(UnpinCacheObjectResponse {
            operation: Some(admitted.operation).into(),
            ..Default::default()
        })
    }
}

impl SandboxService for CapabilityService {
    async fn plan_create<'a>(
        &'a self,
        _context: RequestContext,
        _request: ServiceRequest<'_, PlanCreateSandboxRequest>,
    ) -> ServiceResult<impl Encodable<PlanCreateSandboxResponse> + Send + use<'a>> {
        Err::<Response<PlanCreateSandboxResponse>, _>(mutation_unavailable())
    }

    async fn create_sandbox<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CreateSandboxRequest>,
    ) -> ServiceResult<impl Encodable<CreateSandboxResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CreateSandbox,
                request.bytes(),
            )
            .await?;
        let (operation, resource) = admitted_projection(admitted, PublicProjectionKindV1::Sandbox)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(CreateSandboxResponse {
            sandbox: Some(sandbox).into(),
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn get_sandbox<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetSandboxRequest>,
    ) -> ServiceResult<impl Encodable<GetSandboxResponse> + Send + use<'a>> {
        let resource_id = exact_resource_id(request.view().sandbox_id, "sandbox")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::GetSandbox,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(resource_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind: PublicProjectionKindV1::Sandbox,
                    resource_id,
                },
            )
            .await?;
        let (_, mut records) = read.into_parts();
        let record = records.pop().ok_or_else(projection_mismatch)?;
        if !records.is_empty() {
            return Err(projection_mismatch());
        }
        let PublicProjectionResourceV1::Sandbox(sandbox) = record.resource().clone() else {
            return Err(projection_mismatch());
        };

        Response::ok(GetSandboxResponse {
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn list_sandboxes<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListSandboxesRequest>,
    ) -> ServiceResult<impl Encodable<ListSandboxesResponse> + Send + use<'a>> {
        let view = request.view();
        let project_id = exact_resource_id(view.project_id, "project")?;
        let project = ProjectId::from_bytes(project_id);
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::ListSandboxes,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(project_id),
                request.bytes(),
                PublicProjectionQueryV1::List {
                    kind: PublicProjectionKindV1::Sandbox,
                    project,
                },
            )
            .await?;
        let (authorization, records) = read.into_parts();
        let binding_scope = query_scope(&project_id, view.page_size);
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.SandboxService/ListSandboxes",
            &binding_scope,
            b"project-only-v1",
            b"sandbox-public-v1",
        );
        let page = paginate(
            PublicProjectionKindV1::Sandbox,
            &project_id,
            binding,
            view.page_size,
            view.page_token,
            records,
        )?;
        let page_info = page_info(&page);
        let sandboxes = page
            .records
            .into_iter()
            .map(|record| match record.resource().clone() {
                PublicProjectionResourceV1::Sandbox(sandbox) => Ok(sandbox),
                _ => Err(projection_mismatch()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let response = ListSandboxesResponse {
            sandboxes,
            page: Some(page_info).into(),
            ..Default::default()
        };

        response_with_query_binding(response, binding)
    }

    async fn list_children<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListChildrenRequest>,
    ) -> ServiceResult<impl Encodable<ListChildrenResponse> + Send + use<'a>> {
        self.list_children_response(&context, request).await
    }

    async fn list_ancestors<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListAncestorsRequest>,
    ) -> ServiceResult<impl Encodable<ListAncestorsResponse> + Send + use<'a>> {
        self.list_ancestors_response(&context, request).await
    }

    async fn list_descendants<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListDescendantsRequest>,
    ) -> ServiceResult<impl Encodable<ListDescendantsResponse> + Send + use<'a>> {
        self.list_descendants_response(&context, request).await
    }

    async fn plan_policy<'a>(
        &'a self,
        _context: RequestContext,
        _request: ServiceRequest<'_, PlanSandboxPolicyRequest>,
    ) -> ServiceResult<impl Encodable<PlanSandboxPolicyResponse> + Send + use<'a>> {
        Err::<Response<PlanSandboxPolicyResponse>, _>(mutation_unavailable())
    }

    async fn update_policy<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, UpdateSandboxPolicyRequest>,
    ) -> ServiceResult<impl Encodable<UpdateSandboxPolicyResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::UpdatePolicy,
                request.bytes(),
            )
            .await?;

        Response::ok(UpdateSandboxPolicyResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn start<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, SandboxLifecycleRequest>,
    ) -> ServiceResult<impl Encodable<SandboxLifecycleResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::StartSandbox,
                request.bytes(),
            )
            .await?;

        Response::ok(SandboxLifecycleResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn stop<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, SandboxLifecycleRequest>,
    ) -> ServiceResult<impl Encodable<SandboxLifecycleResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::StopSandbox,
                request.bytes(),
            )
            .await?;

        Response::ok(SandboxLifecycleResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn suspend<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, SandboxLifecycleRequest>,
    ) -> ServiceResult<impl Encodable<SandboxLifecycleResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::SuspendSandbox,
                request.bytes(),
            )
            .await?;

        Response::ok(SandboxLifecycleResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn resume<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, SandboxLifecycleRequest>,
    ) -> ServiceResult<impl Encodable<SandboxLifecycleResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::ResumeSandbox,
                request.bytes(),
            )
            .await?;

        Response::ok(SandboxLifecycleResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn delete_sandbox<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, DeleteSandboxRequest>,
    ) -> ServiceResult<impl Encodable<DeleteSandboxResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::DeleteSandbox,
                request.bytes(),
            )
            .await?;
        let (operation, resource) = admitted_projection(admitted, PublicProjectionKindV1::Sandbox)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(DeleteSandboxResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }
}

impl ExecutionService for CapabilityService {
    async fn create_execution<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CreateExecutionRequest>,
    ) -> ServiceResult<impl Encodable<CreateExecutionResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CreateExecution,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Execution)?;
        let PublicProjectionResourceV1::Execution(execution) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(CreateExecutionResponse {
            execution: Some(execution).into(),
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn get_execution<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetExecutionRequest>,
    ) -> ServiceResult<impl Encodable<GetExecutionResponse> + Send + use<'a>> {
        let resource_id = exact_resource_id(request.view().execution_id, "execution")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::GetExecution,
                ResourceKind::Execution,
                Operation::MetadataRead,
                resource_selector(resource_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind: PublicProjectionKindV1::Execution,
                    resource_id,
                },
            )
            .await?;
        let record = single_record(read.into_parts().1)?;
        let PublicProjectionResourceV1::Execution(execution) = record.resource().clone() else {
            return Err(projection_mismatch());
        };

        Response::ok(GetExecutionResponse {
            execution: Some(execution).into(),
            ..Default::default()
        })
    }

    async fn list_executions<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListExecutionsRequest>,
    ) -> ServiceResult<impl Encodable<ListExecutionsResponse> + Send + use<'a>> {
        let view = request.view();
        let sandbox_id = exact_resource_id(view.sandbox_id, "sandbox")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::ListExecutions,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(sandbox_id),
                request.bytes(),
                PublicProjectionQueryV1::Related {
                    kind: PublicProjectionKindV1::Execution,
                    scope_kind: PublicProjectionKindV1::Sandbox,
                    scope_id: sandbox_id,
                },
            )
            .await?;
        let (authorization, mut records) = read.into_parts();
        records.retain(|record| {
            matches!(
                record.resource(),
                PublicProjectionResourceV1::Execution(execution)
                    if execution.sandbox_id == sandbox_id
            )
        });
        let binding_scope = query_scope(&sandbox_id, view.page_size);
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.ExecutionService/ListExecutions",
            &binding_scope,
            b"sandbox-executions-v1",
            b"execution-public-v1",
        );
        let page = paginate(
            PublicProjectionKindV1::Execution,
            &sandbox_id,
            binding,
            view.page_size,
            view.page_token,
            records,
        )?;
        let page_info = page_info(&page);
        let executions = page
            .records
            .into_iter()
            .map(|record| match record.resource().clone() {
                PublicProjectionResourceV1::Execution(execution) => Ok(execution),
                _ => Err(projection_mismatch()),
            })
            .collect::<Result<Vec<_>, _>>()?;

        response_with_query_binding(
            ListExecutionsResponse {
                executions,
                page: Some(page_info).into(),
                ..Default::default()
            },
            binding,
        )
    }

    async fn control_execution<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ExecutionControlRequest>,
    ) -> ServiceResult<impl Encodable<ExecutionControlResult> + Send + use<'a>> {
        let execution_id = request.view().execution_id.to_vec();
        let action = request.view().action;
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::ControlExecution,
                request.bytes(),
            )
            .await?;

        Response::ok(ExecutionControlResult {
            execution_id,
            action,
            accepted: true,
            operation: Some(admitted.operation).into(),
            ..Default::default()
        })
    }

    async fn cancel_execution<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CancelExecutionRequest>,
    ) -> ServiceResult<impl Encodable<CancelExecutionResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CancelExecution,
                request.bytes(),
            )
            .await?;

        Response::ok(CancelExecutionResponse {
            operation: Some(admitted.operation).into(),
            ..Default::default()
        })
    }
}

impl FilesystemViewService for CapabilityService {
    async fn create_view<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CreateViewRequest>,
    ) -> ServiceResult<impl Encodable<CreateViewResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CreateView,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::FilesystemView)?;
        let PublicProjectionResourceV1::FilesystemView(view) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(CreateViewResponse {
            view: Some(view).into(),
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn get_view<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetViewRequest>,
    ) -> ServiceResult<impl Encodable<GetViewResponse> + Send + use<'a>> {
        let resource_id = exact_resource_id(request.view().view_id, "filesystem view")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::GetView,
                ResourceKind::Tree,
                Operation::MetadataRead,
                resource_selector(resource_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind: PublicProjectionKindV1::FilesystemView,
                    resource_id,
                },
            )
            .await?;
        let record = single_record(read.into_parts().1)?;
        let PublicProjectionResourceV1::FilesystemView(view) = record.resource().clone() else {
            return Err(projection_mismatch());
        };

        Response::ok(GetViewResponse {
            view: Some(view).into(),
            ..Default::default()
        })
    }

    async fn get_attachment<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetAttachmentRequest>,
    ) -> ServiceResult<impl Encodable<GetAttachmentResponse> + Send + use<'a>> {
        let resource_id = exact_resource_id(request.view().attachment_id, "attachment")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::GetAttachment,
                ResourceKind::AttachmentSlot,
                Operation::MetadataRead,
                resource_selector(resource_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind: PublicProjectionKindV1::Attachment,
                    resource_id,
                },
            )
            .await?;
        let record = single_record(read.into_parts().1)?;
        let PublicProjectionResourceV1::Attachment(attachment) = record.resource().clone() else {
            return Err(projection_mismatch());
        };

        Response::ok(GetAttachmentResponse {
            attachment: Some(attachment).into(),
            ..Default::default()
        })
    }

    async fn list_views<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListViewsRequest>,
    ) -> ServiceResult<impl Encodable<ListViewsResponse> + Send + use<'a>> {
        let view = request.view();
        let project_id = exact_resource_id(view.project_id, "project")?;
        let project = ProjectId::from_bytes(project_id);
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::ListViews,
                ResourceKind::Tree,
                Operation::MetadataRead,
                resource_selector(project_id),
                request.bytes(),
                PublicProjectionQueryV1::List {
                    kind: PublicProjectionKindV1::FilesystemView,
                    project,
                },
            )
            .await?;
        let (authorization, records) = read.into_parts();
        let binding_scope = query_scope(&project_id, view.page_size);
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.FilesystemViewService/ListViews",
            &binding_scope,
            b"project-views-v1",
            b"filesystem-view-public-v1",
        );
        let page = paginate(
            PublicProjectionKindV1::FilesystemView,
            &project_id,
            binding,
            view.page_size,
            view.page_token,
            records,
        )?;
        let page_info = page_info(&page);
        let views = page
            .records
            .into_iter()
            .map(|record| match record.resource().clone() {
                PublicProjectionResourceV1::FilesystemView(view) => Ok(view),
                _ => Err(projection_mismatch()),
            })
            .collect::<Result<Vec<_>, _>>()?;

        response_with_query_binding(
            ListViewsResponse {
                views,
                page: Some(page_info).into(),
                ..Default::default()
            },
            binding,
        )
    }

    async fn attach_view<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, AttachViewRequest>,
    ) -> ServiceResult<impl Encodable<AttachViewResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::AttachView,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Attachment)?;
        let PublicProjectionResourceV1::Attachment(attachment) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(AttachViewResponse {
            attachment: Some(attachment).into(),
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn replace_attachment<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ReplaceAttachmentRequest>,
    ) -> ServiceResult<impl Encodable<ReplaceAttachmentResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::ReplaceAttachment,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Attachment)?;
        let PublicProjectionResourceV1::Attachment(attachment) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(ReplaceAttachmentResponse {
            operation: Some(operation).into(),
            attachment: Some(attachment).into(),
            ..Default::default()
        })
    }

    async fn detach_view<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, DetachViewRequest>,
    ) -> ServiceResult<impl Encodable<DetachViewResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::DetachView,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Attachment)?;
        let PublicProjectionResourceV1::Attachment(attachment) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(DetachViewResponse {
            operation: Some(operation).into(),
            attachment: Some(attachment).into(),
            ..Default::default()
        })
    }

    async fn release_view<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ReleaseViewRequest>,
    ) -> ServiceResult<impl Encodable<ReleaseViewResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::ReleaseView,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::FilesystemView)?;
        let PublicProjectionResourceV1::FilesystemView(view) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(ReleaseViewResponse {
            operation: Some(operation).into(),
            view: Some(view).into(),
            ..Default::default()
        })
    }
}

impl SnapshotService for CapabilityService {
    async fn create_snapshot<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CreateSnapshotRequest>,
    ) -> ServiceResult<impl Encodable<CreateSnapshotResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CreateSnapshot,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Snapshot)?;
        let PublicProjectionResourceV1::Snapshot(snapshot) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(CreateSnapshotResponse {
            snapshot: Some(snapshot).into(),
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn get_snapshot<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetSnapshotRequest>,
    ) -> ServiceResult<impl Encodable<GetSnapshotResponse> + Send + use<'a>> {
        let resource_id = exact_resource_id(request.view().snapshot_id, "snapshot")?;
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::GetSnapshot,
                ResourceKind::Snapshot,
                Operation::MetadataRead,
                resource_selector(resource_id),
                request.bytes(),
                PublicProjectionQueryV1::One {
                    kind: PublicProjectionKindV1::Snapshot,
                    resource_id,
                },
            )
            .await?;
        let record = single_record(read.into_parts().1)?;
        let PublicProjectionResourceV1::Snapshot(snapshot) = record.resource().clone() else {
            return Err(projection_mismatch());
        };

        Response::ok(GetSnapshotResponse {
            snapshot: Some(snapshot).into(),
            ..Default::default()
        })
    }

    async fn list_snapshots<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ListSnapshotsRequest>,
    ) -> ServiceResult<impl Encodable<ListSnapshotsResponse> + Send + use<'a>> {
        let view = request.view();
        let project_id = exact_resource_id(view.project_id, "project")?;
        let project = ProjectId::from_bytes(project_id);
        let sandbox_id = optional_resource_id(view.sandbox_id, "sandbox")?;
        let selector_id = sandbox_id.unwrap_or(project_id);
        let selector_kind = if sandbox_id.is_some() {
            ResourceKind::Sandbox
        } else {
            ResourceKind::Snapshot
        };
        let read = self
            .read_public_projection(
                &context,
                PublicApiAuditMethodV1::ListSnapshots,
                selector_kind,
                Operation::MetadataRead,
                resource_selector(selector_id),
                request.bytes(),
                PublicProjectionQueryV1::List {
                    kind: PublicProjectionKindV1::Snapshot,
                    project,
                },
            )
            .await?;
        let (authorization, mut records) = read.into_parts();
        if let Some(sandbox_id) = sandbox_id {
            records.retain(|record| {
                matches!(
                    record.resource(),
                    PublicProjectionResourceV1::Snapshot(snapshot)
                        if snapshot.source_sandbox_id == sandbox_id
                )
            });
        }
        let scope = [project_id.as_slice(), view.sandbox_id].concat();
        let binding_scope = query_scope(&scope, view.page_size);
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.SnapshotService/ListSnapshots",
            &binding_scope,
            b"project-sandbox-snapshots-v1",
            b"snapshot-public-v1",
        );
        let page = paginate(
            PublicProjectionKindV1::Snapshot,
            &scope,
            binding,
            view.page_size,
            view.page_token,
            records,
        )?;
        let page_info = page_info(&page);
        let snapshots = page
            .records
            .into_iter()
            .map(|record| match record.resource().clone() {
                PublicProjectionResourceV1::Snapshot(snapshot) => Ok(snapshot),
                _ => Err(projection_mismatch()),
            })
            .collect::<Result<Vec<_>, _>>()?;

        response_with_query_binding(
            ListSnapshotsResponse {
                snapshots,
                page: Some(page_info).into(),
                ..Default::default()
            },
            binding,
        )
    }

    async fn restore_snapshot<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, RestoreSnapshotRequest>,
    ) -> ServiceResult<impl Encodable<RestoreSnapshotResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::RestoreSnapshot,
                request.bytes(),
            )
            .await?;

        Response::ok(RestoreSnapshotResponse {
            operation: Some(operation).into(),
            sandbox: Some(sandbox).into(),
            ..Default::default()
        })
    }

    async fn fork_snapshot<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, ForkSnapshotRequest>,
    ) -> ServiceResult<impl Encodable<ForkSnapshotResponse> + Send + use<'a>> {
        let (operation, sandbox) = self
            .admit_sandbox_command(
                &context,
                PublicApiAuditMethodV1::ForkSnapshot,
                request.bytes(),
            )
            .await?;

        Response::ok(ForkSnapshotResponse {
            sandbox: Some(sandbox).into(),
            operation: Some(operation).into(),
            ..Default::default()
        })
    }

    async fn delete_snapshot<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, DeleteSnapshotRequest>,
    ) -> ServiceResult<impl Encodable<DeleteSnapshotResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::DeleteSnapshot,
                request.bytes(),
            )
            .await?;
        let (operation, resource) =
            admitted_projection(admitted, PublicProjectionKindV1::Snapshot)?;
        let PublicProjectionResourceV1::Snapshot(snapshot) = resource else {
            return Err(projection_mismatch());
        };

        Response::ok(DeleteSnapshotResponse {
            operation: Some(operation).into(),
            snapshot: Some(snapshot).into(),
            ..Default::default()
        })
    }
}

fn single_record(
    mut records: Vec<PublicProjectionRecordV1>,
) -> Result<PublicProjectionRecordV1, ConnectError> {
    let record = records.pop().ok_or_else(projection_mismatch)?;
    if !records.is_empty() {
        return Err(projection_mismatch());
    }
    Ok(record)
}

pub(super) fn list_query_binding(
    authorization: AuditAuthorizationV1,
    method: &[u8],
    scope: &[u8],
    filters: &[u8],
    visibility: &[u8],
) -> QueryBindingV1 {
    let mut normalized = Vec::with_capacity(method.len() + 1 + scope.len());
    normalized.extend_from_slice(method);
    normalized.push(0);
    normalized.extend_from_slice(scope);

    authorization.query_binding(
        NormalizedQueryDigestV1::commit(&normalized),
        QueryFilterDigestV1::commit(filters),
        QuerySortDigestV1::commit(b"resource-id-ascending-v1"),
        QueryVisibilityDigestV1::commit(visibility),
    )
}

pub(super) fn query_scope(scope: &[u8], page_size: u32) -> Vec<u8> {
    let mut binding = Vec::with_capacity(scope.len() + 4);
    binding.extend_from_slice(scope);
    binding.extend_from_slice(&page_size.to_be_bytes());
    binding
}

pub(super) fn exact_resource_id(
    bytes: &[u8],
    label: &'static str,
) -> Result<[u8; 16], ConnectError> {
    let identity: [u8; 16] = bytes.try_into().map_err(|_| {
        ConnectError::new(
            ErrorCode::InvalidArgument,
            format!("{label} identity must contain exactly 16 bytes"),
        )
    })?;
    if identity == [0; 16] {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            format!("{label} identity must be nonzero"),
        ));
    }

    Ok(identity)
}

fn optional_resource_id(
    bytes: &[u8],
    label: &'static str,
) -> Result<Option<[u8; 16]>, ConnectError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        exact_resource_id(bytes, label).map(Some)
    }
}

pub(super) fn resource_selector(resource_id: [u8; 16]) -> Selector {
    Selector::Resource {
        resource: ResourceId::from_bytes(resource_id),
    }
}

pub(super) fn projection_mismatch() -> ConnectError {
    ConnectError::new(
        ErrorCode::Unavailable,
        "controller public resource projection is inconsistent",
    )
}

pub(super) struct ProjectionPageV1 {
    pub(super) records: Vec<PublicProjectionRecordV1>,
    pub(super) revision: ObjectDigest,
    pub(super) next_page_token: Vec<u8>,
}

pub(super) fn page_info(page: &ProjectionPageV1) -> PageInfo {
    PageInfo {
        next_page_token: page.next_page_token.clone(),
        immutable_list_revision: page.revision.as_bytes().to_vec(),
        ..Default::default()
    }
}

pub(super) fn paginate(
    kind: PublicProjectionKindV1,
    scope: &[u8],
    binding: QueryBindingV1,
    page_size: u32,
    page_token: &[u8],
    records: Vec<PublicProjectionRecordV1>,
) -> Result<ProjectionPageV1, ConnectError> {
    if page_size == 0 || page_size > u32::from(MAXIMUM_CLI_PAGE_SIZE) {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "page size is outside the supported range",
        ));
    }
    let revision = list_revision(kind, scope, &records);
    let start = if page_token.is_empty() {
        0
    } else {
        let after = decode_page_token(page_token, binding, revision)?;
        records
            .iter()
            .position(|record| record.resource().resource_id() == after)
            .ok_or_else(|| {
                ConnectError::new(ErrorCode::InvalidArgument, "page token is no longer valid")
            })?
            + 1
    };

    let mut end = start;
    let mut bytes = 0_usize;
    while end < records.len() && end - start < page_size as usize {
        let next_bytes = bytes
            .checked_add(records[end].encoded_bytes())
            .ok_or_else(projection_mismatch)?;
        if end > start && next_bytes > MAXIMUM_PAGE_BYTES {
            break;
        }
        bytes = next_bytes;
        end += 1;
    }
    let next_page_token = if end < records.len() {
        let last = records
            .get(end.saturating_sub(1))
            .ok_or_else(projection_mismatch)?;
        let after: [u8; 16] = last
            .resource()
            .resource_id()
            .try_into()
            .map_err(|_| projection_mismatch())?;
        encode_page_token(binding, revision, after)
    } else {
        Vec::new()
    };
    let records = records.into_iter().skip(start).take(end - start).collect();

    Ok(ProjectionPageV1 {
        records,
        revision,
        next_page_token,
    })
}

fn list_revision(
    kind: PublicProjectionKindV1,
    scope: &[u8],
    records: &[PublicProjectionRecordV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.public-projection-list.v1\0");
    digest.update([kind as u8]);
    digest.update((scope.len() as u64).to_be_bytes());
    digest.update(scope);
    digest.update((records.len() as u64).to_be_bytes());
    for record in records {
        digest.update(record.resource().resource_id());
        digest.update(record.revision().as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_page_token(binding: QueryBindingV1, revision: ObjectDigest, after: [u8; 16]) -> Vec<u8> {
    let mut token = Vec::with_capacity(PAGE_TOKEN_BYTES);
    token.extend_from_slice(PAGE_TOKEN_MAGIC);
    token.extend_from_slice(&binding.to_transport_bytes());
    token.extend_from_slice(revision.as_bytes());
    token.extend_from_slice(&after);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.public-projection-page-token.v1\0")
        .chain_update(&token)
        .finalize()
        .into();
    token.extend_from_slice(&digest);
    token
}

fn decode_page_token(
    token: &[u8],
    binding: QueryBindingV1,
    revision: ObjectDigest,
) -> Result<[u8; 16], ConnectError> {
    if token.len() != PAGE_TOKEN_BYTES || token.get(..8) != Some(PAGE_TOKEN_MAGIC.as_slice()) {
        return Err(invalid_page_token());
    }
    let binding_end = 8 + QUERY_BINDING_TRANSPORT_BYTES;
    if token.get(8..binding_end) != Some(binding.to_transport_bytes().as_slice())
        || token.get(binding_end..binding_end + 32) != Some(revision.as_bytes().as_slice())
    {
        return Err(invalid_page_token());
    }
    let digest_start = PAGE_TOKEN_BYTES - 32;
    let expected: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.public-projection-page-token.v1\0")
        .chain_update(&token[..digest_start])
        .finalize()
        .into();
    if token[digest_start..] != expected {
        return Err(invalid_page_token());
    }

    token[digest_start - 16..digest_start]
        .try_into()
        .map_err(|_| invalid_page_token())
}

fn invalid_page_token() -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, "page token is invalid")
}

pub(super) fn response_with_query_binding<T>(body: T, binding: QueryBindingV1) -> ServiceResult<T> {
    Response::new(body)
        .try_with_header(
            QUERY_BINDING_HEADER,
            lower_hex(&binding.to_transport_bytes()),
        )
        .map_err(|_| {
            ConnectError::new(
                ErrorCode::Internal,
                "controller could not encode the query binding",
            )
        })
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
