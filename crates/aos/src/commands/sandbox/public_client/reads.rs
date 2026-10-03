//! Checked unary reads over the registered public endpoint.

use anyhow::{Context as _, Result};
use aos_proto::aos::sandbox::v1::{
    CacheServiceClient, CapabilityServiceClient, ExecutionServiceClient,
    FilesystemViewServiceClient, ListAncestorsResponse, ListChildrenResponse,
    ListDescendantsRequest, ListDescendantsResponse, ListExecutionsResponse, ListSandboxesResponse,
    ListSnapshotsResponse, ListViewsResponse, PageInfo, SandboxServiceClient,
    SnapshotServiceClient,
};
use aos_sandbox::cli_model::{
    CheckedCacheStatusV1, CheckedListProtoJsonV1, CheckedPolicyPlanV1, CheckedSandboxTreeV1,
    DormantListContinuationV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1,
    DormantSandboxRequestV1, DormantSandboxTreePageConsumerV1,
};
use aos_sandbox::client_state::{
    ImmutableListPageV1, MAXIMUM_COLLECTED_BYTES, MAXIMUM_COLLECTED_ITEMS, PageApplyOutcomeV1,
    PaginationReducerV1,
};
use aos_sandbox::controller_query::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedSandboxResourceV1, CheckedSnapshotResourceV1,
};
use aos_sandbox_core::CapabilityId;
use connectrpc::client::SharedHttp2Connection;

use crate::cli::sandbox::SandboxArgs;

use super::{AuthorizedEndpoint, authenticated_query_binding, is_supported_read};

macro_rules! fetch_paginated_list {
    (
        $client:expr,
        $method:ident,
        $initial_request:expr,
        $response:ident,
        $field:ident,
        $wrapper:ty,
        $output:expr,
        $maximum_pages:expr,
        $failure:literal
    ) => {{
        let mut next_request = $initial_request.clone();
        let retained = if next_request.page_token.is_empty() {
            None
        } else {
            Some(
                DormantListContinuationV1::decode(&next_request.page_token)
                    .context("list page token is not a bound CLI continuation")?,
            )
        };
        let mut reducer: Option<PaginationReducerV1<$wrapper>> = match retained {
            Some(retained) => {
                next_request.page_token = retained.server_page_token().to_vec();
                Some(
                    PaginationReducerV1::resume(
                        retained.binding(),
                        retained.immutable_revision().to_vec(),
                        retained.server_page_token().to_vec(),
                        MAXIMUM_COLLECTED_ITEMS,
                        MAXIMUM_COLLECTED_BYTES,
                    )
                    .context("retained list continuation is invalid")?,
                )
            }
            None => None,
        };
        let mut complete = false;

        for _ in 0..usize::from($maximum_pages) {
            let unary = $client
                .$method(next_request.clone())
                .await
                .context($failure)?;
            let response_binding = authenticated_query_binding(unary.headers())?;
            let mut response: $response = unary.into_owned();
            let page_info = response
                .page
                .into_option()
                .context("controller omitted list pagination metadata")?;
            let checked_items = std::mem::take(&mut response.$field)
                .into_iter()
                .map(<$wrapper>::try_from)
                .collect::<Result<Vec<_>, _>>()
                .context("controller returned an invalid list resource")?;

            if reducer.is_none() {
                reducer = Some(
                    PaginationReducerV1::new(
                        response_binding,
                        MAXIMUM_COLLECTED_ITEMS,
                        MAXIMUM_COLLECTED_BYTES,
                    )
                    .context("client pagination bounds are invalid")?,
                );
            }
            let reducer = reducer
                .as_mut()
                .context("pagination reducer was not initialized")?;
            let page_request = reducer
                .request()
                .context("controller returned a page after list completion")?;
            if page_request.binding() != response_binding {
                anyhow::bail!("controller changed the authenticated list binding");
            }
            let checked_page =
                ImmutableListPageV1::from_response(page_request, page_info, checked_items)
                    .context("controller returned invalid pagination state")?;

            match reducer
                .apply(checked_page)
                .context("controller returned non-contiguous pagination state")?
            {
                PageApplyOutcomeV1::Continue => {
                    let continuation = reducer
                        .request()
                        .context("pagination continuation omitted its request")?;
                    next_request.page_token = continuation
                        .token_bytes()
                        .context("pagination continuation omitted its token")?
                        .to_vec();
                }
                PageApplyOutcomeV1::Complete => {
                    complete = true;
                    break;
                }
            }
        }

        if !complete {
            anyhow::bail!("list exceeded the requested maximum page count");
        }
        let reducer = reducer.context("controller returned no list pages")?;
        let immutable_list_revision = reducer
            .revision()
            .context("completed list omitted its immutable revision")?
            .as_bytes()
            .to_vec();
        let items = reducer
            .into_complete_items()
            .context("list did not reach a terminal page")?;

        if $output == DormantSandboxOutputV1::JsonLines {
            for item in &items {
                super::super::render_checked($output, item)?;
            }
        } else {
            let response = $response {
                $field: items.into_iter().map(<$wrapper>::into_proto).collect(),
                page: Some(PageInfo {
                    immutable_list_revision,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            };
            let checked = CheckedListProtoJsonV1::try_from(response)
                .context("complete list exceeds the structured-output bound")?;
            super::super::render_checked($output, &checked)?;
        }
    }};
}

/// Routes one read-only public request when its generated client is active here.
///
/// Returns `false` for mutation, streaming, discovery, and local-only routes so
/// the caller can select their separate execution path.
///
/// # Errors
///
/// Returns an error for protected credential, transport, server, response
/// validation, or rendering failure.
pub(in crate::commands::sandbox) async fn dispatch_read(
    args: &SandboxArgs,
    request: &DormantSandboxRequestV1,
    output: DormantSandboxOutputV1,
    expected_capability_id: Option<CapabilityId>,
) -> Result<bool> {
    if !args.public_api || !is_supported_read(request.kind()) {
        return Ok(false);
    }

    let expected_capability_id = expected_capability_id
        .context("authenticated read has no protected capability identity")?;
    let endpoint = AuthorizedEndpoint::connect(args, Some(expected_capability_id)).await?;
    let connection = endpoint.connection.clone();
    let config = endpoint.config()?;

    match request.kind() {
        DormantSandboxRequestKindV1::PlanCreate(message) => {
            let response = SandboxServiceClient::new(connection, config)
                .plan_create(message.clone())
                .await
                .context("controller rejected sandbox create planning")?
                .into_owned();
            let plan = response
                .plan
                .into_option()
                .context("controller omitted the create policy plan")?;
            let checked = CheckedPolicyPlanV1::try_from(plan)
                .context("controller returned an invalid create policy plan")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::GetSandbox(message) => {
            let response = SandboxServiceClient::new(connection, config)
                .get_sandbox(message.clone())
                .await
                .context("controller rejected sandbox lookup")?
                .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the sandbox resource")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid sandbox resource")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::ListSandboxes(message) => {
            let client = SandboxServiceClient::new(connection, config);
            fetch_paginated_list!(
                client,
                list_sandboxes,
                message,
                ListSandboxesResponse,
                sandboxes,
                CheckedSandboxResourceV1,
                output,
                request.client_state().maximum_pages(),
                "controller rejected sandbox listing"
            );
        }
        DormantSandboxRequestKindV1::Children(message) => {
            let client = SandboxServiceClient::new(connection, config);
            fetch_paginated_list!(
                client,
                list_children,
                message,
                ListChildrenResponse,
                children,
                CheckedSandboxResourceV1,
                output,
                request.client_state().maximum_pages(),
                "controller rejected child listing"
            );
        }
        DormantSandboxRequestKindV1::Ancestors(message) => {
            let client = SandboxServiceClient::new(connection, config);
            fetch_paginated_list!(
                client,
                list_ancestors,
                message,
                ListAncestorsResponse,
                ancestors,
                CheckedSandboxResourceV1,
                output,
                request.client_state().maximum_pages(),
                "controller rejected ancestor listing"
            );
        }
        DormantSandboxRequestKindV1::Tree(message) => {
            let client = SandboxServiceClient::new(connection, config);
            fetch_tree(client, message, request, output).await?;
        }
        DormantSandboxRequestKindV1::PlanPolicy(message) => {
            let response = SandboxServiceClient::new(connection, config)
                .plan_policy(message.clone())
                .await
                .context("controller rejected sandbox policy planning")?
                .into_owned();
            let plan = response
                .plan
                .into_option()
                .context("controller omitted the sandbox policy plan")?;
            let checked = CheckedPolicyPlanV1::try_from(plan)
                .context("controller returned an invalid sandbox policy plan")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::GetExecution(message) => {
            let response = ExecutionServiceClient::new(connection, config)
                .get_execution(message.clone())
                .await
                .context("controller rejected execution lookup")?
                .into_owned();
            let resource = response
                .execution
                .into_option()
                .context("controller omitted the execution resource")?;
            let checked = CheckedExecutionResourceV1::try_from(resource)
                .context("controller returned an invalid execution resource")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::ListExecutions(message) => {
            let client = ExecutionServiceClient::new(connection, config);
            fetch_paginated_list!(
                client,
                list_executions,
                message,
                ListExecutionsResponse,
                executions,
                CheckedExecutionResourceV1,
                output,
                request.client_state().maximum_pages(),
                "controller rejected execution listing"
            );
        }
        DormantSandboxRequestKindV1::GetView(message) => {
            let response = FilesystemViewServiceClient::new(connection, config)
                .get_view(message.clone())
                .await
                .context("controller rejected filesystem-view lookup")?
                .into_owned();
            let resource = response
                .view
                .into_option()
                .context("controller omitted the filesystem-view resource")?;
            let checked = CheckedFilesystemViewResourceV1::try_from(resource)
                .context("controller returned an invalid filesystem-view resource")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::GetAttachment(message) => {
            let response = FilesystemViewServiceClient::new(connection, config)
                .get_attachment(message.clone())
                .await
                .context("controller rejected attachment lookup")?
                .into_owned();
            let resource = response
                .attachment
                .into_option()
                .context("controller omitted the attachment resource")?;
            let checked = CheckedAttachmentResourceV1::try_from(resource)
                .context("controller returned an invalid attachment resource")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::ViewList(message) => {
            let client = FilesystemViewServiceClient::new(connection, config);
            fetch_paginated_list!(
                client,
                list_views,
                message,
                ListViewsResponse,
                views,
                CheckedFilesystemViewResourceV1,
                output,
                request.client_state().maximum_pages(),
                "controller rejected filesystem-view listing"
            );
        }
        DormantSandboxRequestKindV1::GetSnapshot(message) => {
            let response = SnapshotServiceClient::new(connection, config)
                .get_snapshot(message.clone())
                .await
                .context("controller rejected snapshot lookup")?
                .into_owned();
            let resource = response
                .snapshot
                .into_option()
                .context("controller omitted the snapshot resource")?;
            let checked = CheckedSnapshotResourceV1::try_from(resource)
                .context("controller returned an invalid snapshot resource")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::ListSnapshots(message) => {
            let client = SnapshotServiceClient::new(connection, config);
            fetch_paginated_list!(
                client,
                list_snapshots,
                message,
                ListSnapshotsResponse,
                snapshots,
                CheckedSnapshotResourceV1,
                output,
                request.client_state().maximum_pages(),
                "controller rejected snapshot listing"
            );
        }
        DormantSandboxRequestKindV1::CacheStatus(message) => {
            let response = CacheServiceClient::new(connection, config)
                .get_status(message.clone())
                .await
                .context("controller rejected cache-status lookup")?
                .into_owned();
            let status = response
                .status
                .into_option()
                .context("controller omitted cache status")?;
            let checked = CheckedCacheStatusV1::try_from(status)
                .context("controller returned invalid cache status")?;
            super::super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::CapabilityInspect(message) => {
            let response = CapabilityServiceClient::new(connection, config)
                .inspect(message.clone())
                .await
                .context("controller rejected capability inspection")?
                .into_owned();
            let resource = response
                .capability
                .into_option()
                .context("controller omitted the capability resource")?;
            let checked = CheckedCapabilityResourceV1::try_from(resource)
                .context("controller returned an invalid capability resource")?;
            super::super::render_checked(output, &checked)?;
        }
        _ => return Ok(false),
    }

    Ok(true)
}

async fn fetch_tree(
    client: SandboxServiceClient<SharedHttp2Connection>,
    initial_request: &ListDescendantsRequest,
    command: &DormantSandboxRequestV1,
    output: DormantSandboxOutputV1,
) -> Result<()> {
    let mut consumer =
        DormantSandboxTreePageConsumerV1::new(initial_request.clone(), command.client_state())
            .context("tree pagination request is invalid")?;
    let mut authenticated_binding = None;
    let mut immutable_revision: Option<Vec<u8>> = None;
    let mut aggregate: Option<ListDescendantsResponse> = None;

    loop {
        let page_request = consumer
            .next_request()
            .cloned()
            .context("tree pagination ended without a terminal page")?;
        let unary = client
            .list_descendants(page_request)
            .await
            .context("controller rejected descendant listing")?;
        let response_binding = authenticated_query_binding(unary.headers())?;
        if authenticated_binding.is_some_and(|binding| binding != response_binding) {
            anyhow::bail!("controller changed the authenticated tree binding");
        }
        authenticated_binding = Some(response_binding);

        let response = unary.into_owned();
        let page = response
            .page
            .as_option()
            .context("controller omitted tree pagination metadata")?;
        if immutable_revision
            .as_ref()
            .is_some_and(|revision| revision != &page.immutable_list_revision)
        {
            anyhow::bail!("controller changed the immutable tree revision");
        }
        immutable_revision.get_or_insert_with(|| page.immutable_list_revision.clone());

        let _checked_page = consumer
            .consume(response.clone())
            .context("controller returned invalid tree pagination state")?;
        match aggregate.as_mut() {
            Some(aggregate) => {
                aggregate.nodes.extend(response.nodes);
                aggregate.page = response.page;
                aggregate.preorder_after = response.preorder_after;
            }
            None => aggregate = Some(response),
        }

        if consumer.next_request().is_none() {
            let aggregate = aggregate.context("controller returned no tree pages")?;
            let checked = CheckedSandboxTreeV1::from_response(initial_request, aggregate)
                .context("complete descendant tree is invalid")?;
            super::super::render_checked(output, &checked)?;
            return Ok(());
        }
        if consumer.remaining_pages() == 0 {
            anyhow::bail!("tree exceeded the requested maximum page count");
        }
    }
}
