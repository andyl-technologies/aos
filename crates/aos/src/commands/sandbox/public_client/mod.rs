//! Generated public API clients for sandbox commands.
//!
//! Every response crosses its checked established-message projection before it
//! reaches a renderer. The capability UUID is only a lookup header on the
//! mutually authenticated connection; it never substitutes for server-side
//! current authorization.

use anyhow::{Context as _, Result};
use aos_proto::aos::sandbox::v1::{
    CacheServiceClient, CapabilityServiceClient, ExecutionServiceClient,
    FilesystemViewServiceClient, GetOperationRequest, Operation, OperationServiceClient,
    OperatorServiceClient, SandboxServiceClient, SnapshotServiceClient,
};
use aos_sandbox::cli_model::{
    CheckedExecutionControlResultV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1,
    DormantSandboxRequestV1, EstablishedProtoJson,
};
use aos_sandbox::client_state::{
    MAXIMUM_WAIT_OBSERVATIONS, OperationWaitApplyOutcomeV1, OperationWaitPolicyV1,
    OperationWaitReducerV1, OperationWaitTerminationV1,
};
use aos_sandbox::controller_query::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedOperationObservationV1, CheckedOperationPhaseV1,
    CheckedOperationResourceV1, CheckedSandboxResourceV1, CheckedSnapshotResourceV1,
    QUERY_BINDING_TRANSPORT_BYTES, QueryBindingV1,
};
use aos_sandbox_core::CapabilityId;
use connectrpc::client::{ClientConfig, SharedHttp2Connection};
use http::Uri;

use crate::cli::sandbox::SandboxArgs;

mod reads;
mod ssh_attach;
mod watch;

pub(super) use reads::dispatch_read;
pub(super) use watch::dispatch_watch;

/// Selects the one execution boundary for every typed sandbox command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicClientRouteV1 {
    /// A command handled locally without a controller connection.
    Local,
    /// Public protocol or node discovery.
    Discovery,
    /// Direct operation lookup over the selected controller endpoint.
    OperationRead,
    /// An authenticated unary public read.
    Read,
    /// An authenticated public mutation.
    Mutation,
    /// An authenticated public watch stream.
    Watch,
}

/// Classifies every typed request without a wildcard fallback.
///
/// Keeping this match exhaustive makes a newly added CLI command fail to
/// compile until its transport boundary is selected deliberately.
#[must_use]
pub(super) const fn route(kind: &DormantSandboxRequestKindV1) -> PublicClientRouteV1 {
    use DormantSandboxRequestKindV1 as R;

    match kind {
        R::Completions(_) => PublicClientRouteV1::Local,
        R::CapabilitiesPublicApi(_) | R::CapabilitiesNode(_) => PublicClientRouteV1::Discovery,
        R::GetOperation(_) => PublicClientRouteV1::OperationRead,
        R::PlanCreate(_)
        | R::GetSandbox(_)
        | R::GetExecution(_)
        | R::GetView(_)
        | R::GetAttachment(_)
        | R::GetSnapshot(_)
        | R::ListSandboxes(_)
        | R::ListExecutions(_)
        | R::ListSnapshots(_)
        | R::Tree(_)
        | R::Children(_)
        | R::Ancestors(_)
        | R::PlanPolicy(_)
        | R::ViewList(_)
        | R::CacheStatus(_)
        | R::CapabilityInspect(_) => PublicClientRouteV1::Read,
        R::Create(_)
        | R::UpdatePolicy(_)
        | R::Start(_)
        | R::Stop(_)
        | R::Suspend(_)
        | R::Resume(_)
        | R::Exec(_)
        | R::ExecutionControl(_)
        | R::CancelExec(_)
        | R::CancelOperation(_)
        | R::Snapshot(_)
        | R::DeleteSnapshot(_)
        | R::Restore(_)
        | R::Fork(_)
        | R::Delete(_)
        | R::ViewCreate(_)
        | R::ViewAttach(_)
        | R::ViewReplace(_)
        | R::ViewDetach(_)
        | R::ViewRelease(_)
        | R::CachePin(_)
        | R::CacheUnpin(_)
        | R::CapabilityAttenuate(_)
        | R::CapabilityRenew(_)
        | R::CapabilityRevoke(_)
        | R::OperatorRecover(_) => PublicClientRouteV1::Mutation,
        R::Events(_) => PublicClientRouteV1::Watch,
    }
}

const OPERATION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
const QUERY_BINDING_HEADER: &str = "aos-query-binding-v1";

struct AuthorizedEndpoint {
    connection: SharedHttp2Connection,
    authority: Uri,
    capability_id: CapabilityId,
}

impl AuthorizedEndpoint {
    async fn connect(
        args: &SandboxArgs,
        expected_capability_id: Option<CapabilityId>,
    ) -> Result<Self> {
        let credentials = args
            .public_credentials
            .as_deref()
            .context("--public-api requires --public-credentials")?;
        let server_name = args
            .public_server_name
            .as_deref()
            .context("--public-api requires --public-server-name")?;
        let (connection, authority, capability_id) =
            super::public_transport::connect_authorized(credentials, server_name).await?;
        if expected_capability_id.is_some_and(|expected| expected != capability_id) {
            anyhow::bail!("public capability identity changed before dispatch");
        }

        Ok(Self {
            connection: connection.shared(8),
            authority,
            capability_id,
        })
    }

    fn config(&self) -> Result<ClientConfig> {
        super::authorized_public_config(self.authority.clone(), self.capability_id)
    }
}

/// Routes one authenticated mutation through its exact generated public client.
///
/// Returns `false` when the request is not a mutation handled by this module.
///
/// # Errors
///
/// Returns an error for authorization rotation, transport or server failure,
/// invalid response resources, contradictory operation progress, bounded-wait
/// expiry, or rendering failure.
pub(super) async fn dispatch_mutation(
    args: &SandboxArgs,
    request: &DormantSandboxRequestV1,
    output: DormantSandboxOutputV1,
    expected_capability_id: Option<CapabilityId>,
) -> Result<bool> {
    if !args.public_api || !is_supported_mutation(request.kind()) {
        return Ok(false);
    }
    let expected_capability_id = expected_capability_id
        .context("authenticated mutation has no protected capability identity")?;
    let endpoint = AuthorizedEndpoint::connect(args, Some(expected_capability_id)).await?;

    match request.kind() {
        DormantSandboxRequestKindV1::Create(message) => {
            let response =
                SandboxServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .create_sandbox(message.clone())
                    .await
                    .context("controller rejected sandbox creation")?
                    .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the created sandbox")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid created sandbox")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "sandbox creation")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::UpdatePolicy(message) => {
            let response =
                SandboxServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .update_policy(message.clone())
                    .await
                    .context("controller rejected sandbox policy update")?
                    .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the updated sandbox")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid updated sandbox")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "sandbox policy update")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::Start(message)
        | DormantSandboxRequestKindV1::Stop(message)
        | DormantSandboxRequestKindV1::Suspend(message)
        | DormantSandboxRequestKindV1::Resume(message) => {
            let client = SandboxServiceClient::new(endpoint.connection.clone(), endpoint.config()?);
            let response = match request.kind() {
                DormantSandboxRequestKindV1::Start(_) => client.start(message.clone()).await,
                DormantSandboxRequestKindV1::Stop(_) => client.stop(message.clone()).await,
                DormantSandboxRequestKindV1::Suspend(_) => client.suspend(message.clone()).await,
                DormantSandboxRequestKindV1::Resume(_) => client.resume(message.clone()).await,
                _ => anyhow::bail!("internal sandbox lifecycle route mismatch"),
            }
            .context("controller rejected sandbox lifecycle request")?
            .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the lifecycle sandbox")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid lifecycle sandbox")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "sandbox lifecycle request")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::Delete(message) => {
            let response =
                SandboxServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .delete_sandbox(message.clone())
                    .await
                    .context("controller rejected sandbox deletion")?
                    .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the deleted sandbox projection")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid deleted sandbox projection")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "sandbox deletion")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::Exec(message) => {
            aos_sandbox::create_holder_proof::verify_create_holder_proof_v1(message)
                .context("execution creation proof does not match the final request")?;
            let response =
                ExecutionServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .create_execution(message.clone())
                    .await
                    .context("controller rejected execution creation")?
                    .into_owned();
            let resource = response
                .execution
                .into_option()
                .context("controller omitted the created execution")?;
            let checked = CheckedExecutionResourceV1::try_from(resource)
                .context("controller returned an invalid created execution")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "execution creation")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::ExecutionControl(message) => {
            let holder_key = if message.action.as_known()
                == Some(aos_proto::aos::sandbox::v1::ExecutionControlAction::EXECUTION_CONTROL_ACTION_ATTACH)
            {
                Some(ssh_attach::load_holder_key(args, message)?)
            } else {
                None
            };
            let response =
                ExecutionServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .control_execution(message.clone())
                    .await
                    .context("controller rejected execution control")?
                    .into_owned();
            let checked = CheckedExecutionControlResultV1::try_from(response)
                .context("controller returned an invalid execution control result")?;
            if let Some(holder_key) = holder_key {
                ssh_attach::attach(&endpoint, message, &checked, &holder_key).await?;
                return Ok(true);
            }
            finish_operation::<CheckedExecutionResourceV1>(
                &endpoint,
                request,
                output,
                required_operation(checked.as_proto().operation.clone(), "execution control")?,
                None,
            )
            .await?;
        }
        DormantSandboxRequestKindV1::CancelExec(message) => {
            let response =
                ExecutionServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .cancel_execution(message.clone())
                    .await
                    .context("controller rejected execution cancellation")?
                    .into_owned();
            finish_operation::<CheckedOperationResourceV1>(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "execution cancellation")?,
                None,
            )
            .await?;
        }
        DormantSandboxRequestKindV1::CancelOperation(message) => {
            let response =
                OperationServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .cancel_operation(message.clone())
                    .await
                    .context("controller rejected operation cancellation")?
                    .into_owned();
            finish_operation::<CheckedOperationResourceV1>(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "operation cancellation")?,
                None,
            )
            .await?;
        }
        DormantSandboxRequestKindV1::Snapshot(message) => {
            let response =
                SnapshotServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .create_snapshot(message.clone())
                    .await
                    .context("controller rejected snapshot creation")?
                    .into_owned();
            let resource = response
                .snapshot
                .into_option()
                .context("controller omitted the created snapshot")?;
            let checked = CheckedSnapshotResourceV1::try_from(resource)
                .context("controller returned an invalid created snapshot")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "snapshot creation")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::DeleteSnapshot(message) => {
            let response =
                SnapshotServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .delete_snapshot(message.clone())
                    .await
                    .context("controller rejected snapshot deletion")?
                    .into_owned();
            let resource = response
                .snapshot
                .into_option()
                .context("controller omitted the deleted snapshot projection")?;
            let checked = CheckedSnapshotResourceV1::try_from(resource)
                .context("controller returned an invalid deleted snapshot projection")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "snapshot deletion")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::Restore(message) => {
            let response =
                SnapshotServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .restore_snapshot(message.clone())
                    .await
                    .context("controller rejected snapshot restore")?
                    .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the restored sandbox")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid restored sandbox")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "snapshot restore")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::Fork(message) => {
            let response =
                SnapshotServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .fork_snapshot(message.clone())
                    .await
                    .context("controller rejected snapshot fork")?
                    .into_owned();
            let resource = response
                .sandbox
                .into_option()
                .context("controller omitted the forked sandbox")?;
            let checked = CheckedSandboxResourceV1::try_from(resource)
                .context("controller returned an invalid forked sandbox")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "snapshot fork")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::ViewCreate(message) => {
            let response =
                FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .create_view(message.clone())
                    .await
                    .context("controller rejected filesystem-view creation")?
                    .into_owned();
            let resource = response
                .view
                .into_option()
                .context("controller omitted the created filesystem view")?;
            let checked = CheckedFilesystemViewResourceV1::try_from(resource)
                .context("controller returned an invalid created filesystem view")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "filesystem-view creation")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::ViewAttach(message) => {
            let response =
                FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .attach_view(message.clone())
                    .await
                    .context("controller rejected filesystem-view attachment")?
                    .into_owned();
            let resource = response
                .attachment
                .into_option()
                .context("controller omitted the created attachment")?;
            let checked = CheckedAttachmentResourceV1::try_from(resource)
                .context("controller returned an invalid created attachment")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "filesystem-view attachment")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::ViewReplace(message) => {
            let response =
                FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .replace_attachment(message.clone())
                    .await
                    .context("controller rejected attachment replacement")?
                    .into_owned();
            let resource = response
                .attachment
                .into_option()
                .context("controller omitted the replaced attachment")?;
            let checked = CheckedAttachmentResourceV1::try_from(resource)
                .context("controller returned an invalid replaced attachment")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "attachment replacement")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::ViewDetach(message) => {
            let response =
                FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .detach_view(message.clone())
                    .await
                    .context("controller rejected attachment detachment")?
                    .into_owned();
            let resource = response
                .attachment
                .into_option()
                .context("controller omitted the detached attachment projection")?;
            let checked = CheckedAttachmentResourceV1::try_from(resource)
                .context("controller returned an invalid detached attachment projection")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "attachment detachment")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::ViewRelease(message) => {
            let response =
                FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .release_view(message.clone())
                    .await
                    .context("controller rejected filesystem-view release")?
                    .into_owned();
            let resource = response
                .view
                .into_option()
                .context("controller omitted the released filesystem-view projection")?;
            let checked = CheckedFilesystemViewResourceV1::try_from(resource)
                .context("controller returned an invalid released filesystem-view projection")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "filesystem-view release")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::CachePin(message) => {
            let response = CacheServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                .pin_object(message.clone())
                .await
                .context("controller rejected cache pin")?
                .into_owned();
            finish_operation::<CheckedOperationResourceV1>(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "cache pin")?,
                None,
            )
            .await?;
        }
        DormantSandboxRequestKindV1::CacheUnpin(message) => {
            let response = CacheServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                .unpin_object(message.clone())
                .await
                .context("controller rejected cache unpin")?
                .into_owned();
            finish_operation::<CheckedOperationResourceV1>(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "cache unpin")?,
                None,
            )
            .await?;
        }
        DormantSandboxRequestKindV1::CapabilityAttenuate(message) => {
            let response =
                CapabilityServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .attenuate(message.clone())
                    .await
                    .context("controller rejected capability attenuation")?
                    .into_owned();
            let resource = response
                .capability
                .into_option()
                .context("controller omitted the attenuated capability")?;
            let checked = CheckedCapabilityResourceV1::try_from(resource)
                .context("controller returned an invalid attenuated capability")?;
            validate_capability_handle(
                &response.capability_handle,
                checked.as_proto().capability_id.as_slice(),
                "attenuated capability",
            )?;
            super::render_checked(output, &checked)?;
        }
        DormantSandboxRequestKindV1::CapabilityRenew(message) => {
            let response =
                CapabilityServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .renew(message.clone())
                    .await
                    .context("controller rejected capability renewal")?
                    .into_owned();
            let resource = response
                .capability
                .into_option()
                .context("controller omitted the renewed capability")?;
            let checked = CheckedCapabilityResourceV1::try_from(resource)
                .context("controller returned an invalid renewed capability")?;
            validate_capability_handle(
                &response.capability_handle,
                checked.as_proto().capability_id.as_slice(),
                "renewed capability",
            )?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "capability renewal")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::CapabilityRevoke(message) => {
            let response =
                CapabilityServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .revoke(message.clone())
                    .await
                    .context("controller rejected capability revocation")?
                    .into_owned();
            let resource = response
                .capability
                .into_option()
                .context("controller omitted the revoked capability projection")?;
            let checked = CheckedCapabilityResourceV1::try_from(resource)
                .context("controller returned an invalid revoked capability projection")?;
            finish_operation(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "capability revocation")?,
                Some(&checked),
            )
            .await?;
        }
        DormantSandboxRequestKindV1::OperatorRecover(message) => {
            let response =
                OperatorServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                    .recover(message.clone())
                    .await
                    .context("controller rejected operator recovery")?
                    .into_owned();
            finish_operation::<CheckedOperationResourceV1>(
                &endpoint,
                request,
                output,
                required_operation(response.operation, "operator recovery")?,
                None,
            )
            .await?;
        }
        _ => return Ok(false),
    }

    Ok(true)
}

fn authenticated_query_binding(headers: &http::HeaderMap) -> Result<QueryBindingV1> {
    let mut values = headers.get_all(QUERY_BINDING_HEADER).iter();
    let value = values
        .next()
        .context("controller omitted authenticated query binding metadata")?;
    if values.next().is_some() {
        anyhow::bail!("controller returned duplicate query binding metadata");
    }
    let encoded = value
        .to_str()
        .context("controller query binding metadata is not valid text")?;
    if encoded.len() != QUERY_BINDING_TRANSPORT_BYTES * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("controller query binding metadata is not canonical");
    }
    let mut bytes = [0_u8; QUERY_BINDING_TRANSPORT_BYTES];
    hex::decode_to_slice(encoded, &mut bytes)
        .context("controller query binding metadata is not valid hexadecimal")?;
    QueryBindingV1::from_transport_bytes(&bytes)
        .context("controller query binding metadata is invalid")
}

fn required_operation<P>(
    operation: buffa::MessageField<Operation, P>,
    action: &'static str,
) -> Result<Operation>
where
    P: buffa::ProtoBox<Operation>,
{
    operation
        .into_option()
        .with_context(|| format!("controller omitted the {action} operation"))
}

async fn finish_operation<T>(
    endpoint: &AuthorizedEndpoint,
    request: &DormantSandboxRequestV1,
    output: DormantSandboxOutputV1,
    operation: Operation,
    completed_resource: Option<&T>,
) -> Result<()>
where
    T: EstablishedProtoJson,
{
    let checked = CheckedOperationObservationV1::try_from(operation)
        .context("controller returned an invalid operation observation")?;
    let Some(timeout_nanos) = request.client_state().wait_timeout_nanos() else {
        return super::render_checked(output, checked.resource());
    };
    let terminal = wait_for_operation(endpoint, checked, timeout_nanos).await?;
    if terminal.phase() != CheckedOperationPhaseV1::Succeeded {
        anyhow::bail!(
            "operation completed unsuccessfully with phase {:?}",
            terminal.phase()
        );
    }
    match completed_resource {
        Some(resource) => super::render_checked(output, resource),
        None => super::render_checked(output, &terminal),
    }
}

async fn wait_for_operation(
    endpoint: &AuthorizedEndpoint,
    initial: CheckedOperationObservationV1,
    timeout_nanos: u64,
) -> Result<CheckedOperationResourceV1> {
    let operation_id = initial.resource().operation_id();
    let policy = OperationWaitPolicyV1::new(timeout_nanos, MAXIMUM_WAIT_OBSERVATIONS)
        .context("invalid operation wait policy")?;
    let mut reducer = OperationWaitReducerV1::new(operation_id, policy)
        .context("invalid operation wait identity")?;
    let started = std::time::Instant::now();
    if let OperationWaitApplyOutcomeV1::Terminal(termination) = reducer
        .apply(initial, 0)
        .context("invalid initial operation observation")?
    {
        return terminal_operation(&reducer, termination);
    }

    loop {
        tokio::time::sleep(OPERATION_POLL_INTERVAL).await;
        let elapsed_nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if let Some(termination) = reducer
            .advance_elapsed(elapsed_nanos)
            .context("operation wait clock advanced inconsistently")?
        {
            return terminal_operation(&reducer, termination);
        }
        let response = OperationServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
            .get_operation(GetOperationRequest {
                operation_id: operation_id.to_vec(),
                ..Default::default()
            })
            .await
            .context("controller rejected operation wait poll")?
            .into_owned();
        let operation = response
            .operation
            .into_option()
            .context("controller omitted the operation wait resource")?;
        let observation = CheckedOperationObservationV1::try_from(operation)
            .context("controller returned an invalid operation wait observation")?;
        if let OperationWaitApplyOutcomeV1::Terminal(termination) = reducer
            .apply(observation, elapsed_nanos)
            .context("controller operation observations contradicted prior state")?
        {
            return terminal_operation(&reducer, termination);
        }
    }
}

fn validate_capability_handle(
    handle: &[u8],
    capability_id: &[u8],
    operation: &'static str,
) -> Result<()> {
    if handle.len() != 16 || handle != capability_id {
        anyhow::bail!("controller returned a substituted {operation} handle");
    }

    Ok(())
}

fn terminal_operation(
    reducer: &OperationWaitReducerV1,
    termination: OperationWaitTerminationV1,
) -> Result<CheckedOperationResourceV1> {
    match termination {
        OperationWaitTerminationV1::OperationTerminal(_) => reducer
            .current()
            .cloned()
            .context("terminal operation wait has no current resource"),
        OperationWaitTerminationV1::DeadlineReached => {
            anyhow::bail!("operation wait deadline reached")
        }
        OperationWaitTerminationV1::ObservationLimitReached => {
            anyhow::bail!("operation wait observation limit reached")
        }
    }
}

const fn is_supported_mutation(kind: &DormantSandboxRequestKindV1) -> bool {
    matches!(route(kind), PublicClientRouteV1::Mutation)
}

const fn is_supported_read(kind: &DormantSandboxRequestKindV1) -> bool {
    matches!(route(kind), PublicClientRouteV1::Read)
}
