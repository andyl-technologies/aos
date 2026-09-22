//! CLI routing for `aos sandbox`.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_proto::aos::sandbox::v1::{DiscoveryServiceClient, OperationServiceClient};
use aos_sandbox::cli_model::{
    CheckedProtoJsonV1, CheckedPublicFeatureRegistryV1, DormantCompletionShellV1,
    DormantPublicApiAuthorizationV1, DormantPublicApiClientV1, DormantPublicApiWireTransportV1,
    DormantSandboxCommandExecutorV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1,
    DormantSandboxRoutingErrorV1, DormantValidatedRequestSinkV1, EstablishedProtoJson,
};
use aos_sandbox::controller_query::CheckedNodeCapabilitiesV1;
use aos_sandbox::controller_query::CheckedOperationObservationV1;
use clap_complete::Shell;
use connectrpc::Protocol;
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};
use http::{HeaderValue, Uri};

use crate::cli::Cli;
use crate::cli::sandbox::SandboxArgs;

mod public_transport;

const NODE_DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_DISCOVERY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";

/// Builds and routes one parsed sandbox request.
///
/// Completion generation stays local. Read-only discovery uses the protected
/// controller socket; request families whose authenticated production
/// transport is not active continue to fail closed.
///
/// # Errors
///
/// Returns an error when semantic validation, controller connection, response
/// validation, rendering, or a deliberately unavailable route fails.
pub async fn run(cli: &Cli, args: &SandboxArgs) -> Result<()> {
    let output = if args.json_lines {
        DormantSandboxOutputV1::JsonLines
    } else if cli.json {
        DormantSandboxOutputV1::Json
    } else {
        DormantSandboxOutputV1::Human
    };
    let request = crate::cli::sandbox::routed_request(args, output)?;
    if let DormantSandboxRequestKindV1::Completions(shell) = request.kind() {
        crate::commands::completions::run(completion_shell(*shell));
        return Ok(());
    }

    match request.kind() {
        DormantSandboxRequestKindV1::CapabilitiesPublicApi(request_message) => {
            let client = discovery_client(args).await?;
            let response = client
                .get_public_feature_registry(request_message.clone())
                .await
                .context("controller rejected public feature discovery")?
                .into_owned();
            let registry = response
                .registry
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("controller omitted the public feature registry"))?;
            let checked = CheckedPublicFeatureRegistryV1::try_from(registry)
                .context("controller returned an invalid public feature registry")?;
            render_checked(output, &checked)?;
            return Ok(());
        }
        DormantSandboxRequestKindV1::CapabilitiesNode(request_message) => {
            let client = discovery_client(args).await?;
            let response = client
                .get_node_capabilities(request_message.clone())
                .await
                .context("controller rejected node capability discovery")?
                .into_owned();
            let capabilities = response
                .capabilities
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("controller omitted node capabilities"))?;
            let checked = CheckedNodeCapabilitiesV1::try_from(capabilities)
                .context("controller returned invalid node capabilities")?;
            render_checked(output, &checked)?;
            return Ok(());
        }
        DormantSandboxRequestKindV1::GetOperation(request_message) => {
            let client = operation_client(args).await?;
            let response = client
                .get_operation(request_message.clone())
                .await
                .context("controller rejected operation lookup")?
                .into_owned();
            let operation = response
                .operation
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("controller omitted the operation resource"))?;
            let checked = CheckedOperationObservationV1::try_from(operation)
                .context("controller returned an invalid operation observation")?
                .into_resource();
            render_checked(output, &checked)?;
            return Ok(());
        }
        _ => {}
    }

    let mut executor = DormantSandboxCommandExecutorV1::new(DormantValidatedRequestSinkV1);
    let _deferred = executor.execute(request)?;
    Err(DormantSandboxRoutingErrorV1::TransportRejected.into())
}

async fn operation_client(
    args: &SandboxArgs,
) -> Result<OperationServiceClient<SharedHttp2Connection>> {
    if args.public_api {
        let credentials = args
            .public_credentials
            .as_deref()
            .context("--public-api requires --public-credentials")?;
        let server_name = args
            .public_server_name
            .as_deref()
            .context("--public-api requires --public-server-name")?;
        let (connection, authority, capability_id) =
            public_transport::connect_authorized(credentials, server_name).await?;
        let config = authorized_operation_config(authority, capability_id)?;
        return Ok(OperationServiceClient::new(connection.shared(8), config));
    }

    let socket = Path::new(NODE_DIAGNOSTIC_SOCKET);
    let authority: Uri = "http://localhost"
        .parse()
        .context("invalid built-in controller authority")?;
    let connection = Http2Connection::connect_unix(socket, authority.clone())
        .await
        .with_context(|| format!("cannot connect to controller socket {}", socket.display()))?
        .shared(8);
    let config = discovery_config(authority);
    Ok(OperationServiceClient::new(connection, config))
}

fn authorized_operation_config(
    authority: Uri,
    capability_id: aos_sandbox_core::CapabilityId,
) -> Result<ClientConfig> {
    let mut headers = http::HeaderMap::new();
    let capability_value = HeaderValue::try_from(capability_id.to_string())
        .context("invalid public capability identity header")?;
    headers.insert(PUBLIC_CAPABILITY_HEADER, capability_value);
    Ok(discovery_config(authority).with_default_headers(headers))
}

async fn discovery_client(
    args: &SandboxArgs,
) -> Result<DiscoveryServiceClient<SharedHttp2Connection>> {
    if args.public_api {
        let credentials = args
            .public_credentials
            .as_deref()
            .context("--public-api requires --public-credentials")?;
        let server_name = args
            .public_server_name
            .as_deref()
            .context("--public-api requires --public-server-name")?;
        let (connection, authority) = public_transport::connect(credentials, server_name).await?;
        let config = discovery_config(authority);
        return Ok(DiscoveryServiceClient::new(connection.shared(8), config));
    }

    let socket = Path::new(NODE_DIAGNOSTIC_SOCKET);
    let authority: Uri = "http://localhost"
        .parse()
        .context("invalid built-in controller authority")?;
    let connection = Http2Connection::connect_unix(socket, authority.clone())
        .await
        .with_context(|| format!("cannot connect to controller socket {}", socket.display()))?
        .shared(8);
    let config = discovery_config(authority);

    Ok(DiscoveryServiceClient::new(connection, config))
}

fn discovery_config(authority: Uri) -> ClientConfig {
    ClientConfig::new(authority)
        .with_protocol(Protocol::Grpc)
        .with_default_timeout(DISCOVERY_TIMEOUT)
        .with_default_max_message_size(MAXIMUM_DISCOVERY_RESPONSE_BYTES)
}

fn render_checked<T>(output: DormantSandboxOutputV1, checked: &T) -> Result<()>
where
    T: EstablishedProtoJson,
{
    let rendered = CheckedProtoJsonV1::render(checked)
        .context("controller response could not be rendered safely")?;
    let output_record = match output {
        DormantSandboxOutputV1::Human => {
            let value: serde_json::Value = serde_json::from_str(rendered.as_str())
                .context("controller response was not valid JSON")?;
            serde_json::to_string_pretty(&value)?
        }
        DormantSandboxOutputV1::Json | DormantSandboxOutputV1::JsonLines => {
            rendered.as_str().to_owned()
        }
    };
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{output_record}").context("could not write sandbox response")?;
    Ok(())
}

const fn completion_shell(shell: DormantCompletionShellV1) -> Shell {
    match shell {
        DormantCompletionShellV1::Bash => Shell::Bash,
        DormantCompletionShellV1::Fish => Shell::Fish,
        DormantCompletionShellV1::Zsh => Shell::Zsh,
    }
}

/// Executes parsed CLI input through an explicitly supplied public API transport.
///
/// This source-only composition is not selected by [`run`]. The caller must
/// obtain authorization from an authenticated client session and choose the
/// endpoint transport explicitly.
///
/// # Errors
///
/// Returns an error when parsing, semantic validation, authorization handoff,
/// exact route selection, or the supplied transport fails.
pub fn run_with_public_api_transport<T>(
    cli: &Cli,
    args: &SandboxArgs,
    authorization: DormantPublicApiAuthorizationV1,
    transport: T,
) -> Result<T::Output>
where
    T: DormantPublicApiWireTransportV1,
{
    let output = if args.json_lines {
        DormantSandboxOutputV1::JsonLines
    } else if cli.json {
        DormantSandboxOutputV1::Json
    } else {
        DormantSandboxOutputV1::Human
    };
    let request =
        crate::cli::sandbox::routed_request_with_authorization(args, output, authorization)?;
    let client = DormantPublicApiClientV1::new(transport);
    let mut executor = DormantSandboxCommandExecutorV1::new(client);
    Ok(executor.execute(request)?)
}
