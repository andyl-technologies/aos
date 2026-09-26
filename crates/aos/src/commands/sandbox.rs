//! CLI routing for `aos sandbox`.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_proto::aos::sandbox::v1::{
    CapabilityServiceClient, DiscoveryServiceClient, OperationServiceClient,
};
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
use crate::cli::sandbox::{BootstrapArgs, CapabilitySubcommand, SandboxArgs, SandboxSubcommand};

mod public_client;
mod public_transport;

/// Preserves the OpenSSH data-plane exit status at the CLI process boundary.
#[derive(Debug)]
pub(crate) struct SandboxAttachExitCode(pub i32);

impl std::fmt::Display for SandboxAttachExitCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "execution attachment exited with status {}",
            self.0
        )
    }
}

impl std::error::Error for SandboxAttachExitCode {}

const NODE_DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_DISCOVERY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";
const PUBLIC_CAPABILITY_HANDLE_HEADER: &str = "aos-capability-handle";

/// Builds and routes one parsed sandbox request.
///
/// Completion generation stays local. Root diagnostics expose only discovery
/// and operation lookup; other read-only commands use generated clients over
/// the registered mutual-TLS public endpoint. Effect routes whose production
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
    if let SandboxSubcommand::Capability {
        command: CapabilitySubcommand::Bootstrap(bootstrap),
    } = &args.command
    {
        return bootstrap_public_capability(args, bootstrap, output).await;
    }
    use public_client::PublicClientRouteV1 as Route;

    let parsed = crate::cli::sandbox::routed_request(args, output);
    let needs_public_authorization = match &parsed {
        Ok(request) => {
            args.public_api
                && matches!(
                    public_client::route(request.kind()),
                    Route::OperationRead | Route::Read | Route::Watch
                )
        }
        Err(error) => {
            args.public_api
                && matches!(
                    error.downcast_ref::<DormantSandboxRoutingErrorV1>(),
                    Some(DormantSandboxRoutingErrorV1::AuthorizationRequired)
                )
        }
    };
    let (request, expected_capability_id) = if needs_public_authorization {
        let credentials = args
            .public_credentials
            .as_deref()
            .context("--public-api requires --public-credentials")?;
        let capability_id =
            public_transport::load_capability_id(credentials, args.capability_name.as_deref())?;
        let authorization =
            DormantPublicApiAuthorizationV1::new(capability_id.to_string().into_bytes())
                .context("invalid public capability authorization context")?;
        let request =
            crate::cli::sandbox::routed_request_with_authorization(args, output, authorization)?;
        (request, Some(capability_id))
    } else {
        (parsed?, None)
    };

    match (public_client::route(request.kind()), request.kind()) {
        (Route::Local, DormantSandboxRequestKindV1::Completions(shell)) => {
            crate::commands::completions::run(completion_shell(*shell));
            Ok(())
        }
        (Route::Discovery, DormantSandboxRequestKindV1::CapabilitiesPublicApi(request_message)) => {
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
            Ok(())
        }
        (Route::Discovery, DormantSandboxRequestKindV1::CapabilitiesNode(request_message)) => {
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
            Ok(())
        }
        (Route::OperationRead, DormantSandboxRequestKindV1::GetOperation(request_message)) => {
            let client = operation_client(args, expected_capability_id).await?;
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
            Ok(())
        }
        (Route::Read, _) if args.public_api => require_dispatched(
            public_client::dispatch_read(args, &request, output, expected_capability_id).await?,
        ),
        (Route::Mutation, _) if args.public_api => require_dispatched(
            public_client::dispatch_mutation(args, &request, output, expected_capability_id)
                .await?,
        ),
        (Route::Watch, _) if args.public_api => require_dispatched(
            public_client::dispatch_watch(args, &request, output, expected_capability_id).await?,
        ),
        (Route::Read | Route::Mutation | Route::Watch, _) => {
            let mut executor = DormantSandboxCommandExecutorV1::new(DormantValidatedRequestSinkV1);
            let _deferred = executor.execute(request)?;
            Err(DormantSandboxRoutingErrorV1::TransportRejected.into())
        }
        _ => Err(anyhow::anyhow!(
            "sandbox command route classification is inconsistent"
        )),
    }
}

async fn bootstrap_public_capability(
    args: &SandboxArgs,
    bootstrap: &BootstrapArgs,
    output: DormantSandboxOutputV1,
) -> Result<()> {
    if !args.public_api {
        anyhow::bail!("capability bootstrap requires --public-api");
    }
    if args.capability_name.is_some() {
        anyhow::bail!("capability bootstrap cannot use --capability-name");
    }
    let credentials = args
        .public_credentials
        .as_deref()
        .context("capability bootstrap requires --public-credentials")?;
    let server_name = args
        .public_server_name
        .as_deref()
        .context("capability bootstrap requires --public-server-name")?;

    // Bootstrap authenticates with the registered TLS certificate before a
    // holder capability exists, so this connection has no capability headers.
    let (connection, authority) = public_transport::connect(credentials, server_name).await?;
    let client =
        CapabilityServiceClient::new(connection.shared(8), bootstrap_public_config(authority));
    let response = client
        .bootstrap(bootstrap.request())
        .await
        .context("controller rejected capability bootstrap")?
        .into_owned();
    public_transport::save_named_capability(
        credentials,
        bootstrap.save_capability_as(),
        &response.capability_id,
        &response.capability_handle,
    )?;

    let capability_bytes: [u8; 16] = response
        .capability_id
        .as_slice()
        .try_into()
        .context("controller returned an invalid bootstrap capability identity")?;
    let capability_id = aos_sandbox_core::CapabilityId::from_bytes(capability_bytes);
    let rendered = match output {
        DormantSandboxOutputV1::Human => format!(
            "Capability {capability_id} saved as {}",
            bootstrap.save_capability_as()
        ),
        DormantSandboxOutputV1::Json | DormantSandboxOutputV1::JsonLines => {
            use base64::Engine as _;
            serde_json::json!({
                "capabilityId": base64::engine::general_purpose::STANDARD.encode(capability_bytes)
            })
            .to_string()
        }
    };
    writeln!(std::io::stdout().lock(), "{rendered}")
        .context("could not write capability bootstrap result")
}

fn bootstrap_public_config(authority: Uri) -> ClientConfig {
    discovery_config(authority)
}

fn require_dispatched(dispatched: bool) -> Result<()> {
    if dispatched {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "sandbox public command route classification is inconsistent"
        ))
    }
}

async fn operation_client(
    args: &SandboxArgs,
    expected_capability_id: Option<aos_sandbox_core::CapabilityId>,
) -> Result<OperationServiceClient<SharedHttp2Connection>> {
    if args.public_api {
        let expected_capability_id = expected_capability_id
            .context("authenticated operation read has no protected capability identity")?;
        let credentials = args
            .public_credentials
            .as_deref()
            .context("--public-api requires --public-credentials")?;
        let server_name = args
            .public_server_name
            .as_deref()
            .context("--public-api requires --public-server-name")?;
        let (connection, authority, capability_id, capability_handle) =
            public_transport::connect_authorized(
                credentials,
                server_name,
                args.capability_name.as_deref(),
            )
            .await?;
        if expected_capability_id != capability_id {
            anyhow::bail!("public capability identity changed before dispatch");
        }
        let config = authorized_public_config(authority, capability_id, capability_handle)?;
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

/// Builds authenticated unary public calls with the bounded request deadline.
///
/// # Errors
///
/// Rejects a capability identity or handle that cannot be encoded as headers.
pub(super) fn authorized_public_config(
    authority: Uri,
    capability_id: aos_sandbox_core::CapabilityId,
    capability_handle: [u8; 32],
) -> Result<ClientConfig> {
    Ok(
        authorized_public_stream_config(authority, capability_id, capability_handle)?
            .with_default_timeout(DISCOVERY_TIMEOUT),
    )
}

/// Builds authenticated public headers without a whole-call stream deadline.
///
/// # Errors
///
/// Rejects a capability identity or handle that cannot be encoded as headers.
pub(super) fn authorized_public_stream_config(
    authority: Uri,
    capability_id: aos_sandbox_core::CapabilityId,
    capability_handle: [u8; 32],
) -> Result<ClientConfig> {
    let mut headers = http::HeaderMap::new();
    let capability_value = HeaderValue::try_from(capability_id.to_string())
        .context("invalid public capability identity header")?;
    headers.insert(PUBLIC_CAPABILITY_HEADER, capability_value);
    let handle_value = HeaderValue::try_from(hex::encode(capability_handle))
        .context("invalid public capability handle header")?;
    headers.insert(PUBLIC_CAPABILITY_HANDLE_HEADER, handle_value);
    // A watch is a long-lived RPC. A whole-call discovery deadline would
    // terminate a healthy stream even when its events remain current.
    Ok(ClientConfig::new(authority)
        .with_protocol(Protocol::Grpc)
        .with_default_max_message_size(MAXIMUM_DISCOVERY_RESPONSE_BYTES)
        .with_default_headers(headers))
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn public_watch_has_no_whole_call_discovery_deadline() {
        let authority: Uri = "https://sandbox-controller.example".parse().unwrap();
        let capability_id = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();
        let handle = [0x5a; 32];

        let unary = authorized_public_config(authority.clone(), capability_id, handle).unwrap();
        let stream = authorized_public_stream_config(authority, capability_id, handle).unwrap();

        assert_eq!(unary.default_timeout(), Some(DISCOVERY_TIMEOUT));
        assert_eq!(stream.default_timeout(), None);
    }

    #[test]
    fn bootstrap_client_config_has_no_capability_headers() {
        let authority: Uri = "https://sandbox-controller.example".parse().unwrap();
        let config = bootstrap_public_config(authority);

        assert!(
            !config
                .default_headers()
                .contains_key(PUBLIC_CAPABILITY_HEADER)
        );
        assert!(
            !config
                .default_headers()
                .contains_key(PUBLIC_CAPABILITY_HANDLE_HEADER)
        );
    }

    #[tokio::test]
    async fn capability_bootstrap_never_falls_back_to_dormant_or_unauthenticated_routes() {
        let cli = Cli::try_parse_from([
            "aos",
            "sandbox",
            "capability",
            "bootstrap",
            "--idempotency-key",
            "00112233445566778899aabbccddeeff",
            "--save-capability-as",
            "initial",
        ])
        .unwrap();
        let crate::cli::Commands::Sandbox(args) = &cli.command else {
            panic!("sandbox command was not preserved");
        };

        assert!(crate::cli::sandbox::routed_request(args, DormantSandboxOutputV1::Human).is_err());
        assert!(
            run(&cli, args)
                .await
                .unwrap_err()
                .to_string()
                .contains("requires --public-api")
        );
    }

    #[tokio::test]
    async fn bootstrap_rejects_a_capability_selector_before_loading_credentials() {
        let cli = Cli::try_parse_from([
            "aos",
            "sandbox",
            "--public-api",
            "--public-server-name",
            "sandbox-controller.example",
            "--public-credentials",
            "/nonexistent/sandbox-client",
            "--capability-name",
            "existing",
            "capability",
            "bootstrap",
            "--idempotency-key",
            "00112233445566778899aabbccddeeff",
            "--save-capability-as",
            "initial",
        ])
        .unwrap();
        let crate::cli::Commands::Sandbox(args) = &cli.command else {
            panic!("sandbox command was not preserved");
        };

        assert!(
            run(&cli, args)
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot use --capability-name")
        );
    }
}
