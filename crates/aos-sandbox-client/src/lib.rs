//! Registered sandbox public clients with protected local credential custody.
//!
//! This crate owns the canonical TLS 1.3/HTTP2 transport, fixed diagnostic and
//! public sockets, generated-client dispatch, checked response reducers,
//! bounded pagination/watch/wait state, and holder-bound OpenSSH attachment.
//! It accepts untrusted Protocol requests and plain client options; it does not
//! adopt Controller provenance or grant server-side effect authority.
//!
//! The private `public_transport` module protects credentials and keys. The
//! private `public_client` family dispatches exact RPC methods and retains
//! checked response state. CLI parsing and local completion generation remain
//! outside this crate.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_proto::aos::sandbox::v1::{
    CapabilityServiceClient, DiscoveryServiceClient, OperationServiceClient,
};
use aos_sandbox_core::CapabilityId;
use aos_sandbox_protocol::public_api::proto_json::{
    CheckedProtoJsonV1, CheckedPublicFeatureRegistryV1, EstablishedProtoJson,
};
use aos_sandbox_protocol::public_api::request::{
    DormantPublicApiRequestV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1,
};
use aos_sandbox_protocol::public_api::{CheckedNodeCapabilitiesV1, CheckedOperationObservationV1};
use connectrpc::Protocol;
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};
use http::{HeaderValue, Uri};

mod public_client;
mod public_transport;

pub use public_transport::load_capability_id;

/// Carries non-authorizing endpoint options independently of CLI parsing.
///
/// Optional values remain raw so each operation retains its established
/// missing-option and credential-validation order.
#[derive(Clone, Debug, Default)]
pub struct PublicClientOptionsV1 {
    /// Selects the registered mutual-TLS public endpoint instead of root diagnostics.
    pub public_api: bool,
    /// Names the protected client credential directory.
    pub public_credentials: Option<PathBuf>,
    /// Names the TLS server identity checked on the fixed public socket.
    pub public_server_name: Option<String>,
    /// Selects a named protected capability instead of the active pair.
    pub capability_name: Option<String>,
    /// Names the explicit protected destination for an issued successor capability.
    pub successor_capability_name: Option<String>,
}

/// Preserves the OpenSSH data-plane exit status at the CLI process boundary.
#[derive(Debug)]
pub struct ClientAttachExitStatusV1(i32);

impl std::fmt::Display for ClientAttachExitStatusV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "execution attachment exited with status {}",
            self.0
        )
    }
}

impl std::error::Error for ClientAttachExitStatusV1 {}

impl ClientAttachExitStatusV1 {
    /// Returns the exact OpenSSH process status retained at the CLI boundary.
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.0
    }
}

const NODE_DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_DISCOVERY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";
const PUBLIC_CAPABILITY_HANDLE_HEADER: &str = "aos-capability-handle";

/// Identifies parsed reads whose public dispatch loads a protected capability.
///
/// Mutation proposals without client context retain their earlier constructor
/// rejection; this predicate only classifies already parsed read requests.
#[must_use]
pub const fn requires_public_read_context(kind: &DormantSandboxRequestKindV1) -> bool {
    matches!(
        public_client::route(kind),
        public_client::PublicClientRouteV1::OperationRead
            | public_client::PublicClientRouteV1::Read
            | public_client::PublicClientRouteV1::Watch
    )
}

/// Dispatches one checked, untrusted public proposal through its existing client.
///
/// Returns `false` for local completions or nonpublic routes handled by the
/// caller's dormant sink. No endpoint, capability, or adopted Controller
/// authority can be selected through the request DATA itself.
///
/// # Errors
///
/// Returns the established error for missing options, unsafe credentials,
/// capability rotation, transport or server failure, invalid checked responses,
/// bounded-state failure, rendering failure, or a nonzero OpenSSH status.
pub async fn dispatch(
    args: &PublicClientOptionsV1,
    request: &DormantPublicApiRequestV1,
    output: DormantSandboxOutputV1,
    expected_capability_id: Option<CapabilityId>,
) -> Result<bool> {
    use public_client::PublicClientRouteV1 as Route;

    match (public_client::route(request.kind()), request.kind()) {
        (Route::Local, _) => Ok(false),
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
            Ok(true)
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
            Ok(true)
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
            Ok(true)
        }
        (Route::Read, _) if args.public_api => require_dispatched(
            public_client::dispatch_read(args, request, output, expected_capability_id).await?,
        ),
        (Route::Mutation, _) if args.public_api => require_dispatched(
            public_client::dispatch_mutation(args, request, output, expected_capability_id).await?,
        ),
        (Route::Watch, _) if args.public_api => require_dispatched(
            public_client::dispatch_watch(args, request, output, expected_capability_id).await?,
        ),
        (Route::Read | Route::Mutation | Route::Watch, _) => Ok(false),
        _ => Err(anyhow::anyhow!(
            "sandbox command route classification is inconsistent"
        )),
    }
}

/// Bootstraps and durably saves a capability using the registered TLS holder.
///
/// Bootstrap sends no capability headers and does not allow a named capability
/// selector. The server alone selects the resulting grants.
///
/// # Errors
///
/// Returns the established error for missing public options, a capability
/// selector, unsafe credentials, transport/server failure, an invalid returned
/// capability pair, durable publication failure, or output failure.
pub async fn bootstrap_public_capability(
    args: &PublicClientOptionsV1,
    request: aos_proto::aos::sandbox::v1::BootstrapCapabilityRequest,
    save_capability_as: &str,
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
        .bootstrap(request)
        .await
        .context("controller rejected capability bootstrap")?
        .into_owned();
    public_transport::save_named_capability(
        credentials,
        save_capability_as,
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
        DormantSandboxOutputV1::Human => {
            format!("Capability {capability_id} saved as {}", save_capability_as)
        }
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

fn require_dispatched(dispatched: bool) -> Result<bool> {
    if dispatched {
        Ok(true)
    } else {
        Err(anyhow::anyhow!(
            "sandbox public command route classification is inconsistent"
        ))
    }
}

async fn operation_client(
    args: &PublicClientOptionsV1,
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
fn authorized_public_config(
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
fn authorized_public_stream_config(
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
    args: &PublicClientOptionsV1,
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

/// Checks the existing protected capability-name grammar.
///
/// # Errors
///
/// Rejects empty, reserved, overlong, or non-ASCII-safe names.
pub fn capability_name(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || matches!(value, "id" | "handle")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("capability name must contain 1..=64 ASCII letters, digits, '-' or '_'".into());
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
