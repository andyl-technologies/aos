//! Source-real dormant routing for `aos sandbox`.

use anyhow::Result;
use aos_sandbox::cli_model::{
    DormantPublicApiAuthorizationV1, DormantPublicApiClientV1, DormantPublicApiWireTransportV1,
    DormantSandboxCommandExecutorV1, DormantSandboxOutputV1, DormantSandboxRoutingErrorV1,
    DormantValidatedRequestSinkV1,
};

use crate::cli::Cli;
use crate::cli::sandbox::SandboxArgs;

/// Builds and routes one parsed sandbox request without activating a service.
///
/// # Errors
///
/// Returns an error when semantic validation rejects the parsed request or the
/// explicitly injected dormant request executor rejects it.
pub fn run(cli: &Cli, args: &SandboxArgs) -> Result<()> {
    let output = if args.json_lines {
        DormantSandboxOutputV1::JsonLines
    } else if cli.json {
        DormantSandboxOutputV1::Json
    } else {
        DormantSandboxOutputV1::Human
    };
    let request = crate::cli::sandbox::routed_request(args, output)?;
    let mut executor = DormantSandboxCommandExecutorV1::new(DormantValidatedRequestSinkV1);
    let _deferred = executor.execute(request)?;
    Err(DormantSandboxRoutingErrorV1::TransportRejected.into())
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
