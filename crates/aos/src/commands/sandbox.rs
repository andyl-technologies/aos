//! CLI parsing handoff and local routing for `aos sandbox`.

use anyhow::{Context as _, Result};
use aos_sandbox_protocol::public_api::request::{
    DormantCompletionShellV1, DormantPublicApiAuthorizationV1, DormantPublicApiClientV1,
    DormantPublicApiWireTransportV1, DormantSandboxCommandExecutorV1, DormantSandboxOutputV1,
    DormantSandboxRequestKindV1, DormantSandboxRoutingErrorV1, DormantValidatedRequestSinkV1,
};
use clap_complete::Shell;

use crate::cli::Cli;
use crate::cli::sandbox::{CapabilitySubcommand, SandboxArgs, SandboxSubcommand};

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
    let options = aos_sandbox_client::PublicClientOptionsV1 {
        public_api: args.public_api,
        public_credentials: args.public_credentials.clone(),
        public_server_name: args.public_server_name.clone(),
        capability_name: args.capability_name.clone(),
        successor_capability_name: args.command.successor_capability_name().map(str::to_owned),
    };
    if let SandboxSubcommand::Capability {
        command: CapabilitySubcommand::Bootstrap(bootstrap),
    } = &args.command
    {
        return aos_sandbox_client::bootstrap_public_capability(
            &options,
            bootstrap.request(),
            bootstrap.save_capability_as(),
            output,
        )
        .await;
    }
    let parsed = crate::cli::sandbox::routed_request(args, output);
    let needs_public_authorization = match &parsed {
        Ok(request) => {
            args.public_api && aos_sandbox_client::requires_public_read_context(request.kind())
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
            aos_sandbox_client::load_capability_id(credentials, args.capability_name.as_deref())?;
        let authorization =
            DormantPublicApiAuthorizationV1::new(capability_id.to_string().into_bytes())
                .context("invalid public capability authorization context")?;
        let request =
            crate::cli::sandbox::routed_request_with_authorization(args, output, authorization)?;
        (request, Some(capability_id))
    } else {
        (parsed?, None)
    };

    if let DormantSandboxRequestKindV1::Completions(shell) = request.kind() {
        crate::commands::completions::run(completion_shell(*shell));
        return Ok(());
    }

    if aos_sandbox_client::dispatch(&options, &request, output, expected_capability_id).await? {
        return Ok(());
    }

    let mut executor = DormantSandboxCommandExecutorV1::new(DormantValidatedRequestSinkV1);
    let _deferred = executor.execute(request)?;
    Err(DormantSandboxRoutingErrorV1::TransportRejected.into())
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
