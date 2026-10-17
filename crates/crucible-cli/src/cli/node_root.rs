//! Transports original root demands without resolving installed authority.

use super::{CliError, bounded_file, node_error};
use clap::Subcommand;
use crucible_daemon::{
    node_control::{
        NodeControlRequest, decode_root_diagnostic, decode_root_preparation, request_node_control,
    },
    node_observed_executor::RootPreparationRequest,
};
use std::path::PathBuf;

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeRootCommand {
    /// Read retained original phase and refusal diagnostics without waiting for native work.
    RootDiagnostic {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve the original 32-digit lowercase execution nonce.
        #[arg(long)]
        execution: String,
    },
    /// Queue the source-qualified fixed Root recipe under original durable custody.
    Root {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the closed original request JSON, including original scenario bytes.
        #[arg(long)]
        request: PathBuf,
    },
    /// Read original root admission without waiting for native preparation.
    RootStatus {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve the original 32-digit lowercase execution nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run(command: &NodeRootCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeRootCommand::Root { socket, request } => {
            let request =
                RootPreparationRequest::from_json(&bounded_file(request, 4 * 1024 * 1024)?)
                    .map_err(node_error)?;
            (
                socket,
                NodeControlRequest::root_preparation("operator/root", request)
                    .map_err(node_error)?,
            )
        }
        NodeRootCommand::RootDiagnostic { socket, execution } => (
            socket,
            NodeControlRequest::root_diagnostic("operator/root-diagnostic", execution.clone())
                .map_err(node_error)?,
        ),
        NodeRootCommand::RootStatus { socket, execution } => (
            socket,
            NodeControlRequest::root_preparation_status("operator/root-status", execution.clone())
                .map_err(node_error)?,
        ),
    };

    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let body = if matches!(command, NodeRootCommand::RootDiagnostic { .. }) {
        serde_json::to_string(&decode_root_diagnostic(&reply).map_err(node_error)?)
    } else {
        serde_json::to_string(&decode_root_preparation(&reply).map_err(node_error)?)
    }
    .map_err(node_error)?;
    println!("{body}");
    Ok(())
}
