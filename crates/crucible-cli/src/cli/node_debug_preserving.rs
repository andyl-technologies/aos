//! Transports source-bound capture and fresh preserving custody without native authority.

use super::{CliError, bounded_file, node_error};
use clap::Subcommand;
use crucible_daemon::{
    node_control::{NodeControlRequest, decode_preserving_debug_record, request_node_control},
    node_observed_executor::{NodePreservingDebugRequest, NodePreservingDebugResumeRequest},
};
use std::path::PathBuf;

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodePreservingDebugCommand {
    /// Queue source capture or fresh restore with a complete original preserving recipe.
    #[command(name = "debug-preserving-prepare")]
    Prepare {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the complete closed preserving Debug request JSON.
        #[arg(long)]
        request: PathBuf,
    },
    /// Read retained original stop, report or resume status without native effects.
    #[command(name = "debug-preserving-status")]
    Status {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve the original lowercase execution nonce.
        #[arg(long)]
        execution: String,
    },
    /// Queue the once-only original resume of a currently owned stopped owner.
    #[command(name = "debug-preserving-resume")]
    Resume {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the exact closed original resume request JSON.
        #[arg(long)]
        request: PathBuf,
    },
}

pub(super) fn run(command: &NodePreservingDebugCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodePreservingDebugCommand::Prepare { socket, request } => {
            let request =
                NodePreservingDebugRequest::from_json(&bounded_file(request, 2 * 1024 * 1024)?)
                    .map_err(node_error)?;
            (
                socket,
                NodeControlRequest::preserving_debug_prepare(
                    "operator/debug-preserving-prepare",
                    request,
                )
                .map_err(node_error)?,
            )
        }
        NodePreservingDebugCommand::Status { socket, execution } => (
            socket,
            NodeControlRequest::preserving_debug_status(
                "operator/debug-preserving-status",
                execution.clone(),
            )
            .map_err(node_error)?,
        ),
        NodePreservingDebugCommand::Resume { socket, request } => {
            let bytes = bounded_file(request, 4096)?;
            let request =
                NodePreservingDebugResumeRequest::from_json(&bytes).map_err(node_error)?;
            (
                socket,
                NodeControlRequest::preserving_debug_resume(
                    "operator/debug-preserving-resume",
                    request,
                )
                .map_err(node_error)?,
            )
        }
    };
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let record = decode_preserving_debug_record(&reply).map_err(node_error)?;
    println!("{}", serde_json::to_string(&record).map_err(node_error)?);
    Ok(())
}
