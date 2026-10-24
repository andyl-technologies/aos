//! Transports original live condition control without creating native authority.

use super::{CliError, bounded_file, node_error};
use clap::Subcommand;
use crucible_daemon::{
    node_control::{NodeControlRequest, decode_debug_record, request_node_control},
    node_observed_executor::{NodeDebugResumeRequest, NodeDebugStartRequest},
};
use std::path::PathBuf;

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeDebugCommand {
    /// Queue an original installed condition stop with a finite physical budget.
    #[command(name = "debug-start")]
    Start {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the complete closed live Debug request JSON.
        #[arg(long)]
        request: PathBuf,
    },
    /// Read retained original stop, report or resume status without native effects.
    #[command(name = "debug-status")]
    Status {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve the original lowercase execution nonce.
        #[arg(long)]
        execution: String,
    },
    /// Queue the once-only original resume of a currently owned live stop.
    #[command(name = "debug-resume")]
    Resume {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the exact closed original resume request JSON.
        #[arg(long)]
        request: PathBuf,
    },
}

pub(super) fn run(command: &NodeDebugCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeDebugCommand::Start { socket, request } => {
            let request = NodeDebugStartRequest::from_json(&bounded_file(request, 1024 * 1024)?)
                .map_err(node_error)?;
            (
                socket,
                NodeControlRequest::debug_start("operator/debug-start", request)
                    .map_err(node_error)?,
            )
        }
        NodeDebugCommand::Status { socket, execution } => (
            socket,
            NodeControlRequest::debug_status("operator/debug-status", execution.clone())
                .map_err(node_error)?,
        ),
        NodeDebugCommand::Resume { socket, request } => {
            let bytes = bounded_file(request, 4096)?;
            let request = NodeDebugResumeRequest::from_json(&bytes).map_err(node_error)?;
            (
                socket,
                NodeControlRequest::debug_resume("operator/debug-resume", request)
                    .map_err(node_error)?,
            )
        }
    };
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let record = decode_debug_record(&reply).map_err(node_error)?;
    println!("{}", serde_json::to_string(&record).map_err(node_error)?);
    Ok(())
}
