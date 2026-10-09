//! Transports original capability demands without resolving installed authority.

use super::{CliError, bounded_file, node_error};
use clap::Subcommand;
use crucible_daemon::{
    node_control::{NodeControlRequest, decode_capability_preparation, request_node_control},
    node_observed_executor::CapabilityPreparationRequest,
};
use std::path::PathBuf;

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeCapabilityCommand {
    /// Queue raw mandatory capabilities and complete candidate choices for installed admission.
    Capability {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the closed original request JSON, including raw requirement bytes.
        #[arg(long)]
        request: PathBuf,
    },
    /// Read original capability admission without waiting for native preparation.
    CapabilityStatus {
        /// Connect to the installed private same-UID daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve the original 32-digit lowercase execution nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run(command: &NodeCapabilityCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeCapabilityCommand::Capability { socket, request } => {
            let request =
                CapabilityPreparationRequest::from_json(&bounded_file(request, 4 * 1024 * 1024)?)
                    .map_err(node_error)?;
            (
                socket,
                NodeControlRequest::capability_preparation("operator/capability", request)
                    .map_err(node_error)?,
            )
        }
        NodeCapabilityCommand::CapabilityStatus { socket, execution } => (
            socket,
            NodeControlRequest::capability_preparation_status(
                "operator/capability-status",
                execution.clone(),
            )
            .map_err(node_error)?,
        ),
    };

    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let record = decode_capability_preparation(&reply).map_err(node_error)?;
    println!("{}", serde_json::to_string(&record).map_err(node_error)?);
    Ok(())
}
