//! Thin local exact-state commands with no native capture or restore authority.

use std::path::PathBuf;

use clap::Subcommand;
use crucible_daemon::node_control::{
    NodeControlRequest, NodeControlResult, NodeHostStateOutcome, NodeHostStateRecord,
    NodeHostStateRequest, decode_node_selections, request_node_control,
};

use super::{CliError, bounded_file, node_error};

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeHostStateCommand {
    /// Capture the complete qualified host world at an exact coherent cut.
    Capture {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve an independent state-operation nonce, 32 lowercase hex digits.
        #[arg(long)]
        execution: String,
        /// Read the closed complete installed host-model selection JSON array.
        #[arg(long)]
        selections: PathBuf,
        /// Read the canonical scenario compiled by this daemon edition.
        #[arg(long)]
        scenario: PathBuf,
        /// Advance all selected models to this physical time in picoseconds.
        #[arg(long)]
        horizon_ps: u64,
    },
    /// Restore an authenticated whole host world and capture its continued cut.
    Restore {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve a new independent state-operation nonce, 32 lowercase hex digits.
        #[arg(long)]
        execution: String,
        /// Read the original complete installed host-model selection JSON array.
        #[arg(long)]
        selections: PathBuf,
        /// Read the exact original canonical scenario.
        #[arg(long)]
        scenario: PathBuf,
        /// Read a completed state-status JSON record from this private host realm.
        #[arg(long)]
        source: PathBuf,
        /// Select the final time at or after the unchanged source cut, in picoseconds.
        #[arg(long)]
        horizon_ps: u64,
    },
    /// Read the original exact-state reservation or result without native dispatch.
    StateStatus {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Select the original independent state-operation nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run(command: &NodeHostStateCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeHostStateCommand::Capture {
            socket,
            execution,
            selections,
            scenario,
            horizon_ps,
        } => {
            let selected = decode_node_selections(&bounded_file(selections, 64 * 1024)?)
                .map_err(node_error)?;
            let request = NodeHostStateRequest::capture(
                execution.clone(),
                selected,
                bounded_file(scenario, 8 * 1024 * 1024)?,
                *horizon_ps,
            )
            .map_err(node_error)?;
            (socket, request)
        }
        NodeHostStateCommand::Restore {
            socket,
            execution,
            selections,
            scenario,
            source,
            horizon_ps,
        } => {
            let original = NodeHostStateRecord::from_json(&bounded_file(source, 8 * 1024 * 1024)?)
                .map_err(node_error)?;
            let NodeHostStateOutcome::Completed { artifact, .. } = original.state else {
                return Err(node_error(
                    "restore requires a completed original state-status record",
                ));
            };
            let selected = decode_node_selections(&bounded_file(selections, 64 * 1024)?)
                .map_err(node_error)?;
            let request = NodeHostStateRequest::restore(
                execution.clone(),
                selected,
                bounded_file(scenario, 8 * 1024 * 1024)?,
                artifact,
                *horizon_ps,
            )
            .map_err(node_error)?;
            (socket, request)
        }
        NodeHostStateCommand::StateStatus { socket, execution } => (
            socket,
            NodeHostStateRequest::status(execution.clone()).map_err(node_error)?,
        ),
    };
    let request =
        NodeControlRequest::host_state("operator/host-state", request).map_err(node_error)?;
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let NodeControlResult::HostState { record } = reply.result else {
        return Err(node_error(
            "daemon refused exact-state operation or returned another result",
        ));
    };
    let encoded =
        serde_json::to_string(record.as_ref()).map_err(|error| node_error(error.to_string()))?;
    println!("{encoded}");
    Ok(())
}
