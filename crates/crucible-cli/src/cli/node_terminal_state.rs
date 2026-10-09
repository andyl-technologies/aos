//! Explicit terminal capture commands without host-side EOF or capture authority.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use crucible_daemon::node_control::{
    NodeControlRequest, NodeControlResult, NodeHostStateOutcome, NodeHostStateRecord,
    NodeTerminalStage, NodeTerminalStateRequest, decode_node_selections, request_node_control,
};

use super::{CliError, bounded_file, node_error};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum TerminalStage {
    Completed,
    Published,
    Acknowledged,
}

impl From<TerminalStage> for NodeTerminalStage {
    fn from(stage: TerminalStage) -> Self {
        match stage {
            TerminalStage::Completed => Self::Completed,
            TerminalStage::Published => Self::Published,
            TerminalStage::Acknowledged => Self::Acknowledged,
        }
    }
}

#[derive(Subcommand, Debug, Eq, PartialEq)]
pub(super) enum NodeTerminalCommand {
    /// Finalize assertions only after authentic whole-world closure and capture.
    #[command(name = "terminal-capture")]
    Capture {
        /// Connect to the private same-UID installed-node socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve an independent original operation nonce, 32 lowercase hex digits.
        #[arg(long)]
        execution: String,
        /// Read the complete installed Clock and semantic-owner selection array.
        #[arg(long)]
        selections: PathBuf,
        /// Read the canonical scenario compiled by the owning daemon.
        #[arg(long)]
        scenario: PathBuf,
        /// Bound execution in picoseconds without declaring EOF.
        #[arg(long)]
        ceiling_ps: u64,
        /// Preserve this original report publication and acknowledgement stage.
        #[arg(long, value_enum, default_value = "acknowledged")]
        stage: TerminalStage,
    },
    /// Restore original terminal custody and complete only saved publication or ACK.
    #[command(name = "terminal-restore")]
    Restore {
        /// Connect to the private same-UID installed-node socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve a fresh independent restoration nonce, 32 lowercase hex digits.
        #[arg(long)]
        execution: String,
        /// Read the original complete installed-owner selection array.
        #[arg(long)]
        selections: PathBuf,
        /// Read the unchanged original actor-compiled scenario.
        #[arg(long)]
        scenario: PathBuf,
        /// Read a completed original terminal operation record.
        #[arg(long)]
        source: PathBuf,
        /// Advance original custody to this publication or acknowledgement stage.
        #[arg(long, value_enum, default_value = "acknowledged")]
        stage: TerminalStage,
    },
    /// Read original terminal status without native launch or finalization.
    #[command(name = "terminal-status")]
    Status {
        /// Connect to the private same-UID installed-node socket.
        #[arg(long)]
        socket: PathBuf,
        /// Select the original independent operation nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run(command: &NodeTerminalCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeTerminalCommand::Capture {
            socket,
            execution,
            selections,
            scenario,
            ceiling_ps,
            stage,
        } => (
            socket,
            NodeTerminalStateRequest::capture(
                execution.clone(),
                decode_node_selections(&bounded_file(selections, 64 * 1024)?)
                    .map_err(node_error)?,
                bounded_file(scenario, 8 * 1024 * 1024)?,
                *ceiling_ps,
                (*stage).into(),
            )
            .map_err(node_error)?,
        ),
        NodeTerminalCommand::Restore {
            socket,
            execution,
            selections,
            scenario,
            source,
            stage,
        } => {
            let record = NodeHostStateRecord::from_json(&bounded_file(source, 8 * 1024 * 1024)?)
                .map_err(node_error)?;
            if record.version != 2 {
                return Err(node_error(
                    "terminal restoration requires an explicit terminal operation record",
                ));
            }
            let NodeHostStateOutcome::Completed { artifact, .. } = record.state else {
                return Err(node_error(
                    "terminal restoration requires a complete original signed archive",
                ));
            };
            (
                socket,
                NodeTerminalStateRequest::restore(
                    execution.clone(),
                    decode_node_selections(&bounded_file(selections, 64 * 1024)?)
                        .map_err(node_error)?,
                    bounded_file(scenario, 8 * 1024 * 1024)?,
                    artifact,
                    (*stage).into(),
                )
                .map_err(node_error)?,
            )
        }
        NodeTerminalCommand::Status { socket, execution } => (
            socket,
            NodeTerminalStateRequest::status(execution.clone()).map_err(node_error)?,
        ),
    };
    let request = NodeControlRequest::terminal_state("operator/terminal-state", request)
        .map_err(node_error)?;
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let NodeControlResult::HostState { record } = reply.result else {
        return Err(node_error(
            "daemon refused original terminal custody or returned another result",
        ));
    };
    println!(
        "{}",
        serde_json::to_string(record.as_ref()).map_err(node_error)?
    );
    Ok(())
}
