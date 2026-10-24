//! Sends explicit unchanged-source conditional replay to the installed daemon.
//!
//! The client carries raw original source identities and configuration. It cannot
//! issue source seals, installation policy or fresh replay/model authority.

use clap::Subcommand;
use crucible_daemon::node_control::{
    NodeConditionalReplayRequest, NodeControlRequest, decode_conditional_preparation,
    decode_conditional_replay_sources, request_node_control,
};
use std::path::PathBuf;

use super::{CliError, bounded_file, node_error};

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeConditionalReplayCommand {
    /// Replay an unchanged original context from the daemon's signed transcript archive.
    ConditionalReplay {
        /// Connect to the installed private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Select the durable original observation ledger.
        #[arg(long)]
        ledger: String,
        /// Preserve a fresh operational nonce, 32 lowercase hexadecimal digits.
        #[arg(long)]
        execution: String,
        /// Read the complete actor-to-signed-source ContentRef JSON object.
        #[arg(long)]
        sources: PathBuf,
        /// Read the unchanged original bounded run configuration JSON.
        #[arg(long)]
        configuration: PathBuf,
    },
    /// Read the original pending admission receipt without source dispatch.
    ConditionalReplayStatus {
        /// Connect to the installed private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the original nonzero 32-digit lowercase hexadecimal nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run(command: &NodeConditionalReplayCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeConditionalReplayCommand::ConditionalReplay {
            socket,
            ledger,
            execution,
            sources,
            configuration,
        } => {
            let sources = decode_conditional_replay_sources(&bounded_file(sources, 65_536)?)
                .map_err(node_error)?;
            let request = NodeConditionalReplayRequest::new(
                ledger.clone(),
                execution.clone(),
                sources,
                bounded_file(configuration, 4096)?,
            )
            .map_err(node_error)?;
            (
                socket,
                NodeControlRequest::conditional_replay("operator/conditional-replay", request)
                    .map_err(node_error)?,
            )
        }
        NodeConditionalReplayCommand::ConditionalReplayStatus { socket, execution } => (
            socket,
            NodeControlRequest::conditional_replay_status(
                "operator/conditional-status",
                execution.clone(),
            )
            .map_err(node_error)?,
        ),
    };
    let response = request_node_control(socket, &request).map_err(node_error)?;
    let record = decode_conditional_preparation(&response).map_err(node_error)?;
    let (admission, authenticated) = match &record.outcome {
        crucible_daemon::node_observed_executor::ConditionalPreparationState::AwaitingAdmission { .. } => ("awaiting_admission", false),
        crucible_daemon::node_observed_executor::ConditionalPreparationState::Admitted { .. } => ("admitted", true),
        crucible_daemon::node_observed_executor::ConditionalPreparationState::Unavailable { .. } => ("unavailable", false),
    };
    println!(
        "{}",
        serde_json::json!({
            "execution":record.execution, "request":record.request,
            "materialization":"conditional_transcript_replay", "admission":admission,
            "source_authenticated":authenticated, "repeatable":false,
        })
    );
    Ok(())
}
