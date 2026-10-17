//! Sends exact signed original commitments to the independently installed preparation caller.

use super::{CliError, bounded_file, node_error};
use clap::Subcommand;
use crucible_daemon::node_control::{
    NodeControlRequest, NodeControlResult, NodeOriginalLineageRequest,
    decode_original_lineage_sources, request_node_control,
};
use std::path::PathBuf;

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeOriginalLineageCommand {
    /// Prepare three original-lineage models under installed source and behavioral authorities.
    OriginalLineagePrepare {
        /// Connect to the private same-UID installed daemon.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve a fresh operational nonce, 32 lowercase hexadecimal digits.
        #[arg(long)]
        execution: String,
        /// Read the complete three-actor signed-source ContentRef object.
        #[arg(long)]
        sources: PathBuf,
        /// Read unchanged original bounded run configuration bytes.
        #[arg(long)]
        configuration: PathBuf,
    },
}

pub(super) fn run(command: &NodeOriginalLineageCommand) -> Result<(), CliError> {
    let NodeOriginalLineageCommand::OriginalLineagePrepare {
        socket,
        execution,
        sources,
        configuration,
    } = command;
    let sources =
        decode_original_lineage_sources(&bounded_file(sources, 65_536)?).map_err(node_error)?;
    let request = NodeOriginalLineageRequest::new(
        execution.clone(),
        sources,
        bounded_file(configuration, 4096)?,
    )
    .map_err(node_error)?;
    let request =
        NodeControlRequest::original_lineage_prepare("operator/original-lineage", request)
            .map_err(node_error)?;
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    match reply.result {
        NodeControlResult::OriginalLineagePrepared {
            execution: returned,
        } if reply.version == 11 && returned == *execution => {
            println!(
                "{}",
                serde_json::json!({"execution":returned, "state":"inactive_prepared"})
            );
            Ok(())
        }
        NodeControlResult::Refused { reason } => Err(node_error(reason)),
        _ => Err(node_error(
            "original-lineage daemon returned another result kind",
        )),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn installed_command_requires_original_files_and_rejects_caller_authority_flags() {
        let args = [
            "crucible",
            "node",
            "original-lineage-prepare",
            "--socket",
            "/tmp/node.sock",
            "--execution",
            "112233445566778899aabbccddeeff00",
            "--sources",
            "/tmp/sources.json",
            "--configuration",
            "/tmp/configuration.json",
        ];
        assert!(super::super::Cli::try_parse_from(args).is_ok());
        assert!(super::super::Cli::try_parse_from(&args[..9]).is_err());
        assert!(
            super::super::Cli::try_parse_from(
                args.into_iter()
                    .chain(["--acceptance-policy", "/tmp/caller-policy.json"])
            )
            .is_err()
        );
    }
}
