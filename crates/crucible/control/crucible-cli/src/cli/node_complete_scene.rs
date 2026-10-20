//! Installs a locally pinned collecting source and requests its inactive lifecycle.
//!
//! The installation files are local operator inputs before endpoint admission.
//! The later control request contains no source identity, native permission or
//! Accepted report. Existing node serve/Compile/Observe routes remain unchanged.

use super::{CliError, bounded_file, node_error};
use clap::Subcommand;
use crucible_daemon::{
    node_control::{NodeControlRequest, NodeControlResult, request_node_control},
    node_qualification::InstalledCompleteSceneManifest,
};
use crucible_node_format::{ContentRef, canonical};
use std::path::PathBuf;

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum CompleteSceneCommand {
    /// Host one independently pinned, unqualified complete collecting scene.
    ServeCompleteScene {
        /// Read the ordinary private daemon installation policy.
        #[arg(long)]
        policy: PathBuf,
        /// Read the independently installed complete-source package manifest.
        #[arg(long)]
        installation: PathBuf,
        /// Read the operator's independently authenticated manifest ContentRef.
        #[arg(long)]
        expected: PathBuf,
    },
    /// Prepare the installed scene once without Arm, activation or class acceptance.
    CompleteScenePrepare {
        /// Connect to the private same-UID installed daemon endpoint.
        #[arg(long)]
        socket: PathBuf,
    },
}

pub(super) fn run(command: &CompleteSceneCommand) -> Result<(), CliError> {
    match command {
        CompleteSceneCommand::ServeCompleteScene {
            policy,
            installation,
            expected,
        } => {
            let value = canonical::parse_json(&bounded_file(expected, 65_536)?, 65_536)
                .map_err(node_error)?;
            let expected: ContentRef = serde_json::from_value(value).map_err(node_error)?;
            let manifest = InstalledCompleteSceneManifest::new(installation.clone(), expected)
                .map_err(node_error)?;
            super::serve_installed(policy, None, Some(manifest))
        }
        CompleteSceneCommand::CompleteScenePrepare { socket } => {
            let request = NodeControlRequest::complete_scene_prepare("operator/complete-scene")
                .map_err(node_error)?;
            let reply = request_node_control(socket, &request).map_err(node_error)?;
            match reply.result {
                NodeControlResult::CompleteScenePrepared {} if reply.version == 12 => {
                    println!(
                        "{}",
                        serde_json::json!({"state":"inactive_collecting_prepared"})
                    );
                    Ok(())
                }
                NodeControlResult::Refused { reason } => Err(node_error(reason)),
                _ => Err(node_error(
                    "complete-scene daemon returned another result kind",
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn complete_scene_cli_requires_independent_pin_and_refuses_authority_flags() {
        let args = [
            "crucible",
            "node",
            "serve-complete-scene",
            "--policy",
            "/tmp/policy",
            "--installation",
            "/tmp/installation",
            "--expected",
            "/tmp/expected",
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        assert!(Cli::try_parse_from(&args[..8]).is_err());
        let mut forged = args.to_vec();
        forged.push("--accepted");
        assert!(Cli::try_parse_from(forged).is_err());
        assert!(
            Cli::try_parse_from([
                "crucible",
                "node",
                "complete-scene-prepare",
                "--socket",
                "/tmp/node.sock"
            ])
            .is_ok()
        );
    }
}
