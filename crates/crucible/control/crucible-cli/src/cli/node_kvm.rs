//! Local operator KVM preparation through measured installation and the real kernel.

use std::path::PathBuf;

use clap::Subcommand;
use crucible_daemon::node_observed_executor::{
    MAX_KVM_CANDIDATE_POLICY_BYTES, prepare_installed_kvm_candidate,
};

use super::{CliError, bounded_file, node_error};

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeKvmCommand {
    /// Attempt native KVM preparation under independently installed local policy.
    KvmPrepare {
        /// Read the operator's closed candidate policy with expected installed bytes.
        #[arg(long)]
        policy: PathBuf,
    },
}

pub(super) fn run(command: &NodeKvmCommand) -> Result<(), CliError> {
    let NodeKvmCommand::KvmPrepare { policy } = command;
    let bytes = bounded_file(policy, MAX_KVM_CANDIDATE_POLICY_BYTES)?;
    prepare_installed_kvm_candidate(&bytes).map_err(|error| {
        let category = if error.environment_unavailable() {
            "EnvironmentUnavailable"
        } else {
            "PreparationRefused"
        };
        node_error(format!("{category}: {error}"))
    })
}
