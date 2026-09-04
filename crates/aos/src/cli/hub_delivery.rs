//! Arguments for coordinated delivery setup and reviewed activation.

use std::path::PathBuf;

use clap::Subcommand;

use super::{HubAccessArgs, HubPaginationArgs, HubReviewedApplyArgs, HubReviewedPlanArgs};

#[derive(Subcommand)]
pub enum HubDeliveryCmd {
    /// Review a complete delivery destination from a typed JSON intent.
    Plan {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Read a DeliveryDestinationIntent JSON document.
        #[arg(long, value_name = "FILE")]
        intent_file: PathBuf,
    },
    /// Apply a reviewed setup plan and record resumable progress.
    Apply(HubReviewedApplyArgs),
    /// Show progress, blockers, and the next available actions.
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Select the workflow by its stable identifier.
        workflow: String,
    },
    /// List delivery workflows for one surface.
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Select registry:SLUG or cache:SLUG.
        #[arg(long)]
        surface: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Resume the immutable setup after resolving its blockers.
    Resume {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Select the workflow by its stable identifier.
        workflow: String,
        /// Require this exact workflow revision.
        #[arg(long)]
        if_version: String,
    },
    /// Review and activate the verified destination for its audiences.
    Activate {
        #[command(subcommand)]
        command: HubDeliveryActivationCmd,
    },
}

#[derive(Subcommand)]
pub enum HubDeliveryActivationCmd {
    /// Review the audience changes against current verification evidence.
    Plan {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Select the workflow by its stable identifier.
        workflow: String,
        /// Require this exact workflow revision.
        #[arg(long)]
        if_version: String,
    },
    /// Activate the exact reviewed audience changes.
    Apply(HubReviewedApplyArgs),
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands, HubCmd};

    #[test]
    fn delivery_setup_and_activation_keep_review_separate_from_apply() {
        let parsed = Cli::try_parse_from([
            "aos",
            "--json",
            "hub",
            "delivery",
            "plan",
            "--intent-file",
            "delivery.json",
            "--idempotency-key",
            "review-1",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::Delivery {
                    command: HubDeliveryCmd::Plan { .. }
                },
            }
        ));
        let apply = [
            "aos",
            "hub",
            "delivery",
            "activate",
            "apply",
            "--plan-id",
            "plan:1",
            "--confirm-hash",
            "reviewed-hash",
            "--idempotency-key",
            "apply-1",
            "--yes",
        ];
        assert!(Cli::try_parse_from(apply).is_ok());
        assert!(
            Cli::try_parse_from(apply.into_iter().chain(["--intent-file", "changed.json"]))
                .is_err()
        );
    }

    #[test]
    fn resume_requires_revision_and_idempotency_without_new_intent() {
        let resume = ["aos", "hub", "delivery", "resume", "workflow:1"];
        assert!(Cli::try_parse_from(resume).is_err());
        assert!(
            Cli::try_parse_from(resume.into_iter().chain([
                "--if-version",
                "3",
                "--idempotency-key",
                "resume-1",
            ]))
            .is_ok()
        );
    }
}
