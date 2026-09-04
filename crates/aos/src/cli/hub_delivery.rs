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
