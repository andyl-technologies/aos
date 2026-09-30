//! Native reference, desired transaction, and retained-output inspection commands.

use clap::{Args, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum AbilityCommand {
    /// Validate and render native module declarations or a desired transaction
    Inspect(AbilityInspectArgs),
    /// Inspect a checked native activation journal without mutation
    Journal(AbilityJournalArgs),
    /// Explain a checked realized artifact-consumption observation
    ArtifactConsumption(AbilityArtifactConsumptionArgs),
    /// Inspect a committed native profile generation and retained outputs
    Diagnostic(AbilityDiagnosticArgs),
    /// Browse a checked native reference or desired transaction locally
    Operator(AbilityOperatorArgs),
    /// Compare native declarations or desired effect revisions
    Compare(AbilityCompareArgs),
    /// Preview effects depending on an exact desired effect identity
    RemovalPreview(AbilityRemovalPreviewArgs),
}

#[derive(Args)]
pub struct AbilityJournalArgs {
    /// Read this native activation journal
    pub journal: PathBuf,
    /// Select checked JSON output
    #[arg(long, value_enum, default_value_t = JournalRenderFormat::Json)]
    pub format: JournalRenderFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum JournalRenderFormat {
    /// Emit the checked native journal inspection
    Json,
}

#[derive(Args)]
pub struct AbilityInspectArgs {
    /// Read native module documentation or a package transaction
    pub document: PathBuf,
    /// Verify the exact document bytes against this independent digest
    #[arg(long)]
    pub expected_digest: Option<String>,
    /// Select the representation
    #[arg(long, value_enum)]
    pub format: Option<AbilityRenderFormat>,
}

#[derive(Args)]
pub struct AbilityCompareArgs {
    /// Read the earlier native document
    pub before: PathBuf,
    /// Read the later native document
    pub after: PathBuf,
    /// Verify the exact earlier document digest
    #[arg(long)]
    pub before_digest: Option<String>,
    /// Verify the exact later document digest
    #[arg(long)]
    pub after_digest: Option<String>,
}

#[derive(Args)]
pub struct AbilityOperatorArgs {
    /// Read native module documentation or a package transaction
    pub document: PathBuf,
    /// Verify the exact document digest
    #[arg(long)]
    pub expected_digest: Option<String>,
    /// Serve a read-only local browser
    #[arg(long)]
    pub serve: bool,
    /// Listen on this loopback address
    #[arg(long, requires = "serve")]
    pub listen: Option<SocketAddr>,
}

#[derive(Args)]
pub struct AbilityRemovalPreviewArgs {
    /// Read the native desired package transaction
    pub document: PathBuf,
    /// Select the exact hashed effect identity
    #[arg(long)]
    pub effect: String,
    /// Verify the exact transaction document digest
    #[arg(long)]
    pub expected_digest: Option<String>,
    /// Bound reverse traversal depth
    #[arg(long, default_value_t = 8)]
    pub max_depth: usize,
    /// Bound the affected effect count
    #[arg(long, default_value_t = 256)]
    pub max_nodes: usize,
}

#[derive(Args)]
pub struct AbilityDiagnosticArgs {
    /// Read this native profile directory
    pub profile: PathBuf,
    /// Select this committed profile generation
    pub generation: u32,
    /// Select protected details to disclose
    #[arg(long, value_enum, default_value_t = AbilityDiagnosticAudience::Redacted)]
    pub audience: AbilityDiagnosticAudience,
}

#[derive(Args)]
pub struct AbilityArtifactConsumptionArgs {
    /// Read canonical realized artifact-consumption evidence
    pub evidence: PathBuf,
    /// Select the exact consuming executable path
    #[arg(long)]
    pub consumer: Option<String>,
    /// Select the exact provider content digest
    #[arg(long)]
    pub provider_content: Option<String>,
    /// Select the explanation representation
    #[arg(long, value_enum)]
    pub format: Option<ArtifactConsumptionRenderFormat>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AbilityRenderFormat {
    /// Render a human reference or ordered desired effect path
    Text,
    /// Emit the checked native document
    Json,
    /// Render package and operation links as HTML
    Html,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ArtifactConsumptionRenderFormat {
    /// Render a human explanation
    Text,
    /// Emit checked observation JSON
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum AbilityDiagnosticAudience {
    /// Withhold desired inputs, implementation paths, and output values
    #[default]
    Redacted,
    /// Include native desired inputs and retained operation results
    Deployment,
}
