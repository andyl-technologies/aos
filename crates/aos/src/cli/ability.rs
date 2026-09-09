//! Offline ability inspection command definitions.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Subcommand)]
pub enum AbilityCommand {
    /// Revalidate and render a canonical portable inspection bundle
    Inspect(AbilityInspectArgs),
}

#[derive(Args)]
pub struct AbilityInspectArgs {
    /// Read the canonical inspection bundle from this file
    pub bundle: PathBuf,

    /// Match an independently obtained digest; this does not assert current policy
    #[arg(long, value_name = "SHA256")]
    pub expected_digest: Option<String>,

    /// Select the rendered inspection representation
    #[arg(long, value_enum)]
    pub format: Option<AbilityRenderFormat>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AbilityRenderFormat {
    /// Emit a line-oriented human report
    Text,
    /// Emit the complete checked view as canonical JSON
    Json,
    /// Emit a Graphviz directed graph
    Dot,
    /// Emit a Mermaid flowchart
    Mermaid,
}
