//! Offline ability inspection command definitions.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Subcommand)]
pub enum AbilityCommand {
    /// Revalidate and render a canonical portable inspection bundle
    Inspect(AbilityInspectArgs),
    /// Export a checked retained execution timeline without mutating it
    Diagnostic(AbilityDiagnosticArgs),
}

#[derive(Args)]
pub struct AbilityDiagnosticArgs {
    /// Select this exact retained system generation
    pub generation: PathBuf,

    /// Select this transaction within the generation
    pub transaction: String,

    /// Select which protected deployment details to disclose
    #[arg(long, value_enum, default_value_t = AbilityDiagnosticAudience::Redacted)]
    pub audience: AbilityDiagnosticAudience,
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

    /// Restrict output to one semantic graph projection
    #[arg(long, value_enum)]
    pub projection: Option<AbilityProjection>,

    /// Apply a bounded canonical inspection-query document
    #[arg(long, value_name = "FILE")]
    pub query: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AbilityProjection {
    /// Show declarations, requests, interfaces, and composition aggregates
    Composition,
    /// Show selected providers, grants, authority, and obligations
    BindingAuthority,
    /// Show operations, resource access, readiness, and scheduling
    Activation,
    /// Show consumer and artifact retention relationships
    Retention,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum AbilityDiagnosticAudience {
    /// Withhold normalized inputs, topology identities, and store paths
    #[default]
    Redacted,
    /// Include replay inputs and deployment topology after filesystem access checks
    Deployment,
}
