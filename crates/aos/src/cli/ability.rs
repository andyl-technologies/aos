//! Offline ability inspection command definitions.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Subcommand)]
pub enum AbilityCommand {
    /// Revalidate and render a canonical portable inspection bundle
    Inspect(AbilityInspectArgs),
    /// Explain one checked realized artifact-consumption relationship
    ArtifactConsumption(AbilityArtifactConsumptionArgs),
    /// Export a checked retained execution timeline without mutating it
    Diagnostic(AbilityDiagnosticArgs),
    /// Render or browse a bounded desired/observed operator view
    Operator(AbilityOperatorArgs),
    /// Classify semantic changes between two checked deployment plans
    Compare(AbilityCompareArgs),
    /// Preview consumers and transitions affected by removing one graph subject
    RemovalPreview(AbilityRemovalPreviewArgs),
}

#[derive(Args)]
pub struct AbilityCompareArgs {
    /// Read the earlier canonical inspection bundle from this file
    pub before: PathBuf,

    /// Read the later canonical inspection bundle from this file
    pub after: PathBuf,

    /// Match the earlier bundle against this independent digest
    #[arg(long, value_name = "SHA256")]
    pub before_digest: Option<String>,

    /// Match the later bundle against this independent digest
    #[arg(long, value_name = "SHA256")]
    pub after_digest: Option<String>,

    /// Compare the later plan with this authenticated observation overlay
    #[arg(long, value_name = "FILE")]
    pub observation: Option<PathBuf>,
}

#[derive(Args)]
pub struct AbilityRemovalPreviewArgs {
    /// Read the canonical inspection bundle from this file
    pub bundle: PathBuf,

    /// Read the canonical typed node identity from this JSON file
    #[arg(long, value_name = "FILE")]
    pub target: PathBuf,

    /// Match the bundle against this independent digest
    #[arg(long, value_name = "SHA256")]
    pub expected_digest: Option<String>,

    /// Bound reverse traversal by this edge depth
    #[arg(long, default_value_t = 8)]
    pub max_depth: usize,

    /// Bound the complete removal closure to this many nodes
    #[arg(long, default_value_t = 256)]
    pub max_nodes: usize,
}

#[derive(Args)]
pub struct AbilityOperatorArgs {
    /// Read the canonical inspection bundle from this file
    pub bundle: PathBuf,

    /// Apply this canonical single-focus operator query
    #[arg(long, value_name = "FILE")]
    pub query: PathBuf,

    /// Overlay this canonical caller-supplied observation
    #[arg(long, value_name = "FILE")]
    pub observation: Option<PathBuf>,

    /// Match an independently obtained bundle digest
    #[arg(long, value_name = "SHA256")]
    pub expected_digest: Option<String>,

    /// Serve an interactive local browser for this operator view
    #[arg(long)]
    pub serve: bool,

    /// Listen on this loopback address instead of an ephemeral port
    #[arg(long, value_name = "ADDRESS", requires = "serve")]
    pub listen: Option<SocketAddr>,
}

#[derive(Args)]
pub struct AbilityArtifactConsumptionArgs {
    /// Read canonical realized artifact-consumption evidence from this file
    pub evidence: PathBuf,

    /// Join both evidence artifacts to this canonical checked inspection bundle
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Match an independently obtained inspection-bundle digest
    #[arg(long, value_name = "SHA256", requires = "bundle")]
    pub expected_bundle_digest: Option<String>,

    /// Require this exact consuming executable path
    #[arg(long, value_name = "STORE-FILE")]
    pub consumer: Option<String>,

    /// Require this exact provider artifact content digest
    #[arg(long, value_name = "SHA256")]
    pub provider_content: Option<String>,

    /// Select the explanation representation
    #[arg(long, value_enum)]
    pub format: Option<ArtifactConsumptionRenderFormat>,
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
    /// Read a canonical checked-plan bundle or public-reference input from this file
    pub bundle: PathBuf,

    /// Match an independently obtained digest; this does not assert current policy
    #[arg(long, value_name = "SHA256")]
    pub expected_digest: Option<String>,

    /// Select the rendered inspection representation
    #[arg(long, value_enum)]
    pub format: Option<AbilityRenderFormat>,

    /// Restrict a checked-plan input to one semantic graph projection
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ArtifactConsumptionRenderFormat {
    /// Emit a concise explanation of exact linkage and retention
    Text,
    /// Emit the complete checked explanation as canonical JSON
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum AbilityDiagnosticAudience {
    /// Withhold normalized inputs, topology identities, and store paths
    #[default]
    Redacted,
    /// Include replay inputs and deployment topology after filesystem access checks
    Deployment,
}
