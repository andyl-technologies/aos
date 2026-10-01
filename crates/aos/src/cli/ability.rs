//! Native source replay, reference, and retained-output inspection commands.

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum AbilityCommand {
    /// Replay immutable evaluation inputs into a desired transaction without activation
    Evaluate(AbilityEvaluateArgs),
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
    /// Check structural interface compatibility for one release owner
    CheckCompat(AbilityCheckCompatArgs),
    /// Preview effects depending on an exact desired effect identity
    RemovalPreview(AbilityRemovalPreviewArgs),
}

#[derive(Args)]
pub struct AbilityEvaluateArgs {
    /// Read this immutable native evaluation input descriptor
    pub input: PathBuf,
    /// Select the absolute source-built nix-store executable (or set AOS_NIX_STORE)
    #[arg(long)]
    pub nix_store: Option<PathBuf>,
    /// Bound pure evaluation time in milliseconds
    #[arg(long, default_value_t = 60_000, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_ms: u64,
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
#[command(group(ArgGroup::new("release_owner").required(true).args(["owner", "os"])))]
pub struct AbilityCheckCompatArgs {
    /// Read the earlier native module documentation
    pub before: PathBuf,
    /// Read the later native module documentation
    pub after: PathBuf,
    /// Check this package's public interface and release version
    #[arg(long)]
    pub owner: Option<String>,
    /// Check the OS public interface and release version
    #[arg(long)]
    pub os: bool,
    /// Read exact compatibility exceptions with their reasons
    #[arg(long)]
    pub exceptions: Option<PathBuf>,
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::AbilityCommand;
    use crate::cli::{Cli, Commands};

    #[test]
    fn evaluate_defaults_to_bounded_source_replay() {
        let parsed =
            Cli::try_parse_from(["aos", "ability", "evaluate", "evaluation-input.json"]).unwrap();
        let Commands::Ability {
            command: AbilityCommand::Evaluate(arguments),
        } = parsed.command
        else {
            panic!("expected native source replay");
        };

        assert_eq!(
            arguments.input,
            std::path::Path::new("evaluation-input.json")
        );
        assert_eq!(arguments.timeout_ms, 60_000);
        assert!(arguments.nix_store.is_none());
    }

    #[test]
    fn evaluate_accepts_explicit_store_tool_and_timeout() {
        let parsed = Cli::try_parse_from([
            "aos",
            "ability",
            "evaluate",
            "evaluation-input.json",
            "--timeout-ms",
            "1234",
            "--nix-store",
            "/nix/store/tool/bin/nix-store",
        ])
        .unwrap();
        let Commands::Ability {
            command: AbilityCommand::Evaluate(arguments),
        } = parsed.command
        else {
            panic!("expected native source replay");
        };

        assert_eq!(arguments.timeout_ms, 1234);
        assert_eq!(
            arguments.nix_store.as_deref(),
            Some(std::path::Path::new("/nix/store/tool/bin/nix-store"))
        );
    }

    #[test]
    fn evaluate_rejects_zero_timeout_and_activation_flags() {
        for arguments in [
            [
                "aos",
                "ability",
                "evaluate",
                "evaluation-input.json",
                "--timeout-ms",
                "0",
            ],
            [
                "aos",
                "ability",
                "evaluate",
                "evaluation-input.json",
                "--profile",
                "/var/lib/profiles/system",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }
}
