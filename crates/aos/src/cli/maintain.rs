//! Command-line contract for local package-maintenance automation.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct MaintainArgs {
    #[command(subcommand)]
    pub command: Option<MaintainCommand>,

    /// Stream typed events and one terminal result as JSON Lines
    #[arg(long)]
    pub jsonl: bool,

    /// Use stable ASCII output ordered for assistive technology
    #[arg(long)]
    pub screen_reader: bool,

    /// Override the repository-bound durable maintenance state root
    #[arg(long, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum MaintainCommand {
    /// Evaluate and validate the repository-bound maintenance inventory
    Inventory(MaintainInventoryArgs),
    /// Refresh bounded direct-upstream and advisory evidence
    Scan(MaintainScanArgs),
    /// Report cached package-update discovery as a maintainer inbox
    Report(MaintainReportArgs),
    /// Show concise cached maintenance and active-run state
    Status(MaintainStatusArgs),
}

#[derive(Args)]
pub struct MaintainInventoryArgs {
    /// Fail unless every emitted association satisfies the closed contract
    #[arg(long)]
    pub check: bool,

    /// Evaluate one explicit Nix target platform
    #[arg(long, visible_alias = "system", value_name = "PLATFORM")]
    pub target: Option<String>,
}

#[derive(Args)]
pub struct MaintainScanArgs {
    /// Use only sufficiently fresh cached observations
    #[arg(long)]
    pub offline: bool,

    /// Evaluate one explicit Nix target platform
    #[arg(long, visible_alias = "system", value_name = "PLATFORM")]
    pub target: Option<String>,
}

#[derive(Args)]
pub struct MaintainReportArgs {
    /// Show only units with a selectable newer release
    #[arg(long)]
    pub outdated: bool,

    /// Show only units whose required upstream evidence is incomplete
    #[arg(long)]
    pub unknown: bool,

    /// Restrict the report to one upstream family
    #[arg(long, value_name = "FAMILY")]
    pub family: Option<String>,
}

#[derive(Args)]
pub struct MaintainStatusArgs {
    /// Exact or unambiguous local run identity
    pub run: Option<String>,

    /// Show only nonterminal runs
    #[arg(long)]
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands};

    #[test]
    fn parses_inventory_check_with_an_explicit_target() {
        let cli = Cli::try_parse_from([
            "aos",
            "maintain",
            "inventory",
            "--check",
            "--target",
            "aarch64-linux",
        ])
        .expect("maintenance inventory arguments should parse");

        let Commands::Maintain(args) = cli.command else {
            panic!("expected maintain command");
        };
        let Some(MaintainCommand::Inventory(inventory)) = args.command else {
            panic!("expected inventory command");
        };
        assert!(inventory.check);
        assert_eq!(inventory.target.as_deref(), Some("aarch64-linux"));
    }

    #[tokio::test]
    async fn accepts_both_machine_formats_for_typed_invocation_diagnostics() {
        let cli = Cli::try_parse_from(["aos", "maintain", "--json", "--jsonl"])
            .expect("recognized maintenance invocations must reach typed diagnostics");
        let Commands::Maintain(args) = &cli.command else {
            panic!("expected maintain command");
        };
        assert!(cli.json, "global JSON flag should remain set");
        assert!(args.jsonl, "maintenance JSON Lines flag should remain set");
        let completion = crate::commands::maintain::run(&cli, args)
            .await
            .expect("output-mode conflict should produce a valid completion");

        assert_eq!(
            completion.result.disposition,
            aos_maintain::presentation::CommandDisposition::InvalidInvocation
        );
        assert_eq!(completion.exit_code(), 2);
    }
}
