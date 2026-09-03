//! Command-line contract for local package-maintenance automation.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

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
    /// Create an immutable update plan without modifying repository source
    Plan(MaintainPlanArgs),
    /// Execute an immutable plan in a managed isolated worktree
    Run(MaintainRunArgs),
    /// Resume a durable run from its last verified boundary
    Resume(MaintainResumeArgs),
    /// Inspect a durable run or immutable plan in detail
    Inspect(MaintainInspectArgs),
    /// Print the exact retained candidate patch for a run
    Diff(MaintainRunIdentityArgs),
    /// Mark a run abandoned while retaining its evidence and worktree
    Abandon(MaintainRunIdentityArgs),
    /// Remove a terminal run's clean managed worktree after exact confirmation
    Clean(MaintainCleanArgs),
    /// Record explicit maintainer acceptance of the exact quick-gated patch
    Accept(MaintainAcceptArgs),
    /// Commit an accepted candidate with maintainer Git identity and policy
    Commit(MaintainCommitArgs),
    /// Run or rerun the immutable quick or final gate plan
    Test(MaintainTestArgs),
    /// Run or accept one bounded local repair-agent proposal
    Repair(MaintainRepairArgs),
    /// Generate and verify the complete local candidate evidence dossier
    Evidence(MaintainRunIdentityArgs),
    /// Render reviewed pull-request title, body, and publication inputs offline
    PreparePr(MaintainRunIdentityArgs),
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

#[derive(Args)]
pub struct MaintainPlanArgs {
    /// Exact update-unit identity
    pub unit: String,

    /// Select an exact observed target for a one-component unit
    #[arg(long, value_name = "VERSION")]
    pub target: Option<String>,
}

#[derive(Args)]
pub struct MaintainRunArgs {
    /// Update unit to plan and execute
    #[arg(required_unless_present = "plan", conflicts_with = "plan")]
    pub unit: Option<String>,

    /// Execute one exact previously created immutable plan
    #[arg(long, value_name = "PLAN", required_unless_present = "unit")]
    pub plan: Option<String>,

    /// Stop after reaching this durable boundary
    #[arg(long, value_enum, default_value_t = MaintainRunUntil::QuickGated)]
    pub until: MaintainRunUntil,

    /// Use an explicit empty destination instead of the managed state path
    #[arg(long, value_name = "PATH")]
    pub worktree: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum MaintainRunUntil {
    /// Stop as soon as the isolated worktree is ready
    WorktreeReady,
    /// Stop after deterministic source and metadata materialization
    Materialized,
    /// Stop after the quick gate plan completes
    QuickGated,
}

#[derive(Args)]
pub struct MaintainResumeArgs {
    /// Exact or unambiguous local run identity
    pub run: String,

    /// Stop after reaching this durable boundary
    #[arg(long, value_enum, default_value_t = MaintainRunUntil::QuickGated)]
    pub until: MaintainRunUntil,
}

#[derive(Args)]
pub struct MaintainInspectArgs {
    /// Exact or unambiguous local run identity
    #[arg(required_unless_present = "plan", conflicts_with = "plan")]
    pub run: Option<String>,

    /// Inspect one exact immutable plan without executing it
    #[arg(long, value_name = "PLAN", required_unless_present = "run")]
    pub plan: Option<String>,
}

#[derive(Args)]
pub struct MaintainRunIdentityArgs {
    /// Exact or unambiguous local run identity
    pub run: String,
}

#[derive(Args)]
pub struct MaintainCleanArgs {
    /// Exact or unambiguous local run identity
    pub run: String,

    /// Confirm removal by repeating the resolved run identity
    #[arg(long, value_name = "RUN")]
    pub confirm: Option<String>,
}

#[derive(Args)]
pub struct MaintainAcceptArgs {
    /// Exact or unambiguous local run identity
    pub run: String,

    /// Confirm the exact candidate patch digest shown by the preview
    #[arg(long, value_name = "DIGEST")]
    pub confirm: Option<String>,
}

#[derive(Args)]
pub struct MaintainCommitArgs {
    /// Exact or unambiguous local run identity
    pub run: String,

    /// Confirm commit creation by repeating the resolved run identity
    #[arg(long, value_name = "RUN")]
    pub confirm: Option<String>,
}

#[derive(Args)]
pub struct MaintainTestArgs {
    /// Exact or unambiguous local run identity
    pub run: String,

    /// Run the attempt-bound quick gate set
    #[arg(long, conflicts_with = "final_gate")]
    pub quick: bool,

    /// Run the exact-commit final gate set
    #[arg(long = "final", conflicts_with = "quick")]
    pub final_gate: bool,
}

#[derive(Args)]
pub struct MaintainRepairArgs {
    /// Exact or unambiguous local run identity
    pub run: String,

    /// Select deterministic manual handoff or a confined local adapter
    #[arg(long, value_enum, default_value_t = MaintainAgentMode::None)]
    pub agent: MaintainAgentMode,

    /// Absolute executable implementing the closed JSON stdin/stdout adapter
    #[arg(
        long,
        value_name = "PATH",
        required_if_eq("agent", "local"),
        conflicts_with = "confirm"
    )]
    pub adapter: Option<PathBuf>,

    /// Apply a retained proposal by confirming its exact patch digest
    #[arg(long, value_name = "DIGEST", conflicts_with = "adapter")]
    pub confirm: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum MaintainAgentMode {
    /// Do not invoke a model; return typed manual repair instructions
    None,
    /// Invoke one explicit local adapter inside the verified boundary
    Local,
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

    #[test]
    fn run_requires_exactly_one_unit_or_plan() {
        assert!(Cli::try_parse_from(["aos", "maintain", "run"]).is_err());
        assert!(
            Cli::try_parse_from(["aos", "maintain", "run", "zlib-1", "--plan", "plan-fixture"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "aos",
                "maintain",
                "run",
                "--plan",
                "plan-fixture",
                "--until",
                "worktree-ready"
            ])
            .is_ok()
        );
    }

    #[test]
    fn repair_defaults_to_no_agent_and_requires_an_explicit_local_adapter() {
        let cli = Cli::try_parse_from(["aos", "maintain", "repair", "run-fixture"])
            .expect("no-agent repair should parse");
        let Commands::Maintain(args) = cli.command else {
            panic!("expected maintain command");
        };
        let Some(MaintainCommand::Repair(repair)) = args.command else {
            panic!("expected repair command");
        };
        assert_eq!(repair.agent, MaintainAgentMode::None);
        assert!(repair.adapter.is_none());

        assert!(
            Cli::try_parse_from([
                "aos",
                "maintain",
                "repair",
                "run-fixture",
                "--agent",
                "local"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "aos",
                "maintain",
                "repair",
                "run-fixture",
                "--agent",
                "local",
                "--adapter",
                "/nix/store/adapter"
            ])
            .is_ok()
        );
    }
}
