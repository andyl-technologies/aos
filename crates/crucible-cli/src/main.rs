//! `crucible` is the CLI entry point for the Crucible control plane.
//!
//! Spec index: RFC-0010 files 23.
//!
//! This L4 binary crate will remain a thin client over `crucible-api` and
//! `crucible-session` as specified by RFC-0010 file 23.
//!
//! Module map: the binary root owns argument dispatch only; future command
//! modules will remain transport clients over the session and API crates.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug, PartialEq, Eq)]
#[command(
    name = "crucible",
    version,
    about = "Run and inspect Crucible simulations.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Set root entropy.
    #[arg(long, env = "CRUCIBLE_SEED", value_name = "u64|hex", global = true)]
    seed: Option<String>,
    /// Select local backend.
    #[arg(long, value_enum, default_value_t = Backend::Auto, global = true)]
    backend: Backend,
    /// Use remote daemon.
    #[arg(long, value_name = "addr", global = true)]
    daemon: Option<String>,
    /// Use patched QEMU binary.
    #[arg(long, value_name = "path", global = true)]
    qemu: Option<PathBuf>,
    /// Use Crucible QEMU plugin.
    #[arg(long, value_name = "path", global = true)]
    plugin: Option<PathBuf>,
    /// Use content-addressed store root.
    #[arg(long, value_name = "path", global = true)]
    store: Option<PathBuf>,
    /// Select output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl, global = true)]
    format: OutputFormat,
    /// Write event log stream.
    #[arg(long, value_name = "path", global = true)]
    trace: Option<PathBuf>,
    /// Write failure artifacts here.
    #[arg(
        long,
        value_name = "path",
        default_value = "./.crucible",
        global = true
    )]
    artifact_dir: PathBuf,
    /// Increase log verbosity.
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Suppress non-essential output.
    #[arg(short = 'q', long, action = ArgAction::SetTrue, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Backend {
    /// Discover the best local backend.
    #[default]
    Auto,
    /// Use patched QEMU locally.
    Qemu,
    /// Use the in-process test double.
    Double,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Emit newline-delimited JSON.
    #[default]
    Jsonl,
    /// Emit one JSON document.
    Json,
    /// Emit a human-readable table.
    Table,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum Commands {
    /// Run a scenario to completion.
    Run(RunArgs),
    /// Prove deterministic replay.
    Verify(VerifyArgs),
    /// Run selected built-in gates.
    Selftest(SelftestArgs),
    /// Run to a savepoint.
    Save(SaveArgs),
    /// Resume from a checkpoint.
    Resume(ResumeArgs),
    /// Fork from a savepoint.
    Fork(ForkArgs),
    /// Replay a reproduction artifact.
    Replay(ReplayArgs),
    /// Drive state-space search.
    Search(SearchArgs),
    /// Drive coverage-guided fuzzing.
    Fuzz(FuzzArgs),
    /// Cluster discovered failures.
    Triage(TriageArgs),
    /// Open the time-travel debugger.
    Debug(DebugArgs),
    /// Run the API daemon.
    Serve(ServeArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct RunArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct VerifyArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SelftestArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SaveArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ResumeArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ForkArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ReplayArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SearchArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct FuzzArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct TriageArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct DebugArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ServeArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct CompletionsArgs {}

fn main() {
    let _cli = Cli::parse();
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_skeleton_exposes_closed_subcommand_set() {
        let mut names = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect::<Vec<_>>();
        names.sort();

        assert_eq!(
            names,
            [
                "completions",
                "debug",
                "fork",
                "fuzz",
                "replay",
                "resume",
                "run",
                "save",
                "search",
                "selftest",
                "serve",
                "triage",
                "verify",
            ]
        );
    }

    #[test]
    fn cli_skeleton_parses_global_flag_block() {
        let cli = Cli::parse_from([
            "crucible",
            "--seed",
            "0x10",
            "--backend",
            "double",
            "--daemon",
            "127.0.0.1:9000",
            "--qemu",
            "/nix/store/qemu/bin/qemu-system-x86_64",
            "--plugin",
            "/nix/store/plugin/lib/crucible-qemu-plugin.so",
            "--store",
            ".crucible-store",
            "--format",
            "json",
            "--trace",
            "trace.jsonl",
            "--artifact-dir",
            "artifacts",
            "-vv",
            "--quiet",
            "run",
        ]);

        assert_eq!(cli.seed.as_deref(), Some("0x10"));
        assert_eq!(cli.backend, Backend::Double);
        assert_eq!(cli.daemon.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(
            cli.qemu.as_ref().and_then(|path| path.to_str()),
            Some("/nix/store/qemu/bin/qemu-system-x86_64")
        );
        assert_eq!(
            cli.plugin.as_ref().and_then(|path| path.to_str()),
            Some("/nix/store/plugin/lib/crucible-qemu-plugin.so")
        );
        assert_eq!(
            cli.store.as_ref().and_then(|path| path.to_str()),
            Some(".crucible-store")
        );
        assert_eq!(cli.format, OutputFormat::Json);
        assert_eq!(
            cli.trace.as_ref().and_then(|path| path.to_str()),
            Some("trace.jsonl")
        );
        assert_eq!(cli.artifact_dir.to_str(), Some("artifacts"));
        assert_eq!(cli.verbose, 2);
        assert!(cli.quiet);
        assert!(matches!(cli.command, Commands::Run(RunArgs {})));
    }

    #[test]
    fn cli_skeleton_rejects_unknown_subcommands() {
        let error = Cli::try_parse_from(["crucible", "invented"]).unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
