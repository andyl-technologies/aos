//! Clap definitions for the `aos` command-line interface.
//!
//! `Cli` is the top-level parser (global `--verbose`/`--quiet`/`--json`
//! flags) and `Commands` enumerates every subcommand. Most subcommands
//! carry their arguments inline in the `Commands` variant; larger
//! argument sets live in the sibling modules (`cache`, `package`,
//! `server`, `test`) and are re-exported here.
//!
//! The doc comments on clap enum variants and fields double as the
//! `--help` text — keep them short, imperative, and user-facing. Do NOT
//! add doc comments to the `#[derive(Parser)]`/`#[derive(Subcommand)]`
//! containers themselves: clap applies container docs to the parent
//! command's `about`/`long_about`, silently changing help output.
//! Command *implementations* live in the `commands` module, keyed by the
//! same names.

mod build;
mod cache;
mod doc;
mod gc;
mod nix_diff;
mod package;
mod prefetch;
mod server;
mod test;

pub use cache::*;
pub use package::*;
pub use server::*;
pub use test::*;

use clap::{ArgAction, Parser, Subcommand};
pub use nix_diff::NixDiffMode;

#[derive(Parser)]
#[command(name = "aos", about = "AOS build tool", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Enable builtins.traceVerbose output
    #[arg(long, global = true)]
    pub trace_verbose: bool,

    /// Override builtins.currentSystem for evaluation
    #[arg(long, global = true)]
    pub eval_system: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Build a package from source
    Build {
        /// Package name
        package: Option<String>,
        /// Build all packages
        #[arg(long)]
        all: bool,
        /// Remote build server URL (enables remote mode)
        #[arg(long, env = "AOS_REMOTE")]
        remote: Option<String>,
        /// View on the remote server
        #[arg(long, env = "AOS_VIEW", default_value = "default")]
        view: String,
        /// Provisioning token for the remote server
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// System operations (build, image, eval)
    System {
        #[command(subcommand)]
        command: SystemCmd,
    },
    /// Show package metadata
    Show {
        /// Package name
        package: String,
    },
    /// Show dependency graph
    Graph {
        /// Package name
        package: String,
        /// Output in DOT format for graphviz
        #[arg(long)]
        dot: bool,
    },
    /// Validate package definitions
    Lint {
        /// Package name (omit to lint all)
        package: Option<String>,
    },
    /// Run tests
    Test {
        #[command(subcommand)]
        command: Option<TestCmd>,
        /// Cap concurrent test-derivation builds. Threaded to
        /// `nix-build --max-jobs <N>`. Defaults to the host's CPU
        /// count (`nproc`); the harness is race-free at any
        /// concurrency, so the default just makes the most of the box.
        /// Pass a smaller number to tame I/O bursts on a slow disk.
        #[arg(long, short = 'j', global = false)]
        jobs: Option<usize>,
    },
    /// Interactive Nix REPL
    Repl,
    /// Garbage collection
    Gc {
        /// List system generations instead of collecting garbage
        #[arg(long)]
        list_generations: bool,
        /// Remote server URL (enables remote GC mode)
        #[arg(long, env = "AOS_REMOTE")]
        remote: Option<String>,
        /// View on the remote server
        #[arg(long, env = "AOS_VIEW")]
        view: Option<String>,
        /// Provisioning token for the remote server
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
        /// Also run nix-store --gc after removing roots
        #[arg(long)]
        collect: bool,
        /// Show what would be removed without acting
        #[arg(long)]
        dry_run: bool,
        /// Remove all roots for a view (decommission)
        #[arg(long)]
        all: bool,
        /// Pin a store path permanently (no TTL expiry); requires --view
        #[arg(long)]
        pin: Option<String>,
    },
    /// Debug dependency chains
    WhyDepends {
        /// Package that has the dependency
        package: String,
        /// Dependency to trace
        dependency: String,
    },
    /// Compare evaluator .drv output
    NixDiff {
        /// Attribute to instantiate
        #[arg(
            short = 'A',
            long,
            conflicts_with = "all",
            required_unless_present = "all"
        )]
        attr: Option<String>,
        /// Compare every derivation in the pkgs set
        #[arg(long)]
        all: bool,
        /// Nix file to instantiate (default: repository default.nix)
        file: Option<std::path::PathBuf>,
        /// Comparison mode
        #[arg(long, value_enum, default_value_t = NixDiffMode::Byte)]
        mode: NixDiffMode,
    },
    /// Show repository info
    Describe,
    /// Prefetch source hashes (parallel downloads with mirror failover)
    Prefetch {
        /// Only prefetch specific packages (repeatable)
        #[arg(short, long)]
        package: Vec<String>,
        /// Prefetch all packages, not just placeholders
        #[arg(long)]
        all: bool,
        /// Write computed hashes back into package .nix files
        #[arg(short, long)]
        update: bool,
        /// Number of parallel downloads
        #[arg(short, long, default_value_t = 8)]
        jobs: usize,
        /// Per-mirror connect timeout in seconds
        #[arg(long, default_value_t = 10)]
        connect_timeout: u64,
        /// Minimum download speed in bytes/sec (0 to disable)
        #[arg(long, default_value_t = 10240)]
        min_speed: u64,
    },
    /// Format Nix files with nixfmt
    Fmt {
        /// Check formatting without modifying files
        #[arg(long)]
        check: bool,
        /// Specific files to format (default: all .nix files)
        files: Vec<String>,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Start the HTTP binary cache server
    Serve {
        /// Path to server configuration file
        #[arg(long, default_value = "/etc/aos/serve.toml")]
        config: std::path::PathBuf,
    },
    /// Manage provisioning tokens
    Token {
        #[command(subcommand)]
        command: TokenCmd,
    },
    /// Package manager (apm)
    Package(PackageArgs),
    /// Binary cache client (push, pull, prefetch, list)
    Cache {
        #[command(subcommand)]
        command: CacheCmd,
    },
    /// Browse documentation
    Doc {
        /// Source path or flake URI (default: current directory)
        source: Option<String>,
        /// Look up a specific doc path
        path: Option<String>,
        /// Search all entries
        #[arg(long)]
        search: Option<String>,
        /// List entries under a prefix
        #[arg(long)]
        list: Option<String>,
        /// Force rebuild index
        #[arg(long)]
        rebuild: bool,
    },
}

#[derive(Subcommand)]
pub enum SystemCmd {
    /// Build the system configuration
    Build,
    /// Build the disk image
    Image,
    /// Evaluate the system configuration
    Eval,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_diff_defaults_to_byte_mode_and_default_file() {
        let cli = parse_cli(["aos", "nix-diff", "--attr", "pkgs.hello"]);

        match cli.command {
            Commands::NixDiff {
                attr,
                all,
                file,
                mode,
            } => {
                assert_eq!(attr.as_deref(), Some("pkgs.hello"));
                assert!(!all);
                assert_eq!(file, None);
                assert_eq!(mode, NixDiffMode::Byte);
            }
            _ => panic!("expected nix-diff command"),
        }
    }

    #[test]
    fn nix_diff_parses_explicit_file_and_path_mode() {
        let cli = parse_cli([
            "aos",
            "nix-diff",
            "--attr",
            "pkgs.busybox",
            "--mode",
            "path",
            "systems/base.nix",
        ]);

        match cli.command {
            Commands::NixDiff {
                attr,
                all,
                file,
                mode,
            } => {
                assert_eq!(attr.as_deref(), Some("pkgs.busybox"));
                assert!(!all);
                assert_eq!(file, Some(std::path::PathBuf::from("systems/base.nix")));
                assert_eq!(mode, NixDiffMode::Path);
            }
            _ => panic!("expected nix-diff command"),
        }
    }

    #[test]
    fn nix_diff_parses_structural_mode() {
        let cli = parse_cli([
            "aos",
            "nix-diff",
            "--attr",
            "pkgs.hello",
            "--mode",
            "structural",
        ]);

        match cli.command {
            Commands::NixDiff { mode, .. } => {
                assert_eq!(mode, NixDiffMode::Structural);
            }
            _ => panic!("expected nix-diff command"),
        }
    }

    #[test]
    fn nix_diff_parses_all_mode() {
        let cli = parse_cli(["aos", "nix-diff", "--all", "--mode", "structural"]);

        match cli.command {
            Commands::NixDiff {
                attr, all, mode, ..
            } => {
                assert_eq!(attr, None);
                assert!(all);
                assert_eq!(mode, NixDiffMode::Structural);
            }
            _ => panic!("expected nix-diff command"),
        }
    }

    #[test]
    fn nix_diff_requires_attr_or_all() {
        let err = parse_cli_error(["aos", "nix-diff"]);

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn nix_diff_rejects_attr_with_all() {
        let err = parse_cli_error(["aos", "nix-diff", "--all", "--attr", "pkgs.hello"]);

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn global_eval_system_is_accepted_after_subcommand() {
        let cli = parse_cli([
            "aos",
            "nix-diff",
            "--attr",
            "pkgs.bc",
            "--eval-system",
            "x86_64-linux",
        ]);

        assert_eq!(cli.eval_system.as_deref(), Some("x86_64-linux"));
    }

    fn parse_cli<const N: usize>(args: [&'static str; N]) -> Cli {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(args).expect("nix-diff argv should parse"))
            .expect("parser test thread should spawn")
            .join()
            .expect("parser test thread should finish")
    }

    fn parse_cli_error<const N: usize>(args: [&'static str; N]) -> clap::Error {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || match Cli::try_parse_from(args) {
                Ok(_) => panic!("nix-diff argv should not parse"),
                Err(err) => err,
            })
            .expect("parser test thread should spawn")
            .join()
            .expect("parser test thread should finish")
    }
}
