use clap::{ArgAction, Parser, Subcommand};

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
    },
    /// Enter development shell
    Shell,
    /// Interactive Nix REPL
    Repl,
    /// Garbage collection
    Gc {
        /// List system generations instead of collecting garbage
        #[arg(long)]
        list_generations: bool,
    },
    /// Debug dependency chains
    WhyDepends {
        /// Package that has the dependency
        package: String,
        /// Dependency to trace
        dependency: String,
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
}

#[derive(Subcommand)]
pub enum SystemCmd {
    /// Build a system configuration
    Build {
        /// System variant (base, server, k8s-worker, k8s-control-plane)
        variant: String,
    },
    /// Build a disk image
    Image {
        /// System variant (base, server, k8s-worker, k8s-control-plane)
        variant: String,
    },
    /// Evaluate a system configuration
    Eval {
        /// System variant (base, server, k8s-worker, k8s-control-plane)
        variant: String,
    },
}

#[derive(Subcommand)]
pub enum TestCmd {
    /// Run evaluation tests
    Eval,
    /// Run build tests
    Build,
    /// Run VM integration tests
    Vm {
        /// Test suite name
        suite: Option<String>,
    },
    /// Run fleet tests
    Fleet {
        /// Test suite name
        suite: Option<String>,
    },
}
