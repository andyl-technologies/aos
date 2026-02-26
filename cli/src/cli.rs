use clap::{ArgAction, Args, Parser, Subcommand};

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
pub enum TokenCmd {
    /// Create a new provisioning token
    Create {
        /// Views this token can access (repeatable)
        #[arg(short, long, required = true)]
        view: Vec<String>,
        /// Comma-separated permissions (e.g., "read,build")
        #[arg(short, long, default_value = "read")]
        permissions: String,
        /// Token expiry duration (e.g., "90d", "24h")
        #[arg(short, long)]
        expires: Option<String>,
        /// Optional comment / description
        #[arg(long)]
        comment: Option<String>,
    },
    /// List active provisioning tokens
    List,
    /// Revoke a provisioning token
    Revoke {
        /// Token ID to revoke
        #[arg(long)]
        token_id: String,
    },
    /// Rotate a provisioning token (revoke old + create new)
    Rotate {
        /// Token ID to rotate
        #[arg(long)]
        token_id: String,
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

// ---------------------------------------------------------------------------
// Package manager (apm) CLI
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct PackageArgs {
    #[command(subcommand)]
    pub command: PackageCommand,

    /// Operate on the system profile (requires root)
    #[arg(long, global = true)]
    pub system: bool,

    /// Show what would be done without doing it
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Assume yes to all prompts
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,
}

#[derive(Subcommand)]
pub enum PackageCommand {
    /// Install one or more packages
    Install {
        /// Package names to install
        packages: Vec<String>,
        /// Install from a specific registry
        #[arg(long)]
        registry: Option<String>,
        /// Download NARs but don't install
        #[arg(long)]
        download_only: bool,
        /// Reinstall even if already at target version
        #[arg(long)]
        reinstall: bool,
        /// Skip automatic dependency installation
        #[arg(long)]
        no_deps: bool,
    },
    /// Remove packages (keep deps)
    Remove {
        /// Package names to remove
        packages: Vec<String>,
        /// Also remove orphaned dependencies
        #[arg(long)]
        autoremove: bool,
    },
    /// Remove orphaned dependency packages
    Autoremove,
    /// Re-download and reinstall packages
    Reinstall {
        /// Package names to reinstall
        packages: Vec<String>,
    },
    /// Fetch latest registry metadata
    Update {
        /// Update only this registry
        #[arg(long)]
        registry: Option<String>,
    },
    /// Upgrade installed packages to latest
    Upgrade {
        /// Specific packages to upgrade (default: all)
        packages: Vec<String>,
        /// Skip specific packages
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// Upgrade all packages with dependency resolution changes
    FullUpgrade,
    /// Search package names and descriptions
    Search {
        /// Search pattern
        pattern: String,
        /// Search only package names
        #[arg(long)]
        names_only: bool,
        /// Search only installed packages
        #[arg(long)]
        installed: bool,
        /// Search only this registry
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show detailed package information
    Show {
        /// Package name
        package: String,
    },
    /// List packages
    List {
        /// Only installed packages
        #[arg(long)]
        installed: bool,
        /// Only packages with available upgrades
        #[arg(long)]
        upgradable: bool,
        /// Only held packages
        #[arg(long)]
        held: bool,
        /// Only from this registry
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show closure tree (store references)
    Depends {
        /// Package name
        package: String,
    },
    /// Show reverse dependencies
    Rdepends {
        /// Package name
        package: String,
    },
    /// Show available versions and registry origins
    Policy {
        /// Package name
        package: String,
    },
    /// List files installed by a package
    Files {
        /// Package name
        package: String,
    },
    /// Prevent a package from being upgraded
    Hold {
        /// Package name
        package: String,
    },
    /// Remove upgrade hold
    Unhold {
        /// Package name
        package: String,
    },
    /// List held packages
    Held,
    /// Remove cached NAR downloads
    Clean {
        /// Also remove old profile generations
        #[arg(long)]
        generations: bool,
        /// Number of generations to retain (with --generations)
        #[arg(long, default_value = "3")]
        keep: u32,
    },
    /// Run Nix garbage collection on unreachable paths
    Gc,
    /// Verify installed package against registry hash
    Verify {
        /// Package name
        package: String,
    },
    /// Show/fetch the source derivation for a package
    Source {
        /// Package name
        package: String,
        /// Print the source derivation path
        #[arg(long)]
        show_drv: bool,
        /// Download the source derivation and all source inputs
        #[arg(long)]
        fetch: bool,
        /// Rebuild from source and compare hash with installed binary
        #[arg(long)]
        verify: bool,
    },
    /// Roll back to a previous profile generation
    Rollback {
        /// Roll back to a specific generation number
        #[arg(long)]
        generation: Option<u32>,
    },
    /// Manage registries
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
}

#[derive(Subcommand)]
pub enum RegistryCommand {
    /// List configured registries and priorities
    List,
    /// Add a registry
    Add {
        /// Registry URL
        url: String,
        /// Priority (higher = preferred)
        #[arg(long, default_value = "500")]
        priority: u32,
    },
    /// Remove a registry (fails if packages still installed)
    Remove {
        /// Registry name
        name: String,
    },
}
