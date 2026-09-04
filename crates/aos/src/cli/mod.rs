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
mod container;
mod doc;
mod gc;
mod hub;
mod hub_container;
mod hub_retained_control;
mod image;
mod maintain;
mod prefetch;
mod release;
mod server;
mod test;
mod vm;

pub use cache::*;
pub use container::*;
pub use hub::*;
pub use hub_container::*;
pub use hub_retained_control::*;
pub use image::*;
pub use maintain::*;
pub use release::*;
pub use server::*;
pub use test::*;
pub use vm::*;

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ProgressChoice {
    /// Select terminal or stable-line rendering automatically.
    #[default]
    Auto,
    /// Always render an updating terminal display.
    Tty,
    /// Always emit stable newline-delimited updates.
    Plain,
    /// Disable progress updates.
    Off,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ColorChoice {
    /// Use color only when standard error is an interactive terminal.
    #[default]
    Auto,
    /// Always emit terminal colors.
    Always,
    /// Never emit terminal colors.
    Never,
}

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

    /// Control progress rendering.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub progress: ProgressChoice,

    /// Control terminal color output.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub color: ColorChoice,
}

#[derive(Parser)]
#[command(
    name = "apm",
    about = "Consume and manage AOS packages",
    version,
    after_long_help = aos_package::ENVIRONMENT_HELP
)]
pub struct ApmCli {
    #[command(subcommand)]
    pub command: aos_package::PackageCommand,

    /// Show what would be done without doing it
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Assume yes to all prompts
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Control progress rendering.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub progress: ProgressChoice,

    /// Control terminal color output.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub color: ColorChoice,
}

#[derive(Parser)]
#[command(
    name = "apr",
    about = "Author and publish AOS package registries",
    version,
    after_long_help = aos_package::ENVIRONMENT_HELP
)]
pub struct AprCli {
    #[command(subcommand)]
    pub command: aos_package::RegistryCommand,

    /// Use system-wide registry configuration
    #[arg(long, global = true)]
    pub system: bool,

    /// Show what would be done without doing it
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Control progress rendering.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub progress: ProgressChoice,

    /// Control terminal color output.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub color: ColorChoice,
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
        /// Cross-compile for this Nix platform
        #[arg(long, visible_alias = "system", value_name = "PLATFORM")]
        target: Option<String>,
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
    /// Show repository or package info
    Describe {
        /// Package name
        package: Option<String>,
    },
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
    /// Cross-cloud metadata agent (initrd user-data fetch)
    Metadata {
        #[command(subcommand)]
        command: MetadataCmd,
    },
    /// Binary cache client (push, pull, prefetch, list)
    Cache {
        #[command(subcommand)]
        command: CacheCmd,
    },
    /// Registry hub client (interacts with an aos-hub via its API)
    Hub {
        #[command(subcommand)]
        command: HubCmd,
    },
    /// Discover and download signed AOS system images
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Build, inspect, and transfer OCI container images
    Container {
        #[command(subcommand)]
        command: ContainerCommand,
    },
    /// Plan, build, verify, and publish canonical AOS releases
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Inspect and advance local package-maintenance campaigns
    Maintain(MaintainArgs),
    /// Run downloaded AOS images locally with QEMU
    Vm {
        #[command(subcommand)]
        command: VmCommand,
    },
    /// Profile a closure for leaked build/dev artifacts
    Profile {
        #[command(subcommand)]
        command: ProfileCmd,
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
        /// Select the system installed-package profile in package mode
        #[arg(long)]
        system: bool,
        /// Hub base URL in package or hub mode
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Hub registry slug in package or hub mode
        #[arg(long)]
        registry: Option<String>,
        /// Hub access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
        /// Exact package version
        #[arg(long)]
        version: Option<String>,
        /// Exact package platform
        #[arg(long)]
        platform: Option<String>,
    },
    /// Serve canonical package option hints over Language Server Protocol stdio
    LanguageServer {
        /// Read the system installed-package profile
        #[arg(long)]
        system: bool,
        /// Add an exact canonical documentation object
        #[arg(long = "document")]
        documents: Vec<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// Profile a target's runtime closure for build/dev artifacts
    Closure {
        /// Package name, attribute path, or store path to profile
        target: String,
        /// Number of largest paths to list
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// Only print confirmed leaks (dev-leak / spurious verdicts)
        #[arg(long)]
        suspects_only: bool,
        /// Also flag any path shipping no library/executable (slower:
        /// scans much more of the closure, catches leaks of any name)
        #[arg(long)]
        deep: bool,
    },
    /// Explain why one package references another, with evidence
    Refs {
        /// Package that holds the reference
        package: String,
        /// Referenced dependency to justify
        dependency: String,
    },
}

#[derive(Subcommand)]
pub enum MetadataCmd {
    /// Detect the platform and probe offline config-drives
    Detect,
    /// Fetch and stash exact user-data + instance facts
    Fetch,
    /// Authorize user-data as exact literal host.nix
    Authorize {
        /// Measured provisioning trust policy: platform or signed
        #[arg(long)]
        trust: String,
        /// Public configuration-key directory; repeatable
        #[arg(long = "trusted-config-keys-dir")]
        trusted_config_keys_dir: Vec<PathBuf>,
    },
    /// Evaluate the closed aos.provisioning projection and render storage
    EvalProvisioning {
        /// ABI-pinned base module library embedded in the image
        #[arg(long)]
        base_lib: PathBuf,
        /// Scratch directory admitted to restricted evaluation
        #[arg(long, default_value = "/run/aos-provisioning-eval")]
        eval_root: PathBuf,
        /// Keep `/var` raw for measured-boot LUKS enrollment
        #[arg(long)]
        measured_boot: bool,
        /// Existing committed arm for advisory post-provision drift evaluation
        #[arg(long)]
        committed_source: Option<String>,
        /// Existing GPT marker UUID for stable generated partition UUIDs
        #[arg(long)]
        marker_uuid: Option<String>,
    },
    /// Verify that stage 2 sees the exact host input accepted in initrd
    VerifyBinding,
    /// Persist validated provisioning evidence and manual repart definitions
    PersistProvisioning {
        /// Durable state directory on `/var`
        #[arg(long, default_value = "/var/lib/aos-provisioning")]
        state_dir: PathBuf,
        /// ABI of the base module library that evaluated the storage plan
        #[arg(long)]
        module_abi: u32,
        /// Version of the image whose initrd evaluated the storage plan
        #[arg(long)]
        image_version: String,
    },
    /// Cache an authorized host input after full stage-2 evaluation succeeds
    CacheRuntime {
        /// Durable state directory on `/var`
        #[arg(long, default_value = "/var/lib/aos-provisioning")]
        state_dir: PathBuf,
    },
    /// Restore the last fully evaluated host input when metadata is unavailable
    RestoreRuntime {
        /// Durable state directory on `/var`
        #[arg(long, default_value = "/var/lib/aos-provisioning")]
        state_dir: PathBuf,
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
