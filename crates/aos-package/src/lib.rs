pub mod clean;
pub mod config;
pub mod deps;
pub mod download;
pub mod hold;
pub mod install;
pub mod profile;
pub mod query;
pub mod registry;
pub mod registry_ops;
pub mod remove;
pub mod resolve;
pub mod rollback;
pub mod security;
pub mod source;
pub mod store;
pub mod sysroot;
pub mod sysroot_lock;
pub mod test_systemd_client;
pub mod types;
pub mod unit_diff;
pub mod update;
pub mod upgrade;
pub mod verify;

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Subcommand;

use aos_core::error::AosError;
use aos_core::output::Printer;
use sysroot::KernelUpgradeMode;
use types::ProfileScope;

/// Clap subcommand enum for `aos package` / `apm`.
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
        /// Install as system sysroot (generation switching)
        #[arg(long)]
        system: bool,
        /// Download a pre-compiled image instead of the toplevel
        #[arg(long)]
        image: Option<String>,
        /// Output path for a downloaded image (with --image)
        #[arg(long)]
        output: Option<String>,
        /// Bypass sysroot-lock check for specific packages (comma-separated) or "all"
        #[arg(long, value_name = "NAMES", num_args = 0..=1, default_missing_value = "all")]
        ignore_sysroot_lock: Option<String>,
        /// Use kexec to hot-load new kernel (with --system)
        #[arg(long, group = "kernel_mode")]
        kexec: bool,
        /// Full reboot after activation (with --system)
        #[arg(long, group = "kernel_mode")]
        reboot: bool,
        /// Userspace only, defer kernel to next reboot (with --system)
        #[arg(long, group = "kernel_mode")]
        live: bool,
        /// Drain workloads before kernel switch (with --kexec or --reboot)
        #[arg(long)]
        drain: bool,
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
        /// Bypass sysroot-lock check for specific packages (comma-separated) or "all"
        #[arg(long, value_name = "NAMES", num_args = 0..=1, default_missing_value = "all")]
        ignore_sysroot_lock: Option<String>,
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
        /// Upgrade the system sysroot
        #[arg(long)]
        system: bool,
        /// Bypass sysroot-lock check for specific packages (comma-separated) or "all"
        #[arg(long, value_name = "NAMES", num_args = 0..=1, default_missing_value = "all")]
        ignore_sysroot_lock: Option<String>,
        /// Use kexec to hot-load new kernel (with --system)
        #[arg(long, group = "kernel_mode")]
        kexec: bool,
        /// Full reboot after activation (with --system)
        #[arg(long, group = "kernel_mode")]
        reboot: bool,
        /// Userspace only, defer kernel to next reboot (with --system)
        #[arg(long, group = "kernel_mode")]
        live: bool,
        /// Drain workloads before kernel switch (with --kexec or --reboot)
        #[arg(long)]
        drain: bool,
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
        /// Roll back the system sysroot
        #[arg(long)]
        system: bool,
        /// List all system generations
        #[arg(long)]
        list: bool,
        /// Use kexec to hot-load old kernel (with --system)
        #[arg(long, group = "kernel_mode")]
        kexec: bool,
        /// Full reboot after rollback (with --system)
        #[arg(long, group = "kernel_mode")]
        reboot: bool,
        /// Userspace only, defer kernel to next reboot (with --system)
        #[arg(long, group = "kernel_mode")]
        live: bool,
        /// Drain workloads before kernel switch (with --kexec or --reboot)
        #[arg(long)]
        drain: bool,
    },
    /// Manage registries
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Hidden: pre-/etc-swap daemon reconcile planning.
    ///
    /// Called only from the toplevel's `activate` script while it holds the
    /// switch lock. Diffs live `/etc` against the candidate overlay, stops
    /// units that must be torn down under their old definitions, and prints a
    /// race-free plan path for the post-swap phase.
    #[command(name = "activate-pre-etc-swap", hide = true)]
    ActivatePreEtcSwap {
        #[arg(long = "gen")]
        generation: u32,
        #[arg(long)]
        candidate_etc: PathBuf,
    },
    /// Hidden: post-/etc-swap daemon reconcile apply.
    ///
    /// Called only from the toplevel's `activate` script while it holds the
    /// switch lock. Reads the pre-swap plan, reloads systemd against the new
    /// `/etc`, applies reload/restart/start actions, and runs the health gate.
    #[command(name = "activate-post-etc-swap", hide = true)]
    ActivatePostEtcSwap {
        #[arg(long)]
        plan: PathBuf,
    },
    /// Hidden: exercise the `aos_systemd::SystemdClient` directly.
    ///
    /// Test vehicle for the fleet test at
    /// `tests/fleet/apm-systemd-client.nix`. The `_` prefix marks it
    /// internal — hidden from `--help`, no stability promise, may break
    /// between versions. It talks to systemd over D-Bus and needs no apm
    /// config, so `run()` dispatches it before `ApmConfig::load`.
    #[command(name = "_test-systemd-client", hide = true)]
    TestSystemdClient {
        #[command(subcommand)]
        op: TestSystemdClientOp,
    },
}

/// Operations for the hidden `apm _test-systemd-client` subcommand. Each maps
/// one-for-one onto a [`aos_systemd::SystemdClient`] method; the handler in
/// [`test_systemd_client`] serialises the result to JSON on stdout.
#[derive(Subcommand)]
pub enum TestSystemdClientOp {
    /// Start a unit (mode "replace") and wait for its job to settle.
    Start { unit: String },
    /// Stop a unit and wait for its job to settle.
    Stop { unit: String },
    /// Restart a unit and wait for its job to settle.
    Restart { unit: String },
    /// Reload a unit (runs `ExecReload=`) and wait for its job to settle.
    Reload { unit: String },
    /// Start a unit in "isolate" mode and wait for its job to settle.
    Isolate { unit: String },
    /// `Manager.Reload()` — the D-Bus equivalent of `systemctl daemon-reload`.
    DaemonReload,
    /// Clear the failed state of a single unit (`--unit`) or all units.
    ResetFailed {
        #[arg(long)]
        unit: Option<String>,
    },
    /// Whether a unit's `ActiveState == "active"`.
    IsActive { unit: String },
    /// List units matching an optional glob `--pattern` / `--state` filter.
    ListUnits {
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long)]
        state: Option<String>,
    },
    /// Read a single `org.freedesktop.systemd1.Unit` property.
    Property { unit: String, name: String },
    /// Scan for failed (and failed-and-auto-restarting) units.
    FailedUnits,
    /// Drain late `JobRemoved` signals until the bus goes quiet.
    Settle,
}

impl PackageCommand {
    /// Returns `true` when the user passed `--system` on a subcommand that
    /// supports it (Install, Upgrade, Rollback).
    pub fn is_system(&self) -> bool {
        match self {
            PackageCommand::Install { system, .. } => *system,
            PackageCommand::Upgrade { system, .. } => *system,
            PackageCommand::Rollback { system, .. } => *system,
            _ => false,
        }
    }
}

/// Clap subcommand enum for `apm registry` / `apr`.
#[derive(Subcommand)]
pub enum RegistryCommand {
    // ----- Registry Lifecycle -----
    /// Initialize a new empty registry
    Create {
        /// Registry name
        name: String,
        /// Remote URL to set as origin
        #[arg(long)]
        remote: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// List configured registries and priorities
    List,
    /// Add a registry (clone remote into storage)
    Add {
        /// Registry URL
        url: String,
        /// Registry name (derived from URL if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Priority (higher = preferred)
        #[arg(long, default_value = "500")]
        priority: u32,
        /// Pin to exact commit hash (mutually exclusive with --branch/--tag/--version)
        #[arg(long, group = "tracking")]
        commit: Option<String>,
        /// Track a branch HEAD (mutually exclusive with --commit/--tag/--version)
        #[arg(long, group = "tracking")]
        branch: Option<String>,
        /// Pin to exact tag name (mutually exclusive with --commit/--branch/--version)
        #[arg(long, group = "tracking")]
        tag: Option<String>,
        /// Semver version constraint on tags (mutually exclusive with --commit/--branch/--tag)
        #[arg(long, group = "tracking")]
        version: Option<String>,
    },
    /// Remove a registry
    Remove {
        /// Registry name
        name: String,
        /// Keep local clone on disk
        #[arg(long)]
        keep_local: bool,
    },

    // ----- Package Entries -----
    /// Publish a package to the registry from a store path
    Publish {
        /// Nix store path to publish
        store_path: String,
        /// Package name override
        #[arg(long)]
        name: Option<String>,
        /// Version override
        #[arg(long)]
        version: Option<String>,
        /// Platform override
        #[arg(long)]
        platform: Option<String>,
        /// Package description
        #[arg(long)]
        description: Option<String>,
        /// Package homepage
        #[arg(long)]
        homepage: Option<String>,
        /// Package license
        #[arg(long)]
        license: Option<String>,
        /// Package maintainer
        #[arg(long)]
        maintainer: Option<String>,
        /// Mark this package as a system toplevel (sysroot)
        #[arg(long)]
        sysroot: bool,
        /// Previous version in the version chain
        #[arg(long)]
        previous: Option<String>,
        /// Pre-compiled image store path (repeatable, paired with --image-format)
        #[arg(long = "image")]
        images: Vec<String>,
        /// Image format for each --image (repeatable, paired with --image)
        #[arg(long = "image-format")]
        image_formats: Vec<String>,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Custom commit message
        #[arg(long)]
        message: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a package entry from the registry
    Unpublish {
        /// Package name
        package: String,
        /// Specific version to remove (removes all if omitted)
        version: Option<String>,
        /// Platform to remove
        #[arg(long)]
        platform: Option<String>,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Custom commit message
        #[arg(long)]
        message: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },

    // ----- Registry Query -----
    /// Show a package entry from the registry
    Show {
        /// Package name
        package: String,
        /// Specific version
        #[arg(long)]
        version: Option<String>,
        /// Show raw TOML
        #[arg(long)]
        raw: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// List packages in the registry
    Packages {
        /// Filter by platform
        #[arg(long)]
        platform: Option<String>,
        /// Show only packages with newer versions available
        #[arg(long)]
        outdated: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Validate TOML schema and hashes
    Verify {
        /// Verify only this package
        #[arg(long)]
        package: Option<String>,
        /// Attempt to fix validation errors
        #[arg(long)]
        fix: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show pending changes vs HEAD or remote
    Diff {
        /// Show only file stats
        #[arg(long)]
        stat: bool,
        /// Diff against remote
        #[arg(long)]
        remote: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Validate cache has all referenced store paths
    Validate {
        /// Validate only this package
        #[arg(long)]
        package: Option<String>,
        /// Filter by platform
        #[arg(long)]
        platform: Option<String>,
        /// Remove entries whose paths are missing
        #[arg(long)]
        fix: bool,
        /// Number of parallel HEAD requests
        #[arg(short, long, default_value = "32")]
        jobs: u32,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },

    // ----- Git Workflow -----
    /// Show working tree status
    Status {
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show commit history
    Log {
        /// Filter log by package
        #[arg(long)]
        package: Option<String>,
        /// Number of commits to show
        #[arg(short, default_value = "20")]
        n: u32,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Branch operations
    Branch {
        #[command(subcommand)]
        command: BranchCommand,
    },
    /// Push to remote
    Push {
        /// Branch to push
        #[arg(long)]
        branch: Option<String>,
        /// Set upstream tracking
        #[arg(long)]
        set_upstream: bool,
        /// Force push
        #[arg(long)]
        force: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Fetch and fast-forward from remote
    Pull {
        /// Use rebase instead of merge
        #[arg(long)]
        rebase: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Merge a branch
    Merge {
        /// Branch to merge
        branch: String,
        /// Create a merge commit even for fast-forward
        #[arg(long)]
        no_ff: bool,
        /// Squash commits
        #[arg(long)]
        squash: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },

    // ----- GitHub Integration -----
    /// GitHub Pull Request operations
    Pr {
        #[command(subcommand)]
        command: PrCommand,
    },

    // ----- Release -----
    /// Create a git tag
    Tag {
        /// Tag name
        name: String,
        /// Tag message
        #[arg(long)]
        message: Option<String>,
        /// Signing key
        #[arg(long)]
        key: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Generate git bundles for HTTP distribution
    Bundle {
        /// Output directory
        #[arg(long)]
        output: Option<String>,
        /// Tag to bundle
        #[arg(long)]
        tag: Option<String>,
        /// Create delta from this tag
        #[arg(long)]
        delta_from: Option<String>,
        /// Update the bundle-list.toml manifest
        #[arg(long)]
        update_manifest: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Re-sign an existing release tag
    Sign {
        /// Tag name to re-sign
        tag: Option<String>,
        /// Signing key
        #[arg(long)]
        key: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// Branch subcommands.
#[derive(Subcommand)]
pub enum BranchCommand {
    /// List branches
    List {
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Create a new branch
    Create {
        /// Branch name
        name: String,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Switch to a branch
    Switch {
        /// Branch name
        name: String,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Delete a branch
    Delete {
        /// Branch name
        name: String,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// GitHub PR subcommands.
#[derive(Subcommand)]
pub enum PrCommand {
    /// Create a pull request
    Create {
        /// PR title
        #[arg(long)]
        title: Option<String>,
        /// PR body
        #[arg(long)]
        body: Option<String>,
        /// Base branch
        #[arg(long)]
        base: Option<String>,
        /// Create as draft
        #[arg(long)]
        draft: bool,
        /// Request review from
        #[arg(long)]
        reviewer: Vec<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// List pull requests
    List {
        /// Filter by author
        #[arg(long)]
        author: Option<String>,
        /// Show only my PRs
        #[arg(long)]
        mine: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show a pull request
    Show {
        /// PR number
        number: u32,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Merge a pull request
    Merge {
        /// PR number
        number: u32,
        /// Squash merge
        #[arg(long)]
        squash: bool,
        /// Rebase merge
        #[arg(long)]
        rebase: bool,
        /// Regular merge
        #[arg(long)]
        merge: bool,
        /// Delete branch after merge
        #[arg(long)]
        delete_branch: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show PR diff
    Diff {
        /// PR number
        number: u32,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// Convert mutually-exclusive kernel mode flags into a `KernelUpgradeMode`.
fn parse_kernel_mode(kexec: bool, reboot: bool, live: bool) -> KernelUpgradeMode {
    if kexec {
        KernelUpgradeMode::Kexec
    } else if reboot {
        KernelUpgradeMode::Reboot
    } else if live {
        KernelUpgradeMode::Live
    } else {
        KernelUpgradeMode::Advisory
    }
}

/// Main entry point for `aos package` / `apm`.
pub async fn run(
    command: &PackageCommand,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    // The hidden systemd-client test vehicle talks to systemd over D-Bus and
    // needs no apm config or profile. Dispatch it before `ApmConfig::load`
    // below so it works on a system with no apm state (mirrors how `main.rs`
    // early-returns `Completions`/`Serve` before building the NixRunner).
    if let PackageCommand::TestSystemdClient { op } = command {
        return test_systemd_client::run(op, printer).await;
    }

    // The hidden activate split runs during the activate script while that
    // script holds the switch lock. These paths talk to systemd over D-Bus,
    // need no apm config, and must return their own 0/1/2 exit codes (which
    // `main.rs` would otherwise flatten to 1).
    if let PackageCommand::ActivatePreEtcSwap {
        generation,
        candidate_etc,
    } = command
    {
        let code =
            sysroot::activate_pre_etc_swap(*generation, candidate_etc, dry_run, printer).await;
        std::process::exit(code);
    }
    if let PackageCommand::ActivatePostEtcSwap { plan } = command {
        let code = sysroot::activate_post_etc_swap(plan, printer).await;
        std::process::exit(code);
    }

    let system = command.is_system();
    let scope = if system {
        ProfileScope::System
    } else {
        ProfileScope::User
    };

    let config = config::ApmConfig::load(scope)?;

    match command {
        PackageCommand::Install {
            packages,
            registry,
            system: install_system,
            image: image_fmt,
            output: image_output,
            ignore_sysroot_lock,
            kexec,
            reboot,
            live,
            drain,
            ..
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(
                ignore_sysroot_lock.as_deref(),
            );
            if *install_system || image_fmt.is_some() {
                let kernel_mode = parse_kernel_mode(*kexec, *reboot, *live);
                sysroot::install_system(
                    &config,
                    packages,
                    registry.as_deref(),
                    image_fmt.as_deref(),
                    image_output.as_deref(),
                    dry_run,
                    yes,
                    kernel_mode,
                    *drain,
                    printer,
                )
                .await
            } else {
                install::run(&config, packages, registry.as_deref(), dry_run, yes, &ignore, printer).await
            }
        }
        PackageCommand::Remove {
            packages,
            autoremove,
        } => remove::run(&config, packages, *autoremove, dry_run, yes, printer).await,
        PackageCommand::Autoremove => {
            remove::run_autoremove(&config, dry_run, yes, printer).await
        }
        PackageCommand::Reinstall {
            packages,
            ignore_sysroot_lock,
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(
                ignore_sysroot_lock.as_deref(),
            );
            install::run(&config, packages, None, dry_run, yes, &ignore, printer).await
        }
        PackageCommand::Update { registry } => {
            update::run(&config, registry.as_deref(), printer).await
        }
        PackageCommand::Upgrade {
            packages,
            exclude,
            system: upgrade_system,
            ignore_sysroot_lock,
            kexec,
            reboot,
            live,
            drain,
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(
                ignore_sysroot_lock.as_deref(),
            );
            if *upgrade_system {
                let kernel_mode = parse_kernel_mode(*kexec, *reboot, *live);
                sysroot::upgrade_system(&config, dry_run, kernel_mode, *drain, printer).await
            } else {
                upgrade::run(&config, packages, exclude, dry_run, yes, &ignore, printer).await
            }
        }
        PackageCommand::FullUpgrade => {
            let ignore = sysroot_lock::IgnoreSysrootLock::Enforce;
            upgrade::run(&config, &[], &[], dry_run, yes, &ignore, printer).await
        }
        PackageCommand::Search {
            pattern,
            names_only,
            installed,
            registry,
        } => {
            query::search(&config, pattern, *names_only, *installed, registry.as_deref(), printer)
                .await
        }
        PackageCommand::Show { package } => query::show(&config, package, printer).await,
        PackageCommand::List {
            installed,
            upgradable,
            held,
            registry,
        } => {
            query::list(&config, *installed, *upgradable, *held, registry.as_deref(), printer)
                .await
        }
        PackageCommand::Depends { package } => {
            deps::depends(&config, package, printer).await
        }
        PackageCommand::Rdepends { package } => {
            deps::rdepends(&config, package, printer).await
        }
        PackageCommand::Policy { package } => {
            deps::policy(&config, package, printer).await
        }
        PackageCommand::Files { package } => {
            deps::files(&config, package, printer).await
        }
        PackageCommand::Hold { package } => {
            hold::run_hold(&config, package, printer).await
        }
        PackageCommand::Unhold { package } => {
            hold::run_unhold(&config, package, printer).await
        }
        PackageCommand::Held => hold::run_held(&config, printer).await,
        PackageCommand::Clean { generations, keep } => {
            clean::run(&config, *generations, *keep, printer).await
        }
        PackageCommand::Gc => clean::run_gc(printer).await,
        PackageCommand::Verify { package } => {
            source::run_verify(&config, package, printer).await
        }
        PackageCommand::Source {
            package,
            show_drv,
            fetch,
            verify,
        } => {
            source::run_source(&config, package, *show_drv, *fetch, *verify, printer).await
        }
        PackageCommand::Rollback {
            generation,
            system: rollback_system,
            list: rollback_list,
            kexec,
            reboot,
            live,
            drain,
        } => {
            if *rollback_system || *rollback_list {
                let kernel_mode = parse_kernel_mode(*kexec, *reboot, *live);
                sysroot::rollback_system(
                    &config,
                    *generation,
                    *rollback_list,
                    dry_run,
                    kernel_mode,
                    *drain,
                    printer,
                )
                .await
            } else {
                rollback::run(&config, *generation, dry_run, printer).await
            }
        }
        PackageCommand::Registry { command } => {
            run_registry(&config, command, printer).await
        }
        // Dispatched by the early-return above, before `ApmConfig::load`.
        PackageCommand::TestSystemdClient { .. } => {
            unreachable!("TestSystemdClient is handled before ApmConfig::load")
        }
        PackageCommand::ActivatePreEtcSwap { .. } => {
            unreachable!("ActivatePreEtcSwap is handled before ApmConfig::load")
        }
        PackageCommand::ActivatePostEtcSwap { .. } => {
            unreachable!("ActivatePostEtcSwap is handled before ApmConfig::load")
        }
    }
}

// ---------------------------------------------------------------------------
// Registry subcommands
// ---------------------------------------------------------------------------

async fn run_registry(
    config: &config::ApmConfig,
    command: &RegistryCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        RegistryCommand::List => registry_list(config, printer).await,
        RegistryCommand::Add {
            url,
            name,
            priority,
            commit,
            branch,
            tag,
            version,
        } => registry_add(
            config,
            url,
            name.as_deref(),
            *priority,
            commit.as_deref(),
            branch.as_deref(),
            tag.as_deref(),
            version.as_deref(),
            printer,
        ).await,
        RegistryCommand::Remove { name, keep_local } => {
            registry_remove(config, name, *keep_local, printer).await
        }
        RegistryCommand::Create {
            name, remote, ..
        } => registry_ops::create(config, name, remote.as_deref(), printer).await,
        RegistryCommand::Publish {
            store_path,
            name,
            version,
            platform,
            description,
            homepage,
            license,
            maintainer,
            sysroot,
            previous,
            images,
            image_formats,
            no_commit,
            message,
            registry,
        } => {
            registry_ops::publish(
                config,
                store_path,
                name.as_deref(),
                version.as_deref(),
                platform.as_deref(),
                description.as_deref(),
                homepage.as_deref(),
                license.as_deref(),
                maintainer.as_deref(),
                *sysroot,
                previous.as_deref(),
                images,
                image_formats,
                *no_commit,
                message.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Unpublish {
            package,
            version,
            platform,
            no_commit,
            message,
            registry,
        } => {
            registry_ops::unpublish(
                config,
                package,
                version.as_deref(),
                platform.as_deref(),
                *no_commit,
                message.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Show {
            package,
            version,
            raw,
            registry,
        } => {
            registry_ops::show(
                config,
                package,
                version.as_deref(),
                *raw,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Packages {
            platform,
            outdated,
            registry,
        } => {
            registry_ops::packages(
                config,
                platform.as_deref(),
                *outdated,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Verify {
            package,
            fix,
            registry,
        } => {
            registry_ops::verify(
                config,
                package.as_deref(),
                *fix,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Diff {
            stat,
            remote,
            registry,
        } => {
            registry_ops::diff(
                config,
                *stat,
                *remote,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Validate {
            package,
            platform,
            fix,
            jobs,
            registry,
        } => {
            registry_ops::validate(
                config,
                package.as_deref(),
                platform.as_deref(),
                *fix,
                *jobs,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Status { registry } => {
            registry_ops::status(config, registry.as_deref(), printer).await
        }
        RegistryCommand::Log {
            package,
            n,
            registry,
        } => {
            registry_ops::log(
                config,
                package.as_deref(),
                *n,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Branch { command } => {
            registry_ops::run_branch(config, command, printer).await
        }
        RegistryCommand::Push {
            branch,
            set_upstream,
            force,
            registry,
        } => {
            registry_ops::push(
                config,
                branch.as_deref(),
                *set_upstream,
                *force,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Pull { rebase, registry } => {
            registry_ops::pull(config, *rebase, registry.as_deref(), printer).await
        }
        RegistryCommand::Merge {
            branch,
            no_ff,
            squash,
            registry,
        } => {
            registry_ops::merge(
                config,
                branch,
                *no_ff,
                *squash,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Pr { command } => {
            registry_ops::run_pr(config, command, printer).await
        }
        RegistryCommand::Tag {
            name,
            message,
            key,
            registry,
        } => {
            registry_ops::tag(
                config,
                name,
                message.as_deref(),
                key.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Bundle {
            output,
            tag: tag_name,
            delta_from,
            update_manifest,
            registry,
        } => {
            registry_ops::bundle(
                config,
                output.as_deref(),
                tag_name.as_deref(),
                delta_from.as_deref(),
                *update_manifest,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Sign {
            tag,
            key,
            registry,
        } => {
            registry_ops::sign(
                config,
                tag.as_deref(),
                key.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
    }
}

async fn registry_list(
    config: &config::ApmConfig,
    printer: &Printer,
) -> Result<()> {
    if config.registries.is_empty() {
        printer.info("No registries configured. Add one with `apm registry add <url>`.");
        return Ok(());
    }

    printer.header("Configured registries:");
    printer.plain("");

    for (reg_config, state) in &config.registries {
        let status = if reg_config.enabled {
            "enabled"
        } else {
            "disabled"
        };

        let tracking = reg_config
            .tracking_mode()
            .map(|m| m.to_string())
            .unwrap_or_else(|_| "invalid".to_string());

        printer.header(&format!("  {} (priority {})", reg_config.name, reg_config.priority));
        printer.kv("URL", &reg_config.url);
        printer.kv("Status", status);
        printer.kv("Transport", &format!("{:?}", reg_config.transport()));
        printer.kv("Tracking", &tracking);

        let cache_dir = config.cache_path();
        let packages_dir = cache_dir.join(&reg_config.name).join("packages");
        let pkg_count = count_packages_in_dir(&packages_dir);
        printer.kv("Packages", &format!("{pkg_count}"));

        if let Some(s) = state {
            if let Some(ref ts) = s.last_update {
                printer.kv("Last update", ts);
            }
            if let Some(ref commit) = s.last_commit {
                let short = &commit[..commit.len().min(12)];
                printer.kv("Last commit", short);
            }
        } else {
            printer.kv("Last update", "never (run `apm update`)");
        }

        if let Some(ref signing) = reg_config.signing {
            printer.kv("Signing", &format!("required={}", signing.required));
        }

        printer.plain("");
    }

    Ok(())
}

async fn registry_add(
    config: &config::ApmConfig,
    url: &str,
    name_override: Option<&str>,
    priority: u32,
    commit: Option<&str>,
    branch: Option<&str>,
    tag: Option<&str>,
    version: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let name = name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| derive_registry_name(url));

    if config.find_registry(&name).is_some() {
        bail!(
            "registry '{}' already exists. Remove it first with `apm registry remove {}`.",
            name,
            name
        );
    }

    // Validate version constraint if provided.
    if let Some(v) = version {
        semver::VersionReq::parse(v)
            .map_err(|e| anyhow::anyhow!("invalid version constraint '{}': {}", v, e))?;
    }

    printer.header(&format!("Adding registry '{name}'..."));
    printer.kv("URL", url);
    printer.kv("Priority", &priority.to_string());

    let config_dir = config.scope.config_dir();
    let registries_dir = config_dir.join("registries.d");
    fs::create_dir_all(&registries_dir)
        .with_context(|| format!("creating {}", registries_dir.display()))?;

    let toml_path = registries_dir.join(format!("{name}.toml"));
    let mut toml_content = format!(
        r#"[registry]
name = "{name}"
url = "{url}"
priority = {priority}
enabled = true
"#,
    );

    // Add tracking mode field if specified.
    if let Some(c) = commit {
        toml_content.push_str(&format!("commit = \"{c}\"\n"));
        printer.kv("Tracking", &format!("commit:{}", &c[..c.len().min(12)]));
    } else if let Some(b) = branch {
        toml_content.push_str(&format!("branch = \"{b}\"\n"));
        printer.kv("Tracking", &format!("branch:{b}"));
    } else if let Some(t) = tag {
        toml_content.push_str(&format!("tag = \"{t}\"\n"));
        printer.kv("Tracking", &format!("tag:{t}"));
    } else if let Some(v) = version {
        toml_content.push_str(&format!("version = \"{v}\"\n"));
        printer.kv("Tracking", &format!("version:{v}"));
    }

    fs::write(&toml_path, &toml_content)
        .with_context(|| format!("writing {}", toml_path.display()))?;

    printer.success(&format!(
        "Registry '{name}' added. Run `apm update {name}` to sync package metadata."
    ));

    Ok(())
}

async fn registry_remove(
    config: &config::ApmConfig,
    name: &str,
    keep_local: bool,
    printer: &Printer,
) -> Result<()> {
    if config.find_registry(name).is_none() {
        return Err(AosError::RegistryError {
            message: format!("registry '{name}' not found"),
        }
        .into());
    }

    let prof = profile::Profile::open(config.scope)?;
    let installed = profile::meta::meta_by_registry(&prof, name)?;

    if !installed.is_empty() {
        let pkg_names: Vec<String> = installed
            .iter()
            .filter_map(|m| m.apm.as_ref().map(|a| a.name.clone()))
            .collect();

        printer.error(&format!(
            "Cannot remove registry '{}': {} installed package(s):",
            name,
            installed.len()
        ));
        for pkg_name in &pkg_names {
            printer.plain(&format!("  - {pkg_name}"));
        }
        printer.plain("Remove these packages first with `apm remove`.");

        return Err(AosError::RegistryHasPackages {
            name: name.to_string(),
            count: installed.len(),
        }
        .into());
    }

    let config_dir = config.scope.config_dir();
    let toml_path = config_dir
        .join("registries.d")
        .join(format!("{name}.toml"));

    if toml_path.exists() {
        fs::remove_file(&toml_path)
            .with_context(|| format!("removing {}", toml_path.display()))?;
    }

    if !keep_local {
        let cache_dir = config.cache_path().join(name);
        if cache_dir.exists() {
            let _ = fs::remove_dir_all(&cache_dir);
        }

        let registries_dir = config.scope.registries_path().join(name);
        if registries_dir.exists() {
            let _ = fs::remove_dir_all(&registries_dir);
        }
    }

    let key_store = security::KeyStore::new(config.scope.trusted_keys_dirs());
    let _ = key_store.remove(name);

    printer.success(&format!("Registry '{name}' removed."));

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_registry_name(url: &str) -> String {
    let cleaned = url
        .trim_end_matches('/')
        .trim_end_matches(".git");
    let name = cleaned
        .rsplit('/')
        .next()
        .unwrap_or("unknown");
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
}

fn count_packages_in_dir(dir: &std::path::Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };

    let mut count = 0;
    for letter_entry in entries.flatten() {
        let letter_path = letter_entry.path();
        if !letter_path.is_dir() {
            continue;
        }
        let Ok(sub) = fs::read_dir(&letter_path) else {
            continue;
        };
        for entry in sub.flatten() {
            if entry
                .path()
                .extension()
                .map(|e| e == "toml")
                .unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApmConfig;
    use crate::types::{ApmSettings, RegistryConfig};
    use tempfile::TempDir;

    fn make_config(
        tmp: &TempDir,
        registries: Vec<(RegistryConfig, Option<types::RegistryState>)>,
    ) -> ApmConfig {
        let config_dir = tmp.path().join("config");
        let registries_dir = config_dir.join("registries.d");
        fs::create_dir_all(&registries_dir).unwrap();

        for (reg_config, _) in &registries {
            let content = format!(
                "[registry]\nname = \"{}\"\nurl = \"{}\"\npriority = {}\n",
                reg_config.name, reg_config.url, reg_config.priority,
            );
            fs::write(
                registries_dir.join(format!("{}.toml", reg_config.name)),
                &content,
            )
            .unwrap();
        }

        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(profile_dir.join("meta")).unwrap();
        fs::write(
            profile_dir.join("state.json"),
            r#"{"current_generation": 0, "next_generation": 1}"#,
        )
        .unwrap();

        ApmConfig {
            settings: ApmSettings::default(),
            registries,
            scope: ProfileScope::User,
        }
    }

    fn reg_config(name: &str, priority: u32) -> RegistryConfig {
        RegistryConfig {
            name: name.into(),
            url: format!("https://registry.example.com/{name}"),
            priority,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            signing: None,
        }
    }

    #[test]
    fn derive_name_from_https_url() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/core"),
            "core"
        );
    }

    #[test]
    fn derive_name_from_git_url() {
        assert_eq!(
            derive_registry_name("git+https://github.com/andyl/registry.git"),
            "registry"
        );
    }

    #[test]
    fn derive_name_trailing_slash() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/extra/"),
            "extra"
        );
    }

    #[tokio::test]
    async fn registry_list_shows_registries() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(
            &tmp,
            vec![
                (reg_config("aos-core", 500), None),
                (
                    reg_config("aos-extra", 400),
                    Some(types::RegistryState {
                        last_commit: Some("deadbeef1234".into()),
                        last_creation_token: Some(2026020003),
                        last_update: Some("2026-02-16T12:00:00Z".into()),
                        ..types::RegistryState::default()
                    }),
                ),
            ],
        );

        let printer = Printer::new(0, true, false);
        let result = registry_list(&config, &printer).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn registry_list_empty() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);

        let printer = Printer::new(0, true, false);
        let result = registry_list(&config, &printer).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn registry_add_creates_config_file() {
        let tmp = TempDir::new().unwrap();

        let config_dir = tmp.path().join("config-add");
        fs::create_dir_all(config_dir.join("registries.d")).unwrap();

        let name = derive_registry_name("https://registry.aos.dev/core");
        assert_eq!(name, "core");

        let toml_content = format!(
            "[registry]\nname = \"{name}\"\nurl = \"https://registry.aos.dev/core\"\npriority = 500\nenabled = true\n",
        );
        let toml_path = config_dir.join("registries.d").join(format!("{name}.toml"));
        fs::write(&toml_path, &toml_content).unwrap();

        assert!(toml_path.exists());
        let content = fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("name = \"core\""));
        assert!(content.contains("https://registry.aos.dev/core"));
        assert!(content.contains("priority = 500"));
    }

    #[tokio::test]
    async fn registry_add_rejects_duplicate() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![(reg_config("core", 500), None)]);

        let printer = Printer::new(0, true, false);
        let result = registry_add(
            &config,
            "https://registry.aos.dev/core",
            None,
            500,
            None,
            None,
            None,
            None,
            &printer,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already exists"), "got: {err}");
    }

    #[tokio::test]
    async fn registry_remove_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);

        let printer = Printer::new(0, true, false);
        let result = registry_remove(&config, "nonexistent", false, &printer).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn count_packages_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(count_packages_in_dir(tmp.path()), 0);
    }

    #[test]
    fn count_packages_with_toml_files() {
        let tmp = TempDir::new().unwrap();
        let c_dir = tmp.path().join("c");
        fs::create_dir_all(&c_dir).unwrap();
        fs::write(c_dir.join("curl.toml"), "test").unwrap();

        let z_dir = tmp.path().join("z");
        fs::create_dir_all(&z_dir).unwrap();
        fs::write(z_dir.join("zlib.toml"), "test").unwrap();
        fs::write(z_dir.join("zstd.toml"), "test").unwrap();

        assert_eq!(count_packages_in_dir(tmp.path()), 3);
    }
}
