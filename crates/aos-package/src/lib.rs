//! The AOS package manager: the `apm` and `apr` command surfaces.
//!
//! This crate implements both halves of the AOS package tooling:
//!
//! - **`apm` (consumer)** — installs, upgrades, and removes packages from
//!   configured registries. The clap tree is [`PackageCommand`], dispatched by
//!   [`run`].
//! - **`apr` (producer)** — authors and publishes registries: package
//!   entries, signing-key rosters, channels, static caches, and releases. The
//!   clap tree is [`RegistryCommand`], reachable as `apm registry ...` or via
//!   the `apr` binary alias.
//!
//! # Profile scopes
//!
//! Every operation runs in one of two [`types::ProfileScope`]s:
//!
//! - **User** — the default. State lives under per-user paths
//!   (`/var/lib/profiles/per-user/$USER/`, XDG config/data/cache dirs) and no
//!   special privileges are required.
//! - **System** — selected by `--system` on `install`, `upgrade`,
//!   `rollback`, and `registry`. Operates on the system sysroot under
//!   `/var/lib/profiles/system/` with numbered generations, activation
//!   scripts, and kernel/boot-loader handling (see [`sysroot`]).
//!
//! # Module map
//!
//! - [`install`] / [`remove`] / [`upgrade`] / [`rollback`] — user-scope
//!   profile mutations (resolve, download, verify, import, generation switch).
//! - [`sysroot`] — system-scope generations, activation, and kernel upgrade
//!   modes; also hosts the hidden `activate-{pre,post}-etc-swap` reconciler.
//! - [`update`] / [`query`] / [`deps`] / [`hold`] / [`clean`] / [`verify`] /
//!   [`source`] — registry sync and read-only or maintenance commands.
//! - [`registry`] / [`registry_ops`] — registry data model and the `apr`
//!   producer operations (publish, keys, channels, caches, releases).
//! - [`config`] / [`types`] — configuration loading and the on-disk data
//!   contracts (registry TOML, generation state JSON, profile paths).
//! - [`security`] / [`sysroot_lock`] — signature verification, trusted-key
//!   storage, and the sysroot-lock divergence check.
//! - [`profile`] / [`store`] / [`download`] — profile generations, the local
//!   store, and the NAR download engine.

#![forbid(unsafe_code)]

pub mod clean;
pub mod config;
pub mod deps;
pub mod download;
pub(crate) mod gitcmd;
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
pub mod sshkey;
pub mod store;
pub mod sysroot;
pub mod sysroot_lock;
pub mod test_systemd_client;
pub mod types;
pub mod unit_diff;
pub mod update;
pub mod upgrade;
pub mod verify;

#[cfg(test)]
pub(crate) mod testutil;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};

use aos_core::error::AosError;
use aos_core::output::{OutputMode, Printer};
use sysroot::KernelUpgradeMode;
use types::{
    ProfileScope, RegistryUploadAuthConfig, validate_branch_name, validate_channel_name,
    validate_commit_hash, validate_git_ref_name, validate_registry_name,
};

/// Environment-variable documentation appended to `apm`/`apr` long help.
pub const ENVIRONMENT_HELP: &str = "Environment:
  APM_SYSTEM_CONFIG_DIR  Override the system configuration root (default
                         /etc/apm). Affects every derived system path,
                         including registries.d and trusted-keys.d, in both
                         the user and system profile scopes. Must be an
                         absolute path; intended for development on non-AOS
                         hosts.
  AOS_ROOT               Override the AOS root filesystem. System-scope APM
                         state is written under <AOS_ROOT>/var/lib/apm, and
                         Nix commands use the AOS_ROOT-relative store.";

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
        /// Sync the system registries (/var/lib/apm, state in /etc/apm)
        #[arg(long)]
        system: bool,
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
        /// Show package from this registry
        #[arg(long)]
        registry: Option<String>,
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
    /// List installed packages whose source registry is no longer configured
    Orphans,
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
        /// List profile generations (system generations with --system)
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
    #[command(after_long_help = ENVIRONMENT_HELP)]
    Registry {
        /// Manage system-wide registries instead of user registries
        #[arg(long)]
        system: bool,
        /// The registry operation to run
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
        /// Generation number being activated
        #[arg(long = "gen")]
        generation: u32,
        /// Path to the candidate /etc overlay to diff against live /etc
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
        /// Path to the pre-swap plan file printed by activate-pre-etc-swap
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
        /// The systemd client operation to exercise
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
    Start {
        /// Unit name (e.g. "foo.service")
        unit: String,
    },
    /// Stop a unit and wait for its job to settle.
    Stop {
        /// Unit name (e.g. "foo.service")
        unit: String,
    },
    /// Restart a unit and wait for its job to settle.
    Restart {
        /// Unit name (e.g. "foo.service")
        unit: String,
    },
    /// Reload a unit (runs `ExecReload=`) and wait for its job to settle.
    Reload {
        /// Unit name (e.g. "foo.service")
        unit: String,
    },
    /// Start a unit in "isolate" mode and wait for its job to settle.
    Isolate {
        /// Unit name (e.g. "rescue.target")
        unit: String,
    },
    /// `Manager.Reload()` — the D-Bus equivalent of `systemctl daemon-reload`.
    DaemonReload,
    /// Clear the failed state of a single unit (`--unit`) or all units.
    ResetFailed {
        /// Unit whose failed state to clear (all units if omitted)
        #[arg(long)]
        unit: Option<String>,
    },
    /// Whether a unit's `ActiveState == "active"`.
    IsActive {
        /// Unit name (e.g. "foo.service")
        unit: String,
    },
    /// List units matching an optional glob `--pattern` / `--state` filter.
    ListUnits {
        /// Glob pattern to match unit names against
        #[arg(long)]
        pattern: Option<String>,
        /// Filter by ActiveState (e.g. "active", "failed")
        #[arg(long)]
        state: Option<String>,
    },
    /// Read a single `org.freedesktop.systemd1.Unit` property.
    Property {
        /// Unit name (e.g. "foo.service")
        unit: String,
        /// Property name (e.g. "ActiveState")
        name: String,
    },
    /// Scan for failed (and failed-and-auto-restarting) units.
    FailedUnits,
    /// Drain late `JobRemoved` signals until the bus goes quiet.
    Settle,
}

impl PackageCommand {
    /// Returns `true` when the user passed `--system` on a subcommand that
    /// supports it (Install, Upgrade, Rollback, Update, Registry).
    pub fn is_system(&self) -> bool {
        match self {
            PackageCommand::Install { system, .. } => *system,
            PackageCommand::Upgrade { system, .. } => *system,
            PackageCommand::Rollback { system, .. } => *system,
            PackageCommand::Update { system, .. } => *system,
            PackageCommand::Registry { system, .. } => *system,
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
        /// Public trust key to write into committed keys.toml
        /// (`<registry>:Ed25519:<base64>`)
        #[arg(long = "trust-key")]
        trust_key: Option<String>,
        /// Identifier for --trust-key inside keys.toml
        #[arg(long = "trust-key-id")]
        trust_key_id: Option<String>,
        /// Private key path used to sign the initial commit
        /// (required with --trust-key)
        #[arg(long)]
        key: Option<String>,
        /// Key id whose configured private key signs the initial commit
        #[arg(long = "key-id")]
        key_id: Option<String>,
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
        /// Pin to exact commit hash (mutually exclusive with other tracking flags)
        #[arg(long, group = "tracking")]
        commit: Option<String>,
        /// Track a branch HEAD (mutually exclusive with other tracking flags)
        #[arg(long, group = "tracking")]
        branch: Option<String>,
        /// Track a signed rollout channel (mutually exclusive with other tracking flags)
        #[arg(long, group = "tracking")]
        channel: Option<String>,
        /// Pin to exact tag name (mutually exclusive with other tracking flags)
        #[arg(long, group = "tracking")]
        tag: Option<String>,
        /// Semver version constraint on tags (mutually exclusive with other tracking flags)
        #[arg(long, group = "tracking")]
        version: Option<String>,
        /// Trusted registry signing key in `<registry>:Ed25519:<base64>` form
        #[arg(long = "trust-key", conflicts_with = "no_verify")]
        trust_key: Option<String>,
        /// Disable signature verification for this registry (writes
        /// `[registry.signing] required = false`; unverified syncs are
        /// intended for local development registries only)
        #[arg(long = "no-verify")]
        no_verify: bool,
        /// Register the config only; skip cloning the registry into local storage
        #[arg(long = "no-clone")]
        no_clone: bool,
    },
    /// Remove a registry
    Remove {
        /// Registry name
        name: String,
        /// Keep local clone on disk
        #[arg(long)]
        keep_local: bool,
        /// Delete the local clone even when it is an authoring clone with
        /// uncommitted or unpushed work
        #[arg(long)]
        force: bool,
    },
    /// Enable a configured registry
    Enable {
        /// Registry name
        name: String,
    },
    /// Disable a configured registry without removing its config or cache
    Disable {
        /// Registry name
        name: String,
    },
    /// Manage trusted registry signing keys
    Trust {
        /// The trust-store operation to run
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Manage the committed registry keys.toml roster
    Keys {
        /// The keys.toml roster operation to run
        #[command(subcommand)]
        command: KeysCommand,
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
        /// Source derivation or source store path to record for this package
        #[arg(long = "source-drv")]
        source_drv: Option<String>,
        /// Pre-compiled image store path (repeatable, paired with --image-format)
        #[arg(long = "image")]
        images: Vec<String>,
        /// Image format for each --image (repeatable, paired with --image)
        #[arg(long = "image-format")]
        image_formats: Vec<String>,
        /// Bless additional content for paths already recorded with different
        /// bits in the store/ graph instead of failing
        #[arg(long)]
        bless: bool,
        /// Write input-addressed records only, even on a content-addressed
        /// registry (skip computing CA realisations for this publish)
        #[arg(long = "no-ca")]
        no_ca: bool,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Custom commit message
        #[arg(long)]
        message: Option<String>,
        /// Private key path used to sign the publish commit
        #[arg(long)]
        key: Option<String>,
        /// Active key id whose configured private key signs the publish commit
        #[arg(long = "key-id")]
        key_id: Option<String>,
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
        /// Private key path used to sign the unpublish commit
        #[arg(long)]
        key: Option<String>,
        /// Active key id whose configured private key signs the unpublish commit
        #[arg(long = "key-id")]
        key_id: Option<String>,
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
        /// The branch operation to run
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
    /// Channel rollout operations
    Channel {
        /// The channel operation to run
        #[command(subcommand)]
        command: ChannelCommand,
    },
    /// Static Nix-cache operations
    Cache {
        /// The cache operation to run
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Maintain the store/ realisation graph (blessed bytes + content addresses)
    Store {
        /// The realisation-graph operation to run
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Static git-origin upload operations
    Origin {
        /// The origin operation to run
        #[command(subcommand)]
        command: OriginCommand,
    },
    /// Run the ordered producer release pipeline
    Release {
        /// Semver release tag, with no `v` prefix
        semver: String,
        /// Optional Nix store path to publish before tagging
        #[arg(long)]
        store_path: Option<String>,
        /// Package name override when --store-path is used
        #[arg(long)]
        name: Option<String>,
        /// Platform override when --store-path is used
        #[arg(long)]
        platform: Option<String>,
        /// Package description when --store-path is used
        #[arg(long)]
        description: Option<String>,
        /// Package homepage when --store-path is used
        #[arg(long)]
        homepage: Option<String>,
        /// Package license when --store-path is used
        #[arg(long)]
        license: Option<String>,
        /// Package maintainer when --store-path is used
        #[arg(long)]
        maintainer: Option<String>,
        /// Mark this package as a system toplevel when --store-path is used
        #[arg(long)]
        sysroot: bool,
        /// Previous version in the version chain when --store-path is used
        #[arg(long)]
        previous: Option<String>,
        /// Source derivation or source store path when --store-path is used
        #[arg(long = "source-drv")]
        source_drv: Option<String>,
        /// Pre-compiled image store path (repeatable, paired with --image-format)
        #[arg(long = "image")]
        images: Vec<String>,
        /// Image format for each --image (repeatable, paired with --image)
        #[arg(long = "image-format")]
        image_formats: Vec<String>,
        /// Bless additional content for paths already recorded with different
        /// bits in the store/ graph when --store-path is used
        #[arg(long)]
        bless: bool,
        /// Custom publish commit message when --store-path is used
        #[arg(long)]
        message: Option<String>,
        /// Channel to initialize or advance after immutable artifacts are ready
        #[arg(long)]
        channel: Option<String>,
        /// Initialize all 256 channel partitions at this release
        #[arg(long)]
        init_channel: bool,
        /// Number of channel partitions to advance by ascending fill
        #[arg(long)]
        count: Option<usize>,
        /// Explicit comma-separated partition list, decimal or hex
        #[arg(long)]
        partitions: Option<String>,
        /// Signing key
        #[arg(long)]
        key: Option<String>,
        /// Resolve signing key path from [registry.signing_keys] by keys.toml id
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Output directory for generated static cache files
        #[arg(long = "cache-output")]
        cache_output: Option<PathBuf>,
        /// Nix narinfo signing key file in `name:base64-secret` form
        #[arg(long = "cache-key")]
        cache_key: Option<PathBuf>,
        /// Public cache URL to write into committed registry.toml [[caches]]
        #[arg(long = "cache-url")]
        cache_url: Option<String>,
        /// Priority for generated nix-cache-info and registry [[caches]]
        #[arg(long = "cache-priority", default_value = "40")]
        cache_priority: u32,
        /// Backend URL to upload the static origin to; repeat for multiple destinations
        /// (default: the upload_urls persisted by `origin config`)
        #[arg(long = "upload-url")]
        upload_urls: Vec<String>,
        /// Authentication and backend-specific upload options
        #[command(flatten)]
        auth: CacheUploadAuthArgs,
        /// Print the ordered plan without mutating the registry
        #[arg(long)]
        dry_run: bool,
        /// Resume an interrupted release by skipping already-present immutable artifacts
        #[arg(long)]
        resume: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
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
        /// Resolve signing key path from [registry.signing_keys] by keys.toml id
        #[arg(long = "key-id")]
        key_id: Option<String>,
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
        /// Resolve signing key path from [registry.signing_keys] by keys.toml id
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// Registry trust-store operations.
#[derive(Subcommand)]
pub enum TrustCommand {
    /// Pin a trusted registry signing key in trusted-keys.d
    Pin {
        /// Registry name
        registry: String,
        /// Public key to pin, in <registry>:Ed25519:<base64> form
        #[arg(value_name = "PUBLIC_KEY")]
        key: String,
        /// Replace existing pinned keys for this registry before pinning
        #[arg(long)]
        replace: bool,
    },
    /// List pinned trusted keys
    List {
        /// Registry name to inspect
        registry: Option<String>,
    },
    /// Remove pinned trusted keys for a registry
    #[command(alias = "unpin")]
    Remove {
        /// Registry name
        registry: String,
    },
}

/// Committed registry keys.toml roster operations.
#[derive(Subcommand)]
pub enum KeysCommand {
    /// List active and revoked keys in committed keys.toml
    List {
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Generate a maintainer Ed25519 keypair and register its private key
    Generate {
        /// Stable key id (also names the private key file)
        #[arg(value_name = "PUBLIC_KEY_ID")]
        id: String,
        /// Also append the public key to committed keys.toml
        #[arg(long)]
        add: bool,
        /// Skip creating a git commit (with --add)
        #[arg(long)]
        no_commit: bool,
        /// Private key path used to sign the roster commit (with --add)
        #[arg(long = "key")]
        signing_key: Option<String>,
        /// Active key id whose configured private key signs the roster
        /// commit (with --add)
        #[arg(long = "key-id")]
        signing_key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Register an externally-held maintainer key (from a path or command)
    /// without generating or persisting any key material
    Register {
        /// Stable key id inside keys.toml
        #[arg(value_name = "PUBLIC_KEY_ID")]
        id: String,
        /// Path to the existing private key file
        #[arg(long = "key", value_name = "PATH", conflicts_with = "key_command")]
        key: Option<String>,
        /// Command, run via `sh -c`, that prints the private key to stdout
        #[arg(long = "key-command", value_name = "COMMAND", conflicts_with = "key")]
        key_command: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Add an active signing key to committed keys.toml
    Add {
        /// Stable key id for the new public key inside keys.toml
        #[arg(value_name = "PUBLIC_KEY_ID")]
        id: String,
        /// Public key to enroll, in <registry>:Ed25519:<base64> form
        #[arg(value_name = "PUBLIC_KEY")]
        key: String,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Private key path used to sign the roster commit
        #[arg(long = "key")]
        signing_key: Option<String>,
        /// Active key id whose configured private key signs the roster commit
        #[arg(long = "key-id")]
        signing_key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Retire an active signing key by moving its id to [[revoked]]
    Retire {
        /// Active key id to retire
        #[arg(value_name = "PUBLIC_KEY_ID")]
        id: String,
        /// Human-readable retirement reason
        #[arg(long)]
        reason: Option<String>,
        /// Active survivor key id expected to vouch for this retirement
        #[arg(long = "vouched-by")]
        vouched_by: Option<String>,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Private key path used to sign the roster commit
        /// (defaults to the vouching key's configured private key)
        #[arg(long = "key")]
        signing_key: Option<String>,
        /// Active key id whose configured private key signs the roster commit
        #[arg(long = "key-id")]
        signing_key_id: Option<String>,
        /// Skip re-signing affected channel and release tags; print them
        /// for manual handling instead
        #[arg(long = "no-resign")]
        no_resign: bool,
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

/// Channel rollout subcommands.
#[derive(Subcommand)]
pub enum ChannelCommand {
    /// Initialize all channel partitions at one release
    Init {
        /// Channel name
        channel: String,
        /// Semver release tag
        semver: String,
        /// Signing key
        #[arg(long)]
        key: Option<String>,
        /// Resolve signing key path from [registry.signing_keys] by keys.toml id
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Advance channel partitions to a release
    Advance {
        /// Channel name
        channel: String,
        /// Semver release tag
        semver: String,
        /// Number of partitions to advance by ascending fill
        #[arg(long)]
        count: Option<usize>,
        /// Explicit comma-separated partition list, decimal or hex
        #[arg(long)]
        partitions: Option<String>,
        /// Signing key
        #[arg(long)]
        key: Option<String>,
        /// Resolve signing key path from [registry.signing_keys] by keys.toml id
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show channel partition state
    Status {
        /// Channel name
        channel: String,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// `store/` realisation-graph subcommands (RFC-0005).
#[derive(Subcommand)]
pub enum StoreCommand {
    /// Bless a store path's local content (whole closure) into the graph
    Bless {
        /// Nix store path whose closure to record
        store_path: String,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Custom commit message
        #[arg(long)]
        message: Option<String>,
        /// Private key path used to sign the commit
        #[arg(long)]
        key: Option<String>,
        /// Active key id whose configured private key signs the commit
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Revoke a blessed realisation (stops the bytes verifying on next sync)
    Revoke {
        /// Store path or bare store-path hash to revoke
        store_path: String,
        /// Specific CA realisation to revoke (all realisations if omitted)
        #[arg(long)]
        realisation: Option<String>,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Custom commit message
        #[arg(long)]
        message: Option<String>,
        /// Private key path used to sign the commit
        #[arg(long)]
        key: Option<String>,
        /// Active key id whose configured private key signs the commit
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Check graph health and closure coverage
    Verify {
        /// Also recompute local store NAR hashes and require blessed matches
        #[arg(long)]
        deep: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Record every published closure from the local Nix store in one pass
    Backfill {
        /// Bless additional content for paths already recorded with different
        /// bits instead of failing
        #[arg(long)]
        bless: bool,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Custom commit message
        #[arg(long)]
        message: Option<String>,
        /// Private key path used to sign the commit
        #[arg(long)]
        key: Option<String>,
        /// Active key id whose configured private key signs the commit
        #[arg(long = "key-id")]
        key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// Static cache subcommands.
#[derive(Subcommand)]
pub enum CacheCommand {
    /// Generate static narinfo/NAR files for every registry store path
    Generate {
        /// Output directory for generated static cache files
        #[arg(long)]
        output: PathBuf,
        /// Nix narinfo signing key file in `name:base64-secret` form
        #[arg(long)]
        key: Option<PathBuf>,
        /// Public cache URL to write into committed registry.toml [[caches]]
        #[arg(long)]
        cache_url: Option<String>,
        /// Backend URL to upload generated files to; repeat for multiple destinations
        /// (file://, s3://, sftp://, http://; default: the upload_urls persisted by
        /// `origin config`)
        #[arg(long = "upload-url")]
        upload_urls: Vec<String>,
        /// Authentication and backend-specific upload options
        #[command(flatten)]
        auth: CacheUploadAuthArgs,
        /// Priority for generated nix-cache-info and registry [[caches]]
        #[arg(long, default_value = "40")]
        priority: u32,
        /// Do not commit registry.toml after updating [[caches]]
        #[arg(long)]
        no_commit: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// Static git-origin subcommands.
#[derive(Subcommand)]
pub enum OriginCommand {
    /// Upload the dumb-HTTP git origin surface to one or more destinations
    Upload {
        /// Backend URL to upload static origin files to; repeat for multiple destinations
        /// (file://, s3://, sftp://, http://; default: the upload_urls persisted by
        /// `origin config`)
        #[arg(long = "upload-url")]
        upload_urls: Vec<String>,
        /// Optional generated static Nix-cache directory to upload beside the git origin
        #[arg(long = "cache-dir")]
        cache_dir: Option<PathBuf>,
        /// Authentication and backend-specific upload options
        #[command(flatten)]
        auth: CacheUploadAuthArgs,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show or persist producer upload defaults ([registry.upload_auth]) for `origin upload`, `cache generate`, and `release`
    Config {
        /// Default backend URL to upload to; repeat for multiple destinations,
        /// replaces the stored list (file://, s3://, sftp://, http://)
        #[arg(long = "upload-url")]
        upload_urls: Vec<String>,
        /// AOS provisioning token for AOS cache backends
        #[arg(long)]
        token: Option<String>,
        /// AOS cache view
        #[arg(long)]
        view: Option<String>,
        /// Basic auth username for generic HTTP caches
        #[arg(long)]
        http_user: Option<String>,
        /// Basic auth password for generic HTTP caches
        #[arg(long)]
        http_password: Option<String>,
        /// Arbitrary HTTP header (repeatable, replaces the stored list)
        #[arg(long)]
        header: Vec<String>,
        /// AWS region
        #[arg(long)]
        s3_region: Option<String>,
        /// AWS credentials profile name
        #[arg(long)]
        s3_profile: Option<String>,
        /// Custom S3-compatible endpoint (MinIO, B2, etc.)
        #[arg(long)]
        s3_endpoint: Option<String>,
        /// Path to SSH private key
        #[arg(long)]
        ssh_key: Option<String>,
        /// SSH password
        #[arg(long)]
        ssh_password: Option<String>,
        /// Always prompt for the SSH password interactively
        #[arg(long)]
        ssh_ask_pass: bool,
        /// Remove a stored setting (repeatable)
        #[arg(long, value_name = "FIELD", value_enum)]
        unset: Vec<UploadConfigField>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
}

/// A `[registry.upload_auth]` field name accepted by
/// `apr origin config --unset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum UploadConfigField {
    /// The stored default upload destinations.
    UploadUrls,
    /// The AOS provisioning token.
    Token,
    /// The AOS cache view.
    View,
    /// The HTTP basic-auth username.
    HttpUser,
    /// The HTTP basic-auth password.
    HttpPassword,
    /// The stored extra HTTP headers.
    Headers,
    /// The AWS region.
    S3Region,
    /// The AWS credentials profile name.
    S3Profile,
    /// The custom S3-compatible endpoint.
    S3Endpoint,
    /// The SSH private key path.
    SshKey,
    /// The SSH password.
    SshPassword,
    /// The interactive SSH password prompt flag.
    SshAskPass,
}

/// Authentication flags for registry static-cache uploads.
#[derive(Debug, Clone, Args, Default)]
pub struct CacheUploadAuthArgs {
    /// AOS provisioning token (AOS_TOKEN env)
    #[arg(long, env = "AOS_TOKEN")]
    pub token: Option<String>,
    /// AOS cache view (default: "default", AOS_VIEW env)
    #[arg(long, env = "AOS_VIEW")]
    pub view: Option<String>,
    /// Basic auth username for generic HTTP caches
    #[arg(long)]
    pub http_user: Option<String>,
    /// Basic auth password (AOS_HTTP_PASSWORD env)
    #[arg(long, env = "AOS_HTTP_PASSWORD")]
    pub http_password: Option<String>,
    /// Arbitrary HTTP header (repeatable, e.g. "Authorization: Bearer ...")
    #[arg(long)]
    pub header: Vec<String>,
    /// AWS region
    #[arg(long, env = "AWS_REGION")]
    pub s3_region: Option<String>,
    /// AWS credentials profile name
    #[arg(long)]
    pub s3_profile: Option<String>,
    /// Custom S3-compatible endpoint (MinIO, B2, etc.)
    #[arg(long)]
    pub s3_endpoint: Option<String>,
    /// Path to SSH private key
    #[arg(long)]
    pub ssh_key: Option<String>,
    /// SSH password (AOS_SSH_PASSWORD env)
    #[arg(long, env = "AOS_SSH_PASSWORD")]
    pub ssh_password: Option<String>,
    /// Prompt for SSH password interactively
    #[arg(long)]
    pub ssh_ask_pass: bool,
}

impl CacheUploadAuthArgs {
    /// Convert these CLI flags into backend [`aos_cache::AuthOptions`],
    /// without any configuration-file defaults.
    ///
    /// Equivalent to [`Self::auth_options_with_config`] with `None`.
    pub fn auth_options(&self) -> aos_cache::AuthOptions {
        self.auth_options_with_config(None)
    }

    /// Convert these CLI flags into backend [`aos_cache::AuthOptions`],
    /// layered over optional `[registry.upload_auth]` config defaults.
    ///
    /// Config values (when present) seed the result; any flag the user set on
    /// the command line (or via its env binding) overrides the corresponding
    /// config value. `ssh_ask_pass` is OR-ed, and the cache view falls back to
    /// `"default"` when neither source sets it.
    pub fn auth_options_with_config(
        &self,
        config: Option<&RegistryUploadAuthConfig>,
    ) -> aos_cache::AuthOptions {
        let mut auth = config
            .map(RegistryUploadAuthConfig::auth_options)
            .unwrap_or_else(|| aos_cache::AuthOptions {
                view: "default".to_string(),
                ..aos_cache::AuthOptions::default()
            });

        if let Some(token) = &self.token {
            auth.token = Some(token.clone());
        }
        if let Some(view) = &self.view {
            auth.view = view.clone();
        }
        if let Some(http_user) = &self.http_user {
            auth.http_user = Some(http_user.clone());
        }
        if let Some(http_password) = &self.http_password {
            auth.http_password = Some(http_password.clone());
        }
        if !self.header.is_empty() {
            auth.headers = self.header.clone();
        }
        if let Some(s3_region) = &self.s3_region {
            auth.s3_region = Some(s3_region.clone());
        }
        if let Some(s3_profile) = &self.s3_profile {
            auth.s3_profile = Some(s3_profile.clone());
        }
        if let Some(s3_endpoint) = &self.s3_endpoint {
            auth.s3_endpoint = Some(s3_endpoint.clone());
        }
        if let Some(ssh_key) = &self.ssh_key {
            auth.ssh_key = Some(ssh_key.clone());
        }
        if let Some(ssh_password) = &self.ssh_password {
            auth.ssh_password = Some(ssh_password.clone());
        }
        auth.ssh_ask_pass = auth.ssh_ask_pass || self.ssh_ask_pass;
        if auth.view.is_empty() {
            auth.view = "default".to_string();
        }

        auth
    }
}

/// Convert mutually-exclusive kernel mode flags into a [`KernelUpgradeMode`].
///
/// Clap's `kernel_mode` arg group guarantees at most one flag is set; with
/// none set the default [`KernelUpgradeMode::Advisory`] is returned.
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
///
/// Loads the [`config::ApmConfig`] for the scope implied by the command
/// (`--system` selects [`ProfileScope::System`]) and dispatches to the
/// matching module. The hidden `_test-systemd-client` and
/// `activate-{pre,post}-etc-swap` subcommands are dispatched *before* config
/// loading; the activate pair terminates the process directly via
/// `std::process::exit` so its 0/1/2 exit-code contract reaches the caller
/// unflattened.
///
/// # Errors
///
/// Returns an error when configuration loading fails or when the dispatched
/// subcommand fails (resolution, download, verification, activation,
/// registry operations, ...). User cancellation at a confirmation prompt is
/// reported as [`aos_core::error::AosError::UserCancelled`].
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
            download_only,
            no_deps,
            system: install_system,
            image: image_fmt,
            output: image_output,
            reinstall,
            ignore_sysroot_lock,
            kexec,
            reboot,
            live,
            drain,
            ..
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(ignore_sysroot_lock.as_deref());
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
                install::run(
                    &config,
                    packages,
                    registry.as_deref(),
                    *reinstall,
                    false,
                    *download_only,
                    *no_deps,
                    dry_run,
                    yes,
                    &ignore,
                    printer,
                )
                .await
            }
        }
        PackageCommand::Remove {
            packages,
            autoremove,
        } => {
            let auto_remove = *autoremove || config.settings.auto_autoremove;
            let outcome =
                remove::run(&config, packages, auto_remove, dry_run, yes, printer).await?;
            if config.settings.auto_gc && auto_remove && !dry_run && outcome.orphan_count > 0 {
                clean::run_gc_after_mutation(printer).await?;
            }
            Ok(())
        }
        PackageCommand::Autoremove => {
            let outcome = remove::run_autoremove(&config, dry_run, yes, printer).await?;
            if config.settings.auto_gc && !dry_run && outcome.orphan_count > 0 {
                clean::run_gc_after_mutation(printer).await?;
            }
            Ok(())
        }
        PackageCommand::Reinstall {
            packages,
            ignore_sysroot_lock,
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(ignore_sysroot_lock.as_deref());
            install::run(
                &config, packages, None, true, true, false, false, dry_run, yes, &ignore, printer,
            )
            .await
        }
        PackageCommand::Update { registry, .. } => {
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
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(ignore_sysroot_lock.as_deref());
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
            query::search(
                &config,
                pattern,
                *names_only,
                *installed,
                registry.as_deref(),
                printer,
            )
            .await
        }
        PackageCommand::Show { package, registry } => {
            query::show(&config, package, registry.as_deref(), printer).await
        }
        PackageCommand::List {
            installed,
            upgradable,
            held,
            registry,
        } => {
            query::list(
                &config,
                *installed,
                *upgradable,
                *held,
                registry.as_deref(),
                printer,
            )
            .await
        }
        PackageCommand::Depends { package } => deps::depends(&config, package, printer).await,
        PackageCommand::Rdepends { package } => deps::rdepends(&config, package, printer).await,
        PackageCommand::Policy { package } => deps::policy(&config, package, printer).await,
        PackageCommand::Files { package } => deps::files(&config, package, printer).await,
        PackageCommand::Hold { package } => hold::run_hold(&config, package, printer).await,
        PackageCommand::Unhold { package } => hold::run_unhold(&config, package, printer).await,
        PackageCommand::Held => hold::run_held(&config, printer).await,
        PackageCommand::Orphans => query::orphans(&config, printer).await,
        PackageCommand::Clean { generations, keep } => {
            clean::run(&config, *generations, *keep, printer).await
        }
        PackageCommand::Gc => clean::run_gc(printer).await,
        PackageCommand::Verify { package } => source::run_verify(&config, package, printer).await,
        PackageCommand::Source {
            package,
            show_drv,
            fetch,
            verify,
        } => source::run_source(&config, package, *show_drv, *fetch, *verify, printer).await,
        PackageCommand::Rollback {
            generation,
            system: rollback_system,
            list: rollback_list,
            kexec,
            reboot,
            live,
            drain,
        } => {
            if *rollback_system {
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
            } else if *rollback_list {
                rollback::list(&config, printer).await
            } else {
                rollback::run(&config, *generation, dry_run, printer).await
            }
        }
        PackageCommand::Registry { command, .. } => run_registry(&config, command, printer).await,
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

/// Dispatch an `apm registry` / `apr` subcommand to its handler.
///
/// The consumer-facing lifecycle commands (`list`, `add`, `remove`) are
/// implemented in this module; everything else delegates to [`registry_ops`].
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
            channel,
            tag,
            version,
            trust_key,
            no_verify,
            no_clone,
        } => {
            registry_add(
                config,
                url,
                name.as_deref(),
                *priority,
                commit.as_deref(),
                branch.as_deref(),
                channel.as_deref(),
                tag.as_deref(),
                version.as_deref(),
                trust_key.as_deref(),
                *no_verify,
                !no_clone,
                printer,
            )
            .await
        }
        RegistryCommand::Remove {
            name,
            keep_local,
            force,
        } => registry_remove(config, name, *keep_local, *force, printer).await,
        RegistryCommand::Enable { name } => registry_set_enabled(config, name, true, printer).await,
        RegistryCommand::Disable { name } => {
            registry_set_enabled(config, name, false, printer).await
        }
        RegistryCommand::Trust { command } => registry_ops::run_trust(config, command, printer),
        RegistryCommand::Keys { command } => registry_ops::run_keys(config, command, printer),
        RegistryCommand::Create {
            name,
            remote,
            trust_key,
            trust_key_id,
            key,
            key_id,
        } => {
            registry_ops::create(
                config,
                name,
                remote.as_deref(),
                trust_key.as_deref(),
                trust_key_id.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                printer,
            )
            .await
        }
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
            source_drv,
            images,
            image_formats,
            bless,
            no_ca,
            no_commit,
            message,
            key,
            key_id,
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
                source_drv.as_deref(),
                images,
                image_formats,
                *bless,
                *no_ca,
                *no_commit,
                message.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
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
            key,
            key_id,
            registry,
        } => {
            registry_ops::unpublish(
                config,
                package,
                version.as_deref(),
                platform.as_deref(),
                *no_commit,
                message.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
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
        } => registry_ops::diff(config, *stat, *remote, registry.as_deref(), printer).await,
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
        } => registry_ops::log(config, package.as_deref(), *n, registry.as_deref(), printer).await,
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
        RegistryCommand::Channel { command } => {
            registry_ops::run_channel(config, command, printer).await
        }
        RegistryCommand::Cache { command } => {
            registry_ops::run_cache(config, command, printer).await
        }
        RegistryCommand::Store { command } => {
            registry_ops::run_store(config, command, printer).await
        }
        RegistryCommand::Origin { command } => {
            registry_ops::run_origin(config, command, printer).await
        }
        RegistryCommand::Release {
            semver,
            store_path,
            name,
            platform,
            description,
            homepage,
            license,
            maintainer,
            sysroot,
            previous,
            source_drv,
            images,
            image_formats,
            bless,
            message,
            channel,
            init_channel,
            count,
            partitions,
            key,
            key_id,
            cache_output,
            cache_key,
            cache_url,
            cache_priority,
            upload_urls,
            auth,
            dry_run,
            resume,
            registry,
        } => {
            registry_ops::release(
                config,
                semver,
                store_path.as_deref(),
                name.as_deref(),
                platform.as_deref(),
                description.as_deref(),
                homepage.as_deref(),
                license.as_deref(),
                maintainer.as_deref(),
                *sysroot,
                previous.as_deref(),
                source_drv.as_deref(),
                images,
                image_formats,
                *bless,
                message.as_deref(),
                channel.as_deref(),
                *init_channel,
                *count,
                partitions.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                cache_output.as_deref(),
                cache_key.as_deref(),
                cache_url.as_deref(),
                *cache_priority,
                upload_urls,
                auth,
                *dry_run,
                *resume,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Tag {
            name,
            message,
            key,
            key_id,
            registry,
        } => {
            registry_ops::tag(
                config,
                name,
                message.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Sign {
            tag,
            key,
            key_id,
            registry,
        } => {
            registry_ops::sign(
                config,
                tag.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
    }
}

/// `apr list` — print every configured registry (name, URL, priority,
/// transport, tracking mode, package count, sync state), plus any local
/// authoring clones that have no `registries.d/` entry.
async fn registry_list(config: &config::ApmConfig, printer: &Printer) -> Result<()> {
    let configured_names: Vec<&str> = config
        .registries
        .iter()
        .map(|(cfg, _)| cfg.name.as_str())
        .collect();
    let local = registry_ops::local_registries(&config.scope.registries_path(), &configured_names);

    if printer.mode() == OutputMode::Json {
        let cache_dir = config.cache_path();
        let registries = config
            .registries
            .iter()
            .map(|(reg_config, state)| {
                let tracking = reg_config
                    .tracking_mode()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|_| "invalid".to_string());
                let packages_dir = cache_dir.join(&reg_config.name).join("packages");
                let signing_required = reg_config.signing.as_ref().map(|signing| signing.required);
                serde_json::json!({
                    "name": &reg_config.name,
                    "url": &reg_config.url,
                    "priority": reg_config.priority,
                    "enabled": reg_config.enabled,
                    "status": if reg_config.enabled { "enabled" } else { "disabled" },
                    "transport": format!("{:?}", reg_config.transport()),
                    "tracking": tracking,
                    "packages": count_packages_in_dir(&packages_dir),
                    "last_update": state.as_ref().and_then(|state| state.last_update.as_ref()),
                    "last_commit": state.as_ref().and_then(|state| state.last_commit.as_ref()),
                    "signing_required": signing_required,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!(registries));
        return Ok(());
    }

    if config.registries.is_empty() {
        printer.info(&format!(
            "No registries configured. Add one with `{} add <url>`.",
            aos_core::invocation::package_registry_command()
        ));
        print_local_registries(&local, printer);
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

        printer.header(&format!(
            "  {} (priority {})",
            reg_config.name, reg_config.priority
        ));
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
            printer.kv(
                "Last update",
                &format!(
                    "never (run `{} update`)",
                    aos_core::invocation::package_manager_command()
                ),
            );
        }

        if let Some(ref signing) = reg_config.signing {
            printer.kv("Signing", &format!("required={}", signing.required));
        }

        printer.plain("");
    }

    print_local_registries(&local, printer);

    Ok(())
}

/// Print the `apr list` section for local clones that have no
/// `registries.d/` entry — typically registries authored with `apr create`,
/// which are otherwise invisible to consumer-side commands.
fn print_local_registries(local: &[registry_ops::LocalRegistry], printer: &Printer) {
    if local.is_empty() {
        return;
    }

    printer.header("Local registries (not configured):");
    printer.plain("");

    for reg in local {
        printer.header(&format!("  {}", reg.name));
        printer.kv("Path", &reg.path.display().to_string());
        if let Some(ref origin) = reg.origin {
            printer.kv("Remote", origin);
        }
        printer.kv("Packages", &reg.packages.to_string());
        printer.plain("");
    }

    printer.info(&format!(
        "Local registries are not used for installs until configured with `{} add <url>`.",
        aos_core::invocation::package_registry_command()
    ));
}

/// `apr add` — register a registry by writing `registries.d/<name>.toml`
/// (with at most one tracking field and optional `[registry.signing]`),
/// pinning the `--trust-key` if given, then syncing the initial clone unless
/// `--no-clone` was passed. A failed initial sync is non-fatal.
struct RegistryAddConfigToml<'a> {
    name: &'a str,
    url: &'a str,
    priority: u32,
    commit: Option<&'a str>,
    branch: Option<&'a str>,
    channel: Option<&'a str>,
    tag: Option<&'a str>,
    version: Option<&'a str>,
    trusted_key: Option<&'a security::TrustedKey>,
    no_verify: bool,
}

fn registry_add_config_toml(config: RegistryAddConfigToml<'_>) -> Result<String> {
    let mut registry = toml::map::Map::new();
    registry.insert("name".into(), toml::Value::String(config.name.to_string()));
    registry.insert("url".into(), toml::Value::String(config.url.to_string()));
    registry.insert(
        "priority".into(),
        toml::Value::Integer(config.priority.into()),
    );
    registry.insert("enabled".into(), toml::Value::Boolean(true));

    if let Some(commit) = config.commit {
        registry.insert("commit".into(), toml::Value::String(commit.to_string()));
    } else if let Some(branch) = config.branch {
        registry.insert("branch".into(), toml::Value::String(branch.to_string()));
    } else if let Some(channel) = config.channel {
        registry.insert("channel".into(), toml::Value::String(channel.to_string()));
    } else if let Some(tag) = config.tag {
        registry.insert("tag".into(), toml::Value::String(tag.to_string()));
    } else if let Some(version) = config.version {
        registry.insert("version".into(), toml::Value::String(version.to_string()));
    }

    if let Some(key) = config.trusted_key {
        let mut signing = toml::map::Map::new();
        signing.insert("required".into(), toml::Value::Boolean(true));
        signing.insert(
            "public_key".into(),
            toml::Value::String(format!(
                "{}:{}:{}",
                key.registry, key.algorithm, key.public_key
            )),
        );
        registry.insert("signing".into(), toml::Value::Table(signing));
    } else if config.no_verify {
        let mut signing = toml::map::Map::new();
        signing.insert("required".into(), toml::Value::Boolean(false));
        registry.insert("signing".into(), toml::Value::Table(signing));
    }

    let mut root = toml::map::Map::new();
    root.insert("registry".into(), toml::Value::Table(registry));
    Ok(toml::to_string_pretty(&toml::Value::Table(root))?)
}

#[allow(clippy::too_many_arguments)]
async fn registry_add(
    config: &config::ApmConfig,
    url: &str,
    name_override: Option<&str>,
    priority: u32,
    commit: Option<&str>,
    branch: Option<&str>,
    channel: Option<&str>,
    tag: Option<&str>,
    version: Option<&str>,
    trust_key: Option<&str>,
    no_verify: bool,
    clone: bool,
    printer: &Printer,
) -> Result<()> {
    let name = name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| derive_registry_name(url));
    validate_registry_name(&name)?;

    if config.find_registry(&name).is_some() {
        bail!(
            "registry '{}' already exists. Remove it first with `{} remove {}`.",
            name,
            aos_core::invocation::package_registry_command(),
            name
        );
    }

    if let Some(c) = commit {
        validate_commit_hash(c)?;
    }
    // Validate version constraint if provided.
    if let Some(v) = version {
        semver::VersionReq::parse(v)
            .map_err(|e| anyhow::anyhow!("invalid version constraint '{}': {}", v, e))?;
    }
    if let Some(b) = branch {
        validate_branch_name(b)?;
    }
    if let Some(c) = channel {
        validate_channel_name(c)?;
    }
    if let Some(t) = tag {
        validate_git_ref_name(t)?;
    }
    let trusted_key = trust_key
        .map(|key| {
            let (registry, algorithm, public_key) = security::parse_signing_key(key)?;
            if registry != name {
                bail!(
                    "--trust-key belongs to registry '{}', expected '{}'",
                    registry,
                    name,
                );
            }
            Ok(security::TrustedKey {
                registry,
                algorithm,
                fingerprint: security::key_fingerprint(&public_key),
                public_key,
                source: security::KeySource::Tofu,
            })
        })
        .transpose()?;

    printer.header(&format!("Adding registry '{name}'..."));
    printer.kv("URL", url);
    printer.kv("Priority", &priority.to_string());

    let config_dir = config.scope.config_dir();
    let registries_dir = config_dir.join("registries.d");
    fs::create_dir_all(&registries_dir)
        .with_context(|| format!("creating {}", registries_dir.display()))?;

    let toml_path = registries_dir.join(format!("{name}.toml"));

    let tracking = if let Some(c) = commit {
        format!("commit:{}", c.chars().take(12).collect::<String>())
    } else if let Some(b) = branch {
        format!("branch:{b}")
    } else if let Some(c) = channel {
        format!("channel:{c}")
    } else if let Some(t) = tag {
        format!("tag:{t}")
    } else if let Some(v) = version {
        format!("version:{v}")
    } else {
        "default".to_string()
    };

    if tracking != "default" {
        printer.kv("Tracking", &tracking);
    }
    if no_verify && trusted_key.is_none() {
        // Verification is fail-closed by default; the explicit opt-out is
        // recorded in the config so the choice is visible and auditable.
        printer.kv("Signing", "verification disabled (--no-verify)");
    }

    let toml_content = registry_add_config_toml(RegistryAddConfigToml {
        name: &name,
        url,
        priority,
        commit,
        branch,
        channel,
        tag,
        version,
        trusted_key: trusted_key.as_ref(),
        no_verify,
    })?;
    fs::write(&toml_path, &toml_content)
        .with_context(|| format!("writing {}", toml_path.display()))?;
    if let Some(key) = &trusted_key {
        security::KeyStore::new(config.scope.trusted_keys_dirs()).store(key)?;
        printer.kv("Signing", "trusted key pinned");
    }

    let pkg_cmd = aos_core::invocation::package_manager_command();

    if !clone {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "action": "registry_add",
                "status": "added",
                "registry": &name,
                "name": &name,
                "url": url,
                "priority": priority,
                "enabled": true,
                "tracking": &tracking,
                "clone": false,
                "synced": false,
                "config": toml_path.to_string_lossy(),
                "signing_required": !no_verify,
                "verification_disabled": no_verify,
                "trusted_key_pinned": trusted_key.is_some(),
            }));
            return Ok(());
        }
        printer.success(&format!(
            "Registry '{name}' added. Run `{pkg_cmd} update --registry {name}` to sync package metadata."
        ));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' added."));

    if aos_core::invocation::binary_name() == "apr" {
        materialize_authoring_clone(config, &name, url, branch, tag, commit, printer)?;
    }

    // Materialise the local clone under the scope's registry-storage directory
    // by syncing now. The config was just written to disk, so reload the scope
    // to pick it up and reuse the regular update path (clone/fetch + state
    // save-back). A sync failure is non-fatal: the registry is registered and
    // can be retried with `<pkg> update`.
    let synced = config::ApmConfig::load(config.scope)?;
    let sync_printer = if printer.mode() == OutputMode::Json {
        Printer::new(0, true, false)
    } else {
        printer.clone()
    };
    let sync_result = update::run(&synced, Some(&name), &sync_printer).await;
    if let Err(e) = sync_result {
        if printer.mode() == OutputMode::Json {
            let packages_dir = config.cache_path().join(&name).join("packages");
            printer.json(&serde_json::json!({
                "action": "registry_add",
                "status": "added",
                "registry": &name,
                "name": &name,
                "url": url,
                "priority": priority,
                "enabled": true,
                "tracking": &tracking,
                "clone": true,
                "synced": false,
                "sync_error": e.to_string(),
                "packages": count_packages_in_dir(&packages_dir),
                "config": toml_path.to_string_lossy(),
                "signing_required": !no_verify,
                "verification_disabled": no_verify,
                "trusted_key_pinned": trusted_key.is_some(),
            }));
            return Ok(());
        }
        printer.warning(&format!(
            "Registry '{name}' was added, but the initial sync failed: {e}\n\
             Retry with `{pkg_cmd} update --registry {name}`."
        ));
    }
    if printer.mode() == OutputMode::Json {
        let reloaded = config::ApmConfig::load(config.scope)?;
        let state = reloaded
            .registries
            .iter()
            .find(|(cfg, _)| cfg.name == name)
            .and_then(|(_, state)| state.as_ref());
        let packages_dir = config.cache_path().join(&name).join("packages");
        printer.json(&serde_json::json!({
            "action": "registry_add",
            "status": "added",
            "registry": &name,
            "name": &name,
            "url": url,
            "priority": priority,
            "enabled": true,
            "tracking": &tracking,
            "clone": true,
            "synced": true,
            "sync_error": null,
            "packages": count_packages_in_dir(&packages_dir),
            "last_commit": state.and_then(|state| state.last_commit.as_ref()),
            "config": toml_path.to_string_lossy(),
            "signing_required": !no_verify,
            "verification_disabled": no_verify,
            "trusted_key_pinned": trusted_key.is_some(),
        }));
    }

    Ok(())
}

/// Materializes the writable producer clone used by `apr add`.
fn materialize_authoring_clone(
    config: &config::ApmConfig,
    name: &str,
    url: &str,
    branch: Option<&str>,
    tag: Option<&str>,
    commit: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let clone_dir = config.scope.registries_path().join(name);
    if clone_dir.join(".git").is_dir() {
        return Ok(());
    }
    if clone_dir.exists() {
        fs::remove_dir_all(&clone_dir).with_context(|| {
            format!(
                "removing consumer metadata tree before cloning {}",
                clone_dir.display()
            )
        })?;
    }
    if let Some(parent) = clone_dir.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let mut clone = gitcmd::transport();
    clone.args(["clone", "--no-checkout", url]);
    clone.arg(&clone_dir);
    run_git_command(clone, format!("cloning registry '{name}' from {url}"))?;

    if let Some(branch) = branch {
        let remote_branch = format!("origin/{branch}");
        let mut checkout = gitcmd::hermetic();
        checkout
            .current_dir(&clone_dir)
            .args(["checkout", "-B", branch, &remote_branch]);
        run_git_command(checkout, format!("checking out branch '{branch}'"))?;
    } else if let Some(tag) = tag {
        let mut checkout = gitcmd::hermetic();
        checkout.current_dir(&clone_dir).args(["checkout", tag]);
        run_git_command(checkout, format!("checking out tag '{tag}'"))?;
    } else if let Some(commit) = commit {
        let mut checkout = gitcmd::hermetic();
        checkout
            .current_dir(&clone_dir)
            .args(["checkout", "--detach", commit]);
        run_git_command(checkout, format!("checking out commit '{commit}'"))?;
    } else {
        let mut checkout = gitcmd::hermetic();
        checkout.current_dir(&clone_dir).arg("checkout");
        run_git_command(checkout, "checking out remote HEAD")?;
    }

    printer.info(&format!("Authoring clone ready at {}", clone_dir.display()));
    Ok(())
}

fn run_git_command(mut command: Command, context: impl Into<String>) -> Result<()> {
    let context = context.into();
    let output = command
        .output()
        .with_context(|| format!("running git command while {context}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    bail!("{} failed: {}", context, stderr);
}

/// `apr remove` — delete a registry's config file, metadata cache, local
/// clone (unless `--keep-local`), and pinned trusted keys.
///
/// Refuses to delete an authoring clone with uncommitted or unpushed work
/// unless `--force` is passed. Installed packages are deliberately left
/// untouched; they become orphans visible via `apm orphans`.
async fn registry_remove(
    config: &config::ApmConfig,
    name: &str,
    keep_local: bool,
    force: bool,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let clone_dir = config.scope.registries_path().join(name);

    // A registry can exist as a local authoring clone (`apr create`) without
    // a registries.d entry; accept those too so everything `apr list` shows
    // can be removed.
    if config.find_registry(name).is_none() && !clone_dir.is_dir() {
        return Err(AosError::RegistryError {
            message: format!("registry '{name}' not found"),
        }
        .into());
    }

    if !keep_local
        && !force
        && let Some(reason) = registry_ops::authoring_clone_precious(&clone_dir)?
    {
        return Err(AosError::RegistryError {
            message: format!(
                "registry '{name}' has a local authoring clone at {} with {reason}.\n\
                 Push it first, keep it with --keep-local, or delete it anyway with --force.",
                clone_dir.display(),
            ),
        }
        .into());
    }

    // Removing a registry is a config operation over user-owned paths
    // (`registries.d/`, the local clone, the metadata cache, trusted keys). It
    // deliberately does NOT touch the package profile under
    // `/var/lib/profiles`: that is `apm`'s domain, requires privileges an
    // unprivileged `apr` invocation may not have, and gating a config delete on
    // installed-package state conflates the two tools. Any packages still
    // installed from this registry become orphans; `apm orphans` surfaces them.
    let toml_path = registry_config_path_for_removal(config, name)?;
    let toml_existed = toml_path.exists();

    if toml_path.exists() {
        fs::remove_file(&toml_path).with_context(|| format!("removing {}", toml_path.display()))?;
    }

    let mut cache_removed = false;
    let mut local_removed = false;
    if !keep_local {
        let cache_dir = config.cache_path().join(name);
        if cache_dir.exists() {
            let _ = fs::remove_dir_all(&cache_dir);
            cache_removed = !cache_dir.exists();
        }

        if clone_dir.exists() {
            let _ = fs::remove_dir_all(&clone_dir);
            local_removed = !clone_dir.exists();
        }
    }

    let trusted_keys_removed = trusted_key_dir_sets_for_registry_removal(config, &toml_path)
        .into_iter()
        .try_fold(false, |removed, dirs| {
            security::KeyStore::new(dirs)
                .remove(name)
                .map(|current| removed || current)
        })?;

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "registry_remove",
            "status": "removed",
            "registry": name,
            "name": name,
            "keep_local": keep_local,
            "force": force,
            "config": toml_path.to_string_lossy(),
            "config_removed": toml_existed && !toml_path.exists(),
            "local": clone_dir.to_string_lossy(),
            "local_removed": local_removed,
            "cache_removed": cache_removed,
            "trusted_keys_removed": trusted_keys_removed,
            "orphan_command": format!("{} orphans", aos_core::invocation::package_manager_command()),
        }));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' removed."));
    printer.info(&format!(
        "Any packages installed from '{name}' are now orphaned; review them with `{} orphans`.",
        aos_core::invocation::package_manager_command()
    ));

    Ok(())
}

/// `apm registry enable|disable` — toggle whether a registry participates in
/// resolution and updates, while keeping its config, local clone, cache, and
/// trusted keys intact.
async fn registry_set_enabled(
    config: &config::ApmConfig,
    name: &str,
    enabled: bool,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let (reg_config, state) =
        config
            .find_registry(name)
            .ok_or_else(|| AosError::RegistryError {
                message: format!("registry '{name}' not found"),
            })?;

    let toml_path = config.registry_config_path_for_update(name);
    let previous_enabled = reg_config.enabled;
    write_registry_enabled(&toml_path, reg_config, state.as_ref(), enabled)?;

    let action = if enabled {
        "registry_enable"
    } else {
        "registry_disable"
    };
    let status = if previous_enabled == enabled {
        "unchanged"
    } else if enabled {
        "enabled"
    } else {
        "disabled"
    };

    if printer.mode() == OutputMode::Json {
        let packages_dir = config.cache_path().join(name).join("packages");
        printer.json(&serde_json::json!({
            "action": action,
            "status": status,
            "registry": name,
            "name": name,
            "enabled": enabled,
            "previous_enabled": previous_enabled,
            "changed": previous_enabled != enabled,
            "config": toml_path.to_string_lossy(),
            "packages": count_packages_in_dir(&packages_dir),
        }));
        return Ok(());
    }

    match (enabled, previous_enabled == enabled) {
        (true, true) => printer.info(&format!("Registry '{name}' is already enabled.")),
        (true, false) => printer.success(&format!("Registry '{name}' enabled.")),
        (false, true) => printer.info(&format!("Registry '{name}' is already disabled.")),
        (false, false) => printer.success(&format!("Registry '{name}' disabled.")),
    }

    Ok(())
}

/// Persist a registry's `enabled` flag, preserving the rest of its config.
fn write_registry_enabled(
    path: &std::path::Path,
    reg_config: &types::RegistryConfig,
    state: Option<&types::RegistryState>,
    enabled: bool,
) -> Result<()> {
    if path.exists() {
        let content =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut value: toml::Value =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        let registry = value
            .get_mut("registry")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| anyhow::anyhow!("{}: missing [registry] table", path.display()))?;
        registry.insert("enabled".into(), toml::Value::Boolean(enabled));
        let rendered = toml::to_string_pretty(&value)?;
        fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;
        return Ok(());
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let mut reg_config = reg_config.clone();
    reg_config.enabled = enabled;
    let mut registry = match toml::Value::try_from(reg_config)? {
        toml::Value::Table(table) => table,
        _ => bail!("registry config did not serialize as a TOML table"),
    };
    if let Some(state) = state {
        registry.insert("state".into(), toml::Value::try_from(state)?);
    }
    let mut root = toml::map::Map::new();
    root.insert("registry".into(), toml::Value::Table(registry));
    let rendered = toml::to_string_pretty(&toml::Value::Table(root))?;
    fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a registry name from its URL: the last path segment with any
/// trailing `/` or `.git` stripped, filtered to `[A-Za-z0-9_-]`.
fn derive_registry_name(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    let name = cleaned.rsplit('/').next().unwrap_or("unknown");
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
}

/// Count package TOML files in a registry's sharded `packages/` directory
/// (`packages/<first-letter>/<name>.toml`). Unreadable directories count as
/// zero rather than erroring — this only feeds informational output.
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

/// Return the registry config file that `registry remove` should delete.
///
/// Removing a user-level config has different semantics than updating it:
/// when a same-name system config exists underneath, deleting only the user
/// layer would make the registry reappear from the fallback. Treat that as an
/// ambiguous removal instead of reporting success for a registry that remains
/// visible.
fn registry_config_path_for_removal(config: &config::ApmConfig, name: &str) -> Result<PathBuf> {
    let primary = config
        .scope
        .config_dir()
        .join("registries.d")
        .join(format!("{name}.toml"));
    if config.scope != ProfileScope::User {
        return Ok(primary);
    }

    let fallback = ProfileScope::System
        .config_dir()
        .join("registries.d")
        .join(format!("{name}.toml"));
    if primary.exists() && fallback.exists() {
        return Err(AosError::RegistryError {
            message: format!(
                "registry '{name}' also exists in system config at {}; refusing to remove only \
                 the user config at {} because the system registry would remain visible",
                fallback.display(),
                primary.display(),
            ),
        }
        .into());
    }

    if primary.exists() || !fallback.exists() {
        Ok(primary)
    } else {
        Ok(fallback)
    }
}

/// Return the trust-store layers to clean up for a registry removal.
///
/// Most user-scope removals should remove or mask user trust entries.
/// When user scope is operating on a writable redirected system registry
/// config, however, the registry itself is being removed from the system layer.
/// In that case cleanup both layers: any colocated system trust key first,
/// then user trust pins learned from the system registry during updates. The
/// order matters because user cleanup masks read-only system anchors that
/// remain; when the system key is being deleted too, no user revocation marker
/// should be left behind for it.
fn trusted_key_dir_sets_for_registry_removal(
    config: &config::ApmConfig,
    removed_config_path: &std::path::Path,
) -> Vec<Vec<PathBuf>> {
    if config.scope == ProfileScope::User {
        if let Some(file_name) = removed_config_path.file_name() {
            let system_registry_config = ProfileScope::System
                .config_dir()
                .join("registries.d")
                .join(file_name);
            if removed_config_path == system_registry_config {
                return vec![
                    ProfileScope::System.trusted_keys_dirs(),
                    config.scope.trusted_keys_dirs(),
                ];
            }
        }
    }

    vec![config.scope.trusted_keys_dirs()]
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
            max_staleness_seconds: None,
            caches: Vec::new(),
            upload_auth: None,
            signing_keys: Default::default(),
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

    #[test]
    fn registry_add_config_toml_escapes_url_and_tracking_fields() {
        let content = registry_add_config_toml(RegistryAddConfigToml {
            name: "quoted-url",
            url: "file:///tmp/registry with \"quotes\"\nand newline",
            priority: 750,
            commit: None,
            branch: Some("feature/quoted-url"),
            channel: None,
            tag: None,
            version: None,
            trusted_key: None,
            no_verify: true,
        })
        .unwrap();

        let parsed: types::RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(parsed.registry.name, "quoted-url");
        assert_eq!(
            parsed.registry.url,
            "file:///tmp/registry with \"quotes\"\nand newline"
        );
        assert_eq!(parsed.registry.priority, 750);
        assert!(parsed.registry.enabled);
        assert_eq!(
            parsed.registry.branch.as_deref(),
            Some("feature/quoted-url")
        );
        assert_eq!(parsed.registry.signing.unwrap().required, false);
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
            None,
            None,
            false,
            false,
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
        let result = registry_remove(&config, "nonexistent", false, false, &printer).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn registry_remove_user_config_cleans_user_trust_layer() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);
        let removed_config = ProfileScope::User
            .config_dir()
            .join("registries.d")
            .join("host-reg.toml");

        assert_eq!(
            trusted_key_dir_sets_for_registry_removal(&config, &removed_config),
            vec![ProfileScope::User.trusted_keys_dirs()]
        );
    }

    #[test]
    fn registry_remove_redirected_system_config_cleans_both_trust_layers() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);
        let removed_config = ProfileScope::System
            .config_dir()
            .join("registries.d")
            .join("host-install-channel.toml");

        assert_eq!(
            trusted_key_dir_sets_for_registry_removal(&config, &removed_config),
            vec![
                ProfileScope::System.trusted_keys_dirs(),
                ProfileScope::User.trusted_keys_dirs()
            ]
        );
    }

    #[test]
    fn registry_remove_system_scope_cleans_system_trust_layer() {
        let tmp = TempDir::new().unwrap();
        let mut config = make_config(&tmp, vec![]);
        config.scope = ProfileScope::System;
        let removed_config = ProfileScope::System
            .config_dir()
            .join("registries.d")
            .join("host-install-channel.toml");

        assert_eq!(
            trusted_key_dir_sets_for_registry_removal(&config, &removed_config),
            vec![ProfileScope::System.trusted_keys_dirs()]
        );
    }

    #[test]
    fn cache_upload_auth_args_map_to_backend_options() {
        let args = CacheUploadAuthArgs {
            token: Some("token".into()),
            view: Some("ops".into()),
            http_user: Some("user".into()),
            http_password: Some("pass".into()),
            header: vec!["X-Test: yes".into()],
            s3_region: Some("us-west-2".into()),
            s3_profile: Some("prod".into()),
            s3_endpoint: Some("https://minio.example".into()),
            ssh_key: Some("/tmp/key".into()),
            ssh_password: Some("ssh-pass".into()),
            ssh_ask_pass: true,
        };

        let auth = args.auth_options();
        assert_eq!(auth.token.as_deref(), Some("token"));
        assert_eq!(auth.view, "ops");
        assert_eq!(auth.http_user.as_deref(), Some("user"));
        assert_eq!(auth.http_password.as_deref(), Some("pass"));
        assert_eq!(auth.headers, vec!["X-Test: yes"]);
        assert_eq!(auth.s3_region.as_deref(), Some("us-west-2"));
        assert_eq!(auth.s3_profile.as_deref(), Some("prod"));
        assert_eq!(auth.s3_endpoint.as_deref(), Some("https://minio.example"));
        assert_eq!(auth.ssh_key.as_deref(), Some("/tmp/key"));
        assert_eq!(auth.ssh_password.as_deref(), Some("ssh-pass"));
        assert!(auth.ssh_ask_pass);
    }

    #[test]
    fn cache_upload_auth_args_merge_config_defaults_and_overrides() {
        let config = RegistryUploadAuthConfig {
            upload_urls: Vec::new(),
            token: Some("config-token".into()),
            view: Some("prod".into()),
            http_user: Some("config-user".into()),
            http_password: Some("config-pass".into()),
            headers: vec!["X-Config: yes".into()],
            s3_region: Some("us-east-1".into()),
            s3_profile: Some("default".into()),
            s3_endpoint: Some("https://config-minio.example".into()),
            ssh_key: Some("/etc/apm/config-key".into()),
            ssh_password: Some("config-ssh-pass".into()),
            ssh_ask_pass: true,
        };
        let args = CacheUploadAuthArgs {
            token: Some("cli-token".into()),
            view: None,
            http_user: None,
            http_password: Some("cli-pass".into()),
            header: vec!["X-Cli: yes".into()],
            s3_region: None,
            s3_profile: Some("cli-profile".into()),
            s3_endpoint: None,
            ssh_key: Some("/tmp/cli-key".into()),
            ssh_password: None,
            ssh_ask_pass: false,
        };

        let auth = args.auth_options_with_config(Some(&config));
        assert_eq!(auth.token.as_deref(), Some("cli-token"));
        assert_eq!(auth.view, "prod");
        assert_eq!(auth.http_user.as_deref(), Some("config-user"));
        assert_eq!(auth.http_password.as_deref(), Some("cli-pass"));
        assert_eq!(auth.headers, vec!["X-Cli: yes"]);
        assert_eq!(auth.s3_region.as_deref(), Some("us-east-1"));
        assert_eq!(auth.s3_profile.as_deref(), Some("cli-profile"));
        assert_eq!(
            auth.s3_endpoint.as_deref(),
            Some("https://config-minio.example")
        );
        assert_eq!(auth.ssh_key.as_deref(), Some("/tmp/cli-key"));
        assert_eq!(auth.ssh_password.as_deref(), Some("config-ssh-pass"));
        assert!(auth.ssh_ask_pass);
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
