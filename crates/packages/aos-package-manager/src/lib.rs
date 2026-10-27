//! Native AOS package installation, configuration activation, and runtime admission.
//!
//! The `apm` command tree is [`PackageCommand`], dispatched by [`run`]. Package
//! operations resolve verified registry data, retain authenticated deployment
//! artifacts, and update per-user or system generations. Runtime admission
//! keeps container and immutable-image restrictions ahead of side effects.
//!
//! Registry reads and trust live in `aos-registry-client`; registry authoring
//! and the APR command vocabulary live in `aos-registry-authoring`. Portable
//! deployment contracts and shared execution live in `aos-deployment-format`
//! and `aos-deployment` respectively. This crate owns package policy and its
//! integration with image generations, credentials, and TPM attestation.
//!
//! [`aos_registry_client::types::ProfileScope`] distinguishes user paths from system generations.
//! [`install`], [`remove`], [`upgrade`], and [`rollback`] implement profile
//! mutations; [`update`], [`query`], [`deps`], [`hold`], [`clean`], [`verify`],
//! and [`source`] provide acquisition, discovery, and maintenance operations.
//! [`sysroot`] owns image generations and boot transitions.

pub mod attestation;
pub mod boot_configuration;
mod cancellation;
pub use cancellation::AbilityCancellationGuard;
pub mod clean;
use aos_registry_client::config;
pub mod config_eval;
pub mod config_trust;
pub mod container_admission;
mod container_environment;
mod container_runtime;
pub(crate) mod credential;
pub mod deployment;
pub mod deps;
pub mod desired;
pub mod documentation;
mod documentation_lsp;
pub mod download;
pub mod error;
use aos_registry_client::dry_run;
pub mod environment;
pub mod hold;
pub mod images;
pub mod install;

pub mod native_deployment;
mod native_registry;
pub(crate) mod package_attestation;
pub use package_attestation::PackageQuoteArtifacts;

/// Reports whether the configured local attestation terminal can address a TPM.
///
/// # Errors
///
/// Returns an error when an explicitly configured TPM transport is invalid.
pub fn local_attestation_tpm_available() -> Result<bool> {
    package_attestation::tpm_available()
}

/// Produces a local TPM quote for the package-attestation PCR selection.
///
/// # Errors
///
/// Returns an error when the nonce is malformed, the configured terminal
/// tools cannot execute, or the private output directory cannot be written.
pub fn produce_local_package_attestation_quote(
    nonce: &str,
    output_directory: &Path,
) -> Result<PackageQuoteArtifacts> {
    package_attestation::produce_package_quote(nonce, output_directory)
}

use aos_registry_format::platform;

pub mod profile;
use aos_registry_client::provenance;
pub mod query;
use aos_registry_authoring::registry_ops;
use aos_registry_client::registry;
pub mod remove;
pub mod resolve;
pub mod rollback;
mod runtime_authoring;
mod runtime_boundary;
pub(crate) mod runtime_modules;
use aos_registry_client::security;
pub mod source;
pub mod store;
pub mod sysroot;
pub mod sysroot_lock;
pub mod types;
pub mod update;
pub mod upgrade;
pub mod verify;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Subcommand, ValueEnum};

use aos_cli_ui::output::{OutputMode, Printer};
use sysroot::SystemTransitionMode;

/// Environment-variable documentation appended to `apm`/`apr` long help.
pub const ENVIRONMENT_HELP: &str = "Environment:
  AOS_RUNTIME            Runtime kind. AOS containers set this to `container`;
                         host boot and TPM operations are unavailable.
                         Package handlers validate their required facilities.
  AOS_CONTAINER_READ_ONLY
                         Set to `1` by container init when package state cannot
                         be mutated. Read-only package queries remain available.
  APM_SYSTEM_CONFIG_DIR  Override the system configuration root (default
                         /etc/apm). Affects every derived system path,
                         including registries.d and trusted-keys.d, in both
                         the user and system profile scopes. Must be an
                         absolute path; intended for development on non-AOS
                         hosts.
  AOS_ROOT               Override the AOS root filesystem. System-scope APM
                         state is written under <AOS_ROOT>/var/lib/apm, and
                         Nix commands use the AOS_ROOT-relative store.";

/// Package-consumer operations implemented for `apm`.
#[derive(Subcommand)]
pub enum PackageCommand {
    /// Apply the complete operator configuration worktree
    Switch {
        /// Preview changes without activating them
        #[arg(long)]
        dry_run: bool,
        /// Read operator modules from this directory
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
        /// Stage immutable evaluation inputs in this directory
        #[arg(long, default_value = "/var/lib/aos/evaluation")]
        eval_root: PathBuf,
    },
    /// Manage runtime configuration modules
    Config {
        /// Select the configuration operation
        #[command(subcommand)]
        command: RuntimeConfigCommand,
    },
    /// Hidden: inspect the authoritative committed profile publication.
    #[command(name = "deployment-current", hide = true)]
    DeploymentCurrent {
        /// Read the native profile at this path
        #[arg(long)]
        profile: PathBuf,
        /// Inspect committed state while later work is pending
        #[arg(long)]
        committed_during_recovery: bool,
    },
    /// Hidden: apply an image-authenticated native deployment.
    #[command(name = "apply-deployment", hide = true)]
    ApplyDeployment(native_deployment::NativeDeploymentArgs),
    /// Hidden: prepare or activate the retained container root profile.
    #[command(name = "container-startup", hide = true)]
    ContainerStartup(container_runtime::ContainerStartupArgs),
    /// Hidden: verify durable completion of a native deployment.
    #[command(name = "verify-deployment", hide = true)]
    VerifyDeployment(native_deployment::NativeDeploymentArgs),
    /// Hidden: export authenticated retained native effect authority.
    #[command(name = "deployment-retained-effects", hide = true)]
    DeploymentRetainedEffects {
        /// Read this package profile's native journals.
        #[arg(long)]
        profile: PathBuf,
    },
    /// Hidden: read an explicitly selected committed native profile result.
    #[command(name = "deployment-result", hide = true)]
    DeploymentResult {
        /// Read this package profile's native journals.
        #[arg(long)]
        profile: PathBuf,
        /// Select the committed package profile generation.
        #[arg(long)]
        generation: u32,
        /// Select this exact effect identity.
        #[arg(long)]
        effect: String,
        /// Read prior committed state while a later activation is pending.
        #[arg(long)]
        committed_during_recovery: bool,
    },
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
        /// Install machine-wide packages
        #[arg(long)]
        system: bool,
        /// Bypass sysroot-lock check for specific packages (comma-separated) or "all"
        #[arg(long, value_name = "NAMES", num_args = 0..=1, default_missing_value = "all")]
        ignore_sysroot_lock: Option<String>,
    },
    /// Apply a complete desired machine-wide package set
    Apply {
        /// Desired-package TOML file (omitted packages are removed)
        #[arg(long = "from")]
        from: PathBuf,
        /// Manage the machine-wide package set
        #[arg(long, required = true)]
        system: bool,
    },
    /// Manage immutable operating-system images
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Remove packages (keep deps)
    Remove {
        /// Package names to remove
        packages: Vec<String>,
        /// Also remove orphaned dependencies
        #[arg(long)]
        autoremove: bool,
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
    },
    /// Remove orphaned dependency packages
    Autoremove {
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
    },
    /// Re-download and reinstall packages
    Reinstall {
        /// Package names to reinstall
        packages: Vec<String>,
        /// Bypass sysroot-lock check for specific packages (comma-separated) or "all"
        #[arg(long, value_name = "NAMES", num_args = 0..=1, default_missing_value = "all")]
        ignore_sysroot_lock: Option<String>,
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
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
        /// Upgrade machine-wide packages
        #[arg(long)]
        system: bool,
        /// Bypass sysroot-lock check for specific packages (comma-separated) or "all"
        #[arg(long, value_name = "NAMES", num_args = 0..=1, default_missing_value = "all")]
        ignore_sysroot_lock: Option<String>,
    },
    /// Upgrade all packages with dependency resolution changes
    FullUpgrade {
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
    },
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
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Show detailed package information
    Show {
        /// Package name
        package: String,
        /// Show package from this registry
        #[arg(long)]
        registry: Option<String>,
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Browse canonical package documentation and editor metadata
    Docs {
        /// Documentation operation to run
        #[command(subcommand)]
        command: DocumentationCommand,
    },
    /// Search, inspect, and compare typed package options
    Options {
        /// Option operation to run
        #[command(subcommand)]
        command: OptionsCommand,
    },
    /// Export one exact signed package reference
    Schema {
        /// Installed package whose exact signed package reference should be exported
        package: String,
        /// Hub root URL for a remote package lookup
        #[arg(long)]
        hub: Option<String>,
        /// Hub registry slug for a remote package lookup
        #[arg(long, requires = "hub")]
        registry: Option<String>,
        /// Exact package version
        #[arg(long)]
        version: Option<String>,
        /// Exact package platform
        #[arg(long)]
        platform: Option<String>,
        /// Hub access token
        #[arg(long, env = "AOS_TOKEN", requires = "hub")]
        token: Option<String>,
        /// Read the system package profile instead of the user profile
        #[arg(long)]
        system: bool,
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
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Show closure tree (store references)
    Depends {
        /// Package name
        package: String,
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Show reverse dependencies
    Rdepends {
        /// Package name
        package: String,
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Show available versions and registry origins
    Policy {
        /// Package name
        package: String,
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// List files installed by a package
    Files {
        /// Package name
        package: String,
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Produce and verify package runtime attestations
    Attest {
        /// The attestation operation to run
        #[command(subcommand)]
        command: AttestCommand,
    },
    /// Prevent a package from being upgraded
    Hold {
        /// Package name
        package: String,
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
    },
    /// Remove upgrade hold
    Unhold {
        /// Package name
        package: String,
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
    },
    /// List held packages
    Held {
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// List installed packages whose source registry is no longer configured
    Orphans {
        /// Query the system scope instead of the user scope
        #[arg(long)]
        system: bool,
    },
    /// Remove cached NAR downloads
    Clean {
        /// Also remove old profile generations
        #[arg(long)]
        generations: bool,
        /// Number of generations to retain (with --generations)
        #[arg(long, default_value = "3")]
        keep: u32,
        /// Clean system package and configuration generations
        #[arg(long)]
        system: bool,
    },
    /// Run Nix garbage collection on unreachable paths
    Gc {
        /// Use machine-wide package metadata for cleanup
        #[arg(long)]
        system: bool,
    },
    /// Verify installed package against registry hash
    Verify {
        /// Package name
        package: String,
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
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
        /// Manage machine-wide packages
        #[arg(long)]
        system: bool,
    },
    /// Roll back to a previous profile generation
    Rollback {
        /// Roll back to a specific generation number
        #[arg(long)]
        generation: Option<u32>,
        /// Roll back machine-wide packages
        #[arg(long)]
        system: bool,
        /// List package profile generations
        #[arg(long)]
        list: bool,
    },
    /// Prepare package credential payloads
    #[command(subcommand)]
    Credential(CredentialCommand),
    /// Manage registries
    #[command(after_long_help = ENVIRONMENT_HELP)]
    Registry {
        /// Manage system-wide registries instead of user registries
        #[arg(long)]
        system: bool,
        /// The registry operation to run
        #[command(subcommand)]
        command: ApmRegistryCommand,
    },
}

/// Canonical package-documentation operations.
#[derive(Subcommand)]
pub enum DocumentationCommand {
    /// Search installed documentation or a Hub index
    Search {
        /// Terms to search for; omit to browse documented packages
        #[arg(default_value = "")]
        query: String,
        /// Restrict results to package, option, or operation
        #[arg(long)]
        kind: Option<String>,
        /// Maximum number of results
        #[arg(long, default_value = "25")]
        limit: usize,
        /// Hub root URL for a remote search
        #[arg(long)]
        hub: Option<String>,
        /// Hub registry slug for a remote search
        #[arg(long, requires = "hub")]
        registry: Option<String>,
        /// Hub access token for private registries
        #[arg(long, env = "AOS_TOKEN", requires = "hub")]
        token: Option<String>,
        /// Search the system package profile instead of the user profile
        #[arg(long)]
        system: bool,
    },
    /// Render one exact package document
    Show {
        /// Package name
        package: String,
        /// Exact version for a remote selection
        #[arg(long)]
        version: Option<String>,
        /// Exact platform for a remote selection
        #[arg(long)]
        platform: Option<String>,
        /// Plain text, canonical JSON, standalone HTML, or roff
        #[arg(long, value_enum)]
        format: Option<DocumentationOutput>,
        /// Write rendered bytes to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
        /// Hub root URL for a remote lookup
        #[arg(long)]
        hub: Option<String>,
        /// Hub registry slug for a remote lookup
        #[arg(long, requires = "hub")]
        registry: Option<String>,
        /// Hub access token for private registries
        #[arg(long, env = "AOS_TOKEN", requires = "hub")]
        token: Option<String>,
        /// Read the system package profile instead of the user profile
        #[arg(long)]
        system: bool,
    },
    /// Print the generated package metadata JSON Schema
    Schema {
        /// Fetch the schema from this Hub instead of using the checked local schema
        #[arg(long)]
        hub: Option<String>,
        /// Hub access token
        #[arg(long, env = "AOS_TOKEN", requires = "hub")]
        token: Option<String>,
    },
    /// Render or install an offline package manpage
    Man {
        /// Installed package name
        package: String,
        /// Install the generated manpage into APM's profile-scoped cache
        #[arg(long)]
        install: bool,
        /// Print only the installed cache path
        #[arg(long, requires = "install")]
        print_path: bool,
        /// Use the system package profile and cache
        #[arg(long)]
        system: bool,
    },
    /// Serve completion, hover, diagnostics, and schema over LSP stdio
    Lsp {
        /// Read the system package profile instead of the user profile
        #[arg(long)]
        system: bool,
        /// Add a canonical documentation JSON file outside the installed profile
        #[arg(long = "document")]
        documents: Vec<PathBuf>,
    },
    /// Serve the installed documentation browser on a loopback HTTP listener
    Serve {
        /// Listener address; non-loopback addresses are rejected
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// Exit after serving one request (useful for automation)
        #[arg(long, hide = true)]
        once: bool,
        /// Read the system package profile instead of the user profile
        #[arg(long)]
        system: bool,
    },
    /// Explain or collect the profile-scoped generated documentation cache
    Cache {
        /// Cache operation to run
        #[command(subcommand)]
        command: DocumentationCacheCommand,
    },
}

/// Typed option discovery and comparison operations.
#[derive(Subcommand)]
pub enum OptionsCommand {
    /// Search option paths and descriptions
    Search {
        /// Terms to search for
        query: String,
        /// Maximum number of results
        #[arg(long, default_value = "25")]
        limit: usize,
        /// Hub root URL for a remote search
        #[arg(long)]
        hub: Option<String>,
        /// Hub registry slug for a remote search
        #[arg(long, requires = "hub")]
        registry: Option<String>,
        /// Hub access token
        #[arg(long, env = "AOS_TOKEN", requires = "hub")]
        token: Option<String>,
        /// Search the system profile
        #[arg(long)]
        system: bool,
    },
    /// Show one exact option path
    Show {
        /// Exact display path, including `<wildcard>` segments
        path: String,
        /// Restrict the lookup to this package
        #[arg(long)]
        package: Option<String>,
        /// Hub root URL for a remote lookup
        #[arg(long)]
        hub: Option<String>,
        /// Hub registry slug for a remote lookup
        #[arg(long, requires = "hub")]
        registry: Option<String>,
        /// Hub access token
        #[arg(long, env = "AOS_TOKEN", requires = "hub")]
        token: Option<String>,
        /// Search the system profile
        #[arg(long)]
        system: bool,
    },
    /// Compare option semantics between two exact package versions
    Compare {
        /// Package name
        package: String,
        /// Source version
        #[arg(long)]
        from: String,
        /// Destination version
        #[arg(long)]
        to: String,
        /// Exact platform
        #[arg(long)]
        platform: String,
        /// Hub root URL
        #[arg(long)]
        hub: String,
        /// Hub registry slug
        #[arg(long)]
        registry: String,
        /// Hub access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// Emit exact option paths for shell and editor completion
    Complete {
        /// Path prefix
        prefix: String,
        /// Search the system profile
        #[arg(long)]
        system: bool,
    },
}

/// Generated documentation cache operations.
#[derive(Subcommand)]
pub enum DocumentationCacheCommand {
    /// Report retained documentation and generated manpage cache entries
    Status {
        /// Inspect the system profile cache
        #[arg(long)]
        system: bool,
    },
    /// Remove generated cache entries not serving as canonical package roots
    Gc {
        /// Collect the system profile cache
        #[arg(long)]
        system: bool,
    },
}

/// Supported package-document renderers.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DocumentationOutput {
    /// Human-readable terminal reference
    Plain,
    /// Exact canonical JSON
    Json,
    /// Standalone safe HTML
    Html,
    /// Troff/groff manpage source
    Man,
}

#[derive(Subcommand)]
pub enum ImageCommand {
    /// Authenticate and physically stage a candidate without changing boot selection
    Prepare {
        /// Resolve this sysroot package from signed registry metadata
        package: String,
        /// Select this configured registry
        #[arg(long)]
        registry: Option<String>,
        /// Require candidate health admission for a later qualified rollout
        #[arg(long)]
        qualified: bool,
    },
    /// Download and stage an operating-system image
    Install {
        /// Image package name
        package: String,
        /// Select a registry
        #[arg(long)]
        registry: Option<String>,
        #[command(flatten)]
        transition: ImageTransitionOptions,
    },
    /// Stage the latest version of the installed operating-system image
    Upgrade {
        #[command(flatten)]
        transition: ImageTransitionOptions,
    },
    /// Select a previous operating-system image generation
    Rollback {
        #[arg(long)]
        generation: Option<u32>,
        #[command(flatten)]
        transition: ImageTransitionOptions,
    },
    /// List operating-system image generations
    List,
    /// Download a precompiled image without staging it
    Download {
        package: String,
        #[arg(long)]
        format: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        registry: Option<String>,
        /// Read machine-wide registries instead of personal registries
        #[arg(long)]
        system: bool,
    },
}

#[derive(clap::Args)]
pub struct ImageTransitionOptions {
    /// Reboot after selecting the image
    #[arg(long, group = "kernel_mode")]
    reboot: bool,
    /// Drain workloads before rebooting
    #[arg(long)]
    drain: bool,
    /// Reject unsupported kexec transitions
    #[arg(long, group = "kernel_mode", hide = true)]
    kexec: bool,
    /// Reject unsupported userspace-only transitions
    #[arg(long, group = "kernel_mode", hide = true)]
    live: bool,
}

#[derive(Subcommand)]
pub enum RuntimeConfigCommand {
    /// Restore a previous configuration generation
    Rollback {
        #[arg(long)]
        generation: Option<u32>,
        /// List configuration generations
        #[arg(long)]
        list: bool,
    },
    /// Show the active immutable set and mutable worktree state.
    Status {
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
    },
    /// List discoverable worktree module entrypoints.
    List {
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
    },
    /// Add a new module to the worktree.
    Add {
        source: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
    },
    /// Atomically replace an existing worktree module.
    Replace {
        name: String,
        source: PathBuf,
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
    },
    /// Move a worktree module to the recoverable sibling trash directory.
    Remove {
        name: String,
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
    },
    /// Evaluate and optionally activate the complete worktree transaction.
    Apply {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
        #[arg(long = "eval-root", default_value = "/var/lib/aos/evaluation")]
        eval_root: PathBuf,
        #[arg(long = "allow-unprivileged-worktree", hide = true)]
        allow_unprivileged_worktree: bool,
    },
    /// Preview the complete worktree transaction without activation.
    Diff {
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
        #[arg(long = "eval-root", default_value = "/var/lib/aos/evaluation")]
        eval_root: PathBuf,
        #[arg(long = "allow-unprivileged-worktree", hide = true)]
        allow_unprivileged_worktree: bool,
    },
    /// Restore the worktree from the active immutable set.
    Discard {
        #[arg(long, default_value = "/var/lib/aos/config/modules.d")]
        worktree: PathBuf,
    },
}

/// Package credential helper operations.
#[derive(Subcommand)]
pub enum CredentialCommand {
    /// Encrypt plaintext for a typed configuration credential declaration.
    Encrypt {
        /// systemd credential name
        name: String,
        /// Plaintext credential file
        input: PathBuf,
        /// Write encrypted payload to this file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Signed PCR public key
        #[arg(long = "pcr-public-key")]
        pcr_public_key: Option<PathBuf>,
    },
}

impl PackageCommand {
    /// Returns whether the command belongs to the private on-host runtime.
    pub fn is_runtime_internal(&self) -> bool {
        matches!(
            self,
            PackageCommand::ContainerStartup(..)
                | PackageCommand::ApplyDeployment(..)
                | PackageCommand::VerifyDeployment(..)
                | PackageCommand::DeploymentCurrent { .. }
                | PackageCommand::DeploymentRetainedEffects { .. }
                | PackageCommand::DeploymentResult { .. }
        )
    }

    /// Returns the runtime environment the command must establish before I/O.
    pub fn runtime_requirement(&self) -> environment::RuntimeRequirement {
        use environment::RuntimeRequirement::{AosRoot, Portable};

        if self.is_system() && !matches!(self, PackageCommand::Image { .. }) {
            return AosRoot;
        }

        match self {
            PackageCommand::Image {
                command: ImageCommand::Download { system, .. },
            } => {
                if *system {
                    AosRoot
                } else {
                    Portable
                }
            }
            PackageCommand::Image { .. } => environment::RuntimeRequirement::LiveAos,
            PackageCommand::ContainerStartup(..)
            | PackageCommand::ApplyDeployment(..)
            | PackageCommand::VerifyDeployment(..)
            | PackageCommand::DeploymentCurrent { .. }
            | PackageCommand::DeploymentRetainedEffects { .. }
            | PackageCommand::DeploymentResult { .. } => Portable,
            PackageCommand::Switch { .. }
            | PackageCommand::Config {
                command: RuntimeConfigCommand::Rollback { .. },
            } => AosRoot,
            PackageCommand::Install { .. }
            | PackageCommand::Apply { .. }
            | PackageCommand::Remove { .. }
            | PackageCommand::Autoremove { .. }
            | PackageCommand::Reinstall { .. }
            | PackageCommand::Update { .. }
            | PackageCommand::Upgrade { .. }
            | PackageCommand::FullUpgrade { .. }
            | PackageCommand::Search { .. }
            | PackageCommand::Show { .. }
            | PackageCommand::Docs { .. }
            | PackageCommand::Options { .. }
            | PackageCommand::Schema { .. }
            | PackageCommand::List { .. }
            | PackageCommand::Depends { .. }
            | PackageCommand::Rdepends { .. }
            | PackageCommand::Policy { .. }
            | PackageCommand::Files { .. }
            | PackageCommand::Attest { .. }
            | PackageCommand::Hold { .. }
            | PackageCommand::Unhold { .. }
            | PackageCommand::Held { .. }
            | PackageCommand::Orphans { .. }
            | PackageCommand::Clean { .. }
            | PackageCommand::Gc { .. }
            | PackageCommand::Verify { .. }
            | PackageCommand::Source { .. }
            | PackageCommand::Rollback { .. }
            | PackageCommand::Credential(..)
            | PackageCommand::Registry { .. }
            | PackageCommand::Config { .. } => Portable,
        }
    }

    /// Returns whether the command uses machine-wide registry and profile state.
    ///
    /// Package commands select it with `--system`. Image staging, upgrades,
    /// rollback, and generation listing implicitly select machine-wide state;
    /// image downloads select personal registries unless passed `--system`.
    pub fn is_system(&self) -> bool {
        match self {
            PackageCommand::Image {
                command: ImageCommand::Download { system, .. },
            } => *system,
            PackageCommand::Image { .. } => true,
            PackageCommand::Apply { system, .. }
            | PackageCommand::Remove { system, .. }
            | PackageCommand::Autoremove { system }
            | PackageCommand::Reinstall { system, .. }
            | PackageCommand::FullUpgrade { system }
            | PackageCommand::Hold { system, .. }
            | PackageCommand::Unhold { system, .. }
            | PackageCommand::Verify { system, .. }
            | PackageCommand::Source { system, .. }
            | PackageCommand::Gc { system } => *system,
            PackageCommand::Install { system, .. } => *system,
            PackageCommand::Upgrade { system, .. } => *system,
            PackageCommand::Rollback { system, .. } => *system,
            PackageCommand::Update { system, .. } => *system,
            PackageCommand::Registry { system, .. } => *system,
            PackageCommand::Search { system, .. } => *system,
            PackageCommand::Show { system, .. } => *system,
            PackageCommand::List { system, .. } => *system,
            PackageCommand::Depends { system, .. } => *system,
            PackageCommand::Rdepends { system, .. } => *system,
            PackageCommand::Policy { system, .. } => *system,
            PackageCommand::Files { system, .. } => *system,
            PackageCommand::Attest { command } => command.is_system(),
            PackageCommand::Held { system, .. } => *system,
            PackageCommand::Orphans { system, .. } => *system,
            PackageCommand::Clean { system, .. } => *system,
            PackageCommand::Schema { system, .. } => *system,
            _ => false,
        }
    }
}

#[derive(Subcommand)]
pub enum AttestCommand {
    /// Produce a TPM quote over the package PCR set
    Quote {
        /// Verifier nonce as an even-length hex string
        #[arg(long)]
        nonce: Option<String>,
        /// File containing the verifier nonce as hex
        #[arg(long)]
        nonce_file: Option<PathBuf>,
        /// Directory where quote artifacts are written
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Enroll a quote identity into a verifier trust catalog
    Enroll {
        /// Directory containing a quote bundle with AK/EK identity files
        #[arg(long)]
        quote_dir: PathBuf,
        /// Human-readable fleet node or TPM label
        #[arg(long)]
        label: String,
        /// Enrollment proof workflow used for this identity
        #[arg(long, value_enum)]
        method: AttestEnrollmentMethod,
        /// File containing the credential-activation, privacy-CA, or OOB proof
        #[arg(long = "evidence-file")]
        evidence_file: PathBuf,
        /// Verifier quote identity catalog to create or update
        #[arg(long = "catalog-file")]
        catalog_file: PathBuf,
    },
    /// Verify a package event log against a PCR 15 value or quote bundle
    Verify {
        /// Use system registry metadata
        #[arg(long)]
        system: bool,
        /// Package event log JSONL path
        #[arg(long)]
        event_log: PathBuf,
        /// Quoted PCR 15 value as SHA-256 hex
        #[arg(long)]
        pcr15: Option<String>,
        /// Directory containing an unauthenticated quote bundle
        #[arg(long)]
        quote_dir: Option<PathBuf>,
        /// Verifier nonce as an even-length hex string
        #[arg(long)]
        nonce: Option<String>,
        /// File containing the verifier nonce as hex
        #[arg(long)]
        nonce_file: Option<PathBuf>,
        /// Pinned quote identity catalog JSON file
        #[arg(long = "quote-identity-file")]
        quote_identity_files: Vec<PathBuf>,
        /// Additional golden measurement catalog JSON file
        #[arg(long = "catalog-file")]
        catalog_files: Vec<PathBuf>,
        /// Expected PCR 15 value before package measurements
        #[arg(long, conflicts_with = "pcr15_baseline_file")]
        pcr15_baseline: Option<String>,
        /// File containing the expected PCR 15 value before package measurements
        #[arg(long, conflicts_with = "pcr15_baseline")]
        pcr15_baseline_file: Option<PathBuf>,
        /// Atomically replace this file with the JSON verification result
        #[arg(long, requires = "json")]
        result_file: Option<PathBuf>,
        /// Generation-attestation JSON record to verify after CEL replay
        #[arg(long)]
        generation_attestation: Option<PathBuf>,
        /// Verifier-owned boot and host-trust policy for generation evidence
        #[arg(long, requires = "generation_attestation")]
        generation_policy_file: Option<PathBuf>,
    },
    /// Print the package golden measurement catalog
    Catalog {
        /// Use system registry metadata
        #[arg(long)]
        system: bool,
        /// Additional golden measurement catalog JSON file
        #[arg(long = "catalog-file")]
        catalog_files: Vec<PathBuf>,
    },
}

impl AttestCommand {
    fn is_system(&self) -> bool {
        match self {
            AttestCommand::Verify { system, .. } => *system,
            AttestCommand::Catalog { system, .. } => *system,
            AttestCommand::Quote { .. } | AttestCommand::Enroll { .. } => false,
        }
    }
}

/// Enrollment proof workflows accepted by `apm attest enroll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AttestEnrollmentMethod {
    /// TPM credential activation was completed outside this verifier.
    CredentialActivation,
    /// A privacy CA certified the AK/EK binding.
    PrivacyCa,
    /// An operator supplied an equivalent out-of-band TPM enrollment proof.
    OutOfBand,
}

impl AttestEnrollmentMethod {
    fn as_str(self) -> &'static str {
        match self {
            AttestEnrollmentMethod::CredentialActivation => "credential-activation",
            AttestEnrollmentMethod::PrivacyCa => "privacy-ca",
            AttestEnrollmentMethod::OutOfBand => "out-of-band",
        }
    }
}

/// Consumer registry configuration commands exposed by `apm registry`.
#[derive(Subcommand)]
pub enum ApmRegistryCommand {
    /// List configured registries and priorities
    List,
    /// Add a registry and optionally synchronize it immediately
    Add {
        /// Registry URL
        url: String,
        /// Registry name (derived from URL if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Priority (higher = preferred)
        #[arg(long, default_value = "500")]
        priority: u32,
        /// Pin to exact commit hash
        #[arg(long, group = "tracking")]
        commit: Option<String>,
        /// Track a branch HEAD
        #[arg(long, group = "tracking")]
        branch: Option<String>,
        /// Track a signed rollout channel
        #[arg(long, group = "tracking")]
        channel: Option<String>,
        /// Pin to exact tag name
        #[arg(long, group = "tracking")]
        tag: Option<String>,
        /// Select tags with a semantic-version constraint
        #[arg(long, group = "tracking")]
        version: Option<String>,
        /// Pin an exact trusted registry signing key; repeat for rotations
        #[arg(long = "trust-key", conflicts_with = "no_verify")]
        trust_key: Vec<String>,
        /// Disable signature verification for local development
        #[arg(long = "no-verify")]
        no_verify: bool,
        /// Write configuration without cloning the registry
        #[arg(long = "no-clone")]
        no_clone: bool,
    },
    /// Remove a configured registry
    Remove {
        /// Registry name
        name: String,
        /// Keep the local checkout
        #[arg(long)]
        keep_local: bool,
        /// Remove a checkout with unpublished or uncommitted authoring work
        #[arg(long)]
        force: bool,
    },
    /// Enable a configured registry
    Enable {
        /// Registry name
        name: String,
    },
    /// Disable a configured registry without deleting it
    Disable {
        /// Registry name
        name: String,
    },
    /// Manage trusted consumer keys
    Trust {
        /// Trust-store operation
        #[command(subcommand)]
        command: TrustCommand,
    },
}

use aos_registry_authoring::{RegistryCommand, TrustCommand};

/// Validates transition flags before loading package-manager state.
///
/// Immutable A/B image transitions can either remain staged or request a full
/// reboot. Kexec cannot select the newly written root slot, and a userspace-only
/// switch would violate the image/config authority split. Configuration-axis
/// rollback has no boot transition at all.
fn validate_system_transition_options(command: &PackageCommand) -> Result<()> {
    let validate_image_transition = |kexec: bool, reboot: bool, live: bool, drain: bool| {
        if kexec {
            bail!(
                "--kexec is not supported for immutable A/B image transitions; use --reboot or omit the transition flag to stage for a later reboot"
            );
        }
        if live {
            bail!(
                "--live is not supported for immutable A/B image transitions; staging never replaces userspace on the running image"
            );
        }
        if drain && !reboot {
            bail!("--drain requires --reboot for an immutable A/B image transition");
        }
        Ok(())
    };

    if let PackageCommand::Image { command } = command {
        let transition = match command {
            ImageCommand::Install { transition, .. }
            | ImageCommand::Upgrade { transition }
            | ImageCommand::Rollback { transition, .. } => Some(transition),
            ImageCommand::Prepare { .. } | ImageCommand::List | ImageCommand::Download { .. } => {
                None
            }
        };
        if let Some(options) = transition {
            validate_image_transition(options.kexec, options.reboot, options.live, options.drain)?;
        }
    }

    Ok(())
}

/// Converts a validated reboot flag into a system transition mode.
fn parse_system_transition_mode(reboot: bool) -> SystemTransitionMode {
    if reboot {
        SystemTransitionMode::Reboot
    } else {
        SystemTransitionMode::Advisory
    }
}

fn acquire_runtime_config_lock(worktree: &Path) -> Result<std::fs::File> {
    let parent = worktree
        .parent()
        .context("runtime module worktree has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating runtime config directory {}", parent.display()))?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(parent.join("modules.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .context("locking runtime configuration worktree")?;
    Ok(lock)
}

fn validate_runtime_module_name(name: &str) -> Result<()> {
    if !name.ends_with(".nix")
        || name.starts_with('_')
        || name.contains('/')
        || name.contains("..")
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        bail!("runtime module name must be a safe, non-underscore .nix file name");
    }
    Ok(())
}

fn publish_runtime_module(source: &Path, destination: &Path, replace: bool) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let bytes = std::fs::read(source)
        .with_context(|| format!("reading runtime module {}", source.display()))?;
    std::str::from_utf8(&bytes).context("runtime module source is not UTF-8")?;
    if replace != destination.is_file() {
        if replace {
            bail!("runtime module {} does not exist", destination.display());
        }
        bail!("runtime module {} already exists", destination.display());
    }
    let parent = destination
        .parent()
        .context("runtime module destination has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".module.tmp.{}", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    // Set the final mode on the open file before publication, independently of
    // the caller's umask and the input file's permissions.
    output.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    std::fs::rename(&temporary, destination)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

async fn run_runtime_config_command(
    command: &RuntimeConfigCommand,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    match command {
        RuntimeConfigCommand::Rollback { generation, list } => {
            let config = config::ApmConfig::load(runtime_boundary::configuration_scope())?;
            sysroot::rollback_system(&config, *generation, *list, dry_run, printer).await
        }
        RuntimeConfigCommand::Status { worktree } => {
            let descriptor = runtime_boundary::configuration_scope()
                .profile_path()
                .join("current/evaluation.json");
            if descriptor.is_file() {
                let inputs = native_deployment::EvaluationInputs::read(&descriptor)?;
                printer.plain(&format!(
                    "active runtime modules: {} entrypoints",
                    inputs.runtime_configuration.len()
                ));
                for module in &inputs.runtime_configuration {
                    printer.plain(&module.display().to_string());
                }
            } else {
                printer.plain("active runtime modules: unavailable (no active native generation)");
            }
            let entries = if worktree.is_dir() {
                runtime_modules::list_entrypoints(worktree)?
            } else {
                Vec::new()
            };
            printer.plain(&format!(
                "worktree: {} ({} entrypoints)",
                worktree.display(),
                entries.len()
            ));
            Ok(())
        }
        RuntimeConfigCommand::List { worktree } => {
            if worktree.is_dir() {
                for entry in runtime_modules::list_entrypoints(worktree)? {
                    printer.plain(&entry.display().to_string());
                }
            }
            Ok(())
        }
        RuntimeConfigCommand::Add {
            source,
            name,
            worktree,
        } => {
            let _lock = acquire_runtime_config_lock(worktree)?;
            let name = name
                .clone()
                .or_else(|| {
                    source
                        .file_name()
                        .and_then(|value| value.to_str())
                        .map(str::to_string)
                })
                .context("runtime module source has no UTF-8 file name; pass --name")?;
            validate_runtime_module_name(&name)?;
            runtime_authoring::initialize(worktree)?;
            publish_runtime_module(source, &worktree.join(&name), false)?;
            printer.success(&format!(
                "Added runtime module {name}; run `apm config apply` to activate."
            ));
            Ok(())
        }
        RuntimeConfigCommand::Replace {
            name,
            source,
            worktree,
        } => {
            let _lock = acquire_runtime_config_lock(worktree)?;
            validate_runtime_module_name(name)?;
            runtime_authoring::initialize(worktree)?;
            publish_runtime_module(source, &worktree.join(name), true)?;
            printer.success(&format!(
                "Replaced runtime module {name}; run `apm config apply` to activate."
            ));
            Ok(())
        }
        RuntimeConfigCommand::Remove { name, worktree } => {
            let _lock = acquire_runtime_config_lock(worktree)?;
            validate_runtime_module_name(name)?;
            runtime_authoring::initialize(worktree)?;
            let source = worktree.join(name);
            if !source.is_file() {
                bail!("runtime module {} does not exist", source.display());
            }
            let trash = worktree
                .parent()
                .context("runtime worktree has no parent")?
                .join("modules-trash");
            std::fs::create_dir_all(&trash)?;
            let destination = trash.join(format!("{}.{}.removed", name, std::process::id()));
            if destination.exists() {
                bail!(
                    "recoverable removal destination already exists: {}",
                    destination.display()
                );
            }
            std::fs::rename(&source, &destination)?;
            std::fs::File::open(&trash)?.sync_all()?;
            std::fs::File::open(worktree)?.sync_all()?;
            printer.success(&format!(
                "Removed {name} to {}; run `apm config apply` to activate.",
                destination.display()
            ));
            Ok(())
        }
        RuntimeConfigCommand::Discard { worktree } => {
            let _lock = acquire_runtime_config_lock(worktree)?;
            if let Some(backup) = runtime_authoring::restore(worktree)? {
                printer.plain(&format!(
                    "previous worktree preserved at {}",
                    backup.display()
                ));
            }
            printer.success("Restored worktree from the active generation.");
            Ok(())
        }
        RuntimeConfigCommand::Apply {
            dry_run,
            worktree,
            eval_root,
            allow_unprivileged_worktree,
        } => {
            apply_runtime_worktree(
                worktree,
                eval_root,
                *allow_unprivileged_worktree,
                *dry_run,
                printer,
            )
            .await
        }
        RuntimeConfigCommand::Diff {
            worktree,
            eval_root,
            allow_unprivileged_worktree,
        } => {
            apply_runtime_worktree(
                worktree,
                eval_root,
                *allow_unprivileged_worktree,
                true,
                printer,
            )
            .await
        }
    }
}

async fn apply_runtime_worktree(
    worktree: &Path,
    eval_root: &Path,
    allow_unprivileged_worktree: bool,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let _lock = if dry_run {
        let path = worktree
            .parent()
            .context("runtime worktree has no parent")?
            .join("modules.lock");
        match std::fs::File::open(path) {
            Ok(lock) => {
                rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockShared)?;
                Some(lock)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        }
    } else {
        Some(acquire_runtime_config_lock(worktree)?)
    };
    let config = config::ApmConfig::load(runtime_boundary::configuration_scope())?;
    let profile = profile::Profile::open_readonly(config.scope);
    if !dry_run {
        install::native::recover(&profile)?;
    }
    let scratch = tempfile::tempdir()?;
    let staged = if dry_run
        && std::fs::symlink_metadata(worktree)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        Some(runtime_authoring::stage_current(scratch.path())?)
    } else {
        if !dry_run {
            runtime_authoring::initialize(worktree)?;
        }
        None
    };
    let source = staged
        .as_ref()
        .map_or(worktree, |staged| staged.path.as_path());
    let snapshot = runtime_modules::snapshot(
        source,
        eval_root,
        staged.is_none() && !allow_unprivileged_worktree,
    )?;
    install::native::reconfigure(&config, &snapshot, dry_run, printer)
}

/// Main entry point for package-consumer and private runtime operations.
///
/// Loads the [`config::ApmConfig`] for the scope implied by the command
/// (`--system` selects [`aos_registry_client::types::ProfileScope::System`] on machines and aliases the
/// image's user profile in containers) and dispatches to the
/// matching module. Private configuration evaluation, materialization,
/// checked activation, and stage commands are dispatched before generic
/// package configuration loading because they authenticate and load their
/// own scoped runtime inputs.
///
/// # Errors
///
/// Returns an error before configuration loading when the process runtime
/// prohibits host boot or TPM operations, or when read-only container state
/// prohibits a mutation. It also returns an error when configuration loading
/// fails or when the dispatched subcommand fails (resolution, download,
/// verification, activation, registry operations, ...). User cancellation at
/// a confirmation prompt is reported as
/// [`crate::error::PackageError::UserCancelled`].
pub async fn run(
    command: &PackageCommand,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    runtime_boundary::validate_environment(command)?;
    if !command.is_runtime_internal() {
        container_environment::prepare()?;
    }
    runtime_boundary::validate(command)?;
    command.runtime_requirement().validate()?;

    if let PackageCommand::ContainerStartup(arguments) = command {
        let cancellation = cancellation::AbilityCancellationGuard::install()?;
        return container_runtime::run(arguments, cancellation.token());
    }
    if let PackageCommand::ApplyDeployment(arguments) = command {
        let cancellation = cancellation::AbilityCancellationGuard::install()?;
        return native_deployment::apply(&arguments.command()?, cancellation.token());
    }
    if let PackageCommand::VerifyDeployment(arguments) = command {
        return native_deployment::verify(&arguments.command()?);
    }
    if let PackageCommand::DeploymentCurrent {
        profile,
        committed_during_recovery,
    } = command
    {
        let generation = profile::deployment::current_committed_generation(profile)?;
        if !*committed_during_recovery {
            if let Some(generation) = generation {
                profile::deployment::committed_generation(profile, generation)?;
            }
        }
        println!("{}", serde_json::json!({"generation": generation}));
        return Ok(());
    }
    if let PackageCommand::DeploymentRetainedEffects { profile } = command {
        let bytes = deployment::retained::export(profile)?;
        println!("{}", std::str::from_utf8(&bytes)?);
        return Ok(());
    }
    if let PackageCommand::DeploymentResult {
        profile,
        generation,
        effect,
        committed_during_recovery,
    } = command
    {
        let result = if *committed_during_recovery {
            profile::deployment::committed_generation_during_recovery(profile, *generation)?
                .outputs
                .get(effect)
                .cloned()
                .context("selected effect has no committed result")?
        } else {
            profile::deployment::committed_result(profile, *generation, effect)?
        };
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }

    if let PackageCommand::Config { command } = command {
        return run_runtime_config_command(command, dry_run, printer).await;
    }

    if let PackageCommand::Switch {
        worktree,
        eval_root,
        dry_run: switch_dry_run,
    } = command
    {
        return apply_runtime_worktree(
            worktree,
            eval_root,
            false,
            dry_run || *switch_dry_run,
            printer,
        )
        .await;
    }

    // TPM quoting and verifier enrollment use explicit inputs. Neither needs
    // mutable registry state, which may not exist on a verifier-only machine.
    if let PackageCommand::Attest { command } = command {
        match command {
            AttestCommand::Quote {
                nonce,
                nonce_file,
                output_dir,
            } => {
                let nonce = read_attestation_nonce(nonce, nonce_file)?;
                return run_produce_package_attestation_quote(&nonce, output_dir, printer);
            }
            AttestCommand::Enroll {
                quote_dir,
                label,
                method,
                evidence_file,
                catalog_file,
            } => {
                return run_enroll_package_attestation_quote(
                    quote_dir,
                    catalog_file,
                    label,
                    *method,
                    evidence_file,
                    printer,
                );
            }
            AttestCommand::Verify { .. } | AttestCommand::Catalog { .. } => {}
        }
    }

    // Documentation reads retained installed objects or the public Hub API and
    // needs neither mutable registry checkout state nor a writable profile.
    if let PackageCommand::Docs { command } = command {
        return documentation::run(command, printer).await;
    }
    if let PackageCommand::Options { command } = command {
        return documentation::run_options(command, printer).await;
    }
    if let PackageCommand::Schema {
        package,
        hub,
        registry,
        version,
        platform,
        token,
        system,
    } = command
    {
        return documentation::run_schema(
            package,
            hub.as_deref(),
            registry.as_deref(),
            version.as_deref(),
            platform.as_deref(),
            token.as_deref(),
            *system,
        )
        .await;
    }

    validate_system_transition_options(command)?;

    let scope = runtime_boundary::profile_scope(command.is_system());

    let config = config::ApmConfig::load(scope)?;

    match command {
        PackageCommand::Image {
            command:
                ImageCommand::Prepare {
                    package,
                    registry,
                    qualified,
                },
        } => {
            let options = sysroot::ImagePrepareOptions {
                package: package.clone(),
                registry: registry.clone(),
                purpose: if *qualified {
                    sysroot::ImagePreparationPurpose::Qualified
                } else {
                    sysroot::ImagePreparationPurpose::Ordinary
                },
                dry_run,
                yes,
            };
            if let Some(candidate) = sysroot::prepare_image(&config, &options, printer).await? {
                printer.json(&serde_json::to_value(candidate)?);
            }
            Ok(())
        }
        PackageCommand::Install {
            packages,
            registry,
            download_only,
            no_deps,
            reinstall,
            ignore_sysroot_lock,
            ..
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(ignore_sysroot_lock.as_deref());
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
        PackageCommand::Apply { from, .. } => {
            desired::reconcile_from_file(&config, from, dry_run, yes, printer).await
        }
        PackageCommand::Image { command } => match command {
            ImageCommand::Prepare { .. } => unreachable!("Image preparation is handled above"),
            ImageCommand::Install {
                package,
                registry,
                transition,
            } => {
                sysroot::install_system(
                    &config,
                    std::slice::from_ref(package),
                    registry.as_deref(),
                    None,
                    None,
                    dry_run,
                    yes,
                    parse_system_transition_mode(transition.reboot),
                    transition.drain,
                    printer,
                )
                .await
            }
            ImageCommand::Download {
                package,
                registry,
                format,
                output,
                ..
            } => {
                sysroot::install_system(
                    &config,
                    std::slice::from_ref(package),
                    registry.as_deref(),
                    Some(format),
                    output.as_deref(),
                    dry_run,
                    yes,
                    SystemTransitionMode::Advisory,
                    false,
                    printer,
                )
                .await
            }
            ImageCommand::Upgrade { transition } => {
                sysroot::upgrade_system(
                    &config,
                    dry_run,
                    parse_system_transition_mode(transition.reboot),
                    transition.drain,
                    printer,
                )
                .await
            }
            ImageCommand::Rollback {
                generation,
                transition,
            } => {
                sysroot::rollback_image_generation(
                    &config,
                    *generation,
                    false,
                    dry_run,
                    parse_system_transition_mode(transition.reboot),
                    transition.drain,
                    printer,
                )
                .await
            }
            ImageCommand::List => {
                sysroot::rollback_image_generation(
                    &config,
                    None,
                    true,
                    dry_run,
                    SystemTransitionMode::Advisory,
                    false,
                    printer,
                )
                .await
            }
        },
        PackageCommand::Remove {
            packages,
            autoremove,
            ..
        } => {
            let auto_remove = *autoremove || config.settings.auto_autoremove;
            let outcome =
                remove::run(&config, packages, auto_remove, dry_run, yes, printer).await?;
            if config.settings.auto_gc && auto_remove && !dry_run && outcome.orphan_count > 0 {
                clean::run_gc_after_mutation(config.scope, printer).await?;
            }
            Ok(())
        }
        PackageCommand::Autoremove { .. } => {
            let outcome = remove::run_autoremove(&config, dry_run, yes, printer).await?;
            if config.settings.auto_gc && !dry_run && outcome.orphan_count > 0 {
                clean::run_gc_after_mutation(config.scope, printer).await?;
            }
            Ok(())
        }
        PackageCommand::Reinstall {
            packages,
            ignore_sysroot_lock,
            ..
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
            ignore_sysroot_lock,
            ..
        } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::parse(ignore_sysroot_lock.as_deref());
            upgrade::run(&config, packages, exclude, dry_run, yes, &ignore, printer).await
        }
        PackageCommand::FullUpgrade { .. } => {
            let ignore = sysroot_lock::IgnoreSysrootLock::Enforce;
            upgrade::run(&config, &[], &[], dry_run, yes, &ignore, printer).await
        }
        PackageCommand::Search {
            pattern,
            names_only,
            installed,
            registry,
            ..
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
        PackageCommand::Show {
            package, registry, ..
        } => query::show(&config, package, registry.as_deref(), printer).await,
        PackageCommand::List {
            installed,
            upgradable,
            held,
            registry,
            ..
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
        PackageCommand::Depends { package, .. } => deps::depends(&config, package, printer).await,
        PackageCommand::Rdepends { package, .. } => deps::rdepends(&config, package, printer).await,
        PackageCommand::Policy { package, .. } => deps::policy(&config, package, printer).await,
        PackageCommand::Files { package, .. } => deps::files(&config, package, printer).await,
        PackageCommand::Attest {
            command:
                AttestCommand::Verify {
                    event_log,
                    pcr15,
                    quote_dir,
                    nonce,
                    nonce_file,
                    quote_identity_files,
                    catalog_files,
                    pcr15_baseline,
                    pcr15_baseline_file,
                    result_file,
                    generation_attestation,
                    generation_policy_file,
                    ..
                },
        } => {
            if let Some(path) = result_file.as_deref() {
                clear_attestation_result(path)?;
            }
            let pcr15_baseline = match (pcr15_baseline, pcr15_baseline_file) {
                (Some(value), None) => Some(value.clone()),
                (None, Some(path)) => Some(read_attestation_baseline(path)?),
                (None, None) => None,
                (Some(_), Some(_)) => {
                    bail!("inline and file-backed PCR 15 baselines are mutually exclusive")
                }
            };
            let measurement = read_attestation_measurement(
                pcr15,
                quote_dir,
                nonce,
                nonce_file,
                quote_identity_files,
            )?;
            run_verify_package_attestation(
                &config,
                event_log,
                measurement,
                catalog_files,
                &pcr15_baseline,
                generation_attestation.as_deref(),
                generation_policy_file.as_deref(),
                result_file.as_deref(),
                printer,
            )
        }
        PackageCommand::Attest {
            command: AttestCommand::Catalog { catalog_files, .. },
        } => run_package_attestation_catalog(&config, catalog_files, printer),
        PackageCommand::Attest {
            command: AttestCommand::Quote { .. },
        } => unreachable!("AttestCommand::Quote is handled before ApmConfig::load"),
        PackageCommand::Attest {
            command: AttestCommand::Enroll { .. },
        } => unreachable!("AttestCommand::Enroll is handled before ApmConfig::load"),
        PackageCommand::Hold { package, .. } => hold::run_hold(&config, package, printer).await,
        PackageCommand::Unhold { package, .. } => hold::run_unhold(&config, package, printer).await,
        PackageCommand::Held { .. } => hold::run_held(&config, printer).await,
        PackageCommand::Orphans { .. } => query::orphans(&config, printer).await,
        PackageCommand::Clean {
            generations, keep, ..
        } => clean::run(&config, *generations, *keep, printer).await,
        PackageCommand::Gc { .. } => clean::run_gc(config.scope, printer).await,
        PackageCommand::Verify { package, .. } => {
            source::run_verify(&config, package, printer).await
        }
        PackageCommand::Source {
            package,
            show_drv,
            fetch,
            verify,
            ..
        } => source::run_source(&config, package, *show_drv, *fetch, *verify, printer).await,
        PackageCommand::Credential(command) => credential::run(command, printer),
        PackageCommand::Rollback {
            generation, list, ..
        } => {
            if *list {
                rollback::list(&config, printer).await
            } else {
                rollback::run(&config, *generation, dry_run, printer).await
            }
        }
        PackageCommand::Registry { command, .. } => {
            run_apm_registry(&config, command, printer).await
        }

        PackageCommand::ContainerStartup(..)
        | PackageCommand::ApplyDeployment(..)
        | PackageCommand::VerifyDeployment(..)
        | PackageCommand::DeploymentCurrent { .. }
        | PackageCommand::DeploymentRetainedEffects { .. }
        | PackageCommand::DeploymentResult { .. } => {
            unreachable!("Native deployment is handled before ApmConfig::load")
        }

        PackageCommand::Switch { .. } => {
            unreachable!("Switch is handled before ApmConfig::load")
        }
        PackageCommand::Config { .. } => {
            unreachable!("Config is handled before ApmConfig::load")
        }
        PackageCommand::Docs { .. } => {
            unreachable!("Docs is handled before ApmConfig::load")
        }
        PackageCommand::Options { .. } => {
            unreachable!("Options is handled before ApmConfig::load")
        }
        PackageCommand::Schema { .. } => {
            unreachable!("Schema is handled before ApmConfig::load")
        }
    }
}

#[derive(Debug)]
enum AttestationMeasurement {
    Pcr15(String),
    Quote {
        quote_dir: PathBuf,
        nonce: String,
        identity_files: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttestationQuoteTrust {
    PcrValueOnly,
    BundleSelfConsistent,
    IdentityPinned { anchor: String, ak_ek_trusted: bool },
}

#[derive(Debug, serde::Serialize)]
struct GenerationVerificationSummary {
    activation_id: String,
    generation_id: String,
    sequence: u64,
    content: String,
    rederived: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddedGenerationQuote {
    schema: String,
    nonce: String,
    pcr_selection: String,
    quoted_pcr15: String,
    ak_public: String,
    quote_message: String,
    quote_signature: String,
    quote_pcrs: String,
}

struct PreverifiedGenerationQuote {
    pcrs: attestation::QuotedPcrs,
    bundle: package_attestation::PackageQuoteBundleBinding,
}

impl attestation::QuoteChecker for PreverifiedGenerationQuote {
    fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<attestation::QuotedPcrs> {
        let embedded: EmbeddedGenerationQuote =
            serde_json::from_slice(quote).context("parsing embedded generation quote")?;
        if embedded.schema != "aos.gen-attestation-quote/v1"
            || embedded.pcr_selection != "sha256:7,11,12,15"
            || embedded.nonce != hex::encode(nonce)
            || embedded.quoted_pcr15 != self.pcrs.pcr15
            || embedded.ak_public != self.bundle.ak_public
            || embedded.quote_message != self.bundle.quote_message
            || embedded.quote_signature != self.bundle.quote_signature
            || embedded.quote_pcrs != self.bundle.quote_pcrs
        {
            bail!("embedded generation quote does not match the verified quote bundle");
        }
        Ok(self.pcrs.clone())
    }
}

fn read_attestation_measurement(
    pcr15: &Option<String>,
    quote_dir: &Option<PathBuf>,
    nonce: &Option<String>,
    nonce_file: &Option<PathBuf>,
    quote_identity_files: &[PathBuf],
) -> Result<AttestationMeasurement> {
    match (pcr15, quote_dir) {
        (Some(_), Some(_)) => bail!("use either --pcr15 or --quote-dir, not both"),
        (Some(pcr15), None) => {
            if nonce.is_some() || nonce_file.is_some() {
                bail!("--nonce and --nonce-file require --quote-dir");
            }
            if !quote_identity_files.is_empty() {
                bail!("--quote-identity-file requires --quote-dir");
            }
            Ok(AttestationMeasurement::Pcr15(pcr15.clone()))
        }
        (None, Some(quote_dir)) => Ok(AttestationMeasurement::Quote {
            quote_dir: quote_dir.clone(),
            nonce: read_attestation_nonce(nonce, nonce_file)?,
            identity_files: quote_identity_files.to_vec(),
        }),
        (None, None) => bail!("attest verify requires --pcr15 or --quote-dir"),
    }
}

fn run_verify_package_attestation(
    config: &config::ApmConfig,
    event_log: &PathBuf,
    measurement: AttestationMeasurement,
    catalog_files: &[PathBuf],
    pcr15_baseline: &Option<String>,
    generation_attestation: Option<&Path>,
    generation_policy_file: Option<&Path>,
    result_file: Option<&Path>,
    printer: &Printer,
) -> Result<()> {
    let (pcr15, trust, quoted_generation_quote) = match measurement {
        AttestationMeasurement::Pcr15(pcr15) => (pcr15, AttestationQuoteTrust::PcrValueOnly, None),
        AttestationMeasurement::Quote {
            quote_dir,
            nonce,
            identity_files,
        } => {
            let quote = package_attestation::verify_attestation_quote_bundle(
                &quote_dir,
                &nonce,
                &identity_files,
            )?;
            let trust = if quote.identity_pinned {
                AttestationQuoteTrust::IdentityPinned {
                    anchor: quote
                        .identity_label
                        .unwrap_or_else(|| "unlabeled".to_string()),
                    ak_ek_trusted: quote.ak_ek_trusted,
                }
            } else {
                AttestationQuoteTrust::BundleSelfConsistent
            };
            let pcrs = attestation::QuotedPcrs {
                pcr7: quote.quoted_pcr7,
                pcr11: quote.quoted_pcr11,
                pcr12: quote.quoted_pcr12,
                pcr15: quote.quoted_pcr15.clone(),
            };
            let checker = PreverifiedGenerationQuote {
                pcrs,
                bundle: quote.bundle,
            };
            (quote.quoted_pcr15, trust, Some(checker))
        }
    };
    let log = fs::read(event_log)
        .with_context(|| format!("reading package event log {}", event_log.display()))?;
    let log = package_attestation::decode_package_event_log_bytes(&log)
        .with_context(|| format!("decoding package event log {}", event_log.display()))?;
    let catalog = load_package_attestation_catalog(config, catalog_files)?;
    let verified = package_attestation::verify_package_event_log_against_measurement_catalog(
        &log,
        &pcr15,
        pcr15_baseline.as_deref(),
        &catalog,
    )?;
    let generation = match generation_attestation {
        Some(path) => Some(verify_generation_attestation_cli(
            config,
            path,
            generation_policy_file.context(
                "--generation-attestation requires --generation-policy-file",
            )?,
            quoted_generation_quote.as_ref().context(
                "--generation-attestation requires --quote-dir; a bare PCR 15 value does not authenticate PCR 7/11/12 or the AK",
            )?,
            &trust,
            &verified,
        )?),
        None => {
            if generation_policy_file.is_some() {
                bail!(
                    "--generation-policy-file requires --generation-attestation"
                );
            }
            None
        }
    };

    if printer.mode() == OutputMode::Json {
        let mut output = serde_json::json!({
            "pcr15": verified.pcr15,
            "package_count": verified.package_count,
            "generation_attestations": &verified.generation_attestations,
        });
        if let Some(generation) = &generation {
            output["generation_verified"] = serde_json::json!(true);
            output["generation"] = serde_json::to_value(generation)?;
        }
        if matches!(
            trust,
            AttestationQuoteTrust::BundleSelfConsistent
                | AttestationQuoteTrust::IdentityPinned { .. }
        ) {
            output["quote_bundle_verified"] = serde_json::json!(true);
            output["ak_ek_trusted"] = serde_json::json!(matches!(
                &trust,
                AttestationQuoteTrust::IdentityPinned {
                    ak_ek_trusted: true,
                    ..
                }
            ));
            output["quote_identity_pinned"] = serde_json::json!(matches!(
                &trust,
                AttestationQuoteTrust::IdentityPinned { .. }
            ));
            if let AttestationQuoteTrust::IdentityPinned { anchor, .. } = &trust {
                output["quote_identity_label"] = serde_json::json!(anchor);
            }
        }
        if let Some(path) = result_file {
            write_attestation_result(path, &output)?;
        }
        printer.json(&output);
    } else {
        let mut message = format!(
            "AOS attestation event log verified ({} package events, {} generation attestations, PCR 15 {}).",
            verified.package_count,
            verified.generation_attestations.len(),
            verified.pcr15
        );
        if let Some(generation) = &generation {
            message.push_str(&format!(
                " Generation activation {} ({}) passed the full trust policy.",
                generation.activation_id, generation.generation_id
            ));
        }
        if trust == AttestationQuoteTrust::BundleSelfConsistent {
            message.push_str(" Quote bundle is self-consistent; AK/EK trust was not checked.");
        } else if let AttestationQuoteTrust::IdentityPinned {
            anchor,
            ak_ek_trusted,
        } = trust
        {
            if ak_ek_trusted {
                message.push_str(&format!(
                    " Quote bundle matches enrolled identity '{anchor}'."
                ));
            } else {
                message.push_str(&format!(
                    " Quote bundle matches pinned identity '{anchor}'; AK/EK trust was not checked."
                ));
            }
        }
        printer.success(&message);
    }
    Ok(())
}

fn read_attestation_baseline(path: &Path) -> Result<String> {
    let baseline = fs::read_to_string(path)
        .with_context(|| format!("reading package attestation baseline {}", path.display()))?;
    let baseline = baseline.trim();
    if baseline.is_empty() {
        bail!(
            "package attestation baseline file is empty: {}",
            path.display()
        );
    }

    Ok(baseline.to_string())
}

fn clear_attestation_result(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("package attestation result path must have a parent directory")?;

    match fs::remove_file(path) {
        Ok(()) => std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| {
                format!(
                    "syncing package attestation result directory {} after invalidation",
                    parent.display()
                )
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "invalidating prior package attestation result {}",
                path.display()
            )
        }),
    }
}

fn write_attestation_result(path: &Path, value: &serde_json::Value) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("package attestation result path must have a parent directory")?;
    let mut bytes = serde_json::to_vec(value).context("encoding package attestation result")?;
    bytes.push(b'\n');

    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "creating package attestation result beside {}",
            path.display()
        )
    })?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .with_context(|| {
            format!(
                "setting package attestation result mode for {}",
                path.display()
            )
        })?;
    temporary
        .write_all(&bytes)
        .with_context(|| format!("writing package attestation result for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("syncing package attestation result for {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "atomically replacing package attestation result {}",
                path.display()
            )
        })?;

    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "syncing package attestation result directory {}",
                parent.display()
            )
        })
}

fn verify_generation_attestation_cli(
    config: &config::ApmConfig,
    record_path: &Path,
    policy_path: &Path,
    checker: &PreverifiedGenerationQuote,
    quote_trust: &AttestationQuoteTrust,
    cel: &package_attestation::PackageEventLogVerification,
) -> Result<GenerationVerificationSummary> {
    if !matches!(quote_trust, AttestationQuoteTrust::IdentityPinned { .. }) {
        bail!("native generation verification requires an enrolled quote identity");
    }
    let record: attestation::native::GenerationEvidence =
        serde_json::from_slice(&native_deployment::read_regular_document(record_path)?)?;
    let policy: attestation::native_cli::Policy =
        serde_json::from_slice(&native_deployment::read_regular_document(policy_path)?)?;
    anyhow::ensure!(
        policy.schema == "aos.package.generation-attestation-policy",
        "unsupported native generation verifier policy"
    );
    let activation_id = record.activation_id.to_string();
    let digest = attestation::native::record_hash(&record)?;
    anyhow::ensure!(
        cel.generation_attestations.get(&activation_id) == Some(&digest.to_string()),
        "native generation evidence differs from its authenticated CEL event"
    );
    let prior = cel
        .generation_attestation_prefix_digests
        .get(&activation_id)
        .context("native generation has no unambiguous CEL prefix")?
        .clone();
    let (active, revoked, releases) = attestation::native_cli::authenticate_releases(
        &config.cache_path(),
        config.scope.trusted_keys_dirs(),
        &record,
    )?;
    let policy = attestation::native::VerifierPolicy {
        image: policy.image,
        expected_pcr7: policy.expected_pcr7,
        expected_pcr12: policy.expected_pcr12,
        library_nar_hash: policy.library_nar_hash,
        pcr15_baseline: cel.pcr15_baseline.clone(),
        prior_pcr15_event_digests: prior,
        roster_fingerprints: active,
        revoked_roster_fingerprints: revoked,
        releases,
        image_roots: policy.image_roots,
        allow_local_root_runtime_modules: policy.allow_local_root_runtime_modules,
        source_authorities: policy.source_authorities,
    };
    attestation::native::verify(
        &record,
        checker,
        &policy,
        digest.as_bytes(),
        &attestation::native::rederive,
    )?;
    Ok(GenerationVerificationSummary {
        activation_id,
        generation_id: record.profile_generation.to_string(),
        sequence: record.sequence,
        content: record.content,
        rederived: true,
    })
}

fn run_package_attestation_catalog(
    config: &config::ApmConfig,
    catalog_files: &[PathBuf],
    printer: &Printer,
) -> Result<()> {
    let catalog = load_package_attestation_catalog(config, catalog_files)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!(catalog));
        return Ok(());
    }
    if catalog.is_empty() {
        printer.info("No package attestation measurements in catalog.");
        return Ok(());
    }
    for entry in catalog {
        printer.plain(&format!(
            "{} {} {} {}",
            entry.name, entry.version, entry.root_digest, entry.measurement
        ));
    }
    Ok(())
}

fn load_package_attestation_catalog(
    config: &config::ApmConfig,
    catalog_files: &[PathBuf],
) -> Result<Vec<package_attestation::PackageMeasurementCatalogEntry>> {
    let registries = install::load_registries(config)?;
    let catalog = registries
        .registries()
        .iter()
        .flat_map(|registry| registry.package_versions().cloned())
        .collect::<Vec<_>>();
    let embedded = embedded_package_attestation_catalog()?;
    package_attestation_catalog_from_sources(&catalog, &embedded, catalog_files)
}

fn package_attestation_catalog_from_sources(
    registry_packages: &[aos_registry_format::consumer::PackageMeta],
    embedded_packages: &[package_attestation::PackageMeasurementCatalogEntry],
    catalog_files: &[PathBuf],
) -> Result<Vec<package_attestation::PackageMeasurementCatalogEntry>> {
    let mut catalog =
        package_attestation::package_measurement_catalog_from_package_meta(registry_packages)?;
    catalog.extend_from_slice(embedded_packages);
    for path in catalog_files {
        append_package_attestation_catalog(path, &mut catalog)?;
    }
    package_attestation::canonical_package_measurement_catalog(&catalog)
}

fn embedded_package_attestation_catalog()
-> Result<Vec<package_attestation::PackageMeasurementCatalogEntry>> {
    let profile = profile::Profile::open_readonly(runtime_boundary::profile_scope(true));
    let Some(generation) = profile.current_generation()? else {
        return Ok(Vec::new());
    };
    if !generation.path.join("native-deployment.json").is_file() {
        return Ok(Vec::new());
    }
    let committed = profile::deployment::committed_generation(&profile.path, generation.number)?;
    let mut catalog = Vec::new();
    for installed in profile::meta::list_meta(&profile)? {
        let Some(package) = installed.apm else {
            continue;
        };
        anyhow::ensure!(
            committed
                .deployment
                .artifacts()
                .iter()
                .any(|artifact| artifact.path == installed.store_path),
            "installed measurement metadata differs from its committed native payloads"
        );
        if let (Some(root_digest), Some(measurement)) = (
            package.attestation.root_digest,
            package.attestation.measurement,
        ) {
            catalog.push(package_attestation::PackageMeasurementCatalogEntry {
                name: package.name,
                version: package.version,
                root_digest,
                measurement,
            });
        }
    }
    package_attestation::canonical_package_measurement_catalog(&catalog)
}

fn append_package_attestation_catalog(
    path: &Path,
    catalog: &mut Vec<package_attestation::PackageMeasurementCatalogEntry>,
) -> Result<()> {
    let entries = read_package_attestation_catalog(path)?;
    catalog.extend(entries);
    Ok(())
}

fn read_package_attestation_catalog(
    path: &Path,
) -> Result<Vec<package_attestation::PackageMeasurementCatalogEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading package attestation catalog {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("parsing package attestation catalog {}", path.display()))
}

fn read_attestation_nonce(nonce: &Option<String>, nonce_file: &Option<PathBuf>) -> Result<String> {
    match (nonce.as_deref(), nonce_file.as_ref()) {
        (Some(_), Some(_)) => bail!("use either --nonce or --nonce-file, not both"),
        (Some(nonce), None) => Ok(nonce.to_string()),
        (None, Some(path)) => fs::read_to_string(path)
            .with_context(|| format!("reading attestation nonce {}", path.display()))
            .map(|nonce| nonce.trim().to_string()),
        (None, None) => bail!("attest quote requires --nonce or --nonce-file"),
    }
}

fn run_produce_package_attestation_quote(
    nonce: &str,
    output_dir: &PathBuf,
    printer: &Printer,
) -> Result<()> {
    let quote = package_attestation::produce_package_quote(nonce, output_dir)?;
    let json = serde_json::to_value(&quote).context("serializing package quote artifacts")?;

    if printer.mode() == OutputMode::Json {
        printer.json(&json);
    } else {
        printer.success(&format!(
            "Package attestation quote written to {} ({}).",
            output_dir.display(),
            quote.pcr_selection
        ));
    }
    Ok(())
}

fn run_enroll_package_attestation_quote(
    quote_dir: &PathBuf,
    catalog_file: &PathBuf,
    label: &str,
    method: AttestEnrollmentMethod,
    evidence_file: &PathBuf,
    printer: &Printer,
) -> Result<()> {
    let enrollment = package_attestation::enroll_quote_identity(
        quote_dir,
        catalog_file,
        label,
        method.as_str(),
        evidence_file,
    )?;
    let json = serde_json::to_value(&enrollment).context("serializing package quote enrollment")?;

    if printer.mode() == OutputMode::Json {
        printer.json(&json);
    } else {
        printer.success(&format!(
            "Enrolled package attestation identity '{}' in {} ({}).",
            enrollment.label,
            catalog_file.display(),
            enrollment.method
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry subcommands
// ---------------------------------------------------------------------------

/// Dispatches an `apm registry` consumer command.
async fn run_apm_registry(
    config: &config::ApmConfig,
    command: &ApmRegistryCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        ApmRegistryCommand::List => aos_registry_authoring::registry_list(config, printer).await,
        ApmRegistryCommand::Add {
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
            aos_registry_authoring::registry_add(
                config,
                url,
                name.as_deref(),
                *priority,
                commit.as_deref(),
                branch.as_deref(),
                channel.as_deref(),
                tag.as_deref(),
                version.as_deref(),
                trust_key,
                *no_verify,
                !no_clone,
                printer,
            )
            .await
        }
        ApmRegistryCommand::Remove {
            name,
            keep_local,
            force,
        } => {
            aos_registry_authoring::registry_remove(config, name, *keep_local, *force, printer)
                .await
        }
        ApmRegistryCommand::Enable { name } => {
            aos_registry_authoring::registry_set_enabled(config, name, true, printer).await
        }
        ApmRegistryCommand::Disable { name } => {
            aos_registry_authoring::registry_set_enabled(config, name, false, printer).await
        }
        ApmRegistryCommand::Trust { command } => registry_ops::run_trust(config, command, printer),
    }
}

/// Runs an `apr` registry workspace or authoring command.
///
/// # Errors
///
/// Returns an error when the selected AOS system root is invalid, registry
/// configuration cannot be loaded, or the authoring operation fails.
pub async fn run_apr(
    command: &RegistryCommand,
    system: bool,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    runtime_boundary::validate_registry_environment(command, system)?;
    container_environment::prepare()?;
    runtime_boundary::validate_registry(command, system)?;
    if system {
        environment::RuntimeRequirement::AosRoot.validate()?;
    }
    let scope = runtime_boundary::profile_scope(system);
    let config = config::ApmConfig::load(scope)?;
    let _dry_run_guard = dry_run.then(dry_run::ScopedDryRun::enter);

    aos_registry_authoring::run(&config, command, dry_run, printer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_format::consumer::{AttestationMeta, PACKAGE_META_FORMAT, PackageMeta};
    use tempfile::TempDir;

    #[test]
    fn runtime_module_publication_is_private_under_any_umask() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD_ENV: &str = "AOS_TEST_RUNTIME_MODULE_PUBLICATION_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            // A separate test process isolates the process-wide umask from
            // concurrently running tests.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::runtime_module_publication_is_private_under_any_umask",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let directory = TempDir::new().unwrap();
        let source = directory.path().join("source.nix");
        let destination = directory.path().join("module.nix");
        std::fs::write(&source, "{ ... }: {}\n").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();

        for mask in [0, 0o777] {
            let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(mask));
            publish_runtime_module(&source, &destination, false).unwrap();
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );

            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o666)).unwrap();
            std::fs::write(&source, "{ ... }: { services.nginx.enable = true; }\n").unwrap();
            publish_runtime_module(&source, &destination, true).unwrap();
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                std::fs::read(&source).unwrap()
            );

            rustix::process::umask(previous);
            std::fs::remove_file(&destination).unwrap();
        }
    }

    fn preverified_generation_quote() -> (PreverifiedGenerationQuote, [u8; 32]) {
        (
            PreverifiedGenerationQuote {
                pcrs: attestation::QuotedPcrs {
                    pcr7: "11".repeat(32),
                    pcr11: "22".repeat(32),
                    pcr12: "00".repeat(32),
                    pcr15: "33".repeat(32),
                },
                bundle: package_attestation::PackageQuoteBundleBinding {
                    ak_public: "aa".repeat(8),
                    quote_message: "bb".repeat(8),
                    quote_signature: "cc".repeat(8),
                    quote_pcrs: "dd".repeat(8),
                },
            },
            [0x44; 32],
        )
    }

    fn embedded_generation_quote(
        checker: &PreverifiedGenerationQuote,
        nonce: &[u8],
    ) -> serde_json::Value {
        serde_json::json!({
            "schema": "aos.gen-attestation-quote/v1",
            "nonce": hex::encode(nonce),
            "pcr_selection": "sha256:7,11,12,15",
            "quoted_pcr15": checker.pcrs.pcr15,
            "ak_public": checker.bundle.ak_public,
            "quote_message": checker.bundle.quote_message,
            "quote_signature": checker.bundle.quote_signature,
            "quote_pcrs": checker.bundle.quote_pcrs,
        })
    }

    #[test]
    fn generation_quote_adapter_rejects_tampered_embedded_quote() {
        let (checker, nonce) = preverified_generation_quote();
        let exact = serde_json::to_vec(&embedded_generation_quote(&checker, &nonce)).unwrap();
        assert!(attestation::QuoteChecker::check(&checker, &exact, &nonce).is_ok());

        let mut tampered = embedded_generation_quote(&checker, &nonce);
        tampered["quote_signature"] = serde_json::json!("00".repeat(8));
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(attestation::QuoteChecker::check(&checker, &tampered, &nonce).is_err());
    }

    #[test]
    fn generation_quote_adapter_rejects_unrelated_bundle_and_nonce() {
        let (checker, nonce) = preverified_generation_quote();
        let mut unrelated = embedded_generation_quote(&checker, &nonce);
        unrelated["ak_public"] = serde_json::json!("99".repeat(8));
        let unrelated = serde_json::to_vec(&unrelated).unwrap();
        assert!(attestation::QuoteChecker::check(&checker, &unrelated, &nonce).is_err());

        let exact = serde_json::to_vec(&embedded_generation_quote(&checker, &nonce)).unwrap();
        assert!(attestation::QuoteChecker::check(&checker, &exact, &[0x55; 32]).is_err());
    }

    fn attested_package_meta(
        name: &str,
        version: &str,
        root_digest: &str,
        measurement: &str,
    ) -> PackageMeta {
        PackageMeta {
            name: name.into(),
            version: version.into(),
            description: String::new(),
            homepage: None,
            license: String::new(),
            maintainer: String::new(),
            platform: "x86_64-linux".into(),
            store_path: format!("/nix/store/hash-{name}-{version}"),
            nar_hash: String::new(),
            nar_size: 0,
            references: Vec::new(),
            source_drv: String::new(),
            source_nar_hash: String::new(),
            named_outputs: std::collections::BTreeMap::new(),
            version_requirement: None,
            os_version: None,
            module_dependencies: Vec::new(),
            closure_size: 0,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: Some(PACKAGE_META_FORMAT),
            requires_features: vec!["attestation-v1".into()],
            deployment: None,
            module_documentation: None,
            qualification: None,
            attestation: AttestationMeta {
                root_digest: Some(root_digest.into()),
                root_hash: Some(root_digest.into()),
                root_hash_sig: Some("root.roothash.p7s".into()),
                provenance: None,
                measurement: Some(measurement.into()),
            },
        }
    }

    fn write_catalog_file(
        path: &Path,
        name: &str,
        version: &str,
        root_digest: &str,
        measurement: &str,
    ) {
        let content = serde_json::json!([{
            "name": name,
            "version": version,
            "root_digest": root_digest,
            "measurement": measurement,
        }]);
        fs::write(path, serde_json::to_vec(&content).expect("catalog JSON"))
            .expect("write catalog");
    }

    #[test]
    fn query_commands_honor_system_flag() {
        // Query subcommands now select scope via --system, just like the
        // mutating ones.
        let list_system = PackageCommand::List {
            installed: false,
            upgradable: false,
            held: false,
            registry: None,
            system: true,
        };
        assert!(list_system.is_system());

        let list_user = PackageCommand::List {
            installed: false,
            upgradable: false,
            held: false,
            registry: None,
            system: false,
        };
        assert!(!list_user.is_system());

        assert!(PackageCommand::Orphans { system: true }.is_system());
        assert!(!PackageCommand::Held { system: false }.is_system());
        assert!(
            PackageCommand::Clean {
                generations: true,
                keep: 3,
                system: true,
            }
            .is_system()
        );
        assert!(
            !PackageCommand::Clean {
                generations: true,
                keep: 3,
                system: false,
            }
            .is_system()
        );
        assert!(
            PackageCommand::Show {
                package: "curl".into(),
                registry: None,
                system: true,
            }
            .is_system()
        );
        assert!(
            PackageCommand::Attest {
                command: AttestCommand::Verify {
                    system: true,
                    event_log: "/run/log/aos-packages.cel".into(),
                    pcr15: Some("00".repeat(32)),
                    quote_dir: None,
                    nonce: None,
                    nonce_file: None,
                    quote_identity_files: Vec::new(),
                    catalog_files: Vec::new(),
                    pcr15_baseline: None,
                    pcr15_baseline_file: None,
                    result_file: None,
                    generation_attestation: None,
                    generation_policy_file: None,
                },
            }
            .is_system()
        );
        assert!(
            !PackageCommand::Attest {
                command: AttestCommand::Quote {
                    nonce: Some("00".into()),
                    nonce_file: None,
                    output_dir: "/tmp/aos-quote".into(),
                },
            }
            .is_system()
        );
        assert!(
            !PackageCommand::Attest {
                command: AttestCommand::Enroll {
                    quote_dir: "/tmp/aos-quote".into(),
                    label: "node-a".into(),
                    method: AttestEnrollmentMethod::OutOfBand,
                    evidence_file: "/tmp/evidence.txt".into(),
                    catalog_file: "/tmp/quote-identity.json".into(),
                },
            }
            .is_system()
        );
        assert!(
            PackageCommand::Attest {
                command: AttestCommand::Catalog {
                    system: true,
                    catalog_files: Vec::new(),
                },
            }
            .is_system()
        );
    }

    #[tokio::test]
    async fn attest_quote_dispatches_before_registry_configuration() {
        let temporary = TempDir::new().expect("private quote test directory");
        let output_dir = temporary.path().join("quote-output");
        let command = PackageCommand::Attest {
            command: AttestCommand::Quote {
                nonce: None,
                nonce_file: None,
                output_dir: output_dir.clone(),
            },
        };

        let error = run(&command, false, false, &Printer::new(0, true, false))
            .await
            .expect_err("quoting requires its explicit nonce");

        assert!(format!("{error:#}").contains("requires --nonce or --nonce-file"));
        assert!(!output_dir.exists());
    }

    #[tokio::test]
    async fn attest_enroll_dispatches_before_registry_configuration() {
        let temporary = TempDir::new().expect("private enrollment test directory");
        let quote_dir = temporary.path().join("missing-quote-bundle");
        let catalog_file = temporary.path().join("verifier-catalog.json");
        let command = PackageCommand::Attest {
            command: AttestCommand::Enroll {
                quote_dir: quote_dir.clone(),
                label: "test-node".into(),
                method: AttestEnrollmentMethod::OutOfBand,
                evidence_file: temporary.path().join("enrollment-proof"),
                catalog_file: catalog_file.clone(),
            },
        };

        let error = run(&command, false, false, &Printer::new(0, true, false))
            .await
            .expect_err("enrollment requires its explicit quote bundle");

        assert!(format!("{error:#}").contains(&quote_dir.display().to_string()));
        assert!(!catalog_file.exists());
    }

    #[test]
    fn attest_nonce_reader_accepts_inline_or_file() {
        assert_eq!(
            read_attestation_nonce(&Some("0011".into()), &None).expect("inline nonce"),
            "0011"
        );

        let tmp = TempDir::new().expect("tempdir");
        let nonce_file = tmp.path().join("nonce");
        fs::write(&nonce_file, "aabb\n").expect("nonce file");
        assert_eq!(
            read_attestation_nonce(&None, &Some(nonce_file)).expect("file nonce"),
            "aabb"
        );

        let conflict =
            read_attestation_nonce(&Some("0011".into()), &Some(tmp.path().join("nonce")))
                .unwrap_err();
        assert!(format!("{conflict:#}").contains("either --nonce or --nonce-file"));
    }

    #[test]
    fn attest_verify_measurement_args_require_one_source() {
        let pcr15 = Some("00".repeat(32));
        let quote_dir = Some(PathBuf::from("/run/aos-attest/quote"));
        let nonce = Some("0011".to_string());
        let no_nonce = None;
        let no_nonce_file = None;

        let pcr = read_attestation_measurement(&pcr15, &None, &no_nonce, &no_nonce_file, &[])
            .expect("pcr15 source");
        assert!(matches!(pcr, AttestationMeasurement::Pcr15(_)));

        let quote = read_attestation_measurement(&None, &quote_dir, &nonce, &no_nonce_file, &[])
            .expect("quote source");
        assert!(matches!(quote, AttestationMeasurement::Quote { .. }));

        let conflict =
            read_attestation_measurement(&pcr15, &quote_dir, &nonce, &no_nonce_file, &[])
                .unwrap_err();
        assert!(format!("{conflict:#}").contains("either --pcr15 or --quote-dir"));

        let missing =
            read_attestation_measurement(&None, &None, &no_nonce, &no_nonce_file, &[]).unwrap_err();
        assert!(format!("{missing:#}").contains("requires --pcr15 or --quote-dir"));

        let stray_nonce =
            read_attestation_measurement(&pcr15, &None, &nonce, &no_nonce_file, &[]).unwrap_err();
        assert!(format!("{stray_nonce:#}").contains("require --quote-dir"));

        let identity_files = vec![PathBuf::from("/etc/aos/attestation-identity.json")];
        let stray_trust =
            read_attestation_measurement(&pcr15, &None, &no_nonce, &no_nonce_file, &identity_files)
                .unwrap_err();
        assert!(format!("{stray_trust:#}").contains("--quote-identity-file"));
    }

    #[test]
    fn package_attestation_catalog_file_parses_entries() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("catalog.json");
        fs::write(
            &path,
            r#"[{"name":"web","version":"1.0","root_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","measurement":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]"#,
        )
        .expect("catalog file");

        let entries = read_package_attestation_catalog(&path).expect("read catalog");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "web");
        assert_eq!(entries[0].version, "1.0");
    }

    #[test]
    fn package_attestation_catalog_sources_merge_registry_embedded_and_files() {
        let tmp = TempDir::new().expect("tempdir");
        let explicit = tmp.path().join("explicit-catalog.json");
        let root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let web_measurement =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let seed_measurement =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let explicit_measurement =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        write_catalog_file(&explicit, "extra", "2.0", root_digest, explicit_measurement);
        let registry = attested_package_meta("web", "1.0", root_digest, web_measurement);
        let embedded = package_attestation::PackageMeasurementCatalogEntry {
            name: "embedded".to_string(),
            version: "1.0".to_string(),
            root_digest: root_digest.to_string(),
            measurement: seed_measurement.to_string(),
        };

        let catalog =
            package_attestation_catalog_from_sources(&[registry], &[embedded], &[explicit])
                .expect("merged catalog");

        let names = catalog
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["embedded", "extra", "web"]);
        assert_eq!(catalog[0].measurement, seed_measurement);
        assert_eq!(catalog[1].measurement, explicit_measurement);
        assert_eq!(catalog[2].measurement, web_measurement);
    }

    #[test]
    fn package_attestation_catalog_sources_reject_conflicting_explicit_file() {
        let tmp = TempDir::new().expect("tempdir");
        let explicit = tmp.path().join("explicit-catalog.json");
        let root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let registry_measurement =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let explicit_measurement =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        write_catalog_file(&explicit, "web", "1.0", root_digest, explicit_measurement);
        let registry = attested_package_meta("web", "1.0", root_digest, registry_measurement);

        let err =
            package_attestation_catalog_from_sources(&[registry], &[], &[explicit]).unwrap_err();

        assert!(format!("{err:#}").contains("conflicting golden measurements"));
    }

    #[test]
    fn attestation_baseline_file_requires_bytes_and_trims_line_endings() {
        let tmp = TempDir::new().unwrap();
        let baseline = tmp.path().join("baseline");

        fs::write(&baseline, "sha256:abcd\r\n").unwrap();
        assert_eq!(read_attestation_baseline(&baseline).unwrap(), "sha256:abcd");

        fs::write(&baseline, "").unwrap();
        assert!(read_attestation_baseline(&baseline).is_err());

        fs::write(&baseline, " \r\n\t").unwrap();
        assert!(read_attestation_baseline(&baseline).is_err());
    }

    #[test]
    fn attestation_result_atomically_replaces_complete_json() {
        let tmp = TempDir::new().unwrap();
        let result = tmp.path().join("result.json");
        fs::write(&result, "stale").unwrap();

        write_attestation_result(&result, &serde_json::json!({"verified": true})).unwrap();

        assert_eq!(
            fs::read_to_string(&result).unwrap(),
            "{\"verified\":true}\n"
        );
    }

    #[test]
    fn attestation_result_invalidation_removes_stale_success() {
        let tmp = TempDir::new().unwrap();
        let result = tmp.path().join("result.json");
        fs::write(&result, "{\"verified\":true}\n").unwrap();

        clear_attestation_result(&result).unwrap();

        assert!(!result.exists());
    }
}
