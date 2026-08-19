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

pub mod attestation;
pub mod clean;
pub mod config;
// `pub` (not `pub(crate)`) so the `golden_config_artifact` integration test —
// which lives in a separate crate and can only reach `pub` items — can import
// `render_package_config` through it. The module is otherwise internal
// (`#[doc(hidden)]`); this widens visibility without changing behavior.
#[doc(hidden)]
pub mod config_artifact;
#[doc(hidden)]
pub use config_artifact::render_package_config;
pub mod config_eval;
pub mod config_trust;
pub(crate) mod credential;
pub(crate) mod credential_artifact;
pub mod deps;
pub mod desired;
pub mod download;
pub(crate) mod ebpf_lsm;
pub(crate) mod exposed_units;
/// Test-only helpers that shell out to the host `git` to set up fixtures; the
/// production registry paths use libgit2 ([`registry::repo`],
/// [`registry::porcelain`]) and never exec `git`.
#[cfg(test)]
pub(crate) mod gitcmd;
pub mod graph_compile;
pub mod hold;
pub mod install;
pub mod metadata;
pub(crate) mod package_attestation;
pub mod policy;
pub mod profile;
pub(crate) mod provenance;
pub mod query;
pub mod registry;
pub mod registry_ops;
pub mod remove;
pub mod resolve;
pub mod rollback;
pub mod secret_ref;
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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};

use aos_core::error::AosError;
use aos_core::output::{OutputMode, Printer};
use sysroot::KernelUpgradeMode;
use types::{
    ProfileScope, RegistryUploadAuthConfig, validate_branch_name, validate_channel_name,
    validate_commit_hash, validate_git_ref_name, validate_registry_name,
};

const PACKAGE_ATTESTATION_SEED_CATALOG: &str = "/etc/aos/package-attestation-catalog.json";

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
        /// Reconcile packages from a desired-package TOML file
        #[arg(long = "from")]
        from: Option<PathBuf>,
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
    /// Show package information
    Info {
        /// Package name
        package: String,
        /// Show package from this registry
        #[arg(long)]
        registry: Option<String>,
        /// Show permission metadata only
        #[arg(long)]
        permissions: bool,
        /// Query the system scope instead of the user scope
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
    },
    /// Remove upgrade hold
    Unhold {
        /// Package name
        package: String,
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
        /// Roll back the durable A/B image selection instead of configuration
        #[arg(long, requires = "system")]
        image: bool,
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
    /// Hidden: recover an interrupted credential publication transaction.
    #[command(name = "recover-credential-transactions", hide = true)]
    RecoverCredentialTransactions,
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
    /// Hidden: reconcile exposed package units from the package profile.
    #[command(name = "_test-reconcile-exposed-units", hide = true)]
    TestReconcileExposedUnits {
        /// Use the system package profile
        #[arg(long)]
        system: bool,
    },
    /// Hidden: verify an RFC-0001 package attestation event log.
    #[command(name = "_test-verify-package-attestation", hide = true)]
    TestVerifyPackageAttestation {
        /// Use system registry metadata
        #[arg(long)]
        system: bool,
        /// Package event log JSONL path
        #[arg(long)]
        event_log: PathBuf,
        /// Quoted PCR 15 value as SHA-256 hex
        #[arg(long)]
        pcr15: String,
        /// Expected PCR 15 value before package measurements
        #[arg(long)]
        pcr15_baseline: Option<String>,
    },
    /// Hidden: produce an RFC-0001 package attestation TPM quote.
    #[command(name = "_test-produce-package-attestation-quote", hide = true)]
    TestProducePackageAttestationQuote {
        /// Verifier nonce as an even-length hex string
        #[arg(long)]
        nonce: String,
        /// Directory where quote artifacts are written
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Hidden: load fleet BPF-LSM policies selected by host policy.
    #[command(name = "_load-ebpf-lsm-policies", hide = true)]
    LoadEbpfLsmPolicies {
        /// Use the system package profile
        #[arg(long)]
        system: bool,
    },
    /// Hidden: drive the on-host resolve/evaluate configuration fixpoint.
    ///
    /// Called only by `aos-eval.service`. Renders the working set into
    /// `entry.nix`, runs the sandboxed stock-Nix evaluator, fetches missing
    /// providers' config outputs, and — only on convergence — writes the
    /// manifest. Failure-safe: a terminal error writes no manifest, so the
    /// install step is a no-op and the active configuration remains unchanged.
    #[command(name = "__eval", hide = true)]
    Eval {
        /// The delivered leaf host.nix path
        #[arg(long = "host-nix")]
        host_nix: PathBuf,
        /// The in-image module library store path
        #[arg(long = "base-lib")]
        base_lib: PathBuf,
        /// Normalized metadata facts consumed as declared host inputs
        #[arg(long = "facts", default_value = config_eval::stock::DEFAULT_FACTS_PATH)]
        facts_json: PathBuf,
        /// A desired.toml whose `packages` seed the working set
        #[arg(long)]
        desired: Option<PathBuf>,
        /// The running image's base-lib module_abi
        #[arg(long = "module-abi")]
        module_abi: u32,
        /// Where to write the converged manifest (only on success)
        #[arg(long, default_value = config_eval::stock::DEFAULT_MANIFEST_PATH)]
        out: PathBuf,
        /// The eval root holding entry.nix
        #[arg(long = "eval-root", default_value = config_eval::stock::DEFAULT_EVAL_ROOT)]
        eval_root: PathBuf,
        /// Operator trust-anchor dir (trusted-config-keys.d); repeatable.
        #[arg(long = "trusted-config-keys-dir")]
        trusted_config_keys_dir: Vec<PathBuf>,
        /// Require a detached host.nix signature from a trusted config key.
        #[arg(long = "require-signed-host-nix")]
        require_signed_host_nix: bool,
        /// Mark host.nix as the image-authored empty no-input fallback.
        #[arg(long = "image-default-host")]
        image_default_host: bool,
    },
    /// Hidden: re-evaluate the active config on a newly booted image.
    #[command(name = "__eval-retained", hide = true)]
    EvalRetained {
        /// Where to write the converged manifest (only on success)
        #[arg(long, default_value = config_eval::stock::DEFAULT_MANIFEST_PATH)]
        out: PathBuf,
        /// The eval root holding generated evaluator inputs
        #[arg(long = "eval-root", default_value = config_eval::stock::DEFAULT_EVAL_ROOT)]
        eval_root: PathBuf,
    },
    /// Apply a converged config manifest into a per-generation `/etc` lower.
    ///
    /// Reads `--manifest` (an `aos.config-manifest/v1` document), writes its
    /// `--generation-dir` atomically publishes and validates the retained
    /// EROFS artifact used by activation. `--etc-root` is the unmounted-tree
    /// test seam; `--overlay-root` applies declared image-path removals to a
    /// mounted candidate overlay. Exactly one mode must be selected.
    #[command(name = "__materialize", hide = true)]
    Materialize {
        /// The converged manifest (`aos.config-manifest/v1` JSON).
        #[arg(long)]
        manifest: PathBuf,
        /// An unmounted `/etc` tree to write directly (test/compatibility mode).
        #[arg(long = "etc-root")]
        etc_root: Option<PathBuf>,
        /// Mounted candidate `/etc` overlay where image removals become whiteouts.
        #[arg(long = "overlay-root")]
        overlay_root: Option<PathBuf>,
        /// The durable config-generation directory that owns `config-lower/`.
        #[arg(long = "generation-dir")]
        generation_dir: Option<PathBuf>,
        /// Absolute path to the running image's AOS-built mkfs.erofs.
        #[arg(long = "mkfs-erofs")]
        mkfs_erofs: Option<PathBuf>,
        /// Absolute path to the running image's AOS-built fsck.erofs.
        #[arg(long = "fsck-erofs")]
        fsck_erofs: Option<PathBuf>,
        /// Runtime directory job scripts resolve to once the lower is `/etc`.
        #[arg(
            long = "job-scripts-runtime-dir",
            default_value = config_eval::materialize::DEFAULT_JOB_SCRIPTS_RUNTIME_DIR
        )]
        job_scripts_runtime_dir: String,
    },
    /// Hidden: commit a converged manifest as a configuration generation.
    ///
    /// Called by `aos-activate.service` after the soft fetch/render wing has
    /// settled. Re-projects the manifest onto successfully materialized
    /// packages, prepares a content-addressed generation, invokes the atomic
    /// toplevel activation script, and publishes the generation only after
    /// the `/etc` swap succeeds.
    #[command(name = "__activate-config", hide = true)]
    ActivateConfig {
        /// The evaluator-produced source manifest
        #[arg(long, default_value = graph_compile::DEFAULT_MANIFEST_PATH)]
        manifest: PathBuf,
        /// The evaluator-produced package dependency graph
        #[arg(long, default_value = graph_compile::DEFAULT_GRAPH_PATH)]
        graph: PathBuf,
        /// Root containing package fetch and render completion markers
        #[arg(long = "marker-root", default_value = graph_compile::subverbs::MARKER_ROOT)]
        marker_root: PathBuf,
        /// System-generation profile directory
        #[arg(long, default_value = "/var/lib/profiles/system")]
        profile: PathBuf,
        /// Running image's base-lib ABI
        #[arg(long = "module-abi")]
        module_abi: u32,
        /// Fail closed unless a TPM-backed generation quote is persisted.
        #[arg(long = "require-attestation-quote")]
        require_attestation_quote: bool,
    },
    /// Evaluate the configuration and diff it against the live generation.
    ///
    /// `--dry-run` runs the evaluator, loads the current generation's
    /// `gen-N/manifest.json`, prints a structural diff (etc entries, unit
    /// actions, closure delta), and stops before any generation or `/etc` swap
    /// — a clean no-op on the live system. The same codepath backs the CI
    /// `checks.config-eval` gate, so green CI predicts on-box behavior.
    Switch {
        /// Evaluate and diff only; never create a generation or touch /etc
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// The operator host.nix to evaluate (defaults to the staged stash leaf)
        #[arg(long = "from")]
        from: Option<PathBuf>,
        /// Base manifest selector: `current`, `gen-N`, or an explicit path
        #[arg(long = "diff-against")]
        diff_against: Option<String>,
        /// Label for the base side of the diff
        #[arg(long = "base-label", default_value = "current")]
        base_label: String,
        /// The in-image module library store path
        #[arg(long = "base-lib")]
        base_lib: Option<PathBuf>,
        /// Normalized metadata facts consumed by the same eval transaction
        #[arg(long = "facts", default_value = config_eval::stock::DEFAULT_FACTS_PATH)]
        facts_json: PathBuf,
        /// A desired.toml whose `packages` seed the working set
        #[arg(long)]
        desired: Option<PathBuf>,
        /// The running image's base-lib module_abi
        #[arg(long = "module-abi")]
        module_abi: Option<u32>,
        /// The eval root holding entry.nix
        #[arg(long = "eval-root", default_value = config_eval::stock::DEFAULT_EVAL_ROOT)]
        eval_root: PathBuf,
        /// Operator trust-anchor dir (trusted-config-keys.d); repeatable.
        #[arg(long = "trusted-config-keys-dir")]
        trusted_config_keys_dir: Vec<PathBuf>,
        /// Require a detached host.nix signature from a trusted config key.
        #[arg(long = "require-signed-host-nix")]
        require_signed_host_nix: bool,
        /// Where a real (non-dry-run) switch publishes the committed manifest
        #[arg(long = "live-manifest", default_value = graph_compile::DEFAULT_MANIFEST_PATH)]
        live_manifest: PathBuf,
    },
    /// Materialize one package's pinned NAR closure into the store.
    ///
    /// Backs the `aos-pkg-fetch@.service` template's `ExecStart=`. Reads the
    /// resolved closure for `<pkg>` from `/run/aos/manifest.json`, realises it
    /// via the configured substituters, and writes `/run/aos/fetch/<pkg>.ok` on
    /// success. Idempotent; safe to run concurrently for distinct packages.
    Fetch {
        /// Package whose closure to fetch
        package: String,
        /// The eval-produced manifest pinning the closure
        #[arg(long, default_value = graph_compile::DEFAULT_MANIFEST_PATH)]
        manifest: PathBuf,
        /// Root holding the per-package completion markers
        #[arg(long = "marker-root", default_value = graph_compile::subverbs::MARKER_ROOT)]
        marker_root: PathBuf,
    },
    /// Render one package's configuration artifacts into the staging area.
    ///
    /// Backs the `aos-pkg-install@.service` template's `ExecStart=`. Validates
    /// the package's `config`/`credentials` blocks against its signed
    /// `expose.config` metadata, stages the artifacts (never touching live
    /// `/etc`), and writes `/run/aos/render/<pkg>.ok`. Exits 2 on a config error.
    #[command(name = "render-one")]
    RenderOne {
        /// Package whose config to render
        package: String,
        /// The eval-produced manifest carrying the package's config block
        #[arg(long, default_value = graph_compile::DEFAULT_MANIFEST_PATH)]
        manifest: PathBuf,
        /// Root holding the per-package completion markers
        #[arg(long = "marker-root", default_value = graph_compile::subverbs::MARKER_ROOT)]
        marker_root: PathBuf,
        /// Root the rendered artifacts are staged under
        #[arg(long = "staging-root", default_value = graph_compile::subverbs::STAGING_ROOT)]
        staging_root: PathBuf,
    },
    /// Hidden: compile the eval output into a runtime systemd unit graph.
    ///
    /// Called only by `aos-graph-compile.service` (`After=aos-eval`,
    /// `ConditionPathExists=/run/aos/manifest.json`). Reads `manifest.json` +
    /// `graph.json`, writes per-instance dropins and `.wants` symlinks under
    /// `/run/systemd/system`, then `daemon-reload`s, awaits activation, and
    /// publishes `aos-config.target`. Talks to systemd over D-Bus and needs no
    /// apm config.
    #[command(name = "__graph-compile", hide = true)]
    GraphCompile {
        /// The eval-produced data contract
        #[arg(long, default_value = graph_compile::DEFAULT_MANIFEST_PATH)]
        manifest: PathBuf,
        /// The eval-produced cross-package DAG
        #[arg(long, default_value = graph_compile::DEFAULT_GRAPH_PATH)]
        graph: PathBuf,
        /// Override the `/run/systemd/system` root (development only)
        #[arg(long = "run-root")]
        run_root: Option<PathBuf>,
    },
}

/// Package credential helper operations.
#[derive(Subcommand)]
pub enum CredentialCommand {
    /// Encrypt plaintext for inline expose credential metadata
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
        /// Print a Nix expose.config.credentials entry
        #[arg(long)]
        expose_nix: bool,
        /// Service unit that consumes the credential
        #[arg(long = "unit")]
        units: Vec<String>,
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
    /// supports it.
    ///
    /// Mutating and sysroot commands (`install`, `upgrade`, `rollback`,
    /// `update`, `registry`) select the system scope to act on it; the
    /// read-only query commands (`search`, `show`, `list`, `depends`,
    /// `rdepends`, `policy`, `files`, `held`, `orphans`, `info`) select it to
    /// read the system registry cache and profile instead of the per-user ones.
    pub fn is_system(&self) -> bool {
        match self {
            PackageCommand::Install { system, .. } => *system,
            PackageCommand::Upgrade { system, .. } => *system,
            PackageCommand::Rollback { system, .. } => *system,
            PackageCommand::Update { system, .. } => *system,
            PackageCommand::Registry { system, .. } => *system,
            PackageCommand::Search { system, .. } => *system,
            PackageCommand::Show { system, .. } => *system,
            PackageCommand::Info { system, .. } => *system,
            PackageCommand::List { system, .. } => *system,
            PackageCommand::Depends { system, .. } => *system,
            PackageCommand::Rdepends { system, .. } => *system,
            PackageCommand::Policy { system, .. } => *system,
            PackageCommand::Files { system, .. } => *system,
            PackageCommand::Attest { command } => command.is_system(),
            PackageCommand::Held { system, .. } => *system,
            PackageCommand::Orphans { system, .. } => *system,
            PackageCommand::Clean { system, .. } => *system,
            PackageCommand::TestReconcileExposedUnits { system } => *system,
            PackageCommand::TestVerifyPackageAttestation { system, .. } => *system,
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
    /// Verify the local generation quote before blessing a booted image.
    #[command(name = "__verify-boot-commit", hide = true)]
    VerifyBootCommit {
        /// Generation-attestation JSON record produced by activation
        #[arg(long = "generation-attestation")]
        generation_attestation: PathBuf,
        /// Private quote bundle published beside the generation record
        #[arg(long = "quote-dir")]
        quote_dir: PathBuf,
        /// Catalog-published stable PCR 11, when the image record has one
        #[arg(long = "expected-pcr11")]
        expected_pcr11: Option<String>,
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
        #[arg(long)]
        pcr15_baseline: Option<String>,
        /// Generation-attestation JSON record to verify after CEL replay
        #[arg(long)]
        generation_attestation: Option<PathBuf>,
        /// Verifier-owned boot and host-trust policy for generation evidence
        #[arg(long, requires = "generation_attestation")]
        generation_policy_file: Option<PathBuf>,
        /// Independently re-derived manifest JSON for the optional step-10 gate
        #[arg(long, requires = "generation_attestation")]
        rederived_manifest: Option<PathBuf>,
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
            AttestCommand::Quote { .. }
            | AttestCommand::Enroll { .. }
            | AttestCommand::VerifyBootCommit { .. } => false,
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
    /// Manage the committed Secure Boot validation catalog (sb-certs.toml)
    #[command(name = "sb-certs")]
    SbCerts {
        /// The sb-certs.toml catalog operation to run
        #[command(subcommand)]
        command: SbCertsCommand,
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
        #[arg(long, required = true)]
        description: Option<String>,
        /// Package homepage
        #[arg(long)]
        homepage: Option<String>,
        /// Package license
        #[arg(long, required = true)]
        license: Option<String>,
        /// Package maintainer
        #[arg(long, required = true)]
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
        /// Exact UKI file for each --image (repeatable, paired with --image)
        #[arg(long = "image-uki")]
        image_ukis: Vec<String>,
        /// Expose manifest.json to publish with package metadata
        #[arg(long = "expose-manifest")]
        expose_manifest: Option<String>,
        /// Config-only module output to publish (contains module.nix and config-meta.json)
        #[arg(long = "config-module")]
        config_module: Option<String>,
        /// Trusted AOS base-lib store path used for the publish-time options-only eval
        #[arg(long = "config-base-lib", requires = "config_module")]
        config_base_lib: Option<String>,
        /// Named runtime output exposed to the config module (`name=/nix/store/...`)
        #[arg(long = "config-dependency", requires = "config_module")]
        config_dependencies: Vec<String>,
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
        /// Active key id whose configured private key signs the publish commit and provenance
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
    /// Commit explicit registry paths through AOS's in-process signer
    Commit {
        /// Registry-relative paths to stage and commit
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Commit message
        #[arg(short, long)]
        message: String,
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
    /// Git-backed config change requests (hub `refs/hub/changes/*`)
    Change {
        /// The change-request operation to run
        #[command(subcommand)]
        command: ChangeCommand,
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
    /// Static web-surface operations (the on-CDN no-JS browse pages)
    Web {
        /// The web operation to run
        #[command(subcommand)]
        command: WebCommand,
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
        /// Package version override when --store-path is used
        #[arg(long)]
        version: Option<String>,
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
        /// Exact UKI file for each --image when --store-path is used
        #[arg(long = "image-uki")]
        image_ukis: Vec<String>,
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
        /// Previous root key to co-sign a TUF root rotation (the key being rotated away from)
        #[arg(long = "rotate-from")]
        rotate_from: Option<PathBuf>,
        /// Nix narinfo signing key file in `name:base64-secret` form
        #[arg(long = "cache-key")]
        cache_key: Option<PathBuf>,
        /// Public cache URL to add to the committed registry cache stack.
        #[arg(long = "cache-url")]
        cache_url: Option<String>,
        /// Priority for generated nix-cache-info.
        #[arg(long = "cache-priority")]
        cache_priority: Option<u32>,
        /// Regenerate and re-upload paths even when local or remote entries exist
        #[arg(long = "no-skip")]
        no_skip: bool,
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
        /// Parallel compression jobs for the static cache (default: CPU count)
        #[arg(long)]
        jobs: Option<usize>,
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

/// Secure Boot validation-catalog subcommands.
///
/// These mutate the committed `sb-certs.toml` roster in an authoring clone:
/// the active db-cert set, its revocations, and the SBAT revocation floor
/// (RFC-0006 phase 4). Like `keys.toml`, every change is written with
/// [`registry_ops::run_sb_certs`] and committed (optionally signed) so the
/// catalog is covered by the registry's release signature.
#[derive(Subcommand)]
pub enum SbCertsCommand {
    /// List the active db certs, revocations, and SBAT floor
    List {
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Add an active Secure Boot db certificate to the catalog
    Add {
        /// Stable cert id used by revocation entries
        #[arg(value_name = "ID")]
        id: String,
        /// Lowercase hex SHA-256 of the db certificate (DER)
        #[arg(long = "cert-sha256", value_name = "HEX")]
        cert_sha256: String,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Private key path used to sign the catalog commit
        #[arg(long = "key")]
        signing_key: Option<String>,
        /// Active key id whose configured private key signs the commit
        #[arg(long = "key-id")]
        signing_key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Retire a db certificate by moving its id to [[revoked]]
    Retire {
        /// Active db cert id to retire
        #[arg(value_name = "ID")]
        id: String,
        /// Human-readable retirement reason
        #[arg(long)]
        reason: Option<String>,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Private key path used to sign the catalog commit
        #[arg(long = "key")]
        signing_key: Option<String>,
        /// Active key id whose configured private key signs the commit
        #[arg(long = "key-id")]
        signing_key_id: Option<String>,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Set (or raise) the SBAT revocation floor for a component
    SetFloor {
        /// SBAT component identifier (e.g. aos, systemd)
        #[arg(long, value_name = "COMPONENT")]
        component: String,
        /// Minimum acceptable SBAT generation for the component
        #[arg(long, value_name = "N")]
        generation: u32,
        /// Skip creating a git commit
        #[arg(long)]
        no_commit: bool,
        /// Private key path used to sign the catalog commit
        #[arg(long = "key")]
        signing_key: Option<String>,
        /// Active key id whose configured private key signs the commit
        #[arg(long = "key-id")]
        signing_key_id: Option<String>,
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

/// Git-backed config change-request subcommands.
///
/// A hub commits web edits to committed config as *change requests* under
/// `refs/hub/changes/<id>`, signed by a non-roster draft-signing key (so they
/// never verify for consumers). These subcommands let a maintainer list, review
/// the diff of, and **promote** a change request — re-signing the same tree
/// with a roster key onto the tracked branch.
#[derive(Subcommand)]
pub enum ChangeCommand {
    /// List the registry's open change requests
    List {
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show a change request's diff vs the current branch HEAD
    Show {
        /// The change-request id (the `refs/hub/changes/<id>` suffix)
        id: String,
        /// Show only file stats
        #[arg(long)]
        stat: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
    },
    /// Promote a change request: re-sign its tree onto the branch and push
    Merge {
        /// The change-request id to promote
        id: String,
        /// Signing key file (an SSH private key) to re-sign with
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
        output: Option<PathBuf>,
        /// Nix narinfo signing key file in `name:base64-secret` form
        #[arg(long)]
        key: Option<PathBuf>,
        /// Public cache URL to add to the committed registry cache stack.
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
        /// Priority for generated nix-cache-info.
        #[arg(long, default_value = "40")]
        priority: u32,
        /// Do not commit registry.toml after updating the cache stack.
        #[arg(long)]
        no_commit: bool,
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
        /// Parallel compression jobs for the static cache (default: CPU count)
        #[arg(long)]
        jobs: Option<usize>,
        /// Regenerate and re-upload paths even when local or remote entries exist
        #[arg(long = "no-skip")]
        no_skip: bool,
    },
    /// Garbage-collect old internally staged static-cache files
    Gc {
        /// Registry to operate on
        #[arg(long)]
        registry: Option<String>,
        /// Maximum unused age in days before deleting a staged narinfo/NAR pair
        #[arg(long = "max-age")]
        max_age: Option<u64>,
        /// Report candidates without deleting them
        #[arg(long)]
        dry_run: bool,
    },
}

/// Static web-surface subcommands.
///
/// The web surface is RFC-0004's on-CDN, no-JS browse tier: a registry
/// serves content-bearing `index.html`, JSON snapshots under `web/`, and
/// `browse/<name>.html` pages from its own bucket, with zero hub in the
/// serving path. `apr web generate` is the producer-side analogue of
/// `apr cache generate`.
#[derive(Subcommand)]
pub enum WebCommand {
    /// Generate the static no-JS web surface (index.html, JSON snapshots,
    /// browse pages) from the committed registry tree
    Generate {
        /// Output directory for the generated web surface (default: a
        /// `web` directory beside the registry clone)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Branding name shown on pages and in config.json (default: the
        /// registry.toml name)
        #[arg(long)]
        name: Option<String>,
        /// Optional hub base URL the SPA connects to, recorded in config.json
        #[arg(long = "hub-url")]
        hub_url: Option<String>,
        /// Optional accent color for the SPA theme, recorded in config.json
        #[arg(long)]
        accent: Option<String>,
        /// Optional path to a built Leptos CSR SPA dist (the output of
        /// `trunk build --release` in crates/aos-registry-spa); when given,
        /// its wasm/js/css are staged into web/ and the generated pages load
        /// them, progressively enhancing the no-JS floor
        #[arg(long = "spa-dist")]
        spa_dist: Option<PathBuf>,
        /// Backend URL to upload generated files to; repeat for multiple
        /// destinations (file://, s3://, sftp://, http://; default: the
        /// upload_urls persisted by `origin config`)
        #[arg(long = "upload-url")]
        upload_urls: Vec<String>,
        /// Authentication and backend-specific upload options
        #[command(flatten)]
        auth: CacheUploadAuthArgs,
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
    /// Custom S3-compatible endpoint (MinIO, B2, R2, etc.)
    #[arg(long, env = "S3_ENDPOINT")]
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

const DEFAULT_SWITCH_HOST_NIX: &str = "/run/aos-metadata/host.nix";
const DEFAULT_SWITCH_BASE_LIB: &str = "/aos-toplevel/base-lib";
const DEFAULT_SWITCH_OS_RELEASE: &str = "/aos-toplevel/os-release";
const DEFAULT_SYSTEM_GENERATION_PROFILE: &str = "/var/lib/profiles/system";

fn resolve_switch_manifest(selector: Option<&str>, profile: &Path) -> Result<(PathBuf, String)> {
    let selector = selector.unwrap_or("current");
    if selector == "current" {
        return Ok((profile.join("current/manifest.json"), "current".to_string()));
    }
    if let Some(number) = selector.strip_prefix("gen-") {
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("invalid configuration generation selector {selector:?}; expected gen-N");
        }
        return Ok((
            profile.join(format!("gen-{number}/manifest.json")),
            selector.to_string(),
        ));
    }
    Ok((PathBuf::from(selector), selector.to_string()))
}

fn running_module_abi(os_release: &Path) -> Result<u32> {
    let contents = std::fs::read_to_string(os_release)
        .with_context(|| format!("reading running image identity {}", os_release.display()))?;
    let value = contents
        .lines()
        .find_map(|line| line.strip_prefix("AOS_MODULE_ABI="))
        .context("running image os-release has no AOS_MODULE_ABI")?;
    value
        .trim_matches('"')
        .parse()
        .context("running image has an invalid AOS_MODULE_ABI")
}

fn resolve_default_switch_host(
    staged_host: &Path,
    current_manifest: &Path,
) -> Result<(PathBuf, bool)> {
    if staged_host.is_file() {
        return Ok((staged_host.to_path_buf(), false));
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(current_manifest).with_context(|| {
            format!(
                "reading current configuration manifest {} after {} was absent",
                current_manifest.display(),
                staged_host.display()
            )
        })?)
        .with_context(|| format!("parsing current manifest {}", current_manifest.display()))?;
    let host = manifest
        .pointer("/inputs/host_nix")
        .context("current manifest has no retained host input")?;
    let trust_mode = host
        .get("trust_mode")
        .and_then(serde_json::Value::as_str)
        .context("current manifest host input has no trust_mode")?;
    if !matches!(trust_mode, "image" | "image-default") {
        bail!(
            "staged host input {} is absent; restore authenticated metadata or pass --from explicitly",
            staged_host.display()
        );
    }
    let store_path = host
        .get("store_path")
        .and_then(serde_json::Value::as_str)
        .context("current image-default host input has no retained store path")?;
    let store_path = PathBuf::from(store_path);
    if !store_path.is_file() {
        bail!(
            "retained image-default host input is unavailable: {}",
            store_path.display()
        );
    }
    Ok((store_path, true))
}

/// Exits with the evaluator's stable class when an error crossed a CLI boundary.
fn exit_for_eval_failure(error: &anyhow::Error, verbose: u8) {
    let Some(failure) = error.downcast_ref::<config_eval::diagnostics::EvalCommandFailure>() else {
        return;
    };
    eprintln!("config-eval.class={} {}", failure.class_tag(), failure);
    if verbose > 0 {
        eprintln!("{}", failure.detail());
    }
    std::process::exit(failure.exit_code());
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

    if let PackageCommand::LoadEbpfLsmPolicies { system } = command {
        if !*system {
            bail!("_load-ebpf-lsm-policies requires --system");
        }
        return ebpf_lsm::load_system_policies();
    }

    // The on-host config-eval driver needs no apm config or profile: it reads
    // the registry index and host.nix from disk and shells out to stock nix.
    // Dispatch it before `ApmConfig::load` (mirrors the systemd-client vehicle).
    if let PackageCommand::Eval {
        host_nix,
        base_lib,
        facts_json,
        desired,
        module_abi,
        out,
        eval_root,
        trusted_config_keys_dir,
        require_signed_host_nix,
        image_default_host,
    } = command
    {
        let verbose = u8::from(printer.mode() == OutputMode::Verbose);
        let result = config_eval::run_eval_command(&config_eval::EvalCommand {
            host_nix: host_nix.clone(),
            base_lib: base_lib.clone(),
            facts_json: Some(facts_json.clone()),
            desired: desired.clone(),
            module_abi: *module_abi,
            out: out.clone(),
            eval_root: eval_root.clone(),
            verbose,
            trusted_config_keys_dirs: trusted_config_keys_dir.clone(),
            require_signed_host_nix: *require_signed_host_nix,
            image_default_host: *image_default_host,
        });
        if let Err(error) = &result {
            exit_for_eval_failure(error, verbose);
        }
        return result;
    }

    if let PackageCommand::EvalRetained { out, eval_root } = command {
        let verbose = u8::from(printer.mode() == OutputMode::Verbose);
        let result = sysroot::reeval_active_config_for_boot(
            &ProfileScope::System.profile_path(),
            eval_root.clone(),
            out.clone(),
            verbose,
        );
        if let Err(error) = &result {
            exit_for_eval_failure(error, verbose);
        }
        return result;
    }

    // `apm __materialize`: apply a converged manifest's
    // /etc tree into a per-generation lower. Called by `activate` on the new
    // path after the configuration fixpoint has converged.
    if let PackageCommand::Materialize {
        manifest,
        etc_root,
        overlay_root,
        generation_dir,
        mkfs_erofs,
        fsck_erofs,
        job_scripts_runtime_dir,
    } = command
    {
        return match (
            etc_root,
            overlay_root,
            generation_dir,
            mkfs_erofs,
            fsck_erofs,
        ) {
            (Some(etc_root), None, None, None, None) => {
                config_eval::materialize::materialize_manifest(
                    manifest,
                    etc_root,
                    job_scripts_runtime_dir,
                )
            }
            (None, Some(overlay_root), None, None, None) => {
                config_eval::materialize::apply_manifest_removals(&manifest, &overlay_root)
            }
            (None, None, Some(generation_dir), Some(mkfs_erofs), Some(fsck_erofs)) => {
                config_eval::materialize::materialize_generation_lower(
                    manifest,
                    generation_dir,
                    job_scripts_runtime_dir,
                    mkfs_erofs,
                    fsck_erofs,
                )
                .map(|_| ())
            }
            _ => bail!(
                "__materialize requires --etc-root alone, --overlay-root alone, or --generation-dir with --mkfs-erofs and --fsck-erofs"
            ),
        };
    }

    // The activation commit owns generation metadata and invokes the image's
    // switch script; it intentionally does not load registry/profile config.
    if let PackageCommand::ActivateConfig {
        manifest,
        graph,
        marker_root,
        profile,
        module_abi,
        require_attestation_quote,
    } = command
    {
        return match config_eval::activation::activate_config(
            &config_eval::activation::ActivateConfigParams {
                manifest: manifest.clone(),
                graph: graph.clone(),
                marker_root: marker_root.clone(),
                profile: profile.clone(),
                module_abi: *module_abi,
                switch_lock: config_eval::activation::default_switch_lock_path(),
                running_image: None,
                image_profile: PathBuf::from("/var/lib/profiles/image"),
                switch_lock_held: false,
                require_attestation_quote: *require_attestation_quote,
            },
        ) {
            Ok(_) => Ok(()),
            Err(error) => {
                if let Some(failure) =
                    error.downcast_ref::<config_eval::activation::ActivationFailure>()
                {
                    eprintln!("config activation: {failure}");
                    std::process::exit(failure.exit_code());
                }
                Err(error)
            }
        };
    }

    // `apm switch [--dry-run]`: evaluate and diff against
    // the live generation; the eval is a pure function of its inputs, so the
    // same codepath runs off-host (CI) and on-host.
    if let PackageCommand::Switch {
        dry_run: switch_dry_run,
        from,
        diff_against,
        base_label,
        base_lib,
        facts_json,
        desired,
        module_abi,
        eval_root,
        trusted_config_keys_dir,
        require_signed_host_nix,
        live_manifest,
    } = command
    {
        let verbose = u8::from(printer.mode() == OutputMode::Verbose);
        let json_out = printer.mode() == OutputMode::Json;
        let (base_manifest, selected_label) = resolve_switch_manifest(
            diff_against.as_deref(),
            Path::new(DEFAULT_SYSTEM_GENERATION_PROFILE),
        )?;
        let (host_nix, image_default_host) = match from {
            Some(path) => (path.clone(), false),
            None => resolve_default_switch_host(
                Path::new(DEFAULT_SWITCH_HOST_NIX),
                &Path::new(DEFAULT_SYSTEM_GENERATION_PROFILE).join("current/manifest.json"),
            )?,
        };
        let base_lib = match base_lib {
            Some(path) => path.clone(),
            None => std::fs::canonicalize(DEFAULT_SWITCH_BASE_LIB).with_context(|| {
                format!("resolving the running image base library {DEFAULT_SWITCH_BASE_LIB}")
            })?,
        };
        let module_abi = match module_abi {
            Some(value) => *value,
            None => running_module_abi(Path::new(DEFAULT_SWITCH_OS_RELEASE))?,
        };
        let base_label = if base_label == "current" {
            selected_label
        } else {
            base_label.clone()
        };
        // The candidate manifest is evaluated to a temp file; the diff reads it.
        let candidate =
            std::env::temp_dir().join(format!("aos-switch-candidate-{}.json", std::process::id()));
        let params = config_eval::dry_run::SwitchParams {
            eval: config_eval::EvalCommand {
                host_nix,
                base_lib,
                facts_json: Some(facts_json.clone()),
                desired: desired.clone(),
                module_abi,
                out: candidate,
                eval_root: eval_root.clone(),
                verbose,
                trusted_config_keys_dirs: trusted_config_keys_dir.clone(),
                require_signed_host_nix: *require_signed_host_nix,
                image_default_host,
            },
            base_manifest,
            base_label,
            dry_run: *switch_dry_run,
            live_manifest: live_manifest.clone(),
            json_out,
        };
        let result = config_eval::dry_run::run_switch(&params).await.map(|_| ());
        if let Err(error) = &result {
            exit_for_eval_failure(error, verbose);
        }
        return result;
    }

    // The graph compiler (`aos-graph-compile.service`) drives systemd
    // over D-Bus and reads the eval output from /run/aos; it needs no apm
    // config. Dispatch it before `ApmConfig::load` (like the eval driver).
    if let PackageCommand::GraphCompile {
        manifest,
        graph,
        run_root,
    } = command
    {
        return graph_compile::run_graph_compile_command(manifest, graph, run_root.as_deref())
            .await;
    }

    // The per-package fetch/render subverbs back the template `ExecStart=`s and
    // run as system services. They own their own exit codes (fetch: 0/1;
    // render-one: 0/1/2), so they exit directly rather than returning `Err`
    // (which `main.rs` would flatten to 1) — mirroring the activate split.
    if let PackageCommand::Fetch {
        package,
        manifest,
        marker_root,
    } = command
    {
        let config = config::ApmConfig::load(ProfileScope::System)?;
        let json_out = printer.mode() == OutputMode::Json;
        let code = graph_compile::subverbs::run_fetch(
            &config,
            package,
            manifest,
            marker_root,
            json_out,
            printer,
        )
        .await;
        std::process::exit(code);
    }
    if let PackageCommand::RenderOne {
        package,
        manifest,
        marker_root,
        staging_root,
    } = command
    {
        let config = config::ApmConfig::load(ProfileScope::System)?;
        let json_out = printer.mode() == OutputMode::Json;
        let code = graph_compile::subverbs::run_render_one(
            &config,
            package,
            manifest,
            marker_root,
            staging_root,
            json_out,
            printer,
        )
        .await;
        std::process::exit(code);
    }

    if let PackageCommand::TestProducePackageAttestationQuote { nonce, output_dir } = command {
        return run_produce_package_attestation_quote(nonce, output_dir, printer);
    }

    if let PackageCommand::Attest {
        command:
            AttestCommand::Quote {
                nonce,
                nonce_file,
                output_dir,
            },
    } = command
    {
        let nonce = read_attestation_nonce(nonce, nonce_file)?;
        return run_produce_package_attestation_quote(&nonce, output_dir, printer);
    }

    if let PackageCommand::Attest {
        command:
            AttestCommand::Enroll {
                quote_dir,
                label,
                method,
                evidence_file,
                catalog_file,
            },
    } = command
    {
        return run_enroll_package_attestation_quote(
            quote_dir,
            catalog_file,
            label,
            *method,
            evidence_file,
            printer,
        );
    }

    if let PackageCommand::Attest {
        command:
            AttestCommand::VerifyBootCommit {
                generation_attestation,
                quote_dir,
                expected_pcr11,
            },
    } = command
    {
        return verify_local_boot_commit(
            generation_attestation,
            quote_dir,
            expected_pcr11.as_deref(),
        );
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
    if let PackageCommand::RecoverCredentialTransactions = command {
        return credential_artifact::recover_credential_transactions(
            &credential_artifact::aos_root_path(),
        );
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
            from,
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
            if let Some(path) = from {
                if !*install_system {
                    anyhow::bail!("apm install --from requires --system");
                }
                if !packages.is_empty() {
                    anyhow::bail!("apm install --from cannot be combined with package names");
                }
                if registry.is_some()
                    || *download_only
                    || *reinstall
                    || *no_deps
                    || image_fmt.is_some()
                    || image_output.is_some()
                {
                    anyhow::bail!(
                        "apm install --from cannot be combined with registry, download, reinstall, dependency, or image options"
                    );
                }
                desired::reconcile_from_file(&config, path, dry_run, yes, printer).await
            } else if *install_system || image_fmt.is_some() {
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
                clean::run_gc_after_mutation(config.scope, printer).await?;
            }
            Ok(())
        }
        PackageCommand::Autoremove => {
            let outcome = remove::run_autoremove(&config, dry_run, yes, printer).await?;
            if config.settings.auto_gc && !dry_run && outcome.orphan_count > 0 {
                clean::run_gc_after_mutation(config.scope, printer).await?;
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
        PackageCommand::Info {
            package,
            registry,
            permissions,
            ..
        } => query::info(&config, package, registry.as_deref(), *permissions, printer).await,
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
                    generation_attestation,
                    generation_policy_file,
                    rederived_manifest,
                    ..
                },
        } => {
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
                pcr15_baseline,
                generation_attestation.as_deref(),
                generation_policy_file.as_deref(),
                rederived_manifest.as_deref(),
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
        PackageCommand::Attest {
            command: AttestCommand::VerifyBootCommit { .. },
        } => unreachable!("AttestCommand::VerifyBootCommit is handled before ApmConfig::load"),
        PackageCommand::Hold { package } => hold::run_hold(&config, package, printer).await,
        PackageCommand::Unhold { package } => hold::run_unhold(&config, package, printer).await,
        PackageCommand::Held { .. } => hold::run_held(&config, printer).await,
        PackageCommand::Orphans { .. } => query::orphans(&config, printer).await,
        PackageCommand::Clean {
            generations, keep, ..
        } => clean::run(&config, *generations, *keep, printer).await,
        PackageCommand::Gc => clean::run_gc(config.scope, printer).await,
        PackageCommand::Verify { package } => source::run_verify(&config, package, printer).await,
        PackageCommand::Source {
            package,
            show_drv,
            fetch,
            verify,
        } => source::run_source(&config, package, *show_drv, *fetch, *verify, printer).await,
        PackageCommand::Credential(command) => credential::run(&config, command, printer),
        PackageCommand::Rollback {
            generation,
            system: rollback_system,
            image,
            list: rollback_list,
            kexec,
            reboot,
            live,
            drain,
        } => {
            if *rollback_system && *image {
                let kernel_mode = parse_kernel_mode(*kexec, *reboot, *live);
                sysroot::rollback_image_generation(
                    *generation,
                    *rollback_list,
                    dry_run,
                    kernel_mode,
                    *drain,
                    printer,
                )
                .await
            } else if *rollback_system {
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
        PackageCommand::TestReconcileExposedUnits { .. } => {
            exposed_units::reconcile_system_profile(&config, printer).await
        }
        PackageCommand::TestVerifyPackageAttestation {
            event_log,
            pcr15,
            pcr15_baseline,
            ..
        } => run_verify_package_attestation(
            &config,
            event_log,
            AttestationMeasurement::Pcr15(pcr15.clone()),
            &[],
            pcr15_baseline,
            None,
            None,
            None,
            printer,
        ),
        PackageCommand::TestProducePackageAttestationQuote { .. } => {
            unreachable!("TestProducePackageAttestationQuote is handled before ApmConfig::load")
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
        PackageCommand::RecoverCredentialTransactions => {
            unreachable!("RecoverCredentialTransactions is handled before ApmConfig::load")
        }
        PackageCommand::LoadEbpfLsmPolicies { .. } => {
            unreachable!("LoadEbpfLsmPolicies is handled before ApmConfig::load")
        }
        PackageCommand::Eval { .. } => {
            unreachable!("Eval is handled before ApmConfig::load")
        }
        PackageCommand::EvalRetained { .. } => {
            unreachable!("EvalRetained is handled before ApmConfig::load")
        }
        PackageCommand::Materialize { .. } => {
            unreachable!("Materialize is handled before ApmConfig::load")
        }
        PackageCommand::ActivateConfig { .. } => {
            unreachable!("ActivateConfig is handled before ApmConfig::load")
        }
        PackageCommand::Switch { .. } => {
            unreachable!("Switch is handled before ApmConfig::load")
        }
        PackageCommand::GraphCompile { .. } => {
            unreachable!("GraphCompile is handled before ApmConfig::load")
        }
        PackageCommand::Fetch { .. } => {
            unreachable!("Fetch is handled before ApmConfig::load")
        }
        PackageCommand::RenderOne { .. } => {
            unreachable!("RenderOne is handled before ApmConfig::load")
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

const GENERATION_VERIFIER_POLICY_SCHEMA: &str = "aos.gen-attestation-policy/v2";

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationVerifierPolicyFile {
    schema: String,
    expected_pcr7: String,
    expected_pcr11: String,
    expected_pcr12: String,
    expected_root_roothash: String,
    #[serde(default)]
    expected_facts_hash: Option<String>,
    #[serde(default)]
    trusted_config_keys: Vec<String>,
    #[serde(default)]
    trusted_platforms: Vec<String>,
    #[serde(default)]
    image_config_modules: Vec<attestation::VerifiedConfigModuleMember>,
}

#[derive(Debug, serde::Serialize)]
struct GenerationVerificationSummary {
    activation_id: String,
    generation_id: String,
    manifest_hash: String,
    registry: Option<String>,
    release_tag: Option<String>,
    tag_signer_key: Option<String>,
    realization: Option<String>,
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
    rederived_manifest: Option<&Path>,
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
            rederived_manifest,
            quoted_generation_quote.as_ref().context(
                "--generation-attestation requires --quote-dir; a bare PCR 15 value does not authenticate PCR 7/11 or the AK",
            )?,
            &trust,
            &verified,
        )?),
        None => {
            if generation_policy_file.is_some() || rederived_manifest.is_some() {
                bail!(
                    "--generation-policy-file and --rederived-manifest require --generation-attestation"
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

fn verify_generation_attestation_cli(
    config: &config::ApmConfig,
    record_path: &Path,
    policy_path: &Path,
    rederived_manifest: Option<&Path>,
    checker: &PreverifiedGenerationQuote,
    quote_trust: &AttestationQuoteTrust,
    cel: &package_attestation::PackageEventLogVerification,
) -> Result<GenerationVerificationSummary> {
    verify_generation_attestation_cli_with(
        record_path,
        policy_path,
        rederived_manifest,
        checker,
        quote_trust,
        cel,
        |modules| verified_generation_release(config, modules),
    )
}

fn verify_generation_attestation_cli_with<F>(
    record_path: &Path,
    policy_path: &Path,
    rederived_manifest: Option<&Path>,
    checker: &PreverifiedGenerationQuote,
    quote_trust: &AttestationQuoteTrust,
    cel: &package_attestation::PackageEventLogVerification,
    verify_release: F,
) -> Result<GenerationVerificationSummary>
where
    F: FnOnce(
        &attestation::ConfigModulesAttInput,
    ) -> Result<(
        Vec<String>,
        Vec<String>,
        Option<attestation::VerifiedConfigModuleRelease>,
    )>,
{
    if !matches!(quote_trust, AttestationQuoteTrust::IdentityPinned { .. }) {
        bail!(
            "generation attestation verification requires an enrolled --quote-identity-file; a self-consistent AK is not a trust anchor"
        );
    }
    let record: attestation::GenAttestation = serde_json::from_slice(
        &fs::read(record_path).with_context(|| format!("reading {}", record_path.display()))?,
    )
    .with_context(|| format!("parsing {}", record_path.display()))?;
    let policy_file: GenerationVerifierPolicyFile = serde_json::from_slice(
        &fs::read(policy_path).with_context(|| format!("reading {}", policy_path.display()))?,
    )
    .with_context(|| format!("parsing {}", policy_path.display()))?;
    if policy_file.schema != GENERATION_VERIFIER_POLICY_SCHEMA {
        bail!(
            "unsupported generation verifier policy schema {:?}",
            policy_file.schema
        );
    }

    let measured_hash = cel
        .generation_attestations
        .get(&record.activation_id)
        .with_context(|| {
            format!(
                "CEL has no generation event for activation {}",
                record.activation_id
            )
        })?;
    let expected_hash = format!("sha256:{}", hex::encode(attestation::record_hash(&record)?));
    if !measured_hash.eq_ignore_ascii_case(&expected_hash) {
        bail!("generation record does not match its activation event in the CEL");
    }
    let prior = cel
        .generation_attestation_prefix_digests
        .get(&record.activation_id)
        .with_context(|| {
            format!(
                "CEL has no unambiguous prefix for activation {}",
                record.activation_id
            )
        })?
        .clone();

    let (roster, revoked, release) = verify_release(&record.inputs.config_modules)?;
    let rederived_hash = rederived_manifest
        .map(hash_rederived_manifest)
        .transpose()?;
    let rederive = rederived_hash
        .as_ref()
        .map(|hash| move |_record: &attestation::GenAttestation| hash.clone());
    let verifier_policy = attestation::VerifierPolicy {
        expected_pcr7: policy_file.expected_pcr7,
        expected_pcr11: policy_file.expected_pcr11,
        expected_pcr12: policy_file.expected_pcr12,
        expected_root_roothash: policy_file.expected_root_roothash,
        expected_facts_hash: policy_file.expected_facts_hash,
        pcr15_baseline: cel.pcr15_baseline.clone(),
        prior_pcr15_event_digests: prior,
        trusted_config_keys: policy_file.trusted_config_keys,
        trusted_platforms: policy_file.trusted_platforms,
        roster_fingerprints: roster,
        revoked_roster_fingerprints: revoked,
        valid_release_tags: release.into_iter().collect(),
        image_config_modules: policy_file.image_config_modules,
    };
    attestation::verify_gen_attestation(
        &record,
        checker,
        &verifier_policy,
        &attestation::record_hash(&record)?,
        rederive
            .as_ref()
            .map(|callback| callback as &dyn Fn(&attestation::GenAttestation) -> String),
    )
    .map_err(|failure| anyhow::anyhow!("generation attestation failed: {failure}"))?;

    Ok(GenerationVerificationSummary {
        activation_id: record.activation_id,
        generation_id: record.generation_id,
        manifest_hash: record.manifest_hash,
        registry: record.inputs.config_modules.registry,
        release_tag: record.inputs.config_modules.release_tag,
        tag_signer_key: record.inputs.config_modules.tag_signer_key,
        realization: record.inputs.config_modules.realization,
        rederived: rederived_hash.is_some(),
    })
}

fn hash_rederived_manifest(path: &Path) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    Ok(graph_compile::reproject::hash_cjson(&value))
}

fn verify_local_boot_commit(
    record_path: &Path,
    quote_dir: &Path,
    catalog_expected_pcr11: Option<&str>,
) -> Result<()> {
    let record: attestation::GenAttestation = serde_json::from_slice(
        &fs::read(record_path).with_context(|| format!("reading {}", record_path.display()))?,
    )
    .with_context(|| format!("parsing {}", record_path.display()))?;
    if record.schema != attestation::GEN_ATTESTATION_SCHEMA
        || record.quote_status != attestation::QUOTE_STATUS_QUOTED
        || record.quote.is_empty()
    {
        bail!("generation attestation is not a complete quoted record");
    }
    let embedded: EmbeddedGenerationQuote = serde_json::from_slice(
        &hex::decode(&record.quote).context("decoding embedded generation quote")?,
    )
    .context("parsing embedded generation quote")?;
    let nonce = hex::encode(attestation::record_hash(&record)?);
    if embedded.schema != "aos.gen-attestation-quote/v1"
        || embedded.nonce != nonce
        || embedded.pcr_selection != "sha256:7,11,12,15"
    {
        bail!("embedded generation quote does not bind the activation record and PCR policy");
    }
    let verified = package_attestation::verify_attestation_quote_bundle(quote_dir, &nonce, &[])?;
    if embedded.ak_public != verified.bundle.ak_public
        || embedded.quote_message != verified.bundle.quote_message
        || embedded.quote_signature != verified.bundle.quote_signature
        || embedded.quote_pcrs != verified.bundle.quote_pcrs
        || !embedded
            .quoted_pcr15
            .eq_ignore_ascii_case(&verified.quoted_pcr15)
    {
        bail!("embedded generation quote differs from the signature-verified bundle");
    }
    let record_expected = record
        .inputs
        .base_lib
        .pcr11_expected
        .as_deref()
        .context("generation attestation has no expected PCR 11")?
        .trim_start_matches("sha256:");
    if !verified.quoted_pcr11.eq_ignore_ascii_case(record_expected)
        || catalog_expected_pcr11.is_some_and(|expected| {
            !verified
                .quoted_pcr11
                .eq_ignore_ascii_case(expected.trim_start_matches("sha256:"))
        })
    {
        bail!("generation quote PCR 11 does not match the published image expectation");
    }
    let live_pcr7 = package_attestation::current_pcr7()?;
    let live_pcr11 = package_attestation::current_pcr11()?;
    let live_pcr12 = package_attestation::current_pcr12()?;
    if !verified
        .quoted_pcr7
        .eq_ignore_ascii_case(live_pcr7.trim_start_matches("sha256:"))
        || !verified
            .quoted_pcr11
            .eq_ignore_ascii_case(live_pcr11.trim_start_matches("sha256:"))
        || !verified
            .quoted_pcr12
            .eq_ignore_ascii_case(live_pcr12.trim_start_matches("sha256:"))
    {
        bail!("generation quote does not bind the live PCR 7/11/12 state");
    }
    Ok(())
}

fn verified_generation_release(
    config: &config::ApmConfig,
    modules: &attestation::ConfigModulesAttInput,
) -> Result<(
    Vec<String>,
    Vec<String>,
    Option<attestation::VerifiedConfigModuleRelease>,
)> {
    verified_generation_release_from_paths(
        &config.cache_path(),
        config.scope.trusted_keys_dirs(),
        modules,
    )
}

fn verified_generation_release_from_paths(
    cache_path: &Path,
    trusted_keys_dirs: Vec<PathBuf>,
    modules: &attestation::ConfigModulesAttInput,
) -> Result<(
    Vec<String>,
    Vec<String>,
    Option<attestation::VerifiedConfigModuleRelease>,
)> {
    let Some(registry_modules) = registry_config_module_subset(modules)? else {
        return Ok((Vec::new(), Vec::new(), None));
    };
    let registry_name = registry_modules
        .registry
        .as_deref()
        .context("generation config modules have no registry")?;
    let repo = cache_path.join(registry_name).join("repo.git");
    if !repo.is_dir() {
        bail!(
            "verified registry repository for '{}' is unavailable at {}",
            registry_name,
            repo.display()
        );
    }
    let key_store = security::KeyStore::new(trusted_keys_dirs);
    let keys = key_store.lookup_all(registry_name);
    let revoked = key_store.revoked_fingerprints(registry_name);
    let receipt =
        registry::load_release_trust_receipt(&cache_path.join(registry_name), registry_name)?
            .with_context(|| {
                format!("registry '{registry_name}' has no signed-release trust receipt")
            })?;
    verify_generation_release_snapshot(&repo, &keys, revoked, &receipt, &registry_modules)
}

/// Selects the registry-authenticated portion of mixed config-module evidence.
///
/// Image-origin modules are authenticated by the generation's verified-boot
/// binding, so the public verifier must not demand a registry release for
/// them. Registry-origin modules remain subject to the full signed-tag and
/// store-graph verification below. Records that predate explicit `origins`
/// are interpreted as registry-only for compatibility.
fn registry_config_module_subset(
    modules: &attestation::ConfigModulesAttInput,
) -> Result<Option<attestation::ConfigModulesAttInput>> {
    if modules.count == 0 {
        return Ok(None);
    }
    if modules.count != modules.package_names.len()
        || modules.count != modules.store_paths.len()
        || modules.count != modules.nar_hashes.len()
    {
        bail!("generation config-module membership vectors are inconsistent");
    }

    let origins = match modules.provenance.get("origins") {
        Some(value) => serde_json::from_value::<Vec<String>>(value.clone())
            .context("generation config-module origins are malformed")?,
        None => vec!["registry".to_string(); modules.count],
    };
    if origins.len() != modules.count
        || origins
            .iter()
            .any(|origin| origin != "registry" && origin != "image")
    {
        bail!("generation config-module origins are inconsistent");
    }
    let indexes = origins
        .iter()
        .enumerate()
        .filter_map(|(index, origin)| (origin == "registry").then_some(index))
        .collect::<Vec<_>>();
    if indexes.is_empty() {
        return Ok(None);
    }

    let mut subset = modules.clone();
    subset.count = indexes.len();
    subset.package_names = indexes
        .iter()
        .map(|index| modules.package_names[*index].clone())
        .collect();
    subset.store_paths = indexes
        .iter()
        .map(|index| modules.store_paths[*index].clone())
        .collect();
    subset.nar_hashes = indexes
        .iter()
        .map(|index| modules.nar_hashes[*index].clone())
        .collect();
    let mut closure_members = subset
        .store_paths
        .iter()
        .zip(&subset.nar_hashes)
        .map(|(path, nar_hash)| serde_json::json!([path, nar_hash]))
        .collect::<Vec<_>>();
    closure_members.sort_by(|left, right| {
        left[0]
            .as_str()
            .unwrap_or_default()
            .cmp(right[0].as_str().unwrap_or_default())
    });
    subset.closure_hash =
        graph_compile::reproject::hash_cjson(&serde_json::Value::Array(closure_members));
    Ok(Some(subset))
}

fn verify_generation_release_snapshot(
    repo: &Path,
    keys: &[security::TrustedKey],
    revoked: Vec<String>,
    receipt: &registry::ReleaseTrustReceipt,
    modules: &attestation::ConfigModulesAttInput,
) -> Result<(
    Vec<String>,
    Vec<String>,
    Option<attestation::VerifiedConfigModuleRelease>,
)> {
    if modules.count == 0
        || modules.count != modules.package_names.len()
        || modules.count != modules.store_paths.len()
        || modules.count != modules.nar_hashes.len()
    {
        bail!("generation config-module membership vectors are inconsistent");
    }
    let registry_name = modules
        .registry
        .as_deref()
        .context("generation config modules have no registry")?;
    let release_tag = modules
        .release_tag
        .as_deref()
        .context("generation config modules have no release tag")?;
    let signer = modules
        .tag_signer_key
        .as_deref()
        .context("generation config modules have no tag signer")?;
    if revoked
        .iter()
        .any(|fingerprint| fingerprint.eq_ignore_ascii_case(signer))
    {
        bail!("release tag signer {signer} is revoked in registry '{registry_name}'");
    }
    let roster = keys
        .iter()
        .map(|key| key.fingerprint.clone())
        .collect::<Vec<_>>();
    let signing_key = keys
        .iter()
        .find(|key| key.fingerprint == signer)
        .with_context(|| {
            format!("release tag signer {signer} is not active in registry '{registry_name}'")
        })?
        .key_line();
    let tag_object = registry::repo::rev_parse_blocking(&repo, &format!("{release_tag}^{{tag}}"))
        .with_context(|| format!("resolving release tag object '{release_tag}'"))?;
    if !security::verify_tag_signature(&repo, &tag_object, &[signing_key])? {
        bail!("release tag '{release_tag}' is not signed by roster key {signer}");
    }
    let tag = registry::verify::read_tag_object(&repo, &tag_object)?;
    registry::verify::verify_name_binding(&tag, release_tag)?;
    if tag.target_type != registry::verify::TagTarget::Commit {
        bail!("release tag '{release_tag}' does not target a commit");
    }
    semver::Version::parse(release_tag)
        .with_context(|| format!("release tag '{release_tag}' is not semver"))?;
    ensure_release_receipt_matches(receipt, registry_name, release_tag, &tag.object, signer)?;

    let mut members = Vec::with_capacity(modules.count);
    let mut realization_members = Vec::with_capacity(modules.count);
    for ((package_name, store_path), nar_hash) in modules
        .package_names
        .iter()
        .zip(&modules.store_paths)
        .zip(&modules.nar_hashes)
    {
        let (module_abi_compat, authorization) = verify_signed_config_module_member(
            &repo,
            &tag.object,
            package_name,
            store_path,
            nar_hash,
        )?;
        let root = registry::store_path_hash(store_path);
        let subset = signed_store_subset_hash(&repo, &tag.object, root)?;
        realization_members.push(serde_json::json!([store_path, subset]));
        members.push(attestation::VerifiedConfigModuleMember {
            package_name: package_name.clone(),
            store_path: store_path.clone(),
            nar_hash: nar_hash.clone(),
            module_abi_compat,
            authorization,
        });
    }
    realization_members.sort_by(|left, right| {
        left[0]
            .as_str()
            .unwrap_or_default()
            .cmp(right[0].as_str().unwrap_or_default())
    });
    let realization =
        graph_compile::reproject::hash_cjson(&serde_json::Value::Array(realization_members));
    Ok((
        roster,
        revoked,
        Some(attestation::VerifiedConfigModuleRelease {
            registry: registry_name.to_string(),
            release_tag: release_tag.to_string(),
            signer_fingerprints: vec![signer.to_string()],
            realization,
            config_modules: members,
        }),
    ))
}

fn ensure_release_receipt_matches(
    receipt: &registry::ReleaseTrustReceipt,
    registry_name: &str,
    release_tag: &str,
    commit: &str,
    signer: &str,
) -> Result<()> {
    if receipt.registry != registry_name
        || receipt.release_tag != release_tag
        || receipt.commit != commit
        || receipt.tag_signer_key != signer
    {
        bail!("signed-release trust receipt does not match the reverified release tag and signer");
    }
    Ok(())
}

fn verify_signed_config_module_member(
    repo: &Path,
    commit: &str,
    package_name: &str,
    store_path: &str,
    nar_hash: &str,
) -> Result<(types::ModuleAbiCompat, config_eval::PackageAuthorization)> {
    types::validate_package_name(package_name)?;
    let path = format!(
        "packages/{}/{}.toml",
        types::package_name_bucket(package_name),
        package_name
    );
    let bytes = registry::repo::read_blob_at_blocking(repo, commit, &path)?
        .with_context(|| format!("signed release has no package catalog entry {path}"))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("signed package catalog entry {path} is not UTF-8"))?;
    let package = registry::parse::parse_package_file(text)?;
    if package.package.name != package_name {
        bail!("signed package catalog entry {path} has the wrong package identity");
    }
    let canonical_nar = registry::store::NarBytes::from_hash(nar_hash, 0)?.nar_hash();
    let matching = package
        .versions
        .iter()
        .flat_map(|version| version.platforms.values())
        .filter_map(|platform| platform.config_module.as_ref())
        .filter(|module| {
            module.config_output.store_path == store_path
                && registry::store::NarBytes::from_hash(&module.config_output.nar_hash, 0)
                    .is_ok_and(|nar| nar.nar_hash() == canonical_nar)
        })
        .collect::<Vec<_>>();
    let [module] = matching.as_slice() else {
        bail!(
            "signed release catalog must authenticate config output {store_path} exactly once for package {package_name}"
        );
    };
    Ok((
        module.module_abi_compat,
        signed_module_authorization(module),
    ))
}

fn signed_module_authorization(
    module: &types::ConfigModuleMeta,
) -> config_eval::PackageAuthorization {
    let mut owns = module
        .owns_roots
        .iter()
        .map(|owned| owned.root.clone())
        .collect::<Vec<_>>();
    owns.sort();
    owns.dedup();
    let mut contributes = BTreeMap::<String, Vec<String>>::new();
    for contribution in &module.contributes {
        contributes
            .entry(contribution.root.clone())
            .or_default()
            .extend(contribution.paths.iter().cloned());
    }
    for paths in contributes.values_mut() {
        paths.sort();
        paths.dedup();
    }
    config_eval::PackageAuthorization { owns, contributes }
}

fn signed_store_subset_hash(repo: &Path, commit: &str, root: &str) -> Result<String> {
    let mut pending = vec![root.to_string()];
    let mut seen = BTreeSet::new();
    let mut members = BTreeMap::new();
    while let Some(ia) = pending.pop() {
        if !seen.insert(ia.clone()) {
            continue;
        }
        let shard = ia
            .get(..2)
            .with_context(|| format!("invalid store hash {ia:?}"))?;
        let path = format!("store/{shard}/{ia}");
        let bytes = registry::repo::read_blob_at_blocking(repo, commit, &path)?
            .with_context(|| format!("signed release has no store record {path}"))?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("signed store record {path} is not UTF-8"))?;
        let entry = registry::store::parse_entry(text)?;
        if entry.realisations.is_empty() {
            bail!("signed release has an empty store record {path}");
        }
        pending.extend(entry.dep_ias());
        members.insert(ia, registry::store::serialize_entry(&entry));
    }
    Ok(graph_compile::reproject::hash_cjson(
        &serde_json::to_value(members).context("serializing signed store subset")?,
    ))
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
    package_attestation_catalog_from_sources(
        &catalog,
        Some(Path::new(PACKAGE_ATTESTATION_SEED_CATALOG)),
        catalog_files,
    )
}

fn package_attestation_catalog_from_sources(
    registry_packages: &[types::PackageMeta],
    seed_catalog: Option<&Path>,
    catalog_files: &[PathBuf],
) -> Result<Vec<package_attestation::PackageMeasurementCatalogEntry>> {
    let mut catalog =
        package_attestation::package_measurement_catalog_from_package_meta(registry_packages)?;
    if let Some(seed_catalog) = seed_catalog {
        append_optional_package_attestation_catalog(seed_catalog, &mut catalog)?;
    }
    for path in catalog_files {
        append_package_attestation_catalog(path, &mut catalog)?;
    }
    package_attestation::canonical_package_measurement_catalog(&catalog)
}

fn append_optional_package_attestation_catalog(
    path: &Path,
    catalog: &mut Vec<package_attestation::PackageMeasurementCatalogEntry>,
) -> Result<()> {
    match read_package_attestation_catalog(path) {
        Ok(entries) => {
            catalog.extend(entries);
            Ok(())
        }
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == ErrorKind::NotFound) =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
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
        RegistryCommand::SbCerts { command } => {
            registry_ops::run_sb_certs(config, command, printer)
        }
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
            image_ukis,
            expose_manifest,
            config_module,
            config_base_lib,
            config_dependencies,
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
                image_ukis,
                expose_manifest.as_deref(),
                config_module.as_deref(),
                config_base_lib.as_deref(),
                config_dependencies,
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
        RegistryCommand::Commit {
            paths,
            message,
            key,
            key_id,
            registry,
        } => {
            registry_ops::commit_changes(
                config,
                paths,
                message,
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
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
        RegistryCommand::Change { command } => {
            registry_ops::run_change(config, command, printer).await
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
        RegistryCommand::Web { command } => registry_ops::run_web(config, command, printer).await,
        RegistryCommand::Release {
            semver,
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
            image_ukis,
            bless,
            message,
            channel,
            init_channel,
            count,
            partitions,
            key,
            key_id,
            rotate_from,
            cache_key,
            cache_url,
            cache_priority,
            no_skip,
            upload_urls,
            auth,
            dry_run,
            resume,
            registry,
            jobs,
        } => {
            registry_ops::release(
                config,
                semver,
                store_path.as_deref(),
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
                image_ukis,
                *bless,
                message.as_deref(),
                channel.as_deref(),
                *init_channel,
                *count,
                partitions.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                rotate_from.as_deref(),
                cache_key.as_deref(),
                cache_url.as_deref(),
                *cache_priority,
                *no_skip,
                upload_urls,
                auth,
                *dry_run,
                *resume,
                registry.as_deref(),
                *jobs,
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

    // A brand-new registry is a self-sufficient definition, written to the
    // writable config layer (`/var/lib/apm/config` for --system), never the
    // read-only `/etc/apm` seed.
    let registries_dir = config.scope.writable_config_dir().join("registries.d");
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

    let normalized = url.strip_prefix("git+").unwrap_or(url);
    clone_authoring_registry(&clone_dir, normalized, branch, tag, commit)
        .with_context(|| format!("cloning registry '{name}' from {url}"))?;

    printer.info(&format!("Authoring clone ready at {}", clone_dir.display()));
    Ok(())
}

/// Clone `url` into `clone_dir` for authoring, then check out the requested
/// ref, using libgit2 for smart transports (local, `git://`, `ssh://`) and the
/// pure-Rust dumb-HTTP reader for static `http(s)://` origins.
fn clone_authoring_registry(
    clone_dir: &std::path::Path,
    url: &str,
    branch: Option<&str>,
    tag: Option<&str>,
    commit: Option<&str>,
) -> Result<()> {
    if url.starts_with("http://") || url.starts_with("https://") {
        // libgit2 cannot read the static dumb-HTTP object tree; init locally
        // and fetch through the pure-Rust reader.
        let repo = init_sha256_authoring_repository(clone_dir)?;
        repo.remote("origin", url).context("adding origin remote")?;
        let refspecs = vec![
            "+refs/heads/*:refs/remotes/origin/*".to_string(),
            "+refs/tags/*:refs/tags/*".to_string(),
            // Capture the origin's default branch so a bare clone can check it
            // out, mirroring `RepoBuilder`/`git clone` on smart transports.
            "+HEAD:refs/remotes/origin/HEAD".to_string(),
        ];
        let dir = clone_dir.to_path_buf();
        let fetch_url = url.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(registry::repo::fetch(&dir, &fetch_url, &refspecs))
        })
        .context("fetching registry objects")?;

        // With no explicit ref, dumb-HTTP has no worktree checked out yet;
        // resolve and check out the origin's default branch.
        let default_branch;
        let effective_branch = if branch.is_none() && tag.is_none() && commit.is_none() {
            default_branch = default_remote_branch(&repo);
            default_branch.as_deref()
        } else {
            branch
        };
        return checkout_authoring_ref(&repo, effective_branch, tag, commit);
    }

    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(registry::repo::credentials);
    let mut fetch_options = git2::FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);
    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fetch_options);
    // RepoBuilder checks out the remote HEAD; only an explicit ref needs more.
    let repo = builder
        .clone(url, clone_dir)
        .with_context(|| format!("cloning {url}"))?;
    checkout_authoring_ref(&repo, branch, tag, commit)
}

/// Initializes the non-bare SHA-256 repository used by a producer clone.
fn init_sha256_authoring_repository(clone_dir: &Path) -> Result<git2::Repository> {
    let mut options = git2::RepositoryInitOptions::new();
    options.object_format(git2::ObjectFormat::Sha256);
    git2::Repository::init_opts(clone_dir, &options)
        .with_context(|| format!("initializing {}", clone_dir.display()))
}

/// Resolve the origin's default branch (the branch its `HEAD` points at) from
/// the fetched `refs/remotes/origin/*`, by matching the captured
/// `refs/remotes/origin/HEAD` object id. Returns `None` for an empty origin.
fn default_remote_branch(repo: &git2::Repository) -> Option<String> {
    let head_oid = repo.refname_to_id("refs/remotes/origin/HEAD").ok()?;
    let references = repo.references_glob("refs/remotes/origin/*").ok()?;
    for reference in references {
        let Ok(reference) = reference else { continue };
        let Ok(name) = reference.name() else { continue };
        if name.ends_with("/HEAD") {
            continue;
        }
        if reference.target() == Some(head_oid) {
            return name
                .strip_prefix("refs/remotes/origin/")
                .map(ToString::to_string);
        }
    }
    None
}

/// Check out the branch, tag, commit, or remote HEAD an authoring clone wants.
fn checkout_authoring_ref(
    repo: &git2::Repository,
    branch: Option<&str>,
    tag: Option<&str>,
    commit: Option<&str>,
) -> Result<()> {
    if let Some(branch) = branch {
        let remote_ref = format!("refs/remotes/origin/{branch}");
        let object = repo
            .revparse_single(&remote_ref)
            .with_context(|| format!("resolving origin/{branch}"))?;
        let target = object
            .peel_to_commit()
            .context("remote branch is not a commit")?;
        repo.branch(branch, &target, true)
            .with_context(|| format!("creating local branch '{branch}'"))?;
        repo.checkout_tree(&object, None)
            .with_context(|| format!("checking out '{branch}'"))?;
        repo.set_head(&format!("refs/heads/{branch}"))
            .with_context(|| format!("switching to '{branch}'"))?;
    } else if let Some(spec) = tag.or(commit) {
        let object = repo
            .revparse_single(spec)
            .with_context(|| format!("resolving '{spec}'"))?;
        let target = object.peel_to_commit().context("target is not a commit")?;
        repo.checkout_tree(&object, None)
            .with_context(|| format!("checking out '{spec}'"))?;
        repo.set_head_detached(target.id())
            .with_context(|| format!("detaching HEAD at '{spec}'"))?;
    }
    // No branch resolved (e.g. an empty origin): nothing to check out. For
    // smart transports `RepoBuilder` has already checked out the remote HEAD.
    Ok(())
}

/// Version-control summary of the git repository at or above `dir`: the short
/// `HEAD` commit, the branch name, and whether the working tree has
/// uncommitted tracked changes.
///
/// Reads through libgit2, so it works without the `git` CLI on `PATH`. Every
/// field degrades to `None`/`false` when it cannot be determined; this drives
/// the best-effort `aos describe` output.
pub fn local_git_info(dir: &Path) -> (Option<String>, Option<String>, bool) {
    let Ok(repo) = git2::Repository::discover(dir) else {
        return (None, None, false);
    };
    let head = repo.head().ok();
    let branch = head
        .as_ref()
        .and_then(|h| h.shorthand().ok())
        .map(ToString::to_string);
    let commit = head
        .as_ref()
        .and_then(|h| h.peel_to_commit().ok())
        .and_then(|c| {
            let short = c.as_object().short_id().ok()?;
            short.as_str().ok().map(ToString::to_string)
        });
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(false);
    let dirty = repo
        .statuses(Some(&mut opts))
        .map(|statuses| !statuses.is_empty())
        .unwrap_or(false);
    (commit, branch, dirty)
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

    // Remove the runtime pin from the writable trusted-keys store and mask any
    // colocated read-only seed anchor.
    let trusted_keys_removed =
        security::KeyStore::new(config.scope.trusted_keys_dirs()).remove(name)?;

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
    let (reg_config, _) = config
        .find_registry(name)
        .ok_or_else(|| AosError::RegistryError {
            message: format!("registry '{name}' not found"),
        })?;

    let toml_path = config.registry_overlay_path(name);
    let previous_enabled = reg_config.enabled;
    write_registry_enabled(&toml_path, enabled)?;

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

/// Persist a registry's `enabled` flag to the writable config layer.
///
/// When the writable-layer file already exists (an operator-added definition
/// or a prior overlay), its `enabled` field is updated in place, preserving
/// every other field. When it does not exist (a *seeded* registry), a minimal
/// `[registry]` overlay carrying only `enabled` is written, so the registry's
/// url/signing keep inheriting from the `/etc` seed rather than being shadowed
/// by a full copy.
///
/// # Errors
///
/// Returns an error when an existing file cannot be read or parsed, when the
/// parent directory cannot be created, or when the file cannot be written.
fn write_registry_enabled(path: &std::path::Path, enabled: bool) -> Result<()> {
    let mut root: toml::Value = if path.exists() {
        let content =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        toml::Value::Table(toml::map::Map::new())
    };

    let table = root
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: top level is not a TOML table", path.display()))?;
    let registry = table
        .entry("registry".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: [registry] is not a TOML table", path.display()))?;
    registry.insert("enabled".to_string(), toml::Value::Boolean(enabled));

    let rendered = toml::to_string_pretty(&root)?;
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

/// Return the writable-layer config file that `registry remove` should delete.
///
/// Removal only ever deletes from the writable layer
/// (`/var/lib/apm/config` for system scope). A registry that is (also) defined
/// by a read-only seed below it — typically `/etc/apm`, baked into the image —
/// cannot be removed this way: deleting the writable file would leave it
/// visible from the seed, and apm never writes `/etc`. Such a removal is
/// refused with guidance to blank the seed through signed host configuration.
fn registry_config_path_for_removal(config: &config::ApmConfig, name: &str) -> Result<PathBuf> {
    if registry_defined_by_seed(config, name) {
        return Err(AosError::RegistryError {
            message: format!(
                "registry '{name}' is defined by a read-only seed (e.g. /etc/apm) that apm \
                 cannot modify. To remove a seeded registry, blank its seed file \
                 (replace the contents of registries.d/{name}.toml) through signed host.nix."
            ),
        }
        .into());
    }

    Ok(config
        .scope
        .writable_config_dir()
        .join("registries.d")
        .join(format!("{name}.toml")))
}

/// Whether a layer strictly below the writable one defines registry `name`.
///
/// A "definition" is a non-blank `registries.d/{name}.toml` that contributes a
/// `url`. Seeds always carry a `url`; a writable-layer overlay that only
/// adjusts state or `enabled` does not. Used to refuse removing a seeded
/// registry (which apm cannot delete) — see [`registry_config_path_for_removal`].
fn registry_defined_by_seed(config: &config::ApmConfig, name: &str) -> bool {
    let layers = config.scope.config_layers();
    // The last entry is the writable layer; everything below it is a seed.
    let seed_layers = &layers[..layers.len().saturating_sub(1)];
    seed_layers.iter().any(|layer| {
        config::registry_file_has_url(&layer.join("registries.d").join(format!("{name}.toml")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApmConfig;
    use crate::types::{
        ApmSettings, AttestationMeta, PACKAGE_META_FORMAT, PackageMeta, PermissionsMeta,
        RegistryConfig,
    };
    use tempfile::TempDir;

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

    fn generation_verifier_evidence(
        root: &Path,
        label: &str,
        mut record: attestation::GenAttestation,
    ) -> (
        PathBuf,
        PreverifiedGenerationQuote,
        package_attestation::PackageEventLogVerification,
    ) {
        use sha2::{Digest as _, Sha256};

        let digest = attestation::record_hash(&record).expect("hash generation attestation");
        let mut pcr = Sha256::new();
        pcr.update([0_u8; 32]);
        pcr.update(digest);
        let pcr15 = hex::encode(pcr.finalize());
        let checker = PreverifiedGenerationQuote {
            pcrs: attestation::QuotedPcrs {
                pcr7: "11".repeat(32),
                pcr11: "22".repeat(32),
                pcr12: "00".repeat(32),
                pcr15,
            },
            bundle: package_attestation::PackageQuoteBundleBinding {
                ak_public: "aa".repeat(8),
                quote_message: "bb".repeat(8),
                quote_signature: "cc".repeat(8),
                quote_pcrs: "dd".repeat(8),
            },
        };
        record.quote = hex::encode(
            serde_json::to_vec(&embedded_generation_quote(&checker, &digest))
                .expect("serialize embedded quote"),
        );
        assert_eq!(
            attestation::record_hash(&record).expect("rehash quoted generation attestation"),
            digest,
            "the embedded quote must not change the measured record identity"
        );

        let record_path = root.join(format!("{label}.gen-attestation.json"));
        fs::write(
            &record_path,
            serde_json::to_vec(&record).expect("serialize generation attestation"),
        )
        .expect("write generation attestation");
        let measured_hash = format!("sha256:{}", hex::encode(digest));
        let cel = package_attestation::PackageEventLogVerification {
            pcr15: checker.pcrs.pcr15.clone(),
            pcr15_baseline: None,
            package_count: 0,
            current_packages: Vec::new(),
            generation_attestations: std::collections::BTreeMap::from([(
                record.activation_id.clone(),
                measured_hash,
            )]),
            generation_attestation_prefix_digests: std::collections::BTreeMap::from([(
                record.activation_id,
                Vec::new(),
            )]),
        };
        (record_path, checker, cel)
    }

    #[test]
    fn authoring_repository_uses_sha256_object_format() {
        let clone_dir = TempDir::new().unwrap();
        let repo = init_sha256_authoring_repository(clone_dir.path()).unwrap();

        assert!(!repo.is_bare());
        assert_eq!(repo.object_format(), git2::ObjectFormat::Sha256);
        assert_eq!(repo.path(), clone_dir.path().join(".git"));
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

    #[test]
    fn switch_manifest_selectors_resolve_current_generation_and_paths() {
        let profile = Path::new("/var/lib/profiles/system");
        assert_eq!(
            resolve_switch_manifest(None, profile).unwrap(),
            (
                PathBuf::from("/var/lib/profiles/system/current/manifest.json"),
                "current".to_string()
            )
        );
        assert_eq!(
            resolve_switch_manifest(Some("gen-17"), profile).unwrap(),
            (
                PathBuf::from("/var/lib/profiles/system/gen-17/manifest.json"),
                "gen-17".to_string()
            )
        );
        assert_eq!(
            resolve_switch_manifest(Some("/tmp/reference.json"), profile).unwrap(),
            (
                PathBuf::from("/tmp/reference.json"),
                "/tmp/reference.json".to_string()
            )
        );
        assert!(resolve_switch_manifest(Some("gen-../7"), profile).is_err());
    }

    #[test]
    fn running_module_abi_reads_aos_os_release_field() {
        let tmp = TempDir::new().unwrap();
        let release = tmp.path().join("os-release");
        std::fs::write(&release, "NAME=AOS\nAOS_MODULE_ABI=\"11\"\nVERSION_ID=1\n").unwrap();
        assert_eq!(running_module_abi(&release).unwrap(), 11);
        std::fs::write(&release, "NAME=AOS\n").unwrap();
        assert!(running_module_abi(&release).is_err());
    }

    #[test]
    fn switch_defaults_to_retained_image_authored_empty_module_only() {
        let tmp = TempDir::new().unwrap();
        let staged = tmp.path().join("run/aos-metadata/host.nix");
        let retained = tmp.path().join("store/host.nix");
        let manifest = tmp.path().join("manifest.json");
        std::fs::create_dir_all(retained.parent().unwrap()).unwrap();
        std::fs::write(&retained, "{}\n").unwrap();
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({
                "inputs": {
                    "host_nix": {
                        "trust_mode": "image",
                        "store_path": retained,
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            resolve_default_switch_host(&staged, &manifest).unwrap(),
            (retained.clone(), true)
        );

        let operator_manifest = serde_json::json!({
            "inputs": {
                "host_nix": {
                    "trust_mode": "platform",
                    "store_path": retained,
                }
            }
        });
        std::fs::write(&manifest, serde_json::to_vec(&operator_manifest).unwrap()).unwrap();
        assert!(resolve_default_switch_host(&staged, &manifest).is_err());

        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, "{}\n").unwrap();
        assert_eq!(
            resolve_default_switch_host(&staged, &manifest).unwrap(),
            (staged, false)
        );
    }

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
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        }
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
            closure_size: 0,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: Some(PACKAGE_META_FORMAT),
            requires_features: vec!["attestation-v1".into()],
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
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
    fn derive_name_from_https_url() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/core"),
            "core"
        );
    }

    #[test]
    fn generation_release_receipt_must_match_reverified_release() {
        let receipt = registry::ReleaseTrustReceipt {
            schema: "aos.registry-release-trust/v1".to_string(),
            registry: "aos-core".to_string(),
            release_tag: "1.4.0".to_string(),
            commit: "a".repeat(40),
            tag_signer_key: "deadbeef".to_string(),
        };
        assert!(
            ensure_release_receipt_matches(
                &receipt,
                "aos-core",
                "1.4.0",
                &"a".repeat(40),
                "deadbeef",
            )
            .is_ok()
        );

        let mut tampered = receipt.clone();
        tampered.commit = "b".repeat(40);
        assert!(
            ensure_release_receipt_matches(
                &tampered,
                "aos-core",
                "1.4.0",
                &"a".repeat(40),
                "deadbeef",
            )
            .is_err()
        );
    }

    #[test]
    fn generation_release_receipt_rejects_unrelated_signer_and_registry() {
        let receipt = registry::ReleaseTrustReceipt {
            schema: "aos.registry-release-trust/v1".to_string(),
            registry: "aos-extra".to_string(),
            release_tag: "1.4.0".to_string(),
            commit: "a".repeat(40),
            tag_signer_key: "feedface".to_string(),
        };
        assert!(
            ensure_release_receipt_matches(
                &receipt,
                "aos-core",
                "1.4.0",
                &"a".repeat(40),
                "deadbeef",
            )
            .is_err()
        );
    }

    #[test]
    fn generation_release_snapshot_reverifies_tag_catalog_and_store_graph() {
        let tmp = TempDir::new().expect("temporary release repository");
        let registry_cache = tmp.path().join("cache/aos-core");
        let repo = registry_cache.join("repo.git");
        fs::create_dir_all(&repo).expect("create repository");
        crate::testutil::git(&repo, &["init", "--object-format=sha256"]);

        let keypair = crate::sshkey::Ed25519Keypair::from_seed([71_u8; 32]);
        let private_key = tmp.path().join("release.key");
        fs::write(&private_key, keypair.to_openssh_private_key("release"))
            .expect("write release key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
                .expect("protect release key");
        }

        let store_hash = "00000000000000000000000000000000";
        let nar_digest = "0".repeat(52);
        let store_path = format!("/nix/store/{store_hash}-firewall-config");
        let package_dir = repo.join("packages/f");
        fs::create_dir_all(&package_dir).expect("create package directory");
        fs::write(
            package_dir.join("firewall.toml"),
            format!(
                r#"[package]
name = "firewall"
description = "fixture"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/11111111111111111111111111111111-firewall"
nar_hash = "sha256:{nar_digest}"
nar_size = 1
closure_size = 1
source_drv = "/nix/store/22222222222222222222222222222222-firewall.drv"
source_nar_hash = "sha256:{nar_digest}"
references = []
requires-features = ["config-module-v1", "attestation-v1"]
provenance = "provenance/firewall.jsonl"

[versions.platforms.x86_64-linux.config_module.config_output]
store_path = "{store_path}"
nar_hash = "sha256:{nar_digest}"
nar_size = 7
references = []

[versions.platforms.x86_64-linux.config_module.module_abi_compat]
min = 1
max = 1

[[versions.platforms.x86_64-linux.config_module.owns_roots]]
root = "firewall"
interface_abi = 1
contributable = ["allowedTCPPorts"]
"#
            ),
        )
        .expect("write signed package catalog");
        let store_dir = repo.join("store/00");
        fs::create_dir_all(&store_dir).expect("create store graph shard");
        fs::write(
            store_dir.join(store_hash),
            format!("nar:sha256:{nar_digest}:7\n"),
        )
        .expect("write signed store record");
        crate::testutil::git(&repo, &["add", "."]);
        crate::testutil::git(&repo, &["commit", "-m", "release fixture"]);
        crate::testutil::git(
            &repo,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", private_key.display()),
                "tag",
                "-s",
                "1.0.0",
                "-m",
                "release 1.0.0",
            ],
        );

        let commit = crate::testutil::git(&repo, &["rev-parse", "HEAD"]);
        let public_key = keypair.public_key_base64();
        let fingerprint = security::key_fingerprint(&public_key);
        let key = security::TrustedKey {
            registry: "aos-core".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key,
            fingerprint: fingerprint.clone(),
            source: security::KeySource::Tofu,
        };
        let receipt = registry::ReleaseTrustReceipt {
            schema: "aos.registry-release-trust/v1".to_string(),
            registry: "aos-core".to_string(),
            release_tag: "1.0.0".to_string(),
            commit,
            tag_signer_key: fingerprint.clone(),
        };
        let modules = attestation::ConfigModulesAttInput {
            closure_hash: format!("sha256:{}", "1".repeat(64)),
            count: 1,
            store_paths: vec![store_path.clone()],
            nar_hashes: vec![format!("sha256:{nar_digest}")],
            package_names: vec!["firewall".to_string()],
            registry: Some("aos-core".to_string()),
            release_tag: Some("1.0.0".to_string()),
            tag_signer_key: Some(fingerprint),
            realization: None,
            provenance: serde_json::Value::Null,
        };

        let (_, _, release) = verify_generation_release_snapshot(
            &repo,
            std::slice::from_ref(&key),
            vec![],
            &receipt,
            &modules,
        )
        .expect("verify signed release snapshot");
        let release = release.expect("non-empty release");
        assert_eq!(release.registry, "aos-core");
        assert_eq!(release.release_tag, "1.0.0");
        assert_eq!(release.config_modules[0].store_path, store_path);
        assert_eq!(
            release.config_modules[0].module_abi_compat,
            types::ModuleAbiCompat { min: 1, max: 1 }
        );
        assert_eq!(
            release.config_modules[0].authorization.owns,
            vec!["firewall".to_string()]
        );

        assert!(
            verify_generation_release_snapshot(
                &repo,
                std::slice::from_ref(&key),
                vec![key.fingerprint.clone()],
                &receipt,
                &modules,
            )
            .is_err(),
            "an explicitly revoked signer must fail even if its key remains available"
        );

        let trusted_keys = tmp.path().join("trusted-keys.d");
        fs::create_dir_all(&trusted_keys).expect("create trusted key directory");
        let trusted_key_file = trusted_keys.join("aos-core.pub");
        fs::write(&trusted_key_file, format!("{}\n", key.key_line()))
            .expect("write active release key");
        fs::write(
            registry_cache.join(registry::RELEASE_TRUST_RECEIPT),
            serde_json::to_vec(&receipt).expect("serialize release trust receipt"),
        )
        .expect("write release trust receipt");

        let mut verified_modules = modules.clone();
        verified_modules.closure_hash = graph_compile::reproject::hash_cjson(&serde_json::json!([
            [&store_path, &verified_modules.nar_hashes[0]]
        ]));
        verified_modules.realization = Some(release.realization.clone());
        verified_modules.provenance = serde_json::json!({
            "module_abi_compat": [{"min": 1, "max": 1}],
            "authorizations": [{"owns": ["firewall"], "contributes": {}}]
        });
        let base_record = attestation::GenAttestation {
            schema: attestation::GEN_ATTESTATION_SCHEMA.to_string(),
            activation_id: format!("sha256:{}", "a1".repeat(32)),
            generation_id: format!("sha256:{}", "b2".repeat(32)),
            manifest_hash: format!("sha256:{}", "c3".repeat(32)),
            inputs: attestation::AttestationInputs {
                base_lib: attestation::BaseLibAttInput {
                    store_path: "/nix/store/33333333333333333333333333333333-aos-base-lib"
                        .to_string(),
                    pcr11_expected: Some(format!("sha256:{}", "22".repeat(32))),
                    abi_hash: format!("sha256:{}", "44".repeat(32)),
                    module_abi: 1,
                    root_verity_roothash: Some("55".repeat(32)),
                    root_verity_uuid: None,
                },
                evaluator: attestation::EvaluatorAttInput {
                    store_path: "/nix/store/44444444444444444444444444444444-aos-eval".to_string(),
                    store_hash: "44444444444444444444444444444444".to_string(),
                },
                config_modules: verified_modules,
                host_nix: attestation::HostNixAttInput {
                    content_hash: format!("sha256:{}", "66".repeat(32)),
                    store_path: "/nix/store/55555555555555555555555555555555-host-nix".to_string(),
                    trust_mode: "platform".to_string(),
                    platform: Some("aws".to_string()),
                    signer_key: None,
                },
                instance_facts: attestation::InstanceFactsAttInput {
                    facts_hash: format!("sha256:{}", "77".repeat(32)),
                    store_path: "/nix/store/66666666666666666666666666666666-host-facts"
                        .to_string(),
                    platform: "aws".to_string(),
                },
            },
            eval_mode: attestation::EVAL_MODE_PURE.to_string(),
            quote_status: attestation::QUOTE_STATUS_QUOTED.to_string(),
            quote: String::new(),
        };
        let policy_path = tmp.path().join("generation-policy.json");
        fs::write(
            &policy_path,
            serde_json::to_vec(&serde_json::json!({
                "schema": GENERATION_VERIFIER_POLICY_SCHEMA,
                "expected_pcr7": "11".repeat(32),
                "expected_pcr11": format!("sha256:{}", "22".repeat(32)),
                "expected_pcr12": "00".repeat(32),
                "expected_root_roothash": "55".repeat(32),
                "trusted_platforms": ["aws"]
            }))
            .expect("serialize generation policy"),
        )
        .expect("write generation policy");
        let quote_trust = AttestationQuoteTrust::IdentityPinned {
            anchor: "test-enrolled-ak".to_string(),
            ak_ek_trusted: true,
        };
        let (record_path, checker, cel) =
            generation_verifier_evidence(tmp.path(), "valid", base_record.clone());
        let summary = verify_generation_attestation_cli_with(
            &record_path,
            &policy_path,
            None,
            &checker,
            &quote_trust,
            &cel,
            |attested_modules| {
                verified_generation_release_from_paths(
                    &tmp.path().join("cache"),
                    vec![trusted_keys.clone()],
                    attested_modules,
                )
            },
        )
        .expect("verify generation through the public-command core");
        assert_eq!(summary.registry.as_deref(), Some("aos-core"));
        assert_eq!(summary.release_tag.as_deref(), Some("1.0.0"));
        assert_eq!(
            summary.tag_signer_key.as_deref(),
            Some(key.fingerprint.as_str())
        );
        assert_eq!(
            summary.realization.as_deref(),
            Some(release.realization.as_str())
        );

        fs::write(
            &trusted_key_file,
            format!("{}\n# revoked: {}\n", key.key_line(), key.key_line()),
        )
        .expect("revoke release key");
        assert!(
            verify_generation_attestation_cli_with(
                &record_path,
                &policy_path,
                None,
                &checker,
                &quote_trust,
                &cel,
                |attested_modules| {
                    verified_generation_release_from_paths(
                        &tmp.path().join("cache"),
                        vec![trusted_keys.clone()],
                        attested_modules,
                    )
                },
            )
            .is_err(),
            "the generation verifier must reject a signer revoked in the actual key store"
        );
        fs::write(&trusted_key_file, format!("{}\n", key.key_line()))
            .expect("restore active release key");

        let mut mismatched_receipt = receipt.clone();
        mismatched_receipt.commit = "f".repeat(receipt.commit.len());
        fs::write(
            registry_cache.join(registry::RELEASE_TRUST_RECEIPT),
            serde_json::to_vec(&mismatched_receipt).expect("serialize mismatched receipt"),
        )
        .expect("write mismatched receipt");
        assert!(
            verify_generation_attestation_cli_with(
                &record_path,
                &policy_path,
                None,
                &checker,
                &quote_trust,
                &cel,
                |attested_modules| {
                    verified_generation_release_from_paths(
                        &tmp.path().join("cache"),
                        vec![trusted_keys.clone()],
                        attested_modules,
                    )
                },
            )
            .is_err(),
            "the generation verifier must reject a receipt for another commit"
        );
        fs::write(
            registry_cache.join(registry::RELEASE_TRUST_RECEIPT),
            serde_json::to_vec(&receipt).expect("serialize restored receipt"),
        )
        .expect("restore release trust receipt");

        let mut wrong_realization = base_record.clone();
        wrong_realization.activation_id = format!("sha256:{}", "a2".repeat(32));
        wrong_realization.inputs.config_modules.realization =
            Some(format!("sha256:{}", "88".repeat(32)));
        let (wrong_realization_path, wrong_realization_checker, wrong_realization_cel) =
            generation_verifier_evidence(tmp.path(), "wrong-realization", wrong_realization);
        assert!(
            verify_generation_attestation_cli_with(
                &wrong_realization_path,
                &policy_path,
                None,
                &wrong_realization_checker,
                &quote_trust,
                &wrong_realization_cel,
                |attested_modules| {
                    verified_generation_release_from_paths(
                        &tmp.path().join("cache"),
                        vec![trusted_keys.clone()],
                        attested_modules,
                    )
                },
            )
            .is_err(),
            "the generation verifier must reject a different signed-store realization"
        );

        let mut wrong_catalog = base_record;
        wrong_catalog.activation_id = format!("sha256:{}", "a3".repeat(32));
        wrong_catalog.inputs.config_modules.nar_hashes[0] = format!("sha256:{}", "1".repeat(52));
        wrong_catalog.inputs.config_modules.closure_hash =
            graph_compile::reproject::hash_cjson(&serde_json::json!([[
                &store_path,
                &wrong_catalog.inputs.config_modules.nar_hashes[0]
            ]]));
        let (wrong_catalog_path, wrong_catalog_checker, wrong_catalog_cel) =
            generation_verifier_evidence(tmp.path(), "wrong-catalog", wrong_catalog);
        assert!(
            verify_generation_attestation_cli_with(
                &wrong_catalog_path,
                &policy_path,
                None,
                &wrong_catalog_checker,
                &quote_trust,
                &wrong_catalog_cel,
                |attested_modules| {
                    verified_generation_release_from_paths(
                        &tmp.path().join("cache"),
                        vec![trusted_keys.clone()],
                        attested_modules,
                    )
                },
            )
            .is_err(),
            "the generation verifier must reject module evidence absent from the signed catalog"
        );

        let mut unrelated = modules;
        unrelated.nar_hashes[0] = format!("sha256:{}", "1".repeat(52));
        assert!(
            verify_generation_release_snapshot(
                &repo,
                std::slice::from_ref(&key),
                vec![],
                &receipt,
                &unrelated,
            )
            .is_err()
        );
    }

    #[test]
    fn generation_release_selection_filters_image_origins() {
        let mut modules = attestation::ConfigModulesAttInput {
            registry: Some("aos-core".to_string()),
            release_tag: Some("1.0.0".to_string()),
            tag_signer_key: Some("1234abcd".to_string()),
            realization: Some(format!("sha256:{}", "11".repeat(32))),
            closure_hash: format!("sha256:{}", "22".repeat(32)),
            count: 2,
            store_paths: vec![
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-image-module".to_string(),
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-registry-module".to_string(),
            ],
            nar_hashes: vec![
                format!("sha256:{}", "33".repeat(32)),
                format!("sha256:{}", "44".repeat(32)),
            ],
            package_names: vec!["image-package".to_string(), "registry-package".to_string()],
            provenance: serde_json::json!({
                "module_abi_compat": [
                    {"min": 1, "max": 1},
                    {"min": 1, "max": 1}
                ],
                "authorizations": [
                    {"owns": [], "contributes": {}},
                    {"owns": [], "contributes": {}}
                ],
                "origins": ["image", "registry"]
            }),
        };

        let subset = registry_config_module_subset(&modules)
            .expect("select registry subset")
            .expect("mixed evidence has a registry subset");
        assert_eq!(subset.count, 1);
        assert_eq!(subset.package_names, ["registry-package"]);
        assert_eq!(subset.store_paths, [modules.store_paths[1].clone()]);
        assert_eq!(subset.nar_hashes, [modules.nar_hashes[1].clone()]);

        modules.registry = None;
        modules.release_tag = None;
        modules.tag_signer_key = None;
        modules.realization = None;
        modules.provenance["origins"] = serde_json::json!(["image", "image"]);
        assert!(
            registry_config_module_subset(&modules)
                .expect("accept image-only origins")
                .is_none()
        );

        modules.provenance["origins"] = serde_json::json!(["image"]);
        assert!(registry_config_module_subset(&modules).is_err());
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
                    generation_attestation: None,
                    generation_policy_file: None,
                    rederived_manifest: None,
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
    fn package_attestation_catalog_sources_merge_registry_seed_and_files() {
        let tmp = TempDir::new().expect("tempdir");
        let seed = tmp.path().join("seed-catalog.json");
        let explicit = tmp.path().join("explicit-catalog.json");
        let root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let web_measurement =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let seed_measurement =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let explicit_measurement =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        write_catalog_file(&seed, "seeded", "1.0", root_digest, seed_measurement);
        write_catalog_file(&explicit, "extra", "2.0", root_digest, explicit_measurement);
        let registry = attested_package_meta("web", "1.0", root_digest, web_measurement);

        let catalog =
            package_attestation_catalog_from_sources(&[registry], Some(&seed), &[explicit])
                .expect("merged catalog");

        let names = catalog
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["extra", "seeded", "web"]);
        assert_eq!(catalog[0].measurement, explicit_measurement);
        assert_eq!(catalog[1].measurement, seed_measurement);
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
            package_attestation_catalog_from_sources(&[registry], None, &[explicit]).unwrap_err();

        assert!(format!("{err:#}").contains("conflicting golden measurements"));
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
        assert_eq!(parsed.registry.name.as_deref(), Some("quoted-url"));
        assert_eq!(
            parsed.registry.url.as_deref(),
            Some("file:///tmp/registry with \"quotes\"\nand newline")
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
    fn registry_config_path_for_removal_targets_writable_layer() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);
        // A registry that no read-only seed defines resolves to the writable
        // layer, never the `/etc` seed. (The unique name is absent from any
        // real seed dir, so the seed check is deterministically false.)
        let path = registry_config_path_for_removal(&config, "operator-added-xyz").unwrap();
        assert!(path.starts_with(config.scope.writable_config_dir()));
        assert!(path.ends_with("registries.d/operator-added-xyz.toml"));
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
