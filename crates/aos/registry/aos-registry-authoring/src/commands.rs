//! Registry authoring command arguments and dispatch vocabulary.

use clap::{Args, Subcommand, ValueEnum};
use aos_registry_format::consumer::*;
use std::path::PathBuf;

/// Registry workspace and authoring commands exposed by `apr`.
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
        /// Add another active key to the initial keys.toml (repeatable; requires --trust-key)
        #[arg(long = "roster-key", value_name = "ID=TRUST_LINE")]
        roster_key: Vec<String>,
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
        /// Trusted registry signing key in `<registry>:Ed25519:<base64>` form; repeat to pin multiple rotation anchors
        #[arg(long = "trust-key", conflicts_with = "no_verify")]
        trust_key: Vec<String>,
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
        /// Package name for a manually described sysroot
        #[arg(long)]
        name: Option<String>,
        /// Package version for a manually described sysroot
        #[arg(long)]
        version: Option<String>,
        /// Platform override
        #[arg(long)]
        platform: Option<String>,
        /// Package description for a manually described sysroot
        #[arg(long)]
        description: Option<String>,
        /// Package homepage for a manually described sysroot
        #[arg(long)]
        homepage: Option<String>,
        /// Package license for a manually described sysroot
        #[arg(long)]
        license: Option<String>,
        /// Package maintainer for a manually described sysroot
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
        /// Image payload bundle used to verify layout and recovery facts
        #[arg(long = "image-payload")]
        image_payloads: Vec<String>,
        /// Regular-file disk store output for each image payload
        #[arg(long = "image-disk")]
        image_disks: Vec<String>,
        /// Regular-file image-info store output for each image payload
        #[arg(long = "image-info")]
        image_infos: Vec<String>,
        /// Image format for each image artifact group
        #[arg(long = "image-format")]
        image_formats: Vec<String>,
        /// Provider-owned contract schema for each image artifact group
        #[arg(long = "image-contract-schema")]
        image_contract_schemas: Vec<String>,
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
    /// Inspect or discard isolated unpublished release candidates
    Stage {
        #[command(subcommand)]
        command: RegistryStageCommand,
    },
    /// Run the ordered producer release pipeline
    #[command(group(clap::ArgGroup::new("stage_identity").args(["stage", "from_stage"]).multiple(false)))]
    Release {
        /// Semver release tag, with no `v` prefix
        semver: String,
        /// Create or update an unpublished candidate with this identity
        #[arg(long, conflicts_with = "from_stage")]
        stage: Option<String>,
        /// Expected candidate revision for an update, resume, or finalization
        #[arg(long, requires = "stage_identity")]
        stage_revision: Option<u64>,
        /// Finalize this exact unpublished candidate
        #[arg(long, conflicts_with = "stage", requires = "stage_revision")]
        from_stage: Option<String>,
        /// Canonical signed container release sidecar to commit in the release
        #[arg(long = "container-release")]
        container_release: Option<PathBuf>,
        /// OCI image layout whose exact graph belongs to the container candidate
        #[arg(long = "container-layout", requires = "container_release")]
        container_layout: Option<PathBuf>,
        /// Distribution repository for the signed container image
        #[arg(long = "container-repository", requires = "container_layout")]
        container_repository: Option<String>,
        /// Canonical Nix signature input bound by the container release
        #[arg(long = "container-signature-input")]
        container_signature_input: Option<PathBuf>,
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
        /// Image payload bundle used to verify layout and recovery facts
        #[arg(long = "image-payload")]
        image_payloads: Vec<String>,
        /// Regular-file disk store output for each image payload
        #[arg(long = "image-disk")]
        image_disks: Vec<String>,
        /// Regular-file image-info store output for each image payload
        #[arg(long = "image-info")]
        image_infos: Vec<String>,
        /// Image format for each image artifact group
        #[arg(long = "image-format")]
        image_formats: Vec<String>,
        /// Provider-owned contract schema for each image artifact group
        #[arg(long = "image-contract-schema")]
        image_contract_schemas: Vec<String>,
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

#[derive(Subcommand)]
pub enum RegistryStageCommand {
    /// List retained unpublished release candidates
    List {
        /// Registry to inspect
        #[arg(long)]
        registry: Option<String>,
    },
    /// Inspect one candidate's exact inventory and revision
    Show {
        /// Candidate identity
        id: String,
        /// Registry to inspect
        #[arg(long)]
        registry: Option<String>,
    },
    /// Discard a candidate after checking its current revision
    Discard {
        /// Candidate identity
        id: String,
        /// Exact expected candidate revision
        #[arg(long = "stage-revision")]
        revision: u64,
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
        /// OpenSSH private key used to sign a cache-pointer commit
        #[arg(long = "registry-key", conflicts_with = "registry_key_id")]
        registry_key: Option<String>,
        /// Active roster key id used to sign a cache-pointer commit
        #[arg(long = "registry-key-id", conflicts_with = "registry_key")]
        registry_key_id: Option<String>,
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
        /// `trunk build --release` in crates/aos/registry/aos-registry-web); when given,
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
    /// Prepare bounded index bundles in an already materialized static surface
    PrepareIndexBundles {
        /// Static registry surface directory containing the root objects store
        #[arg(long)]
        surface_dir: PathBuf,
    },
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
    /// Convert these CLI flags into backend [`aos_nix_cache::AuthOptions`],
    /// without any configuration-file defaults.
    ///
    /// Equivalent to [`Self::auth_options_with_config`] with `None`.
    pub fn auth_options(&self) -> aos_nix_cache::AuthOptions {
        self.auth_options_with_config(None)
    }

    /// Convert these CLI flags into backend [`aos_nix_cache::AuthOptions`],
    /// layered over optional `[registry.upload_auth]` config defaults.
    ///
    /// Config values (when present) seed the result; any flag the user set on
    /// the command line (or via its env binding) overrides the corresponding
    /// config value. `ssh_ask_pass` is OR-ed, and the cache view falls back to
    /// `"default"` when neither source sets it.
    pub fn auth_options_with_config(
        &self,
        config: Option<&RegistryUploadAuthConfig>,
    ) -> aos_nix_cache::AuthOptions {
        let mut auth = config
            .map(upload_auth_options)
            .unwrap_or_else(|| aos_nix_cache::AuthOptions {
                view: "default".to_string(),
                ..aos_nix_cache::AuthOptions::default()
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



    /// Convert these config defaults into backend [`aos_nix_cache::AuthOptions`],
    /// substituting the `"default"` view when none is configured.
    fn upload_auth_options(config: &RegistryUploadAuthConfig) -> aos_nix_cache::AuthOptions {
        aos_nix_cache::AuthOptions {
            token: config.token.clone(),
            view: config.view.clone().unwrap_or_else(|| "default".to_string()),
            http_user: config.http_user.clone(),
            http_password: config.http_password.clone(),
            headers: config.headers.clone(),
            s3_region: config.s3_region.clone(),
            s3_profile: config.s3_profile.clone(),
            s3_endpoint: config.s3_endpoint.clone(),
            ssh_key: config.ssh_key.clone(),
            ssh_password: config.ssh_password.clone(),
            ssh_ask_pass: config.ssh_ask_pass,
        }
    }
