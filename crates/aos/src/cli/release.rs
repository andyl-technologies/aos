//! Command-line contract for canonical AOS release operations.
//!
//! The porcelain operates one release from the maintainer configuration and
//! a work directory:
//!
//! ```text
//! aos maintain release new --registry R --version V --images PATH [--release-id ID] [--override DIR] [--work DIR] [--config PATH]
//! aos maintain release advance --to <destination> [--stop-after-upload] [--stage-revision N] [--ring N] [--override DIR] [--accept-transaction] [--work DIR] [--config PATH]
//! aos maintain release publish --to <destination> [--stage-revision N] [--work DIR] [--config PATH]
//! aos maintain release status [--work DIR] [--config PATH]
//! aos maintain release explain --to <destination> [--work DIR] [--config PATH]
//! aos maintain release review [--reject --reason TEXT] [--work DIR] [--config PATH]
//! aos maintain release fitness run <kind> [--report PATH] [--config PATH]
//! aos maintain release fitness status [--config PATH]
//! ```
//!
//! `aos maintain release step <command>` exposes each leaf operation with explicit
//! inputs: planning, build and signing, publication to one destination
//! (`<surface>/<channel>`, such as `production/stable`), per-destination
//! qualification, ring-by-ring channel rollout, and inspection. Every
//! effectful step verifies what it consumes and writes new outputs without
//! replacing existing paths.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ReleaseCommand {
    /// Derive a release's plan request from the maintainer configuration and freeze the plan
    New(ReleaseNewArgs),
    /// Run every automated step toward a destination until it completes or needs a person
    Advance(ReleaseAdvanceArgs),
    /// Publish a fully uploaded destination after explicit review
    Publish(ReleaseDestinationArgs),
    /// Show the release state, each destination's state, and the next step
    Status(ReleaseWorkArgs),
    /// List a destination's obligations and whether each is met
    Explain(ReleaseExplainArgs),
    /// Sign the pending qualification review or completion approval
    Review(ReleaseReviewArgs),
    /// Record and inspect environment fitness attestations
    Fitness {
        #[command(subcommand)]
        command: ReleaseFitnessCommand,
    },
    /// Run one explicit release operation
    Step {
        #[command(subcommand)]
        command: ReleaseStepCommand,
    },
}

#[derive(Args)]
pub struct ReleaseNewArgs {
    /// Registry to release; must equal the configuration's registry
    #[arg(long)]
    pub registry: String,

    /// Calendar release version, such as 2026.9.0-dev.20260929.1
    #[arg(long)]
    pub version: String,

    /// Release identity [default: release-<version>]
    #[arg(long)]
    pub release_id: Option<String>,

    /// Reviewed Linux image decisions (JSON array of image plans)
    #[arg(long)]
    pub images: PathBuf,

    /// Directory of signed profile-override envelopes to plan with
    #[arg(long = "override", value_name = "DIR")]
    pub override_dir: Option<PathBuf>,

    /// Plan a registry's first release from its root commit; staging must hold no publication
    #[arg(long, requires = "source_registry")]
    pub first_release: bool,

    /// Clean single-commit authoring clone whose root commit is the first release's base
    #[arg(long, value_name = "DIR", requires = "first_release")]
    pub source_registry: Option<PathBuf>,

    /// Derive and write request.json, then stop before planning
    #[arg(long)]
    pub request_only: bool,

    /// Work directory [default: <work_root>/<release-id>]
    #[arg(long)]
    pub work: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseAdvanceArgs {
    /// Destination to advance, such as staging/edge or production/stable
    #[arg(long)]
    pub to: String,

    /// Stop after this one-based rollout ring
    #[arg(long)]
    pub ring: Option<u16>,

    /// Re-freeze the unbuilt plan with the signed override envelopes in DIR
    #[arg(long = "override", value_name = "DIR")]
    pub override_dir: Option<PathBuf>,

    /// Stop after uploading immutable artifacts, before release visibility changes
    #[arg(long)]
    pub stop_after_upload: bool,

    /// Expected current candidate revision when updating an immutable upload
    #[arg(long, requires = "stop_after_upload")]
    pub stage_revision: Option<u64>,

    /// Accept the reviewed isolated registry transaction and continue
    #[arg(long)]
    pub accept_transaction: bool,

    /// Work directory [default: newest release under work_root]
    #[arg(long)]
    pub work: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseDestinationArgs {
    /// Exact candidate revision selected for publication
    #[arg(long)]
    pub stage_revision: Option<u64>,

    /// Destination to publish, such as staging/edge or production/stable
    #[arg(long)]
    pub to: String,

    /// Work directory [default: newest release under work_root]
    #[arg(long)]
    pub work: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseWorkArgs {
    /// Work directory [default: newest release under work_root]
    #[arg(long)]
    pub work: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseExplainArgs {
    /// Destination to explain, such as production/stable
    #[arg(long)]
    pub to: String,

    /// Work directory [default: newest release under work_root]
    #[arg(long)]
    pub work: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseReviewArgs {
    /// Sign a rejection instead of an approval
    #[arg(long, requires = "reason")]
    pub reject: bool,

    /// Reason recorded beside a rejection
    #[arg(long, requires = "reject")]
    pub reason: Option<String>,

    /// Work directory [default: newest release under work_root]
    #[arg(long)]
    pub work: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum ReleaseFitnessCommand {
    /// Sign and record an attestation from one exercise report
    Run(ReleaseFitnessRunArgs),
    /// Show each fitness kind's newest attestation, age, and bindings
    Status(ReleaseFitnessStatusArgs),
}

#[derive(Args)]
pub struct ReleaseFitnessRunArgs {
    /// Fitness kind, such as storage-restore or hub-restore
    pub kind: String,

    /// Exercise report (aos.release.fitness-report/v1) [default: standard input]
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseFitnessStatusArgs {
    /// Maintainer configuration [default: $AOS_RELEASE_CONFIG or the standard search]
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum ReleaseStepCommand {
    /// Inspect cases or execute an exact qualification request
    Qualification {
        #[command(subcommand)]
        command: ReleaseQualificationCommand,
    },
    /// Print the destination table, or one destination's profile and gates
    Contract(ReleaseContractArgs),
    /// Derive and freeze a release plan from Git and the Nix inventory
    Plan(ReleasePlanArgs),
    /// Realize and repeat-check every planned Nix output
    Build(ReleaseBuildArgs),
    /// Assemble finalized release inputs into a closed unsigned payload
    Assemble(ReleaseAssembleArgs),
    /// Reconcile and display an append-only release journal
    Status(ReleaseStatusArgs),
    /// Exercise and audit a configured external signing provider
    Signer {
        #[command(subcommand)]
        command: ReleaseSignerCommand,
    },
    /// Finalize one Linux image assembly through external signers
    FinalizeImage(ReleaseFinalizeImageArgs),
    /// Author one isolated registry tree and emit its review transaction
    PrepareRegistry(ReleasePrepareRegistryArgs),
    /// Commit and sign one reviewed isolated canonical registry release
    FinalizeRegistry(ReleaseFinalizeRegistryArgs),
    /// Close and threshold-sign one release bundle
    Finalize(ReleaseFinalizeArgs),
    /// Generate and externally sign the complete static Nix cache
    FinalizeCache(ReleaseFinalizeCacheArgs),
    /// Renew or publish short-lived TUF timestamp metadata
    Timestamp {
        #[command(subcommand)]
        command: ReleaseTimestampCommand,
    },
    /// Construct immutable role-separated TUF repository metadata
    Tuf(ReleaseTufArgs),
    /// Compose registry, release target, and TUF bytes for one destination
    ComposeSurface(ReleaseComposeSurfaceArgs),
    /// Publish the finalized bundle to one destination's surface
    Publish(ReleasePublishArgs),
    /// Execute and sign one destination's qualification phase
    QualifyRun(ReleaseQualifyRunArgs),
    /// Compose the public release record from signed staging qualification
    Record(ReleaseRecordArgs),
    /// Install one approved first registry base on an empty surface
    Bootstrap(ReleaseBootstrapArgs),
    /// Advance a rollout ring or complete a destination's rollout
    Channel {
        #[command(subcommand)]
        command: ReleaseChannelCommand,
    },
    /// Verify a captured release bundle using only public trust inputs
    Verify(ReleaseVerifyArgs),
}

#[derive(Subcommand)]
pub enum ReleaseQualificationCommand {
    /// Expand the applicable cases in an exported plan and manifest
    Cases(ReleaseQualificationCasesArgs),
    /// Download exact public objects and run a configured scenario
    Execute(ReleaseQualificationExecuteArgs),
    /// Bind one scenario report to its exact executor request
    Respond(ReleaseQualificationRespondArgs),
}

#[derive(Args)]
pub struct ReleaseQualificationCasesArgs {
    /// Destination whose profile selects the cases; omit for every destination
    #[arg(long)]
    pub to: Option<String>,

    /// Canonical frozen release plan
    #[arg(long)]
    pub plan: PathBuf,
    /// Canonical manifest payload or signed manifest envelope
    #[arg(long)]
    pub manifest: PathBuf,
    /// Select the release hold point
    #[arg(long, value_parser = ["build", "staging", "rollout", "complete"])]
    pub phase: String,
}

#[derive(Args)]
pub struct ReleaseQualificationExecuteArgs {
    /// Immutable scenario registry produced by the Nix qualification builder
    #[arg(long)]
    pub scenarios: PathBuf,
    /// Public executor identity expected by the coordinator
    #[arg(long)]
    pub identity: String,
    /// Parent directory for retained requests, objects, observations, and diagnostics
    #[arg(long)]
    pub work_root: PathBuf,
    /// Maximum duration of a scenario in seconds
    #[arg(long, default_value_t = 1800)]
    pub timeout_seconds: u64,
}

#[derive(Args)]
pub struct ReleaseQualificationRespondArgs {
    /// Canonical executor request retained by the native runner
    #[arg(long)]
    pub request: PathBuf,
    /// Canonical scenario registry retained by the native runner
    #[arg(long)]
    pub scenarios: PathBuf,
    /// Canonical report produced by the scenario exercise
    #[arg(
        long,
        conflicts_with = "report_root",
        required_unless_present = "report_root"
    )]
    pub report: Option<PathBuf>,
    /// Directory of case-digest-named canonical scenario reports
    #[arg(long, conflicts_with = "report")]
    pub report_root: Option<PathBuf>,
    /// Public executor identity expected by the coordinator
    #[arg(long)]
    pub identity: String,
}

#[derive(Args)]
pub struct ReleaseContractArgs {
    /// Registry whose destination table is displayed
    #[arg(long, default_value = "andyl/main")]
    pub registry: String,

    /// Show one destination's profile and gates, such as production/stable
    #[arg(long)]
    pub to: Option<String>,

    /// Read an exported contract offline instead of evaluating Nix
    #[arg(long)]
    pub input: Option<PathBuf>,

    /// Write canonical contract bytes to a new file
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseBootstrapArgs {
    /// Canonical release plan whose registry base is being installed
    #[arg(long)]
    pub plan: PathBuf,

    /// Complete static registry surface at the exact planned base commit
    #[arg(long)]
    pub registry_surface: PathBuf,

    /// Surface receiving the base
    #[arg(long, value_parser = ["staging", "production"])]
    pub environment: String,

    /// Identical signed bootstrap intent; repeat to satisfy its threshold
    #[arg(long = "signed-intent", required = true)]
    pub signed_intents: Vec<PathBuf>,

    /// Release-evidence key as KEY_ID=PATH; repeat for the planned threshold
    #[arg(long = "approval-key", value_name = "KEY_ID=PATH", required = true)]
    pub approval_keys: Vec<String>,

    /// Short-lived access token for a Hub surface
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// Maintainer configuration with static-surface credentials
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// New bootstrap evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Subcommand)]
pub enum ReleaseTimestampCommand {
    /// Sign a fresh pointer to one already-authorized snapshot
    Refresh(ReleaseTimestampRefreshArgs),
    /// Publish and publicly verify one exact signed timestamp pointer
    Publish(ReleaseTimestampPublishArgs),
}

#[derive(Args)]
pub struct ReleaseTimestampPublishArgs {
    /// Destination whose surface receives the timestamp
    #[arg(long)]
    pub to: String,

    /// Canonical release plan governing the timestamp publication
    #[arg(long)]
    pub plan: PathBuf,

    /// Current signed TUF root envelope
    #[arg(long)]
    pub root: PathBuf,

    /// Current signed immutable snapshot envelope
    #[arg(long)]
    pub snapshot: PathBuf,

    /// Fresh signed timestamp envelope
    #[arg(long)]
    pub timestamp: PathBuf,

    /// Previous timestamp version, or zero for the first publication
    #[arg(long, default_value_t = 0)]
    pub previous_version: u64,

    /// Independently trusted root key as KEY_ID=PATH
    #[arg(long = "trusted-root-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_root_keys: Vec<String>,

    /// Required independently trusted root signature count
    #[arg(long, default_value_t = 2)]
    pub trusted_root_threshold: u16,

    /// Complete registry surface containing the timestamp and snapshot paths
    #[arg(long)]
    pub registry_surface: PathBuf,

    /// Short-lived access token for a Hub surface
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// Maintainer configuration with static-surface credentials
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// New timestamp publication evidence directory
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseTimestampRefreshArgs {
    /// Destination whose surface will serve the timestamp
    #[arg(long)]
    pub to: String,

    /// Canonical release plan governing the timestamp signer
    #[arg(long)]
    pub plan: PathBuf,

    /// Current signed TUF root envelope
    #[arg(long)]
    pub root: PathBuf,

    /// Current signed immutable snapshot envelope
    #[arg(long)]
    pub snapshot: PathBuf,

    /// Timestamp the surface serves now, over this or an older snapshot
    #[arg(long)]
    pub previous_timestamp: Option<PathBuf>,

    /// Independently trusted root key as KEY_ID=PATH
    #[arg(long = "trusted-root-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_root_keys: Vec<String>,

    /// Required independently trusted root signature count
    #[arg(long, default_value_t = 2)]
    pub trusted_root_threshold: u16,

    /// Timestamp signing key as KEY_ID=PATH; repeat to satisfy its threshold
    #[arg(long = "signing-key", value_name = "KEY_ID=PATH", required = true)]
    pub signing_keys: Vec<String>,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Maximum duration of each external signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub signer_timeout_seconds: u64,

    /// Strictly increasing timestamp metadata version
    #[arg(long)]
    pub version: u64,

    /// RFC 3339 UTC issuance time
    #[arg(long)]
    pub issued_at: String,

    /// RFC 3339 UTC expiry no more than 48 hours after issuance
    #[arg(long)]
    pub expires: String,

    /// New canonical signed timestamp path
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseTufArgs {
    /// Public release record to authorize beside the manifest
    #[arg(long)]
    pub release_record: Option<PathBuf>,

    /// Canonical release plan governing all metadata roles
    #[arg(long)]
    pub plan: PathBuf,

    /// Finalized release bundle whose signed manifest is authorized
    #[arg(long)]
    pub bundle: PathBuf,

    /// Manifest verification key as KEY_ID=PATH; repeat to threshold
    #[arg(long = "manifest-key", value_name = "KEY_ID=PATH", required = true)]
    pub manifest_keys: Vec<String>,

    /// Current signed TUF root envelope
    #[arg(long)]
    pub root: PathBuf,

    /// Previous signed root when the current root is a rotation
    #[arg(long)]
    pub previous_root: Option<PathBuf>,

    /// Independently trusted root key as KEY_ID=PATH
    #[arg(long = "trusted-root-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_root_keys: Vec<String>,

    /// Required independently trusted root signature count
    #[arg(long, default_value_t = 2)]
    pub trusted_root_threshold: u16,

    /// Top-level targets signing key as KEY_ID=PATH; repeat to threshold
    #[arg(long = "targets-key", value_name = "KEY_ID=PATH", required = true)]
    pub targets_keys: Vec<String>,

    /// Release-class delegated signing key as KEY_ID=PATH; repeat to threshold
    #[arg(long = "delegated-key", value_name = "KEY_ID=PATH", required = true)]
    pub delegated_keys: Vec<String>,

    /// Snapshot signing key as KEY_ID=PATH; repeat to threshold
    #[arg(long = "snapshot-key", value_name = "KEY_ID=PATH", required = true)]
    pub snapshot_keys: Vec<String>,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Maximum duration of each external signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub signer_timeout_seconds: u64,

    /// Top-level targets metadata version
    #[arg(long)]
    pub targets_version: u64,

    /// Release-class delegated metadata version
    #[arg(long)]
    pub delegated_version: u64,

    /// Snapshot metadata version
    #[arg(long)]
    pub snapshot_version: u64,

    /// RFC 3339 UTC top-level targets expiry
    #[arg(long)]
    pub targets_expires: String,

    /// RFC 3339 UTC delegated targets expiry
    #[arg(long)]
    pub delegated_expires: String,

    /// RFC 3339 UTC snapshot expiry
    #[arg(long)]
    pub snapshot_expires: String,

    /// RFC 3339 UTC verification time
    #[arg(long)]
    pub now: String,

    /// New immutable TUF metadata directory
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseComposeSurfaceArgs {
    /// Destination whose surface is composed
    #[arg(long)]
    pub to: String,

    /// Public release record authorized by the delegated targets
    #[arg(long)]
    pub release_record: Option<PathBuf>,

    /// Canonical release plan governing the publication surface
    #[arg(long)]
    pub plan: PathBuf,

    /// Finalized release bundle whose manifest is the delegated TUF target
    #[arg(long)]
    pub bundle: PathBuf,

    /// Manifest verification key as KEY_ID=PATH; repeat to threshold
    #[arg(long = "manifest-key", value_name = "KEY_ID=PATH", required = true)]
    pub manifest_keys: Vec<String>,

    /// Existing immutable registry/cache publication surface
    #[arg(long)]
    pub base_surface: PathBuf,

    /// Current signed TUF root envelope
    #[arg(long)]
    pub root: PathBuf,

    /// Previous signed root when the current root is a rotation
    #[arg(long)]
    pub previous_root: Option<PathBuf>,

    /// Signed top-level TUF targets envelope
    #[arg(long)]
    pub targets: PathBuf,

    /// Signed release-class delegated targets envelope
    #[arg(long)]
    pub delegated: PathBuf,

    /// Signed immutable TUF snapshot envelope
    #[arg(long)]
    pub snapshot: PathBuf,

    /// Fresh signed TUF timestamp envelope
    #[arg(long)]
    pub timestamp: PathBuf,

    /// Independently trusted root key as KEY_ID=PATH
    #[arg(long = "trusted-root-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_root_keys: Vec<String>,

    /// Required independently trusted root signature count
    #[arg(long, default_value_t = 2)]
    pub trusted_root_threshold: u16,

    /// Prior timestamp version, or zero for the first timestamp
    #[arg(long, default_value_t = 0)]
    pub previous_timestamp_version: u64,

    /// RFC 3339 UTC verification time
    #[arg(long)]
    pub now: String,

    /// New complete publication surface; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseFinalizeImageArgs {
    /// Canonical release plan authorizing the image and signer policies
    #[arg(long)]
    pub plan: PathBuf,

    /// Nix-produced public unsigned-image assembly directory
    #[arg(long)]
    pub assembly: PathBuf,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Exact role key as ROLE=KEY_ID; repeat for all three image roles
    #[arg(long = "signer-key", value_name = "ROLE=KEY_ID", required = true)]
    pub signer_keys: Vec<String>,

    /// Maximum duration of each external signer operation in seconds
    #[arg(long, default_value_t = 300)]
    pub signer_timeout_seconds: u64,

    /// New private finalization work directory containing the final output
    #[arg(long)]
    pub work: PathBuf,
}

#[derive(Args)]
pub struct ReleasePrepareRegistryArgs {
    /// Canonical release plan authorizing the registry transaction
    #[arg(long)]
    pub plan: PathBuf,

    /// Validated build report containing every transaction store output
    #[arg(long)]
    pub build_report: PathBuf,

    /// Externally signed canonical container-release sidecar to commit
    #[arg(long, requires_all = ["container_signature_input", "container_layout"])]
    pub container_release: Option<PathBuf>,

    /// Nix-produced signature input paired with --container-release
    #[arg(long, requires = "container_release")]
    pub container_signature_input: Option<PathBuf>,

    /// OCI image layout whose graph is captured with the container candidate
    #[arg(long, requires = "container_release")]
    pub container_layout: Option<PathBuf>,

    /// Distribution repository for the signed container image
    #[arg(long, requires = "container_layout")]
    pub container_repository: Option<String>,

    /// Clean authoring registry at the exact planned base commit
    #[arg(long)]
    pub source_registry: PathBuf,

    /// New isolated registry directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,

    /// New generated transaction JSON for review before finalization
    #[arg(long)]
    pub transaction: PathBuf,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Provenance roster key and public trust line as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub provenance_key: String,

    /// Active registry roster key for canonical catalog metadata as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub registry_key: String,

    /// Provider verification identity expected for catalog metadata operations
    #[arg(long)]
    pub registry_verification_identity: String,

    /// Provider verification identity expected for provenance operations
    #[arg(long)]
    pub provenance_verification_identity: String,

    /// Maximum duration of each external signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub signer_timeout_seconds: u64,
}

#[derive(Args)]
pub struct ReleaseFinalizeRegistryArgs {
    /// Canonical release plan authorizing the reviewed transaction
    #[arg(long)]
    pub plan: PathBuf,

    /// Validated build report containing every transaction store output
    #[arg(long)]
    pub build_report: PathBuf,

    /// Reviewed generated transaction with exact prepared surface digests
    #[arg(long)]
    pub transaction: PathBuf,

    /// Prepared isolated registry directory bound by the transaction
    #[arg(long)]
    pub prepared_registry: PathBuf,

    /// Externally signed canonical container-release sidecar that was prepared
    #[arg(long, requires = "container_signature_input")]
    pub container_release: Option<PathBuf>,

    /// Nix-produced signature input paired with --container-release
    #[arg(long, requires = "container_release")]
    pub container_signature_input: Option<PathBuf>,

    /// New canonical finalization result JSON
    #[arg(long)]
    pub result: PathBuf,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Registry roster key and public trust line as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub registry_key: String,

    /// Provider verification identity expected for registry operations
    #[arg(long)]
    pub registry_verification_identity: String,

    /// Maximum duration of each external signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub signer_timeout_seconds: u64,

    /// Public Git author and tagger name
    #[arg(long)]
    pub git_name: String,

    /// Public Git author and tagger email
    #[arg(long)]
    pub git_email: String,

    /// Frozen Git author and tagger time as Unix seconds
    #[arg(long)]
    pub git_unix_seconds: i64,

    /// Frozen timezone offset in minutes east of UTC
    #[arg(long, default_value_t = 0)]
    pub git_offset_minutes: i32,
}

#[derive(Args)]
pub struct ReleaseFinalizeArgs {
    /// Canonical release plan copied into the closed bundle
    #[arg(long)]
    pub plan: PathBuf,

    /// Payload tree containing every manifest artifact except the release plan
    #[arg(long)]
    pub payload: PathBuf,

    /// Canonical unsigned release-manifest payload
    #[arg(long)]
    pub manifest_payload: PathBuf,

    /// Built-state append-only release journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Release-evidence public key as KEY_ID=PATH; repeat to threshold
    #[arg(long = "signing-key", value_name = "KEY_ID=PATH", required = true)]
    pub signing_keys: Vec<String>,

    /// Independently pinned provider identity as KEY_ID=IDENTITY
    #[arg(
        long = "verification-identity",
        value_name = "KEY_ID=IDENTITY",
        required = true
    )]
    pub verification_identities: Vec<String>,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Maximum duration of each external signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub signer_timeout_seconds: u64,

    /// RFC 3339 UTC finalization time recorded in the journal
    #[arg(long)]
    pub recorded_at: String,

    /// New directory containing bundle and finalized journal
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseFinalizeCacheArgs {
    /// Canonical release plan authorizing cache signing
    #[arg(long)]
    pub plan: PathBuf,

    /// Validated build report for the exact package matrix
    #[arg(long)]
    pub build_report: PathBuf,

    /// Finalized isolated registry directory
    #[arg(long)]
    pub registry: PathBuf,

    /// Cache-role public Ed25519 key as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub cache_key: String,

    /// Independently pinned provider identity for the cache key
    #[arg(long)]
    pub verification_identity: String,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Maximum duration of each signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub signer_timeout_seconds: u64,

    /// Cache priority written into nix-cache-info
    #[arg(long, default_value_t = 40)]
    pub priority: u32,

    /// Maximum parallel NAR compression jobs
    #[arg(long)]
    pub jobs: Option<usize>,

    /// New externally signed static-cache directory
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args, Clone, Debug, Default)]
pub struct ReleaseFitnessInputArgs {
    /// Directory of signed fitness attestations, as <kind>/<performed_at>.json
    #[arg(long)]
    pub fitness: Option<PathBuf>,

    /// Live tooling-closure digest bound by tooling fitness
    #[arg(long)]
    pub tooling_digest: Option<String>,

    /// Live alert-configuration digest bound by alert-config fitness
    #[arg(long)]
    pub alert_config_digest: Option<String>,

    /// Live Hub schema version bound by hub-schema fitness
    #[arg(long)]
    pub hub_schema: Option<String>,
}

#[derive(Args)]
pub struct ReleasePublishArgs {
    /// Expected candidate revision for an upload update or publication
    #[arg(long)]
    pub stage_revision: Option<u64>,

    /// Upload immutable artifacts and retain an unpublished candidate
    #[arg(long)]
    pub stage_only: bool,

    /// Completed candidate upload directory whose exact revision is being published
    #[arg(long)]
    pub staged_upload: Option<PathBuf>,

    /// Destination to publish, such as staging/edge or production/stable
    #[arg(long)]
    pub to: String,

    /// Closed finalized bundle
    #[arg(long)]
    pub bundle: PathBuf,

    /// Current append-only journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Composed surface (TUF metadata, release record) to publish with the bundle
    #[arg(long, requires = "trusted_root_keys")]
    pub surface: Option<PathBuf>,

    /// Independently trusted TUF root key as KEY_ID=PATH, verifying --surface
    #[arg(
        long = "trusted-root-key",
        value_name = "KEY_ID=PATH",
        requires = "surface"
    )]
    pub trusted_root_keys: Vec<String>,

    /// Required independently trusted TUF root signature count
    #[arg(long, default_value_t = 2)]
    pub trusted_root_threshold: u16,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Destination surface receipt key as KEY_ID=PATH
    #[arg(long = "receipt-key", value_name = "KEY_ID=PATH", required = true)]
    pub receipt_keys: Vec<String>,

    /// Staging publication receipt, required for production destinations
    #[arg(long)]
    pub predecessor_receipt: Option<PathBuf>,

    /// Staging surface receipt key as KEY_ID=PATH
    #[arg(long = "predecessor-receipt-key", value_name = "KEY_ID=PATH")]
    pub predecessor_receipt_keys: Vec<String>,

    /// Signed staging-phase qualification directory; repeatable
    #[arg(long = "evidence")]
    pub evidence: Vec<PathBuf>,

    /// Qualification authority key as KEY_ID=PATH
    #[arg(long = "qualification-key", value_name = "KEY_ID=PATH")]
    pub qualification_keys: Vec<String>,

    #[command(flatten)]
    pub fitness: ReleaseFitnessInputArgs,

    /// Short-lived access token for a Hub surface
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// Maintainer configuration with static-surface credentials and signers
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// New receipt-and-journal directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args, Clone)]
pub struct ReleaseQualifyRunArgs {
    /// Destination whose profile selects the cases
    #[arg(long)]
    pub to: String,
    /// Collect a report for independent review without invoking the signer
    #[arg(long, conflicts_with = "report_input")]
    pub prepare_only: bool,

    /// Admit an already collected canonical report after independent review
    #[arg(long)]
    pub report_input: Option<PathBuf>,
    /// Select the hold point whose exact public objects are qualified
    #[arg(long, default_value = "staging", value_parser = ["staging", "rollout", "complete"])]
    pub phase: String,

    /// Rollout ring being admitted, required for the rollout phase
    #[arg(long, required_if_eq("phase", "rollout"))]
    pub ring: Option<u16>,

    /// Expected channel generation before the ring, required for the rollout phase
    #[arg(long, required_if_eq("phase", "rollout"))]
    pub prior_generation: Option<u64>,

    /// Current journal, required for rollout and completion qualification
    #[arg(long)]
    pub journal: Option<PathBuf>,

    /// Independent signed report review; repeat to the release-evidence threshold
    #[arg(long = "review-receipt")]
    pub review_receipts: Vec<PathBuf>,
    /// Closed finalized bundle whose public staging objects are tested
    #[arg(long)]
    pub bundle: PathBuf,

    /// Publication receipt of the surface under test
    #[arg(long, alias = "publication-receipt")]
    pub staging_receipt: PathBuf,

    /// Verified prior release bundle used by image update scenarios
    #[arg(long, conflicts_with = "report_input")]
    pub predecessor_bundle: Option<PathBuf>,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Receipt key of the surface under test as KEY_ID=PATH
    #[arg(
        long = "hub-receipt-key",
        alias = "receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub hub_receipt_keys: Vec<String>,

    /// Executor as PLATFORM=ABSOLUTE_PATH for each applicable platform
    #[arg(long = "executor", value_name = "PLATFORM=PATH", required = true)]
    pub executors: Vec<String>,

    /// Expected executor identity as PLATFORM=IDENTITY for each applicable platform
    #[arg(
        long = "executor-identity",
        value_name = "PLATFORM=IDENTITY",
        required = true
    )]
    pub executor_identities: Vec<String>,

    /// Maximum duration of each native executor operation in seconds
    #[arg(long, default_value_t = 1800)]
    pub executor_timeout_seconds: u64,

    /// Absolute path to the qualification authority signer executable
    #[arg(long)]
    pub authority_executable: PathBuf,

    /// Qualification authority public key as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub authority_key: String,

    /// Independently pinned qualification signer provider identity
    #[arg(long)]
    pub authority_verification_identity: String,

    /// Maximum duration of the authority signer operation in seconds
    #[arg(long, default_value_t = 120)]
    pub authority_timeout_seconds: u64,

    /// Lowercase 32-byte hexadecimal nonce seed for executor requests
    #[arg(long)]
    pub executor_nonce: String,

    /// Lowercase 32-byte hexadecimal nonce for aggregate authority signing
    #[arg(long)]
    pub authority_nonce: String,

    /// RFC 3339 admission time, or now after observations have been collected
    #[arg(long, default_value = "now")]
    pub qualified_at: String,

    /// New qualification result directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseRecordArgs {
    /// Production destination whose staging qualification is recorded
    #[arg(long)]
    pub to: String,

    /// Closed finalized bundle already qualified in staging
    #[arg(long)]
    pub bundle: PathBuf,

    /// Exact signed qualification envelope
    #[arg(long)]
    pub signed_qualification: PathBuf,

    /// Canonical staging-phase qualification report
    #[arg(long)]
    pub qualification_report: PathBuf,

    /// Exact staging publication receipt the qualification binds
    #[arg(long)]
    pub staging_receipt: PathBuf,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted qualification key as KEY_ID=PATH
    #[arg(
        long = "qualification-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub qualification_keys: Vec<String>,

    /// Destination for the canonical release record JSON
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Subcommand)]
pub enum ReleaseChannelCommand {
    /// Compare-and-swap one planned channel partition range
    Advance(ReleaseChannelAdvanceArgs),
    /// Verify rollout, retention, and operational handoff as complete
    Complete(ReleaseChannelCompleteArgs),
}

#[derive(Args)]
pub struct ReleaseChannelAdvanceArgs {
    /// Destination whose channel advances
    #[arg(long)]
    pub to: String,

    /// One-based rollout ring to advance
    #[arg(long)]
    pub ring: u16,

    /// Expected channel generation; read from a static surface when omitted
    #[arg(long)]
    pub prior_generation: Option<u64>,

    /// Signed rollout qualification directory for this ring
    #[arg(long)]
    pub qualification: Option<PathBuf>,

    /// Qualification authority key as KEY_ID=PATH
    #[arg(long = "qualification-key", value_name = "KEY_ID=PATH")]
    pub qualification_keys: Vec<String>,

    /// Closed finalized bundle whose manifest is being rolled out
    #[arg(long)]
    pub bundle: PathBuf,

    /// Current append-only journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Destination surface publication receipt
    #[arg(long)]
    pub publication_receipt: PathBuf,

    /// Channel receipt of an earlier ring of this destination; repeatable
    #[arg(long = "channel-receipt")]
    pub channel_receipts: Vec<PathBuf>,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Destination surface receipt key as KEY_ID=PATH
    #[arg(long = "receipt-key", value_name = "KEY_ID=PATH", required = true)]
    pub receipt_keys: Vec<String>,

    /// Channel receipt key as KEY_ID=PATH; defaults to the receipt keys
    #[arg(long = "channel-receipt-key", value_name = "KEY_ID=PATH")]
    pub channel_receipt_keys: Vec<String>,

    #[command(flatten)]
    pub fitness: ReleaseFitnessInputArgs,

    /// Short-lived access token for a Hub surface
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// Maintainer configuration with static-surface credentials and signers
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// New channel evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseChannelCompleteArgs {
    /// Destination whose rollout completes
    #[arg(long)]
    pub to: String,

    /// Signed completion qualification directory
    #[arg(long)]
    pub qualification: Option<PathBuf>,

    /// Qualification authority key as KEY_ID=PATH
    #[arg(long = "qualification-key", value_name = "KEY_ID=PATH")]
    pub qualification_keys: Vec<String>,

    /// Closed finalized bundle whose rollout is completing
    #[arg(long)]
    pub bundle: PathBuf,

    /// Rolling append-only journal containing every ring
    #[arg(long)]
    pub journal: PathBuf,

    /// Destination surface publication receipt
    #[arg(long)]
    pub publication_receipt: PathBuf,

    /// Signed channel receipt; repeat for every planned ring
    #[arg(long = "channel-receipt", required = true)]
    pub channel_receipts: Vec<PathBuf>,

    /// Identical signed completion decision; repeat to satisfy its threshold
    #[arg(long = "completion-receipt", required = true)]
    pub completion_receipts: Vec<PathBuf>,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Destination surface receipt key as KEY_ID=PATH
    #[arg(long = "receipt-key", value_name = "KEY_ID=PATH", required = true)]
    pub receipt_keys: Vec<String>,

    /// Channel receipt key as KEY_ID=PATH; defaults to the receipt keys
    #[arg(long = "channel-receipt-key", value_name = "KEY_ID=PATH")]
    pub channel_receipt_keys: Vec<String>,

    /// Release-evidence key as KEY_ID=PATH; repeat for the planned threshold
    #[arg(long = "completion-key", value_name = "KEY_ID=PATH", required = true)]
    pub completion_keys: Vec<String>,

    /// New completion evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Subcommand)]
pub enum ReleaseSignerCommand {
    /// Submit one canonical request and verify its detached Ed25519 response
    Invoke(ReleaseSignerInvokeArgs),
}

#[derive(Args)]
pub struct ReleaseSignerInvokeArgs {
    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub executable: PathBuf,

    /// Canonical signing-request JSON
    #[arg(long)]
    pub request: PathBuf,

    /// Exact payload whose digest is bound by the signing request
    #[arg(long)]
    pub payload: PathBuf,

    /// Trusted Ed25519 public key as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub trusted_key: String,

    /// Independently pinned device, certificate, or provider identity
    #[arg(long)]
    pub verification_identity: String,

    /// Maximum provider call time in seconds
    #[arg(long, default_value_t = 120)]
    pub timeout_seconds: u64,

    /// New canonical response path; existing files are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseStatusArgs {
    /// Canonical append-only release journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Frozen plan, to list destinations not yet published
    #[arg(long)]
    pub plan: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReleaseBuildArgs {
    /// Canonical release plan produced by `aos maintain release plan`
    #[arg(long)]
    pub plan: PathBuf,

    /// New build-evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,

    /// RFC 3339 UTC time at which the build operation began
    #[arg(long)]
    pub started_at: String,
}

#[derive(Args)]
pub struct ReleaseAssembleArgs {
    /// Canonical release plan produced by `aos maintain release plan`
    #[arg(long)]
    pub plan: PathBuf,

    /// Validated build report for the exact package matrix
    #[arg(long)]
    pub build_report: PathBuf,

    /// SPDX document emitted beside the build report
    #[arg(long)]
    pub sbom: PathBuf,

    /// Public contributor-authorization summary bound by the plan
    #[arg(long)]
    pub contributor_authorization: PathBuf,

    /// Reviewed canonical advisory disposition for the exact SBOM
    #[arg(long)]
    pub advisory_disposition: PathBuf,

    /// Externally signed static Nix cache
    #[arg(long)]
    pub cache: PathBuf,

    /// Cache-role public Ed25519 key as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub cache_key: String,

    /// Finalized isolated registry directory
    #[arg(long)]
    pub registry: PathBuf,

    /// Canonical registry finalization result
    #[arg(long)]
    pub registry_result: PathBuf,

    /// Finalized image-set root; repeat for every planned Linux image cell
    #[arg(long = "image-set")]
    pub image_sets: Vec<PathBuf>,

    /// Final externally signed container publication bundle
    #[arg(long)]
    pub container: Option<PathBuf>,

    /// RFC 3339 UTC time at which assembly validation completed
    #[arg(long)]
    pub completed_at: String,

    /// New directory containing payload and canonical unsigned manifest
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleasePlanArgs {
    /// Canonical reviewed planner-input JSON
    #[arg(long)]
    pub request: PathBuf,

    /// Public contributor-authorization evidence bound by the request
    #[arg(long = "contributor-authorization")]
    pub contributor_authorization: PathBuf,

    /// Predecessor manifest (payload or envelope) used to compute the change scope
    #[arg(long)]
    pub predecessor_manifest: Option<PathBuf>,

    /// Directory of signed profile-override envelopes; repeatable
    #[arg(long = "override")]
    pub overrides: Vec<PathBuf>,

    /// Release-evidence key as KEY_ID=PATH that may approve overrides
    #[arg(long = "override-key", value_name = "KEY_ID=PATH")]
    pub override_keys: Vec<String>,

    /// New canonical release-plan path; existing files are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseVerifyArgs {
    /// Closed release bundle directory
    pub bundle: PathBuf,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Optional append-only canonical JSONL release journal
    #[arg(long)]
    pub journal: Option<PathBuf>,
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod tests;
