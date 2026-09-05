//! Command-line contract for canonical AOS release operations.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ReleaseCommand {
    /// Inspect cases or execute an exact qualification request
    Qualification {
        #[command(subcommand)]
        command: ReleaseQualificationCommand,
    },
    /// Inspect the shared qualification contract and required release gates
    Contract(ReleaseContractArgs),
    /// Derive and freeze a release plan from Git and the Nix inventory
    Plan(ReleasePlanArgs),
    /// Realize and repeat-check every planned Nix output
    Build(ReleaseBuildArgs),
    /// Reconcile and display an append-only release journal
    Status(ReleaseStatusArgs),
    /// Exercise and audit a configured external signing provider
    Signer {
        #[command(subcommand)]
        command: ReleaseSignerCommand,
    },
    /// Finalize one Linux image assembly through external signers
    FinalizeImage(ReleaseFinalizeImageArgs),
    /// Author and sign one isolated canonical registry release
    FinalizeRegistry(ReleaseFinalizeRegistryArgs),
    /// Close and threshold-sign one release bundle
    Finalize(ReleaseFinalizeArgs),
    /// Generate and externally sign the complete static Nix cache
    FinalizeCache(ReleaseFinalizeCacheArgs),
    /// Renew short-lived metadata without changing authorized content
    Timestamp {
        #[command(subcommand)]
        command: ReleaseTimestampCommand,
    },
    /// Construct immutable role-separated TUF repository metadata
    Tuf(ReleaseTufArgs),
    /// Compose verified registry, release target, and TUF bytes atomically
    ComposeSurface(ReleaseComposeSurfaceArgs),
    /// Upload an exact finalized bundle to the canonical staging Hub
    Stage(ReleaseStageArgs),
    /// Admit signed qualification of the exact staged public release
    Qualify(ReleaseQualifyArgs),
    /// Execute every planned gate against exact public staging bytes
    QualifyRun(ReleaseQualifyRunArgs),
    /// Import the exact qualified release into the canonical production Hub
    Promote(ReleasePromoteArgs),
    /// Compose the public release record from admitted qualification evidence
    Record(ReleaseRecordArgs),
    /// Install one explicitly approved first registry base in an empty Hub
    Bootstrap(ReleaseBootstrapArgs),
    /// Advance or complete planned production channel rollout
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
}

#[derive(Args)]
pub struct ReleaseQualificationCasesArgs {
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
pub struct ReleaseContractArgs {
    /// Select the release class whose obligations are displayed
    #[arg(long = "class", default_value = "edge", value_parser = ["edge", "candidate", "stable", "emergency"])]
    pub release_class: String,

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

    /// Isolated destination: staging or production
    #[arg(long, value_parser = ["staging", "production"])]
    pub environment: String,

    /// Identical signed bootstrap intent; repeat to satisfy its threshold
    #[arg(long = "signed-intent", required = true)]
    pub signed_intents: Vec<PathBuf>,

    /// Release-evidence key as KEY_ID=PATH; repeat for the planned threshold
    #[arg(long = "approval-key", value_name = "KEY_ID=PATH", required = true)]
    pub approval_keys: Vec<String>,

    /// Short-lived environment-specific Hub access token
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

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

    /// Short-lived production-only Hub access token
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// New timestamp publication evidence directory
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseTimestampRefreshArgs {
    /// Canonical release plan governing the timestamp signer
    #[arg(long)]
    pub plan: PathBuf,

    /// Current signed TUF root envelope
    #[arg(long)]
    pub root: PathBuf,

    /// Current signed immutable snapshot envelope
    #[arg(long)]
    pub snapshot: PathBuf,

    /// Previous timestamp for this snapshot, when one exists
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
pub struct ReleaseFinalizeRegistryArgs {
    /// Canonical release plan authorizing the registry transaction
    #[arg(long)]
    pub plan: PathBuf,

    /// Validated build report containing every transaction store output
    #[arg(long)]
    pub build_report: PathBuf,

    /// Reviewed atomic registry transaction with expected surface digests
    #[arg(long)]
    pub transaction: PathBuf,

    /// Externally signed canonical container-release sidecar to commit
    #[arg(long, requires = "container_signature_input")]
    pub container_release: Option<PathBuf>,

    /// Nix-produced signature input paired with --container-release
    #[arg(long, requires = "container_release")]
    pub container_signature_input: Option<PathBuf>,

    /// Clean authoring registry at the exact planned base commit
    #[arg(long)]
    pub source_registry: PathBuf,

    /// New isolated registry directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,

    /// New canonical finalization result JSON
    #[arg(long)]
    pub result: PathBuf,

    /// Absolute path to the deployment-configured signer executable
    #[arg(long)]
    pub signer_executable: PathBuf,

    /// Provenance roster key and public trust line as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub provenance_key: String,

    /// Registry roster key and public trust line as KEY_ID=PATH
    #[arg(long, value_name = "KEY_ID=PATH")]
    pub registry_key: String,

    /// Provider verification identity expected for provenance operations
    #[arg(long)]
    pub provenance_verification_identity: String,

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

#[derive(Args)]
pub struct ReleaseStageArgs {
    /// Closed finalized bundle and registry surface
    #[arg(long)]
    pub bundle: PathBuf,

    /// Finalized append-only journal captured before staging
    #[arg(long)]
    pub journal: PathBuf,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted staging Hub receipt key as KEY_ID=PATH
    #[arg(long = "hub-receipt-key", value_name = "KEY_ID=PATH", required = true)]
    pub hub_receipt_keys: Vec<String>,

    /// Short-lived staging-only Hub access token
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// New receipt-and-journal directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseQualifyArgs {
    /// Closed finalized bundle whose staged bytes were qualified
    #[arg(long)]
    pub bundle: PathBuf,

    /// Staged append-only journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Exact signed staging receipt returned by the Hub
    #[arg(long)]
    pub staging_receipt: PathBuf,

    /// Signed qualification envelope returned by the qualification authority
    #[arg(long)]
    pub signed_qualification: PathBuf,

    /// Canonical complete gate/platform qualification report
    #[arg(long)]
    pub qualification_report: PathBuf,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted staging Hub receipt key as KEY_ID=PATH
    #[arg(long = "hub-receipt-key", value_name = "KEY_ID=PATH", required = true)]
    pub hub_receipt_keys: Vec<String>,

    /// Independently trusted qualification key as KEY_ID=PATH
    #[arg(
        long = "qualification-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub qualification_keys: Vec<String>,

    /// Short-lived staging-only Hub access token
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// New qualification evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args, Clone)]
pub struct ReleaseQualifyRunArgs {
    /// Collect a report for independent review without invoking the signer
    #[arg(long, conflicts_with = "report_input")]
    pub prepare_only: bool,

    /// Admit an already collected canonical report after independent review
    #[arg(long)]
    pub report_input: Option<PathBuf>,
    /// Select the hold point whose exact public objects are qualified
    #[arg(long, default_value = "staging", value_parser = ["staging", "rollout", "complete"])]
    pub phase: String,

    /// Canonical channel/generation/partition intent, required for rollout signing
    #[arg(long)]
    pub rollout_intent: Option<PathBuf>,

    /// Current journal, required for rollout and completion qualification
    #[arg(long)]
    pub journal: Option<PathBuf>,

    /// Independent signed report review; repeat to the release-evidence threshold
    #[arg(long = "review-receipt")]
    pub review_receipts: Vec<PathBuf>,
    /// Closed finalized bundle whose public staging objects are tested
    #[arg(long)]
    pub bundle: PathBuf,

    /// Exact signed staging receipt returned by the Hub
    #[arg(long, alias = "publication-receipt")]
    pub staging_receipt: PathBuf,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted staging Hub receipt key as KEY_ID=PATH
    #[arg(long = "hub-receipt-key", value_name = "KEY_ID=PATH", required = true)]
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
    /// Closed finalized bundle already qualified in staging
    #[arg(long)]
    pub bundle: PathBuf,

    /// Canonical qualification receipt payload
    #[arg(long)]
    pub qualification_receipt: PathBuf,

    /// Exact signed qualification envelope
    #[arg(long)]
    pub signed_qualification: PathBuf,

    /// Canonical complete gate/platform qualification report
    #[arg(long)]
    pub qualification_report: PathBuf,

    /// Exact signed staging receipt the qualification binds
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

#[derive(Debug, Args)]
pub struct ReleasePromoteArgs {
    /// Closed finalized bundle already qualified in staging
    #[arg(long)]
    pub bundle: PathBuf,

    /// Qualified append-only journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Exact signed staging receipt
    #[arg(long)]
    pub staging_receipt: PathBuf,

    /// Canonical qualification receipt payload
    #[arg(long)]
    pub qualification_receipt: PathBuf,

    /// Exact signed qualification envelope
    #[arg(long)]
    pub signed_qualification: PathBuf,

    /// Canonical complete gate/platform qualification report
    #[arg(long)]
    pub qualification_report: PathBuf,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted staging Hub receipt key as KEY_ID=PATH
    #[arg(
        long = "staging-receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub staging_receipt_keys: Vec<String>,

    /// Independently trusted qualification key as KEY_ID=PATH
    #[arg(
        long = "qualification-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub qualification_keys: Vec<String>,

    /// Independently trusted production Hub receipt key as KEY_ID=PATH
    #[arg(
        long = "production-receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub production_receipt_keys: Vec<String>,

    /// Short-lived production-only Hub access token
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// New production evidence directory; existing paths are never replaced
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
    /// Signed current rollout qualification directory
    #[arg(long)]
    pub qualification: Option<PathBuf>,

    /// Planned qualification authority public key as KEY_ID=PATH
    #[arg(long = "qualification-key")]
    pub qualification_keys: Vec<String>,
    /// Closed finalized bundle whose manifest is being rolled out
    #[arg(long)]
    pub bundle: PathBuf,

    /// Promoted or rolling append-only journal
    #[arg(long)]
    pub journal: PathBuf,

    /// Exact signed production publication receipt
    #[arg(long)]
    pub production_receipt: PathBuf,

    /// Planned channel name
    #[arg(long)]
    pub channel: String,

    /// Expected prior channel generation
    #[arg(long)]
    pub prior_generation: u64,

    /// Inclusive first planned partition
    #[arg(long)]
    pub first_partition: u16,

    /// Inclusive final planned partition
    #[arg(long)]
    pub last_partition: u16,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted production Hub receipt key as KEY_ID=PATH
    #[arg(
        long = "production-receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub production_receipt_keys: Vec<String>,

    /// Independently trusted channel receipt key as KEY_ID=PATH
    #[arg(
        long = "channel-receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub channel_receipt_keys: Vec<String>,

    /// Short-lived production-only Hub access token
    #[arg(long, env = "AOS_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// New channel evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReleaseChannelCompleteArgs {
    /// Signed current completion qualification directory
    #[arg(long)]
    pub qualification: Option<PathBuf>,

    /// Planned qualification authority public key as KEY_ID=PATH
    #[arg(long = "qualification-key")]
    pub qualification_keys: Vec<String>,
    /// Closed finalized bundle whose rollout is completing
    #[arg(long)]
    pub bundle: PathBuf,

    /// Rolling append-only journal containing every channel operation
    #[arg(long)]
    pub journal: PathBuf,

    /// Exact signed production publication receipt
    #[arg(long)]
    pub production_receipt: PathBuf,

    /// Signed channel receipt; repeat for every planned range
    #[arg(long = "channel-receipt", required = true)]
    pub channel_receipts: Vec<PathBuf>,

    /// Identical signed completion decision; repeat to satisfy its threshold
    #[arg(long = "completion-receipt", required = true)]
    pub completion_receipts: Vec<PathBuf>,

    /// Trusted manifest key as KEY_ID=PATH; repeat to satisfy thresholds
    #[arg(long = "trusted-key", value_name = "KEY_ID=PATH", required = true)]
    pub trusted_keys: Vec<String>,

    /// Independently trusted production Hub receipt key as KEY_ID=PATH
    #[arg(
        long = "production-receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
    pub production_receipt_keys: Vec<String>,

    /// Independently trusted channel receipt key as KEY_ID=PATH
    #[arg(
        long = "channel-receipt-key",
        value_name = "KEY_ID=PATH",
        required = true
    )]
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
}

#[derive(Args)]
pub struct ReleaseBuildArgs {
    /// Canonical release plan produced by `aos release plan`
    #[arg(long)]
    pub plan: PathBuf,

    /// New build-evidence directory; existing paths are never replaced
    #[arg(long)]
    pub output: PathBuf,

    /// RFC 3339 UTC time at which the build operation began
    #[arg(long)]
    pub started_at: String,

    /// RFC 3339 UTC time at which the completed report is recorded
    #[arg(long)]
    pub completed_at: String,
}

#[derive(Args)]
pub struct ReleasePlanArgs {
    /// Canonical reviewed planner-input JSON
    #[arg(long)]
    pub request: PathBuf,

    /// Public contributor-authorization evidence bound by the request
    #[arg(long = "contributor-authorization")]
    pub contributor_authorization: PathBuf,

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
mod tests {
    use clap::Parser as _;

    use crate::cli::{Cli, Commands};

    #[test]
    fn verifier_requires_explicit_trust_input() {
        assert!(Cli::try_parse_from(["aos", "release", "verify", "bundle"]).is_err());

        let Ok(parsed) = Cli::try_parse_from([
            "aos",
            "release",
            "verify",
            "bundle",
            "--trusted-key",
            "release=/keys/release.pub",
        ]) else {
            panic!("release verifier arguments should parse");
        };
        assert!(matches!(parsed.command, Commands::Release { .. }));
    }

    #[test]
    fn planner_requires_review_and_authorization_inputs() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "plan",
                "--request",
                "request.json",
                "--contributor-authorization",
                "authorization.json",
                "--output",
                "release-plan.json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn image_finalization_requires_explicit_role_keys() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "finalize-image",
                "--plan",
                "release-plan.json",
                "--assembly",
                "/nix/store/example-assembly",
                "--signer-executable",
                "/opt/aos/signer",
                "--work",
                "/var/lib/aos-release/work",
            ])
            .is_err()
        );
    }

    #[test]
    fn registry_finalization_requires_both_public_role_keys() {
        let base = [
            "aos",
            "release",
            "finalize-registry",
            "--plan",
            "release-plan.json",
            "--build-report",
            "build-report.json",
            "--transaction",
            "registry-transaction.json",
            "--source-registry",
            "registry",
            "--output",
            "isolated-registry",
            "--result",
            "registry-result.json",
            "--signer-executable",
            "/opt/aos/signer",
            "--provenance-key",
            "provenance=provenance.pub",
            "--registry-key",
            "registry=registry.pub",
            "--provenance-verification-identity",
            "provider-provenance",
            "--registry-verification-identity",
            "provider-registry",
            "--git-name",
            "AOS Release",
            "--git-email",
            "release@example.invalid",
            "--git-unix-seconds",
            "1",
        ];
        assert!(Cli::try_parse_from(base).is_ok());

        let with_container = base
            .into_iter()
            .chain([
                "--container-release",
                "container-release.json",
                "--container-signature-input",
                "signature-input.json",
            ])
            .collect::<Vec<_>>();
        assert!(Cli::try_parse_from(with_container).is_ok());

        let unpaired = base
            .into_iter()
            .chain(["--container-release", "container-release.json"])
            .collect::<Vec<_>>();
        assert!(Cli::try_parse_from(unpaired).is_err());
    }

    #[test]
    fn bundle_finalization_requires_provider_identity_for_signers() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "finalize",
                "--plan",
                "release-plan.json",
                "--payload",
                "payload",
                "--manifest-payload",
                "manifest-payload.json",
                "--journal",
                "release-journal.jsonl",
                "--signing-key",
                "release-1=release-1.pub",
                "--verification-identity",
                "release-1=provider-slot-1",
                "--signer-executable",
                "/opt/aos/signer",
                "--recorded-at",
                "2026-09-03T12:00:00Z",
                "--output",
                "finalized",
            ])
            .is_ok()
        );
    }

    #[test]
    fn tuf_construction_requires_each_online_release_role() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "tuf",
                "--plan",
                "release-plan.json",
                "--bundle",
                "bundle",
                "--manifest-key",
                "release=release.pub",
                "--root",
                "1.root.json",
                "--trusted-root-key",
                "root-1=root-1.pub",
                "--targets-key",
                "targets-1=targets-1.pub",
                "--delegated-key",
                "stable-1=stable-1.pub",
                "--snapshot-key",
                "snapshot-1=snapshot-1.pub",
                "--signer-executable",
                "/opt/aos/signer",
                "--targets-version",
                "1",
                "--delegated-version",
                "1",
                "--snapshot-version",
                "1",
                "--targets-expires",
                "2027-01-01T00:00:00Z",
                "--delegated-expires",
                "2027-01-01T00:00:00Z",
                "--snapshot-expires",
                "2027-01-01T00:00:00Z",
                "--now",
                "2026-09-03T12:00:00Z",
                "--output",
                "tuf",
            ])
            .is_ok()
        );
    }

    #[test]
    fn cache_finalization_requires_external_key_and_provider_identity() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "finalize-cache",
                "--plan",
                "release-plan.json",
                "--build-report",
                "build-report.json",
                "--registry",
                "registry",
                "--cache-key",
                "cache-1=cache-1.pub",
                "--verification-identity",
                "provider-cache-slot",
                "--signer-executable",
                "/opt/aos/signer",
                "--output",
                "cache",
            ])
            .is_ok()
        );
    }

    #[test]
    fn qualification_run_requires_native_matrix_and_authority_inputs() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "qualify-run",
                "--bundle",
                "bundle",
                "--staging-receipt",
                "staging.json",
                "--trusted-key",
                "release=release.pub",
                "--hub-receipt-key",
                "staging=staging.pub",
                "--executor",
                "x86_64-linux=/opt/aos/qualify-linux-x86",
                "--executor",
                "aarch64-linux=/opt/aos/qualify-linux-arm",
                "--executor",
                "x86_64-darwin=/opt/aos/qualify-darwin-x86",
                "--executor",
                "aarch64-darwin=/opt/aos/qualify-darwin-arm",
                "--executor-identity",
                "x86_64-linux=linux-x86-v1",
                "--executor-identity",
                "aarch64-linux=linux-arm-v1",
                "--executor-identity",
                "x86_64-darwin=darwin-x86-v1",
                "--executor-identity",
                "aarch64-darwin=darwin-arm-v1",
                "--authority-executable",
                "/opt/aos/signer",
                "--authority-key",
                "qualification=qualification.pub",
                "--authority-verification-identity",
                "qualification-provider-v1",
                "--executor-nonce",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "--authority-nonce",
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "--qualified-at",
                "2026-09-03T12:00:00Z",
                "--output",
                "qualification",
            ])
            .is_ok()
        );
    }

    #[test]
    fn surface_composition_requires_the_complete_tuf_set() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "release",
                "compose-surface",
                "--plan",
                "release-plan.json",
                "--bundle",
                "bundle",
                "--manifest-key",
                "release=release.pub",
                "--base-surface",
                "registry-surface",
                "--root",
                "12.root.json",
                "--targets",
                "43.targets.json",
                "--delegated",
                "19.stable.json",
                "--snapshot",
                "44.snapshot.json",
                "--timestamp",
                "87.timestamp.json",
                "--trusted-root-key",
                "root-1=root-1.pub",
                "--now",
                "2026-09-03T12:00:00Z",
                "--output",
                "complete-surface",
            ])
            .is_ok()
        );
    }
}
