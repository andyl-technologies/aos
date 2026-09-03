//! Command-line contract for canonical AOS release operations.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ReleaseCommand {
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
    /// Renew short-lived metadata without changing authorized content
    Timestamp {
        #[command(subcommand)]
        command: ReleaseTimestampCommand,
    },
    /// Upload an exact finalized bundle to the canonical staging Hub
    Stage(ReleaseStageArgs),
    /// Admit signed qualification of the exact staged public release
    Qualify(ReleaseQualifyArgs),
    /// Import the exact qualified release into the canonical production Hub
    Promote(ReleasePromoteArgs),
    /// Advance or complete planned production channel rollout
    Channel {
        #[command(subcommand)]
        command: ReleaseChannelCommand,
    },
    /// Verify a captured release bundle using only public trust inputs
    Verify(ReleaseVerifyArgs),
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

#[derive(Args)]
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
}
