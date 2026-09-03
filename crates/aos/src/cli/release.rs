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
    /// Verify a captured release bundle using only public trust inputs
    Verify(ReleaseVerifyArgs),
}

#[derive(Subcommand)]
pub enum ReleaseTimestampCommand {
    /// Sign a fresh pointer to one already-authorized snapshot
    Refresh(ReleaseTimestampRefreshArgs),
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
