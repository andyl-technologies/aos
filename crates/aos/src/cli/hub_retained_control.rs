//! Live retained-control command hierarchy for `aos hub`.
//!
//! Retained mutations deliberately expose separate `plan` and `apply`
//! subcommands. Planning owns every mutable semantic input; applying accepts
//! only the immutable plan identity, its effect-manifest confirmation, and a
//! caller-supplied idempotency key.

use clap::{Args, Subcommand};
use std::num::NonZeroU64;
use std::path::PathBuf;

use super::{HubAccessArgs, HubPaginationArgs};

/// One deployment-wide retained settings section.
#[derive(Subcommand)]
pub enum HubInstanceSettingsSectionCmd {
    /// Show the current effective settings and exact revision.
    Show {
        /// Hub connection and authentication.
        #[command(flatten)]
        access: HubAccessArgs,
    },
    /// Update this section through immutable review.
    Update {
        #[command(subcommand)]
        command: HubInstanceSettingsMutationCmd,
    },
}

/// Arguments shared by every retained-control apply command.
#[derive(Args, Debug, Clone)]
pub struct HubReviewedApplyArgs {
    /// Hub connection and authentication.
    #[command(flatten)]
    pub access: HubAccessArgs,
    /// Apply this exact immutable plan.
    #[arg(long, value_name = "ID")]
    pub plan_id: String,
    /// Confirm the exact reviewed effect manifest.
    #[arg(long, value_name = "HASH")]
    pub confirm_hash: String,
    /// Stable key reused for every retry of this apply.
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: String,
    /// Confirm non-interactive application.
    #[arg(long)]
    pub yes: bool,
}

/// Arguments shared by every retained-control planning command.
#[derive(Args, Debug, Clone)]
pub struct HubReviewedPlanArgs {
    /// Hub connection and authentication.
    #[command(flatten)]
    pub access: HubAccessArgs,
    /// Stable key reused for every retry of this plan request.
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: String,
}

/// Signing-key inventory and reviewed lifecycle commands.
#[derive(Subcommand)]
pub enum HubSigningKeyCmd {
    /// List signing keys at one exact owner scope.
    List {
        /// Hub connection and authentication.
        #[command(flatten)]
        access: HubAccessArgs,
        /// Canonical organization, registry, or cache scope key.
        #[arg(long)]
        scope: String,
        /// Result pagination.
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one signing key and its active generation.
    Show {
        /// Hub connection and authentication.
        #[command(flatten)]
        access: HubAccessArgs,
        /// Canonical organization, registry, or cache scope key.
        #[arg(long)]
        scope: String,
        /// Stable signing-key name within the owner scope.
        name: String,
    },
    /// Enroll a signing key through immutable review.
    Enroll {
        #[command(subcommand)]
        command: HubSigningKeyEnrollCmd,
    },
    /// Rotate a signing key through immutable review.
    Rotate {
        #[command(subcommand)]
        command: HubSigningKeyRotateCmd,
    },
    /// Retire a signing key through immutable review.
    Retire {
        #[command(subcommand)]
        command: HubSigningKeyRetireCmd,
    },
    /// Attach or detach one typed signing usage through immutable review.
    SetUsage {
        #[command(subcommand)]
        command: HubSigningKeySetUsageCmd,
    },
}

/// Explicit plan/apply flow for signing-key enrollment.
#[derive(Subcommand)]
pub enum HubSigningKeyEnrollCmd {
    /// Create and print an immutable signing-key enrollment plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Canonical organization, registry, or cache scope key.
        #[arg(long)]
        scope: String,
        /// Stable signing-key name within the owner scope.
        name: String,
        /// File containing the canonical public key.
        #[arg(long, value_name = "FILE")]
        public_key_file: PathBuf,
        /// SHA-256 fingerprint of the canonical public-key bytes.
        #[arg(long, value_name = "SHA256")]
        public_key_fingerprint: String,
        /// Select external custody (the only supported mode).
        #[arg(long, value_parser = ["external"])]
        custody: String,
    },
    /// Apply an exact previously reviewed enrollment plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for signing-key rotation.
#[derive(Subcommand)]
pub enum HubSigningKeyRotateCmd {
    /// Create and print an immutable signing-key rotation plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Canonical organization, registry, or cache scope key.
        #[arg(long)]
        scope: String,
        /// Stable signing-key name within the owner scope.
        name: String,
        /// File containing the successor canonical public key.
        #[arg(long, value_name = "FILE")]
        public_key_file: PathBuf,
        /// SHA-256 fingerprint of the canonical public-key bytes.
        #[arg(long, value_name = "SHA256")]
        public_key_fingerprint: String,
        /// Select external custody (the only supported mode).
        #[arg(long, value_parser = ["external"])]
        custody: String,
        /// Require this exact current signing-key revision.
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed rotation plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for signing-key retirement.
#[derive(Subcommand)]
pub enum HubSigningKeyRetireCmd {
    /// Create and print an immutable signing-key retirement plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Canonical organization, registry, or cache scope key.
        #[arg(long)]
        scope: String,
        /// Stable signing-key name within the owner scope.
        name: String,
        /// Require this exact current signing-key revision.
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed retirement plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for one signing-key usage association.
#[derive(Subcommand)]
pub enum HubSigningKeySetUsageCmd {
    /// Create and print an immutable signing-usage plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Stable typed consumer identity.
        #[arg(long)]
        consumer: String,
        /// Typed signing purpose.
        #[arg(long, value_parser = ["registry-publication", "nar-info", "channel-frontier"])]
        purpose: String,
        /// Stable signing-key identity.
        #[arg(long)]
        signing_key: String,
        /// Exact immutable signing-key generation.
        #[arg(long)]
        generation: NonZeroU64,
        /// Attach or detach the usage.
        #[arg(long, value_parser = ["active", "detached"])]
        state: String,
        /// Require this usage revision (`absent` for a new association).
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed usage plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for deployment-wide instance settings.
#[derive(Subcommand)]
pub enum HubInstanceSettingsMutationCmd {
    /// Create and print an immutable settings plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Set one setting as `KEY=VALUE`; repeat for multiple settings.
        #[arg(value_name = "KEY=VALUE")]
        assignments: Vec<String>,
        /// Clear one setting override; repeat for multiple settings.
        #[arg(long = "clear", value_name = "KEY")]
        clear: Vec<String>,
        /// Require this exact current settings revision.
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed settings plan.
    Apply(HubReviewedApplyArgs),
}

/// Organization-owned service-account commands.
#[derive(Subcommand)]
pub enum HubServiceAccountCmd {
    /// List an organization's service accounts.
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one service account.
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        name: String,
    },
    /// Create a service account through immutable review.
    Create {
        #[command(subcommand)]
        command: HubServiceAccountCreateCmd,
    },
    /// Rename a service account through immutable review.
    Update {
        #[command(subcommand)]
        command: HubServiceAccountUpdateCmd,
    },
    /// Delete a service account through immutable review.
    Delete {
        #[command(subcommand)]
        command: HubServiceAccountDeleteCmd,
    },
}

#[derive(Subcommand)]
pub enum HubServiceAccountUpdateCmd {
    /// Create and print an immutable rename plan.
    Plan {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        org: String,
        name: String,
        #[arg(long)]
        new_name: String,
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed rename plan.
    Apply(HubReviewedApplyArgs),
}

#[derive(Subcommand)]
pub enum HubServiceAccountDeleteCmd {
    /// Create and print an immutable deletion plan.
    Plan {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        org: String,
        name: String,
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed deletion plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for service-account creation.
#[derive(Subcommand)]
pub enum HubServiceAccountCreateCmd {
    /// Create and print an immutable service-account plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Owning organization slug.
        org: String,
        /// Service-account name.
        name: String,
        /// Require this organization revision when supplied.
        #[arg(long, value_name = "VERSION")]
        if_version: Option<String>,
    },
    /// Apply an exact previously reviewed service-account plan.
    Apply(HubReviewedApplyArgs),
}

/// Organization invitation inventory and lifecycle commands.
#[derive(Subcommand)]
pub enum HubInvitationCmd {
    /// List invitation history for an organization.
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one invitation without its acceptance secret.
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        invitation_id: i64,
    },
    /// Create a pending invitation through immutable review.
    Create {
        #[command(subcommand)]
        command: HubInvitationCreateCmd,
    },
    /// Cancel a pending invitation through immutable review.
    Cancel {
        #[command(subcommand)]
        command: HubInvitationCancelCmd,
    },
    /// Accept an invitation as the signed-in user.
    Accept {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long, env = "AOS_INVITATION_SECRET", hide_env_values = true)]
        secret: String,
    },
}

#[derive(Subcommand)]
pub enum HubInvitationCreateCmd {
    /// Create and print an immutable invitation plan.
    Plan {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        org: String,
        email: String,
        #[arg(long, value_name = "STABLE_SCOPE")]
        scope: String,
        #[arg(long)]
        role: String,
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<i64>,
    },
    /// Apply an exact previously reviewed invitation plan.
    Apply(HubReviewedApplyArgs),
}

#[derive(Subcommand)]
pub enum HubInvitationCancelCmd {
    /// Create and print an immutable cancellation plan.
    Plan {
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        org: String,
        invitation_id: i64,
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed cancellation plan.
    Apply(HubReviewedApplyArgs),
}

/// Organization membership queries and reviewed mutations.
#[derive(Subcommand)]
pub enum HubOrgMemberCmd {
    /// Show one direct membership grant.
    Show {
        /// Hub connection and authentication.
        #[command(flatten)]
        access: HubAccessArgs,
        /// Principal kind (`user` or `service_account`).
        #[arg(long, value_parser = ["user", "service_account"])]
        principal_kind: String,
        /// Stable principal reference.
        #[arg(long)]
        principal: String,
        /// Canonical instance, organization, or registry scope.
        #[arg(long)]
        scope: String,
    },
    /// Replace a direct membership role through immutable review.
    SetRole {
        #[command(subcommand)]
        command: HubMembershipSetRoleCmd,
    },
    /// Remove a direct membership grant through immutable review.
    Remove {
        #[command(subcommand)]
        command: HubMembershipRemoveCmd,
    },
}

/// Explicit plan/apply flow for replacing a membership role.
#[derive(Subcommand)]
pub enum HubMembershipSetRoleCmd {
    /// Create and print an immutable membership plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Principal kind (`user` or `service_account`).
        #[arg(long, value_parser = ["user", "service_account"])]
        principal_kind: String,
        /// Stable principal reference.
        #[arg(long)]
        principal: String,
        /// Canonical instance, organization, or registry scope.
        #[arg(long)]
        scope: String,
        /// Replacement role.
        #[arg(long, value_parser = ["owner", "admin", "maintainer", "developer", "viewer"])]
        role: String,
        /// Require this exact current membership revision.
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed membership plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for removing a membership grant.
#[derive(Subcommand)]
pub enum HubMembershipRemoveCmd {
    /// Create and print an immutable membership-removal plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Principal kind (`user` or `service_account`).
        #[arg(long, value_parser = ["user", "service_account"])]
        principal_kind: String,
        /// Stable principal reference.
        #[arg(long)]
        principal: String,
        /// Canonical instance, organization, or registry scope.
        #[arg(long)]
        scope: String,
        /// Require this exact current membership revision.
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed membership-removal plan.
    Apply(HubReviewedApplyArgs),
}

/// Scoped access-token inventory and lifecycle commands.
#[derive(Subcommand)]
pub enum HubAccessTokenCmd {
    /// List token metadata without secret material.
    List {
        /// Hub connection and authentication.
        #[command(flatten)]
        access: HubAccessArgs,
        /// Canonical live authorization scope.
        scope: String,
        /// Result pagination.
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Issue a token through immutable review.
    Issue {
        #[command(subcommand)]
        command: HubAccessTokenIssueCmd,
    },
    /// Retire one token generation through immutable review.
    Retire {
        #[command(subcommand)]
        command: HubAccessTokenRetireCmd,
    },
}

/// Explicit plan/apply flow for access-token issuance.
#[derive(Subcommand)]
pub enum HubAccessTokenIssueCmd {
    /// Create and print an immutable token-issuance plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Canonical live authorization scope.
        scope: String,
        /// Token owner (`user:EMAIL` or `service_account:ORG/NAME`).
        #[arg(long)]
        owner: String,
        /// Grant one native permission verb; repeat for multiple permissions.
        #[arg(long = "permission", required = true)]
        permissions: Vec<String>,
        /// Optional token lifetime in seconds.
        #[arg(long)]
        ttl_secs: Option<i64>,
        /// Record a non-secret purpose for this token.
        #[arg(long)]
        comment: Option<String>,
        /// Require this token-owner grant revision when supplied.
        #[arg(long, value_name = "VERSION")]
        if_version: Option<String>,
    },
    /// Apply an exact previously reviewed token-issuance plan.
    Apply(HubReviewedApplyArgs),
}

/// Explicit plan/apply flow for access-token retirement.
#[derive(Subcommand)]
pub enum HubAccessTokenRetireCmd {
    /// Create and print an immutable token-retirement plan.
    Plan {
        /// Plan request identity and Hub access.
        #[command(flatten)]
        request: HubReviewedPlanArgs,
        /// Stable token generation identity.
        token_id: String,
        /// Require this exact current token lifecycle revision.
        #[arg(long, value_name = "VERSION")]
        if_version: String,
    },
    /// Apply an exact previously reviewed token-retirement plan.
    Apply(HubReviewedApplyArgs),
}
