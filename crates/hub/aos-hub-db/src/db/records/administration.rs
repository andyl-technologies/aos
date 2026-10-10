//! Administration records returned by typed Hub persistence operations.

use super::*;

/// Marker error: a membership mutation was refused because it would leave an
/// org with zero owners.
///
/// Raised when the write-time guard in [`Database::revoke_membership_owner_safe`]
/// or [`Database::set_membership_role_owner_safe`] refuses the mutation, so a
/// caller can classify the failure through `anyhow` context chains via
/// [`is_last_owner_error`] and surface it as a `409 Conflict` rather than a
/// generic `500`.
#[derive(Debug, thiserror::Error)]
#[error("refusing to leave org scope '{0}' without an owner")]
pub struct LastOwnerError(pub String);

/// The editable instance-wide settings bundle (RFC-0004 console).
///
/// Every field is persisted in the `instance_config` key/value table and is
/// configurable via the WebUI, the API, and the CLI; the deploy seeds initial
/// values but never owns them thereafter. Optional fields are `None`/empty when
/// unset and fall back to a documented default. Loaded by
/// [`Database::instance_settings`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct InstanceSettings {
    /// Operator-chosen site title shown in the masthead and page titles; `None`
    /// renders an empty title.
    pub site_title: Option<String>,
    /// Short tagline shown under the brand on the home page.
    pub tagline: Option<String>,
    /// A global announcement banner rendered on every console page; `None` for
    /// no banner.
    pub announcement: Option<String>,
    /// Terms-of-service URL for the footer.
    pub tos_url: Option<String>,
    /// Privacy-policy URL for the footer.
    pub privacy_url: Option<String>,
    /// Support/contact URL for the footer.
    pub support_url: Option<String>,
    /// Who may create organizations (also exposed standalone as
    /// [`Database::signup_policy`]).
    pub signup_policy: SignupPolicy,
    /// Lowercased email-domain allowlist for signup; empty allows any domain.
    pub signup_domains: Vec<String>,
    /// Whether local password login is offered (else SSO/magic-link only).
    /// Defaults to `true`.
    pub password_login: bool,
    /// Whether the binary-caches surface (the masthead caches tab, the global
    /// caches list, and direct cache pages) is visible to logged-out visitors.
    /// Defaults to `false` — caches are a signed-in-only surface.
    pub caches_public: bool,
    /// Session absolute lifetime in seconds; `None` uses the built-in default.
    pub session_lifetime_secs: Option<i64>,
    /// Default `robots.txt` crawl policy new registries inherit
    /// (`allow_all`/`allow_no_ai`/`deny_all`). Defaults to `allow_all`.
    pub default_crawl_policy: String,
    /// Maximum surface upload size in bytes; `None` uses the built-in default.
    pub max_upload_bytes: Option<i64>,
}

/// One append-only audit-log row (system-of-record).
///
/// Records a single mutating action: the actor, the action verb, the
/// targeted scope, the optional change-set join key, and the optional
/// cryptographic-history cross-references for surface-touching operations.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// Row id (monotonic; orders entries within a scope).
    pub id: i64,
    /// The change-set this entry ties to, or `None` when not change-set
    /// driven.
    pub change_id: Option<String>,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Human label of the actor (email, `sa:org/name`, key fingerprint, or
    /// `system`).
    pub actor_label: String,
    /// The action verb (e.g. `registry.visibility`, `membership.grant`).
    pub action: String,
    /// Scope path the action targeted.
    pub scope: String,
    /// Resulting git commit hash for surface-touching ops, when applicable.
    pub result_commit: Option<String>,
    /// Resulting git tag hash for surface-touching ops, when applicable.
    pub result_tag: Option<String>,
    /// Free-form detail (often a compact JSON object).
    pub detail: Option<String>,
    /// Unix time the entry was recorded.
    pub created_at: i64,
}

/// One configuration change-set summary row (system-of-record).
#[derive(Debug, Clone)]
pub struct ChangesetRow {
    /// Stable change-set id (UUID v4); the audit/revision join key.
    pub change_id: String,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Owning principal's row id, when applicable.
    pub actor_id: Option<i64>,
    /// Human label of the actor that opened the change-set.
    pub actor_label: String,
    /// Scope path the change-set targets.
    pub scope: String,
    /// Lifecycle status: `draft`, `applied`, or `reverted`.
    pub status: String,
    /// One-line human summary.
    pub summary: Option<String>,
    /// Unix time the change-set was created.
    pub created_at: i64,
    /// Unix time the change-set was applied, or `None` when never applied.
    pub applied_at: Option<i64>,
    /// The change-set that reverted this one, or `None`.
    pub reverted_by_change_id: Option<String>,
    /// Draft ref the hub wrote for a git-backed change request
    /// (`refs/hub/changes/<change_id>`), or `None` for a SQL-only change-set.
    pub git_ref: Option<String>,
    /// Signed draft-commit oid the [`Self::git_ref`] points at, or `None` for
    /// a SQL-only change-set.
    pub git_commit: Option<String>,
    /// Human title the proposer gave the change request, or `None` for change-
    /// sets opened before the review surface existed (fall back to
    /// [`Self::summary`]).
    pub title: Option<String>,
    /// Optional free-text description the proposer wrote, or `None`.
    pub body: Option<String>,
    /// Unix time an open draft was *withdrawn* (closed without merging), or
    /// `None` when open or reopened. Orthogonal to [`Self::status`]: a closed
    /// change-set keeps `status = 'draft'` so the indexer can still flip it to
    /// `applied` if its ref is later promoted.
    pub closed_at: Option<i64>,
}

/// One discussion comment on a change request (system-of-record row).
#[derive(Debug, Clone)]
pub struct ChangeCommentRow {
    /// Row id (monotonic; the timeline orders by it).
    pub id: i64,
    /// The change-set this comment belongs to.
    pub change_id: String,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Owning principal's row id, when applicable.
    pub actor_id: Option<i64>,
    /// Human label of the comment's author.
    pub actor_label: String,
    /// The comment text (plain, rendered escaped).
    pub body: String,
    /// Unix time the comment was posted.
    pub created_at: i64,
}

/// One advisory review on a change request (system-of-record row).
///
/// Reviews carry no enforcement: promotion is via `apr change merge`, so an
/// `approve` unlocks nothing. They are recorded for the conversation timeline.
#[derive(Debug, Clone)]
pub struct ChangeReviewRow {
    /// Row id (monotonic; the timeline orders by it).
    pub id: i64,
    /// The change-set this review belongs to.
    pub change_id: String,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Owning principal's row id, when applicable.
    pub actor_id: Option<i64>,
    /// Human label of the reviewer.
    pub actor_label: String,
    /// The verdict: `approve` or `request_changes`.
    pub verdict: String,
    /// Optional review note, or `None`.
    pub body: Option<String>,
    /// Unix time the review was submitted.
    pub created_at: i64,
}

/// One revision row within a change-set (system-of-record).
///
/// A revision is a staged operation on one object, carrying the full
/// before/after JSON snapshots that diffs and reverts are computed from.
/// Rows are never updated once written.
#[derive(Debug, Clone)]
pub struct RevisionRow {
    /// Row id.
    pub id: i64,
    /// The change-set this revision belongs to.
    pub change_id: String,
    /// The object's type (e.g. `registry`, `membership`, `token`).
    pub object_type: String,
    /// The object's stable id within its type.
    pub object_id: String,
    /// The operation: `create`, `update`, or `delete`.
    pub op: String,
    /// Full object snapshot before the change (`None` for a create).
    pub old_json: Option<String>,
    /// Full object snapshot after the change (`None` for a delete).
    pub new_json: Option<String>,
    /// Ordinal of this revision within its change-set, from `0`.
    pub seq: i64,
}
