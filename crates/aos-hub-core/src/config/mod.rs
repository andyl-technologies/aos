//! The SQL-backed configuration change-set engine (RFC-0004
//! "Configuration management").
//!
//! Half of the hub's configuration is a git repo (handled by phase 4); the
//! other half — orgs, projects, members, roles, tokens metadata,
//! visibility, and storage bindings — is the SQL system of record. This
//! module is the engine that makes *every* SQL-backed mutation a reviewed,
//! revertible **change-set**, recorded in the append-only
//! `config_changesets` / `config_revisions` / `audit_log` tables (see the
//! [`crate::db`] module docs for the schema).
//!
//! # The change-set lifecycle
//!
//! 1. [`open_draft`] creates a `draft` change-set with a fresh
//!    [`ChangeId`].
//! 2. [`stage`] appends a [`Revision`] — a full before/after JSON snapshot
//!    of one object — for each object the change touches.
//! 3. [`review`] renders the staged revisions as semantic field diffs (the
//!    terraform-plan view), via [`semantic_diff`].
//! 4. [`apply`] runs the caller-supplied live mutation for each revision
//!    inside one transaction, stamps the change-set `applied`, and writes
//!    one [`crate::db::Database::record_audit`] row carrying the
//!    `change_id`.
//!
//! [`change_registry_visibility`] and [`change_membership`] are the real
//! consumers that wire actual hub mutations through this engine, so the
//! audit log carries genuine entries.
//!
//! # Revert
//!
//! [`revert`] implements RFC-0004's **snapshot-targeted forward revert**: it
//! drafts a *new* change-set whose revisions target each original
//! revision's `old_json` (a `create` reverts to a `delete`, a `delete` to a
//! `create`, an `update` to an `update` back to the old snapshot). It does
//! not literally restore rows; the revert draft re-enters [`apply`], so it
//! is re-validated. When an object's current live state has diverged from
//! the original revision's `new_json`, the revision is flagged as a
//! **conflict** in the returned change-set summary rather than silently
//! clobbering the divergence.
//!
//! Security objects are revert-exempt by type (RFC-0004): a `token` revert
//! renders as an "issue replacement" note (a no-op create — a revoked token
//! is never resurrected), and a `membership` delete reverts to an
//! *invitation* rather than a silent re-admit. These are encoded as the
//! revision's `op`/note, never as a live re-grant.
//!
//! # `change_id` format
//!
//! A [`ChangeId`] is a UUID v4 string (reusing the crate's existing `uuid`
//! dependency); change-sets order by `created_at`, so no sortable-id
//! (ULID) generator dependency is taken on. The v4 RNG and the `created_at`
//! clock run on every target — natively, and on the Worker through
//! getrandom's JS backend.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::db::{Database, RevisionRow};
use crate::domain::{Principal, PrincipalKind, Role, Scope};

/// A stable change-set identifier (a UUID v4 string).
///
/// The single join key across `config_changesets`, `config_revisions`, and
/// `audit_log`. Construct fresh ids with [`ChangeId::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeId(pub String);

impl ChangeId {
    /// Returns a fresh random change-set id (a UUID v4).
    #[must_use]
    pub fn new() -> ChangeId {
        ChangeId(uuid::Uuid::new_v4().to_string())
    }

    /// Returns the id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ChangeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ChangeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The operation a [`Revision`] performs on an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOp {
    /// The object did not exist before and exists after.
    Create,
    /// The object existed before and after, with changed fields.
    Update,
    /// The object existed before and is gone after.
    Delete,
}

impl ConfigOp {
    /// Returns the snake-case wire name stored in `config_revisions.op`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigOp::Create => "create",
            ConfigOp::Update => "update",
            ConfigOp::Delete => "delete",
        }
    }

    /// Parses an op from its wire name, or `None` for an unknown string.
    #[must_use]
    pub fn parse(s: &str) -> Option<ConfigOp> {
        match s {
            "create" => Some(ConfigOp::Create),
            "update" => Some(ConfigOp::Update),
            "delete" => Some(ConfigOp::Delete),
            _ => None,
        }
    }
}

/// One staged operation on one object within a change-set.
///
/// `old_json`/`new_json` are full object snapshots, not field deltas;
/// [`semantic_diff`] derives the field-level diff at review time.
#[derive(Debug, Clone)]
pub struct Revision {
    /// The object's type (e.g. `registry`, `membership`, `token`).
    pub object_type: String,
    /// The object's stable id within its type.
    pub object_id: String,
    /// The operation this revision performs.
    pub op: ConfigOp,
    /// Full object snapshot before the change (`None` for a create).
    pub old_json: Option<Value>,
    /// Full object snapshot after the change (`None` for a delete).
    pub new_json: Option<Value>,
    /// Ordinal of this revision within its change-set, from `0`.
    pub seq: i64,
}

impl Revision {
    /// Builds a domain [`Revision`] from a stored [`RevisionRow`].
    ///
    /// JSON snapshot columns that are present but unparseable are treated as
    /// absent (`None`) — a stored snapshot is engine-written and should
    /// always parse, but a malformed value must not panic the review path.
    fn from_row(row: &RevisionRow) -> Revision {
        Revision {
            object_type: row.object_type.clone(),
            object_id: row.object_id.clone(),
            op: ConfigOp::parse(&row.op).unwrap_or(ConfigOp::Update),
            old_json: row
                .old_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            new_json: row
                .new_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            seq: row.seq,
        }
    }
}

/// One field-level difference between two object snapshots.
///
/// A `None` `old` means the field was added; a `None` `new` means it was
/// removed. Values are rendered as strings: scalars verbatim, nested
/// objects/arrays as compact JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDiff {
    /// The field name (a JSON object key).
    pub field: String,
    /// The old value, or `None` when the field was added.
    pub old: Option<String>,
    /// The new value, or `None` when the field was removed.
    pub new: Option<String>,
}

/// A whole change-set, materialized from storage with its revisions.
#[derive(Debug, Clone)]
pub struct Changeset {
    /// The change-set id.
    pub change_id: ChangeId,
    /// Human label of the actor that opened it.
    pub actor_label: String,
    /// Scope path the change-set targets.
    pub scope: String,
    /// Lifecycle status: `draft`, `applied`, or `reverted`.
    pub status: String,
    /// One-line human summary.
    pub summary: Option<String>,
    /// Unix time the change-set was created.
    pub created_at: i64,
    /// Unix time the change-set was applied, or `None`.
    pub applied_at: Option<i64>,
    /// The change-set's revisions, in `seq` order.
    pub revisions: Vec<Revision>,
}

/// Renders a string for one JSON value: scalars verbatim, nested values as
/// compact JSON.
fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        // Nested objects/arrays render as compact JSON (RFC-0004: field
        // diffs are semantic; nested structure is shown as a JSON string).
        other => other.to_string(),
    }
}

/// Computes the semantic field-level diff between two object snapshots.
///
/// Compares two JSON objects field by field, emitting a [`FieldDiff`] for
/// every key whose rendered value changed, was added (present only in
/// `new`), or was removed (present only in `old`). Unchanged fields are
/// omitted. Non-object inputs (a scalar or array snapshot, or a `null`
/// standing in for an absent side) are treated as the empty object, so a
/// create (`old = null`) lists every `new` field as an addition and a delete
/// lists every `old` field as a removal. Output is ordered by field name.
///
/// # Examples
///
/// ```
/// use aos_hub_core::config::semantic_diff;
/// use serde_json::json;
///
/// let diffs = semantic_diff(
///     &json!({"visibility": "public", "name": "cdn"}),
///     &json!({"visibility": "private", "name": "cdn"}),
/// );
/// assert_eq!(diffs.len(), 1);
/// assert_eq!(diffs[0].field, "visibility");
/// assert_eq!(diffs[0].old.as_deref(), Some("public"));
/// assert_eq!(diffs[0].new.as_deref(), Some("private"));
/// ```
#[must_use]
pub fn semantic_diff(old: &Value, new: &Value) -> Vec<FieldDiff> {
    let empty = serde_json::Map::new();
    let old_map = old.as_object().unwrap_or(&empty);
    let new_map = new.as_object().unwrap_or(&empty);

    let mut keys: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    keys.extend(old_map.keys());
    keys.extend(new_map.keys());

    let mut diffs = Vec::new();
    for key in keys {
        let old_v = old_map.get(key);
        let new_v = new_map.get(key);
        match (old_v, new_v) {
            (Some(o), Some(n)) if o == n => {}
            (o, n) => diffs.push(FieldDiff {
                field: key.clone(),
                old: o.map(render_value),
                new: n.map(render_value),
            }),
        }
    }
    diffs
}

/// The wire `actor_kind`/`actor_id` for a [`Principal`].
fn principal_actor(principal: &Principal) -> (&'static str, Option<i64>) {
    (principal.kind.as_str(), Some(principal.id))
}

/// Opens a fresh `draft` change-set owned by `actor` at `scope`.
///
/// `summary` is the one-line human description shown in the review screen.
/// Returns the new [`ChangeId`]; stage revisions onto it with [`stage`] and
/// commit them with [`apply`].
///
/// # Errors
///
/// Returns an error on database failure (including a change-id collision,
/// which is astronomically unlikely for a UUID v4).
pub async fn open_draft(
    db: &Database,
    actor: &Principal,
    actor_label: &str,
    scope: &Scope,
    summary: &str,
) -> Result<ChangeId> {
    let change_id = ChangeId::new();
    let (kind, id) = principal_actor(actor);
    db.create_changeset(
        change_id.as_str(),
        kind,
        id,
        actor_label,
        scope.as_str(),
        Some(summary),
    )
    .await?;
    Ok(change_id)
}

/// Appends a revision to a draft change-set.
///
/// `op` is the operation, `old`/`new` the full before/after object
/// snapshots (pass `None` for the absent side of a create or delete). The
/// revision's `seq` is assigned automatically as the next ordinal.
///
/// # Errors
///
/// Returns an error on database failure, including a foreign-key violation
/// when `change_id` does not name an existing change-set.
pub async fn stage(
    db: &Database,
    change_id: &ChangeId,
    object_type: &str,
    object_id: &str,
    op: ConfigOp,
    old: Option<Value>,
    new: Option<Value>,
) -> Result<()> {
    let old_json = old.map(|v| v.to_string());
    let new_json = new.map(|v| v.to_string());
    db.add_revision(
        change_id.as_str(),
        object_type,
        object_id,
        op.as_str(),
        old_json.as_deref(),
        new_json.as_deref(),
    )
    .await?;
    Ok(())
}

/// Loads a change-set's revisions with their semantic field diffs.
///
/// This is the terraform-plan review view: each revision is paired with the
/// [`semantic_diff`] of its `old_json` → `new_json` snapshots (treating an
/// absent side as the empty object). Revisions come back in `seq` order.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn review(
    db: &Database,
    change_id: &ChangeId,
) -> Result<Vec<(Revision, Vec<FieldDiff>)>> {
    let rows = db.list_revisions(change_id.as_str()).await?;
    Ok(rows
        .iter()
        .map(|row| {
            let revision = Revision::from_row(row);
            let old = revision.old_json.clone().unwrap_or(Value::Null);
            let new = revision.new_json.clone().unwrap_or(Value::Null);
            let diffs = semantic_diff(&old, &new);
            (revision, diffs)
        })
        .collect())
}

/// Applies a change-set atomically, then records one audit row.
///
/// Runs `apply_fn` for each revision in `seq` order inside a transaction
/// (see [`Database::apply_changeset`](crate::db::Database::apply_changeset)),
/// stamps the change-set `applied`, and writes exactly one audit-log row
/// tied to the `change_id`. `apply_fn` is the caller's live-object
/// mutation; the engine supplies each [`Revision`] in turn.
///
/// The audit row's `action`, `actor_label`, and `detail` are taken from the
/// stored change-set so the audit feed is self-describing.
///
/// # Errors
///
/// Returns an error if the change-set is unknown, if any `apply_fn` call
/// fails (the transaction rolls back), or on database failure.
pub async fn apply<F, Fut>(
    db: &Database,
    change_id: &ChangeId,
    action: &str,
    mut apply_fn: F,
) -> Result<()>
where
    F: FnMut(&Revision) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let summary = db
        .changeset(change_id.as_str())
        .await?
        .with_context(|| format!("no change-set {change_id}"))?;
    for row in db.list_revisions(change_id.as_str()).await? {
        let revision = Revision::from_row(&row);
        apply_fn(&revision).await?;
    }
    db.mark_changeset_applied(change_id.as_str()).await?;
    db.record_audit(
        &summary.actor_kind,
        summary.actor_id,
        &summary.actor_label,
        action,
        &summary.scope,
        Some(change_id.as_str()),
        None,
        None,
        summary.summary.as_deref(),
    )
    .await?;
    Ok(())
}

/// The result of drafting a [`revert`]: the new change-set plus any
/// conflicts detected against current live state.
#[derive(Debug, Clone)]
pub struct RevertDraft {
    /// The newly drafted revert change-set id (in `draft` status).
    pub change_id: ChangeId,
    /// Human-readable conflict notes: revisions whose live object had
    /// diverged from the original change-set's recorded `new_json`. Empty
    /// when the revert applies cleanly.
    pub conflicts: Vec<String>,
}

/// Drafts a snapshot-targeted forward revert of an applied change-set.
///
/// Builds a *new* `draft` change-set whose revisions undo the original's
/// (RFC-0004): a `create` reverts to a `delete`, a `delete` to a `create`
/// of the old snapshot, and an `update` to an `update` back to `old_json`.
/// The original change-set's `reverted_by_change_id` is stamped to the new
/// id. The revert is *not* applied here — the caller applies the returned
/// draft through [`apply`] (so it re-enters validation/authz).
///
/// **Conflict detection.** For each original revision, if the object's
/// current live state (passed via `live_state(object_type, object_id)`)
/// differs from the revision's recorded `new_json`, a human-readable note is
/// added to [`RevertDraft::conflicts`] — the divergence is surfaced, never
/// silently clobbered. The revert revision is still staged so a reviewer can
/// decide; conflicts are advisory.
///
/// **Security-object exemptions.** A `token` revision reverts to a no-op
/// `create` carrying an "issue replacement" note (a revoked token is never
/// resurrected), and a `membership` revision whose original op deleted the
/// grant reverts to a `create` of an *invitation* object rather than the
/// membership itself — see the [module docs](self).
///
/// # Errors
///
/// Returns an error when `change_id` is unknown, and on database failure.
pub async fn revert<S, Fut>(
    db: &Database,
    original: &ChangeId,
    actor: &Principal,
    actor_label: &str,
    mut live_state: S,
) -> Result<RevertDraft>
where
    S: FnMut(&str, &str) -> Fut,
    Fut: std::future::Future<Output = Option<Value>>,
{
    let original_cs = db
        .changeset(original.as_str())
        .await?
        .with_context(|| format!("no change-set {original}"))?;
    let rows = db.list_revisions(original.as_str()).await?;
    if rows.is_empty() {
        bail!("change-set {original} has no revisions to revert");
    }

    let scope = Scope::parse(&original_cs.scope);
    let summary = format!("revert of {original}");
    let revert_id = open_draft(db, actor, actor_label, &scope, &summary).await?;

    let mut conflicts = Vec::new();
    for row in &rows {
        let revision = Revision::from_row(row);

        // Conflict detection: the live object should still match what the
        // original change-set last wrote (its new_json). A divergence means
        // someone changed the object since; flag it.
        if let Some(recorded_new) = &revision.new_json {
            let live = live_state(&revision.object_type, &revision.object_id).await;
            let matches = match &live {
                Some(live) => live == recorded_new,
                // A delete revision recorded new_json = None; for non-delete
                // ops a missing live object is itself a divergence.
                None => false,
            };
            if !matches {
                conflicts.push(format!(
                    "{} '{}' has changed since the original change-set; revert may not apply cleanly",
                    revision.object_type, revision.object_id
                ));
            }
        }

        match revision.object_type.as_str() {
            // Security exemption: a token is never reverted into a live
            // credential. Render the revert as a no-op create carrying an
            // "issue replacement" note (RFC-0004).
            "token" => {
                let note = serde_json::json!({
                    "note": "issue replacement token",
                    "original_token": revision.object_id,
                });
                stage(
                    db,
                    &revert_id,
                    "token",
                    &revision.object_id,
                    ConfigOp::Create,
                    None,
                    Some(note),
                )
                .await?;
            }
            // Security exemption: a membership removal reverts to an
            // *invitation*, not a silent re-admit (RFC-0004).
            "membership" if revision.op == ConfigOp::Delete => {
                let invite = invitation_from_membership(revision.old_json.as_ref());
                stage(
                    db,
                    &revert_id,
                    "invitation",
                    &revision.object_id,
                    ConfigOp::Create,
                    None,
                    Some(invite),
                )
                .await?;
            }
            // General case: forward-revert by swapping snapshots and op.
            _ => {
                let (op, old, new) = match revision.op {
                    ConfigOp::Create => (ConfigOp::Delete, revision.new_json.clone(), None),
                    ConfigOp::Delete => (ConfigOp::Create, None, revision.old_json.clone()),
                    ConfigOp::Update => (
                        ConfigOp::Update,
                        revision.new_json.clone(),
                        revision.old_json.clone(),
                    ),
                };
                stage(
                    db,
                    &revert_id,
                    &revision.object_type,
                    &revision.object_id,
                    op,
                    old,
                    new,
                )
                .await?;
            }
        }
    }

    // Mark the original reverted by the new change-set.
    db.set_changeset_status(
        original.as_str(),
        "reverted",
        None,
        Some(revert_id.as_str()),
    )
    .await?;

    Ok(RevertDraft {
        change_id: revert_id,
        conflicts,
    })
}

/// Builds an invitation snapshot from a reverted membership's old snapshot.
///
/// Carries the scope/role the membership granted so a reviewer applies an
/// invitation rather than a silent re-admit.
fn invitation_from_membership(old: Option<&Value>) -> Value {
    let scope = old
        .and_then(|v| v.get("scope"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let role = old
        .and_then(|v| v.get("role"))
        .and_then(|v| v.as_str())
        .unwrap_or("viewer");
    let email = old
        .and_then(|v| v.get("email"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    serde_json::json!({
        "note": "re-invite (membership revert never silently re-admits)",
        "scope": scope,
        "role": role,
        "email": email,
    })
}

// -- real consumers: mutations that flow through the engine -----------------

/// Changes a registry's visibility through a one-revision change-set.
///
/// Opens a draft, stages a single `update` revision recording the old and
/// new visibility, and applies it — the apply step calls
/// [`Database::set_registry_visibility`](crate::db::Database::set_registry_visibility)
/// to mutate the live registry, and one audit row is written. Returns the
/// applied change-set's id.
///
/// This is a real engine consumer (not a demo): the visibility flip is the
/// confirmation-gated change-set the RFC's access matrix requires, and it
/// gives the audit log a genuine entry.
///
/// # Errors
///
/// Returns an error when `registry_id` names no registry, and on database
/// failure (the change-set is rolled back on a failed apply).
pub async fn change_registry_visibility(
    db: &Database,
    actor: &Principal,
    actor_label: &str,
    registry_id: i64,
    new_visibility: &str,
) -> Result<ChangeId> {
    // Resolve the registry to read its slug (the object id / scope) and old
    // visibility.
    let record = registry_record(db, registry_id).await?;
    let old_visibility = record.visibility.clone();
    let scope = Scope::parse(&record.slug);
    let summary = format!(
        "set {} visibility {old_visibility} -> {new_visibility}",
        record.slug
    );
    let change_id = open_draft(db, actor, actor_label, &scope, &summary).await?;
    stage(
        db,
        &change_id,
        "registry",
        &record.slug,
        ConfigOp::Update,
        Some(serde_json::json!({ "visibility": old_visibility.clone() })),
        Some(serde_json::json!({ "visibility": new_visibility })),
    )
    .await?;
    apply(db, &change_id, "registry.visibility", |_rev| async move {
        db.set_registry_visibility(registry_id, new_visibility)
            .await
    })
    .await?;

    // Notify subscribers of the visibility flip. Additive and non-fatal: the
    // change is already applied and audited; a webhook failure must not undo it.
    if let Some(org_id) = record.org_id {
        // Cross-platform clock — `SystemTime::now()` panics on the Worker (wasm32).
        let now = crate::clock::now_unix_secs();
        let event = crate::webhook::WebhookEvent::VisibilityChanged {
            registry: record.slug.clone(),
            old: old_visibility,
            new: new_visibility.to_string(),
            at: now,
        };
        if let Err(err) = crate::webhook::dispatch(db, org_id, &event).await {
            tracing::warn!(slug = %record.slug, error = %format!("{err:#}"), "dispatching registry.visibility_changed webhook");
        }
    }
    Ok(change_id)
}

/// Changes a registry's crawl policy through a one-revision change-set.
///
/// Opens a draft, stages a single `update` revision recording the old and new
/// crawl policy, and applies it — the apply step calls
/// [`Database::set_registry_crawl_policy`](crate::db::Database::set_registry_crawl_policy)
/// to mutate the live registry, and one audit row is written. Returns the
/// applied change-set's id.
///
/// Mirrors [`change_registry_visibility`]: the crawl-policy flip is a
/// confirmation-gated, audited change so the RFC's access matrix and audit feed
/// cover it. `new_policy` is the wire string of a
/// [`CrawlPolicy`](crate::crawl::CrawlPolicy); the caller validates it before
/// calling.
///
/// # Errors
///
/// Returns an error when `registry_id` names no registry, and on database
/// failure (the change-set is rolled back on a failed apply).
pub async fn change_registry_crawl_policy(
    db: &Database,
    actor: &Principal,
    actor_label: &str,
    registry_id: i64,
    new_policy: &str,
) -> Result<ChangeId> {
    let record = registry_record(db, registry_id).await?;
    let old_policy = record.crawl_policy.clone();
    let slug = record.slug.clone();
    let scope = Scope::parse(&slug);
    let summary = format!("set {slug} crawl policy {old_policy} -> {new_policy}");
    let change_id = open_draft(db, actor, actor_label, &scope, &summary).await?;
    stage(
        db,
        &change_id,
        "registry",
        &slug,
        ConfigOp::Update,
        Some(serde_json::json!({ "crawl_policy": old_policy })),
        Some(serde_json::json!({ "crawl_policy": new_policy })),
    )
    .await?;
    apply(db, &change_id, "registry.crawl_policy", move |_rev| {
        let slug = slug.clone();
        async move { db.set_registry_crawl_policy(&slug, new_policy).await }
    })
    .await?;
    Ok(change_id)
}

/// Whether a [`change_membership`] grants or revokes a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipChange {
    /// Grant (or update) the principal's role at the scope.
    Grant,
    /// Revoke the principal's grant at the scope.
    Revoke,
}

/// Returns the highest role rank `actor` effectively holds over `scope`.
///
/// A grant inherits downward (a grant at an ancestor scope covers `scope`),
/// so this scans every `(grant_scope, role)` the actor holds and takes the
/// maximum [`Role::rank`] among those whose `grant_scope` contains `scope`.
/// Returns `None` when the actor holds no covering grant.
///
/// # Errors
///
/// Returns an error on database failure.
async fn actor_max_rank(db: &Database, actor: &Principal, scope: &Scope) -> Result<Option<u8>> {
    Ok(db
        .effective_scopes(*actor)
        .await?
        .into_iter()
        .filter(|(grant_scope, _)| grant_scope.contains(scope))
        .map(|(_, role)| role.rank())
        .max())
}

/// Grants or revokes a membership through a one-revision change-set.
///
/// Opens a draft, stages a `create`/`delete` revision snapshotting the
/// `(principal, scope, role)` grant, and applies it — the apply step calls
/// the live `grant_membership`/`revoke_membership` setter and one audit row
/// is written. The revision's `object_id` is
/// `{principal_kind}:{principal_id}@{scope}`. Returns the change-set id.
///
/// A revoke records the old grant's snapshot as `old_json`, so a later
/// [`revert`] of the revoke produces an *invitation* (the membership
/// security exemption), never a silent re-grant.
///
/// # Privilege ceiling
///
/// A `Grant` is refused (returns an error) when it would let `actor` confer
/// authority it does not itself hold (H1, vertical privilege escalation).
/// Concretely, over the target `scope`:
///
/// - the granted role's rank may not exceed the actor's own highest rank;
/// - only an actor who is [`Role::Owner`] over the scope may create or modify
///   an `Owner` grant (an instance-root owner qualifies via inheritance);
/// - an actor may not **raise its own** role above its current rank
///   (self-promotion), though lateral grants at or below its rank are allowed.
///
/// A `Revoke` is not subject to the ceiling.
///
/// # Errors
///
/// Returns an error on database failure, on a privilege-ceiling violation, or
/// if the change-set is rolled back on a failed apply.
pub async fn change_membership(
    db: &Database,
    actor: &Principal,
    actor_label: &str,
    change: MembershipChange,
    principal: &Principal,
    scope: &Scope,
    role: Role,
) -> Result<ChangeId> {
    if change == MembershipChange::Grant {
        let actor_rank = actor_max_rank(db, actor, scope).await?.unwrap_or(0);
        // The granted role may not exceed the actor's own authority.
        if role.rank() > actor_rank {
            bail!(
                "insufficient privilege to grant '{}' at scope '{}'",
                role.as_str(),
                scope.as_str()
            );
        }
        // Owner grants are owner-only (an instance-root owner inherits in).
        if role == Role::Owner && actor_rank < Role::Owner.rank() {
            bail!(
                "only an owner may grant 'owner' at scope '{}'",
                scope.as_str()
            );
        }
        // A principal may not raise its own role above what it already holds.
        if actor == principal && role.rank() > actor_rank {
            bail!(
                "a principal may not promote itself to '{}' at scope '{}'",
                role.as_str(),
                scope.as_str()
            );
        }
    }
    let object_id = format!(
        "{}:{}@{}",
        principal.kind.as_str(),
        principal.id,
        scope.as_str()
    );
    let snapshot = serde_json::json!({
        "principal_kind": principal.kind.as_str(),
        "principal_id": principal.id,
        "scope": scope.as_str(),
        "role": role.as_str(),
    });
    let (op, old, new, action, verb) = match change {
        MembershipChange::Grant => (
            ConfigOp::Create,
            None,
            Some(snapshot),
            "membership.grant",
            "grant",
        ),
        MembershipChange::Revoke => (
            ConfigOp::Delete,
            Some(snapshot),
            None,
            "membership.revoke",
            "revoke",
        ),
    };
    let summary = format!(
        "{verb} {} for {}:{} at {}",
        role.as_str(),
        principal.kind.as_str(),
        principal.id,
        scope.as_str()
    );
    let change_id = open_draft(db, actor, actor_label, scope, &summary).await?;
    stage(db, &change_id, "membership", &object_id, op, old, new).await?;

    let principal = *principal;
    let scope_str = scope.as_str().to_string();
    let role_str = role.as_str().to_string();
    // Route the live write through the owner-safe variants so the surviving
    // owner count is read and re-checked *inside the write's transaction*: a
    // grant/revoke that would leave the scope ownerless is rolled back with a
    // `LastOwnerError`, closing the check-then-act race the handler's
    // pre-check alone cannot (the pre-check still runs to render a friendly
    // 409 on the common, uncontended path).
    apply(db, &change_id, action, move |_rev| {
        let scope_str = scope_str.clone();
        let role_str = role_str.clone();
        async move {
            match change {
                MembershipChange::Grant => {
                    db.set_membership_role_owner_safe(
                        principal.kind.as_str(),
                        principal.id,
                        &scope_str,
                        &role_str,
                    )
                    .await
                }
                MembershipChange::Revoke => {
                    db.revoke_membership_owner_safe(
                        principal.kind.as_str(),
                        principal.id,
                        &scope_str,
                    )
                    .await
                }
            }
        }
    })
    .await?;
    Ok(change_id)
}

/// Prepares a channel-advance as a draft change-set for client-side signing.
///
/// Channel advances are signed-tag operations, which a commit-style change
/// request cannot carry (RFC-0004 "Configuration management"). For a BYO-key
/// org the hub records the exact intent — channel, target release, partition
/// count — as a **prepared operation**: a draft change-set with a single
/// `channel_advance` revision whose `new_json` is the intent. The maintainer
/// executes `apr channel advance --from-hub <change_id>` to fetch, verify,
/// sign the partition tags locally, and push. The preparation is audited.
///
/// Returns the new [`ChangeId`]; the change-set stays in `draft` status (it
/// is never applied server-side without a hosted key).
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn prepare_channel_advance(
    db: &Database,
    actor: &Principal,
    actor_label: &str,
    registry_slug: &str,
    channel: &str,
    release: &str,
    partitions: u16,
) -> Result<ChangeId> {
    let scope = Scope::parse(registry_slug);
    let summary = format!("advance {channel} to {release} ({partitions} partitions)");
    let change_id = open_draft(db, actor, actor_label, &scope, &summary).await?;
    let object_id = format!("{registry_slug}:{channel}");
    let intent = serde_json::json!({
        "registry": registry_slug,
        "channel": channel,
        "release": release,
        "partitions": partitions,
    });
    stage(
        db,
        &change_id,
        "channel_advance",
        &object_id,
        ConfigOp::Create,
        None,
        Some(intent),
    )
    .await?;
    // Audit the preparation directly: there is no live mutation to apply
    // (signing is client-side), so this does not flow through `apply`.
    let (kind, id) = principal_actor(actor);
    db.record_audit(
        kind,
        id,
        actor_label,
        "channel.advance.prepared",
        scope.as_str(),
        Some(change_id.as_str()),
        None,
        None,
        Some(&summary),
    )
    .await?;
    Ok(change_id)
}

/// The `apr channel advance --from-hub` command a prepared advance renders.
///
/// The maintainer runs it locally to fetch the recorded intent, verify it
/// matches what was reviewed, sign the partition tags, and push.
#[must_use]
pub fn advance_command(registry_url: &str, change_id: &ChangeId) -> String {
    format!(
        "apr channel advance --registry {} --from-hub {change_id}",
        registry_url.trim_end_matches('/'),
    )
}

/// Resolves a registry record by id (slug + visibility), or an error when
/// absent.
async fn registry_record(db: &Database, registry_id: i64) -> Result<crate::db::RegistryRecord> {
    for record in db.list_registries().await? {
        if record.id == registry_id {
            return Ok(record);
        }
    }
    bail!("no registry with id {registry_id}")
}

/// Maps a JWT/owner principal kind string to a [`Principal`], if known.
///
/// A convenience for callers (the RPC plane) that hold an `(owner_kind,
/// owner_id)` pair and need a typed principal for the engine.
#[must_use]
pub fn principal_from_owner(owner_kind: &str, owner_id: i64) -> Option<Principal> {
    PrincipalKind::parse(owner_kind).map(|kind| Principal { kind, id: owner_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn change_id_is_unique() {
        assert_ne!(ChangeId::new(), ChangeId::new());
    }

    #[test]
    fn semantic_diff_changed_added_removed() {
        let diffs = semantic_diff(
            &json!({"a": "1", "b": "2", "gone": "x"}),
            &json!({"a": "1", "b": "3", "added": "y"}),
        );
        // a is unchanged and omitted; b changed; added is new; gone removed.
        assert_eq!(diffs.len(), 3);
        let by_field: std::collections::HashMap<_, _> =
            diffs.iter().map(|d| (d.field.clone(), d.clone())).collect();
        assert_eq!(by_field["b"].old.as_deref(), Some("2"));
        assert_eq!(by_field["b"].new.as_deref(), Some("3"));
        assert_eq!(by_field["added"].old, None);
        assert_eq!(by_field["added"].new.as_deref(), Some("y"));
        assert_eq!(by_field["gone"].old.as_deref(), Some("x"));
        assert_eq!(by_field["gone"].new, None);
    }

    #[test]
    fn semantic_diff_renders_nested_as_json() {
        let diffs = semantic_diff(&json!({"caches": ["a"]}), &json!({"caches": ["a", "b"]}));
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field, "caches");
        assert_eq!(diffs[0].old.as_deref(), Some(r#"["a"]"#));
        assert_eq!(diffs[0].new.as_deref(), Some(r#"["a","b"]"#));
    }
}
