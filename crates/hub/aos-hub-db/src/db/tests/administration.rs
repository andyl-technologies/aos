//! Administration regression cases and contract checks.

use super::*;

#[tokio::test]
async fn deployment_default_records_one_valid_write_revision() {
    let db = Database::open_in_memory().await.unwrap();
    let first = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_model::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let second = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_model::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    assert_eq!(first.id, second.id);

    let credential = db
        .current_binding_credential(first.id, "write")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.validation_state, "valid");
    assert_eq!(
        credential.secret_version_ref,
        "worker://aos-hub/default-storage/v1"
    );
    let state = db.binding_write_state(first.id).await.unwrap().unwrap();
    let revision = db
        .binding_write_revision(first.id, state.current_write_revision.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(revision.writes_supported);
    assert!(!revision.conditional_writes_supported);
    assert_eq!(revision.write_credential_generation, credential.generation);

    let count: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM binding_write_revisions
                 WHERE binding_id = ?1",
            &vals![first.id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(count, 1);
    assert!(db
        .ensure_instance_default_binding("deployment_r2", None, Some("different"))
        .await
        .is_err());
}

#[tokio::test]
async fn audit_and_changeset_scope_containment() {
    let db = Database::open_in_memory().await.unwrap();
    let acme_id = db.create_org("acme", "Acme").await.unwrap();
    let acme_scope = db.org_by_id(acme_id).await.unwrap().unwrap().stable_id;
    db.create_project(acme_id, "infra/prod", "Production")
        .await
        .unwrap();
    let project_scope = db.list_projects(acme_id).await.unwrap()[0]
        .scope_key
        .clone();
    let globex_id = db.create_org("globex", "Globex").await.unwrap();
    let globex_scope = db.org_by_id(globex_id).await.unwrap().unwrap().stable_id;
    db.record_audit(
        "system",
        None,
        "system",
        "a",
        &project_scope,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    db.record_audit(
        "system",
        None,
        "system",
        "b",
        &globex_scope,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    // An org-scoped query surfaces the registry-scoped row but not the
    // sibling org's.
    let rows = db.list_audit(&acme_scope).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "a");
    // The root scope lists everything, newest first.
    let all = db.list_audit("instance").await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].action, "b", "newest first");
}

#[tokio::test]
async fn record_audit_sanitizes_crlf_in_detail_and_label() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    // A forged label/detail with embedded CRLF must be stored sanitized so a
    // reader of the audit feed (or a log line derived from it) cannot be
    // fooled by an injected newline.
    db.record_audit(
        "token",
        None,
        "label\r\nINJECTED admin",
        "publish",
        &org_scope,
        None,
        None,
        None,
        Some("fetching http://host/x\r\nFAKE: line"),
    )
    .await
    .unwrap();
    let rows = db.list_audit(&org_scope).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        !rows[0].actor_label.contains('\n') && !rows[0].actor_label.contains('\r'),
        "label retained CR/LF: {:?}",
        rows[0].actor_label
    );
    let detail = rows[0].detail.as_deref().unwrap_or("");
    assert!(
        !detail.contains('\n') && !detail.contains('\r'),
        "detail retained CR/LF: {detail:?}"
    );
    assert!(
        detail.contains("http://host/x"),
        "content preserved: {detail:?}"
    );
}

#[tokio::test]
async fn mark_changeset_applied_commit_links_promoting_commit() {
    let db = Database::open_in_memory().await.unwrap();
    db.create_git_changeset(
        "ch-3",
        "user",
        Some(7),
        "alice@acme.com",
        "instance",
        Some("edit"),
        "refs/hub/changes/ch-3",
        "draftoid",
        None,
        None,
    )
    .await
    .unwrap();
    db.mark_changeset_applied_commit("ch-3", "rosteroid")
        .await
        .unwrap();
    let cs = db.changeset("ch-3").await.unwrap().unwrap();
    assert_eq!(cs.status, "applied");
    assert!(cs.applied_at.is_some());
    assert_eq!(cs.git_commit.as_deref(), Some("rosteroid"));
    // Re-marking an applied row is a no-op (status-guarded UPDATE).
    db.mark_changeset_applied_commit("ch-3", "otheroid")
        .await
        .unwrap();
    let again = db.changeset("ch-3").await.unwrap().unwrap();
    assert_eq!(again.git_commit.as_deref(), Some("rosteroid"));
}

#[tokio::test]
async fn audit_exists_for_commit_is_specific_to_action_and_commit() {
    let db = Database::open_in_memory().await.unwrap();
    assert!(!db
        .audit_exists_for_commit("index.external_commit", "oid-1")
        .await
        .unwrap());
    db.record_audit(
        "key",
        None,
        "key:abc",
        "index.external_commit",
        "acme/cdn",
        None,
        Some("oid-1"),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(db
        .audit_exists_for_commit("index.external_commit", "oid-1")
        .await
        .unwrap());
    // A different commit, or a different action, does not match.
    assert!(!db
        .audit_exists_for_commit("index.external_commit", "oid-2")
        .await
        .unwrap());
    assert!(!db.audit_exists_for_commit("index", "oid-1").await.unwrap());
}

#[tokio::test]
async fn list_audit_is_bounded_and_newest_first() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    db.create_project(org_id, "infra", "Infrastructure")
        .await
        .unwrap();
    let project_scope = db.list_projects(org_id).await.unwrap()[0].scope_key.clone();
    let other_id = db.create_org("other", "Other").await.unwrap();
    let other_scope = db.org_by_id(other_id).await.unwrap().unwrap().stable_id;
    // Append a batch of audit rows under one scope.
    let rows = 50;
    for i in 0..rows {
        db.record_audit(
            "user",
            None,
            "alice@acme.com",
            &format!("action.{i}"),
            &project_scope,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }

    // A root-scoped query returns every row (all under the cap), capped at
    // MAX_AUDIT_SCAN, newest (highest id) first.
    let all = db.list_audit("instance").await.unwrap();
    assert_eq!(all.len(), rows);
    assert!(
        all.len() <= MAX_AUDIT_SCAN as usize,
        "bounded by the scan cap"
    );
    assert_eq!(
        all[0].action,
        format!("action.{}", rows - 1),
        "newest first"
    );
    for pair in all.windows(2) {
        assert!(pair[0].id > pair[1].id, "ids strictly descending");
    }

    // Scope filtering still works over the bounded read.
    assert_eq!(db.list_audit(&org_scope).await.unwrap().len(), rows);
    assert!(db.list_audit(&other_scope).await.unwrap().is_empty());
}
