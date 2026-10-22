//! Joined authorization snapshots still validate the complete independent graph.

use super::*;

async fn project_scope(db: &Database, key: &str, parent: &str, org: i64) {
    db.backend
        .execute(
            "INSERT INTO authorization_scopes
               (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
             VALUES (?1, 'project', ?2, ?3, ?1, 1)",
            &vals![key, org, parent],
        )
        .await
        .unwrap();
}

async fn closure(db: &Database, target: &str, ancestors: &[String]) {
    for (depth, ancestor) in ancestors.iter().enumerate() {
        db.backend
            .execute(
                "INSERT INTO authorization_scope_ancestors
                   (descendant_scope_key, ancestor_scope_key, depth) VALUES (?1, ?2, ?3)",
                &vals![target, ancestor, i64::try_from(depth).unwrap()],
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn joined_authorization_rejects_missing_and_misordered_closure_rows() {
    for fault in ["missing_parent", "missing_root", "wrong_depth"] {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("joined-context", "Joined").await.unwrap();
        let owner = db.org_by_id(org).await.unwrap().unwrap().stable_id;
        let target = format!("project:{}", "a".repeat(32));
        project_scope(&db, &target, &owner, org).await;
        closure(
            &db,
            &target,
            &[target.clone(), owner.clone(), "instance".into()],
        )
        .await;

        let context = db.authorization_context(&target).await.unwrap().unwrap();
        assert_eq!(context.target().as_str(), target);
        assert!(context.is_covered_by(&aos_hub_model::domain::Scope::parse(&owner)));
        assert!(context.is_covered_by(&aos_hub_model::domain::Scope::root()));

        let (sql, selected) = match fault {
            "missing_parent" => (
                "DELETE FROM authorization_scope_ancestors WHERE descendant_scope_key = ?1 AND ancestor_scope_key = ?2",
                owner,
            ),
            "missing_root" => (
                "DELETE FROM authorization_scope_ancestors WHERE descendant_scope_key = ?1 AND ancestor_scope_key = ?2",
                "instance".into(),
            ),
            "wrong_depth" => (
                "UPDATE authorization_scope_ancestors SET depth = 3 WHERE descendant_scope_key = ?1 AND ancestor_scope_key = ?2",
                owner,
            ),
            _ => unreachable!(),
        };
        db.backend
            .execute(sql, &vals![target, selected])
            .await
            .unwrap();
        assert!(db.authorization_context(&target).await.is_err(), "{fault}");
    }
}

#[tokio::test]
async fn joined_authorization_rejects_cycles_and_cross_organization_parents() {
    for fault in ["cycle", "cross_organization"] {
        let db = Database::open_in_memory().await.unwrap();
        let left = db.create_org("left-joined", "Left").await.unwrap();
        let right = db.create_org("right-joined", "Right").await.unwrap();
        let parent = db.org_by_id(right).await.unwrap().unwrap().stable_id;
        let target = format!("project:{}", "b".repeat(32));
        project_scope(&db, &target, &parent, left).await;
        closure(&db, &target, &[target.clone(), parent, "instance".into()]).await;
        if fault == "cycle" {
            db.backend.execute(
                "UPDATE authorization_scopes SET parent_scope_key = scope_key WHERE scope_key = ?1",
                &vals![target],
            ).await.unwrap();
        }

        let error = db.authorization_context(&target).await.unwrap_err();
        let expected = if fault == "cycle" {
            "authorization scope parent graph contains a cycle"
        } else {
            "authorization scope parent crosses organization ownership"
        };
        assert_eq!(error.to_string(), expected);
    }
}

#[tokio::test]
async fn joined_authorization_retains_depth_and_live_owner_bounds() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("deep-joined", "Deep").await.unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap().stable_id;
    let mut ancestors = vec![owner.clone(), "instance".to_owned()];
    let mut parent = owner;
    for index in 0..7 {
        let key = format!("project:{index:032x}");
        project_scope(&db, &key, &parent, org).await;
        ancestors.insert(0, key.clone());
        closure(&db, &key, &ancestors).await;
        parent = key;
    }

    let error = db.authorization_context(&parent).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "authorization scope parent graph exceeds the closed topology depth"
    );

    db.backend
        .execute("UPDATE orgs SET deleted_at = 2 WHERE id = ?1", &vals![org])
        .await
        .unwrap();
    assert!(db.authorization_context(&parent).await.unwrap().is_none());
    assert!(db.authorization_context("invalid").await.unwrap().is_none());
    assert!(db
        .authorization_context(&format!("project:{}", "f".repeat(32)))
        .await
        .unwrap()
        .is_none());
}
