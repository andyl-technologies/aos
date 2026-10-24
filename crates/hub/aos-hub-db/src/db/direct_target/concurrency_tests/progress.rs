//! Concurrent publication progress with current PostgreSQL authority fences.

use super::*;

/// Independent originals share authority while every authority writer waits.
#[tokio::test]
async fn direct_publication_postgres_progress_shares_authority_and_rechecks_after_writers() {
    let Ok(url) = std::env::var("AOS_HUB_DIRECT_PROGRESS_TEST_PG_URL") else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    let db = Arc::new(
        Database::with_backend(Box::new(SqlxBackend::Postgres(pool.clone())))
            .await
            .unwrap(),
    );
    let cache = external_original(&db).await;
    let object = publication(&db).await;
    let first = publication_original(&db, &cache, object).await;
    let claims = claims(&db, &first).await;
    let mut admission = first.admission.clone();
    admission.session_id = "second-publication-session".into();
    admission.intent.client_operation_id = "9".repeat(64);
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    let second = db
        .admit_direct_upload(
            "deployment",
            &admission,
            &first.owner_scope_key,
            &DirectSqlOwner::Publication,
            10,
        )
        .await
        .unwrap();
    db.backend
        .execute_batch("CREATE TABLE direct_progress_probe (session_id TEXT PRIMARY KEY);")
        .await
        .unwrap();

    db.backend
        .execute(
            "INSERT INTO binding_credential_revisions
           (binding_id, purpose, generation, secret_version_ref, validation_state,
            validated_at, credential_fingerprint, created_by, created_at)
         VALUES (1, 'write', 2, 'secret://test/write/v2', 'valid', 1, ?1, 'test', 1)",
            &vals!["f".repeat(64)],
        )
        .await
        .unwrap();

    // Both transactions must reach the same final gate while retaining all
    // production authority locks. An exclusive authority lock would serialize
    // them before this point. Gates use the test's isolated database only.
    let mut holder = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(GATE)
        .execute(&mut *holder)
        .await
        .unwrap();
    let mut transactions = Vec::new();
    for record in [&first, &second] {
        let mut statements = db
            .direct_iam_statements(
                &claims,
                &record.owner_scope_key,
                Permission::RegistryConfigure,
                14,
            )
            .await
            .unwrap();
        statements.push(Database::direct_placement_fence(&record.admission.placements[0]).unwrap());
        statements.push(
            Database::direct_publication_phase_fence("direct-concurrent-publication", false)
                .unwrap(),
        );
        statements.extend(
            db.direct_publication_dependency_locks("direct-concurrent-publication")
                .await
                .unwrap(),
        );
        statements.push(current_guard(record, 14).unwrap());
        statements.push(CheckedStatement::unchecked(
            "INSERT INTO direct_progress_probe(session_id) VALUES (?1)",
            vals![record.admission.session_id],
        ));
        statements.push(CheckedStatement::unchecked(
            "SELECT pg_advisory_xact_lock_shared(?1)",
            vals![GATE],
        ));
        let db = Arc::clone(&db);
        let record = record.clone();
        transactions.push(tokio::spawn(async move {
            db.direct_batch(&record)
                .checked_session_batch(&statements)
                .await
        }));
    }
    let overlapped = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()
                   AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();

    let mut writer = pool.begin().await.unwrap();
    let mut mutation = Box::pin(
        sqlx::query("UPDATE tokens SET revoked_at = 15 WHERE id = $1")
            .bind(&claims.sub)
            .execute(&mut *writer),
    );
    let blocked = tokio::time::timeout(Duration::from_millis(80), &mut mutation)
        .await
        .is_err();
    let mut rotation = pool.begin().await.unwrap();
    let mut rotate = Box::pin(
        sqlx::query(
            "UPDATE binding_credential_heads SET current_generation = current_generation + 1
                     WHERE binding_id = 1 AND purpose = 'write'",
        )
        .execute(&mut *rotation),
    );
    let rotation_blocked = tokio::time::timeout(Duration::from_millis(80), &mut rotate)
        .await
        .is_err();
    let mut dependency = pool.begin().await.unwrap();
    let mut replace = Box::pin(
        sqlx::query("UPDATE surface_objects SET content_hash = $1 WHERE id = $2")
            .bind("f".repeat(64))
            .bind(object)
            .execute(&mut *dependency),
    );
    let dependency_blocked = tokio::time::timeout(Duration::from_millis(80), &mut replace)
        .await
        .is_err();
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(GATE)
        .execute(&mut *holder)
        .await
        .unwrap();
    for transaction in transactions {
        tokio::time::timeout(Duration::from_secs(5), transaction)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    mutation.await.unwrap();
    writer.rollback().await.unwrap();
    rotate.await.unwrap();
    rotation.rollback().await.unwrap();
    replace.await.unwrap();
    dependency.rollback().await.unwrap();
    assert!(
        overlapped,
        "independent publication progress serialized on authority rows"
    );
    assert!(
        blocked,
        "credential revocation crossed a progress transaction"
    );
    assert!(
        rotation_blocked,
        "credential rotation crossed shared authority"
    );
    assert!(
        dependency_blocked,
        "immutable replacement crossed shared authority"
    );
    eprintln!("actual concurrent publication progress and blocked credential revocation");
    eprintln!("actual shared authority blocked credential rotation and immutable replacement");

    // A writer that wins first must invalidate the prebuilt plan. A mutation
    // preceding the IAM fence must also disappear with that failed transaction.
    let mut stale = vec![CheckedStatement::unchecked(
        "DELETE FROM direct_progress_probe WHERE session_id = ?1",
        vals![first.admission.session_id],
    )];
    stale.extend(
        db.direct_iam_statements(
            &claims,
            &first.owner_scope_key,
            Permission::RegistryConfigure,
            14,
        )
        .await
        .unwrap(),
    );
    let mut revoke = pool.begin().await.unwrap();
    sqlx::query("UPDATE tokens SET revoked_at = 15 WHERE id = $1")
        .bind(&claims.sub)
        .execute(&mut *revoke)
        .await
        .unwrap();
    let stale_db = Arc::clone(&db);
    let stale_record = first.clone();
    let progress = tokio::spawn(async move {
        stale_db
            .direct_batch(&stale_record)
            .checked_session_batch(&stale)
            .await
    });
    wait_for_lock(&pool, false).await;
    revoke.commit().await.unwrap();
    assert!(progress.await.unwrap().is_err());
    let retained = db
        .backend
        .query("SELECT session_id FROM direct_progress_probe", &[])
        .await
        .unwrap();
    assert_eq!(
        retained.len(),
        2,
        "failed shared-authority fence did not roll back"
    );
    eprintln!("actual shared authority stale-plan refusal and atomic rollback");
}
