//! Exercises OCI commit ordering against replacement of indexed release roots.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

use super::{tests, BeginOciPublication, OciPublicationRequiredPlacement};
use crate::{backend::SqlxBackend, db::Database};

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL server via AOS_TEST_POSTGRES_SOCKET"]
async fn release_commit_waits_for_reindexed_root() -> Result<()> {
    let socket = std::env::var("AOS_TEST_POSTGRES_SOCKET")
        .context("AOS_TEST_POSTGRES_SOCKET is required")?;
    anyhow::ensure!(socket.starts_with('/'), "a local Unix socket is required");

    let schema = format!("release_root_{}", uuid::Uuid::new_v4().simple());
    let options = PgConnectOptions::new()
        .host(&socket)
        .username("postgres")
        .database("postgres")
        .ssl_mode(PgSslMode::Disable);
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone())
        .await?;
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await?;

    let result = check_replacement(&pool, &admin).await;
    pool.close().await;
    let cleanup = sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await;
    admin.close().await;
    result?;
    cleanup?;
    Ok(())
}

async fn check_replacement(pool: &sqlx::PgPool, admin: &sqlx::PgPool) -> Result<()> {
    let db = Database::with_backend(Box::new(SqlxBackend::Postgres(pool.clone()))).await?;
    let (db, registry_id, placement_id) = tests::catalog_database_with_backend(db).await;
    let catalog = tests::catalog_fixture(registry_id, placement_id);
    tests::record_catalog_bytes(&db, &catalog).await;
    let repository = db.index_oci_repository_catalog(&catalog).await?;
    let graph = db
        .oci_repository_closed_graph(repository.id, &[catalog.objects[0].descriptor.clone()])
        .await?;
    let release_tag = "1.0.0";
    let sidecar = aos_oci_types::Sha256Digest::digest(b"signed container release").encoded();
    sqlx::query(
        "INSERT INTO releases
           (id, registry_id, semver, tag_oid, commit_oid, signer, tagged_at, pack_present)
         VALUES (91001, $1, $2, 'verified-tag', 'verified-commit', 'test signer', $3, 1)",
    )
    .bind(registry_id)
    .bind(release_tag)
    .bind(catalog.observed_at)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO oci_release_roots
           (registry_id, release_id, release_tag, repository_id, container_name,
            index_digest, source_commit, verified_tag_oid, catalog_digest, created_at)
         VALUES ($1, 91001, $2, $3, $4, $5, 'verified-commit', 'verified-tag', $6, $7)",
    )
    .bind(registry_id)
    .bind(release_tag)
    .bind(repository.id)
    .bind(catalog.repository.as_str())
    .bind(catalog.root_digest.to_string())
    .bind(&sidecar)
    .bind(catalog.observed_at)
    .execute(pool)
    .await?;

    let placement = db.surface_placement(placement_id).await?.unwrap();
    let revision = db
        .placement_publication_write_revision(placement_id)
        .await?
        .unwrap();
    let now = catalog.observed_at + 100;
    let publication = db
        .begin_oci_publication(&BeginOciPublication {
            registry_id,
            repository_id: repository.id,
            writer_id: "writer:release".into(),
            token_id: "token:release".into(),
            target_tag: Some(aos_oci_types::Tag::parse(release_tag)?),
            expected_tag_version: None,
            expected_tag_digest: None,
            root_digest: catalog.root_digest,
            catalog_digest: super::oci_catalog_declaration_digest(catalog.root_digest, &graph)?,
            release_tag: Some(release_tag.into()),
            sidecar_sha256_hex: Some(sidecar),
            required_placements: vec![OciPublicationRequiredPlacement {
                placement_id,
                placement_resource_version: placement.resource_version,
                placement_write_spec_version: placement.write_spec_version,
                placement_observation_version: placement.observation_version.unwrap(),
                binding_id: revision.binding_id,
                binding_write_revision: revision.revision,
                revision_fingerprint: revision.revision_fingerprint,
                capability_fingerprint: revision.capability_fingerprint,
            }],
            source_kind: "release".into(),
            idempotency_key: "release-publication".into(),
            now,
            expires_at: now + 60,
        })
        .await?;
    let publication = tests::freeze_publication_graph(
        &db,
        publication,
        repository.id,
        placement_id,
        &graph,
        now + 1,
    )
    .await;
    let frozen = db
        .oci_publication_catalog(
            &publication.id,
            &publication.writer_id,
            &publication.token_id,
            "release:test",
            now + 2,
        )
        .await?;

    // Reindexing already locks the registry before replacing its derived roots.
    // Hold that transaction open until the ordinary commit reaches its row lock.
    let mut reindex = pool.begin().await?;
    let guard = Database::registry_index_mutation_guard(registry_id, Some(placement_id));
    let guard_sql = guard.statement.sql.replace("?1", "$1").replace("?2", "$2");
    assert_eq!(
        sqlx::query(&guard_sql)
            .bind(registry_id)
            .bind(placement_id)
            .execute(&mut *reindex)
            .await?
            .rows_affected(),
        1,
    );
    let reindex_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *reindex)
        .await?;
    sqlx::raw_sql(
        "CREATE TEMP TABLE saved_root AS SELECT * FROM oci_release_roots;
         DELETE FROM oci_release_roots;
         INSERT INTO oci_release_roots SELECT * FROM saved_root;",
    )
    .execute(&mut *reindex)
    .await?;

    let db = Arc::new(db);
    let committing_db = db.clone();
    let committing = tokio::spawn(async move {
        committing_db
            .commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:release",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
    });
    let waiting = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                 WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(reindex_pid)
            .fetch_one(admin)
            .await?;
            if blocked {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    // Release the blocker even if the observation times out, so cleanup is bounded.
    reindex.commit().await?;
    let committed = tokio::time::timeout(Duration::from_secs(10), committing).await;
    waiting??;
    let committed = committed???;
    assert_eq!(committed.state, "ready");
    Ok(())
}
