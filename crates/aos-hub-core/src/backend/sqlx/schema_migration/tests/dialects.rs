//! Real PostgreSQL and MariaDB initialization/refusal on create-new test databases.

use super::*;

fn database_name(label: &str) -> String {
    format!("hub_reset_{label}_{}", uuid::Uuid::new_v4().simple())
}

async fn verify_fresh_and_refusal(first: SqlxBackend, second: SqlxBackend, old: SqlxBackend) {
    let (left, right) = tokio::join!(first.migrate_schema(), second.migrate_schema());
    left.unwrap();
    right.unwrap();
    let marker = first
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    assert_eq!(marker.len(), 1);
    assert_eq!(marker[0].get::<i64>(0).unwrap(), 8);
    let stamp = first
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await
        .unwrap();
    assert_eq!(stamp.len(), 1);
    assert_eq!(stamp[0].get::<String>(0).unwrap(), SCHEMA_IDENTITY);

    first
        .execute(
            "INSERT INTO users(email,created_at) VALUES ('retained@example.test',1)",
            &[],
        )
        .await
        .unwrap();
    let before = serving_rows(&first).await;
    first.migrate_schema().await.unwrap();
    assert_eq!(serving_rows(&first).await, before);

    // Reproduce the actual incompatible master-v2 history, not a sentinel-only
    // approximation. The current serving initializer must never upgrade it.
    seed(&old, &[MIGRATIONS[0], MIGRATIONS[7]], 2).await;
    let before = serving_rows(&old).await;
    assert!(old
        .migrate_schema()
        .await
        .unwrap_err()
        .to_string()
        .contains("explicitly initialize a new canonical database"));
    assert_eq!(serving_rows(&old).await, before);

    // The keyed MySQL ledger is absent on this old lineage; PostgreSQL has no
    // such ledger. Refusal must not manufacture it as a preflight side effect.
    let sql = match old.dialect() {
        Dialect::Postgres => "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() ORDER BY table_name",
        Dialect::Mysql => "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY table_name",
        Dialect::Sqlite => unreachable!(),
    };
    let tables = old.query(sql, &[]).await.unwrap();
    assert!(!tables
        .iter()
        .any(|row| row.get::<String>(0).unwrap() == "hub_schema_version"));
}

async fn serving_rows(backend: &SqlxBackend) -> String {
    let tables_sql = match backend.dialect() {
        Dialect::Postgres => "SELECT table_name,column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema=current_schema() ORDER BY table_name,ordinal_position",
        Dialect::Mysql => "SELECT table_name,column_name,column_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema=DATABASE() ORDER BY table_name,ordinal_position",
        Dialect::Sqlite => unreachable!(),
    };
    let schema = backend.query(tables_sql, &[]).await.unwrap();
    let version = backend
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    let identity = backend
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await
        .unwrap();
    let payload = backend
        .query("SELECT email FROM users ORDER BY id", &[])
        .await
        .unwrap();
    serde_json::to_string(&(schema, version, identity, payload)).unwrap()
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL admin endpoint"]
async fn actual_postgres_reset_only_fresh_reopen_refusal_and_concurrency() {
    let admin_url = std::env::var("AOS_HUB_RESET_PG_ADMIN_URL").unwrap();
    let admin = sqlx::PgPool::connect(&admin_url).await.unwrap();
    let fresh = database_name("pg_fresh");
    let old = database_name("pg_old");
    for name in [&fresh, &old] {
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
    }
    let endpoint = admin_url.rsplit_once('/').unwrap().0;
    let url = format!("{endpoint}/{fresh}");
    verify_fresh_and_refusal(
        SqlxBackend::connect_postgres(&url).await.unwrap(),
        SqlxBackend::connect_postgres(&url).await.unwrap(),
        SqlxBackend::connect_postgres(&format!("{endpoint}/{old}"))
            .await
            .unwrap(),
    )
    .await;
    println!("retained PostgreSQL databases {fresh} {old}");
}

#[cfg(feature = "mysql")]
#[tokio::test]
#[ignore = "requires explicitly owned MariaDB admin endpoint; not a MySQL qualification"]
async fn actual_mariadb_reset_only_fresh_reopen_refusal_and_concurrency() {
    let admin_url = std::env::var("AOS_HUB_RESET_MARIA_ADMIN_URL").unwrap();
    let admin = sqlx::MySqlPool::connect(&admin_url).await.unwrap();
    let fresh = database_name("maria_fresh");
    let old = database_name("maria_old");
    for name in [&fresh, &old] {
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
    }
    let endpoint = admin_url.rsplit_once('/').unwrap().0;
    let url = format!("{endpoint}/{fresh}");
    verify_fresh_and_refusal(
        SqlxBackend::connect_mysql(&url).await.unwrap(),
        SqlxBackend::connect_mysql(&url).await.unwrap(),
        SqlxBackend::connect_mysql(&format!("{endpoint}/{old}"))
            .await
            .unwrap(),
    )
    .await;
    println!("retained MariaDB databases {fresh} {old}");
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL admin endpoint"]
async fn postgres_fresh_owned_schema_does_not_stamp_lower_search_path_history() {
    let admin_url = std::env::var("AOS_HUB_RESET_PG_ADMIN_URL").unwrap();
    let admin = sqlx::PgPool::connect(&admin_url).await.unwrap();
    let name = database_name("pg_search");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let endpoint = admin_url.rsplit_once('/').unwrap().0;
    let url = format!("{endpoint}/{name}");
    let old = SqlxBackend::connect_postgres(&url).await.unwrap();
    seed(&old, &[MIGRATIONS[0], MIGRATIONS[7]], 2).await;
    let before = serving_rows(&old).await;
    old.execute("CREATE SCHEMA owned", &[]).await.unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path=owned,public")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let current = SqlxBackend::Postgres(pool);

    current.migrate_schema().await.unwrap();

    assert_eq!(serving_rows(&old).await, before);
    let stamp = current
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await
        .unwrap();
    assert_eq!(stamp[0].get::<String>(0).unwrap(), SCHEMA_IDENTITY);
    println!("retained PostgreSQL search-path database {name}");
}
