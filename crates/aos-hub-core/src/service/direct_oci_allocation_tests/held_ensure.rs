//! Real outer allocation race held immediately before its checked ensure batch.

use super::*;
use crate::backend::{Backend, CheckedStatement, Statement};
use crate::dialect::Dialect;
use crate::value::{Row, Value};

struct HeldEnsureBackend {
    inner: Arc<crate::db::Database>,
    pause: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

#[async_trait::async_trait]
impl Backend for HeldEnsureBackend {
    fn dialect(&self) -> Dialect {
        self.inner.backend.dialect()
    }

    async fn migrate_schema(&self) -> anyhow::Result<()> {
        self.inner.backend.migrate_schema().await
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> anyhow::Result<u64> {
        self.inner.backend.execute(sql, params).await
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> anyhow::Result<i64> {
        self.inner.backend.execute_insert(sql, params).await
    }

    async fn query(&self, sql: &str, params: &[Value]) -> anyhow::Result<Vec<Row>> {
        self.inner.backend.query(sql, params).await
    }

    async fn execute_batch(&self, sql: &str) -> anyhow::Result<()> {
        self.inner.backend.execute_batch(sql).await
    }

    async fn batch(&self, statements: &[Statement]) -> anyhow::Result<()> {
        self.inner.backend.batch(statements).await
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> anyhow::Result<()> {
        if statements
            .first()
            .is_some_and(|statement| statement.statement.sql.contains("registry.stable_id = ?5"))
        {
            let pause = self.pause.lock().unwrap().take();
            if let Some((entered, release)) = pause {
                entered.send(()).unwrap();
                release.await.unwrap();
            }
        }
        self.inner.backend.checked_batch(statements).await
    }
}

#[tokio::test]
async fn original_registry_identity_changes_after_live_auth_before_ensure_without_new_rows() {
    let mut fixture = fixture().await;
    let name = RepositoryName::parse("fresh/image").unwrap();
    let authorization = headers_for(&fixture, true, &name);
    let original_query = query('8');
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, continue_ensure) = tokio::sync::oneshot::channel();
    let service = Arc::get_mut(&mut fixture.service).unwrap();
    let original_db = service.db.clone();
    let original_epoch = original_db
        .backend
        .query_opt(
            "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
            &sql_values![fixture.registry.id],
        )
        .await
        .unwrap()
        .unwrap()
        .get::<i64>(0)
        .unwrap();
    service.db = Arc::new(crate::db::Database::attach(Box::new(HeldEnsureBackend {
        inner: original_db.clone(),
        pause: std::sync::Mutex::new(Some((entered, continue_ensure))),
    })));

    let service = fixture.service.clone();
    let route = initial_route(&fixture, &name);
    let pending = tokio::spawn(async move {
        service
            .serve_oci(
                route,
                axum::http::Method::POST,
                authorization,
                Some(&original_query),
                Body::empty(),
            )
            .await
    });
    observed.await.unwrap();
    // The real actor and IAM already passed. Reuse of the numeric registry
    // slot must still fail its captured stable identity inside the transaction.
    // A replacement must satisfy the real scope/identity CHECKs and foreign
    // keys. Keep the original scope/history and create a valid new scope.
    let replacement = format!("registry:{}", uuid::Uuid::new_v4().simple());
    original_db
        .backend
        .checked_batch(&[
            Statement::new(
                "INSERT INTO authorization_scopes
             (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
             SELECT ?2, kind, org_id, parent_scope_key, ?2, created_at
             FROM authorization_scopes WHERE scope_key = ?1 AND kind = 'registry'",
                sql_values![fixture.registry.stable_id.as_str(), replacement.as_str()],
            )
            .expecting(1),
            Statement::new(
                "UPDATE registries SET stable_id = ?2, scope_key = ?2
             WHERE id = ?1 AND stable_id = ?3",
                sql_values![
                    fixture.registry.id,
                    replacement.as_str(),
                    fixture.registry.stable_id.as_str()
                ],
            )
            .expecting(1),
        ])
        .await
        .unwrap();
    release.send(()).unwrap();

    let response = pending.await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(original_db
        .oci_repository(fixture.registry.id, &name)
        .await
        .unwrap()
        .is_none());
    let current_epoch = original_db
        .backend
        .query_opt(
            "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
            &sql_values![fixture.registry.id],
        )
        .await
        .unwrap()
        .unwrap()
        .get::<i64>(0)
        .unwrap();
    assert_eq!(current_epoch, original_epoch);
    for table in [
        "direct_oci_allocations",
        "oci_upload_sessions",
        "oci_quota_reservations",
    ] {
        let count = original_db
            .backend
            .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}
