//! Deterministic real SQLite account replacement during an awaited IAM read.

use super::*;
use crate::backend::{Backend, CheckedStatement, SqlxBackend, Statement};
use crate::dialect::Dialect;
use crate::value::{Row, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ReplaceDuringIam {
    inner: SqlxBackend,
    remaining: AtomicUsize,
    changed: AtomicBool,
}

#[async_trait::async_trait]
impl Backend for Arc<ReplaceDuringIam> {
    fn dialect(&self) -> Dialect {
        self.inner.dialect()
    }

    async fn migrate_schema(&self) -> anyhow::Result<()> {
        self.inner.migrate_schema().await
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> anyhow::Result<u64> {
        self.inner.execute(sql, params).await
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> anyhow::Result<i64> {
        self.inner.execute_insert(sql, params).await
    }

    async fn query(&self, sql: &str, params: &[Value]) -> anyhow::Result<Vec<Row>> {
        let rows = self.inner.query(sql, params).await?;
        if sql.starts_with("SELECT m.scope_key, m.role FROM memberships m") {
            let remaining = self.remaining.load(Ordering::SeqCst);
            if remaining != 0 && self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                let Some(Value::Int(user)) = params.get(1) else {
                    anyhow::bail!("IAM fixture received unexpected principal slot");
                };
                self.inner
                    .execute(
                        "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
                        &[
                            Value::Int(*user),
                            Value::Text("00000000-0000-4000-8000-000000000099".into()),
                        ],
                    )
                    .await?;
                self.changed.store(true, Ordering::SeqCst);
            }
        }
        Ok(rows)
    }

    async fn execute_batch(&self, sql: &str) -> anyhow::Result<()> {
        self.inner.execute_batch(sql).await
    }

    async fn batch(&self, statements: &[Statement]) -> anyhow::Result<()> {
        self.inner.batch(statements).await
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> anyhow::Result<()> {
        self.inner.checked_batch(statements).await
    }
}

#[tokio::test]
async fn account_replacement_during_iam_await_denies_erroring_and_filter_gates() {
    for filter in [false, true] {
        let (mut service, _) = super::tests::fixture().await;
        let backend = Arc::new(ReplaceDuringIam {
            inner: SqlxBackend::connect_sqlite(":memory:").await.unwrap(),
            remaining: AtomicUsize::new(0),
            changed: AtomicBool::new(false),
        });
        service.db = Arc::new(
            Database::with_backend(Box::new(Arc::clone(&backend)))
                .await
                .unwrap(),
        );
        let user = service
            .db
            .create_user("race@example.test", None)
            .await
            .unwrap();
        service
            .db
            .grant_membership("user", user, "instance", Role::Owner.as_str())
            .await
            .unwrap();
        let (claims, _) = super::tests::claims(&service, user).await;

        // The first membership read belongs to live token validation. The
        // second is the RPC's IAM lookup. Replace the account after preserving
        // that lookup's positive rows and before returning its await result.
        backend.remaining.store(2, Ordering::SeqCst);
        if filter {
            assert!(
                !service
                    .claims_allow(Some(&claims), Permission::StorageManage, &Scope::root())
                    .await
            );
        } else {
            assert!(matches!(
                service
                    .require_permission(&claims, Permission::StorageManage, &Scope::root())
                    .await,
                Err(RpcError::PermissionDenied(_))
            ));
        }
        assert!(
            backend.changed.load(Ordering::SeqCst),
            "real IAM await mutation did not occur"
        );
    }
}
