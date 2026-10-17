//! Pauses a real read-only connection before the export's final SQL head read.

use std::sync::atomic::{AtomicUsize, Ordering};

use aos_hub_core::{
    backend::{Backend, CheckedStatement, SqlxBackend, Statement},
    dialect::Dialect,
    value::{Row, Value},
};

use super::*;

struct PausedReader {
    inner: SqlxBackend,
    publication_reads: AtomicUsize,
    entered: Arc<tokio::sync::Notify>,
    released: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl Backend for PausedReader {
    fn dialect(&self) -> Dialect {
        self.inner.dialect()
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        self.inner.execute(sql, params).await
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        self.inner.execute_insert(sql, params).await
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        if sql.contains("FROM physical_storage_authorities WHERE authority_id")
            && self.publication_reads.fetch_add(1, Ordering::SeqCst) == 1
        {
            self.entered.notify_one();
            self.released.notified().await;
        }
        self.inner.query(sql, params).await
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        self.inner.execute_batch(sql).await
    }

    async fn batch(&self, statements: &[Statement]) -> Result<()> {
        self.inner.batch(statements).await
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        self.inner.checked_batch(statements).await
    }
}

#[tokio::test]
async fn actual_reviewed_head_change_between_reads_refuses_without_output_or_sql_writes() {
    let directory = private_directory();
    let path = directory.path().join("authority.db");
    let fixture = fixture_with_database_and_purposes(
        Database::open(&path).await.unwrap(),
        &["list", "presign", "read", "write"],
    )
    .await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let released = Arc::new(tokio::sync::Notify::new());
    let reader = Database::attach(Box::new(PausedReader {
        inner: SqlxBackend::connect_sqlite_read_only(path.to_str().unwrap())
            .await
            .unwrap(),
        publication_reads: AtomicUsize::new(0),
        entered: entered.clone(),
        released: released.clone(),
    }));
    let output = relative_private_directory(&directory).join("list-selection");
    let authority = PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap();
    let exporting = export_list_cohort(
        &reader,
        &authority,
        &fixture.configuration,
        "bootstrap-association",
        PREFIX,
        &output,
    );
    let changing = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        super::super::publication_export::set_admission(
            &fixture,
            pb::StorageAuthorityDesiredState::Blocked,
            "during-list-export",
        )
        .await;
        released.notify_one();
    };
    let (result, ()) = tokio::join!(exporting, changing);
    assert!(result.is_err());
    assert!(!output.exists());
    assert!(reader
        .create_user("forbidden@example.test", None)
        .await
        .is_err());
}
