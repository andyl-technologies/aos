//! The native (`sqlx`) database driver and connection-URL helper.
//!
//! The engine-neutral abstraction — the async [`Backend`] trait, the
//! [`Statement`] unit of atomic work, and the
//! [`split_statements`]/[`with_returning_id`]/[`prepare`] helpers — lives in
//! [`aos_registry_core::backend`] (RFC-0004 Phase 5) so the Cloudflare Worker's
//! D1 driver shares it; this module re-exports those items to keep the hub's
//! `db::backend::…` paths stable.
//!
//! What stays here is native-only: [`SqlxBackend`], the one [`Backend`]
//! implementation that runs every query over a concrete `sqlx` connection pool
//! (sqlite by default; postgres and mysql behind their cargo features), and
//! [`redact_db_url`], which strips the password from a `postgres://`/`mysql://`
//! connection URL before it reaches a log line.

pub use aos_registry_core::backend::*;

mod sqlx;
pub use sqlx::SqlxBackend;

/// Redacts the password from a `postgres://`/`mysql://` connection URL so it
/// is safe to embed in an error chain or log line.
///
/// A connection URL is `scheme://user:PASSWORD@host:port/db?…`, and the
/// password is a long-lived database secret. Connection failures are logged
/// with the URL as context (`connecting to postgres …`), so the raw form would
/// leak the credential into the hub's logs. This replaces the password
/// component with `***` while preserving every other part (user, host, port,
/// database, query) so the redacted form remains diagnostically useful.
///
/// When the input does not parse as a URL — or carries no password — it is
/// returned unchanged, since there is no credential to strip. The fallback is
/// safe because a non-URL string never contains the `user:password@` userinfo
/// shape this guards against.
///
/// # Examples
///
/// ```no_run
/// # // Illustrative only; `redact_db_url` is crate-private.
/// // redact_db_url("postgresql://app:s3cret@db.internal/hub")
/// //   == "postgresql://app:***@db.internal/hub"
/// ```
#[cfg_attr(not(any(feature = "postgres", feature = "mysql")), allow(dead_code))]
pub(crate) fn redact_db_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) if parsed.password().is_some() => {
            // `set_password` only fails for URLs that cannot have credentials
            // (e.g. those without a host); for those we fall through to the
            // original string, which by construction carries no userinfo.
            if parsed.set_password(Some("***")).is_ok() {
                parsed.into()
            } else {
                url.to_string()
            }
        }
        _ => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_db_url, Backend, SqlxBackend, Statement};
    use crate::db::value::Value;

    /// An in-memory sqlite backend with a single `t(id, v)` table for batch tests.
    async fn batch_fixture() -> SqlxBackend {
        let backend = SqlxBackend::connect_sqlite(":memory:")
            .await
            .expect("open in-memory sqlite");
        backend
            .execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);")
            .await
            .expect("create table");
        backend
    }

    #[tokio::test]
    async fn batch_commits_all_statements_atomically() {
        let backend = batch_fixture().await;
        backend
            .batch(&[
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(1), Value::Text("a".into())],
                ),
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(2), Value::Text("b".into())],
                ),
            ])
            .await
            .expect("batch commits");
        let rows = backend
            .query("SELECT id FROM t ORDER BY id", &[])
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "both rows committed");
    }

    #[tokio::test]
    async fn batch_rolls_back_on_a_failing_statement() {
        let backend = batch_fixture().await;
        let err = backend
            .batch(&[
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(1), Value::Text("a".into())],
                ),
                // NOT NULL violation: the whole batch must roll back.
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, NULL)",
                    vec![Value::Int(2)],
                ),
            ])
            .await;
        assert!(err.is_err(), "a failing statement aborts the batch");
        let rows = backend.query("SELECT id FROM t", &[]).await.unwrap();
        assert!(rows.is_empty(), "the first insert was rolled back");
    }

    #[test]
    fn redact_db_url_strips_password() {
        let redacted = redact_db_url("postgresql://user:secret@host/db");
        assert!(
            !redacted.contains("secret"),
            "password must not survive redaction: {redacted}"
        );
        assert_eq!(redacted, "postgresql://user:***@host/db");
    }

    #[test]
    fn redact_db_url_preserves_non_secret_parts() {
        let redacted = redact_db_url("mysql://app:p%40ss@db.internal:3306/hub?ssl-mode=required");
        assert!(!redacted.contains("p%40ss") && !redacted.contains("p@ss"));
        assert!(redacted.contains("app@") || redacted.contains("app:***@"));
        assert!(redacted.contains("db.internal:3306"));
        assert!(redacted.contains("hub"));
        assert!(redacted.contains("ssl-mode=required"));
    }

    #[test]
    fn redact_db_url_passes_through_without_password() {
        // No userinfo password: nothing to strip, returned (parse-normalized)
        // without inventing a credential.
        let redacted = redact_db_url("postgres://host/db");
        assert!(!redacted.contains("***"));
        assert!(redacted.contains("host"));
        // A non-URL string is returned verbatim (no credential shape).
        assert_eq!(redact_db_url("not a url"), "not a url");
    }
}
