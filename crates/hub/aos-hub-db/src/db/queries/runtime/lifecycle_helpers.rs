//! Lifecycle helpers in the runtime capability.

use super::*;

impl Database {
    /// Rejects databases from a different migration lineage before changing data.
    pub(in crate::db) async fn require_schema_identity(&self) -> Result<()> {
        let rows = self
            .backend
            .query("SELECT identity FROM hub_schema_identity", &[])
            .await
            .context("database predates the first stable production baseline")?;
        anyhow::ensure!(
            rows.len() == 1,
            "Hub schema identity ledger must contain exactly one row"
        );
        let identity: String = rows[0].get(0)?;
        anyhow::ensure!(
            identity == SCHEMA_IDENTITY,
            "unsupported Hub schema identity '{identity}'; expected '{SCHEMA_IDENTITY}'"
        );
        Ok(())
    }

    /// The SQL dialect of the underlying backend.
    pub(in crate::db) fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    pub(in crate::db) async fn migrate(&self) -> Result<()> {
        self.backend
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
                &[],
            )
            .await?;
        let mysql = self.dialect() == Dialect::Mysql;
        if mysql {
            // MySQL DDL can commit before the version marker. A keyed ledger
            // coordinates replay and concurrent starters; id 1 avoids MySQL's
            // generated-identity behavior for zero-valued primary keys.
            self.backend
                .execute(
                    "CREATE TABLE IF NOT EXISTS hub_schema_version (
                       id INTEGER PRIMARY KEY, version INTEGER NOT NULL)",
                    &[],
                )
                .await?;
            self.backend
                .execute(
                    "INSERT INTO hub_schema_version(id, version)
                     VALUES (1, 0)
                     ON CONFLICT(id) DO NOTHING",
                    &[],
                )
                .await?;
        }
        let marker_query = if mysql {
            "SELECT version, id FROM hub_schema_version"
        } else {
            "SELECT version FROM schema_version"
        };
        let rows = self.backend.query(marker_query, &[]).await?;
        anyhow::ensure!(
            rows.len() <= 1,
            "Hub schema version ledger has duplicate rows"
        );
        let current = rows
            .first()
            .map(|row| row.get::<i64>(0))
            .transpose()?
            .unwrap_or(0);
        let target = MIGRATIONS.len() as i64;
        anyhow::ensure!(current >= 0, "Hub schema version cannot be negative");
        if current > target {
            bail!("hub database schema {current} is newer than this build supports ({target})");
        }
        if mysql {
            anyhow::ensure!(
                rows.len() == 1 && rows[0].get::<i64>(1)? == 1,
                "Hub keyed schema version ledger is not a singleton"
            );
            let portable_rows = self
                .backend
                .query("SELECT version FROM schema_version", &[])
                .await?;
            anyhow::ensure!(
                portable_rows.len() <= 1,
                "Hub schema version ledger has duplicate rows"
            );
            anyhow::ensure!(
                current == 0 || portable_rows.len() == 1,
                "Hub portable schema version marker is missing"
            );
            if let Some(row) = portable_rows.first() {
                anyhow::ensure!(
                    row.get::<i64>(0)? == current,
                    "Hub schema version ledgers disagree"
                );
            }
        }
        if current > 0 {
            self.require_schema_identity().await?;
        }

        // Apply every pending migration *and* advance the version marker in one
        // portable transaction. Keeping the marker in the same batch matters
        // for Durable Objects: if an isolate is evicted after DDL commits but
        // before a separate marker write, startup would replay a non-idempotent
        // `ALTER TABLE` and permanently wedge the object.
        if (current as usize) < MIGRATIONS.len() {
            if mysql {
                // MySQL implicitly commits DDL. Apply one replay-safe
                // statement at a time, checking indexes through the catalog,
                // then atomically advance the singleton ledger after each
                // complete migration. A crash can repeat only idempotent work.
                for (offset, migration) in MIGRATIONS[current as usize..].iter().enumerate() {
                    let migration_version = current + offset as i64 + 1;
                    for sql in crate::backend::split_statements(migration) {
                        if let Some((table, index)) = mysql_migration_index_identity(&sql) {
                            let exists = self
                                .backend
                                .query_opt(
                                    "SELECT 1 FROM information_schema.statistics
                                      WHERE table_schema = DATABASE()
                                        AND table_name = ?1 AND index_name = ?2 LIMIT 1",
                                    &vals![table, index],
                                )
                                .await?
                                .is_some();
                            if exists {
                                continue;
                            }
                        }
                        let replay_safe = mysql_replay_safe_migration_sql(&sql);
                        if let Err(error) = self.backend.execute(&replay_safe, &[]).await {
                            // Concurrent starters can both observe an absent
                            // index. Treat the losing CREATE as success only
                            // after the catalog proves the exact index exists.
                            let concurrently_created = if let Some((table, index)) =
                                mysql_migration_index_identity(&sql)
                            {
                                self.backend
                                    .query_opt(
                                        "SELECT 1 FROM information_schema.statistics
                                          WHERE table_schema = DATABASE()
                                            AND table_name = ?1 AND index_name = ?2 LIMIT 1",
                                        &vals![table, index],
                                    )
                                    .await?
                                    .is_some()
                            } else {
                                false
                            };
                            if !concurrently_created {
                                return Err(error).with_context(|| {
                                    format!("applying MySQL schema migration v{migration_version}")
                                });
                            }
                        }
                    }
                    self.backend
                        .batch(&[
                            Statement::new(
                                "UPDATE hub_schema_version SET version = ?1 WHERE id = 1",
                                vals![migration_version],
                            ),
                            Statement::new("DELETE FROM schema_version", Vec::new()),
                            Statement::new(
                                "INSERT INTO schema_version (version) VALUES (?1)",
                                vals![migration_version],
                            ),
                        ])
                        .await?;
                }
            } else {
                let mut pending = MIGRATIONS[current as usize..].join("\n");
                pending.push_str("\nDELETE FROM schema_version;\n");
                pending.push_str(&format!(
                    "INSERT INTO schema_version (version) VALUES ({target});\n"
                ));
                let statements = crate::backend::split_statements(&pending)
                    .into_iter()
                    .map(|sql| Statement::new(sql, Vec::new()))
                    .collect::<Vec<_>>();
                self.backend
                    .migration_batch(current, target, &statements)
                    .await
                    .with_context(|| format!("applying migrations v{}..=v{target}", current + 1))?;
            }
            self.require_schema_identity().await?;
        }
        Ok(())
    }

    /// Returns the current maximum `id` in `table`, or `0` when it is empty.
    ///
    /// Used to allocate surrogate ids client-side before a batch insert, so the
    /// batch carries no mid-flight `last_insert_rowid` round-trip (the seam the
    /// native backends and Worker HubDb share). `table` must be a trusted
    /// literal — it is interpolated directly into the query.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub(in crate::db) async fn max_id(&self, table: &str) -> Result<i64> {
        let row = self
            .backend
            .query_opt(&format!("SELECT COALESCE(MAX(id), 0) FROM {table}"), &[])
            .await?
            .context("COALESCE(MAX(id), 0) returned no row")?;
        row.get(0)
    }
}
