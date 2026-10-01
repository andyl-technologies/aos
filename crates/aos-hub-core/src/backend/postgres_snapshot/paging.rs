//! Length-first pages over internal heap locators in one held PostgreSQL snapshot.

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row as _, Transaction, TypeInfo, ValueRef};

use super::super::sqlite_snapshot::SqliteSnapshotLimits;
use super::{quote, refresh_timeout, SqliteSnapshotPage, SqliteSnapshotTableSchema};
use crate::value::{Row, Value};

/// A cursor borrowing the reader's pinned, read-only transaction.
///
/// Its physical `ctid` boundary never becomes a logical archive identifier.
/// ACCESS SHARE held by the reader prevents heap rewrite; REPEATABLE READ keeps
/// original tuple versions visible through ordinary mutation and VACUUM.
pub struct PostgresSnapshotTable<'a> {
    transaction: &'a mut Transaction<'static, Postgres>,
    schema: SqliteSnapshotTableSchema,
    last_locator: Option<String>,
    deadline: Instant,
    statement_timeout: Duration,
    finished: bool,
}

impl<'a> PostgresSnapshotTable<'a> {
    pub(super) fn new(
        transaction: &'a mut Transaction<'static, Postgres>,
        schema: SqliteSnapshotTableSchema,
        deadline: Instant,
        statement_timeout: Duration,
    ) -> Self {
        Self {
            transaction,
            schema,
            deadline,
            statement_timeout,
            last_locator: None,
            finished: false,
        }
    }

    #[cfg(test)]
    pub(super) fn last_locator_for_test(&self) -> Option<&str> {
        self.last_locator.as_deref()
    }

    /// Borrows the compiled logical column order.
    pub fn schema(&self) -> &SqliteSnapshotTableSchema {
        &self.schema
    }

    /// Fetches one page after checking all cell lengths before value allocation.
    ///
    /// # Errors
    ///
    /// Rejects invalid budgets, oversized cells/rows, unsupported SQL types,
    /// inconsistent tuple coverage, source/lock deadlines and SQL failures.
    pub async fn next_page(&mut self, limits: SqliteSnapshotLimits) -> Result<SqliteSnapshotPage> {
        self.next_inner(limits)
            .await
            .map_err(|_| anyhow::anyhow!("PostgreSQL snapshot page refused"))
    }

    async fn next_inner(&mut self, limits: SqliteSnapshotLimits) -> Result<SqliteSnapshotPage> {
        ensure!(
            (1..=256).contains(&limits.max_rows)
                && (8..=1_048_576).contains(&limits.max_cell_bytes)
                && (8..=8_388_608).contains(&limits.max_page_bytes),
            "invalid snapshot page limits"
        );
        refresh_timeout(self.transaction, self.deadline, self.statement_timeout).await?;
        if self.finished {
            return Ok(SqliteSnapshotPage {
                rows: Vec::new(),
                payload_bytes: 0,
                finished: true,
            });
        }
        let table = format!("public.{}", quote(&self.schema.name));
        let columns = self
            .schema
            .columns
            .iter()
            .map(|column| quote(column))
            .collect::<Vec<_>>();
        // The admitted finite catalogue determines native types. CASE branches
        // must remain type-correct even when their values are never selected.
        let types = sqlx::query(
            "SELECT a.attname, t.typname FROM pg_catalog.pg_attribute a \
            JOIN pg_catalog.pg_type t ON t.oid=a.atttypid WHERE a.attrelid=$1::regclass \
            AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",
        )
        .bind(&table)
        .fetch_all(&mut **self.transaction)
        .await?;
        ensure!(types.len() == columns.len(), "column type count differs");
        let sizes = types
            .iter()
            .zip(&columns)
            .map(|(row, column)| -> Result<String> {
                let name: String = row.try_get(1)?;
                ensure!(
                    matches!(
                        name.as_str(),
                        "int8" | "int4" | "int2" | "text" | "varchar" | "bytea"
                    ),
                    "unsupported column type"
                );
                let length = if matches!(name.as_str(), "int8" | "int4" | "int2") {
                    "8".to_owned()
                } else {
                    format!("octet_length({column})")
                };
                Ok(format!(
                    "CASE WHEN {column} IS NULL THEN 0 ELSE {length} END::bigint"
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let lower = if self.last_locator.is_some() {
            "WHERE source_row.ctid > $1::text::tid"
        } else {
            "WHERE $1::text IS NULL"
        };
        // ORDER BY must name the physical tid, not its text projection: the
        // latter sorts offset 10 before 9 and admits a different value range.
        let metadata = sqlx::query(&format!(
            "SELECT source_row.ctid::text AS snapshot_locator, {} FROM {table} AS source_row \
             {lower} ORDER BY source_row.ctid LIMIT $2",
            sizes.join(", ")
        ))
        .bind(&self.last_locator)
        .bind(i64::try_from(limits.max_rows)?)
        .fetch_all(&mut **self.transaction)
        .await?;
        let mut payload_bytes = 0_usize;
        let mut count = 0_usize;
        for row in &metadata {
            let mut row_bytes = 0_usize;
            for column in 1..row.len() {
                let size = usize::try_from(row.try_get::<i64, _>(column)?)?;
                ensure!(
                    size <= limits.max_cell_bytes,
                    "snapshot cell exceeds its budget"
                );
                row_bytes = row_bytes
                    .checked_add(size)
                    .ok_or_else(|| anyhow::anyhow!("row size overflow"))?;
            }
            let next = payload_bytes
                .checked_add(row_bytes)
                .ok_or_else(|| anyhow::anyhow!("page size overflow"))?;
            if next > limits.max_page_bytes {
                ensure!(count > 0, "first row exceeds page budget");
                break;
            }
            count += 1;
            payload_bytes = next;
        }
        let Some(last) = metadata.get(count.saturating_sub(1)).filter(|_| count > 0) else {
            self.finished = true;
            return Ok(SqliteSnapshotPage {
                rows: Vec::new(),
                payload_bytes: 0,
                finished: true,
            });
        };
        let last_locator: String = last.try_get(0)?;
        refresh_timeout(self.transaction, self.deadline, self.statement_timeout).await?;
        let rows = sqlx::query(&format!(
            "SELECT {} FROM {table} AS source_row \
             WHERE ($1::text IS NULL OR source_row.ctid>$1::text::tid) \
             AND source_row.ctid<=$2::text::tid ORDER BY source_row.ctid",
            columns.join(", ")
        ))
        .bind(&self.last_locator)
        .bind(&last_locator)
        .fetch_all(&mut **self.transaction)
        .await?;
        ensure!(rows.len() == count, "held snapshot tuple coverage differs");
        let rows = rows.iter().map(decode).collect::<Result<Vec<_>>>()?;
        self.last_locator = Some(last_locator);
        self.finished = count == metadata.len() && metadata.len() < limits.max_rows;
        Ok(SqliteSnapshotPage {
            rows,
            payload_bytes,
            finished: self.finished,
        })
    }
}

fn decode(row: &PgRow) -> Result<Row> {
    let mut values = Vec::with_capacity(row.len());
    for index in 0..row.len() {
        let raw = row.try_get_raw(index)?;
        let value = if raw.is_null() {
            Value::Null
        } else {
            match raw.type_info().name() {
                "INT8" => Value::Int(row.try_get::<i64, _>(index)?),
                "INT4" => Value::Int(i64::from(row.try_get::<i32, _>(index)?)),
                "INT2" => Value::Int(i64::from(row.try_get::<i16, _>(index)?)),
                "TEXT" | "VARCHAR" => Value::Text(row.try_get(index)?),
                "BYTEA" => Value::Bytes(row.try_get(index)?),
                _ => anyhow::bail!("unsupported snapshot value type"),
            }
        };
        values.push(value);
    }
    Ok(Row::new(values))
}
