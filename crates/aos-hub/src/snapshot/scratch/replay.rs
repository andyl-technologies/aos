//! Exact typed row insertion and final constraint checks in disposable memory.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Read;

use aos_hub_core::backend::sqlite_snapshot::{
    CompiledSqliteSnapshotCatalogue, CompiledSqliteSnapshotDisposition as Disposition,
    CompiledSqliteSnapshotObjectKind as ObjectKind,
};
use aos_hub_core::snapshot::archive::records::{
    VerifiedDatabaseCaptureRecords, verify_database_capture_with_schema,
};
use aos_hub_core::value::{Row, Value};
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Connection, ToSql};

use super::budget::WorkBudget;
use super::{
    ScratchResult, ScratchVerificationError as Failure, ScratchVerificationInputs,
    ScratchVerificationLimits, VerifiedRetainedSqliteCapture,
};

const PAGE_BYTES: u64 = 4096;

mod direct_presence;
mod lifetimes;

pub(super) fn verify<M: Read, P: Read>(
    inputs: ScratchVerificationInputs<M, P>,
    catalogues: [CompiledSqliteSnapshotCatalogue; 6],
    limits: ScratchVerificationLimits,
    budget: WorkBudget,
    projection: Option<Box<dyn super::ScratchProjection>>,
) -> ScratchResult<VerifiedRetainedSqliteCapture> {
    let scratch = RefCell::new(None::<MemoryReplay>);
    let projection = RefCell::new(projection);
    let failure = Cell::new(None::<Failure>);
    let mut candidates = Some(catalogues);
    let records = verify_database_capture_with_schema(
        &inputs.root,
        &inputs.trust,
        &inputs.wrapping,
        &inputs.exclusions,
        inputs.metadata,
        inputs.private,
        limits.streams,
        |manifest| {
            let result = (|| -> ScratchResult<()> {
                if let Some(observer) = projection
                    .try_borrow_mut()
                    .map_err(|_| Failure::Schema)?
                    .as_mut()
                {
                    observer.schema(manifest).map_err(|_| Failure::Schema)?;
                }
                let catalogue = candidates
                    .take()
                    .and_then(|values| {
                        values
                            .into_iter()
                            .find(|value| value.schema_manifest() == manifest)
                    })
                    .ok_or(Failure::Schema)?;
                let mut slot = scratch.try_borrow_mut().map_err(|_| Failure::Schema)?;
                if slot.is_some() {
                    return Err(Failure::Schema);
                }
                *slot = Some(MemoryReplay::new(catalogue, limits, budget.clone())?);
                Ok(())
            })();
            result.map_err(|error| {
                failure.set(Some(error));
                anyhow::anyhow!("snapshot scratch schema rejected")
            })
        },
        |name, sequence, row| {
            let result = (|| -> ScratchResult<()> {
                let mut slot = scratch.try_borrow_mut().map_err(|_| Failure::RetainedRow)?;
                let current = slot.as_mut().ok_or(Failure::Schema)?;
                row.with_private_row(|row| {
                    current.insert(name, sequence, row)?;
                    if let Some(observer) = projection
                        .try_borrow_mut()
                        .map_err(|_| Failure::RetainedRow)?
                        .as_mut()
                    {
                        observer
                            .row(name, sequence, row)
                            .map_err(|_| Failure::RetainedRow)?;
                    }
                    Ok(())
                })
            })();
            result.map_err(|error| {
                failure.set(Some(error));
                anyhow::anyhow!("snapshot scratch row rejected")
            })
        },
    );
    let records = records.map_err(|_| budget.error_or(failure.get().unwrap_or(Failure::Records)));
    let Some(mut scratch) = scratch.into_inner() else {
        return Err(records.err().unwrap_or(Failure::Schema));
    };
    let result = records.and_then(|records| scratch.finish(records));
    scratch.destroy()?;
    result
}

struct RetainedTable {
    insert: String,
    readback: String,
    primary_columns: Vec<usize>,
    column_count: usize,
    rows: u64,
}

struct MemoryReplay {
    connection: Option<Connection>,
    catalogue: CompiledSqliteSnapshotCatalogue,
    tables: BTreeMap<String, RetainedTable>,
    retained_rows: u64,
    value_bytes: u64,
    limits: ScratchVerificationLimits,
    budget: WorkBudget,
}

impl MemoryReplay {
    fn new(
        catalogue: CompiledSqliteSnapshotCatalogue,
        limits: ScratchVerificationLimits,
        budget: WorkBudget,
    ) -> ScratchResult<Self> {
        budget.check()?;
        let connection =
            Connection::open_in_memory().map_err(|_| budget.error_or(Failure::Schema))?;
        let observer = budget.clone();
        connection.progress_handler(1000, Some(move || observer.interrupt()));
        connection.set_prepared_statement_cache_capacity(2);

        let mut scratch = Self {
            connection: Some(connection),
            catalogue,
            tables: BTreeMap::new(),
            retained_rows: 0,
            value_bytes: 0,
            limits,
            budget,
        };
        scratch.configure()?;
        scratch.create_schema()?;
        scratch.require_exact_catalogue()?;
        scratch.prepare_tables()?;
        scratch.seed_lineage_only()?;
        scratch.execute("BEGIN; PRAGMA defer_foreign_keys=ON", Failure::Schema)?;
        if scratch.scalar("PRAGMA defer_foreign_keys", Failure::Schema)? != 1 {
            return Err(Failure::Schema);
        }
        Ok(scratch)
    }

    fn connection(&self) -> ScratchResult<&Connection> {
        self.connection.as_ref().ok_or(Failure::Cleanup)
    }

    fn execute(&self, sql: &str, fallback: Failure) -> ScratchResult<()> {
        self.budget.check()?;
        self.connection()?
            .execute_batch(sql)
            .map_err(|error| self.sql_failure(&error, fallback))?;
        self.budget.check()
    }

    fn scalar(&self, sql: &str, fallback: Failure) -> ScratchResult<i64> {
        self.budget.check()?;
        let value = self
            .connection()?
            .query_row(sql, [], |row| row.get(0))
            .map_err(|error| self.sql_failure(&error, fallback))?;
        self.budget.check()?;
        Ok(value)
    }

    fn sql_failure(&self, error: &rusqlite::Error, fallback: Failure) -> Failure {
        let resource = matches!(
            error,
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(code.code, rusqlite::ErrorCode::DiskFull | rusqlite::ErrorCode::OutOfMemory)
        );
        self.budget
            .error_or(if resource { Failure::Limits } else { fallback })
    }

    fn configure(&self) -> ScratchResult<()> {
        self.execute(
            "PRAGMA page_size=4096; PRAGMA foreign_keys=ON;
             PRAGMA ignore_check_constraints=OFF; PRAGMA temp_store=MEMORY;
             PRAGMA journal_mode=MEMORY; PRAGMA cache_size=-2048",
            Failure::Schema,
        )?;
        let page_limit = self.limits.max_database_bytes / PAGE_BYTES;
        if self.scalar("PRAGMA page_size", Failure::Schema)? != PAGE_BYTES as i64
            || self.scalar("PRAGMA foreign_keys", Failure::Schema)? != 1
            || self.scalar("PRAGMA ignore_check_constraints", Failure::Schema)? != 0
            || self.scalar("PRAGMA temp_store", Failure::Schema)? != 2
            || self.scalar(
                &format!("PRAGMA max_page_count={page_limit}"),
                Failure::Schema,
            )? != page_limit as i64
        {
            return Err(Failure::Schema);
        }
        Ok(())
    }

    fn create_schema(&self) -> ScratchResult<()> {
        // Catalogue objects are generated from compiled DDL. Template seed
        // rows are deliberately absent, so no captured defaults are duplicated.
        for kind in [ObjectKind::Table, ObjectKind::Index, ObjectKind::View] {
            for definition in self.catalogue.definitions() {
                if definition.kind() == kind {
                    if let Some(sql) = definition.sql() {
                        self.execute(sql, Failure::Schema)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn require_exact_catalogue(&self) -> ScratchResult<()> {
        self.budget.check()?;
        let mut statement = self
            .connection()?
            .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
            .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
        let mut rows = statement
            .query([])
            .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
        for definition in self.catalogue.definitions() {
            self.budget.check()?;
            let row = rows
                .next()
                .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                .ok_or(Failure::Schema)?;
            let kind: String = row
                .get(0)
                .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
            let expected_kind = match definition.kind() {
                ObjectKind::Table => "table",
                ObjectKind::Index => "index",
                ObjectKind::View => "view",
            };
            if kind != expected_kind
                || row
                    .get::<_, String>(1)
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                    != definition.name()
                || row
                    .get::<_, String>(2)
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                    != definition.table()
                || row
                    .get::<_, Option<String>>(3)
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                    .as_deref()
                    != definition.sql()
            {
                return Err(Failure::Schema);
            }
        }
        if rows
            .next()
            .map_err(|error| self.sql_failure(&error, Failure::Schema))?
            .is_some()
        {
            return Err(Failure::Schema);
        }
        self.budget.check()
    }

    fn prepare_tables(&mut self) -> ScratchResult<()> {
        for table in &self.catalogue.schema().tables {
            self.budget.check()?;
            let mut info = self
                .connection()?
                .prepare(&format!("PRAGMA table_info({})", identifier(&table.name)))
                .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
            let mut rows = info
                .query([])
                .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
            let mut primary_columns = Vec::new();
            for (index, column) in table.columns.iter().enumerate() {
                let row = rows
                    .next()
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                    .ok_or(Failure::Schema)?;
                if row
                    .get::<_, String>(1)
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                    != *column
                {
                    return Err(Failure::Schema);
                }
                if row
                    .get::<_, i64>(5)
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                    > 0
                {
                    primary_columns.push(index);
                }
            }
            if rows
                .next()
                .map_err(|error| self.sql_failure(&error, Failure::Schema))?
                .is_some()
            {
                return Err(Failure::Schema);
            }
            drop(rows);
            drop(info);

            if self.catalogue.disposition(&table.name) == Some(Disposition::Retained) {
                if primary_columns.is_empty() {
                    return Err(Failure::Schema);
                }
                let mut foreign_keys = self
                    .connection()?
                    .prepare(&format!(
                        "PRAGMA foreign_key_list({})",
                        identifier(&table.name)
                    ))
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
                let parents = foreign_keys
                    .query_map([], |row| row.get::<_, String>(2))
                    .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
                for parent in parents {
                    let parent =
                        parent.map_err(|error| self.sql_failure(&error, Failure::Schema))?;
                    if self.catalogue.disposition(&parent) != Some(Disposition::Retained) {
                        return Err(Failure::Schema);
                    }
                }
                drop(foreign_keys);

                let columns = table
                    .columns
                    .iter()
                    .map(|name| identifier(name))
                    .collect::<Vec<_>>()
                    .join(",");
                let parameters = (1..=table.columns.len())
                    .map(|index| format!("?{index}"))
                    .collect::<Vec<_>>()
                    .join(",");
                // The opaque compiled catalogue already rejects WITHOUT ROWID
                // and every rowid/_rowid_/oid shadow before admitting shapes.
                self.tables.insert(
                    table.name.clone(),
                    RetainedTable {
                        insert: format!(
                            "INSERT INTO {} ({columns}) VALUES ({parameters})",
                            identifier(&table.name)
                        ),
                        readback: format!(
                            "SELECT {columns} FROM {} WHERE rowid=?1",
                            identifier(&table.name)
                        ),
                        primary_columns,
                        column_count: table.columns.len(),
                        rows: 0,
                    },
                );
            }
        }
        Ok(())
    }

    fn seed_lineage_only(&self) -> ScratchResult<()> {
        let metadata: Vec<_> = self
            .catalogue
            .schema()
            .tables
            .iter()
            .filter(|table| {
                self.catalogue.disposition(&table.name) == Some(Disposition::SourceMetadata)
            })
            .map(|table| table.name.as_str())
            .collect();
        if metadata != ["hub_schema_identity", "schema_version"] {
            return Err(Failure::Schema);
        }
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO schema_version(version) VALUES (?1)",
                [self.catalogue.schema().version as i64],
            )
            .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
        connection
            .execute(
                "INSERT INTO hub_schema_identity(identity) VALUES (?1)",
                [&self.catalogue.schema().identity],
            )
            .map_err(|error| self.sql_failure(&error, Failure::Schema))?;
        self.budget.check()
    }

    fn insert(&mut self, name: &str, sequence: u64, row: &Row) -> ScratchResult<()> {
        self.budget.check()?;
        let table = self.tables.get(name).ok_or(Failure::RetainedRow)?;
        if sequence != self.retained_rows
            || row.len() != table.column_count
            || self.retained_rows >= self.limits.max_retained_rows
        {
            return Err(if self.retained_rows >= self.limits.max_retained_rows {
                Failure::Limits
            } else {
                Failure::RetainedRow
            });
        }
        let mut parameters = Vec::with_capacity(row.len());
        let mut total = self.value_bytes;
        for index in 0..row.len() {
            let value = row.value(index).ok_or(Failure::RetainedRow)?;
            if matches!(value, Value::Real(_))
                || (table.primary_columns.contains(&index) && value.is_null())
            {
                return Err(Failure::RetainedRow);
            }
            let bytes = match value {
                Value::Null => 0,
                Value::Int(_) => 8,
                Value::Text(text) => text.len() as u64,
                Value::Bytes(bytes) => bytes.len() as u64,
                Value::Real(_) => return Err(Failure::RetainedRow),
            };
            total = total.checked_add(bytes).ok_or(Failure::Limits)?;
            if total > self.limits.max_value_bytes {
                return Err(Failure::Limits);
            }
            parameters.push(Parameter(value));
        }

        let connection = self.connection()?;
        let mut insert = connection
            .prepare_cached(&table.insert)
            .map_err(|error| self.sql_failure(&error, Failure::RetainedRow))?;
        if insert
            .execute(rusqlite::params_from_iter(parameters.iter()))
            .map_err(|error| self.sql_failure(&error, Failure::RetainedRow))?
            != 1
        {
            return Err(Failure::RetainedRow);
        }
        let mut readback = connection
            .prepare_cached(&table.readback)
            .map_err(|error| self.sql_failure(&error, Failure::RetainedRow))?;
        let exact: bool = readback
            .query_row([connection.last_insert_rowid()], |stored| {
                for index in 0..row.len() {
                    let value = row
                        .value(index)
                        .ok_or(rusqlite::Error::InvalidColumnIndex(index))?;
                    if !exact_value(value, stored.get_ref(index)?) {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .map_err(|error| self.sql_failure(&error, Failure::RetainedRow))?;
        if !exact {
            return Err(Failure::RetainedRow);
        }
        drop(readback);
        drop(insert);
        self.budget.check()?;
        self.tables.get_mut(name).ok_or(Failure::RetainedRow)?.rows += 1;
        self.retained_rows += 1;
        self.value_bytes = total;
        Ok(())
    }

    fn finish(
        &mut self,
        records: VerifiedDatabaseCaptureRecords,
    ) -> ScratchResult<VerifiedRetainedSqliteCapture> {
        self.budget.check()?;
        self.budget.begin_final_checks();
        self.final_checks()?;
        if records.counts().retained_rows != self.retained_rows
            || records.counts().tables != self.catalogue.schema().tables.len() as u64
        {
            return Err(Failure::Constraints);
        }
        Ok(VerifiedRetainedSqliteCapture {
            records,
            checked_tables: self.tables.len(),
        })
    }

    fn final_checks(&self) -> ScratchResult<()> {
        self.lifetime_checks()?;
        let integrity = self.scalar(
            "SELECT CASE WHEN COUNT(*)=1 AND COALESCE(MAX(integrity_check='ok' COLLATE BINARY),0)=1 THEN 1 ELSE 0 END
             FROM (SELECT integrity_check FROM pragma_integrity_check LIMIT 2)", Failure::Constraints)?;
        if integrity != 1
            || self.scalar(
                "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check LIMIT 1)",
                Failure::Constraints,
            )? != 0
        {
            return Err(Failure::Constraints);
        }
        for table in &self.catalogue.schema().tables {
            let actual = self.scalar(
                &format!("SELECT COUNT(*) FROM {}", identifier(&table.name)),
                Failure::Constraints,
            )?;
            let expected = match self.catalogue.disposition(&table.name) {
                Some(Disposition::Retained) => {
                    self.tables
                        .get(&table.name)
                        .ok_or(Failure::Constraints)?
                        .rows
                }
                Some(Disposition::AuthTransient) => 0,
                Some(Disposition::SourceMetadata) => 1,
                None => return Err(Failure::Constraints),
            };
            if u64::try_from(actual).ok() != Some(expected) {
                return Err(Failure::Constraints);
            }
        }
        let identity_ok: bool = self
            .connection()?
            .query_row(
                "SELECT identity=?1 COLLATE BINARY FROM hub_schema_identity",
                [&self.catalogue.schema().identity],
                |row| row.get(0),
            )
            .map_err(|error| self.sql_failure(&error, Failure::Constraints))?;
        if !identity_ok
            || self.scalar("SELECT version FROM schema_version", Failure::Constraints)?
                != self.catalogue.schema().version as i64
        {
            return Err(Failure::Constraints);
        }
        self.budget.check()
    }

    fn destroy(&mut self) -> ScratchResult<()> {
        let connection = self.connection.take().ok_or(Failure::Cleanup)?;
        connection.progress_handler(0, None::<fn() -> bool>);
        if !connection.is_autocommit() {
            connection
                .execute_batch("ROLLBACK")
                .map_err(|_| Failure::Cleanup)?;
        }
        connection.close().map_err(|_| Failure::Cleanup)?;
        self.budget.cleaned();
        Ok(())
    }
}

impl Drop for MemoryReplay {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.progress_handler(0, None::<fn() -> bool>);
            drop(connection);
        }
        self.budget.cleaned();
    }
}

struct Parameter<'a>(&'a Value);

impl ToSql for Parameter<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let borrowed = match self.0 {
            Value::Null => ValueRef::Null,
            Value::Int(value) => ValueRef::Integer(*value),
            Value::Text(value) => ValueRef::Text(value.as_bytes()),
            Value::Bytes(value) => ValueRef::Blob(value),
            Value::Real(_) => {
                return Err(rusqlite::Error::InvalidParameterName(
                    "unsupported snapshot scalar".into(),
                ));
            }
        };
        Ok(ToSqlOutput::Borrowed(borrowed))
    }
}

fn exact_value(expected: &Value, stored: ValueRef<'_>) -> bool {
    match (expected, stored) {
        (Value::Null, ValueRef::Null) => true,
        (Value::Int(expected), ValueRef::Integer(stored)) => *expected == stored,
        (Value::Text(expected), ValueRef::Text(stored)) => expected.as_bytes() == stored,
        (Value::Bytes(expected), ValueRef::Blob(stored)) => expected.as_slice() == stored,
        _ => false,
    }
}

fn identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exact_compiled_corpus_has_no_seeds_triggers_or_retained_to_omitted_fks() {
        let catalogue = CompiledSqliteSnapshotCatalogue::load().await.unwrap();
        assert_eq!(catalogue.schema().tables.len(), 279);
        let limits = ScratchVerificationLimits::default();
        let budget = WorkBudget::new(limits, Default::default(), Default::default()).unwrap();
        // Construction traverses EVERY retained FK, fails unknown dispositions
        // and rejects unsupported kinds before any archive row is consumed.
        let mut scratch = MemoryReplay::new(catalogue, limits, budget).unwrap();
        assert_eq!(scratch.tables.len(), 269);
        assert_eq!(scratch.retained_rows, 0);
        for table in &scratch.catalogue.schema().tables {
            let count = scratch
                .scalar(
                    &format!("SELECT COUNT(*) FROM {}", identifier(&table.name)),
                    Failure::Schema,
                )
                .unwrap();
            assert_eq!(
                count,
                if scratch.catalogue.disposition(&table.name) == Some(Disposition::SourceMetadata) {
                    1
                } else {
                    0
                }
            );
        }
        scratch.destroy().unwrap();
        assert!(scratch.connection.is_none());
    }

    #[test]
    fn typed_binding_and_readback_preserve_original_storage_classes_and_payloads() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE scalars(value)")
            .unwrap();
        for value in [
            Value::Null,
            Value::Int(i64::MIN),
            Value::Int(i64::MAX),
            Value::Text("☃\0tail".into()),
            Value::Bytes(vec![0, 255, 1, 0]),
        ] {
            connection
                .execute(
                    "INSERT INTO scalars(value) VALUES (?1)",
                    [Parameter(&value)],
                )
                .unwrap();
            let exact = connection
                .query_row(
                    "SELECT value FROM scalars WHERE rowid=?1",
                    [connection.last_insert_rowid()],
                    |row| Ok(exact_value(&value, row.get_ref(0)?)),
                )
                .unwrap();
            assert!(exact);
        }
        assert!(!exact_value(&Value::Int(7), ValueRef::Text(b"7")));
        assert!(!exact_value(&Value::Text("7".into()), ValueRef::Integer(7)));
        assert!(!exact_value(&Value::Bytes(vec![55]), ValueRef::Text(b"7")));
        assert!(Parameter(&Value::Real(0.5)).to_sql().is_err());
    }
}
