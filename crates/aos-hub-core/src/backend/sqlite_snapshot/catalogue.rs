//! Trusted compiled SQLite definitions for isolated Native constraint replay.
//!
//! Construction compiles the production schema in disposable memory and admits
//! its exact classification. No source/archive SQL, source rows or runtime
//! initialization is accepted. These definitions authorize no restore effects.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

use super::{compiled_schema, SqliteSnapshotSchema};
use crate::db::{MIGRATIONS, SCHEMA_IDENTITY};
use crate::snapshot::SnapshotClassifier;

/// A supported object kind in the independently compiled SQLite catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSqliteSnapshotObjectKind {
    /// An ordinary table, including the production lineage tables.
    Table,
    /// An explicit index or SQLite-generated constraint autoindex.
    Index,
    /// A compiled view whose definition contains no archive input.
    View,
}

/// The exact compiled classification of one table, including empty tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSqliteSnapshotDisposition {
    /// Original rows are retained and must be reconstructed exactly.
    Retained,
    /// Authentication ceremony state is omitted and must remain empty.
    AuthTransient,
    /// Source lineage rows are represented by the verified schema contract.
    SourceMetadata,
}

/// An immutable definition admitted only through the compiled catalogue factory.
///
/// No public constructor, deserializer or mutable SQL accessor is supplied.
pub struct CompiledSqliteSnapshotDefinition {
    kind: CompiledSqliteSnapshotObjectKind,
    name: String,
    table: String,
    sql: Option<String>,
}

impl CompiledSqliteSnapshotDefinition {
    /// Returns the closed supported object kind.
    pub fn kind(&self) -> CompiledSqliteSnapshotObjectKind {
        self.kind
    }

    /// Borrows the compiler-selected object identifier.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrows the compiler-selected owning table identifier.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Borrows normalized compiled DDL, absent only for generated autoindexes.
    pub fn sql(&self) -> Option<&str> {
        self.sql.as_deref()
    }
}

/// An opaque Native catalogue loaded from the exact compiled schema and policy.
///
/// It contains definitions only, never template seeds or source/private values.
/// Borrowed accessors cannot manufacture a caller-selected catalogue for replay.
pub struct CompiledSqliteSnapshotCatalogue {
    definitions: Vec<CompiledSqliteSnapshotDefinition>,
    schema: SqliteSnapshotSchema,
    dispositions: BTreeMap<String, CompiledSqliteSnapshotDisposition>,
}

impl fmt::Debug for CompiledSqliteSnapshotCatalogue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledSqliteSnapshotCatalogue { <compiled definitions only> }")
    }
}

impl CompiledSqliteSnapshotCatalogue {
    /// Compiles and classifies the trusted production schema in disposable memory.
    ///
    /// This uses the existing disposable compiled-schema initializer. It opens
    /// no source database or serving/auth/provider runtime and returns no template
    /// seed rows. Rowid shadowing and WITHOUT ROWID tables are rejected before
    /// shapes are admitted.
    ///
    /// # Errors
    ///
    /// Rejects unavailable compilation, unclassified shapes or unsupported
    /// triggers/system/virtual objects. Errors omit underlying SQL diagnostics.
    pub async fn load() -> Result<Self> {
        Self::load_inner()
            .await
            .map_err(|_| anyhow::anyhow!("snapshot compiled replay catalogue is unavailable"))
    }

    async fn load_inner() -> Result<Self> {
        let (objects, tables) = compiled_schema().await?;
        let schema = SqliteSnapshotSchema {
            identity: SCHEMA_IDENTITY.into(),
            version: MIGRATIONS.len(),
            migration_digests: MIGRATIONS
                .iter()
                .map(|script| hex::encode(Sha256::digest(script.as_bytes())))
                .collect(),
            tables,
        };
        let classifier = SnapshotClassifier::from_sqlite_schema(&schema)?;
        let mut dispositions = BTreeMap::new();
        for table in &schema.tables {
            let disposition = match classifier.table_disposition(&table.name)? {
                "retain" => CompiledSqliteSnapshotDisposition::Retained,
                "auth_transient" => CompiledSqliteSnapshotDisposition::AuthTransient,
                "source_metadata" => CompiledSqliteSnapshotDisposition::SourceMetadata,
                _ => anyhow::bail!("unsupported snapshot disposition"),
            };
            dispositions.insert(table.name.clone(), disposition);
        }

        let mut definitions = Vec::with_capacity(objects.len());
        for object in objects {
            let kind = match object.kind.as_str() {
                "table" => {
                    ensure!(
                        !object.name.starts_with("sqlite_")
                            && object.sql.as_ref().is_some_and(|sql| {
                                sql.trim_start()
                                    .to_ascii_uppercase()
                                    .starts_with("CREATE TABLE ")
                            }),
                        "unsupported snapshot table definition"
                    );
                    CompiledSqliteSnapshotObjectKind::Table
                }
                "index" => {
                    ensure!(
                        object.sql.is_some() || object.name.starts_with("sqlite_autoindex_"),
                        "unsupported snapshot index definition"
                    );
                    CompiledSqliteSnapshotObjectKind::Index
                }
                "view" => {
                    ensure!(object.sql.is_some(), "missing snapshot view definition");
                    CompiledSqliteSnapshotObjectKind::View
                }
                _ => anyhow::bail!("unsupported snapshot object definition"),
            };
            definitions.push(CompiledSqliteSnapshotDefinition {
                kind,
                name: object.name,
                table: object.table,
                sql: object.sql,
            });
        }
        Ok(Self {
            definitions,
            schema,
            dispositions,
        })
    }

    /// Borrows exact normalized definitions selected by the compiled factory.
    pub fn definitions(&self) -> &[CompiledSqliteSnapshotDefinition] {
        &self.definitions
    }

    /// Borrows validated lineage and source-order table/column metadata.
    pub fn schema(&self) -> &SqliteSnapshotSchema {
        &self.schema
    }

    /// Returns a table's exact compiled disposition without exposing its policy.
    pub fn disposition(&self, table: &str) -> Option<CompiledSqliteSnapshotDisposition> {
        self.dispositions.get(table).copied()
    }
}
