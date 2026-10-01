//! Trusted compiled SQLite definitions for isolated Native constraint replay.
//!
//! Construction compiles the production schema in disposable memory and admits
//! its exact classification. No source/archive SQL, source rows or runtime
//! initialization is accepted. These definitions authorize no restore effects.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

use super::{compiled_schema_for_generation, SqliteSnapshotSchema};
use crate::db::{snapshot_schema_identity, MIGRATIONS};
use crate::snapshot::{SnapshotClassifier, SnapshotSchemaManifest};

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
    manifest: SnapshotSchemaManifest,
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
        Self::load_generation(MIGRATIONS.len()).await
    }

    /// Compiles exactly a supported historical or current schema from trusted DDL.
    ///
    /// This factory authenticates no archive. Callers select the returned
    /// catalogue only after its exact manifest matches authenticated headers.
    /// No archive SQL or source rows influence compilation.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown generations, changed hashes or invalid DDL.
    pub async fn load_generation(version: usize) -> Result<Self> {
        Self::load_inner(version)
            .await
            .map_err(|_| anyhow::anyhow!("snapshot compiled replay catalogue is unavailable"))
    }

    async fn load_inner(version: usize) -> Result<Self> {
        let (objects, tables) = compiled_schema_for_generation(version).await?;
        let schema = SqliteSnapshotSchema {
            identity: snapshot_schema_identity(version)?.into(),
            version,
            migration_digests: MIGRATIONS
                .get(..version)
                .ok_or_else(|| anyhow::anyhow!("snapshot compiled generation is absent"))?
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
            manifest: classifier.manifest().clone(),
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

    /// Borrows the exact compiled classifier commitment for header comparison.
    pub fn schema_manifest(&self) -> &SnapshotSchemaManifest {
        &self.manifest
    }

    /// Returns a table's exact compiled disposition without exposing its policy.
    pub fn disposition(&self, table: &str) -> Option<CompiledSqliteSnapshotDisposition> {
        self.dispositions.get(table).copied()
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    #[tokio::test]
    async fn historical_replay_uses_historical_ddl_and_refuses_unknown_generations() {
        let historical = CompiledSqliteSnapshotCatalogue::load_generation(3)
            .await
            .unwrap();
        let generation4 = CompiledSqliteSnapshotCatalogue::load_generation(4)
            .await
            .unwrap();
        let generation5 = CompiledSqliteSnapshotCatalogue::load_generation(5)
            .await
            .unwrap();
        let generation6 = CompiledSqliteSnapshotCatalogue::load_generation(6)
            .await
            .unwrap();
        let current = CompiledSqliteSnapshotCatalogue::load_generation(7)
            .await
            .unwrap();

        assert_eq!(historical.schema().tables.len(), 267);
        assert_eq!(generation4.schema().tables.len(), 275);
        assert_eq!(generation6.schema().tables.len(), 276);
        assert_eq!(current.schema().tables.len(), 278);
        assert!(!generation4
            .definitions()
            .iter()
            .any(|value| value.name() == "mirror_import_objects"));
        assert!(current
            .definitions()
            .iter()
            .any(|value| value.name() == "mirror_import_objects"));
        assert_eq!(generation4.schema_manifest().migration_digests.len(), 4);
        assert_eq!(generation5.schema_manifest().migration_digests.len(), 5);
        assert_eq!(generation6.schema_manifest().migration_digests.len(), 6);
        assert_eq!(current.schema_manifest().migration_digests.len(), 7);
        let mirror_columns = |catalogue: &CompiledSqliteSnapshotCatalogue| {
            catalogue
                .schema()
                .tables
                .iter()
                .find(|table| table.name == "mirror_import_objects")
                .unwrap()
                .columns
                .len()
        };
        assert_eq!(mirror_columns(&generation5), 9);
        assert_eq!(mirror_columns(&generation6), 12);
        assert_eq!(mirror_columns(&current), 13);
        assert!(!historical
            .definitions()
            .iter()
            .any(|value| value.name() == "direct_upload_sessions"));
        assert!(current
            .definitions()
            .iter()
            .any(|value| value.name() == "direct_upload_sessions"));
        let config = |catalogue: &CompiledSqliteSnapshotCatalogue| {
            catalogue
                .schema()
                .tables
                .iter()
                .find(|table| table.name == "oci_image_config_projections")
                .unwrap()
                .columns
                .clone()
        };
        assert!(!config(&historical).contains(&"config_representation".to_owned()));
        assert!(config(&current).contains(&"config_representation".to_owned()));
        assert_eq!(historical.schema_manifest().version, 3);
        assert_eq!(historical.schema_manifest().migration_digests.len(), 3);
        assert!(CompiledSqliteSnapshotCatalogue::load_generation(9)
            .await
            .is_err());
    }
}
