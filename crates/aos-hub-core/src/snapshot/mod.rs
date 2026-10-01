//! Current-schema row classification for a future logical Hub snapshot.
//!
//! This module owns an exhaustive table/column contract, lossless archive
//! scalars, and private exact-cell dependency manifests. Classified metadata
//! excludes secret and opaque private originals; the explicit private capture
//! seam can pair and revalidate them one bounded row at a time. No database,
//! file, provider, or import operation occurs here.
//!
//! A classified database is incomplete until private originals are matched to
//! every dependency. This seam neither authorizes provider access nor
//! adopts a guard namespace. Source authority rows and replay fences survive
//! unchanged; transient authentication state is explicitly omitted. Subsequent
//! export must authenticate the artifact and reconcile foreign keys, object
//! closure, private dependencies, and activation before any import may serve.
//!
//! ```json
//! {"kind":"integer","value":"9223372036854775807"}
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::{snapshot_schema_identity, MIGRATIONS, SCHEMA_IDENTITY};
use crate::value::{Row, Value};

pub mod archive;
pub mod inventory;

mod capture;
mod direct;
mod json;
mod lifetimes;
mod mirror;

pub use capture::{CapturedSnapshotRow, PrivateSnapshotCell, ReconstructedSnapshotRow};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "tests/capture.rs"]
mod capture_tests;

const CLASSIFICATION_VERSION: &str = "aos-hub.snapshot-classification/v1";
const LEGACY_CONTRACT: &str = include_str!("schema-v3.tsv");
const GENERATION4_CONTRACT: &str = include_str!("schema-v4.tsv");
const GENERATION5_CONTRACT: &str = include_str!("schema-v5.tsv");
const GENERATION6_CONTRACT: &str = include_str!("schema-v6.tsv");
const GENERATION7_CONTRACT: &str = include_str!("schema-v7.tsv");
const CONTRACT: &str = include_str!("schema-v8.tsv");
const LEGACY_CONTRACT_MIGRATION_DIGESTS: &[&str] = &[
    "ac60f004a8c71ad9aaf5169a3497a40cbd886648eedee5394da9bc7cbd72e061",
    "8da079db002b25543fc856e9cc57f335e67a73b3272c9a339ef8cc66c65ae51d",
    "1378ed62ac1a61f2abaf960d64a4617bdf523a437dcf326f3cb083f7e75ccdb1",
];
const GENERATION4_MIGRATION_DIGESTS: &[&str] = &[
    "ac60f004a8c71ad9aaf5169a3497a40cbd886648eedee5394da9bc7cbd72e061",
    "8da079db002b25543fc856e9cc57f335e67a73b3272c9a339ef8cc66c65ae51d",
    "1378ed62ac1a61f2abaf960d64a4617bdf523a437dcf326f3cb083f7e75ccdb1",
    "aed8c7be101fe114a4b989184d79c5224fb27ba0b1065b881f1a0779b71d09c3",
];
const GENERATION5_MIGRATION_DIGESTS: &[&str] = &[
    "ac60f004a8c71ad9aaf5169a3497a40cbd886648eedee5394da9bc7cbd72e061",
    "8da079db002b25543fc856e9cc57f335e67a73b3272c9a339ef8cc66c65ae51d",
    "1378ed62ac1a61f2abaf960d64a4617bdf523a437dcf326f3cb083f7e75ccdb1",
    "aed8c7be101fe114a4b989184d79c5224fb27ba0b1065b881f1a0779b71d09c3",
    "a65b54c031446a5960de39354623d8e9ce22bc116ce3f735ae065cf96d54faf4",
];
const GENERATION6_MIGRATION_DIGESTS: &[&str] = &[
    "ac60f004a8c71ad9aaf5169a3497a40cbd886648eedee5394da9bc7cbd72e061",
    "8da079db002b25543fc856e9cc57f335e67a73b3272c9a339ef8cc66c65ae51d",
    "1378ed62ac1a61f2abaf960d64a4617bdf523a437dcf326f3cb083f7e75ccdb1",
    "aed8c7be101fe114a4b989184d79c5224fb27ba0b1065b881f1a0779b71d09c3",
    "a65b54c031446a5960de39354623d8e9ce22bc116ce3f735ae065cf96d54faf4",
    "24ad86fc4c15974cdacbb0d3f1374c7b2061778777e97fa78e0fb9673171bc26",
];
const GENERATION7_MIGRATION_DIGESTS: &[&str] = &[
    "ac60f004a8c71ad9aaf5169a3497a40cbd886648eedee5394da9bc7cbd72e061",
    "8da079db002b25543fc856e9cc57f335e67a73b3272c9a339ef8cc66c65ae51d",
    "1378ed62ac1a61f2abaf960d64a4617bdf523a437dcf326f3cb083f7e75ccdb1",
    "aed8c7be101fe114a4b989184d79c5224fb27ba0b1065b881f1a0779b71d09c3",
    "a65b54c031446a5960de39354623d8e9ce22bc116ce3f735ae065cf96d54faf4",
    "24ad86fc4c15974cdacbb0d3f1374c7b2061778777e97fa78e0fb9673171bc26",
    "0053f400c189667dfd0bc59dfc8818d02e2fbc0694d1e4cd9ccbd8d319dd4e93",
];
const CONTRACT_MIGRATION_DIGESTS: &[&str] = &[
    "ac60f004a8c71ad9aaf5169a3497a40cbd886648eedee5394da9bc7cbd72e061",
    "8da079db002b25543fc856e9cc57f335e67a73b3272c9a339ef8cc66c65ae51d",
    "1378ed62ac1a61f2abaf960d64a4617bdf523a437dcf326f3cb083f7e75ccdb1",
    "aed8c7be101fe114a4b989184d79c5224fb27ba0b1065b881f1a0779b71d09c3",
    "a65b54c031446a5960de39354623d8e9ce22bc116ce3f735ae065cf96d54faf4",
    "24ad86fc4c15974cdacbb0d3f1374c7b2061778777e97fa78e0fb9673171bc26",
    "0053f400c189667dfd0bc59dfc8818d02e2fbc0694d1e4cd9ccbd8d319dd4e93",
    "7d9f4b656245f8e533bf497ef1db9854d0371c54e95dd1942d5b615d63fdd7cb",
];

const MAX_CELL_BYTES: usize = 1024 * 1024;
const MAX_ROW_BYTES: usize = 8 * 1024 * 1024;

/// A portable scalar whose integer and byte representations are lossless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SnapshotScalar {
    /// Signed 64-bit integer encoded in decimal, never a JSON number.
    Integer(String),
    /// Finite IEEE-754 bits encoded as sixteen lowercase hexadecimal digits.
    RealBits(String),
    /// Exact valid UTF-8 source text.
    Text(String),
    /// Exact source bytes encoded as lowercase hexadecimal pairs.
    BytesHex(String),
    /// SQL NULL, distinct from empty text and empty bytes.
    Null,
}

/// An archive cell containing either a portable value or a private dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClassifiedCell {
    /// A retained lossless scalar.
    Scalar(SnapshotScalar),
    /// An exact source-cell digest; private bytes are absent from this model.
    External(String),
}

/// Why exact original bytes must be supplied through private restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDependencyReason {
    /// Credential hash, encrypted secret, or secret-bearing immutable document.
    Secret,
    /// Free-form context or binary state conservatively excluded from the archive.
    PrivateContext,
    /// Opaque JSON with no complete portable semantic restoration contract.
    OpaqueJson,
}

/// One exact private cell required before a future restoration can be complete.
///
/// Digests cover type and original bytes; JSON is never rewritten. The primary
/// key digest identifies the exact source row without placing private key cells
/// in a public manifest. This is a checksum, not authentication or encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotPrivateDependency {
    /// Exact classified source table.
    pub table: String,
    /// SHA-256 of the ordered, typed primary-key cells and their column names.
    pub primary_key_digest: String,
    /// Exact source column, not an inferred JSON field locator.
    pub column: String,
    /// SHA-256 of the domain-separated original typed source cell.
    pub cell_digest: String,
    /// Source value payload length in bytes, before hex encoding.
    pub payload_bytes: usize,
    /// Required private restoration category.
    pub reason: PrivateDependencyReason,
}

/// One retained row containing no raw private cell payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassifiedSnapshotRow {
    /// Exact source table name.
    pub table: String,
    /// Cells keyed by exact source column name.
    pub cells: BTreeMap<String, ClassifiedCell>,
    /// Private original cells required for a lossless future import.
    pub private_dependencies: Vec<SnapshotPrivateDependency>,
}

/// Explicit disposition of one schema-covered source row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "disposition", content = "row", rename_all = "snake_case")]
pub enum SnapshotRowDisposition {
    /// Authoritative or derived state retained without dropping leases or fences.
    Retained(ClassifiedSnapshotRow),
    /// Login/session ceremony state requiring fresh authentication on restoration.
    AuthTransient,
    /// Validated source lineage metadata represented by the schema manifest.
    SourceMetadata,
}

/// Exact table and column order supplied by a schema-validating source adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotTableShape {
    /// Exact source table name.
    pub name: String,
    /// Source columns in declared order.
    pub columns: Vec<String>,
}

/// Source lineage and catalogue accepted before any classified row is returned.
///
/// The adapter must validate SQL definitions and metadata singleton contents;
/// this model checks the classification contract and compiled migration hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotSchemaManifest {
    /// Exact version of the row/value classification model.
    pub classification_version: String,
    /// Exact compiled production lineage, never inferred from a migration count.
    pub identity: String,
    /// Exact supported source generation, currently three through eight.
    pub version: usize,
    /// Ordered SHA-256 hashes of the compiled schema scripts.
    pub migration_digests: Vec<String>,
    /// SHA-256 of the complete checked-in classification contract bytes.
    pub classification_digest: String,
}

#[derive(Debug)]
struct ColumnContract {
    name: String,
    storage: String,
    nullable: bool,
    primary_key_ordinal: usize,
    rule: String,
}

#[derive(Debug)]
struct TableContract {
    disposition: String,
    columns: Vec<ColumnContract>,
}

/// Validated current-schema classifier processing at most one bounded row.
pub struct SnapshotClassifier {
    tables: BTreeMap<String, TableContract>,
    manifest: SnapshotSchemaManifest,
}

impl SnapshotClassifier {
    /// Checks lineage, migration hashes, and complete catalogue coverage.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown/incomplete/future lineage, script hashes,
    /// tables, columns, order, or a malformed checked-in classification contract.
    pub fn new(
        identity: &str,
        version: usize,
        migration_digests: &[String],
        shapes: &[SnapshotTableShape],
    ) -> Result<Self> {
        let (document, committed_digests) = generation_contract(version)?;
        let scripts = MIGRATIONS
            .get(..version)
            .ok_or_else(|| anyhow::anyhow!("snapshot compiled generation is absent"))?;
        let expected_digests: Vec<_> = scripts
            .iter()
            .map(|script| hex::encode(Sha256::digest(script.as_bytes())))
            .collect();
        ensure!(
            identity == snapshot_schema_identity(version)?
                && migration_digests == expected_digests
                && expected_digests
                    .iter()
                    .map(String::as_str)
                    .eq(committed_digests.iter().copied()),
            "snapshot classification lineage is not a supported compiled schema"
        );

        let tables = parse_contract(document)?;
        ensure!(
            shapes.len() == tables.len(),
            "snapshot table coverage differs"
        );
        let mut seen = std::collections::BTreeSet::new();
        for shape in shapes {
            ensure!(seen.insert(&shape.name), "snapshot table is duplicated");
            let table = tables
                .get(&shape.name)
                .ok_or_else(|| anyhow::anyhow!("snapshot table is unclassified"))?;
            ensure!(
                shape
                    .columns
                    .iter()
                    .map(String::as_str)
                    .eq(table.columns.iter().map(|column| column.name.as_str())),
                "snapshot column coverage differs"
            );
        }

        Ok(Self {
            tables,
            manifest: SnapshotSchemaManifest {
                classification_version: CLASSIFICATION_VERSION.to_owned(),
                identity: identity.to_owned(),
                version,
                migration_digests: migration_digests.to_owned(),
                classification_digest: hex::encode(Sha256::digest(document.as_bytes())),
            },
        })
    }

    /// Constructs only a checked-in supported catalogue from compiled source.
    ///
    /// This factory does not authenticate an archive or choose its generation.
    /// Readers separately compare the authenticated header with this manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported generations or changed compiled hashes.
    pub fn for_supported_generation(version: usize) -> Result<Self> {
        let tables = parse_contract(generation_contract(version)?.0)?;
        let shapes = tables
            .iter()
            .map(|(name, table)| SnapshotTableShape {
                name: name.clone(),
                columns: table
                    .columns
                    .iter()
                    .map(|column| column.name.clone())
                    .collect(),
            })
            .collect::<Vec<_>>();
        let scripts = MIGRATIONS
            .get(..version)
            .ok_or_else(|| anyhow::anyhow!("snapshot compiled generation is absent"))?;
        let hashes = scripts
            .iter()
            .map(|script| hex::encode(Sha256::digest(script.as_bytes())))
            .collect::<Vec<_>>();
        Self::new(
            snapshot_schema_identity(version)?,
            version,
            &hashes,
            &shapes,
        )
    }

    /// Accepts the catalogue of the read-only Native SQLite adapter.
    ///
    /// # Errors
    ///
    /// Returns an error under the conditions described by [`Self::new`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_sqlite_schema(
        schema: &crate::backend::sqlite_snapshot::SqliteSnapshotSchema,
    ) -> Result<Self> {
        let shapes: Vec<_> = schema
            .tables
            .iter()
            .map(|table| SnapshotTableShape {
                name: table.name.clone(),
                columns: table.columns.clone(),
            })
            .collect();
        Self::new(
            &schema.identity,
            schema.version,
            &schema.migration_digests,
            &shapes,
        )
    }

    /// Returns the accepted source lineage and classification identity.
    pub fn manifest(&self) -> &SnapshotSchemaManifest {
        &self.manifest
    }

    /// Selects classification metadata without exposing the private contract.
    pub(crate) fn table_disposition(&self, name: &str) -> Result<&str> {
        self.tables
            .get(name)
            .map(|table| table.disposition.as_str())
            .ok_or_else(|| anyhow::anyhow!("snapshot table is unclassified"))
    }

    /// Classifies one row in the source's declared column order.
    ///
    /// Private cells produce exact-cell dependencies with no raw payload. Unknown
    /// dynamic settings, closed JSON fields, document versions, SQL storage
    /// classes, and over-limit values reject the entire row before any output.
    ///
    /// # Errors
    ///
    /// Returns an error for an uncovered table, shape/type/nullability mismatch,
    /// invalid or unknown JSON/configuration, or more than one MiB per cell or
    /// eight MiB of total source payload. Error text excludes source values.
    pub fn classify(&self, table_name: &str, row: &Row) -> Result<SnapshotRowDisposition> {
        let table = self
            .tables
            .get(table_name)
            .ok_or_else(|| anyhow::anyhow!("snapshot table is unclassified"))?;
        ensure!(
            row.len() == table.columns.len(),
            "snapshot row width differs"
        );
        let mut payload_bytes = 0usize;
        for (index, column) in table.columns.iter().enumerate() {
            let value = value_at(row, index)?;
            let size = payload_len(value);
            payload_bytes = payload_bytes
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("snapshot row payload exceeds limits"))?;
            ensure!(
                size <= MAX_CELL_BYTES && payload_bytes <= MAX_ROW_BYTES,
                "snapshot row payload exceeds limits"
            );
            ensure!(
                valid_storage(column, value),
                "snapshot SQL value class differs"
            );
        }

        // Closed business documents are inspected only after the complete row
        // has passed its allocation and SQL-value budget. These checks preserve
        // exact private bytes and do not authenticate archived provider proof.
        direct::validate_row(table_name, table, row)?;
        mirror::validate_row(table_name, table, row)?;
        lifetimes::validate_row(table_name, table, row)?;

        match table.disposition.as_str() {
            "auth_transient" => return Ok(SnapshotRowDisposition::AuthTransient),
            "source_metadata" => return Ok(SnapshotRowDisposition::SourceMetadata),
            _ => {}
        }

        let primary_key_digest = primary_key_digest(table_name, table, row)?;
        let mut cells = BTreeMap::new();
        let mut private_dependencies = Vec::new();
        for (index, column) in table.columns.iter().enumerate() {
            let value = value_at(row, index)?;
            let reason = if matches!(value, Value::Null) {
                None
            } else {
                classify_cell(table_name, table, column, row, value, self.manifest.version)?
            };
            let cell = if let Some(reason) = reason {
                let digest = cell_digest(value);
                private_dependencies.push(SnapshotPrivateDependency {
                    table: table_name.to_owned(),
                    primary_key_digest: primary_key_digest.clone(),
                    column: column.name.clone(),
                    cell_digest: digest.clone(),
                    payload_bytes: payload_len(value),
                    reason,
                });
                ClassifiedCell::External(digest)
            } else {
                ClassifiedCell::Scalar(scalar(value)?)
            };
            cells.insert(column.name.clone(), cell);
        }

        Ok(SnapshotRowDisposition::Retained(ClassifiedSnapshotRow {
            table: table_name.to_owned(),
            cells,
            private_dependencies,
        }))
    }
}

fn generation_contract(version: usize) -> Result<(&'static str, &'static [&'static str])> {
    match version {
        3 => Ok((LEGACY_CONTRACT, LEGACY_CONTRACT_MIGRATION_DIGESTS)),
        4 => Ok((GENERATION4_CONTRACT, GENERATION4_MIGRATION_DIGESTS)),
        5 => Ok((GENERATION5_CONTRACT, GENERATION5_MIGRATION_DIGESTS)),
        6 => Ok((GENERATION6_CONTRACT, GENERATION6_MIGRATION_DIGESTS)),
        7 => Ok((GENERATION7_CONTRACT, GENERATION7_MIGRATION_DIGESTS)),
        8 => Ok((CONTRACT, CONTRACT_MIGRATION_DIGESTS)),
        _ => anyhow::bail!("snapshot generation is unsupported"),
    }
}

fn contract() -> Result<BTreeMap<String, TableContract>> {
    parse_contract(generation_contract(MIGRATIONS.len())?.0)
}

fn parse_contract(document: &str) -> Result<BTreeMap<String, TableContract>> {
    let mut tables: BTreeMap<String, TableContract> = BTreeMap::new();
    for line in document.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        ensure!(fields.len() == 7, "snapshot contract row is malformed");
        ensure!(
            matches!(fields[1], "retain" | "auth_transient" | "source_metadata")
                && matches!(fields[3], "integer" | "bytes" | "text")
                && matches!(fields[4], "yes" | "no")
                && matches!(
                    fields[6],
                    "retain"
                        | "secret"
                        | "instance_config"
                        | "authority"
                        | "private_json"
                        | "private_cell"
                        | "secret_reference"
                        | "fingerprint"
                        | "idp_locator"
                        | "oci_sha256_state"
                ),
            "snapshot contract rule is unknown"
        );
        let table = tables
            .entry(fields[0].to_owned())
            .or_insert_with(|| TableContract {
                disposition: fields[1].to_owned(),
                columns: Vec::new(),
            });
        ensure!(
            table.disposition == fields[1]
                && !table.columns.iter().any(|column| column.name == fields[2]),
            "snapshot contract classification conflicts"
        );
        table.columns.push(ColumnContract {
            name: fields[2].to_owned(),
            storage: fields[3].to_owned(),
            nullable: fields[4] == "yes",
            primary_key_ordinal: fields[5].parse()?,
            rule: fields[6].to_owned(),
        });
    }
    for table in tables.values() {
        let mut ordinals: Vec<_> = table
            .columns
            .iter()
            .filter_map(|column| {
                (column.primary_key_ordinal != 0).then_some(column.primary_key_ordinal)
            })
            .collect();
        ordinals.sort_unstable();
        ensure!(
            table.disposition == "source_metadata"
                || ordinals == (1..=ordinals.len()).collect::<Vec<_>>() && !ordinals.is_empty(),
            "snapshot contract primary key is incomplete"
        );
    }
    Ok(tables)
}

fn classify_cell(
    table_name: &str,
    table: &TableContract,
    column: &ColumnContract,
    row: &Row,
    value: &Value,
    generation: usize,
) -> Result<Option<PrivateDependencyReason>> {
    match column.rule.as_str() {
        "secret" => Ok(Some(PrivateDependencyReason::Secret)),
        "private_cell" => Ok(Some(PrivateDependencyReason::PrivateContext)),
        "idp_locator" => {
            json::validate_idp_locator(text(value)?)?;
            Ok(None)
        }
        "oci_sha256_state" => {
            validate_oci_sha256_state(table, row)?;
            Ok(None)
        }
        "secret_reference" => {
            json::validate_reference(text(value)?)?;
            Ok(None)
        }
        "fingerprint" => {
            json::validate_fingerprint(text(value)?)?;
            Ok(None)
        }
        "authority" => {
            json::validate_authority(table_name, text(value)?)?;
            Ok(None)
        }
        "private_json" => {
            if table_name == "oci_image_config_projections"
                && column.name == "config_json"
                && text(value)?.is_empty()
                && table
                    .columns
                    .iter()
                    .any(|item| item.name == "config_representation")
                && text(named_value(table, row, "config_representation")?)? == "storage_summary_v1"
            {
                // The closed row validator already checked the typed summary.
                // Empty legacy raw storage is exact private data, not JSON.
                return Ok(Some(PrivateDependencyReason::PrivateContext));
            }
            let plan_kind = if table_name == "topology_plans" {
                Some(text(named_value(table, row, "plan_kind")?)?)
            } else {
                None
            };
            let secret = if generation >= 8
                && matches!(
                    (table_name, column.name.as_str()),
                    ("release_channel_advances", "receipt_json")
                        | ("release_bundle_publications", "receipt_json")
                        | ("release_qualifications", "staging_receipt_json")
                ) {
                json::validate_current_release_receipt(table_name, text(value)?)?;
                false
            } else {
                json::validate_private(table_name, &column.name, text(value)?, plan_kind)?
            };
            Ok(Some(if secret {
                PrivateDependencyReason::Secret
            } else {
                PrivateDependencyReason::OpaqueJson
            }))
        }
        "instance_config" => {
            let key = text(named_value(table, row, "config_key")?)?;
            json::classify_setting(key, text(value)?)
        }
        _ => Ok(None),
    }
}

fn named_value<'a>(table: &TableContract, row: &'a Row, name: &str) -> Result<&'a Value> {
    let index = table
        .columns
        .iter()
        .position(|column| column.name == name)
        .ok_or_else(|| anyhow::anyhow!("snapshot contract discriminator is absent"))?;
    value_at(row, index)
}

fn value_at(row: &Row, index: usize) -> Result<&Value> {
    row.value(index)
        .ok_or_else(|| anyhow::anyhow!("snapshot row width differs"))
}

fn text(value: &Value) -> Result<&str> {
    match value {
        Value::Text(text) => Ok(text),
        _ => anyhow::bail!("snapshot structured cell is not text"),
    }
}

fn valid_storage(column: &ColumnContract, value: &Value) -> bool {
    match value {
        Value::Null => column.nullable,
        Value::Int(_) => column.storage == "integer",
        Value::Text(_) => column.storage == "text",
        Value::Bytes(_) => column.storage == "bytes",
        Value::Real(_) => false,
    }
}

fn payload_len(value: &Value) -> usize {
    match value {
        Value::Int(_) | Value::Real(_) => 8,
        Value::Text(text) => text.len(),
        Value::Bytes(bytes) => bytes.len(),
        Value::Null => 0,
    }
}

fn scalar(value: &Value) -> Result<SnapshotScalar> {
    Ok(match value {
        Value::Int(integer) => SnapshotScalar::Integer(integer.to_string()),
        Value::Real(real) => {
            ensure!(real.is_finite(), "snapshot real value is not finite");
            SnapshotScalar::RealBits(format!("{:016x}", real.to_bits()))
        }
        Value::Text(text) => SnapshotScalar::Text(text.clone()),
        Value::Bytes(bytes) => SnapshotScalar::BytesHex(hex::encode(bytes)),
        Value::Null => SnapshotScalar::Null,
    })
}

fn hash_value(hash: &mut Sha256, value: &Value) {
    match value {
        Value::Int(integer) => {
            hash.update(b"integer\0");
            hash.update(integer.to_be_bytes());
        }
        Value::Real(real) => {
            hash.update(b"real\0");
            hash.update(real.to_bits().to_be_bytes());
        }
        Value::Text(text) => {
            hash.update(b"text\0");
            hash.update((text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        }
        Value::Bytes(bytes) => {
            hash.update(b"bytes\0");
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Value::Null => hash.update(b"null\0"),
    }
}

fn cell_digest(value: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aos-hub.snapshot.cell/v1\0");
    hash_value(&mut hash, value);
    hex::encode(hash.finalize())
}

fn primary_key_digest(table_name: &str, table: &TableContract, row: &Row) -> Result<String> {
    let mut keys: Vec<_> = table
        .columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.primary_key_ordinal != 0)
        .collect();
    keys.sort_unstable_by_key(|(_, column)| column.primary_key_ordinal);
    let mut hash = Sha256::new();
    hash.update(b"aos-hub.snapshot.row-key/v1\0");
    hash.update((table_name.len() as u64).to_be_bytes());
    hash.update(table_name.as_bytes());
    for (index, column) in keys {
        hash.update((column.name.len() as u64).to_be_bytes());
        hash.update(column.name.as_bytes());
        hash_value(&mut hash, value_at(row, index)?);
    }
    Ok(hex::encode(hash.finalize()))
}

fn validate_oci_sha256_state(table: &TableContract, row: &Row) -> Result<()> {
    let integer = |name| -> Result<i64> {
        match named_value(table, row, name)? {
            Value::Int(value) => Ok(*value),
            _ => anyhow::bail!("snapshot OCI hash state is invalid"),
        }
    };
    let unsigned_word = |name| -> Result<u32> {
        u32::try_from(integer(name)?)
            .map_err(|_| anyhow::anyhow!("snapshot OCI hash state is invalid"))
    };
    let state = crate::db::OciSha256State {
        version: unsigned_word("sha256_state_version")?,
        words: [
            unsigned_word("sha256_h0")?,
            unsigned_word("sha256_h1")?,
            unsigned_word("sha256_h2")?,
            unsigned_word("sha256_h3")?,
            unsigned_word("sha256_h4")?,
            unsigned_word("sha256_h5")?,
            unsigned_word("sha256_h6")?,
            unsigned_word("sha256_h7")?,
        ],
        total_bytes: u64::try_from(integer("sha256_total_bytes")?)
            .map_err(|_| anyhow::anyhow!("snapshot OCI hash state is invalid"))?,
        tail_hex: text(named_value(table, row, "sha256_tail_hex")?)?.to_owned(),
    };
    state
        .validate()
        .map_err(|_| anyhow::anyhow!("snapshot OCI hash state is invalid"))
}
