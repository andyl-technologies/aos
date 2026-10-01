//! Authenticated, incomplete object requirements derived from retained SQL.
//!
//! Generation-eight coverage explicitly classifies every source column. Exact
//! scalar references and identity/version fields are projected only into the
//! encrypted private stream. Secret cells are excluded; opaque application and
//! mutation cells contribute context-bound digests and unresolved dependencies.
//! This is a requirements list, never physical existence, graph closure,
//! journal settlement, provider permission, import or activation authority.
//!
//! ```text
//! authenticated capture -> private constraint replay -> encrypted requirements
//! requirements + exact source capture -> replay and exact projection comparison
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(test)]
use zeroize::Zeroizing;

use crate::snapshot::{SnapshotClassifier, SnapshotSchemaManifest};
use crate::value::{Row, Value};

mod codec;
mod io;

pub use codec::{ObjectRequirementsOutput, ObjectRequirementsReader, ObjectRequirementsWriter};

#[cfg(test)]
mod tests;

const COVERAGE: &str = include_str!("coverage-v8.tsv");
const SOURCE: &str = include_str!("../schema-v8.tsv");
const PROFILE: &str = "aos.hub.object-requirements/v1";
const RECORD_BYTES: usize = 1024 * 1024;
const FAMILIES: [&str; 10] = [
    "none",
    "catalogue_copy",
    "authority_dependency",
    "mutation_dependency",
    "cache_store_root",
    "oci_root",
    "registry_store_root",
    "image_root",
    "operation_dependency",
    "application_dependency",
];

/// Hard bounds for projected records, independent of source and frame limits.
#[derive(Debug, Clone, Copy)]
pub struct ObjectRequirementsLimits {
    /// Maximum projected source rows, at most ten million.
    pub max_rows: u64,
}

impl Default for ObjectRequirementsLimits {
    fn default() -> Self {
        Self {
            max_rows: 1_000_000,
        }
    }
}

impl ObjectRequirementsLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            (1..=10_000_000).contains(&self.max_rows),
            "object requirements limits are invalid"
        );
        Ok(())
    }
}

/// Value-free counts from exact source projection, without completeness claims.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ObjectRequirementsCounts {
    /// Rows that carry an object, authority, operation or application dependency.
    pub projected_rows: u64,
    /// Every retained source row consumed in exact authenticated ordinal order.
    pub source_retained_rows: u64,
    /// Non-null opaque cells requiring separate typed application closure.
    pub opaque_dependencies: u64,
    /// Non-null source secret cells deliberately absent from requirements.
    pub excluded_secret_cells: u64,
    /// Projected row counts by the fixed compiled family names.
    pub families: BTreeMap<String, u64>,
}

#[derive(Clone, Copy)]
enum Policy {
    Omit,
    Value,
    DependencyDigest,
    SecretExcluded,
}

struct Column {
    name: String,
    policy: Policy,
}

struct Table {
    family: String,
    columns: Vec<Column>,
}

/// Exact current-schema coverage with bounded, one-row private projection.
///
/// Construction proves compiled coverage only. Authentication and relational
/// validation of source rows are caller obligations before publishing a result.
pub struct ObjectRequirementsCoverage {
    tables: BTreeMap<String, Table>,
    schema: SnapshotSchemaManifest,
}

impl ObjectRequirementsCoverage {
    /// Admits the complete literal generation-eight column coverage contract.
    ///
    /// # Errors
    ///
    /// Rejects changed, missing, duplicate or reordered source/coverage columns,
    /// unknown policies/families or inconsistent policies for secret originals.
    pub fn current8() -> Result<Self> {
        Self::from_contract(COVERAGE)
    }

    fn from_contract(coverage: &str) -> Result<Self> {
        let source = SOURCE
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        let mut contract = coverage
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        let mut tables: BTreeMap<String, Table> = BTreeMap::new();
        for line in source {
            let original: Vec<_> = line.split('\t').collect();
            let fields: Vec<_> = contract
                .next()
                .ok_or_else(|| anyhow::anyhow!("object coverage is incomplete"))?
                .split('\t')
                .collect();
            ensure!(
                original.len() == 7
                    && fields.len() == 4
                    && fields[0] == original[0]
                    && fields[1] == original[2],
                "object coverage differs from source"
            );
            ensure!(
                FAMILIES.contains(&fields[2]),
                "object coverage family is unknown"
            );
            let policy = match fields[3] {
                "omit" => Policy::Omit,
                "value" => Policy::Value,
                "dependency_digest" => Policy::DependencyDigest,
                "secret_excluded" => Policy::SecretExcluded,
                _ => anyhow::bail!("object coverage policy is unknown"),
            };
            ensure!(
                (original[6] == "secret") == matches!(policy, Policy::SecretExcluded)
                    && (!matches!(policy, Policy::Value)
                        || !matches!(original[6], "private_json" | "private_cell" | "secret"))
                    && (original[1] == "retain" || fields[2] == "none"),
                "object coverage confidentiality policy differs"
            );
            let table = tables.entry(fields[0].into()).or_insert_with(|| Table {
                family: fields[2].into(),
                columns: Vec::new(),
            });
            ensure!(
                table.family == fields[2]
                    && !table.columns.iter().any(|column| column.name == fields[1]),
                "object coverage table differs"
            );
            table.columns.push(Column {
                name: fields[1].into(),
                policy,
            });
        }
        ensure!(
            contract.next().is_none(),
            "object coverage has extra columns"
        );
        let classifier = SnapshotClassifier::for_supported_generation(8)?;
        Ok(Self {
            tables,
            schema: classifier.manifest().clone(),
        })
    }

    /// Compares an authenticated source manifest with this exact current contract.
    ///
    /// Historical capture verification stays supported separately; this first
    /// requirements projection never silently upgrades a historical schema.
    ///
    /// # Errors
    ///
    /// Rejects any generation, identity, migration or classification difference.
    pub fn require_schema(&self, schema: &SnapshotSchemaManifest) -> Result<()> {
        ensure!(
            schema == &self.schema,
            "object requirements source schema differs"
        );
        Ok(())
    }

    fn header(&self, archive: &str, role: &str, source_root_sha256: &str) -> Header {
        Header {
            kind: "header",
            profile: PROFILE,
            archive_id: archive.into(),
            role: role.into(),
            source_capture_root_sha256: source_root_sha256.into(),
            schema: self.schema.clone(),
            coverage_sha256: hex::encode(Sha256::digest(COVERAGE.as_bytes())),
            pending: [
                "signed_graph_closure",
                "physical_content_and_incarnations",
                "external_journal_continuity",
                "source_credential_and_key_custody",
                "old_writer_fencing",
                "target_import_and_activation",
            ],
        }
    }

    fn project(
        &self,
        name: &str,
        sequence: u64,
        row: &Row,
        counts: &mut ObjectRequirementsCounts,
        limits: ObjectRequirementsLimits,
    ) -> Result<Option<Projection>> {
        ensure!(
            counts.source_retained_rows < 10_000_000,
            "object requirements source rows exceed limits"
        );
        ensure!(
            sequence == counts.source_retained_rows,
            "object requirements source order differs"
        );
        add(&mut counts.source_retained_rows)?;
        let table = self
            .tables
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("object requirements table is unknown"))?;
        ensure!(
            row.len() == table.columns.len(),
            "object requirements source row shape differs"
        );
        let mut estimate = 1024usize;
        for (index, column) in table.columns.iter().enumerate() {
            let value = row
                .value(index)
                .ok_or_else(|| anyhow::anyhow!("object requirements source cell is absent"))?;
            if matches!(column.policy, Policy::SecretExcluded) && !value.is_null() {
                add(&mut counts.excluded_secret_cells)?;
            }
            if table.family != "none" && matches!(column.policy, Policy::Value) {
                let length = match value {
                    Value::Text(text) => text.len(),
                    Value::Bytes(bytes) => bytes.len(),
                    _ => 16,
                };
                estimate = estimate
                    .checked_add(
                        length
                            .checked_mul(6)
                            .ok_or_else(|| anyhow::anyhow!("object requirement exceeds limits"))?
                            + column.name.len()
                            + 128,
                    )
                    .ok_or_else(|| anyhow::anyhow!("object requirement exceeds limits"))?;
            } else if matches!(column.policy, Policy::DependencyDigest) {
                estimate = estimate.saturating_add(column.name.len() + 256);
            }
        }
        ensure!(
            estimate <= RECORD_BYTES,
            "object requirement exceeds record limits"
        );
        if table.family == "none" {
            return Ok(None);
        }
        ensure!(
            counts.projected_rows < limits.max_rows,
            "object requirements exceed row limits"
        );
        let mut cells = Vec::with_capacity(table.columns.len());
        for (index, column) in table.columns.iter().enumerate() {
            let value = row
                .value(index)
                .ok_or_else(|| anyhow::anyhow!("object requirements source cell is absent"))?;
            let value = match column.policy {
                Policy::Omit | Policy::SecretExcluded => continue,
                Policy::Value => scalar(value)?,
                Policy::DependencyDigest if value.is_null() => CellValue::Null,
                Policy::DependencyDigest => {
                    add(&mut counts.opaque_dependencies)?;
                    CellValue::UnresolvedDigest {
                        sha256: dependency_digest(name, &column.name, value)?,
                    }
                }
            };
            cells.push(Cell {
                column: column.name.clone(),
                value,
            });
        }
        add(&mut counts.projected_rows)?;
        add(counts.families.entry(table.family.clone()).or_default())?;
        Ok(Some(Projection {
            kind: "requirement",
            source_row: sequence.to_string(),
            source_table: name.into(),
            family: table.family.clone(),
            cells,
        }))
    }
}

fn add(value: &mut u64) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("object requirements counter exceeds limits"))?;
    Ok(())
}

#[derive(Serialize)]
struct Header {
    kind: &'static str,
    profile: &'static str,
    archive_id: String,
    role: String,
    source_capture_root_sha256: String,
    schema: SnapshotSchemaManifest,
    coverage_sha256: String,
    pending: [&'static str; 6],
}

#[derive(Serialize)]
struct Projection {
    kind: &'static str,
    source_row: String,
    source_table: String,
    family: String,
    cells: Vec<Cell>,
}

#[derive(Serialize)]
struct Cell {
    column: String,
    value: CellValue,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum CellValue {
    Integer(String),
    Text(String),
    BytesHex(String),
    Null,
    UnresolvedDigest { sha256: String },
}

fn scalar(value: &Value) -> Result<CellValue> {
    Ok(match value {
        Value::Int(value) => CellValue::Integer(value.to_string()),
        Value::Text(value) => CellValue::Text(value.clone()),
        Value::Bytes(value) => CellValue::BytesHex(hex::encode(value)),
        Value::Null => CellValue::Null,
        Value::Real(_) => anyhow::bail!("object requirement scalar is unsupported"),
    })
}

fn dependency_digest(table: &str, column: &str, value: &Value) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"aos.hub.object-requirement-private-dependency/v1\0");
    for identity in [table, column] {
        hash.update((identity.len() as u64).to_be_bytes());
        hash.update(identity.as_bytes());
    }
    match value {
        Value::Text(text) => {
            hash.update(b"text\0");
            hash.update(text.as_bytes());
        }
        Value::Bytes(bytes) => {
            hash.update(b"bytes\0");
            hash.update(bytes);
        }
        Value::Int(value) => {
            hash.update(b"integer\0");
            hash.update(value.to_be_bytes());
        }
        _ => anyhow::bail!("object requirement dependency is unsupported"),
    }
    Ok(hex::encode(hash.finalize()))
}

fn hash_string(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "object requirements source digest is invalid"
    );
    Ok(())
}

#[cfg(test)]
fn bytes(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    io::encode(value)
}
