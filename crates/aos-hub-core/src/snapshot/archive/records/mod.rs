//! Typed encrypted database capture with exact private-row reconstruction.
//!
//! The immutable SQLite `database_capture/v1` and distinct PostgreSQL
//! `database_capture/v2` JSONL profiles account for every admitted table,
//! including empty tables and explicit transient/lineage omissions. Version two
//! declares PostgreSQL read-only repeatable-read catalogue/constraint evidence;
//! it never substitutes that evidence for a SQLite physical integrity check.
//! Verification joins metadata and private cells in one-row order, reclassifies
//! exact originals, checks counts and requires logical ends plus authenticated
//! frame END/EOF and both actual signed-summary matches.
//!
//! This result establishes grammar, reconstruction and count consistency with
//! authenticated exporter declarations. It does not independently repeat the
//! source audit, prove unique primary keys or global SQL/application/object
//! closure, bind original sealing keys, authorize import or activate jobs.
//! Those require later private scratch-database replay and recovery protocols.
//! The enclosing signed-root profile remains `framing_only`.
//!
//! ```text
//! audited SQLite -> metadata/private records -> encrypted streams -> signed root
//! pinned root -> complete paired decoders -> exact row reconstruction -> report
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use anyhow::{ensure, Result};

use super::root::{
    verify_declared_root, ArchiveSignerTrust, ArchiveWrappingKeys, ExcludedArchiveKey,
};
use super::{StreamDecoder, StreamLimits, StreamRole};
use crate::snapshot::{
    ClassifiedCell, ClassifiedSnapshotRow, PrivateSnapshotCell, ReconstructedSnapshotRow,
    SnapshotClassifier,
};

mod wire;

#[cfg(not(target_arch = "wasm32"))]
mod sqlite;

#[cfg(not(target_arch = "wasm32"))]
mod source;

#[cfg(not(target_arch = "wasm32"))]
pub use sqlite::{capture_sqlite, CaptureKeyCustody, DatabaseCaptureOutput, SqliteCaptureOptions};

#[cfg(all(feature = "postgres", not(target_arch = "wasm32")))]
pub use sqlite::{capture_postgres, PostgresCaptureOptions};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

use wire::*;

/// Authenticated source-audit declarations, not independently observed SQL proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSourceAudit {
    checked_expressions: u64,
    postgres: bool,
}

impl DeclaredSourceAudit {
    /// Returns the independently authenticated source engine declaration.
    ///
    /// This describes exporter evidence, not independent provider authority.
    pub fn source_engine(&self) -> &'static str {
        if self.postgres {
            "postgresql"
        } else {
            "sqlite"
        }
    }

    /// Returns declared checked expressions: CHECKs in v1, CHECKs and FKs in v2.
    pub fn checked_expressions(&self) -> u64 {
        self.checked_expressions
    }
}

/// Counts established by logical grammar and exact paired row reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DatabaseCaptureCounts {
    /// Every compiled source table, including empty and omitted tables.
    pub tables: u64,
    /// Retained rows individually reconstructed and reclassified.
    pub retained_rows: u64,
    /// Source rows explicitly omitted by the current classification policy.
    pub omitted_rows: u64,
    /// Exact private originals matched one-to-one with classified dependencies.
    pub private_cells: u64,
}

/// A complete record verification result, never an executable restore authority.
///
/// Private construction requires both actual decoder END/EOF summaries and
/// logical ends. Source audit facts remain signer declarations. Duplicate row
/// identities and global constraints/references are intentionally unproved;
/// a later scratch-database replay must enforce those independently.
pub struct VerifiedDatabaseCaptureRecords {
    counts: DatabaseCaptureCounts,
    audit: DeclaredSourceAudit,
}

impl fmt::Debug for VerifiedDatabaseCaptureRecords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDatabaseCaptureRecords")
            .field("counts", &self.counts)
            .field("scope", &"records_and_reconstruction_only")
            .finish_non_exhaustive()
    }
}

impl VerifiedDatabaseCaptureRecords {
    /// Borrows counts established by this paired record verification.
    pub fn counts(&self) -> &DatabaseCaptureCounts {
        &self.counts
    }

    /// Borrows authenticated exporter declarations about its source audit.
    pub fn declared_source_audit(&self) -> &DeclaredSourceAudit {
        &self.audit
    }
}

/// Verifies both actual streams and their exact private-row reconstruction.
///
/// The callback receives provisional private rows before stream completion;
/// callers own confidentiality and must not activate or commit a restore from
/// a callback. Completion is reported only after both logical ends, frame ends,
/// clean EOF and actual summary reconciliation. No provider/SQL operation occurs.
/// Blocking input/callback liveness and immutable input custody remain caller
/// obligations. No raw private row is returned through an unrestricted serializer.
///
/// # Errors
///
/// Rejects untrusted roots/keys, framing/record limits, unknown/duplicate fields,
/// schema/order/count differences, private-cell mismatches, callback failure,
/// truncation or trailing data. All returned errors omit input/parser details.
pub fn verify_database_capture<M: Read, P: Read>(
    root_bytes: &[u8],
    trust: &ArchiveSignerTrust,
    wrapping: &ArchiveWrappingKeys,
    exclusions: &[ExcludedArchiveKey],
    metadata: M,
    private: P,
    limits: StreamLimits,
    on_row: impl FnMut(&str, u64, &ReconstructedSnapshotRow) -> Result<()>,
) -> Result<VerifiedDatabaseCaptureRecords> {
    verify_database_capture_with_schema(
        root_bytes,
        trust,
        wrapping,
        exclusions,
        metadata,
        private,
        limits,
        |_| Ok(()),
        on_row,
    )
}

/// Verifies supported authenticated schema headers before provisional row callbacks.
///
/// Both independently AEAD-authenticated headers must match the same exact
/// compiled generation. The schema callback may select only its trusted replay
/// DDL; it cannot activate a restore. Final logical ends, END/EOF and signed
/// summaries are still required before this function returns a positive report.
/// The signed-root profile remains `framing_only`.
///
/// # Errors
///
/// Returns the same bounded, value-free failures as [`verify_database_capture`],
/// including a rejected schema callback or unsupported generation/digest set.
pub fn verify_database_capture_with_schema<M: Read, P: Read>(
    root_bytes: &[u8],
    trust: &ArchiveSignerTrust,
    wrapping: &ArchiveWrappingKeys,
    exclusions: &[ExcludedArchiveKey],
    metadata: M,
    private: P,
    limits: StreamLimits,
    mut on_schema: impl FnMut(&crate::snapshot::SnapshotSchemaManifest) -> Result<()>,
    mut on_row: impl FnMut(&str, u64, &ReconstructedSnapshotRow) -> Result<()>,
) -> Result<VerifiedDatabaseCaptureRecords> {
    let root = verify_declared_root(root_bytes, trust)?;
    let (metadata_key, private_key) = root
        .unwrap_reader_keys(wrapping, exclusions)?
        .into_role_keys();
    let mut metadata = RecordReader::new(StreamDecoder::new(
        metadata,
        metadata_key,
        root.stream_context(StreamRole::Metadata),
        limits,
    )?);
    let mut private = RecordReader::new(StreamDecoder::new(
        private,
        private_key,
        root.stream_context(StreamRole::Private),
        limits,
    )?);
    let archive_id = hex::encode(root.archive_id());
    let header: Header = metadata.read(CONTROL_CAP)?;
    let version = usize::try_from(number(&header.schema.version)?)
        .map_err(|_| anyhow::anyhow!("snapshot generation overflows"))?;
    let classifier = SnapshotClassifier::for_supported_generation(version)?;
    check_header(&header, &classifier, &archive_id, "metadata")?;
    let private_header: Header = private.read(CONTROL_CAP)?;
    check_header(&private_header, &classifier, &archive_id, "private")?;
    ensure!(
        header.audit == private_header.audit
            && header.source == private_header.source
            && header.profile == private_header.profile,
        "snapshot source audit declarations differ"
    );

    on_schema(classifier.manifest())
        .map_err(|_| anyhow::anyhow!("snapshot schema callback failed"))?;

    let mut counts = DatabaseCaptureCounts::default();
    for (ordinal, (name, table)) in classifier.tables.iter().enumerate() {
        let start: TableStart = metadata.read(CONTROL_CAP)?;
        ensure!(
            start.kind == "table_start"
                && number(&start.ordinal)? == ordinal as u64
                && start.table == *name
                && start.disposition == table.disposition,
            "snapshot table record order differs"
        );
        let source_rows = number(&start.source_rows)?;
        ensure!(
            source_rows <= i64::MAX as u64,
            "snapshot source count exceeds SQL bounds"
        );
        ensure!(
            table.disposition != "source_metadata" || source_rows == 1,
            "snapshot source singleton count differs"
        );
        let before = counts.clone();
        if table.disposition == "retain" {
            for _ in 0..source_rows {
                let mark: RowMark = metadata.read(CONTROL_CAP)?;
                let row_number = counts.retained_rows;
                ensure!(
                    mark.kind == "row_start" && number(&mark.row)? == row_number,
                    "snapshot row record order differs"
                );
                let mut cells = BTreeMap::new();
                let mut dependencies = Vec::new();
                let mut originals = Vec::new();
                let mut payload = 0usize;
                for column in &table.columns {
                    let cell: Cell = metadata.read(CELL_CAP)?;
                    ensure!(
                        cell.kind == "cell" && cell.column == column.name,
                        "snapshot cell record order differs"
                    );
                    let classified = match (cell.scalar, cell.external) {
                        (Some(scalar), None) => {
                            bounded_payload(
                                &mut payload,
                                crate::snapshot::capture::scalar_payload_len(&scalar.0)?,
                            )?;
                            ClassifiedCell::Scalar(scalar.0)
                        }
                        (None, Some(dependency)) => {
                            let dependency = dependency.into_dependency()?;
                            ensure!(
                                dependency.table == *name && dependency.column == column.name,
                                "snapshot private cell locator differs"
                            );
                            bounded_payload(&mut payload, dependency.payload_bytes)?;
                            let original: PrivateCell = private.read(CELL_CAP)?;
                            ensure!(
                                original.kind == "private_cell"
                                    && number(&original.row)? == row_number
                                    && original.dependency.into_dependency()? == dependency,
                                "snapshot private cell record differs"
                            );
                            ensure!(
                                crate::snapshot::capture::scalar_payload_len(&original.scalar.0)?
                                    == dependency.payload_bytes,
                                "snapshot private scalar length differs"
                            );
                            originals.push(PrivateSnapshotCell::from_private_scalar(
                                dependency.clone(),
                                &original.scalar.0,
                            )?);
                            let classified =
                                ClassifiedCell::External(dependency.cell_digest.clone());
                            dependencies.push(dependency);
                            add(&mut counts.private_cells, 1)?;
                            classified
                        }
                        _ => anyhow::bail!("snapshot cell representation is invalid"),
                    };
                    cells.insert(column.name.clone(), classified);
                }
                let mark: RowMark = metadata.read(CONTROL_CAP)?;
                ensure!(
                    mark.kind == "row_end" && number(&mark.row)? == row_number,
                    "snapshot row end differs"
                );
                let row = ClassifiedSnapshotRow {
                    table: name.clone(),
                    cells,
                    private_dependencies: dependencies,
                };
                let reconstructed = classifier.reconstruct_private_row(&row, &originals)?;
                on_row(name, row_number, &reconstructed)
                    .map_err(|_| anyhow::anyhow!("snapshot private row callback failed"))?;
                add(&mut counts.retained_rows, 1)?;
            }
        } else {
            add(&mut counts.omitted_rows, source_rows)?;
        }
        let end: TableEnd = metadata.read(CONTROL_CAP)?;
        ensure!(
            end.kind == "table_end"
                && number(&end.ordinal)? == ordinal as u64
                && number(&end.source_rows)? == source_rows
                && number(&end.retained_rows)? == counts.retained_rows - before.retained_rows
                && number(&end.omitted_rows)? == counts.omitted_rows - before.omitted_rows
                && number(&end.private_cells)? == counts.private_cells - before.private_cells,
            "snapshot table end counts differ"
        );
        add(&mut counts.tables, 1)?;
    }
    check_end(
        &mut metadata,
        &archive_id,
        "metadata",
        &counts,
        &header.profile,
    )?;
    check_end(
        &mut private,
        &archive_id,
        "private",
        &counts,
        &header.profile,
    )?;
    root.reconcile_declared_summary(
        StreamRole::Metadata,
        metadata
            .decoder
            .summary()
            .ok_or_else(|| anyhow::anyhow!("snapshot metadata is incomplete"))?,
    )?;
    root.reconcile_declared_summary(
        StreamRole::Private,
        private
            .decoder
            .summary()
            .ok_or_else(|| anyhow::anyhow!("snapshot private stream is incomplete"))?,
    )?;

    Ok(VerifiedDatabaseCaptureRecords {
        counts,
        audit: DeclaredSourceAudit {
            checked_expressions: number(&header.audit.checked_expressions)?,
            postgres: header.profile == POSTGRES_PROFILE,
        },
    })
}

fn bounded_payload(total: &mut usize, size: usize) -> Result<()> {
    ensure!(
        size <= 1024 * 1024 && size <= (8 * 1024 * 1024usize).saturating_sub(*total),
        "snapshot record row exceeds limits"
    );
    *total += size;
    Ok(())
}

fn current_classifier() -> Result<SnapshotClassifier> {
    SnapshotClassifier::for_supported_generation(crate::db::MIGRATIONS.len())
}

fn schema(classifier: &SnapshotClassifier) -> Result<Schema> {
    let manifest = classifier.manifest();
    Ok(Schema {
        classification_version: manifest.classification_version.clone(),
        identity: manifest.identity.clone(),
        version: manifest.version.to_string(),
        migration_digests: MigrationDigests::from_vec(manifest.migration_digests.clone())?,
        classification_digest: manifest.classification_digest.clone(),
    })
}

fn check_header(
    header: &Header,
    classifier: &SnapshotClassifier,
    archive_id: &str,
    role: &str,
) -> Result<()> {
    ensure!(
        header.kind == "header"
            && header.archive_id == archive_id
            && header.role == role
            && header.schema == schema(classifier)?
            && number(&header.table_count)? == classifier.tables.len() as u64,
        "snapshot record header differs"
    );
    let postgres = header.profile == POSTGRES_PROFILE;
    ensure!(
        (header.profile == PROFILE && header.source.is_none())
            || (postgres
                && classifier.manifest().version == 8
                && header.source.as_ref() == Some(&PostgresSource::expected())),
        "snapshot source profile differs"
    );
    ensure!(
        header.audit.integrity == if postgres { "not_observed" } else { "passed" }
            && header.audit.compiled_checks == "passed"
            && header.audit.declared_foreign_keys == "passed",
        "snapshot source audit declaration is invalid"
    );
    number(&header.audit.checked_expressions)?;
    Ok(())
}

fn check_end<R: Read>(
    reader: &mut RecordReader<R>,
    archive_id: &str,
    role: &str,
    counts: &DatabaseCaptureCounts,
    profile: &str,
) -> Result<()> {
    let prior_records = reader.records;
    let end: End = reader.read(CONTROL_CAP)?;
    ensure!(
        end.kind == "end"
            && end.profile == profile
            && end.archive_id == archive_id
            && end.role == role
            && number(&end.table_count)? == counts.tables
            && number(&end.retained_rows)? == counts.retained_rows
            && number(&end.omitted_rows)? == counts.omitted_rows
            && number(&end.private_cells)? == counts.private_cells
            && number(&end.records)? == prior_records,
        "snapshot logical end differs"
    );
    reader.finish()
}
