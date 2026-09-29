//! Actual audited SQLite enumeration into the paired encrypted record protocol.
//!
//! One source transaction survives audit and every table page. Only caller-owned
//! sinks and explicit archive key custody are used; no source is opened through
//! a migrating initializer, and no runtime, filesystem or provider is installed.

use std::fmt;
use std::io::Write;

use anyhow::{ensure, Result};
use rand::TryCryptoRng;

use super::super::root::{
    prepare_archive_keys, sign_declared_root, ArchiveSigningKey, ArchiveWrappingKeys,
    ExcludedArchiveKey, FreshArchiveId, SignedDeclaredRoot,
};
use super::super::{FreshStreamKey, StreamContext, StreamEncoder, StreamLimits, StreamRole};
use super::wire::*;
use super::{schema, DatabaseCaptureCounts};
use crate::backend::sqlite_snapshot::{
    SqliteSnapshotAuditLimits, SqliteSnapshotLimits, SqliteSnapshotReader,
};
use crate::snapshot::{ClassifiedCell, SnapshotClassifier, SnapshotRowDisposition};

/// Explicit fresh-archive custody, separate from all Hub/source runtime keys.
///
/// Known exclusions constrain only supplied material. The caller still owns RNG
/// entropy/freshness and key custody; unknown/global key separation is unproved.
pub struct CaptureKeyCustody<'a> {
    /// Dedicated exporter signing seed and identity.
    pub signer: &'a ArchiveSigningKey,
    /// Separate metadata/private wrapping materials and opaque identities.
    pub wrapping: &'a ArchiveWrappingKeys,
    /// Explicit known nonarchive keys excluded from archive roles.
    pub exclusions: &'a [ExcludedArchiveKey],
}

impl fmt::Debug for CaptureKeyCustody<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CaptureKeyCustody { <redacted> }")
    }
}

/// Explicit source-work, page-memory and ciphertext bounds for one capture.
#[derive(Debug, Clone, Copy)]
pub struct SqliteCaptureOptions {
    /// Integrity/constraint/count work and elapsed audit limits.
    pub audit: SqliteSnapshotAuditLimits,
    /// Existing bounded, lossless source-page limits.
    pub pages: SqliteSnapshotLimits,
    /// Independently applied limits for each encrypted stream.
    pub streams: StreamLimits,
}

/// Completed caller sinks and a framing-only root for actual database records.
///
/// This type records actual source enumeration and finished ciphertext streams.
/// It does not establish original key custody, provider/object closure, recoverable
/// global database constraints, executable jobs or permission to activate.
pub struct DatabaseCaptureOutput<M, P> {
    /// Caller-owned metadata sink containing encrypted typed records.
    pub metadata: M,
    /// Caller-owned private sink containing encrypted exact original cells.
    pub private: P,
    /// Signed framing-only root bound to these finished stream summaries.
    pub root: SignedDeclaredRoot,
    /// Counts observed during actual source enumeration.
    pub counts: DatabaseCaptureCounts,
}

impl<M, P> fmt::Debug for DatabaseCaptureOutput<M, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseCaptureOutput")
            .field("counts", &self.counts)
            .finish_non_exhaustive()
    }
}

/// Audits and captures every current SQLite table in one pinned read transaction.
///
/// Explicit empty/omitted table counts are written; retained rows and their
/// original private cells are streamed in schema order. No source/key file is
/// created, migrated or loaded and no guard namespace is adopted. Failure may
/// leave partial ciphertext in caller sinks; restart with fresh RNG/key state.
///
/// # Errors
///
/// Rejects source corruption/constraints/schema/classification, work/memory/
/// stream limits, count differences, entropy/key-custody failure or sink failure.
/// Returned errors exclude source values, SQL diagnostics and sink error detail.
pub async fn capture_sqlite<M: Write, P: Write>(
    source: SqliteSnapshotReader,
    metadata: M,
    private: P,
    custody: CaptureKeyCustody<'_>,
    rng: &mut impl TryCryptoRng,
    options: SqliteCaptureOptions,
) -> Result<DatabaseCaptureOutput<M, P>> {
    capture_inner(source, metadata, private, custody, rng, options)
        .await
        .map_err(|_| anyhow::anyhow!("snapshot SQLite database capture failed"))
}

async fn capture_inner<M: Write, P: Write>(
    source: SqliteSnapshotReader,
    metadata: M,
    private: P,
    custody: CaptureKeyCustody<'_>,
    rng: &mut impl TryCryptoRng,
    options: SqliteCaptureOptions,
) -> Result<DatabaseCaptureOutput<M, P>> {
    let (mut source, audit) = source.audit_source(options.audit).await?;
    let classifier = SnapshotClassifier::from_sqlite_schema(source.schema())?;
    let tables = source.schema().tables.clone();
    ensure!(
        tables.len() == audit.table_counts().len(),
        "snapshot source count coverage differs"
    );
    let archive = FreshArchiveId::generate(rng)?;
    let archive_bytes = archive.bytes();
    let archive_id = hex::encode(archive_bytes);
    let metadata_key = FreshStreamKey::generate(rng)?;
    let private_key = FreshStreamKey::generate(rng)?;
    let prepared = prepare_archive_keys(
        &archive,
        custody.signer,
        custody.wrapping,
        &metadata_key,
        &private_key,
        custody.exclusions,
    )?;
    let mut metadata = RecordWriter {
        encoder: StreamEncoder::new(
            metadata,
            metadata_key,
            StreamContext::new(archive_bytes, StreamRole::Metadata),
            options.streams,
        )?,
        records: 0,
    };
    let mut private = RecordWriter {
        encoder: StreamEncoder::new(
            private,
            private_key,
            StreamContext::new(archive_bytes, StreamRole::Private),
            options.streams,
        )?,
        records: 0,
    };
    for role in ["metadata", "private"] {
        let header = Header {
            kind: "header".into(),
            profile: PROFILE.into(),
            archive_id: archive_id.clone(),
            role: role.into(),
            schema: schema(&classifier)?,
            table_count: tables.len().to_string(),
            audit: Audit {
                integrity: "passed".into(),
                compiled_checks: "passed".into(),
                declared_foreign_keys: "passed".into(),
                checked_expressions: audit.checked_expressions().to_string(),
            },
        };
        if role == "metadata" {
            metadata.write(&header)?;
        } else {
            private.write(&header)?;
        }
    }

    let mut counts = DatabaseCaptureCounts::default();
    for (ordinal, table) in tables.iter().enumerate() {
        let table_count = &audit.table_counts()[ordinal];
        ensure!(
            table_count.table == table.name,
            "snapshot source count order differs"
        );
        let contract = classifier
            .tables
            .get(&table.name)
            .ok_or_else(|| anyhow::anyhow!("snapshot source table is unclassified"))?;
        let start = TableStart {
            kind: "table_start".into(),
            ordinal: ordinal.to_string(),
            table: table.name.clone(),
            disposition: contract.disposition.clone(),
            source_rows: table_count.rows.to_string(),
        };
        metadata.write(&start)?;
        let before = counts.clone();
        let mut seen_rows = 0u64;
        let mut cursor = source.table(&table.name)?;
        loop {
            let page = cursor.next_page(options.pages).await?;
            for row in page.rows {
                add(&mut seen_rows, 1)?;
                ensure!(
                    seen_rows <= table_count.rows,
                    "snapshot source table count differs"
                );
                let captured = classifier.capture_private_row(&table.name, &row)?;
                let (disposition, originals) = captured.into_parts();
                match disposition {
                    SnapshotRowDisposition::Retained(retained) => {
                        ensure!(
                            contract.disposition == "retain",
                            "snapshot table disposition differs"
                        );
                        let row_number = counts.retained_rows;
                        metadata.write(&RowMark {
                            kind: "row_start".into(),
                            row: row_number.to_string(),
                        })?;
                        let mut original_index = 0usize;
                        for column in &table.columns {
                            let cell = retained
                                .cells
                                .get(column)
                                .ok_or_else(|| anyhow::anyhow!("snapshot source cell is absent"))?;
                            let wire = match cell {
                                ClassifiedCell::Scalar(value) => Cell {
                                    kind: "cell".into(),
                                    column: column.clone(),
                                    scalar: Some(WireScalar(value.clone())),
                                    external: None,
                                },
                                ClassifiedCell::External(_) => {
                                    let original =
                                        originals.get(original_index).ok_or_else(|| {
                                            anyhow::anyhow!(
                                                "snapshot source private cell is absent"
                                            )
                                        })?;
                                    ensure!(
                                        original.dependency().column == *column,
                                        "snapshot private source order differs"
                                    );
                                    let scalar =
                                        original.with_private_value(crate::snapshot::scalar)?;
                                    private.write(&PrivateCell {
                                        kind: "private_cell".into(),
                                        row: row_number.to_string(),
                                        dependency: Dependency::from_dependency(
                                            original.dependency(),
                                        ),
                                        scalar: WireScalar(scalar),
                                    })?;
                                    original_index += 1;
                                    add(&mut counts.private_cells, 1)?;
                                    Cell {
                                        kind: "cell".into(),
                                        column: column.clone(),
                                        scalar: None,
                                        external: Some(Dependency::from_dependency(
                                            original.dependency(),
                                        )),
                                    }
                                }
                            };
                            metadata.write(&wire)?;
                        }
                        ensure!(
                            original_index == originals.len(),
                            "snapshot source private count differs"
                        );
                        metadata.write(&RowMark {
                            kind: "row_end".into(),
                            row: row_number.to_string(),
                        })?;
                        add(&mut counts.retained_rows, 1)?;
                    }
                    SnapshotRowDisposition::AuthTransient => {
                        ensure!(
                            contract.disposition == "auth_transient",
                            "snapshot table disposition differs"
                        );
                        add(&mut counts.omitted_rows, 1)?;
                    }
                    SnapshotRowDisposition::SourceMetadata => {
                        ensure!(
                            contract.disposition == "source_metadata",
                            "snapshot table disposition differs"
                        );
                        add(&mut counts.omitted_rows, 1)?;
                    }
                }
            }
            if page.finished {
                break;
            }
        }
        ensure!(
            seen_rows == table_count.rows,
            "snapshot source table count differs"
        );
        metadata.write(&TableEnd {
            kind: "table_end".into(),
            ordinal: ordinal.to_string(),
            source_rows: seen_rows.to_string(),
            retained_rows: (counts.retained_rows - before.retained_rows).to_string(),
            omitted_rows: (counts.omitted_rows - before.omitted_rows).to_string(),
            private_cells: (counts.private_cells - before.private_cells).to_string(),
        })?;
        add(&mut counts.tables, 1)?;
    }
    write_end(&mut metadata, &archive_id, "metadata", &counts)?;
    write_end(&mut private, &archive_id, "private", &counts)?;
    source.close().await?;
    let (metadata, metadata_summary) = metadata.encoder.finish()?;
    let (private, private_summary) = private.encoder.finish()?;
    let root = sign_declared_root(
        prepared,
        custody.signer,
        &metadata_summary,
        &private_summary,
    )?;
    Ok(DatabaseCaptureOutput {
        metadata,
        private,
        root,
        counts,
    })
}

fn write_end<W: Write>(
    writer: &mut RecordWriter<W>,
    archive_id: &str,
    role: &str,
    counts: &DatabaseCaptureCounts,
) -> Result<()> {
    writer.write(&End {
        kind: "end".into(),
        profile: PROFILE.into(),
        archive_id: archive_id.into(),
        role: role.into(),
        table_count: counts.tables.to_string(),
        retained_rows: counts.retained_rows.to_string(),
        omitted_rows: counts.omitted_rows.to_string(),
        private_cells: counts.private_cells.to_string(),
        records: writer.records.to_string(),
    })
}
