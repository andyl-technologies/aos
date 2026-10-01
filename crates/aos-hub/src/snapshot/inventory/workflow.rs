//! Private custody, provisional projection and independent paired readback.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use aos_hub_core::snapshot::archive::root::verify_declared_root;
use aos_hub_core::snapshot::inventory::{
    ObjectRequirementsCounts, ObjectRequirementsLimits, ObjectRequirementsReader,
    ObjectRequirementsWriter,
};
use aos_hub_core::snapshot::SnapshotSchemaManifest;
use aos_hub_core::value::Row;
use sha2::{Digest, Sha256};

use crate::snapshot::credentials::{load_capture, load_exclusions, load_trust, load_wrapping};
use crate::snapshot::filesystem::{self, Directory, PublishError, Stage};
use crate::snapshot::scratch::{ScratchProjection, VerifiedRetainedSqliteCapture};
use crate::snapshot::workflow::{
    report, verify_directory_projecting, BudgetIo, CancelOnDrop, SnapshotBudget, SnapshotError,
    SnapshotReport,
};
use crate::snapshot::{CaptureCredentials, VerifyCredentials};

type Writer = ObjectRequirementsWriter<BudgetIo<BufWriter<File>>, BudgetIo<BufWriter<File>>>;
type Reader = ObjectRequirementsReader<BudgetIo<File>, BudgetIo<File>>;

struct WriteProjection(Arc<Mutex<Option<Writer>>>);
struct ReadProjection(Arc<Mutex<Option<Reader>>>);

impl ScratchProjection for WriteProjection {
    fn schema(&mut self, schema: &SnapshotSchemaManifest) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("object projection is unavailable"))?
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("object projection is closed"))?
            .require_schema(schema)
    }

    fn row(&mut self, table: &str, sequence: u64, row: &Row) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("object projection is unavailable"))?
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("object projection is closed"))?
            .row(table, sequence, row)
    }
}

impl ScratchProjection for ReadProjection {
    fn schema(&mut self, schema: &SnapshotSchemaManifest) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("object projection is unavailable"))?
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("object projection is closed"))?
            .require_schema(schema)
    }

    fn row(&mut self, table: &str, sequence: u64, row: &Row) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("object projection is unavailable"))?
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("object projection is closed"))?
            .row(table, sequence, row)
    }
}

fn duplicate(directory: &Directory) -> Result<Directory, SnapshotError> {
    Ok(Directory {
        fd: rustix::io::dup(&directory.fd).map_err(|_| SnapshotError::Verification)?,
    })
}

async fn replay(
    source: &Directory,
    root: &[u8],
    credentials: &VerifyCredentials,
    budget: SnapshotBudget,
    projection: Box<dyn ScratchProjection>,
) -> Result<VerifiedRetainedSqliteCapture, SnapshotError> {
    budget.check()?;
    let trust =
        load_trust(&credentials.signer_trust_file).map_err(|_| SnapshotError::Credentials)?;
    verify_declared_root(root, &trust).map_err(|_| SnapshotError::Verification)?;
    let wrapping = load_wrapping(&credentials.wrapping).map_err(|_| SnapshotError::Credentials)?;
    let exclusions =
        load_exclusions(&credentials.exclusion_files).map_err(|_| SnapshotError::Credentials)?;
    verify_directory_projecting(
        duplicate(source)?,
        root.to_vec(),
        trust,
        wrapping,
        exclusions,
        budget,
        Some(projection),
    )
    .await
}

async fn readback(
    source: &Directory,
    source_root: &[u8],
    requirements: &Directory,
    credentials: &VerifyCredentials,
    limits: ObjectRequirementsLimits,
    budget: SnapshotBudget,
) -> Result<(VerifiedRetainedSqliteCapture, ObjectRequirementsCounts), SnapshotError> {
    budget.check()?;
    let root = filesystem::root(requirements).map_err(|_| SnapshotError::Verification)?;
    let trust =
        load_trust(&credentials.signer_trust_file).map_err(|_| SnapshotError::Credentials)?;
    verify_declared_root(&root, &trust).map_err(|_| SnapshotError::Verification)?;
    let wrapping = load_wrapping(&credentials.wrapping).map_err(|_| SnapshotError::Credentials)?;
    let exclusions =
        load_exclusions(&credentials.exclusion_files).map_err(|_| SnapshotError::Credentials)?;
    let reader = ObjectRequirementsReader::new(
        &root,
        &trust,
        &wrapping,
        &exclusions,
        BudgetIo {
            inner: requirements
                .file("metadata.aosh")
                .map_err(|_| SnapshotError::Verification)?,
            budget: budget.clone(),
        },
        BudgetIo {
            inner: requirements
                .file("private.aosh")
                .map_err(|_| SnapshotError::Verification)?,
            budget: budget.clone(),
        },
        &hex::encode(Sha256::digest(source_root)),
        budget.streams,
        limits,
    )
    .map_err(|_| SnapshotError::Verification)?;
    let shared = Arc::new(Mutex::new(Some(reader)));
    let verified = replay(
        source,
        source_root,
        credentials,
        budget.clone(),
        Box::new(ReadProjection(shared.clone())),
    )
    .await?;
    budget.check()?;
    let reader = shared
        .lock()
        .map_err(|_| SnapshotError::Verification)?
        .take()
        .ok_or(SnapshotError::Verification)?;
    let counts = reader
        .finish(verified.records().counts())
        .map_err(|_| SnapshotError::Verification)?;
    budget.check()?;
    Ok((verified, counts))
}

fn requirements_report(
    operation: &'static str,
    verified: &VerifiedRetainedSqliteCapture,
    counts: ObjectRequirementsCounts,
) -> SnapshotReport {
    let mut result = report(operation, verified);
    result.verification_scope = "retained_sql_and_incomplete_object_requirements";
    result.object_requirements = Some(counts);
    result
}

/// Derives bounded encrypted requirements from an authenticated current capture.
///
/// Existing explicit archive signer/wrapping custody authenticates input and
/// wraps fresh output streams; no runtime/provider keys, network or initializer
/// are consulted. Secret-classified cells are excluded; opaque originals are hashed.
/// Independent exact-source readback precedes no-replace publication. Missing
/// storage/graph/journal/fencing proofs stay explicit pending requirements.
///
/// # Errors
///
/// Rejects custody, source, schema/coverage, SQL/provenance, projection bounds,
/// readback, cancellation or output failure. A post-rename durability failure
/// retains the published directory and reports that distinct unknown outcome.
pub async fn derive_object_requirements(
    archive: &Path,
    destination: &Path,
    credentials: &CaptureCredentials,
    limits: ObjectRequirementsLimits,
    budget: SnapshotBudget,
) -> Result<SnapshotReport, SnapshotError> {
    let _cancellation = CancelOnDrop(budget.clone());
    if !(1..=10_000_000).contains(&limits.max_rows) {
        return Err(SnapshotError::Limits);
    }
    budget.check()?;
    let custody = load_capture(credentials).map_err(|_| SnapshotError::Credentials)?;
    let source = Directory::open(archive, true).map_err(|_| SnapshotError::Verification)?;
    let source_root = filesystem::root(&source).map_err(|_| SnapshotError::Verification)?;
    verify_declared_root(&source_root, &custody.trust).map_err(|_| SnapshotError::Verification)?;
    // Only encrypted provisional records enter staging. Full source replay and
    // independent exact-source readback must both finish before publication.
    let mut stage = Stage::create(destination).map_err(|_| SnapshotError::Output)?;
    let writer = ObjectRequirementsWriter::new(
        BudgetIo {
            inner: BufWriter::new(
                stage
                    .create_file("metadata.aosh")
                    .map_err(|_| SnapshotError::Output)?,
            ),
            budget: budget.clone(),
        },
        BudgetIo {
            inner: BufWriter::new(
                stage
                    .create_file("private.aosh")
                    .map_err(|_| SnapshotError::Output)?,
            ),
            budget: budget.clone(),
        },
        &hex::encode(Sha256::digest(&source_root)),
        &custody.signer,
        &custody.wrapping,
        &custody.exclusions,
        &mut rand::rngs::OsRng,
        budget.streams,
        limits,
    )
    .map_err(|_| SnapshotError::Output)?;
    let readers = VerifyCredentials {
        wrapping: crate::snapshot::WrappingFiles {
            metadata_id: credentials.wrapping.metadata_id.clone(),
            metadata_file: credentials.wrapping.metadata_file.clone(),
            private_id: credentials.wrapping.private_id.clone(),
            private_file: credentials.wrapping.private_file.clone(),
        },
        signer_trust_file: credentials.signer_trust_file.clone(),
        exclusion_files: credentials.exclusion_files.clone(),
    };
    let shared = Arc::new(Mutex::new(Some(writer)));
    let verified = replay(
        &source,
        &source_root,
        &readers,
        budget.clone(),
        Box::new(WriteProjection(shared.clone())),
    )
    .await?;
    budget.check()?;
    let writer = shared
        .lock()
        .map_err(|_| SnapshotError::Output)?
        .take()
        .ok_or(SnapshotError::Output)?;
    let output = writer
        .finish(&custody.signer, verified.records().counts())
        .map_err(|_| SnapshotError::Output)?;
    for writer in [output.metadata, output.private] {
        let file = writer
            .inner
            .into_inner()
            .map_err(|_| SnapshotError::Output)?;
        file.sync_all().map_err(|_| SnapshotError::Output)?;
    }
    stage
        .write_root(output.root.as_bytes())
        .map_err(|_| SnapshotError::Output)?;
    let (readback, counts) = readback(
        &source,
        &source_root,
        stage.directory(),
        &readers,
        limits,
        budget.clone(),
    )
    .await?;
    if counts != output.counts || readback.records().counts() != verified.records().counts() {
        return Err(SnapshotError::Verification);
    }
    budget.check()?;
    stage.publish().map_err(|error| match error {
        PublishError::BeforeRename => SnapshotError::Output,
        PublishError::DurabilityUnconfirmed => SnapshotError::PublishedDurabilityUnconfirmed,
    })?;
    Ok(requirements_report(
        "derive_object_requirements",
        &readback,
        counts,
    ))
}

/// Verifies encrypted requirements by independently replaying their exact capture.
///
/// The comparison requires every expected canonical private projection and
/// clean paired EOFs. It never accepts an inventory as provider permission or
/// establishes physical closure, transfer, import or serving activation.
///
/// # Errors
///
/// Rejects custody, source/requirements mismatch, SQL/provenance, bounds,
/// canonical records, authenticated framing or cancellation.
pub async fn verify_object_requirements(
    archive: &Path,
    requirements: &Path,
    credentials: &VerifyCredentials,
    limits: ObjectRequirementsLimits,
    budget: SnapshotBudget,
) -> Result<SnapshotReport, SnapshotError> {
    let _cancellation = CancelOnDrop(budget.clone());
    if !(1..=10_000_000).contains(&limits.max_rows) {
        return Err(SnapshotError::Limits);
    }
    budget.check()?;
    let source = Directory::open(archive, true).map_err(|_| SnapshotError::Verification)?;
    let source_root = filesystem::root(&source).map_err(|_| SnapshotError::Verification)?;
    let requirements =
        Directory::open(requirements, true).map_err(|_| SnapshotError::Verification)?;
    let (verified, counts) = readback(
        &source,
        &source_root,
        &requirements,
        credentials,
        limits,
        budget,
    )
    .await?;
    Ok(requirements_report(
        "verify_object_requirements",
        &verified,
        counts,
    ))
}
