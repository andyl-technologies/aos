//! Private PostgreSQL connection custody and inert capture orchestration.

use anyhow::{ensure, Result};
use aos_hub_core::backend::postgres_snapshot::{PostgresSnapshotLimits, PostgresSnapshotReader};
use aos_hub_core::snapshot::archive::records::{
    capture_postgres as encode, PostgresCaptureOptions,
};
use zeroize::Zeroizing;

use super::*;

/// Captures a held PostgreSQL snapshot into a new private encrypted directory.
///
/// The URL comes exclusively from a bounded owner-private file. Source and
/// archive credentials are distinct; neither URL nor source values enter reports.
/// Independent paired-record and retained SQLite constraint verification precedes
/// local publication. No target SQL, provider operation or activation occurs.
///
/// # Errors
///
/// Returns sanitized custody, engine/schema, source/stream deadline, capture and
/// verification failures. Published durability uncertainty remains explicit.
pub async fn capture_postgres(
    source_database_url_file: &Path,
    destination: &Path,
    credentials: &CaptureCredentials,
    budget: SnapshotBudget,
) -> std::result::Result<SnapshotReport, SnapshotError> {
    let _cancellation = CancelOnDrop(budget.clone());
    budget.check()?;
    let custody = load_capture(credentials).map_err(|_| SnapshotError::Credentials)?;
    let url =
        connection_string(source_database_url_file).map_err(|_| SnapshotError::PostgresSource)?;
    let duration = budget
        .deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(300));
    let limits = PostgresSnapshotLimits {
        max_duration: duration,
        statement_timeout: duration.min(Duration::from_secs(30)),
        lock_timeout: duration.min(Duration::from_secs(5)),
    };
    let reader = tokio::select! {
        result = PostgresSnapshotReader::open(&url, limits) => result.map_err(|_| SnapshotError::PostgresSource)?,
        _ = budget.stopped() => return Err(SnapshotError::Cancelled),
    };
    drop(url);
    budget.check()?;
    let stage = Stage::create(destination).map_err(|_| SnapshotError::Output)?;
    let metadata = BudgetIo {
        inner: BufWriter::new(
            stage
                .create_file("metadata.aosh")
                .map_err(|_| SnapshotError::Output)?,
        ),
        budget: budget.clone(),
    };
    let private = BudgetIo {
        inner: BufWriter::new(
            stage
                .create_file("private.aosh")
                .map_err(|_| SnapshotError::Output)?,
        ),
        budget: budget.clone(),
    };
    let mut rng = rand::rngs::OsRng;
    let output = tokio::select! {
        result = encode(reader, metadata, private,
            CaptureKeyCustody { signer: &custody.signer, wrapping: &custody.wrapping, exclusions: &custody.exclusions },
            &mut rng, PostgresCaptureOptions { pages: SqliteSnapshotLimits::default(), streams: budget.streams }) => result,
        _ = budget.stopped() => return Err(SnapshotError::Cancelled),
    };
    budget.check()?;
    finish_capture(
        stage,
        output.map_err(|_| SnapshotError::Capture)?,
        custody,
        budget,
        "capture_postgres",
    )
    .await
}

fn connection_string(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(path, 16 * 1024)?;
    let text = std::str::from_utf8(&bytes)?.trim();
    let parsed = url::Url::parse(text)?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql")
            && parsed.host_str().is_some()
            && !parsed.username().is_empty()
            && parsed.path().len() > 1
            && parsed.fragment().is_none(),
        "explicit PostgreSQL source connection required"
    );
    Ok(Zeroizing::new(text.to_owned()))
}
