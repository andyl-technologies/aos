//! Explicit offline snapshot command inputs, before runtime credential loading.
//!
//! These Linux-only local operations never initialize a Hub. Archive custody
//! has no environment fallback and never selects existing runtime/source keys.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct SnapshotArgs {
    #[command(subcommand)]
    command: SnapshotCommand,
}

#[derive(Subcommand)]
enum SnapshotCommand {
    /// Capture an existing SQLite database into a private encrypted directory.
    CaptureSqlite {
        /// Read this existing SQLite database without initialization.
        #[arg(long)]
        source_sqlite: PathBuf,
        /// Publish this new archive directory; it must not already exist.
        #[arg(long)]
        output: PathBuf,
        /// Use this dedicated exporter signer identity.
        #[arg(long)]
        signer_id: String,
        /// Read an existing private file containing a raw 32-byte Ed25519 seed.
        #[arg(long)]
        signing_seed_file: PathBuf,
        #[command(flatten)]
        custody: CustodyArgs,
    },
    /// Verify actual paired records without importing SQL or activating a Hub.
    VerifyCapture {
        /// Read this existing private archive directory.
        #[arg(long)]
        archive: PathBuf,
        #[command(flatten)]
        custody: CustodyArgs,
    },
}

#[derive(Args)]
struct CustodyArgs {
    /// Read closed v1 signer pins from an existing private file (at most 64KiB).
    #[arg(long)]
    signer_trust_file: PathBuf,
    /// Use this opaque metadata wrapping identity.
    #[arg(long)]
    metadata_wrapping_id: String,
    /// Read an existing private file containing 32 raw metadata AES key bytes.
    #[arg(long)]
    metadata_wrapping_key_file: PathBuf,
    /// Use this distinct opaque private-stream wrapping identity.
    #[arg(long)]
    private_wrapping_id: String,
    /// Read an existing private file containing 32 raw private-stream AES key bytes.
    #[arg(long)]
    private_wrapping_key_file: PathBuf,
    /// Exclude this explicitly supplied existing raw nonarchive key (at most 32).
    #[arg(long)]
    exclude_key_file: Vec<PathBuf>,
    /// Stop cooperatively after this many seconds (maximum 86400).
    #[arg(long, default_value_t = 3600)]
    timeout_seconds: u64,
    /// Bound plaintext bytes per encrypted stream (maximum 64GiB).
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    max_stream_plaintext_bytes: u64,
}

/// Rejects runtime configuration before reading any credential or creating state.
pub(crate) fn validate_runtime_inputs(
    root: Option<&Path>,
    database_url: Option<&str>,
    database_url_file: Option<&Path>,
    target: &str,
) -> Result<()> {
    ensure!(root.is_none() && database_url.is_none() && database_url_file.is_none() && target == "local",
        "snapshot commands require explicit archive inputs; runtime root/database/target options are unsupported");
    Ok(())
}

#[cfg(target_os = "linux")]
impl CustodyArgs {
    fn wrapping(&self) -> aos_hub::snapshot::WrappingFiles {
        aos_hub::snapshot::WrappingFiles {
            metadata_id: self.metadata_wrapping_id.clone(),
            metadata_file: self.metadata_wrapping_key_file.clone(),
            private_id: self.private_wrapping_id.clone(),
            private_file: self.private_wrapping_key_file.clone(),
        }
    }

    fn budget(&self) -> Result<aos_hub::snapshot::workflow::SnapshotBudget> {
        ensure!(
            self.exclude_key_file.len() <= 32,
            "snapshot exclusions exceed limits"
        );
        Ok(aos_hub::snapshot::workflow::SnapshotBudget::new(
            std::time::Duration::from_secs(self.timeout_seconds),
            self.max_stream_plaintext_bytes,
        )?)
    }
}

/// Runs a record-only operation with cooperative SIGINT/SIGTERM cancellation.
///
/// # Errors
///
/// Rejects invalid arguments, private custody, source/schema, streams or local
/// publication. Printed reports contain counts/scopes, never private values.
#[cfg(target_os = "linux")]
pub(crate) async fn run(arguments: &SnapshotArgs) -> Result<()> {
    use aos_hub::snapshot::{workflow, CaptureCredentials, VerifyCredentials};

    let custody = match &arguments.command {
        SnapshotCommand::CaptureSqlite { custody, .. }
        | SnapshotCommand::VerifyCapture { custody, .. } => custody,
    };
    let budget = custody.budget()?;
    let signal_budget = budget.clone();
    // Signal registration failures abort before source/output admission.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let watcher = tokio::spawn(async move {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        signal_budget.cancel();
    });
    let watcher = AbortOnDrop(watcher);
    let result = match &arguments.command {
        SnapshotCommand::CaptureSqlite {
            source_sqlite,
            output,
            signer_id,
            signing_seed_file,
            custody,
        } => {
            workflow::capture(
                source_sqlite,
                output,
                &CaptureCredentials {
                    signer_id: signer_id.clone(),
                    signing_seed_file: signing_seed_file.clone(),
                    wrapping: custody.wrapping(),
                    signer_trust_file: custody.signer_trust_file.clone(),
                    exclusion_files: custody.exclude_key_file.clone(),
                },
                budget,
            )
            .await
        }
        SnapshotCommand::VerifyCapture { archive, custody } => {
            workflow::verify(
                archive,
                &VerifyCredentials {
                    wrapping: custody.wrapping(),
                    signer_trust_file: custody.signer_trust_file.clone(),
                    exclusion_files: custody.exclude_key_file.clone(),
                },
                budget,
            )
            .await
        }
    };
    drop(watcher);
    let report = result?;
    // Report serialization is fixed-shape and does not serialize caller paths.
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

#[cfg(target_os = "linux")]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn run(_: &SnapshotArgs) -> Result<()> {
    anyhow::bail!("offline archive filesystem operations require Linux")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        snapshot: SnapshotArgs,
    }

    #[test]
    fn runtime_preflight_rejects_without_reading_or_initializing() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-private-db-url");
        let root = directory.path().join("uncreated-root");
        for result in [
            validate_runtime_inputs(Some(&root), None, None, "local"),
            validate_runtime_inputs(None, Some("secret-url"), None, "local"),
            validate_runtime_inputs(None, None, Some(&missing), "local"),
            validate_runtime_inputs(None, None, None, "worker"),
        ] {
            let error = result.unwrap_err();
            assert!(!format!("{error:#}").contains("secret-url"));
        }
        assert!(!root.exists());
        assert!(!missing.exists());
        validate_runtime_inputs(None, None, None, "local").unwrap();
    }

    #[test]
    fn closed_parser_requires_explicit_archive_custody_and_rejects_import() {
        let args = [
            "test",
            "verify-capture",
            "--archive",
            "archive",
            "--signer-trust-file",
            "pins",
            "--metadata-wrapping-id",
            "m",
            "--metadata-wrapping-key-file",
            "m.key",
            "--private-wrapping-id",
            "p",
            "--private-wrapping-key-file",
            "p.key",
        ];
        let parsed = TestCli::try_parse_from(args).unwrap();
        assert!(matches!(
            parsed.snapshot.command,
            SnapshotCommand::VerifyCapture { .. }
        ));
        assert!(
            TestCli::try_parse_from(["test", "verify-capture", "--archive", "archive"]).is_err()
        );
        let mut unknown = args.to_vec();
        unknown.push("--activate");
        assert!(TestCli::try_parse_from(unknown).is_err());
        assert!(TestCli::try_parse_from(["test", "import"]).is_err());
    }
}
