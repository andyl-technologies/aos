//! Local bundle import/export with explicit reproduction and exact committed custody.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{Context as _, Result, bail};
use aos_assessment::bundle::AssessmentBundleV1;
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::ports::Clock as _;
use aos_contract::Sha256Digest;
use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer};

use super::{inventory, state::StateStore};
use crate::cli::{Cli, MaintainArgs, MaintainAssessmentEvidenceCommand};

/// Exports exact committed evidence or retains a non-authoritative reproduction.
///
/// # Errors
/// Returns an error for unavailable or corrupt custody, unsupported evidence,
/// excessive or nonregular files, conflicting output paths or protected state failure.
pub fn run_local_assessment_evidence(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainAssessmentEvidenceCommand,
    printer: &Printer,
) -> Result<()> {
    let nix = NixRunner::new(cli.verbose, cli.quiet)?;
    let coordinates = inventory::repository_coordinates(nix.root())?;
    let store = StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    match command {
        MaintainAssessmentEvidenceCommand::Export {
            assessment_digest,
            output,
        } => {
            let digest = Sha256Digest::parse(assessment_digest)?;
            let bundle = store.export_local_assessment_evidence(digest)?;
            let manifest = bundle.verify()?;
            let bytes = bundle.encoded()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if printer.mode() == OutputMode::Json || args.jsonl {
                printer.json(&serde_json::json!({"schema_version":"aos.assessment-cli/v1", "kind":"assessment-evidence-export",
                    "execution":{"mode":"local"}, "data":{"assessmentDigest":digest, "bundleManifestDigest":manifest, "profile":bundle.manifest.profile}}));
            } else {
                printer.info(&format!(
                    "Exported assessment {digest}; manifest {manifest}; reference profile"
                ));
            }
        }
        MaintainAssessmentEvidenceCommand::Import { input } => {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(input)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
                bail!("assessment bundle input is not a bounded regular file");
            }
            let mut bytes = Vec::new();
            file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                bail!("assessment bundle input grew beyond its byte allowance");
            }
            let bundle = AssessmentBundleV1::from_slice(&bytes)
                .context("reproducing imported assessment evidence")?;
            let receipt = store.import_local_assessment_evidence(&bundle, PhysicalClock.now()?)?;
            if printer.mode() == OutputMode::Json || args.jsonl {
                printer.json(&serde_json::json!({"schema_version":"aos.assessment-cli/v1", "kind":"assessment-evidence-import",
                    "execution":{"mode":"local"}, "data":receipt}));
            } else {
                printer.info(&format!("Reproduced assessment {}; evidence authority not established; {} external raw members",
                    receipt.assessment_digest, receipt.external_raw_members));
            }
        }
    }
    Ok(())
}
