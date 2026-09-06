//! Exact planned Nix realization, reproducibility checks, and build evidence.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_release::build::{
    BUILD_REPORT_V1, BuildOutputEvidence, BuildReportV1, BuildSourceEvidence,
    ReproducibilityResult, planned_nix_outputs,
};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::sbom::SpdxDocument;
use aos_release::state::{JournalEntryV1, ReleaseState};
use serde::Deserialize;

use crate::cli::ReleaseBuildArgs;

use super::capture;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NixPathInfo {
    nar_hash: String,
    nar_size: u64,
    closure_size: u64,
    deriver: Option<String>,
    references: Vec<String>,
}

/// Realizes every planned derivation twice and writes a closed evidence tree.
pub(super) fn run(args: &ReleaseBuildArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    let started_at = require_utc_time(&args.started_at, "build start time")?;
    if started_at > std::time::SystemTime::now() {
        bail!("build start time is in the future");
    }

    let plan_bytes = capture::control_file(&args.plan, "release plan")?;
    canonical::require_canonical(&plan_bytes, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    let planned = planned_nix_outputs(&plan)?;
    let derivations = planned
        .values()
        .map(|output| PathBuf::from(output.derivation))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    printer.info(&format!(
        "Realizing {} exact outputs from {} derivations...",
        planned.len(),
        derivations.len()
    ));
    nix.realise_derivations(&derivations, false)?;
    printer.info("Repeat-building planned derivations with Nix --check...");
    nix.realise_derivations(&derivations, true)?;

    let source_paths = planned
        .values()
        .flat_map(|output| output.source_store_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let store_paths = planned
        .values()
        .map(|output| PathBuf::from(output.store_path))
        .chain(source_paths.iter().map(PathBuf::from))
        .collect::<Vec<_>>();
    let path_info = nix.path_info_json(&store_paths)?;
    let path_info = path_info
        .as_object()
        .context("Nix path-info response is not an object")?;
    let mut outputs = Vec::with_capacity(planned.len());
    for (id, expected) in &planned {
        let value = path_info
            .get(expected.store_path)
            .with_context(|| format!("Nix omitted planned store path {}", expected.store_path))?;
        let mut info: NixPathInfo = serde_json::from_value(value.clone())
            .with_context(|| format!("decoding Nix facts for {}", expected.store_path))?;
        if info.deriver.as_deref() != Some(expected.derivation) {
            bail!("realized output {id} has a different deriver than the plan");
        }
        info.references.sort();
        info.references.dedup();
        outputs.push(BuildOutputEvidence {
            id: (*id).to_string(),
            package: expected.package.to_owned(),
            version: expected.version.to_owned(),
            license_expression: expected.license_expression.to_owned(),
            source_store_paths: expected.source_store_paths.to_vec(),
            platform: expected.platform,
            derivation: expected.derivation.to_string(),
            output: expected.output.to_string(),
            store_path: expected.store_path.to_string(),
            nar_hash: info.nar_hash,
            nar_size: info.nar_size,
            closure_size: info.closure_size,
            references: info.references,
            reproducibility: ReproducibilityResult::Reproduced,
        });
    }
    let sources = source_paths
        .into_iter()
        .map(|store_path| {
            let value = path_info
                .get(&store_path)
                .with_context(|| format!("Nix omitted source store path {store_path}"))?;
            let info: NixPathInfo = serde_json::from_value(value.clone())
                .with_context(|| format!("decoding Nix source facts for {store_path}"))?;
            Ok(BuildSourceEvidence {
                store_path,
                nar_hash: info.nar_hash,
                nar_size: info.nar_size,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let completed_at = humantime::format_rfc3339(std::time::SystemTime::now()).to_string();
    let report = BuildReportV1 {
        schema_version: BUILD_REPORT_V1.to_string(),
        plan_digest,
        source_commit: plan.source.commit.clone(),
        outputs,
        sources,
        completed_at: completed_at.clone(),
    };
    report.validate(&plan, plan_digest)?;
    let sbom = SpdxDocument::from_build(&report);
    sbom.validate()?;

    let report_bytes = canonical::to_vec(&report)?;
    let sbom_bytes = canonical::to_vec(&sbom)?;
    let journal = build_journal(
        plan_digest,
        &args.started_at,
        &completed_at,
        &report_bytes,
        &sbom_bytes,
    )?;
    persist_build_tree(
        &args.output,
        &plan_bytes,
        &report_bytes,
        &sbom_bytes,
        &journal,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.build-result/v1",
        "plan_digest": plan_digest,
        "outputs": report.outputs.len(),
        "derivations": derivations.len(),
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Built and repeat-checked {} planned outputs; evidence written to {}",
        report.outputs.len(),
        args.output.display()
    ));
    Ok(())
}

fn build_journal(
    plan_digest: Sha256Digest,
    started_at: &str,
    completed_at: &str,
    report: &[u8],
    sbom: &[u8],
) -> Result<Vec<u8>> {
    let planned = JournalEntryV1 {
        schema_version: aos_release::RELEASE_JOURNAL_ENTRY_V1.to_string(),
        sequence: 1,
        previous_entry_digest: None,
        plan_digest,
        manifest_digest: None,
        prior_state: None,
        new_state: ReleaseState::Planned,
        operation_ids: vec!["release-plan".to_string()],
        evidence: vec![],
        recorded_at: started_at.to_string(),
    };
    planned.validate()?;
    let planned_digest = Sha256Digest::of_canonical("aos.release.journal-entry/v1", &planned)?;
    let built = JournalEntryV1 {
        schema_version: aos_release::RELEASE_JOURNAL_ENTRY_V1.to_string(),
        sequence: 2,
        previous_entry_digest: Some(planned_digest),
        plan_digest,
        manifest_digest: None,
        prior_state: Some(ReleaseState::Planned),
        new_state: ReleaseState::Built,
        operation_ids: vec!["nix-realise-check".to_string()],
        evidence: vec![Sha256Digest::of_bytes(report), Sha256Digest::of_bytes(sbom)],
        recorded_at: completed_at.to_string(),
    };
    built.validate()?;
    aos_release::verify::verify_journal(&[planned.clone(), built.clone()])?;

    let mut bytes = canonical::to_vec(&planned)?;
    bytes.push(b'\n');
    bytes.extend(canonical::to_vec(&built)?);
    bytes.push(b'\n');
    Ok(bytes)
}

fn persist_build_tree(
    output: &Path,
    plan: &[u8],
    report: &[u8],
    sbom: &[u8],
    journal: &[u8],
) -> Result<()> {
    if output.exists() {
        bail!("build evidence output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-build-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir_all(root.join("evidence"))?;
    write_synced(&root.join("release-plan.json"), plan)?;
    write_synced(&root.join("evidence/build-report.json"), report)?;
    write_synced(&root.join("evidence/sbom.spdx.json"), sbom)?;
    write_synced(&root.join("release-journal.jsonl"), journal)?;
    File::open(root.join("evidence"))?.sync_all()?;
    File::open(&root)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &root,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .with_context(|| format!("installing new build evidence tree {}", output.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_utc_time(value: &str, label: &str) -> Result<std::time::SystemTime> {
    if !value.ends_with('Z') {
        bail!("{label} must be an RFC 3339 UTC timestamp");
    }
    humantime::parse_rfc3339(value)
        .with_context(|| format!("{label} must be an RFC 3339 UTC timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_records_only_direct_planned_to_built_transition() -> Result<()> {
        let bytes = build_journal(
            Sha256Digest::of_bytes("plan"),
            "2026-09-03T00:00:00Z",
            "2026-09-03T01:00:00Z",
            b"report",
            b"sbom",
        )?;
        let lines = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| canonical::from_slice(line, "test journal"))
            .collect::<Result<Vec<JournalEntryV1>>>()?;

        assert_eq!(lines.len(), 2);
        assert_eq!(
            aos_release::verify::verify_journal(&lines)?,
            ReleaseState::Built
        );
        Ok(())
    }

    #[test]
    fn evidence_tree_never_replaces_an_existing_output() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("build");
        persist_build_tree(&output, b"plan", b"report", b"sbom", b"journal")?;
        assert!(persist_build_tree(&output, b"other", b"other", b"other", b"other").is_err());
        assert_eq!(fs::read(output.join("release-plan.json"))?, b"plan");
        Ok(())
    }

    #[test]
    fn timestamps_must_be_real_utc_rfc3339_values() {
        assert!(require_utc_time("2026-09-03T00:00:00Z", "time").is_ok());
        assert!(require_utc_time("2026-99-99T00:00:00Z", "time").is_err());
        assert!(require_utc_time("2026-09-03T00:00:00+01:00", "time").is_err());
    }
}
